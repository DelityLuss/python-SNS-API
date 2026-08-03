"""Decoding of appliance answers, against real captured XML."""

from __future__ import annotations

import pytest

from stormshield.sns.configparser import ConfigParser, serialize
from stormshield.sns.sslclient import Response, format_output

from .conftest import load


def test_section_format():
    r = Response.from_xml(load("system_property"))

    assert r.ret == 100
    assert r.format == "section"
    assert r.data["Result"]["Model"] == "EVA2"
    assert r.data["Result"]["Version"] == "4.8.15"
    # keys are case insensitive
    assert r.data["result"]["VERSION"] == "4.8.15"
    assert bool(r) is True


def test_section_format_multiple_sections():
    r = Response.from_xml(load("hostrep_show"))

    assert r.format == "section"
    assert set(serialize(r.data)) == {"Global", "Alarm", "Sandboxing", "Antivirus"}
    assert r.data["Alarm"]["Minor"] == "2"
    assert r.data["Antivirus"]["Infected"] == "100"


def test_section_line_format():
    r = Response.from_xml(load("ntp_server_list"))

    assert r.format == "section_line"
    assert r.data["Result"][0]["keynum"] == "none"
    assert r.data["Result"][0]["type"] == "host"
    assert len(r.data["Result"]) == 2


def test_list_format():
    r = Response.from_xml(load("webadmin_access"))

    assert r.format == "list"
    assert r.data["Result"] == ["network_internals", "labo_networks"]


def test_raw_format():
    r = Response.from_xml(load("help_raw"))

    assert r.format == "raw"
    assert isinstance(r.data, str)
    assert r.data.startswith("AUTH")
    # the trailing newline of a raw payload is preserved (1.x dropped it)
    assert r.data.endswith("\n")


def test_xml_format():
    r = Response.from_xml(load("filter_xml"))

    assert r.format == "xml"
    assert isinstance(r.data, str)
    assert r.data.startswith("<data format=\"xml\">")


def test_error_answer_has_no_payload():
    r = Response.from_xml(load("unknown_command"))

    assert r.ret == 200
    assert r.format is None
    assert bool(r) is False
    assert serialize(r.data) == {}


def test_privilege_error():
    r = Response.from_xml(load("system_information"))

    assert r.ret == 205
    assert bool(r) is False


def test_multiline_answer_reports_final_status():
    """ret/code/msg come from the last serverd node, serverd_code from the first."""

    r = Response.from_xml(load("system_property"))

    assert r.ret == 100  # last node
    assert r.code == "00a00100"
    assert r.serverd_code == "00a01000"  # first node, carries the transfer state


@pytest.mark.parametrize(
    "name",
    [
        "system_property", "hostrep_show", "monitor_stat", "nettoken",
        "ntp_server_list", "object_list_host", "user_list", "webadmin_access",
        "unknown_command", "bad_args", "system_information",
    ],
)
def test_xml_and_text_paths_agree(name):
    """The XML-direct decoding must match parsing the rendered ini text.

    This is the contract that let 2.0 stop round-tripping every answer
    through its text rendering.
    """

    xml = load(name)
    from_xml = Response.from_xml(xml)
    from_text = ConfigParser(format_output(xml))

    assert from_xml.format == from_text.format
    assert serialize(from_xml.data) == serialize(from_text.data)


@pytest.mark.parametrize("name", ["system_property", "object_list_host", "webadmin_access", "help_raw"])
def test_output_rendering_is_stable(name):
    """`output` keeps the exact 1.x ini rendering."""

    xml = load(name)
    assert Response.from_xml(xml).output == format_output(xml)


def test_output_is_lazy():
    """Reading `data` must not build the ini rendering."""

    r = Response.from_xml(load("user_list"))
    assert "output" not in r.__dict__
    _ = r.data
    assert "output" not in r.__dict__
    _ = r.output
    assert "output" in r.__dict__


def test_parser_reuses_decoded_data():
    """`response.parser` must not re-parse anything."""

    r = Response.from_xml(load("system_property"))
    assert r.parser.get("Result", "Model") == "EVA2"
    assert r.parser.format == "section"
    assert "output" not in r.__dict__


def test_get_shortcut():
    r = Response.from_xml(load("system_property"))

    assert r.get("Result", "Model") == "EVA2"
    assert r.get("Result", "Nope", default="fallback") == "fallback"
    assert r.get("Nope", "Model", default=None) is None


def test_serialize_data_is_json_ready():
    import json

    r = Response.from_xml(load("ntp_server_list"))
    assert json.loads(json.dumps(r.parser.serialize_data()))["Result"][0]["type"] == "host"


def test_repr_does_not_dump_the_payload():
    """1.x __repr__ returned the whole output, and crashed when it was None."""

    r = Response.from_xml(load("user_list"))
    assert len(repr(r)) < 100
    assert "ret=100" in repr(r)
    assert repr(Response())  # no output, must not raise


def test_str_returns_output():
    xml = load("system_property")
    assert str(Response.from_xml(xml)) == format_output(xml)


def test_empty_answer_is_rejected():
    with pytest.raises(ValueError):
        Response.from_xml('<?xml version="1.0"?><nws code="100" msg="OK"></nws>')


def test_response_without_payload_is_usable():
    """A hand-built Response (as returned by download()) still decodes."""

    r = Response(ret=100, code="00a00100", msg="OK", output='100 code=00a00100 msg="Ok"')

    assert r.output == '100 code=00a00100 msg="Ok"'
    assert r.format is None
    assert bool(r) is True


def test_bool_is_true_for_warnings():
    assert bool(Response(ret=110)) is True
    assert bool(Response(ret=111)) is True
    assert bool(Response(ret=100)) is True
    assert bool(Response(ret=200)) is False
    assert bool(Response(ret=99)) is False
