"""Answer metadata and JSON serialisation.

The appliance carries row counts and truncation flags as attributes of the
``<serverd>`` node. They are not rows, so they are not in `data`; 1.x dropped
them entirely, which made a paged answer indistinguishable from a complete one.
"""

from __future__ import annotations

import json

import pytest

from stormshield.sns.sslclient import Response

from .conftest import load


def build(serverd_attrs: str = "", body: str = "", fmt: str = "section_line") -> str:
    return (
        '<?xml version="1.0"?><nws code="100" msg="OK">'
        f'<serverd ret="101" code="00a01000" msg="Begin" {serverd_attrs}>'
        f'<data format="{fmt}"><section title="Result">{body}</section></data></serverd>'
        '<serverd ret="100" code="00a00100" msg="Ok"></serverd></nws>'
    )


def rows(n: int) -> str:
    return "".join(f'<line><key name="id" value="{i}"/></line>' for i in range(n))


# --- meta -------------------------------------------------------------------


def test_meta_exposes_the_serverd_attributes():
    r = Response.from_xml(load("object_list_host"))

    assert r.meta == {
        "total": "134",
        "data_changed": "0",
        "too_many_data": "0",
        "not_enough_space": "0",
    }


def test_meta_excludes_the_status_attributes():
    r = Response.from_xml(load("object_list_host"))

    assert "ret" not in r.meta
    assert "code" not in r.meta
    assert "msg" not in r.meta


def test_meta_is_empty_when_the_appliance_sends_none():
    assert Response.from_xml(load("system_property")).meta == {}
    assert Response.from_xml(load("unknown_command")).meta == {}
    assert Response().meta == {}


# --- total / count / truncated ----------------------------------------------


def test_total_is_an_int():
    assert Response.from_xml(load("object_list_host")).total == 134


def test_total_is_none_without_the_attribute():
    assert Response.from_xml(load("system_property")).total is None


def test_total_ignores_a_non_numeric_value():
    assert Response.from_xml(build('total="lots"', rows(3))).total is None


def test_count_counts_the_returned_rows():
    r = Response.from_xml(load("object_list_host"))

    assert r.count == 100
    assert r.count == len(r.data["Object"])


def test_count_is_none_for_non_row_formats():
    assert Response.from_xml(load("system_property")).count is None  # section
    assert Response.from_xml(load("help_raw")).count is None  # raw


def test_count_sums_every_section():
    xml = (
        '<?xml version="1.0"?><nws code="100" msg="OK">'
        '<serverd ret="101" code="00a01000" msg="Begin"><data format="section_line">'
        f'<section title="A">{rows(2)}</section><section title="B">{rows(3)}</section>'
        "</data></serverd>"
        '<serverd ret="100" code="00a00100" msg="Ok"></serverd></nws>'
    )
    assert Response.from_xml(xml).count == 5


def test_truncated_when_fewer_rows_than_total():
    """The real case: 100 of 134 objects, with no error reported."""

    r = Response.from_xml(load("object_list_host"))

    assert r.truncated is True
    assert r.count < r.total


def test_not_truncated_when_every_row_is_there():
    assert Response.from_xml(build('total="3"', rows(3))).truncated is False


def test_not_truncated_without_metadata():
    assert Response.from_xml(load("system_property")).truncated is False
    assert Response.from_xml(load("unknown_command")).truncated is False
    assert Response().truncated is False


def test_truncated_on_too_many_data_flag():
    assert Response.from_xml(build('total="2" too_many_data="1"', rows(2))).truncated is True


def test_truncated_on_not_enough_space_flag():
    assert Response.from_xml(build('total="2" not_enough_space="1"', rows(2))).truncated is True


def test_truncated_is_false_when_flags_are_zero():
    xml = build('total="2" too_many_data="0" not_enough_space="0"', rows(2))
    assert Response.from_xml(xml).truncated is False


# --- JSON -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["system_property", "hostrep_show", "ntp_server_list", "webadmin_access",
     "object_list_host", "help_raw", "filter_xml", "unknown_command"],
)
def test_json_is_valid_for_every_format(name):
    """`data` itself is a CaseInsensitiveDict, which json.dumps refuses."""

    r = Response.from_xml(load(name))

    assert json.loads(r.json()) == json.loads(json.dumps(r.to_dict()))


def test_raw_data_is_not_json_serialisable():
    """Documents why to_dict()/json() exist."""

    r = Response.from_xml(load("system_property"))

    with pytest.raises(TypeError, match="CaseInsensitiveDict"):
        json.dumps(r.data)


def test_to_dict_returns_plain_containers():
    r = Response.from_xml(load("ntp_server_list"))
    decoded = r.to_dict()

    assert type(decoded) is dict
    assert type(decoded["Result"]) is list
    assert type(decoded["Result"][0]) is dict


def test_json_keeps_unicode_readable_by_default():
    xml = build("", '<line><key name="comment" value="accents éèà et ✓"/></line>')
    r = Response.from_xml(xml)

    assert "éèà et ✓" in r.json()
    assert "\\u00e9" in r.json(ensure_ascii=True)


def test_json_forwards_kwargs():
    r = Response.from_xml(load("ntp_server_list"))

    assert "\n" in r.json(indent=2)


def test_every_value_is_a_string():
    """The appliance sends XML attributes, so no typing survives the wire."""

    r = Response.from_xml(load("system_property"))

    assert all(isinstance(v, str) for v in r.to_dict()["Result"].values())

    r = Response.from_xml(load("object_list_host"))
    assert all(isinstance(v, str) for row in r.to_dict()["Object"] for v in row.values())


def test_json_matches_parser_serialize_data():
    """`to_dict()` is the same thing `parser.serialize_data()` produced."""

    r = Response.from_xml(load("object_list_host"))

    assert r.to_dict() == r.parser.serialize_data()


# --- paging must terminate --------------------------------------------------


def paged(start: int, n: int, total: int) -> Response:
    """An answer covering rows [start, start+n) out of `total`."""

    r = Response.from_xml(build(f'total="{total}"', rows(n)))
    r.offset = start
    return r


def test_last_page_is_not_truncated():
    """offset+count == total, so nothing remains even though count < total."""

    r = paged(start=100, n=34, total=134)

    assert r.count == 34
    assert r.count < r.total  # the naive comparison would say "more to fetch"
    assert r.truncated is False


def test_page_past_the_end_is_not_truncated():
    """The appliance still reports the full total alongside zero rows.

    Without this, `while response.truncated` never terminates.
    """

    r = paged(start=134, n=0, total=134)

    assert r.count == 0
    assert r.truncated is False


def test_first_page_of_several_is_truncated():
    assert paged(start=0, n=100, total=134).truncated is True


def test_middle_page_is_truncated():
    assert paged(start=100, n=100, total=300).truncated is True


def test_unknown_offset_falls_back_to_zero():
    """Without a `start=` in the command the answer is assumed to be page one."""

    r = Response.from_xml(build('total="134"', rows(100)))

    assert r.offset is None
    assert r.truncated is True


def test_paging_loop_terminates():
    """The documented loop must converge, and collect every row exactly once."""

    total, page_size = 134, 100
    collected, start, guard = 0, 0, 0

    while True:
        guard += 1
        assert guard < 10, "paging loop did not terminate"
        n = max(0, min(page_size, total - start))
        response = paged(start=start, n=n, total=total)
        collected += response.count
        if not response.truncated:
            break
        start += response.count

    assert collected == total
    assert guard == 2  # 100 + 34, no wasted empty request


def test_zero_rows_with_a_zero_total_is_not_truncated():
    r = paged(start=0, n=0, total=0)

    assert r.truncated is False
