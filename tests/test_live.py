"""End-to-end tests against a real appliance.

Skipped unless the appliance is configured::

    export APPLIANCE=10.0.0.254 PASSWORD=... [USER=admin] [SERIAL=...]
    pytest tests/test_live.py

These are intentionally locale independent: an appliance answers in the
language of its configuration, so the serverd ``msg`` text is never asserted.
"""

from __future__ import annotations

import logging
import os
import random
import string

import pytest

from stormshield.sns.sslclient import ServerError, SSLClient

APPLIANCE = os.getenv("APPLIANCE") or os.getenv("SNS_URL", "")
PASSWORD = os.getenv("PASSWORD") or os.getenv("SNS_PASSWORD", "")
USER = os.getenv("USER_SNS") or os.getenv("SNS_USER", "admin")
SERIAL = os.getenv("SERIAL", "")
SSLVERIFYPEER = os.getenv("SSLVERIFYPEER", "0") == "1"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not APPLIANCE, reason="APPLIANCE/SNS_URL must point at a running SNS appliance"),
    pytest.mark.skipif(not PASSWORD, reason="PASSWORD/SNS_PASSWORD must be set"),
]


@pytest.fixture(scope="module")
def client():
    with SSLClient(
        host=APPLIANCE,
        user=USER,
        password=PASSWORD,
        sslverifyhost=False,
        sslverifypeer=SSLVERIFYPEER,
        timeout=30,
    ) as c:
        yield c


# --- session ----------------------------------------------------------------


def test_connect_opens_a_session(client):
    assert client.sessionid
    assert client.protocol
    assert "admin" in client.sessionlevel or client.sessionlevel


def test_context_manager_round_trip():
    with SSLClient(
        host=APPLIANCE, user=USER, password=PASSWORD,
        sslverifyhost=False, sslverifypeer=SSLVERIFYPEER,
    ) as c:
        assert c.send_command("SYSTEM PROPERTY").ret == 100
        session = c.session
    # __exit__ closed the session; a second disconnect is a no-op
    c.disconnect()
    assert session is c.session


# --- answer formats ---------------------------------------------------------


def test_section_format(client):
    response = client.send_command("SYSTEM PROPERTY")

    assert response.ret == 100
    assert response.format == "section"
    assert response.data["Result"]["Version"]
    assert response.data["result"]["version"] == response.data["Result"]["Version"]
    assert bool(response) is True


def test_section_line_format(client):
    response = client.send_command("CONFIG OBJECT LIST type=host start=0")

    assert response.ret == 100
    assert response.format == "section_line"
    assert isinstance(response.data["Object"], list)
    assert "name" in response.data["Object"][0]


def test_list_format(client):
    response = client.send_command("CONFIG WEBADMIN ACCESS SHOW")

    assert response.ret == 100
    assert response.format == "list"
    assert isinstance(response.data["Result"], list)


def test_raw_format(client):
    response = client.send_command("HELP")

    assert response.ret == 100
    assert response.format == "raw"
    assert "AUTH" in response.data


def test_xml_format(client):
    response = client.send_command("CONFIG FILTER EXPLICIT index=1 type=filter output=xml")

    assert response.ret == 100
    assert response.format == "xml"
    assert response.xml.startswith("<?xml")


def test_output_matches_the_decoded_data(client):
    """The lazy ini rendering must stay consistent with `data`."""

    from stormshield.sns.configparser import ConfigParser, serialize

    response = client.send_command("CONFIG OBJECT LIST type=host start=0")
    assert serialize(ConfigParser(response.output).data) == serialize(response.data)


# --- errors -----------------------------------------------------------------


def test_unknown_command_is_reported_not_raised(client):
    response = client.send_command("THIS_COMMAND_DOES_NOT_EXIST")

    assert response.ret == 200
    assert bool(response) is False


def test_bad_arguments_are_reported(client):
    response = client.send_command("CONFIG OBJECT HOST NEW")

    assert bool(response) is False


# --- utf-8 ------------------------------------------------------------------


def test_utf8_round_trip(client):
    name = "_testutf8"
    comment = "comment with utf8 characters éè✓"
    client.send_command(f'CONFIG OBJECT HOST NEW name={name} ip=10.99.99.99 comment="{comment}"')
    try:
        response = client.send_command(f"CONFIG OBJECT LIST type=host search={name} start=0")
        assert response.ret == 100
        entry = response.data["Object"][0]
        assert entry["name"] == name
        assert entry["comment"] == comment
    finally:
        client.send_command(f"CONFIG OBJECT HOST DELETE name={name}")


# --- file transfer ----------------------------------------------------------


def test_upload_download_round_trip(client, tmp_path):
    """Exercises the zlib-based CRC against the appliance's own checksum."""

    letters = string.ascii_letters + "éèàÎîô"
    content = (
        "[Filter] \n pass from network_internals to any #ASCII"
        + "".join(random.choice(letters) for _ in range(100))
    ).encode("utf-8")

    upload = tmp_path / "upload"
    download = tmp_path / "download"
    upload.write_bytes(content)

    response = client.send_command(f"CONFIG SLOT UPLOAD slot=1 name=testUpload < {upload}")
    assert response.ret == 100

    response = client.send_command(f"CONFIG SLOT DOWNLOAD slot=1 name=testUpload > {download}")
    assert response.ret == 100

    assert download.read_bytes() == content
    assert not list(tmp_path.glob("*.part"))


def test_download_of_a_large_payload(client, tmp_path):
    """A backup is big enough to exercise chunked CRC accumulation."""

    target = tmp_path / "backup.na"
    try:
        response = client.send_command(f"CONFIG BACKUP list=all > {target}")
    except ServerError as exc:
        pytest.skip(f"backup not available on this appliance: {exc}")

    assert response.ret == 100
    assert target.stat().st_size > 1024
    assert not list(tmp_path.glob("*.part"))


# --- upload must not poison the session -------------------------------------


def test_commands_still_work_after_an_upload(client, tmp_path):
    """1.x left the multipart Content-Type on the session after an upload."""

    payload = tmp_path / "slot"
    payload.write_bytes(b"[Filter]\n pass from any to any\n")

    client.send_command(f"CONFIG SLOT UPLOAD slot=1 name=testUpload < {payload}")

    assert "Content-Type" not in client.headers
    response = client.send_command("SYSTEM PROPERTY")
    assert response.ret == 100
    assert response.format == "section"


# --- logging ----------------------------------------------------------------


def test_library_logs_under_its_own_namespace(client, caplog):
    with caplog.at_level(logging.DEBUG, logger="stormshield.sns.sslclient"):
        client.send_command("SYSTEM PROPERTY")

    assert caplog.records
    assert all(r.name.startswith("stormshield.sns.sslclient") for r in caplog.records)


# --- answer metadata --------------------------------------------------------


def test_paged_answer_reports_truncation(client, caplog):
    """`CONFIG OBJECT LIST` caps its rows while announcing the real total."""

    with caplog.at_level(logging.WARNING, logger="stormshield.sns.sslclient"):
        response = client.send_command("CONFIG OBJECT LIST type=host start=0")

    assert response.ret == 100
    if response.total is None:
        pytest.skip("this appliance does not announce a total")

    if response.count < response.total:
        assert response.truncated is True
        assert any("page with the command's start argument" in r.getMessage() for r in caplog.records)
    else:
        assert response.truncated is False


def test_paging_reaches_every_row(client):
    """Following `start` until `truncated` is False must yield `total` rows."""

    first = client.send_command("CONFIG OBJECT LIST type=host start=0")
    if first.total is None or not first.truncated:
        pytest.skip("nothing to page on this appliance")

    seen, start = first.count, first.count
    for _ in range(20):
        page = client.send_command(f"CONFIG OBJECT LIST type=host start={start}")
        if page.count == 0:
            break
        seen += page.count
        start += page.count
        if not page.truncated:
            break

    assert seen == first.total


def test_answer_without_metadata_is_not_truncated(client):
    response = client.send_command("SYSTEM PROPERTY")

    assert response.meta == {}
    assert response.total is None
    assert response.truncated is False


def test_json_round_trip_on_a_real_answer(client):
    import json

    response = client.send_command("CONFIG OBJECT LIST type=host start=0")

    assert json.loads(response.json()) == response.to_dict()
    with pytest.raises(TypeError):
        json.dumps(response.data)
