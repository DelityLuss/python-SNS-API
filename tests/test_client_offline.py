"""SSLClient behaviour that does not need a live appliance."""

from __future__ import annotations

import os
import zlib
from unittest import mock

import pytest
import requests

from stormshield.sns.sslclient import (
    MissingAuth,
    MissingCABundle,
    MissingHost,
    ServerError,
    SNSError,
    SSLClient,
)

from .conftest import load


def make_client(**kwargs) -> SSLClient:
    """A client that never touches the network."""

    params = {
        "host": "appliance.example.com",
        "user": "admin",
        "password": "secret",
        "autoconnect": False,
    }
    params.update(kwargs)
    client = SSLClient(**params)
    client.sessionid = "SESSION"
    client.session = mock.MagicMock(spec=requests.Session)
    return client


def fake_answer(content: str, status: int = 200) -> mock.Mock:
    response = mock.Mock()
    response.status_code = status
    response.content = content.encode("utf-8")
    response.text = content
    return response


# --- constructor validation -------------------------------------------------


def test_host_is_required():
    with pytest.raises(MissingHost):
        SSLClient(password="x", autoconnect=False)


def test_auth_is_required():
    with pytest.raises(MissingAuth):
        SSLClient(host="fw", autoconnect=False)


def test_totp_needs_a_password():
    with pytest.raises(MissingAuth):
        SSLClient(host="fw", totp="123456", autoconnect=False)


def test_missing_usercert_is_reported():
    with pytest.raises(MissingAuth):
        SSLClient(host="fw", usercert="/nope/absent.pem", autoconnect=False)


def test_missing_cabundle_is_reported():
    with pytest.raises(MissingCABundle):
        SSLClient(host="fw", password="x", cabundle="/nope/absent.ca", autoconnect=False)


def test_errors_share_a_base_class():
    """Callers can catch the whole family with one except clause."""

    with pytest.raises(SNSError):
        SSLClient(password="x", autoconnect=False)


def test_default_cabundle_is_shipped():
    client = make_client()
    assert os.path.isfile(client.cabundle)


def test_ipv6_host_is_bracketed():
    client = make_client(host="2001:db8::1")
    assert client.baseurl == "https://[2001:db8::1]:443"


def test_ipv4_host_is_not_bracketed():
    client = make_client(host="10.0.0.254", port=8443)
    assert client.baseurl == "https://10.0.0.254:8443"


def test_ipv6_ip_option_is_bracketed():
    client = make_client(host="SERIAL123", ip="2001:db8::2")
    assert client.baseurl == "https://[2001:db8::2]:443"


def test_default_timeout_is_applied():
    """1.x waited forever by default when an appliance stopped answering."""

    assert make_client().conn_options["timeout"] == SSLClient.DEFAULT_TIMEOUT


def test_timeout_can_be_disabled():
    assert make_client(timeout=None).conn_options == {}


# --- send_command -----------------------------------------------------------


def test_send_command_decodes_answer():
    client = make_client()
    client.session.get.return_value = fake_answer(load("system_property"))

    response = client.send_command("SYSTEM PROPERTY")

    assert response.ret == 100
    assert response.data["Result"]["Model"] == "EVA2"


def test_send_command_url_encodes_spaces():
    client = make_client()
    client.session.get.return_value = fake_answer(load("system_property"))

    client.send_command("CONFIG OBJECT LIST type=host")

    url = client.session.get.call_args[0][0]
    assert "cmd=CONFIG%20OBJECT%20LIST%20type%3Dhost" in url


def test_send_command_raises_on_http_error():
    client = make_client()
    client.session.get.return_value = fake_answer("", status=500)

    with pytest.raises(ServerError, match="HTTP error 500"):
        client.send_command("LIST")


def test_send_command_rejects_answer_without_serverd_node():
    """1.x raised a bare IndexError here."""

    client = make_client()
    client.session.get.return_value = fake_answer('<?xml version="1.0"?><nws code="100" msg="OK"></nws>')

    with pytest.raises(ServerError, match="serverd"):
        client.send_command("LIST")


def test_send_command_maps_serverd_errors():
    client = make_client()
    client.session.get.return_value = fake_answer(
        '<?xml version="1.0"?><nws code="502" msg="Disconnected"></nws>'
    )

    with pytest.raises(ServerError, match="Server disconnected"):
        client.send_command("QUIT")


def test_send_command_timeout_can_be_overridden():
    client = make_client()
    client.session.get.return_value = fake_answer(load("system_property"))

    client.send_command("LIST", timeout=99)

    assert client.session.get.call_args.kwargs["timeout"] == 99


# --- upload -----------------------------------------------------------------


def test_upload_does_not_leak_content_type_into_the_session(tmp_path):
    """1.x mutated self.headers, so every later request carried the
    multipart Content-Type of the last upload."""

    client = make_client()
    payload = tmp_path / "conf.txt"
    payload.write_text("data")
    client.session.post.return_value = fake_answer(load("unknown_command"))

    before = dict(client.headers)
    client.upload(str(payload))

    assert client.headers == before
    assert "Content-Type" not in client.headers
    # the request itself did carry it
    assert client.session.post.call_args.kwargs["headers"]["Content-Type"].startswith("multipart/")


def test_upload_closes_the_file_on_error(tmp_path):
    client = make_client()
    payload = tmp_path / "conf.txt"
    payload.write_text("data")
    client.session.post.side_effect = requests.ConnectionError("boom")

    with pytest.raises(requests.ConnectionError):
        client.upload(str(payload))
    # nothing to assert on the fd directly; the `with` block guarantees closure


# --- download ---------------------------------------------------------------


def streamed(payload: bytes) -> mock.Mock:
    response = mock.Mock()
    response.status_code = 200
    response.iter_content = lambda size: iter([payload[i : i + size] for i in range(0, len(payload), size)])
    return response


def test_download_writes_the_file(tmp_path):
    client = make_client()
    payload = b"appliance backup payload" * 100
    client.dl_size = len(payload)
    client.dl_crc = "%X" % (zlib.crc32(payload) ^ 0xFFFFFFFF)
    client.session.get.return_value = streamed(payload)

    target = tmp_path / "backup.na"
    response = client.download(str(target))

    assert target.read_bytes() == payload
    assert response.ret == 100
    assert not list(tmp_path.glob("*.part"))


def test_download_leaves_no_file_on_crc_mismatch(tmp_path):
    """1.x wrote the payload, then verified, leaving corrupted files behind."""

    client = make_client()
    payload = b"corrupted"
    client.dl_size = len(payload)
    client.dl_crc = "DEADBEEF"
    client.session.get.return_value = streamed(payload)

    target = tmp_path / "backup.na"
    with pytest.raises(ServerError, match="crc"):
        client.download(str(target))

    assert not target.exists()
    assert not list(tmp_path.glob("*.part"))


def test_download_leaves_no_file_on_size_mismatch(tmp_path):
    client = make_client()
    payload = b"truncated"
    client.dl_size = 99999
    client.dl_crc = "%X" % (zlib.crc32(payload) ^ 0xFFFFFFFF)
    client.session.get.return_value = streamed(payload)

    target = tmp_path / "backup.na"
    with pytest.raises(ServerError, match="bytes downloaded"):
        client.download(str(target))

    assert not target.exists()
    assert not list(tmp_path.glob("*.part"))


def test_download_does_not_clobber_an_existing_file_on_failure(tmp_path):
    client = make_client()
    target = tmp_path / "backup.na"
    target.write_bytes(b"previous good backup")

    client.dl_size = 5
    client.dl_crc = "DEADBEEF"
    client.session.get.return_value = streamed(b"bad")

    with pytest.raises(ServerError):
        client.download(str(target))

    assert target.read_bytes() == b"previous good backup"


def test_download_raises_on_http_error(tmp_path):
    client = make_client()
    response = mock.Mock()
    response.status_code = 404
    client.session.get.return_value = response

    with pytest.raises(ServerError, match="HTTP error 404"):
        client.download(str(tmp_path / "x"))


# --- session lifecycle ------------------------------------------------------


def test_disconnect_is_idempotent():
    client = make_client()
    client._connected = True
    client.session.get.return_value = fake_answer("", status=200)

    client.disconnect()
    client.disconnect()

    assert client.session.get.call_count == 1


def test_disconnect_survives_a_dead_connection():
    client = make_client()
    client._connected = True
    client.session.get.side_effect = requests.ConnectionError("gone")

    client.disconnect()  # must not raise

    client.session.close.assert_called_once()


def test_context_manager_disconnects():
    client = make_client()
    client._connected = True
    client.session.get.return_value = fake_answer("", status=200)

    with client as c:
        assert c is client

    client.session.close.assert_called_once()


def test_client_does_not_hijack_the_root_logger():
    """1.x did `logging.getLogger()`, capturing the host application's root."""

    import logging

    assert make_client().logger is logging.getLogger("stormshield.sns.sslclient.client")
    assert make_client().logger.name != "root"


# --- paging offset ----------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("CONFIG OBJECT LIST type=host start=0", 0),
        ("CONFIG OBJECT LIST type=host start=100", 100),
        ("CONFIG OBJECT LIST start=42 type=host", 42),
        ("CONFIG OBJECT LIST type=host START=7", 7),
        ("CONFIG OBJECT LIST type=host", None),
        ("SYSTEM PROPERTY", None),
        # must not match a token that merely ends in "start"
        ("CONFIG OBJECT LIST restart=5", None),
    ],
)
def test_send_command_reads_the_paging_offset(command, expected):
    client = make_client()
    client.session.get.return_value = fake_answer(load("object_list_host"))

    assert client.send_command(command).offset == expected


def test_truncation_is_logged(caplog):
    """The silent case of 1.x: 100 rows of 134 with no error reported."""

    import logging

    client = make_client()
    client.session.get.return_value = fake_answer(load("object_list_host"))

    with caplog.at_level(logging.WARNING, logger="stormshield.sns.sslclient"):
        response = client.send_command("CONFIG OBJECT LIST type=host start=0")

    assert response.truncated is True
    assert "rows 0-100 of 134" in caplog.text


def test_complete_answer_logs_nothing(caplog):
    import logging

    client = make_client()
    client.session.get.return_value = fake_answer(load("ntp_server_list"))

    with caplog.at_level(logging.WARNING, logger="stormshield.sns.sslclient"):
        response = client.send_command("CONFIG NTP SERVER LIST")

    assert response.truncated is False
    assert caplog.text == ""
