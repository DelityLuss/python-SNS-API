"""Connection and authentication modes against a real appliance.

Each test skips on its own unless the matching environment variables are set::

    APPLIANCE   ip/hostname of a running SNS appliance   (all tests)
    PASSWORD    appliance password                       (all but the cert test)
    SERIAL      appliance serial, i.e. certificate CN    (host name check)
    FQDN        appliance fqdn                           (cabundle tests)
    CABUNDLE    CA bundle file in PEM format             (cabundle tests)
    CERT        user certificate file                    (certificate auth)
    PROXY       proxy url                                (proxy test)
"""

from __future__ import annotations

import os

import pytest

from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv("APPLIANCE") or os.getenv("SNS_URL", "")
PASSWORD = os.getenv("PASSWORD") or os.getenv("SNS_PASSWORD", "")
USER = os.getenv("USER_SNS") or os.getenv("SNS_USER", "admin")
SERIAL = os.getenv("SERIAL", "")
FQDN = os.getenv("FQDN", "")
CABUNDLE = os.getenv("CABUNDLE", "")
CERT = os.getenv("CERT", "")
PROXY = os.getenv("PROXY", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not APPLIANCE, reason="APPLIANCE/SNS_URL must point at a running SNS appliance"),
]

needs_password = pytest.mark.skipif(not PASSWORD, reason="PASSWORD/SNS_PASSWORD must be set")


def check(client: SSLClient) -> None:
    """A connected client must answer a trivial command."""

    try:
        assert client.send_command("LIST").ret == 100
    finally:
        client.disconnect()


@needs_password
@pytest.mark.skipif(not SERIAL, reason="SERIAL must be set to the appliance serial number")
def test_host_name_check_against_the_certificate_cn():
    """Factory certificates carry the serial in CN and have no subjectAltName."""

    check(
        SSLClient(
            host=SERIAL, ip=APPLIANCE, user=USER, password=PASSWORD,
            sslverifyhost=True, sslverifypeer=os.getenv("SSLVERIFYPEER", "0") == "1",
        )
    )


@needs_password
def test_host_name_check_can_be_disabled():
    check(
        SSLClient(
            host=APPLIANCE, user=USER, password=PASSWORD,
            sslverifyhost=False, sslverifypeer=False,
        )
    )


@needs_password
def test_untrusted_ca_is_rejected_by_default():
    """sslverifypeer defaults to True, so an unknown CA must fail."""

    import requests

    with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
        SSLClient(host=APPLIANCE, user=USER, password=PASSWORD)


@needs_password
@pytest.mark.skipif(not (FQDN and CABUNDLE), reason="FQDN and CABUNDLE must be set")
def test_cabundle():
    check(
        SSLClient(
            host=FQDN, ip=APPLIANCE, user=USER, password=PASSWORD,
            sslverifyhost=True, cabundle=CABUNDLE,
        )
    )


@pytest.mark.skipif(not (FQDN and CABUNDLE and CERT), reason="FQDN, CABUNDLE and CERT must be set")
def test_user_certificate_authentication():
    check(SSLClient(host=FQDN, ip=APPLIANCE, usercert=CERT, sslverifyhost=True, cabundle=CABUNDLE))


@needs_password
@pytest.mark.skipif(not PROXY, reason="PROXY must be set to a proxy url")
def test_proxy():
    check(
        SSLClient(
            host=APPLIANCE, user=USER, password=PASSWORD,
            sslverifypeer=False, sslverifyhost=False, proxy=PROXY,
        )
    )


@needs_password
def test_wrong_password_is_rejected():
    from stormshield.sns.sslclient import AuthenticationError

    with pytest.raises(AuthenticationError):
        SSLClient(
            host=APPLIANCE, user=USER, password=PASSWORD + "-wrong",
            sslverifyhost=False, sslverifypeer=False,
        )
