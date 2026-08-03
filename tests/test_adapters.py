"""SSL context construction.

`sslverifyhost=False` and the `ip=` option both mount an adapter that builds
its own SSL context. That context must trust the caller's bundle and nothing
else: `ssl.create_default_context()` with no `cafile` activates the system
trust store, which urllib3 then combines with the bundle, silently widening
the caller's CA pinning to every publicly trusted authority.
"""

from __future__ import annotations

import ssl

from stormshield.sns.sslclient import SSLClient
from stormshield.sns.sslclient.adapters import SNSHTTPSAdapter, _common_name_context

BUNDLE = SSLClient(host="fw", password="x", autoconnect=False).cabundle


def subjects(context: ssl.SSLContext) -> set[str]:
    names = set()
    for cert in context.get_ca_certs():
        fields = {k: v for rdn in cert["subject"] for k, v in rdn}
        names.add(fields.get("commonName") or fields.get("organizationalUnitName", ""))
    return names


# --- the context itself -----------------------------------------------------


def test_context_with_a_bundle_trusts_only_that_bundle():
    context = _common_name_context(BUNDLE)

    assert subjects(context) == {
        "NETASQ Firewall Certification Authority",
        "Stormshield Products Root CA",
    }


def test_context_without_a_bundle_loads_no_explicit_ca():
    """Peer verification is off in that case; urllib3 forces CERT_NONE."""

    assert _common_name_context(None).get_ca_certs() == []


def test_context_matches_the_common_name():
    """Factory certificates carry the serial in CN and have no subjectAltName."""

    context = _common_name_context(BUNDLE)

    assert context.hostname_checks_common_name is True
    assert context.check_hostname is False  # urllib3 does it via assert_hostname


def test_context_keeps_the_default_hardening():
    context = _common_name_context(BUNDLE)

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# --- the adapter ------------------------------------------------------------


def test_adapter_passes_the_bundle_to_its_context():
    adapter = SNSHTTPSAdapter(False, cafile=BUNDLE)

    assert subjects(adapter._ssl_pool_kwargs()["ssl_context"])


def test_adapter_disables_host_name_check():
    assert SNSHTTPSAdapter(False, cafile=BUNDLE)._ssl_pool_kwargs()["assert_hostname"] is False


def test_adapter_asserts_the_serial_for_a_factory_certificate():
    kwargs = SNSHTTPSAdapter("VMSNSX00000000A", cafile=BUNDLE)._ssl_pool_kwargs()

    assert kwargs["assert_hostname"] == "VMSNSX00000000A"
    assert "ssl_context" in kwargs  # a serial has no dot -> CN matching needed


def test_adapter_leaves_a_fqdn_to_the_standard_check():
    """A dotted name is a real host name, matched the usual way."""

    kwargs = SNSHTTPSAdapter("firewall.example.com", cafile=BUNDLE)._ssl_pool_kwargs()

    assert kwargs["assert_hostname"] == "firewall.example.com"
    assert "ssl_context" not in kwargs


# --- wiring from the client -------------------------------------------------


def mounted(client: SSLClient) -> SNSHTTPSAdapter:
    return next(a for a in client.session.adapters.values() if isinstance(a, SNSHTTPSAdapter))


def test_client_hands_its_bundle_to_the_adapter():
    client = SSLClient(host="fw", password="x", sslverifyhost=False, autoconnect=False)

    assert mounted(client)._cafile == client.cabundle


def test_client_passes_a_custom_bundle_through():
    client = SSLClient(
        host="fw", password="x", cabundle=BUNDLE, sslverifyhost=False, autoconnect=False
    )

    assert mounted(client)._cafile == BUNDLE


def test_no_bundle_when_peer_verification_is_disabled():
    client = SSLClient(
        host="fw", password="x", sslverifypeer=False, sslverifyhost=False, autoconnect=False
    )

    assert mounted(client)._cafile is None
    assert client.session.verify is False


def test_ip_option_also_pins_the_bundle():
    """`ip=` mounts the adapter too, and used to leak the system store as well."""

    client = SSLClient(host="VMSNSX00000000A", ip="10.0.0.254", password="x", autoconnect=False)
    adapter = mounted(client)

    assert adapter._cafile == client.cabundle
    assert adapter._assert_hostname == "VMSNSX00000000A"
