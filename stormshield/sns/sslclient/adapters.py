"""
stormshield.sns.sslclient.adapters

HTTP adapter used to check the peer certificate against an appliance name
instead of the URL host name.

Appliances shipped with their factory certificate carry the serial number in
the ``CN`` field only, with no ``subjectAltName``. Python refuses to match
those by default, so hostname verification is delegated to urllib3's
``assert_hostname`` with an SSL context that opts back into CN matching.
"""

from __future__ import annotations

import ssl
from typing import Any

from requests.adapters import HTTPAdapter

__all__ = ["SNSHTTPSAdapter"]


def _common_name_context(cafile: str | None = None) -> ssl.SSLContext:
    """SSL context matching the peer against the certificate ``CN`` field.

    ``cafile`` must be the bundle the caller asked to trust. Passing it keeps
    :func:`ssl.create_default_context` from falling back to the system trust
    store, which urllib3 would then combine with the bundle: the caller's CA
    pinning would silently widen to every publicly trusted authority.
    """

    context = ssl.create_default_context(cafile=cafile)
    context.hostname_checks_common_name = True  # factory Stormshield certificates
    context.check_hostname = False  # done by urllib3 via assert_hostname
    return context


class SNSHTTPSAdapter(HTTPAdapter):
    """Verify the peer certificate name against ``assert_hostname``.

    :param assert_hostname: name the peer certificate must match, or ``False``
        to disable host name verification entirely.
    :param cafile: the only certificate authority bundle to trust, or ``None``
        when peer verification is disabled.
    """

    def __init__(self, assert_hostname: str | bool, cafile: str | None = None, **kwargs: Any) -> None:
        self._assert_hostname = assert_hostname
        self._cafile = cafile
        # A name without a dot is an appliance serial, i.e. a factory
        # certificate that only carries it in CN.
        self._needs_cn_match = assert_hostname is False or "." not in str(assert_hostname)
        super().__init__(**kwargs)

    def _ssl_pool_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"assert_hostname": self._assert_hostname}
        if self._needs_cn_match:
            kwargs["ssl_context"] = _common_name_context(self._cafile)
        return kwargs

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs.update(self._ssl_pool_kwargs())
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        if proxy not in self.proxy_manager:
            proxy_kwargs.update(self._ssl_pool_kwargs())
        return super().proxy_manager_for(proxy, **proxy_kwargs)
