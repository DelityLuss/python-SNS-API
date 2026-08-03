"""
stormshield.sns.sslclient.client

This module contains the SSLClient class handling SNS API calls.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import platform
import re
from contextlib import suppress
from types import TracebackType
from typing import Any, ClassVar

import defusedxml.ElementTree as ElementTree
import requests
import requests.compat
import urllib3
from requests.adapters import HTTPAdapter
from requests_toolbelt.multipart.encoder import MultipartEncoder
from urllib3.util.retry import Retry

import stormshield.sns.crc as snscrc

from .__version__ import __version__
from .adapters import SNSHTTPSAdapter
from .exceptions import (
    AuthenticationError,
    FileError,
    MissingAuth,
    MissingCABundle,
    MissingHost,
    ServerError,
    TOTPNeededError,
)
from .response import Response

__all__ = ["SSLClient"]

logger = logging.getLogger(__name__)

# disable ssl warnings, we have --sslverify* for that
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# disable http warning 'Received response with both Content-Length and Transfer-Encoding set'
logging.getLogger(urllib3.__name__).setLevel(logging.ERROR)


class SSLClient:
    """SSL client to the SNS configuration API."""

    SSL_SERVERD_OK = 100
    SSL_SERVERD_REQUEST_ERROR = 200
    SSL_SERVERD_UNKNOWN_COMMAND = 201
    SSL_SERVERD_ERROR_COMMAND = 202
    SSL_SERVERD_INVALID_SESSION = 203
    SSL_SERVERD_EXPIRED_SESSION = 204
    SSL_SERVERD_AUTH_ERROR = 205
    SSL_SERVERD_PENDING_TRANSFER = 206
    SSL_SERVERD_PENDING_UPLOAD = 207
    SSL_SERVERD_OVERHEAT = 500
    SSL_SERVERD_UNREACHABLE = 501
    SSL_SERVERD_DISCONNECTED = 502
    SSL_SERVERD_INTERNAL_ERROR = 900

    SSL_SERVERD_MSG: ClassVar[dict[int, str]] = {
        SSL_SERVERD_REQUEST_ERROR: "Request error",
        SSL_SERVERD_UNKNOWN_COMMAND: "Unknown command",
        SSL_SERVERD_ERROR_COMMAND: "Command error",
        SSL_SERVERD_INVALID_SESSION: "Invalid session",
        SSL_SERVERD_EXPIRED_SESSION: "Expired session",
        SSL_SERVERD_AUTH_ERROR: "Authentication error",
        SSL_SERVERD_PENDING_TRANSFER: "Pending transfer",
        SSL_SERVERD_PENDING_UPLOAD: "Upload pending",
        SSL_SERVERD_OVERHEAT: "Server overheat",
        SSL_SERVERD_UNREACHABLE: "Server unreachable",
        SSL_SERVERD_DISCONNECTED: "Server disconnected",
        SSL_SERVERD_INTERNAL_ERROR: "Internal error",
    }

    SRV_RET_OK = 100
    SRV_RET_DOWNLOAD = 101
    SRV_RET_UPLOAD = 102
    SRV_RET_LASTCMD = 103
    SRV_RET_MUSTREBOOT = 104
    SRV_RET_WARNING = 110
    SRV_RET_MULTIWARN = 111
    SRV_RET_COMMAND = 200
    SRV_RET_MULTILINE = 201
    SRV_RET_AUTHFAILED = 202
    SRV_RET_IDLE = 203
    SRV_RET_AUTHLIMIT = 204
    SRV_RET_AUTHLEVEL = 205
    SRV_RET_LICENCE = 206

    SERVERD_WAIT_DOWNLOAD = "00a01c00"
    SERVERD_WAIT_UPLOAD = "00a00300"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    NEED_TOTP_AUTH = "NEED_TOTP_AUTH"
    ERR_BRUTEFORCE = "ERR_BRUTEFORCE"

    fileregexp = re.compile(r'^(?P<cmd>.+?)\s*[<>]\s*(?!.*\")(?P<file>.*?)$')

    #: ``start=`` argument of the paged listing commands, used to know which
    #: slice of the rows an answer covers.
    startregexp = re.compile(r"(?:^|\s)start=(?P<start>\d+)\b", re.IGNORECASE)

    CHUNK_SIZE = 65536  # bytes

    #: Default connect/read timeout, so a silent appliance cannot hang forever.
    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        user: str = "admin",
        password: str | None = None,
        totp: str | None = None,
        host: str | None = None,
        ip: str | None = None,
        port: int = 443,
        cabundle: str | None = None,
        sslverifypeer: bool = True,
        sslverifyhost: bool = True,
        credentials: str | None = None,
        usercert: str | None = None,
        autoconnect: bool = True,
        proxy: str | None = None,
        timeout: float | tuple[float, float] | None = DEFAULT_TIMEOUT,
        retries: int = 2,
    ) -> None:
        """:class:`SSLClient <SSLClient>` constructor.

        :param user: Optional user name.
        :param password: Optional password.
        :param totp: Optional time-based one time password.
        :param host: hostname to connect or certificate common name (appliance serial).
        :param ip: Optional ip address to connect.
        :param port: Optional port number.
        :param cabundle: Optional certificat authorities bundle file in PEM format.
        :param sslverifypeer: Optional boolean to verify remote certificate authority.
        :param sslverifyhost: Optional boolean to verify remote certificate common name.
        :param credentials: Optional list of requested privileges.
        :param usercert: Optional user certificate.
        :param autoconnect: Connect to the appliance at initialization
        :param proxy: https proxy url (socks5://user:pass@host:port  http://user:password@host/)
        :param timeout: connection and read timeout in seconds, ``None`` to wait forever
        :param retries: number of retries on connection failure. Only connection
            establishment is retried; a command that reached the appliance is
            never replayed, as API commands are not idempotent.
        """

        self.user = user
        self.password = password
        self.totp = totp
        self.ip = ip
        self.port = port
        self.app = "sslclient"
        self.sslverifypeer = sslverifypeer
        self.sslverifyhost = sslverifyhost
        self.credentials = credentials
        self.usercert = usercert
        self.sessionid = ""
        self.protocol = ""
        self.sessionlevel = ""
        self.dl_size = 0
        self.dl_crc = ""
        self.autoconnect = autoconnect
        self.proxy = proxy
        self.conn_options: dict[str, Any] = {}
        self._connected = False

        if host is None:
            raise MissingHost("Host parameter must be provided")
        if password is None and usercert is None:
            raise MissingAuth("Password parameter must be provided")
        if password is None and totp is not None:
            raise MissingAuth("Password parameter must be provided when totp parameter is provided")
        if usercert is not None and not os.path.isfile(usercert):
            raise MissingAuth("User certificate not found")
        if cabundle is None:
            # use default cabundle
            cabundle = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "bundle.ca"))
        if not os.path.isfile(cabundle):
            raise MissingCABundle("Certificate authority bundle not found")

        # assigned once validated, so both are known to be set from here on
        self.host = host
        self.cabundle = cabundle

        self.baseurl = f"https://{self._urlhost(self.host)}:{self.port}"

        self.headers = {
            "Accept-Encoding": "identity",
            "user-agent": f"stormshield.sns.sslclient/{__version__} ({platform.platform()})",
        }

        # Retry connection failures only: replaying a request that already
        # reached the appliance could apply a configuration command twice.
        retry = Retry(
            total=retries,
            connect=retries,
            read=False,
            # `other` covers the errors urllib3 classifies as neither connect
            # nor read (TLS record errors, for one). Leaving it to `total`
            # would replay a request that already reached the appliance.
            other=0,
            status=0,
            redirect=0,
            backoff_factor=0.3,
            allowed_methods=None,
        )

        self.session = requests.Session()
        self.session.verify = self.cabundle if self.sslverifypeer else False

        # the adapters build their own SSL context, so they need the bundle:
        # without it they would fall back to the system trust store on top of
        # the caller's, widening the set of accepted authorities
        cafile = self.cabundle if self.sslverifypeer else None

        if self.ip is not None:
            # connect to the ip, but keep checking the certificate against the
            # appliance name the caller asked for
            self.baseurl = f"https://{self._urlhost(self.ip)}:{self.port}"

        adapter: HTTPAdapter
        if not self.sslverifyhost:
            adapter = SNSHTTPSAdapter(False, cafile=cafile, max_retries=retry)
        elif self.ip is not None:
            adapter = SNSHTTPSAdapter(self.host, cafile=cafile, max_retries=retry)
        else:
            adapter = HTTPAdapter(max_retries=retry)

        # a single adapter, mounted on the url actually used: mounting one per
        # option would let the last one win and silently drop the others,
        # retries included
        self.session.mount(self.baseurl.lower(), adapter)

        if self.usercert is not None:
            self.session.cert = self.usercert

        if self.proxy:
            self.session.proxies = {"https": self.proxy}

        if timeout is not None:
            self.conn_options = {"timeout": timeout}

        #: Kept for backward compatibility, prefer the module level ``logger``.
        self.logger = logger

        if self.autoconnect:
            self.connect()

    @staticmethod
    def _urlhost(host: str) -> str:
        """Bracket ``host`` if it is an IPv6 literal."""

        try:
            ipaddress.IPv6Address(host)
        except ipaddress.AddressValueError:
            return host
        return f"[{host}]"

    @staticmethod
    def get_completer() -> str:
        """Get the path to the installed cmd.complete file."""

        return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "cmd.complete"))

    def __enter__(self) -> SSLClient:
        if not self._connected:
            self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    def connect(self) -> None:
        """Connect to the server."""

        logger.info(
            "Connecting to %s on port %d with user %s%s",
            self.host,
            self.port,
            self.user,
            f" (proxy {self.proxy})" if self.proxy else "",
        )

        # 1. Authentication and get cookie
        if self.usercert is not None:
            # user cert authentication
            logger.debug("Authentication with SSL certificate")
            request = self.session.get(
                self.baseurl + f"/auth/admin.html?sslcert=1&app={self.app}",
                headers=self.headers,
                **self.conn_options,
            )
        else:
            # password authentication
            logger.debug("Authentication with user/password")
            if self.password is None:
                raise MissingAuth("Password parameter must be provided")
            data = {
                "uid": base64.b64encode(self.user.encode("utf-8")),
                "pswd": base64.b64encode(self.password.encode("utf-8")),
                "app": self.app,
            }

            if self.totp is not None:
                data["totp"] = base64.b64encode(self.totp.encode("utf-8"))

            request = self.session.post(
                self.baseurl + "/auth/admin.html",
                data,
                headers=self.headers,
                **self.conn_options,
            )

        logger.debug("%s", request.text)

        try:
            nws_node = ElementTree.fromstring(request.content)
            msg = nws_node.attrib["msg"]
        except (ElementTree.ParseError, KeyError) as exc:
            raise ServerError("Can't decode authentication result") from exc

        if msg == self.ERR_BRUTEFORCE:
            delay = nws_node.attrib.get("delay", "?")
            raise AuthenticationError("Brut force detected, try again after " + delay + " seconds.")
        if msg == self.NEED_TOTP_AUTH:
            raise TOTPNeededError("TOTP is needed")
        if msg != self.AUTH_SUCCESS:
            raise AuthenticationError("Authentication failed")

        # 2. Serverd session
        login: dict[str, Any] = {"app": self.app, "id": 0}
        if self.credentials is not None:
            login["reqlevel"] = self.credentials
        request = self.session.post(
            self.baseurl + "/api/auth/login",
            data=login,
            headers=self.headers,
            **self.conn_options,
        )

        logger.debug("%s", request.text)

        if request.status_code != requests.codes.OK:
            raise ServerError("can't get serverd session")

        nws_node = ElementTree.fromstring(request.content)
        ret = int(nws_node.attrib["code"])
        msg = nws_node.attrib["msg"]

        if ret != self.SSL_SERVERD_OK:
            raise ServerError(f"ERROR: {ret} {msg}")

        try:
            self.sessionid = nws_node.find("sessionid").text
            self.protocol = nws_node.find("protocol").text
            self.sessionlevel = nws_node.find("sessionlevel").text
        except AttributeError as exception:
            raise ServerError("Malformed answer: incomplete serverd session") from exception
        self._connected = True

        logger.debug("Session ID: %s", self.sessionid)
        logger.debug("Protocol: %s", self.protocol)
        logger.debug("Session level: %s", self.sessionlevel)

    def disconnect(self) -> None:
        """Disconnect from the server. Calling it twice is a no-op."""

        if not self._connected:
            return
        self._connected = False

        try:
            request = self.session.get(
                self.baseurl + "/api/auth/logout?sessionid=" + self.sessionid,
                headers=self.headers,
                **self.conn_options,
            )
        except requests.RequestException as exception:
            logger.error("Disconnect failed: %s", exception)
        else:
            if request.status_code == requests.codes.OK:
                logger.info("Disconnected from %s", self.host)
            else:
                logger.error("Disconnect failed")
        finally:
            self.session.close()

    def nws_parse(self, code: int) -> None:
        """Parse server response."""

        if code == self.SSL_SERVERD_OK:
            return

        if code == self.SSL_SERVERD_AUTH_ERROR:
            raise AuthenticationError(self.SSL_SERVERD_MSG[code])
        if code in self.SSL_SERVERD_MSG:
            raise ServerError(self.SSL_SERVERD_MSG[code])
        raise ServerError("Unknown error")

    def send_command(self, command: str, **conn_options: Any) -> Response:
        """Execute a NSRPC command on the remote appliance.

        :param command: SNS API command. Files can be uploaded by adding '< filename'
            at the end of the command. Downloads are handled with '> filename'.
        :return: :class:`Response <Response>` object
        :rtype: stormshield.sns.sslclient.Response
        """

        # overload connection options
        for key, value in self.conn_options.items():
            conn_options.setdefault(key, value)

        filename = None
        result = self.fileregexp.match(command)
        if result:
            command = result.group("cmd")
            filename = result.group("file")

        request = self.session.get(
            self.baseurl
            + "/api/command?sessionid="
            + self.sessionid
            + "&cmd="
            + requests.compat.quote(command.encode("utf-8")),  # manually done since we need %20 encoding
            headers=self.headers,
            **conn_options,
        )

        logger.debug("%s", request.text)

        if request.status_code != requests.codes.OK:
            raise ServerError(f"HTTP error {request.status_code}")

        nws_node = ElementTree.fromstring(request.content)
        self.nws_parse(int(nws_node.attrib["code"]))

        try:
            response = Response.from_tree(nws_node, request.text)
        except ValueError as exception:
            raise ServerError(str(exception)) from exception

        offset = self.startregexp.search(command)
        if offset:
            response.offset = int(offset.group("start"))

        if response.truncated:
            logger.warning(
                "%s: rows %s-%s of %s returned, page with the command's start argument "
                "(response.truncated, response.total)",
                command,
                response.offset or 0,
                (response.offset or 0) + (response.count or 0),
                response.total if response.total is not None else "?",
            )

        if response.serverd_code == self.SERVERD_WAIT_UPLOAD:
            if filename:
                return self.upload(filename)
            return response

        if response.serverd_code == self.SERVERD_WAIT_DOWNLOAD:
            self._read_download_header(nws_node[0])
            if filename:
                return self.download(filename)

        return response

    def _read_download_header(self, serverd: Any) -> None:
        """Keep the announced size and crc for further verification."""

        data = serverd.find("data")
        if data is None:
            raise ServerError("Malformed answer: missing download header")

        try:
            if data.get("format") == "section":
                # <data format="section"><section title="Result">
                #   <key name="format" value="base64,crc=923B2C86,size=952"/>
                key = data.find("section").find("key")
                values = key.get("value").split(",")
                self.dl_size = int(values[2].split("=")[1])
                self.dl_crc = values[1].split("=")[1]
            else:
                # <data format="raw"><crc>439B852</crc><size>5096
                self.dl_size = int(data.find("size").text)
                self.dl_crc = data.find("crc").text
        except (AttributeError, IndexError, TypeError, ValueError) as exception:
            raise ServerError("Malformed answer: invalid download header") from exception

    def download(self, filename: str) -> Response:
        """Handle file download.

        The payload is written to a temporary file next to ``filename`` and
        only moved into place once its size and CRC have been verified, so a
        failed transfer never leaves a corrupted file behind.
        """

        request = self.session.get(
            self.baseurl + "/api/download/tmp.file?sessionid=" + self.sessionid,
            headers=self.headers,
            stream=True,
            **self.conn_options,
        )

        if request.status_code != requests.codes.OK:
            raise ServerError(f"HTTP error {request.status_code}")

        partial = filename + ".part"
        size = 0
        crc = snscrc.CRC32_init
        try:
            with open(partial, "wb") as savefile:
                for chunk in request.iter_content(self.CHUNK_SIZE):
                    savefile.write(chunk)
                    size += len(chunk)
                    crc = snscrc.update_crc32(chunk, crc)
        except requests.RequestException:
            # RequestException derives from OSError: without this clause a
            # transport failure would be reported as a local file error
            self._unlink(partial)
            raise
        except OSError as exception:
            self._unlink(partial)
            logger.error("%s", exception)
            raise FileError("Can't save file") from exception
        except BaseException:
            self._unlink(partial)
            raise

        try:
            if size != self.dl_size:
                raise ServerError(
                    f"Download error: {size} bytes downloaded, expecting {self.dl_size} bytes"
                )

            crc_hex = format(crc, "X")
            if crc_hex != self.dl_crc:
                raise ServerError(f"Download error: crc {crc_hex}, expecting {self.dl_crc}")

            os.replace(partial, filename)
        except BaseException:
            self._unlink(partial)
            raise

        return Response(
            ret=100,
            code="00a00100",
            msg="OK",
            output='100 code=00a00100 msg="Ok"',
            xml='<?xml version="1.0" ?><nws code="100" msg="OK">'
            '<serverd code="00a00100" msg="Ok" ret="100"/></nws>',
        )

    @staticmethod
    def _unlink(path: str) -> None:
        with suppress(OSError):
            os.unlink(path)

    def upload(self, filename: str) -> Response:
        """Handle file upload."""

        with open(filename, "rb") as uploadh:
            data = MultipartEncoder(fields={"upload": uploadh})
            # copy: mutating self.headers would leak the multipart content type
            # into every later request of this session
            headers = {**self.headers, "Content-Type": data.content_type}

            request = self.session.post(
                self.baseurl + "/api/upload?sessionid=" + self.sessionid,
                headers=headers,
                data=data,
                **self.conn_options,
            )

        if request.status_code != requests.codes.OK:
            raise ServerError(f"HTTP error {request.status_code}")

        nws_node = ElementTree.fromstring(request.content)
        self.nws_parse(int(nws_node.attrib["code"]))

        try:
            return Response.from_tree(nws_node, request.text)
        except ValueError as exception:
            raise ServerError(str(exception)) from exception
