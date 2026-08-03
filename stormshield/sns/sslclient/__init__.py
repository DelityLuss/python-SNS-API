"""
stormshield.sns.sslclient
~~~~~~~~~~~~~~~~~~~~~~~~~

SSL API client for Stormshield Network Security appliances.

    >>> from stormshield.sns.sslclient import SSLClient
    >>> with SSLClient(host="10.0.0.254", user="admin", password="pass") as client:
    ...     response = client.send_command("SYSTEM PROPERTY")
    ...     print(response.data["Result"]["Version"])
"""

from __future__ import annotations

from .__version__ import __version__
from .adapters import SNSHTTPSAdapter
from .client import SSLClient
from .exceptions import (
    AuthenticationError,
    FileError,
    MissingAuth,
    MissingCABundle,
    MissingHost,
    ServerError,
    SNSError,
    TOTPNeededError,
)
from .response import Response, format_output, quote, render_output

__all__ = [
    "AuthenticationError",
    "FileError",
    "MissingAuth",
    "MissingCABundle",
    "MissingHost",
    "Response",
    "SNSError",
    "SNSHTTPSAdapter",
    "SSLClient",
    "ServerError",
    "TOTPNeededError",
    "__version__",
    "format_output",
    "quote",
    "render_output",
]
