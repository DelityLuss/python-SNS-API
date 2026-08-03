"""
stormshield.sns.sslclient.exceptions

Exceptions raised by the SNS API client. They all derive from
:class:`SNSError`, so callers can catch the whole family at once.
"""

from __future__ import annotations

__all__ = [
    "AuthenticationError",
    "FileError",
    "MissingAuth",
    "MissingCABundle",
    "MissingHost",
    "SNSError",
    "ServerError",
    "TOTPNeededError",
]


class SNSError(Exception):
    """Base class of every error raised by this library."""


class MissingHost(SNSError, ValueError):
    """The remote host is missing."""


class MissingAuth(SNSError, ValueError):
    """Password or user certificate is missing."""


class MissingCABundle(SNSError, ValueError):
    """The certificate authority bundle is missing."""


class TOTPNeededError(SNSError):
    """Time-based one time password needed."""


class AuthenticationError(SNSError):
    """Authentication failed."""


class ServerError(SNSError):
    """NWS server error."""


class FileError(SNSError):
    """File access error."""
