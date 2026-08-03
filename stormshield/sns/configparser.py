"""
stormshield.sns.configparser

This module handles SNS API responses and extracts section/token/values
in ini/section format.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from requests.structures import CaseInsensitiveDict

logger = logging.getLogger(__name__)

__all__ = ["ConfigParser", "serialize", "unquote"]


def unquote(value: Any) -> Any:
    """Remove the surrounding double quotes of ``value`` if present."""

    if isinstance(value, str) and len(value) > 1 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def serialize(data: Any) -> Any:
    """Recursively convert :class:`CaseInsensitiveDict` into plain dicts."""

    if isinstance(data, CaseInsensitiveDict):
        return {k: serialize(v) for k, v in data.items()}
    if isinstance(data, list):
        return [serialize(v) for v in data]
    return data


class ConfigParser:
    """A class to parse section format from SNS API responses."""

    SERVERD_HEAD_RE = re.compile(r'^\d{3} code=.* msg=.* format="(.*?)"')
    SERVERD_TAIL_RE = re.compile(r"^\d{3} code=.*? msg=.*?")
    SECTION_RE = re.compile(r"^\s*\[\s*(.+?)\s*\]\s*$")
    EMPTY_RE = re.compile(r"^\s*$")

    #: ``token=value`` pairs, where a value is either double quoted or
    #: runs up to the next whitespace. Replaces the per-line :mod:`shlex`
    #: lexer, which needed a hand-maintained ``wordchars`` allow-list.
    _PAIR_RE = re.compile(r'(?:^|\s)(?P<token>[^\s="]+)=(?P<value>"[^"]*"|\S*)')

    def __init__(self, text: str | None) -> None:
        """Load a section from text."""

        self.data: Any = CaseInsensitiveDict()
        self.format: str | None = None

        lines = (text or "").splitlines()
        if not lines:
            return

        # strip serverd headers if needed
        match = self.SERVERD_HEAD_RE.match(lines[0])
        if match:
            del lines[0]
            self.format = match.group(1)
        if lines and self.SERVERD_TAIL_RE.match(lines[-1]):
            del lines[-1]

        text = "\n".join(lines)

        if self.format in ("raw", "xml"):
            # plain data, no parsing
            self.data = text
            return

        section = "Result"  # default section
        for line in lines:
            # comment
            if line.startswith("#"):
                continue

            # empty lines
            if self.EMPTY_RE.match(line):
                continue

            # section header
            match = self.SECTION_RE.match(line)
            if match:
                section = match.group(1)
                # anything but list/section_line is parsed as token=value below,
                # so the section must be a dict there too
                if self.format in ("list", "section_line"):
                    self.data[section] = []
                else:
                    self.data[section] = CaseInsensitiveDict()
                continue

            if self.format == "list":
                self.data.setdefault(section, []).append(line)
            elif self.format == "section_line":
                self.data.setdefault(section, []).append(self._parse_pairs(line))
            else:
                # section
                token, sep, value = line.partition("=")
                if not sep:
                    logger.warning("Can't parse line: `%s`, error: no '=' separator", line)
                    continue
                if section not in self.data:
                    self.data[section] = CaseInsensitiveDict()
                self.data[section][token] = unquote(value)

    @classmethod
    def from_data(cls, fmt: str | None, data: Any) -> ConfigParser:
        """Build a parser around already decoded data, skipping any text parsing.

        Used by :class:`~stormshield.sns.sslclient.Response`, which decodes the
        API answer straight from its XML tree.
        """

        parser = cls.__new__(cls)
        parser.format = fmt
        parser.data = data
        return parser

    @classmethod
    def _parse_pairs(cls, line: str) -> dict[str, str]:
        """Parse a ``token=value token2="value 2"`` line into a dict."""

        # An odd number of quotes means the appliance sent a truncated line:
        # keep the pairs that end before the unmatched quote rather than
        # half-parsing the last value or dropping the whole row.
        limit = len(line)
        if line.count('"') % 2:
            logger.warning("Can't parse line: `%s`, error: unbalanced quotes", line)
            limit = line.rfind('"')

        return {
            m.group("token"): unquote(m.group("value"))
            for m in cls._PAIR_RE.finditer(line)
            if m.end() <= limit
        }

    def get(
        self,
        section: str,
        token: str | None = None,
        line: int | None = None,
        default: Any = None,
    ) -> Any:
        """Get the value of a token or a plain line from the given section."""

        if section not in self.data:
            return default

        if token is not None:
            # token/value mode
            if token not in self.data[section]:
                return default
            return unquote(self.data[section][token])

        if line is None:
            # return all tokens/lines from the section
            return self.data[section]

        if line < 1 or len(self.data[section]) < line:
            return default
        return self.data[section][line - 1]

    def serialize_data(self) -> Any:
        """Return the parsed data as plain serializable structures."""

        return serialize(self.data)
