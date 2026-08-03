"""
stormshield.sns.sslclient.response

Decoding of SNS API answers.

The appliance answers in XML. Rather than rendering that XML to ini text and
parsing the text back (which is what versions up to 1.x did), the structured
``data`` is built straight from the XML tree, and the ini rendering is only
produced when :attr:`Response.output` is actually read.
"""

from __future__ import annotations

import json
from functools import cached_property
from typing import Any
from xml.etree import ElementTree as Et

import defusedxml.ElementTree as ElementTree
from requests.structures import CaseInsensitiveDict

from stormshield.sns.configparser import ConfigParser, serialize

__all__ = ["Response", "format_output", "parse_tree", "quote", "render_output"]

#: attributes of a ``<serverd>`` node that carry the command status; anything
#: else is answer metadata (row counts, truncation flags, ...).
_STATUS_ATTRS = frozenset({"ret", "code", "msg"})


def quote(value: Any) -> Any:
    """Quote ``value`` if it contains a space."""

    if value and isinstance(value, str) and " " in value:
        return '"' + value + '"'
    return value


def _serverd_line(node: Et.Element) -> str:
    return '{} code={} msg="{}"'.format(node.get("ret"), node.get("code"), node.get("msg"))


def _render_body(data_node: Et.Element, parts: list[str]) -> None:
    """Append the ini rendering of a ``<data>`` node to ``parts``."""

    node_format = data_node.get("format")
    parts.append(f' format="{node_format}"\n')

    if node_format == "raw":
        if data_node.text:
            parts.append(data_node.text)

    elif node_format == "section":
        for section_node in data_node:
            parts.append("[{}]\n".format(section_node.get("title")))
            for key_node in section_node:
                parts.append("{}={}\n".format(key_node.get("name"), quote(key_node.get("value"))))

    elif node_format == "section_line":
        for section_node in data_node:
            parts.append("[{}]\n".format(section_node.get("title")))
            for line_node in section_node:
                parts.append(
                    " ".join(
                        "{}={}".format(key_node.get("name"), quote(key_node.get("value")))
                        for key_node in line_node
                    )
                )
                parts.append("\n")

    elif node_format == "list":
        for section_node in data_node:
            parts.append("[{}]\n".format(section_node.get("title")))
            for line_node in section_node:
                parts.append(f"{line_node.text}\n")

    elif node_format == "xml":
        # display xml data node
        parts.append(Et.tostring(data_node).decode() + "\n")


def render_output(nws_node: Et.Element) -> str:
    """Render a parsed ``<nws>`` tree in ini/section or text format."""

    serverd_nodes = list(nws_node)
    if not serverd_nodes:
        return ""

    parts = [_serverd_line(serverd_nodes[0])]

    if len(serverd_nodes) > 1:
        data_nodes = list(serverd_nodes[0])
        if data_nodes:
            _render_body(data_nodes[0], parts)
        parts.append(_serverd_line(serverd_nodes[1]))

    return "".join(parts)


def format_output(output: str | bytes) -> str:
    """Format a raw XML command output in ini/section or text format."""

    return render_output(ElementTree.fromstring(output))


def parse_tree(nws_node: Et.Element) -> tuple[str | None, Any]:
    """Extract ``(format, data)`` straight from a parsed ``<nws>`` tree."""

    serverd_nodes = list(nws_node)
    if len(serverd_nodes) < 2:
        # single serverd node: an error or an answer with no payload
        return None, CaseInsensitiveDict()

    data_nodes = list(serverd_nodes[0])
    if not data_nodes:
        return None, CaseInsensitiveDict()

    data_node = data_nodes[0]
    node_format = data_node.get("format")

    if node_format == "raw":
        return node_format, data_node.text or ""

    if node_format == "xml":
        return node_format, Et.tostring(data_node).decode()

    data: Any = CaseInsensitiveDict()

    if node_format == "section":
        for section_node in data_node:
            section = CaseInsensitiveDict()
            for key_node in section_node:
                section[key_node.get("name")] = key_node.get("value")
            data[section_node.get("title")] = section

    elif node_format == "section_line":
        for section_node in data_node:
            data[section_node.get("title")] = [
                {key_node.get("name"): key_node.get("value") for key_node in line_node}
                for line_node in section_node
            ]

    elif node_format == "list":
        for section_node in data_node:
            data[section_node.get("title")] = [line_node.text for line_node in section_node]

    return node_format, data


class Response:
    """:class:`Response <Response>` object contains the SNS API response to a request.

    :attr:`data` and :attr:`output` are computed on first access, so a caller
    that only reads :attr:`data` never pays for the ini rendering.
    """

    def __init__(
        self,
        code: str | None = None,
        ret: int = 0,
        msg: str | None = None,
        output: str | None = None,
        xml: str | None = None,
        tree: Et.Element | None = None,
    ) -> None:
        self.code = code
        self.ret = ret
        self.msg = msg
        self.xml = xml
        self._tree = tree
        self._output = output
        #: Code of the *first* serverd node, which carries the transfer state
        #: (``SERVERD_WAIT_UPLOAD`` / ``SERVERD_WAIT_DOWNLOAD``). :attr:`code`
        #: holds the code of the last node for multiline answers.
        self.serverd_code = code
        #: Row offset this answer starts at, read from the command's ``start=``
        #: argument by :meth:`SSLClient.send_command`. ``None`` when unknown,
        #: which :attr:`truncated` treats as 0.
        self.offset: int | None = None

    @classmethod
    def from_tree(cls, nws_node: Et.Element, xml: str | None = None) -> Response:
        """Build a response from a parsed ``<nws>`` tree.

        For a multiline answer the returned :attr:`ret`, :attr:`code` and
        :attr:`msg` are those of the *last* serverd node, which carries the
        final status of the command.
        """

        serverd_nodes = list(nws_node)
        if not serverd_nodes:
            raise ValueError("Malformed answer: no serverd node")

        first = serverd_nodes[0]
        response = cls(
            code=first.get("code"),
            ret=cls._ret(first),
            msg=first.get("msg"),
            xml=xml,
            tree=nws_node,
        )

        if len(serverd_nodes) > 1:
            last = serverd_nodes[-1]
            response.code = last.get("code")
            response.msg = last.get("msg")
            response.ret = cls._ret(last)

        return response

    @staticmethod
    def _ret(node: Et.Element) -> int:
        """Read the ``ret`` attribute of a serverd node."""

        ret = node.get("ret")
        if ret is None:
            raise ValueError("Malformed answer: serverd node without ret")
        return int(ret)

    @classmethod
    def from_xml(cls, xml: str | bytes) -> Response:
        """Build a response from a raw XML answer."""

        text = xml.decode("utf-8") if isinstance(xml, bytes) else xml
        return cls.from_tree(ElementTree.fromstring(xml), text)

    @cached_property
    def output(self) -> str:
        """The answer rendered in ini/section format."""

        if self._output is not None:
            return self._output
        if self._tree is not None:
            return render_output(self._tree)
        return ""

    @cached_property
    def _decoded(self) -> tuple[str | None, Any]:
        if self._tree is not None:
            return parse_tree(self._tree)
        parser = ConfigParser(self.output)
        return parser.format, parser.data

    @property
    def format(self) -> str | None:
        """The payload format announced by the appliance."""

        return self._decoded[0]

    @property
    def data(self) -> Any:
        """The answer decoded into dicts/lists, with case insensitive keys."""

        return self._decoded[1]

    @cached_property
    def parser(self) -> ConfigParser:
        """A :class:`ConfigParser` over :attr:`data`, for :meth:`ConfigParser.get`."""

        return ConfigParser.from_data(*self._decoded)

    def get(self, section: str, token: str | None = None, line: int | None = None, default: Any = None) -> Any:
        """Shortcut for ``response.parser.get(...)``."""

        return self.parser.get(section, token=token, line=line, default=default)

    # --- answer metadata ----------------------------------------------------

    @cached_property
    def meta(self) -> dict[str, str]:
        """Extra attributes the appliance put on the answer.

        Commands that page their results announce a row count and truncation
        flags here, for instance ``{'total': '134', 'too_many_data': '0',
        'not_enough_space': '0', 'data_changed': '0'}``. They are not part of
        :attr:`data`, which only holds the rows themselves.
        """

        if self._tree is None:
            return {}
        serverd_nodes = list(self._tree)
        if not serverd_nodes:
            return {}
        return {k: v for k, v in serverd_nodes[0].attrib.items() if k not in _STATUS_ATTRS}

    @property
    def total(self) -> int | None:
        """Number of rows the appliance holds, when it announces one.

        This can be larger than the number of rows actually returned: see
        :attr:`truncated`.
        """

        value = self.meta.get("total")
        if value is None or not value.lstrip("-").isdigit():
            return None
        return int(value)

    @property
    def count(self) -> int | None:
        """Number of rows returned, for the row-shaped formats."""

        if self.format not in ("section_line", "list"):
            return None
        return sum(len(rows) for rows in self.data.values())

    @property
    def truncated(self) -> bool:
        """True when rows remain past this answer.

        ``CONFIG OBJECT LIST type=host start=0`` answers at most 100 rows while
        announcing ``total=134``; iterating :attr:`data` alone would silently
        process a quarter of the objects. Page with the command's ``start``
        argument until this is False.

        The comparison is ``offset + count < total``, not ``count < total``:
        past the last page the appliance still reports the full ``total``
        alongside zero rows, so the naive form never terminates.
        """

        if self.meta.get("too_many_data", "0") not in ("0", ""):
            return True
        if self.meta.get("not_enough_space", "0") not in ("0", ""):
            return True
        total, count = self.total, self.count
        if total is None or count is None:
            return False
        if count == 0:
            # nothing came back, so there is nothing left to page through
            return False
        return (self.offset or 0) + count < total

    # --- serialisation ------------------------------------------------------

    def to_dict(self) -> Any:
        """:attr:`data` as plain dicts and lists, ready for JSON.

        :attr:`data` itself uses :class:`CaseInsensitiveDict`, which
        :func:`json.dumps` cannot serialise.
        """

        return serialize(self.data)

    def json(self, **kwargs: Any) -> str:
        """Serialise :attr:`data` to a JSON string.

        Every value is a string: the appliance sends XML attributes, so no type
        information ever reaches the client. ``"0"`` is the text zero, not the
        integer nor the boolean.
        """

        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(self.to_dict(), **kwargs)

    def __repr__(self) -> str:
        return f"<Response ret={self.ret} code={self.code} msg={self.msg!r}>"

    def __str__(self) -> str:
        return self.output

    def __bool__(self) -> bool:
        """Returns True if :attr:`ret` is OK or WARNING."""

        return 100 <= self.ret < 200
