"""
stormshield.sns.crc

SNS CRC32 helpers.

The appliance announces the CRC of a download as the *non-finalised* CRC-32
value: the standard IEEE 802.3 algorithm without the final one's complement.
That is exactly ``zlib.crc32(data) ^ 0xFFFFFFFF``, so the C implementation of
zlib is used instead of a table lookup written in Python.
"""

from __future__ import annotations

import zlib

__all__ = ["CRC32_init", "compute_crc32", "update_crc32"]

#: Seed value of an empty SNS CRC.
CRC32_init = 0xFFFFFFFF

_FINAL_XOR = 0xFFFFFFFF


def _tobytes(data: bytes | str) -> bytes:
    """Encode ``data`` as UTF-8 when it is a ``str``."""

    return data.encode("utf-8") if isinstance(data, str) else data


def compute_crc32(data: bytes | str) -> int:
    """Return the SNS CRC32 value of ``data``, a ``str`` being read as UTF-8."""

    return zlib.crc32(_tobytes(data)) ^ _FINAL_XOR


def update_crc32(data: bytes | str, crc: int) -> int:
    """Return ``crc`` updated with ``data``, for incremental hashing.

    ``crc`` must be a value previously returned by :func:`compute_crc32`,
    :func:`update_crc32`, or :data:`CRC32_init` to start a new computation.
    """

    return zlib.crc32(_tobytes(data), crc ^ _FINAL_XOR) ^ _FINAL_XOR
