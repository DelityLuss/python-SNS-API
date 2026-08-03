"""CRC32 helpers - the appliance sends the non-finalised IEEE CRC-32."""

import os
import zlib

import pytest

from stormshield.sns.crc import CRC32_init, compute_crc32, update_crc32

VECTORS = [b"", b"a", b"hello", b"x" * 4096, bytes(range(256))]


@pytest.mark.parametrize("data", VECTORS)
def test_matches_zlib(data):
    """SNS CRC is zlib's CRC without the final one's complement."""

    assert compute_crc32(data) == zlib.crc32(data) ^ 0xFFFFFFFF


def test_known_values():
    """Guard against a silent change of convention."""

    assert compute_crc32(b"") == CRC32_init
    assert compute_crc32(b"hello") == 0xC9EF5979


@pytest.mark.parametrize("data", VECTORS)
def test_incremental_matches_oneshot(data):
    """Chunked hashing must equal hashing the whole payload at once."""

    crc = CRC32_init
    for i in range(0, len(data), 7):
        crc = update_crc32(data[i : i + 7], crc)
    assert crc == compute_crc32(data)


def test_incremental_random_chunks():
    data = os.urandom(50_000)
    crc = CRC32_init
    pos = 0
    for step in (1, 10, 1000, 17, 32768):
        crc = update_crc32(data[pos : pos + step], crc)
        pos += step
    crc = update_crc32(data[pos:], crc)
    assert crc == compute_crc32(data)


def test_update_from_seed_is_oneshot():
    assert update_crc32(b"hello", CRC32_init) == compute_crc32(b"hello")


def test_result_is_uint32():
    for data in VECTORS:
        assert 0 <= compute_crc32(data) <= 0xFFFFFFFF
