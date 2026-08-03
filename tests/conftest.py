"""Shared helpers for the offline test suite.

The XML fixtures under ``tests/fixtures`` are real answers captured from an
SNS appliance (v4.8.15), with serials, addresses and object names scrubbed.
"""

from __future__ import annotations

import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    """Return the raw XML of a captured appliance answer."""

    return (FIXTURES / f"{name}.xml").read_text(encoding="utf-8")


@pytest.fixture
def fixture_xml():
    return load


@pytest.fixture
def all_fixtures() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*.xml"))
