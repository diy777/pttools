"""Tests for cli.menu helpers — pure-function pieces, no I/O loop coverage."""

from __future__ import annotations

import io
import os
from contextlib import redirect_stdout

from cli.menu import (
    MENU_CATEGORIES,
    _filter_tag,
    _has,
    _recommend,
    _search,
)


def test_catalog_structure() -> None:
    assert len(MENU_CATEGORIES) >= 12, "expected at least 12 categories"
    for cat in MENU_CATEGORIES:
        assert "id" in cat
        assert isinstance(cat["id"], int)
        assert "name" in cat
        assert "tools" in cat
        assert isinstance(cat["tools"], list)
        assert "tags" in cat
        for entry in cat["tools"]:
            assert isinstance(entry, tuple)
            assert len(entry) == 3, f"tool tuple must be (name, desc, command): {entry}"
            name, desc, cmd = entry
            assert all(isinstance(x, str) and x for x in (name, desc, cmd))


def test_category_ids_are_unique() -> None:
    ids = [c["id"] for c in MENU_CATEGORIES]
    assert len(ids) == len(set(ids)), "duplicate category IDs detected"


def test_search_finds_known_tool() -> None:
    """A search for 'nmap' must surface the recon category."""
    buf = io.StringIO()
    os.environ["NO_COLOR"] = "1"  # easier substring assertions
    with redirect_stdout(buf):
        _search("nmap")
    out = buf.getvalue().lower()
    assert "nmap" in out
    assert "reconnaissance" in out
    os.environ.pop("NO_COLOR", None)


def test_search_no_match_prints_no_matches() -> None:
    buf = io.StringIO()
    os.environ["NO_COLOR"] = "1"
    with redirect_stdout(buf):
        _search("zzz-no-such-tool")
    assert "no matches" in buf.getvalue().lower()
    os.environ.pop("NO_COLOR", None)


def test_tag_filter_routes_correctly() -> None:
    buf = io.StringIO()
    os.environ["NO_COLOR"] = "1"
    with redirect_stdout(buf):
        _filter_tag("web")
    out = buf.getvalue().lower()
    assert "web application testing" in out
    os.environ.pop("NO_COLOR", None)


def test_recommend_routes_aws_to_cloud() -> None:
    buf = io.StringIO()
    os.environ["NO_COLOR"] = "1"
    with redirect_stdout(buf):
        _recommend("scan our aws infrastructure for misconfigurations")
    out = buf.getvalue().lower()
    assert "cloud security" in out
    assert "cloud-security" in out
    os.environ.pop("NO_COLOR", None)


def test_recommend_no_match() -> None:
    buf = io.StringIO()
    os.environ["NO_COLOR"] = "1"
    with redirect_stdout(buf):
        _recommend("write a poem")
    assert "no obvious match" in buf.getvalue().lower()
    os.environ.pop("NO_COLOR", None)


def test_has_for_known_binary() -> None:
    """`ls` is on every system the test suite runs on."""
    assert _has("ls") is True
    assert _has("definitely-not-a-real-command-xyz") is False
