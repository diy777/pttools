"""Tests for engine.target_expander."""

from __future__ import annotations

import pytest

from engine.target_expander import (
    MAX_EXPANDED_TARGETS,
    expand_target,
    load_targets_file,
    resolve_targets,
)


class TestExpandTarget:
    def test_single_hostname(self):
        assert expand_target("example.com") == ["example.com"]

    def test_single_ip(self):
        assert expand_target("10.0.0.1") == ["10.0.0.1"]

    def test_strips_whitespace(self):
        assert expand_target("  example.com  ") == ["example.com"]

    def test_empty_string(self):
        assert expand_target("") == []

    def test_whitespace_only(self):
        assert expand_target("   ") == []

    def test_comma_separated(self):
        out = expand_target("10.0.0.1,10.0.0.2,example.com")
        assert out == ["10.0.0.1", "10.0.0.2", "example.com"]

    def test_comma_separated_with_spaces(self):
        out = expand_target("a.com, b.com , c.com")
        assert out == ["a.com", "b.com", "c.com"]

    def test_comma_separated_skips_empty_parts(self):
        out = expand_target("a.com,,b.com")
        assert out == ["a.com", "b.com"]

    def test_cidr_24(self):
        out = expand_target("10.0.0.0/24")
        assert len(out) == 254
        assert "10.0.0.1" in out
        assert "10.0.0.254" in out
        assert "10.0.0.0" not in out
        assert "10.0.0.255" not in out

    def test_cidr_30(self):
        out = expand_target("10.0.0.0/30")
        assert out == ["10.0.0.1", "10.0.0.2"]

    def test_cidr_32_single_host(self):
        out = expand_target("10.0.0.5/32")
        assert out == ["10.0.0.5"]

    def test_cidr_31_point_to_point(self):
        # RFC 3021: /31 yields both addresses as usable.
        out = expand_target("10.0.0.0/31")
        assert out == ["10.0.0.0", "10.0.0.1"]

    def test_cidr_non_strict_host_bits(self):
        out = expand_target("10.0.0.5/24")
        assert len(out) == 254
        assert "10.0.0.1" in out

    def test_malformed_cidr_falls_back_to_literal(self):
        out = expand_target("not-a-network/abc")
        assert out == ["not-a-network/abc"]

    def test_url_with_path_falls_back_to_literal(self):
        out = expand_target("https://example.com/path")
        assert out == ["https://example.com/path"]

    def test_comma_with_cidr_mix(self):
        out = expand_target("10.0.0.1,192.168.1.0/30")
        assert out == ["10.0.0.1", "192.168.1.1", "192.168.1.2"]


class TestLoadTargetsFile:
    def test_simple_file(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("a.com\nb.com\nc.com\n")
        assert load_targets_file(p) == ["a.com", "b.com", "c.com"]

    def test_file_with_comments(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("# header comment\na.com\nb.com  # inline comment\n")
        assert load_targets_file(p) == ["a.com", "b.com"]

    def test_file_with_blank_lines(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("a.com\n\n\nb.com\n   \n")
        assert load_targets_file(p) == ["a.com", "b.com"]

    def test_file_with_cidr(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("10.0.0.0/30\nexample.com\n")
        assert load_targets_file(p) == ["10.0.0.1", "10.0.0.2", "example.com"]

    def test_file_with_comma_separated_line(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("a.com,b.com\nc.com\n")
        assert load_targets_file(p) == ["a.com", "b.com", "c.com"]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_targets_file(tmp_path / "does-not-exist.txt")

    def test_accepts_string_path(self, tmp_path):
        p = tmp_path / "targets.txt"
        p.write_text("a.com\n")
        assert load_targets_file(str(p)) == ["a.com"]

    def test_expanduser(self, tmp_path, monkeypatch):
        # On Windows, `~` resolves via USERPROFILE, not HOME.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        p = tmp_path / "targets.txt"
        p.write_text("a.com\n")
        assert load_targets_file("~/targets.txt") == ["a.com"]


class TestResolveTargets:
    def test_target_arg_only(self):
        assert resolve_targets("example.com", None) == ["example.com"]

    def test_targets_file_only(self, tmp_path):
        p = tmp_path / "t.txt"
        p.write_text("a.com\nb.com\n")
        assert resolve_targets(None, str(p)) == ["a.com", "b.com"]

    def test_combines_arg_and_file(self, tmp_path):
        p = tmp_path / "t.txt"
        p.write_text("a.com\n")
        assert resolve_targets("b.com", str(p)) == ["a.com", "b.com"]

    def test_dedupes_across_arg_and_file(self, tmp_path):
        p = tmp_path / "t.txt"
        p.write_text("a.com\nb.com\n")
        assert resolve_targets("a.com,c.com", str(p)) == ["a.com", "b.com", "c.com"]

    def test_dedupes_within_arg(self):
        assert resolve_targets("a.com,a.com,b.com", None) == ["a.com", "b.com"]

    def test_preserves_order(self):
        assert resolve_targets("c.com,a.com,b.com", None) == ["c.com", "a.com", "b.com"]

    def test_no_inputs_returns_empty(self):
        assert resolve_targets(None, None) == []

    def test_cidr_expansion(self):
        out = resolve_targets("10.0.0.0/30", None)
        assert out == ["10.0.0.1", "10.0.0.2"]

    def test_cap_enforced(self):
        # /20 expands to 4094 hosts (under cap); /19 expands to 8190 (over cap).
        with pytest.raises(ValueError, match="exceeds cap"):
            resolve_targets("10.0.0.0/19", None)

    def test_just_under_cap_is_ok(self):
        # /20 = 4094 usable hosts, under MAX_EXPANDED_TARGETS=4096
        out = resolve_targets("10.0.0.0/20", None)
        assert len(out) == 4094
        assert len(out) <= MAX_EXPANDED_TARGETS

    def test_skips_empty_strings(self):
        assert resolve_targets(",,a.com,,", None) == ["a.com"]
