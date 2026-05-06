"""Coverage fill for tools/registry.py — Phase 5.4.

Targets:
- SecurityTool._build_command: blocked keys, allowed_args, invalid key chars,
  bool-True flag, shell injection chars in value
- SecurityTool.execute: cache hit, subprocess success, parse_output call,
  cache put, persist, FileNotFoundError, general exception
- configure_cache: sets class-level vars
- _persist_tool_result: with active engagement context, DB error swallowed
- parse_nmap: http/https severity=low branch
- parse_sqlmap: union, time-based, error-based branches
- parse_nikto: vuln-keyword line (high), info line (info), empty
- parse_wafw00f: WAF detected, no WAF
- parse_subfinder: subdomains, excludes exact target
- parse_amass: subdomain with source
- parse_whatweb: tech detection
- parse_trufflehog: secret line
- parse_gitleaks: rule/secret line
- parse_default: substantial output, short/empty output
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.registry import (
    SecurityTool,
    _persist_tool_result,
    configure_cache,
    parse_amass,
    parse_default,
    parse_gitleaks,
    parse_nikto,
    parse_nmap,
    parse_nuclei,
    parse_sqlmap,
    parse_subfinder,
    parse_trufflehog,
    parse_wafw00f,
    parse_whatweb,
)

# ─── fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_cache():
    configure_cache(None, "normal", disabled=False)
    yield
    configure_cache(None, "normal", disabled=False)


def _tool(**kw):
    defaults = dict(name="test-tool", category="network", description="test", command="nmap")
    defaults.update(kw)
    return SecurityTool(**defaults)


# ─── SecurityTool.is_installed ──────────────────────────────────────────

def test_is_installed_true(monkeypatch):
    monkeypatch.setattr("tools.registry.shutil.which", lambda cmd: f"/usr/bin/{cmd}")
    assert _tool().is_installed() is True


def test_is_installed_false(monkeypatch):
    monkeypatch.setattr("tools.registry.shutil.which", lambda cmd: None)
    assert _tool().is_installed() is False


# ─── SecurityTool._build_command ────────────────────────────────────────

def test_build_command_no_args():
    assert _tool()._build_command("t.com") == ["nmap", "t.com"]


def test_build_command_blocks_dangerous_key():
    """Line 49: continue after BLOCKED_ARG_KEYS hit."""
    cmd = _tool()._build_command("t.com", {"script": "evil.nse", "timeout": "10"})
    assert "--script" not in cmd
    assert "evil.nse" not in cmd
    assert "--timeout" in cmd


def test_build_command_respects_allowed_args():
    """Line 51: continue when key not in allowed_args."""
    t = _tool(allowed_args={"depth"})
    cmd = t._build_command("t.com", {"depth": "3", "other": "x"})
    assert "--depth" in cmd and "3" in cmd
    assert "--other" not in cmd


def test_build_command_rejects_invalid_key_chars():
    """Line 53: continue when key fails regex."""
    cmd = _tool()._build_command("t.com", {"bad key!": "value", "good-key": "ok"})
    assert "bad" not in " ".join(cmd)
    assert "--good-key" in cmd


def test_build_command_bool_true_appends_flag():
    """Line 55: bool-True produces bare flag."""
    cmd = _tool()._build_command("t.com", {"verbose": True})
    assert "--verbose" in cmd
    idx = cmd.index("--verbose")
    assert cmd[idx + 1] == "t.com"  # no value between flag and target


def test_build_command_rejects_shell_injection_in_value():
    """Line 59: continue when value contains shell metachar."""
    cmd = _tool()._build_command("t.com", {"output": "file; rm -rf /", "rate": "100"})
    assert "--output" not in cmd
    assert "--rate" in cmd


def test_build_command_int_arg():
    cmd = _tool()._build_command("t.com", {"port": 8080})
    assert "--port" in cmd and "8080" in cmd


def test_build_command_custom_build_args():
    def custom(target, args):
        return ["mytool", "-t", target]
    assert _tool(build_args=custom)._build_command("t.com") == ["mytool", "-t", "t.com"]


# ─── configure_cache ────────────────────────────────────────────────────

def test_configure_cache_sets_vars():
    fake = MagicMock()
    configure_cache(fake, intensity="aggressive")
    assert SecurityTool._cache is fake
    assert SecurityTool._cache_intensity == "aggressive"
    assert SecurityTool._cache_disabled is False


def test_configure_cache_disabled_flag():
    configure_cache(MagicMock(), disabled=True)
    assert SecurityTool._cache_disabled is True


# ─── SecurityTool.execute ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_subprocess_success(monkeypatch):
    """Lines 85-122: happy subprocess path."""
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"22/tcp open ssh", b""))
    monkeypatch.setattr("tools.registry.asyncio.create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr("tools.registry._persist_tool_result", AsyncMock())
    result = await _tool().execute("t.com")
    assert result["tool"] == "test-tool"
    assert result["exit_code"] == 0
    assert result["stdout"] == "22/tcp open ssh"
    assert result["cache_hit"] is False


@pytest.mark.asyncio
async def test_execute_calls_parse_output(monkeypatch):
    """Line 99: parse_output is invoked and findings are populated."""
    def my_parser(r):
        return [{"title": "found", "severity": "info"}]

    t = _tool(parse_output=my_parser)
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"something", b""))
    monkeypatch.setattr("tools.registry.asyncio.create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr("tools.registry._persist_tool_result", AsyncMock())
    result = await t.execute("t.com")
    assert result["findings"] == [{"title": "found", "severity": "info"}]


@pytest.mark.asyncio
async def test_execute_cache_hit():
    """Lines 71-76: cache hit returns early with cache_hit=True."""
    cached = {"tool": "test-tool", "target": "t.com", "findings": [], "cache_hit": False}
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=cached)
    configure_cache(mock_cache)
    with patch("engine.cache.make_key", return_value="k"):
        result = await _tool().execute("t.com")
    assert result["cache_hit"] is True


@pytest.mark.asyncio
async def test_execute_cache_miss_writes_result(monkeypatch):
    """Lines 105-108: cache put is called when returncode==0 and ttl>0."""
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.put = AsyncMock()
    configure_cache(mock_cache)
    proc = MagicMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"ok", b""))
    monkeypatch.setattr("tools.registry.asyncio.create_subprocess_exec", AsyncMock(return_value=proc))
    monkeypatch.setattr("tools.registry._persist_tool_result", AsyncMock())
    with patch("engine.cache.make_key", return_value="k"), \
         patch("engine.cache.ttl_for", return_value=300):
        await _tool().execute("t.com")
    mock_cache.put.assert_called_once()


@pytest.mark.asyncio
async def test_execute_file_not_found(monkeypatch):
    """Lines 119-122: FileNotFoundError → error dict returned."""
    monkeypatch.setattr(
        "tools.registry.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=FileNotFoundError()),
    )
    result = await _tool().execute("t.com")
    assert "error" in result
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_execute_general_exception(monkeypatch):
    """Generic exception → error dict with message."""
    monkeypatch.setattr(
        "tools.registry.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=RuntimeError("boom")),
    )
    result = await _tool().execute("t.com")
    assert "error" in result and "boom" in result["error"]


# ─── _persist_tool_result ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_persist_noop_without_context():
    """Without an active engagement, persist is a no-op."""
    result = {"tool": "nmap", "target": "t.com", "stdout": "x", "stderr": "", "exit_code": 0, "duration": 1.0}
    await _persist_tool_result(result, {})  # must not raise


@pytest.mark.asyncio
async def test_persist_writes_to_db(monkeypatch):
    """Lines 140-141: DB write happens when engagement is active."""
    mock_db = MagicMock()
    mock_db.add_tool_result = AsyncMock()
    monkeypatch.setattr("engine.exec_context.get_exec_context", lambda: ("eng-1", mock_db))
    result = {"tool": "nmap", "target": "t.com", "stdout": "out", "stderr": "", "exit_code": 0, "duration": 1.5}
    await _persist_tool_result(result, {"p": "v"})
    mock_db.add_tool_result.assert_called_once()
    payload = mock_db.add_tool_result.call_args[0][0]
    assert payload["engagement_id"] == "eng-1"
    assert payload["tool_name"] == "nmap"


@pytest.mark.asyncio
async def test_persist_db_error_swallowed(monkeypatch):
    """DB exception is caught and logged — does not propagate."""
    mock_db = MagicMock()
    mock_db.add_tool_result = AsyncMock(side_effect=RuntimeError("DB gone"))
    monkeypatch.setattr("engine.exec_context.get_exec_context", lambda: ("eng-1", mock_db))
    result = {"tool": "nmap", "target": "t.com", "stdout": "x", "stderr": "", "exit_code": 0, "duration": 1.0}
    await _persist_tool_result(result, {})  # must not raise


# ─── parse_nmap ─────────────────────────────────────────────────────────

def test_parse_nmap_http_severity_low():
    """Line 199: http/https maps to severity=low."""
    r = {"stdout": "80/tcp open http\n443/tcp open https", "target": "t.com"}
    findings = parse_nmap(r)
    sevs = {f["severity"] for f in findings}
    assert "low" in sevs


# ─── parse_sqlmap ────────────────────────────────────────────────────────

def test_parse_sqlmap_union_based():
    """Line 244: UNION branch."""
    r = {"stdout": "target is vulnerable union-based injection found", "target": "http://t.com/"}
    findings = parse_sqlmap(r)
    assert len(findings) == 1 and "UNION" in findings[0]["title"]


def test_parse_sqlmap_time_based():
    """Lines 247-248: time-based branch."""
    r = {"stdout": "is vulnerable time-based blind attack", "target": "http://t.com/"}
    findings = parse_sqlmap(r)
    assert len(findings) == 1 and "Time" in findings[0]["title"]


def test_parse_sqlmap_error_based():
    """Lines 249-250: error-based branch."""
    r = {"stdout": "is vulnerable error-based response injection found", "target": "http://t.com/"}
    findings = parse_sqlmap(r)
    assert len(findings) == 1 and "Error" in findings[0]["title"]


# ─── parse_nuclei ────────────────────────────────────────────────────────

def test_parse_nuclei_high_finding():
    r = {"stdout": "[high] cve-2021-1234 http://target.com/vuln", "target": "http://target.com"}
    findings = parse_nuclei(r)
    assert len(findings) == 1 and findings[0]["severity"] == "high"


# ─── parse_nikto ─────────────────────────────────────────────────────────

def test_parse_nikto_vuln_keyword_high():
    """Lines 299-311: keyword match → severity=high."""
    r = {
        "stdout": "+ OSVDB-3092: /admin/: possible vuln exploit path disclosure",
        "target": "http://t.com",
    }
    findings = parse_nikto(r)
    assert len(findings) >= 1 and findings[0]["severity"] == "high"


def test_parse_nikto_info_line():
    """Lines 312-325: non-vuln content → severity=info."""
    r = {
        "stdout": "+ Server: Apache/2.4.41 (Ubuntu)",
        "target": "http://t.com",
    }
    findings = parse_nikto(r)
    assert len(findings) >= 1 and findings[0]["severity"] == "info"


def test_parse_nikto_no_plus_lines():
    r = {"stdout": "Scanning target...\nDone.", "target": "http://t.com"}
    assert parse_nikto(r) == []


# ─── parse_wafw00f ───────────────────────────────────────────────────────

def test_parse_wafw00f_waf_detected():
    """Lines 338-352: WAF match."""
    r = {"stdout": "Detected WAF: ModSecurity (Apache)", "target": "http://t.com"}
    findings = parse_wafw00f(r)
    assert len(findings) == 1 and "ModSecurity" in findings[0]["title"]


def test_parse_wafw00f_none_detected():
    r = {"stdout": "No WAF detected.", "target": "http://t.com"}
    assert parse_wafw00f(r) == []


# ─── parse_subfinder ─────────────────────────────────────────────────────

def test_parse_subfinder_subdomains():
    """Lines 359-374: subdomain lines → one finding each."""
    r = {
        "stdout": "api.example.com\nwww.example.com\nmail.example.com",
        "target": "example.com",
    }
    findings = parse_subfinder(r)
    assert len(findings) == 3
    assert all(f["tool_source"] == "subfinder" for f in findings)


def test_parse_subfinder_excludes_exact_target():
    r = {"stdout": "example.com\napi.example.com", "target": "example.com"}
    findings = parse_subfinder(r)
    assert len(findings) == 1 and "api.example.com" in findings[0]["title"]


# ─── parse_amass ─────────────────────────────────────────────────────────

def test_parse_amass_with_source():
    """Lines 380-398: subdomain + source column."""
    r = {"stdout": "api.example.com cert.sh\nwww.example.com dns", "target": "example.com"}
    findings = parse_amass(r)
    assert len(findings) == 2
    assert findings[0]["tool_source"] == "amass"


def test_parse_amass_empty():
    r = {"stdout": "", "target": "example.com"}
    assert parse_amass(r) == []


# ─── parse_whatweb ───────────────────────────────────────────────────────

def test_parse_whatweb_detects_tech():
    """Lines 404-421: regex match on [code] url [tech,...]."""
    r = {
        "stdout": "[200] http://example.com [WordPress, PHP/8.1, Apache/2.4]",
        "target": "http://example.com",
    }
    findings = parse_whatweb(r)
    assert len(findings) >= 1
    titles = [f["title"] for f in findings]
    assert any("WordPress" in t or "PHP" in t or "Apache" in t for t in titles)


def test_parse_whatweb_no_match():
    r = {"stdout": "Scanning example.com...", "target": "http://example.com"}
    assert parse_whatweb(r) == []


# ─── parse_trufflehog ────────────────────────────────────────────────────

def test_parse_trufflehog_finds_secret():
    """Lines 451-465: Detector Type/Secret lines → critical finding."""
    r = {
        "stdout": "Detector Type: AWS\nSecret: <redacted-test-token>",
        "target": "https://github.com/org/repo",
    }
    findings = parse_trufflehog(r)
    assert len(findings) >= 1 and findings[0]["severity"] == "critical"


def test_parse_trufflehog_no_secrets():
    r = {"stdout": "Scanning repo...\nDone.", "target": "repo"}
    assert parse_trufflehog(r) == []


# ─── parse_gitleaks ──────────────────────────────────────────────────────

def test_parse_gitleaks_finds_secret():
    """Lines 471-485: rule/secret/author → critical finding."""
    r = {
        "stdout": "rule: aws-access-key\nsecret: <redacted-test-token>\nauthor: someone",
        "target": "/path/to/repo",
    }
    findings = parse_gitleaks(r)
    assert len(findings) >= 1 and findings[0]["severity"] == "critical"


def test_parse_gitleaks_no_leaks():
    r = {"stdout": "No leaks found.", "target": "/path/to/repo"}
    assert parse_gitleaks(r) == []


# ─── parse_default ───────────────────────────────────────────────────────

def test_parse_default_substantial_output():
    """Lines 547-561: non-trivial stdout → one info finding."""
    r = {"stdout": "This is output longer than ten characters", "target": "t.com", "tool": "mytool"}
    findings = parse_default(r)
    assert len(findings) == 1 and findings[0]["tool_source"] == "mytool"


def test_parse_default_short_output_ignored():
    r = {"stdout": "hi", "target": "t.com", "tool": "mytool"}
    assert parse_default(r) == []


def test_parse_default_empty_output():
    r = {"stdout": "", "target": "t.com", "tool": "mytool"}
    assert parse_default(r) == []
