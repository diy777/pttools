"""Unit tests for the SPA probes module.

These pin the false-positive guard (SPA shell filter) and the JWT two-step
logic (anonymous vs alg=none vs valid auth). The full integration check
runs against a live Juice Shop target in CI's e2e job, not here.
"""
from __future__ import annotations

import json

import pytest

from agents.web import spa_probes


def test_normalize_base_strips_trailing_slash():
    assert spa_probes._normalize_base("http://x.example/") == "http://x.example"
    assert spa_probes._normalize_base("x.example") == "http://x.example"
    assert spa_probes._normalize_base("https://x.example/y/") == "https://x.example/y"


def test_is_spa_shell_matches_baseline_prefix():
    baseline = "<html><app-root></app-root></html>" + ("X" * 5000)
    body = baseline
    assert spa_probes._is_spa_shell(body, baseline) is True


def test_is_spa_shell_drops_with_app_root_marker_and_no_json():
    baseline = ""
    body = "<html><base href='/'><app-root></app-root></html>"
    assert spa_probes._is_spa_shell(body, baseline) is True


def test_is_spa_shell_keeps_real_json_response():
    baseline = "<html><app-root></app-root></html>"
    body = '{"users":[{"id":1,"email":"admin@x"}]}'
    assert spa_probes._is_spa_shell(body, baseline) is False


def test_looks_sensitive_requires_two_needles():
    body_real = '{"config":{"users":[{"role":"admin"}]}}'
    body_thin = '{"hello":"world"}'
    assert spa_probes._looks_sensitive("/foo", body_real) is True
    assert spa_probes._looks_sensitive("/foo", body_thin) is False
    # Path hint trigger: even thin body counts if path looks like /admin.
    assert spa_probes._looks_sensitive("/admin/things", body_thin) is True


def test_looks_sensitive_requires_json_start():
    html = "<html>email password user</html>"
    assert spa_probes._looks_sensitive("/foo", html) is False


def test_looks_like_user_collection():
    body_real = '[{"email":"a@x","role":"customer"},{"email":"b@x","role":"admin"}]'
    body_html = "<html>email role admin</html>"
    body_one = '{"email":"a@x"}'
    assert spa_probes._looks_like_user_collection(body_real) is True
    assert spa_probes._looks_like_user_collection(body_html) is False
    assert spa_probes._looks_like_user_collection(body_one) is False


def test_craft_alg_none_token_has_three_segments_with_empty_signature():
    token = spa_probes._craft_alg_none_token({"sub": "x"})
    parts = token.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # alg=none means empty signature
    import base64
    header_raw = parts[0] + "=" * (4 - len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_raw))
    assert header["alg"] == "none"


@pytest.mark.asyncio
async def test_run_all_probes_empty_target_no_crash():
    # All probes should fail gracefully when nothing answers.
    findings = await spa_probes.run_all_probes("http://127.0.0.1:1")
    assert findings == []


def test_looks_like_token_response_detects_jwt_field():
    body = '{"authentication":{"token":"eyJhbGc..."}}'
    assert spa_probes._looks_like_token_response(body) is True
    body2 = '{"access_token":"abc","token_type":"Bearer"}'
    assert spa_probes._looks_like_token_response(body2) is True


def test_looks_like_token_response_rejects_non_token_json():
    body = '{"status":"ok","message":"login attempt logged"}'
    assert spa_probes._looks_like_token_response(body) is False
    assert spa_probes._looks_like_token_response("<html>token</html>") is False


def test_count_review_records_handles_data_envelope():
    body = '{"status":"success","data":[{"id":1},{"id":2},{"id":3}]}'
    assert spa_probes._count_review_records(body) == 3


def test_count_review_records_handles_bare_array():
    body = '[{"id":1},{"id":2}]'
    assert spa_probes._count_review_records(body) == 2


def test_count_review_records_zero_for_html():
    assert spa_probes._count_review_records("<html>data</html>") == 0
    assert spa_probes._count_review_records("") == 0


def test_interesting_ftp_extensions_includes_canonical_leaks():
    # Confirms the wordlist that gates the /ftp leak download step has the
    # extensions any pentester expects: backup, key, env, sql, etc.
    assert ".bak" in spa_probes.INTERESTING_FTP_EXTENSIONS
    assert ".env" in spa_probes.INTERESTING_FTP_EXTENSIONS
    assert ".pem" in spa_probes.INTERESTING_FTP_EXTENSIONS
    assert ".sql" in spa_probes.INTERESTING_FTP_EXTENSIONS


def test_login_paths_includes_juice_shop_canonical():
    assert "/rest/user/login" in spa_probes.LOGIN_PATHS


def test_sqli_payloads_include_classic_or_1_eq_1():
    payloads = [p[0] for p in spa_probes.SQLI_LOGIN_PAYLOADS]
    assert any("OR 1=1" in p for p in payloads)
    assert any("admin'" in p for p in payloads)


def test_redirect_finding_shape():
    f = spa_probes._redirect_finding(
        "http://x/redirect?to=https://example.org/pttools-canary",
        "to",
        "https://example.org/pttools-canary",
    )
    assert f["severity"] == "medium"
    assert f["category"] == "redirect"
    assert f["tool_source"] == "spa_probe"
    assert "Open Redirect" in f["title"]
    assert "example.org" in f["description"]
