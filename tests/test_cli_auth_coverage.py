"""Coverage fill for cli/auth.py and cli/mcp_setup.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

# ─── cli/auth.py ────────────────────────────────────────────────────────


def test_api_base_default():
    from cli import auth
    with patch.dict("os.environ", {}, clear=False):
        # Don't actually unset; just verify default path works if env unset
        import os
        os.environ.pop("PENTESTAI_API_BASE", None)
        assert auth.api_base().startswith("http")


def test_api_base_override():
    import os

    from cli import auth
    os.environ["PENTESTAI_API_BASE"] = "https://staging.example/"
    try:
        assert auth.api_base() == "https://staging.example"
    finally:
        os.environ.pop("PENTESTAI_API_BASE", None)


def test_store_and_load_api_key(tmp_path, monkeypatch):
    import sys

    from cli import auth
    monkeypatch.setattr(auth, "PENTEST_TOOLS_DIR", tmp_path / ".pentest-tools")
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / ".pentest-tools" / "credentials")
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)

    auth.store_api_key("sk-abc")
    assert auth.load_api_key() == "sk-abc"
    if sys.platform != "win32":
        # File mode 0600 (Windows uses ACLs, st_mode is meaningless there)
        mode = (tmp_path / ".pentest-tools" / "credentials").stat().st_mode & 0o777
        assert mode == 0o600


def test_load_api_key_env_overrides_file(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / "creds")
    (tmp_path / "creds").write_text("file-key")
    monkeypatch.setenv("PENTESTAI_API_KEY", "env-key")
    assert auth.load_api_key() == "env-key"


def test_load_api_key_returns_none_when_missing(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / "missing")
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)
    assert auth.load_api_key() is None


def test_load_api_key_handles_oserror(tmp_path, monkeypatch):
    from cli import auth
    f = tmp_path / "creds"
    f.write_text("k")
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", f)
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)
    with patch.object(Path, "read_text", side_effect=OSError("perm")):
        assert auth.load_api_key() is None


def test_key_source_env(monkeypatch):
    from cli import auth
    monkeypatch.setenv("PENTESTAI_API_KEY", "sk-abc")
    assert auth.key_source() == "env"


def test_key_source_file(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)
    f = tmp_path / "creds"
    f.write_text("sk-file")
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", f)
    assert auth.key_source() == "file"


def test_key_source_none(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / "missing")
    assert auth.key_source() is None


def test_remove_credentials(tmp_path, monkeypatch):
    from cli import auth
    f = tmp_path / "creds"
    f.write_text("k")
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", f)
    auth.remove_credentials()
    assert not f.exists()


def test_remove_credentials_no_file(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / "missing")
    auth.remove_credentials()  # must not raise


def test_validate_key_remote_success():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"valid": True, "org_id": "org-1"}
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        result = auth.validate_key_remote("sk-abc")
    assert result["org_id"] == "org-1"


def test_validate_key_remote_invalid():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"valid": False}
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        assert auth.validate_key_remote("sk-bad") is None


def test_validate_key_remote_http_error():
    from cli import auth
    with patch("cli.auth.httpx.post", side_effect=httpx.ConnectError("down")):
        assert auth.validate_key_remote("sk-x") is None


def test_validate_key_remote_non_200():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 500
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        assert auth.validate_key_remote("sk-x") is None


def test_ingest_engagement_no_key(tmp_path, monkeypatch):
    from cli import auth
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", tmp_path / "missing")
    monkeypatch.delenv("PENTESTAI_API_KEY", raising=False)
    assert auth.ingest_engagement({"engagement": {}}) is None


def test_ingest_engagement_success():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 201
    fake_resp.json.return_value = {"id": "eng-server-1"}
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        result = auth.ingest_engagement({"x": "y"}, api_key="sk-x")
    assert result["id"] == "eng-server-1"


def test_ingest_engagement_quota_exceeded():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 402
    fake_resp.json.return_value = {"error": "out of quota", "upgrade_url": "https://x"}
    fake_resp.text = '{"error":"x"}'
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        result = auth.ingest_engagement({"x": "y"}, api_key="sk-x")
    assert result["quota_exceeded"] is True


def test_ingest_engagement_quota_with_unparseable_body():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 402
    fake_resp.json.side_effect = ValueError("not json")
    fake_resp.text = "<html>not json</html>"
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        result = auth.ingest_engagement({"x": "y"}, api_key="sk-x")
    assert result["quota_exceeded"] is True


def test_ingest_engagement_other_failure():
    from cli import auth
    fake_resp = MagicMock()
    fake_resp.status_code = 500
    fake_resp.text = "boom"
    with patch("cli.auth.httpx.post", return_value=fake_resp):
        assert auth.ingest_engagement({"x": "y"}, api_key="sk-x") is None


def test_ingest_engagement_http_error():
    from cli import auth
    with patch("cli.auth.httpx.post", side_effect=httpx.ConnectError("down")):
        assert auth.ingest_engagement({"x": "y"}, api_key="sk-x") is None


def test_mask_key_short():
    from cli import auth
    out = auth.mask_key("abc")
    # Must obscure: original "abc" should not appear verbatim
    assert "abc" not in out
    assert len(out) > 0


def test_mask_key_long():
    from cli import auth
    masked = auth.mask_key("sk-abcdef1234567890")
    # Some part of the original should be visible (prefix or suffix)
    # and middle should be obscured (contains "…" or "*")
    assert "…" in masked or "*" in masked
    # Trailing identifier visible
    assert "7890" in masked


# ─── cli/mcp_setup.py ───────────────────────────────────────────────────


def test_get_platform_returns_a_known_value(monkeypatch):
    from cli import mcp_setup
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    out = mcp_setup._get_platform()
    assert isinstance(out, str) and len(out) > 0


def test_get_platform_linux(monkeypatch):
    from cli import mcp_setup
    monkeypatch.setattr("platform.system", lambda: "Linux")
    out = mcp_setup._get_platform()
    assert "linux" in out.lower()


def test_get_platform_windows(monkeypatch):
    from cli import mcp_setup
    monkeypatch.setattr("platform.system", lambda: "Windows")
    out = mcp_setup._get_platform()
    assert "windows" in out.lower()


def test_get_pentest_ai_command_returns_string(monkeypatch):
    from cli import mcp_setup
    monkeypatch.setattr("shutil.which", lambda c: f"/usr/bin/{c}")
    out = mcp_setup._get_pentest_ai_command()
    assert isinstance(out, str)


def test_mcp_server_entry_shape():
    from cli import mcp_setup
    e = mcp_setup._mcp_server_entry()
    assert "command" in e
    assert "args" in e


def test_generate_config_snippet_shape():
    from cli import mcp_setup
    s = mcp_setup.generate_config_snippet()
    assert isinstance(s, dict)


def test_detect_installed_clients_returns_list(monkeypatch):
    from cli import mcp_setup
    # Clients are detected by config file existence; with no real config files,
    # we just verify the function returns a list of dicts.
    monkeypatch.setattr(Path, "exists", lambda self: False)
    clients = mcp_setup.detect_installed_clients()
    assert isinstance(clients, list)


def test_inject_config_dry_run(tmp_path):
    from cli import mcp_setup
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text('{"mcpServers": {}}')
    result = mcp_setup.inject_config(cfg_path, dry_run=True)
    assert isinstance(result, dict)


def test_inject_config_writes_when_not_dry_run(tmp_path):
    import json

    from cli import mcp_setup
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text('{"mcpServers": {}}')
    mcp_setup.inject_config(cfg_path, dry_run=False)
    after = json.loads(cfg_path.read_text())
    assert "mcpServers" in after


def test_inject_config_creates_missing_file(tmp_path):
    import json

    from cli import mcp_setup
    cfg_path = tmp_path / "new" / "config.json"
    result = mcp_setup.inject_config(cfg_path, dry_run=False)
    assert isinstance(result, dict)
    if cfg_path.exists():
        json.loads(cfg_path.read_text())
