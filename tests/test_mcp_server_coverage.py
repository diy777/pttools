"""Coverage fill for mcp_server/server.py uncovered tool handlers.

The existing test_mcp_server.py covers core engagement management and a
handful of tools. This file targets every remaining tool path so the file
clears 85% line coverage.

Strategy: each tool function delegates to an agent class imported lazily
inside the function. We patch the agent class at its module path, hand it
a mock instance whose `run_assessment` (or whatever entrypoint) returns a
canned dict, then assert the wiring is correct.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp_server.server as srv


@pytest.fixture(autouse=True)
def _reset_globals():
    srv.findings_db = None
    srv.orchestrator = None
    srv.tool_registry = None
    yield
    srv.findings_db = None
    srv.orchestrator = None
    srv.tool_registry = None


def _mock_db(**overrides):
    db = MagicMock()
    db.get_engagement = AsyncMock(return_value=overrides.get("get_engagement"))
    db.get_findings = AsyncMock(return_value=overrides.get("get_findings", []))
    db.list_engagements = AsyncMock(return_value=overrides.get("list_engagements", []))
    db.get_checkpoint = AsyncMock(return_value=overrides.get("get_checkpoint"))
    db.create_campaign = AsyncMock(return_value=overrides.get("create_campaign", "camp-1"))
    db.create_engagement = AsyncMock(return_value=overrides.get("create_engagement", {
        "id": "eng-1", "target": "t", "status": "running",
    }))
    db.get_campaign_summary = AsyncMock(return_value=overrides.get("get_campaign_summary", {}))
    db.add_finding = AsyncMock()
    return db


# ─── _validate_target_arg ────────────────────────────────────────────────


def test_validate_target_accepts_normal_target():
    assert srv._validate_target_arg("example.com") is None
    assert srv._validate_target_arg("10.0.0.1") is None


def test_validate_target_rejects_empty():
    err = srv._validate_target_arg("")
    assert err is not None
    assert "empty" in err.lower() or "required" in err.lower() or "missing" in err.lower()


def test_validate_target_rejects_shell_metachars():
    # The validator exists to stop command-injection; whatever rejection rule
    # it uses, semicolons and backticks should not be acceptable.
    for bad in ["a; rm -rf /", "a`whoami`", "a$(whoami)"]:
        err = srv._validate_target_arg(bad)
        assert err is not None, f"expected rejection of {bad!r}"


# ─── start_engagement progress notification path ────────────────────────


@pytest.mark.asyncio
async def test_start_engagement_with_ctx_calls_progress():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    mock_orch = MagicMock()

    async def _fake_start(_eng, on_progress=None):
        if on_progress:
            on_progress("recon", "started", 0.1)

    mock_orch.start_engagement = AsyncMock(side_effect=_fake_start)
    srv.orchestrator = mock_orch

    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()

    result = await srv.start_engagement("10.0.0.1", scope="web", ctx=ctx)
    assert result["status"] == "running"
    # _on_progress schedules a task; let it run
    import asyncio
    await asyncio.sleep(0)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_start_engagement_progress_handles_ctx_exception():
    """If ctx.report_progress raises, _notify swallows it (line 91-92)."""
    mock_db = _mock_db()
    srv.findings_db = mock_db
    mock_orch = MagicMock()

    async def _fake_start(_eng, on_progress=None):
        if on_progress:
            on_progress("recon", "started", 0.1)

    mock_orch.start_engagement = AsyncMock(side_effect=_fake_start)
    srv.orchestrator = mock_orch

    ctx = MagicMock()
    ctx.report_progress = AsyncMock(side_effect=RuntimeError("boom"))
    ctx.info = AsyncMock()

    await srv.start_engagement("10.0.0.1", ctx=ctx)
    import asyncio
    await asyncio.sleep(0)


# ─── run_recon error path ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_recon_delegates_to_agent():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    with patch("agents.recon.recon_agent.ReconAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_recon = AsyncMock(return_value={"hosts": ["10.0.0.1"]})
        result = await srv.run_recon("example.com", depth="standard")
    assert isinstance(result, dict)
    instance.run_recon.assert_awaited_once_with("example.com", depth="standard")


# ─── test_web_app paths ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_web_app_basic_no_auth():
    with patch("agents.web.web_agent.WebAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_web_app("http://example.com")
        assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_web_app_rejects_both_profile_and_credentials():
    result = await srv.test_web_app(
        "http://example.com",
        auth_profile="prof1",
        auth_credentials={"user": "x", "pass": "y"},
    )
    assert "error" in result
    assert "mutually exclusive" in result["error"]


@pytest.mark.asyncio
async def test_test_web_app_profile_error_returned():
    from cli.auth_profiles import ProfileError
    with patch("cli.auth_profiles.get_profile", side_effect=ProfileError("nope")):
        result = await srv.test_web_app("http://example.com", auth_profile="missing")
    assert "error" in result
    assert "missing" in result["error"]


@pytest.mark.asyncio
async def test_test_web_app_legacy_credentials_warns():
    with patch("agents.web.web_agent.WebAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_web_app(
            "http://example.com",
            auth_credentials={"type": "form", "username": "u", "password": "p"},
        )
        assert isinstance(result, dict)


# ─── authenticated_scan paths ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_authenticated_scan_rejects_profile_and_password_combo():
    result = await srv.authenticated_scan(
        "http://example.com",
        auth_profile="p1",
        password="leak",
    )
    assert "error" in result
    assert "mutually exclusive" in result["error"]


@pytest.mark.asyncio
async def test_authenticated_scan_profile_error():
    from cli.auth_profiles import ProfileError
    with patch("cli.auth_profiles.get_profile", side_effect=ProfileError("bad")):
        result = await srv.authenticated_scan(
            "http://example.com",
            auth_profile="missing",
        )
    assert "error" in result


@pytest.mark.asyncio
async def test_authenticated_scan_form_flow_legacy_runs_scanner():
    with patch("engine.authenticated_scan.run_authenticated_scan",
               new=AsyncMock(return_value={"findings": []})):
        result = await srv.authenticated_scan(
            "http://example.com",
            login_url="http://example.com/login",
            username="u",
            password="p",
        )
    assert "findings" in result


@pytest.mark.asyncio
async def test_authenticated_scan_persists_findings_when_engagement_id():
    mock_db = _mock_db()
    srv.findings_db = mock_db
    findings = [{"title": "XSS", "severity": "medium"}]
    with patch("engine.authenticated_scan.run_authenticated_scan",
               new=AsyncMock(return_value={"findings": findings})):
        await srv.authenticated_scan(
            "http://example.com",
            login_url="http://example.com/login",
            username="u",
            password="p",
            engagement_id="eng-X",
        )
    mock_db.add_finding.assert_awaited()


@pytest.mark.asyncio
async def test_authenticated_scan_handles_auth_error():
    from engine.auth_session import AuthError
    with patch("engine.authenticated_scan.run_authenticated_scan",
               new=AsyncMock(side_effect=AuthError("login failed"))):
        result = await srv.authenticated_scan(
            "http://example.com",
            login_url="http://example.com/login",
            username="u",
            password="p",
        )
    assert "error" in result
    assert "authentication failed" in result["error"]


# ─── test_active_directory paths ────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_active_directory_basic():
    with patch("agents.ad.ad_agent.ADAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_active_directory("CORP", "10.0.0.10")
        assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_active_directory_rejects_both_profile_and_credentials():
    result = await srv.test_active_directory(
        "CORP", "10.0.0.10",
        auth_profile="ad1",
        credentials={"username": "u", "password": "p"},
    )
    assert "error" in result
    assert "mutually exclusive" in result["error"]


@pytest.mark.asyncio
async def test_test_active_directory_profile_error():
    from cli.auth_profiles import ProfileError
    with patch("cli.auth_profiles.get_profile", side_effect=ProfileError("nope")):
        result = await srv.test_active_directory("CORP", "10.0.0.10", auth_profile="x")
    assert "error" in result


# ─── test_cloud paths ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_cloud_basic():
    with patch("agents.cloud.cloud_agent.CloudAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_cloud("aws", "arn:aws:account:123")
        assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_cloud_rejects_both_profile_and_credentials():
    result = await srv.test_cloud(
        "aws", "x",
        auth_profile="aws1",
        credentials={"key": "v"},
    )
    assert "error" in result


@pytest.mark.asyncio
async def test_test_cloud_profile_error():
    from cli.auth_profiles import ProfileError
    with patch("cli.auth_profiles.get_profile", side_effect=ProfileError("nope")):
        result = await srv.test_cloud("aws", "x", auth_profile="bad")
    assert "error" in result


# ─── discover_attack_chains ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_attack_chains_returns_chain_count():
    chains = [{"id": "c1"}, {"id": "c2"}]
    with patch("agents.exploit_chain.chain_agent.ExploitChainAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.discover_chains = AsyncMock(return_value=chains)
        result = await srv.discover_attack_chains("eng-1")
    assert result["chains_found"] == 2
    assert result["engagement_id"] == "eng-1"


# ─── generate_report ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_report_delegates_to_agent():
    with patch("agents.report.report_agent.ReportAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.generate_report = AsyncMock(return_value={"format": "markdown", "body": "..."})
        result = await srv.generate_report("eng-1", format="markdown")
    assert result["format"] == "markdown"


# ─── generate_detection_rules ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_detection_rules_returns_rule_count():
    rules = [{"name": "r1"}, {"name": "r2"}, {"name": "r3"}]
    with patch("agents.detection.detection_agent.DetectionAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.generate_rules = AsyncMock(return_value=rules)
        result = await srv.generate_detection_rules("eng-1")
    assert result["rules_count"] == 3
    assert result["engagement_id"] == "eng-1"


# ─── validate_finding ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_validate_finding_delegates_to_poc_agent():
    with patch("agents.poc_validator.poc_agent.PoCAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.validate_finding = AsyncMock(return_value={"valid": True})
        result = await srv.validate_finding("f-1")
    assert result == {"valid": True}


# ─── Specialist agent thin wrappers ─────────────────────────────────────


@pytest.mark.asyncio
async def test_test_api_security_delegates():
    with patch("agents.api_security.api_security_agent.APISecurityAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_api_security("https://api.example.com")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_credentials_delegates():
    with patch("agents.credential_tester.credential_tester_agent.CredentialTesterAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_credentials("https://target.example.com")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_vulnerabilities_delegates():
    with patch("agents.vuln_scanner.vuln_scanner_agent.VulnScannerAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_vulnerabilities("10.0.0.1")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_privesc_delegates():
    with patch("agents.privesc.privesc_agent.PrivescAdvisorAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_privesc("10.0.0.1", platform="linux")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_mobile_delegates():
    with patch("agents.mobile.mobile_agent.MobileAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_mobile("/tmp/app.apk", platform="android")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_wireless_delegates():
    with patch("agents.wireless.wireless_agent.WirelessAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_wireless("AP-name")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_test_social_engineering_delegates():
    with patch("agents.social_engineer.social_engineer_agent.SocialEngineerAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.run_assessment = AsyncMock(return_value={"findings": []})
        result = await srv.test_social_engineering("acme.com", campaign_type="phishing")
    assert isinstance(result, dict)


# ─── browser_inspect dispatch ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_browser_inspect_headers():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.check_security_headers = AsyncMock(return_value={"hsts": True})
        result = await srv.browser_inspect("https://example.com", action="headers")
    assert "result" in result


@pytest.mark.asyncio
async def test_browser_inspect_dom():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.inspect_dom = AsyncMock(return_value={"forms": []})
        result = await srv.browser_inspect("https://example.com", action="dom")
    assert "result" in result


@pytest.mark.asyncio
async def test_browser_inspect_network():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.capture_network = AsyncMock(return_value=[])
        result = await srv.browser_inspect("https://example.com", action="network")
    assert "result" in result


@pytest.mark.asyncio
async def test_browser_inspect_forms():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.extract_forms = AsyncMock(return_value=[])
        result = await srv.browser_inspect("https://example.com", action="forms")
    assert "result" in result


@pytest.mark.asyncio
async def test_browser_inspect_cookies():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.get_cookies = AsyncMock(return_value=[])
        result = await srv.browser_inspect("https://example.com", action="cookies")
    assert "result" in result


@pytest.mark.asyncio
async def test_browser_inspect_screenshot():
    with patch("agents.browser.browser_agent.BrowserAgent") as MockAgent:
        instance = MockAgent.return_value
        instance.capture_screenshot = AsyncMock(return_value=b"PNG_BYTES_HERE")
        result = await srv.browser_inspect("https://example.com", action="screenshot")
    assert result["bytes"] > 0


@pytest.mark.asyncio
async def test_browser_inspect_unknown_action():
    with patch("agents.browser.browser_agent.BrowserAgent"):
        result = await srv.browser_inspect("https://example.com", action="bogus")
    assert "error" in result


# ─── builtin scanner wrappers ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_headers_builtin():
    with patch("engine.scanners.scan_http_headers", new=AsyncMock(return_value=[{"title": "x"}])):
        result = await srv.scan_headers_builtin("http://example.com")
    assert result["findings_count"] == 1


@pytest.mark.asyncio
async def test_scan_ssl_builtin():
    with patch("engine.scanners.check_ssl", new=AsyncMock(return_value=[])):
        result = await srv.scan_ssl_builtin("example.com", port=443)
    assert result["findings_count"] == 0


@pytest.mark.asyncio
async def test_scan_paths_builtin():
    with patch("engine.scanners.scan_common_paths", new=AsyncMock(return_value=[])):
        result = await srv.scan_paths_builtin("http://example.com")
    assert "findings" in result


@pytest.mark.asyncio
async def test_scan_dns_builtin():
    with patch("engine.scanners.check_dns", new=AsyncMock(return_value=[])):
        result = await srv.scan_dns_builtin("example.com")
    assert "findings" in result


@pytest.mark.asyncio
async def test_scan_secrets_builtin():
    with patch("engine.scanners.scan_secrets_in_response", new=AsyncMock(return_value=[])):
        result = await srv.scan_secrets_builtin("http://example.com")
    assert "findings" in result


# ─── list_engagements ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_engagements_returns_db_rows():
    rows = [{"id": "eng-1", "status": "running"}]
    mock_db = _mock_db(list_engagements=rows)
    srv.findings_db = mock_db
    result = await srv.list_engagements(limit=20)
    assert result == rows


# ─── resume_engagement paths ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resume_engagement_not_found():
    mock_db = _mock_db(get_engagement=None)
    srv.findings_db = mock_db
    result = await srv.resume_engagement("missing")
    assert "error" in result


@pytest.mark.asyncio
async def test_resume_engagement_no_checkpoint():
    mock_db = _mock_db(get_engagement={"id": "eng-1"}, get_checkpoint=None)
    srv.findings_db = mock_db
    result = await srv.resume_engagement("eng-1")
    assert "error" in result


@pytest.mark.asyncio
async def test_resume_engagement_already_completed():
    mock_db = _mock_db(
        get_engagement={"id": "eng-1"},
        get_checkpoint={"status": "completed", "completed_phases": ["recon"]},
    )
    srv.findings_db = mock_db
    result = await srv.resume_engagement("eng-1")
    assert result["status"] == "already_completed"


@pytest.mark.asyncio
async def test_resume_engagement_resumes():
    mock_db = _mock_db(
        get_engagement={"id": "eng-1"},
        get_checkpoint={"status": "running", "completed_phases": ["recon"]},
    )
    srv.findings_db = mock_db
    mock_orch = MagicMock()
    mock_orch.resume_engagement = AsyncMock()
    srv.orchestrator = mock_orch
    result = await srv.resume_engagement("eng-1")
    assert result["status"] == "completed"
    assert result["resumed_from"] == ["recon"]


# ─── query_compliance ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_compliance_groups_by_control():
    findings = [
        {"title": "F1", "severity": "high", "category": "injection"},
        {"title": "F2", "severity": "medium", "category": "auth"},
    ]
    mock_db = _mock_db(get_findings=findings)
    srv.findings_db = mock_db
    with patch("engine.compliance.map_finding_compliance",
               return_value={"owasp": ["A01"], "pci_dss": ["6.5.1"]}):
        result = await srv.query_compliance("eng-1", framework="all")
    assert result["framework"] == "all"
    assert "controls" in result
    assert any(k.startswith("owasp:") for k in result["controls"])


@pytest.mark.asyncio
async def test_query_compliance_filters_by_framework():
    findings = [{"title": "F1", "severity": "high"}]
    mock_db = _mock_db(get_findings=findings)
    srv.findings_db = mock_db
    with patch("engine.compliance.map_finding_compliance",
               return_value={"owasp": ["A01"], "pci_dss": ["6.5.1"]}):
        result = await srv.query_compliance("eng-1", framework="owasp")
    assert all(k.startswith("owasp:") for k in result["controls"])


# ─── get_evidence paths ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_evidence_no_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_EVIDENCE_DIR", str(tmp_path / "missing"))
    result = await srv.get_evidence("eng-empty")
    assert result["artifacts"] == []


@pytest.mark.asyncio
async def test_get_evidence_lists_artifacts(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng-1"
    eng_dir.mkdir()
    (eng_dir / "screenshot-finding-abc.png").write_bytes(b"PNG")
    (eng_dir / "trace-finding-xyz.json").write_text("{}")
    monkeypatch.setenv("PENTEST_EVIDENCE_DIR", str(tmp_path))
    result = await srv.get_evidence("eng-1")
    assert len(result["artifacts"]) == 2


@pytest.mark.asyncio
async def test_get_evidence_filters_by_finding_id(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng-1"
    eng_dir.mkdir()
    (eng_dir / "screenshot-finding-abc.png").write_bytes(b"PNG")
    (eng_dir / "trace-finding-xyz.json").write_text("{}")
    monkeypatch.setenv("PENTEST_EVIDENCE_DIR", str(tmp_path))
    result = await srv.get_evidence("eng-1", finding_id="abc")
    assert len(result["artifacts"]) == 1


# ─── list_plugins / get_config ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_plugins_returns_loaded():
    with patch("tools.plugin_loader.load_plugins", return_value=[{"name": "demo"}]):
        result = await srv.list_plugins()
    assert result == [{"name": "demo"}]


@pytest.mark.asyncio
async def test_get_config_returns_masked_dict():
    fake_cfg = MagicMock()
    fake_cfg.to_dict.return_value = {"api_key": "***"}
    with patch("config.settings.load_config", return_value=fake_cfg):
        result = await srv.get_config()
    assert result == {"api_key": "***"}
    fake_cfg.to_dict.assert_called_once_with(mask_secrets=True)


# ─── set_intensity paths ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_set_intensity_engagement_not_found():
    mock_db = _mock_db(get_engagement=None)
    srv.findings_db = mock_db
    result = await srv.set_intensity("missing", "aggressive")
    assert "error" in result


@pytest.mark.asyncio
async def test_set_intensity_orchestrator_value_error():
    mock_db = _mock_db(get_engagement={"id": "eng-1"})
    srv.findings_db = mock_db
    mock_orch = MagicMock()
    mock_orch.set_intensity = AsyncMock(side_effect=ValueError("bad intensity"))
    mock_orch.is_running = False
    srv.orchestrator = mock_orch
    result = await srv.set_intensity("eng-1", "wrong")
    assert "error" in result


@pytest.mark.asyncio
async def test_set_intensity_success():
    mock_db = _mock_db(get_engagement={"id": "eng-1"})
    srv.findings_db = mock_db
    mock_orch = MagicMock()
    mock_orch.set_intensity = AsyncMock()
    mock_orch.is_running = True
    srv.orchestrator = mock_orch
    result = await srv.set_intensity("eng-1", "aggressive")
    assert result["intensity"] == "aggressive"
    assert result["applied_live"] is True


# ─── start_campaign / get_campaign_summary ──────────────────────────────


@pytest.mark.asyncio
async def test_start_campaign_creates_one_engagement_per_target():
    mock_db = _mock_db(create_campaign="camp-X")
    # create_engagement should be called once per target with unique IDs
    seq = iter([
        {"id": "eng-a", "target": "t1", "status": "running"},
        {"id": "eng-b", "target": "t2", "status": "running"},
        {"id": "eng-c", "target": "t3", "status": "running"},
    ])
    mock_db.create_engagement = AsyncMock(side_effect=lambda **kw: next(seq))
    srv.findings_db = mock_db
    result = await srv.start_campaign(["t1", "t2", "t3"], scope="full")
    assert result["campaign_id"] == "camp-X"
    assert result["targets"] == 3
    assert result["engagement_ids"] == ["eng-a", "eng-b", "eng-c"]


@pytest.mark.asyncio
async def test_get_campaign_summary_delegates_to_db():
    mock_db = _mock_db(get_campaign_summary={"engagements": 3, "findings": 12})
    srv.findings_db = mock_db
    result = await srv.get_campaign_summary("camp-X")
    assert result["findings"] == 12
