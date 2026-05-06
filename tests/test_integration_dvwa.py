"""Integration test: full pipeline against local DVWA instance."""


import pytest

from engine.dedup import FindingDeduplicator
from engine.evidence import EvidenceCollector
from engine.findings_db import FindingsDB
from engine.orchestrator import AgentOrchestrator
from engine.scope import ScopeEnforcer

DVWA_URL = "http://localhost:4280"


def dvwa_reachable():
    import httpx
    try:
        r = httpx.get(DVWA_URL, follow_redirects=True, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not dvwa_reachable(), reason="DVWA not running on localhost:4280")


@pytest.fixture
def db():
    return FindingsDB(":memory:")


@pytest.fixture
def scope():
    return ScopeEnforcer(
        allowed_targets=["localhost", "127.0.0.1"],
        allowed_ports=[80, 4280, 443],
        mode="strict",
    )


@pytest.fixture
def dedup():
    return FindingDeduplicator()


@pytest.fixture
def evidence(tmp_path):
    return EvidenceCollector(base_dir=str(tmp_path))


class TestScopeAgainstDVWA:
    def test_dvwa_in_scope(self, scope):
        allowed, reason = scope.check("localhost")
        assert allowed

    def test_external_blocked(self, scope):
        allowed, reason = scope.check("evil.com")
        assert not allowed

    def test_dvwa_port_allowed(self, scope):
        allowed, _ = scope.check_port(4280)
        assert allowed

    def test_random_port_blocked(self, scope):
        allowed, _ = scope.check_port(9999)
        assert not allowed


class TestBuiltinScannersAgainstDVWA:
    async def test_port_scan(self):
        from engine.scanners import scan_ports
        results = await scan_ports("localhost")
        assert isinstance(results, list)
        assert len(results) > 0
        assert "category" in results[0]

    async def test_http_headers(self):
        from engine.scanners import scan_http_headers
        results = await scan_http_headers(DVWA_URL)
        assert isinstance(results, list)
        assert len(results) > 0
        assert results[0]["category"] == "misconfiguration"

    async def test_path_scan(self):
        from engine.scanners import scan_common_paths
        results = await scan_common_paths(DVWA_URL)
        assert isinstance(results, list)


class TestDedupWithRealFindings:
    def test_dedup_real_findings(self, dedup):
        f1 = {
            "id": "f1", "target": "localhost", "category": "web",
            "title": "Missing X-Frame-Options header",
            "description": "The X-Frame-Options header is not set",
        }
        f2 = {
            "id": "f2", "target": "localhost", "category": "web",
            "title": "Missing X-Frame-Options header",
            "description": "X-Frame-Options not present",
        }
        enriched1 = dedup.enrich(f1)
        assert "fingerprint" in enriched1

        is_dup, _ = dedup.is_duplicate(f1)
        assert not is_dup

        is_dup2, _ = dedup.is_duplicate(f2)
        assert is_dup2


class TestEvidenceWithRealData:
    async def test_store_http_from_dvwa(self, evidence):
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(DVWA_URL, follow_redirects=True)

        artifact = await evidence.store_http_exchange(
            engagement_id="dvwa-test",
            finding_id="f-dvwa-1",
            method="GET",
            url=DVWA_URL,
            request_headers=dict(resp.request.headers),
            request_body="",
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text[:2000],
        )
        assert artifact.sha256
        assert artifact.size_bytes > 0

    async def test_integrity_after_store(self, evidence):
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(DVWA_URL, follow_redirects=True)

        await evidence.store_http_exchange(
            engagement_id="dvwa-verify",
            finding_id="f-dvwa-2",
            method="GET",
            url=DVWA_URL,
            request_headers={},
            request_body="",
            status_code=resp.status_code,
            response_headers={},
            response_body=resp.text[:500],
        )
        violations = evidence.verify_integrity("dvwa-verify")
        assert len(violations) == 0


class TestAuthenticatedScanAgainstDVWA:
    """Regression gate for Phase 1: pttools must find SQLi + XSS + cmdi on DVWA.

    These are the vulnerabilities every DVWA install ships with. If any of
    them stops being detected, Phase 1 has regressed and the scanner is no
    longer demonstrably vouchable on its canonical target.

    Requires a freshly-initialized DVWA (login works, DB is clean). If
    DVWA's admin password was corrupted by an earlier run, reset it via
    http://localhost:4280/setup.php.
    """

    async def test_auth_scan_finds_sqli_xss_cmdi(self):
        from engine.auth_session import WebAuthenticator
        from engine.authenticated_scan import run_authenticated_scan

        authenticator = WebAuthenticator(
            flow="form_post",
            login_url="http://localhost:4280/login.php",
            username="admin",
            password="password",
        )
        result = await run_authenticated_scan(
            target="http://localhost:4280/index.php",
            authenticator=authenticator,
            max_pages=30,
        )

        assert result["endpoints_tested"] >= 5, (
            f"crawler found too few endpoints: {result['endpoints_tested']}"
        )
        findings = result["findings"]
        assert findings, "authenticated scan produced zero findings on DVWA"

        titles = [f["title"] for f in findings]
        assert any("SQL injection" in t for t in titles), (
            f"expected SQLi finding, got: {titles}"
        )
        assert any("Reflected XSS" in t for t in titles), (
            f"expected reflected XSS finding, got: {titles}"
        )
        assert any("Command injection" in t for t in titles), (
            f"expected command injection finding, got: {titles}"
        )

        for f in findings:
            assert f["category"] == "injection"
            assert f["tool_source"] == "authenticated_scan"
            assert f["severity"] in ("critical", "high")
            assert f["poc"], f"finding missing PoC: {f['title']}"


class TestOrchestratorAgainstDVWA:
    async def test_recon_phase_runs(self, db, scope):
        orch = AgentOrchestrator(db, scope=scope)
        eng = await db.create_engagement("localhost", "full", "", "normal")
        await orch._run_recon(eng)

    async def test_detection_phase_after_findings(self, db):
        orch = AgentOrchestrator(db)
        eng = await db.create_engagement("localhost", "full", "", "normal")
        await db.add_finding({
            "engagement_id": eng["id"],
            "title": "Missing security headers on DVWA",
            "description": "X-Frame-Options, CSP, HSTS not set",
            "severity": "medium",
            "category": "web",
            "target": "localhost:4280",
        })
        await orch._run_detection_generation(eng)
        rules = await db.get_detection_rules(eng["id"])
        assert len(rules) >= 3

    async def test_chain_discovery_after_findings(self, db):
        orch = AgentOrchestrator(db)
        eng = await db.create_engagement("localhost", "full", "", "normal")
        await db.add_finding({
            "engagement_id": eng["id"],
            "title": "SQL Injection in login",
            "description": "SQLi via user parameter",
            "severity": "critical",
            "category": "injection",
            "target": "localhost:4280",
        })
        await db.add_finding({
            "engagement_id": eng["id"],
            "title": "Admin panel exposed",
            "description": "Admin panel at /admin",
            "severity": "medium",
            "category": "discovery",
            "target": "localhost:4280",
        })
        await orch._run_exploit_chaining(eng)
        chains = await db.get_attack_chains(eng["id"])
        assert len(chains) >= 1
