"""Tests for severity calibration in nuclei + nikto parsers.

Real Juice Shop scans were producing 200+ findings, mostly info-level
noise from tech-fingerprint duplicates and trivia. These parsers now:

- Drop info-level findings that duplicate other phases (tech-detect,
  fingerprint, robots.txt, favicon, etc.)
- Bump real security misconfigs (missing security headers, insecure
  cookies, directory listing) from info to low so they surface in
  reports rather than getting filtered out.

These tests pin both the drop and the bump so a future "let's surface
everything" change doesn't quietly re-flood the findings table.
"""

from __future__ import annotations

from tools.registry import parse_nikto, parse_nuclei

# ─── Nuclei calibration ───────────────────────────────────────────────────


class TestNucleiCalibration:
    def test_high_severity_kept_as_is(self):
        result = {
            "stdout": "[some-cve] [http] [critical] http://t.local",
            "target": "http://t.local",
        }
        findings = parse_nuclei(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_tech_detect_info_dropped(self):
        result = {
            "stdout": "[tech-detect:nginx] [http] [info] http://t.local",
            "target": "http://t.local",
        }
        assert parse_nuclei(result) == []

    def test_fingerprint_info_dropped(self):
        result = {
            "stdout": "[favicon-detect] [http] [info] http://t.local",
            "target": "http://t.local",
        }
        assert parse_nuclei(result) == []

    def test_missing_csp_info_bumped_to_low(self):
        result = {
            "stdout": "[missing-csp-header] [http] [info] http://t.local",
            "target": "http://t.local",
        }
        findings = parse_nuclei(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_cookie_without_secure_bumped_to_low(self):
        result = {
            "stdout": "[cookies-without-secure] [http] [info] http://t.local",
            "target": "http://t.local",
        }
        findings = parse_nuclei(result)
        assert findings[0]["severity"] == "low"

    def test_unknown_info_template_kept_as_info(self):
        # An info-level template that is neither noise nor a known misconfig
        # should pass through unchanged.
        result = {
            "stdout": "[some-novel-thing] [http] [info] http://t.local",
            "target": "http://t.local",
        }
        findings = parse_nuclei(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"


# ─── Nikto calibration ────────────────────────────────────────────────────


class TestNiktoCalibration:
    def test_real_vulnerability_kept_high(self):
        result = {
            "stdout": "+ /admin/: SQL injection appears possible",
            "target": "http://t.local",
        }
        findings = parse_nikto(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["category"] == "vulnerability"

    def test_missing_x_frame_options_bumped_to_low(self):
        result = {
            "stdout": (
                "+ The X-Frame-Options header is not set. "
                "This could allow the website to be framed."
            ),
            "target": "http://t.local",
        }
        findings = parse_nikto(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert findings[0]["category"] == "misconfiguration"

    def test_missing_hsts_bumped_to_low(self):
        result = {
            "stdout": "+ The Strict-Transport-Security header is missing",
            "target": "http://t.local",
        }
        findings = parse_nikto(result)
        assert findings[0]["severity"] == "low"

    def test_cookie_without_httponly_bumped_to_low(self):
        result = {
            "stdout": "+ Cookie session_id created without the httponly flag",
            "target": "http://t.local",
        }
        findings = parse_nikto(result)
        assert findings[0]["severity"] == "low"

    def test_robots_txt_dropped(self):
        result = {
            "stdout": "+ /robots.txt: Entry '/admin' is in the file",
            "target": "http://t.local",
        }
        assert parse_nikto(result) == []

    def test_favicon_noise_dropped(self):
        result = {
            "stdout": "+ /favicon.ico: identifies this as an Apache server",
            "target": "http://t.local",
        }
        assert parse_nikto(result) == []

    def test_unknown_observation_kept_as_info(self):
        result = {
            "stdout": "+ /unusual-path: returned 200",
            "target": "http://t.local",
        }
        findings = parse_nikto(result)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert findings[0]["category"] == "discovery"
