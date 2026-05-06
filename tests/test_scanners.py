"""Tests for engine/scanners.py — built-in security scanners."""

import asyncio
import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from engine.scanners import (
    _check_path,
    _check_port,
    check_dns,
    check_ssl,
    run_builtin_scan,
    scan_common_paths,
    scan_http_headers,
    scan_ports,
    scan_secrets_in_response,
)

# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------


class TestCheckPort:
    async def test_open_port_returns_finding(self):
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("engine.scanners.asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await _check_port("192.168.1.1", 22, 2.0, "ssh", {"ssh": "medium"})

        assert result["open"] is True
        assert result["severity"] == "medium"
        assert result["category"] == "network"
        assert "22" in result["title"]
        assert result["target"] == "192.168.1.1:22"

    async def test_closed_port_returns_not_open(self):
        with patch("engine.scanners.asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await _check_port("192.168.1.1", 9999, 2.0, "unknown", {})

        assert result == {"open": False}

    async def test_timeout_returns_not_open(self):
        with patch("engine.scanners.asyncio.open_connection", side_effect=asyncio.TimeoutError):
            result = await _check_port("10.0.0.1", 443, 2.0, "https", {})

        assert result == {"open": False}

    async def test_os_error_returns_not_open(self):
        with patch("engine.scanners.asyncio.open_connection", side_effect=OSError("unreachable")):
            result = await _check_port("10.0.0.1", 80, 2.0, "http", {})

        assert result == {"open": False}

    async def test_unknown_service_defaults_to_info_severity(self):
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("engine.scanners.asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await _check_port("192.168.1.1", 12345, 2.0, "unknown", {})

        assert result["severity"] == "info"

    async def test_high_risk_service_severity(self):
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        severity_map = {"mysql": "high"}
        with patch("engine.scanners.asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await _check_port("192.168.1.1", 3306, 2.0, "mysql", severity_map)

        assert result["severity"] == "high"
        assert result["tool_source"] == "pentest-tools-port-scan"


class TestScanPorts:
    async def test_open_ports_returned_as_findings(self):
        open_ports = {22, 80}

        async def fake_check_port(target, port, timeout, service, severity_map):
            if port in open_ports:
                return {
                    "open": True,
                    "title": f"Open port {port}/tcp",
                    "severity": "medium",
                    "target": f"{target}:{port}",
                }
            return {"open": False}

        with patch("engine.scanners._check_port", side_effect=fake_check_port):
            findings = await scan_ports("example.com", ports=[22, 80, 443])

        assert len(findings) == 2
        targets = {f["target"] for f in findings}
        assert "example.com:22" in targets
        assert "example.com:80" in targets

    async def test_no_open_ports_returns_empty(self):
        async def fake_check_port(target, port, timeout, service, severity_map):
            return {"open": False}

        with patch("engine.scanners._check_port", side_effect=fake_check_port):
            findings = await scan_ports("example.com", ports=[9998, 9999])

        assert findings == []

    async def test_default_port_list_used_when_none_given(self):
        async def fake_check_port(target, port, timeout, service, severity_map):
            return {"open": False}

        with patch("engine.scanners._check_port", side_effect=fake_check_port) as mock_fn:
            await scan_ports("example.com")

        called_ports = {call.args[1] for call in mock_fn.call_args_list}
        # Default list includes 22 and 80
        assert 22 in called_ports
        assert 80 in called_ports

    async def test_exceptions_from_gather_are_ignored(self):
        async def fake_check_port(target, port, timeout, service, severity_map):
            raise RuntimeError("unexpected")

        with patch("engine.scanners._check_port", side_effect=fake_check_port):
            findings = await scan_ports("example.com", ports=[22])

        # Exceptions propagate as exception objects, not dicts — they should be dropped
        assert findings == []


# ---------------------------------------------------------------------------
# HTTP header scanning
# ---------------------------------------------------------------------------


class TestScanHttpHeaders:
    def _make_response(self, headers: dict) -> MagicMock:
        resp = MagicMock(spec=httpx.Response)
        resp.headers = httpx.Headers(headers)
        return resp

    async def test_missing_hsts_generates_finding(self):
        resp = self._make_response({})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        titles = [f["title"] for f in findings]
        assert any("HSTS" in t for t in titles)

    async def test_missing_csp_generates_finding(self):
        resp = self._make_response({})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        titles = [f["title"] for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)

    async def test_all_security_headers_present_no_header_findings(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        resp = self._make_response(headers)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        missing_header_findings = [f for f in findings if f.get("category") == "misconfiguration" and "Missing" in f["title"]]
        assert missing_header_findings == []

    async def test_server_header_disclosure_reported(self):
        resp = self._make_response({"server": "Apache/2.4.51"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        server_findings = [f for f in findings if "Server header" in f["title"]]
        assert len(server_findings) == 1
        assert server_findings[0]["severity"] == "info"
        assert server_findings[0]["category"] == "information_disclosure"

    async def test_wildcard_cors_generates_finding(self):
        resp = self._make_response({"access-control-allow-origin": "*"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        cors_findings = [f for f in findings if "CORS" in f["title"]]
        assert len(cors_findings) == 1
        assert cors_findings[0]["severity"] == "medium"

    async def test_specific_cors_origin_not_flagged(self):
        resp = self._make_response({"access-control-allow-origin": "https://app.example.com"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        cors_findings = [f for f in findings if "CORS" in f["title"]]
        assert cors_findings == []

    async def test_insecure_cookie_missing_secure_flag(self):
        resp = self._make_response({"set-cookie": "session=abc123; Path=/; HttpOnly"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        secure_findings = [f for f in findings if "Secure flag" in f["title"]]
        assert len(secure_findings) == 1

    async def test_insecure_cookie_missing_httponly_flag(self):
        resp = self._make_response({"set-cookie": "session=abc123; Path=/; Secure"})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        httponly_findings = [f for f in findings if "HttpOnly flag" in f["title"]]
        assert len(httponly_findings) == 1

    async def test_http_error_returns_error_finding(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_http_headers("https://example.com")

        assert len(findings) == 1
        assert findings[0]["category"] == "error"
        assert findings[0]["severity"] == "info"

    async def test_target_without_scheme_gets_https_prefix(self):
        resp = self._make_response({})
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            await scan_http_headers("example.com")

        mock_client.get.assert_called_once_with("https://example.com")


# ---------------------------------------------------------------------------
# SSL/TLS checking
# ---------------------------------------------------------------------------


class TestCheckSsl:
    def _make_ssl_socket(self, cert: dict, cipher: tuple, version: str) -> MagicMock:
        ssock = MagicMock()
        ssock.getpeercert.return_value = cert
        ssock.cipher.return_value = cipher
        ssock.version.return_value = version
        ssock.__enter__ = MagicMock(return_value=ssock)
        ssock.__exit__ = MagicMock(return_value=False)
        return ssock

    async def test_valid_cert_no_findings(self):
        from datetime import datetime, timedelta

        future = datetime.now() + timedelta(days=90)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        assert findings == []

    async def test_expired_cert_generates_high_finding(self):
        from datetime import datetime, timedelta

        past = datetime.now() - timedelta(days=10)
        cert = {"notAfter": past.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        expired = [f for f in findings if "expired" in f["title"]]
        assert len(expired) == 1
        assert expired[0]["severity"] == "high"

    async def test_cert_expiring_soon_generates_medium_finding(self):
        from datetime import datetime, timedelta

        soon = datetime.now() + timedelta(days=15)
        cert = {"notAfter": soon.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        expiring = [f for f in findings if "expires in" in f["title"]]
        assert len(expiring) == 1
        assert expiring[0]["severity"] == "medium"

    async def test_weak_tls_version_generates_high_finding(self):
        from datetime import datetime, timedelta

        future = datetime.now() + timedelta(days=90)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("AES128-SHA", "TLSv1", 128), "TLSv1")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        weak_tls = [f for f in findings if "Weak TLS" in f["title"]]
        assert len(weak_tls) == 1
        assert weak_tls[0]["severity"] == "high"

    async def test_rc4_cipher_generates_high_finding(self):
        from datetime import datetime, timedelta

        future = datetime.now() + timedelta(days=90)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("RC4-SHA", "TLSv1.2", 128), "TLSv1.2")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        cipher_findings = [f for f in findings if "Weak cipher" in f["title"]]
        assert len(cipher_findings) == 1
        assert cipher_findings[0]["severity"] == "high"

    async def test_des_cipher_generates_high_finding(self):
        from datetime import datetime, timedelta

        future = datetime.now() + timedelta(days=90)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y UTC")}
        ssock = self._make_ssl_socket(cert, ("DES-CBC3-SHA", "TLSv1.2", 112), "TLSv1.2")

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = ssock
            findings = await check_ssl("example.com")

        cipher_findings = [f for f in findings if "Weak cipher" in f["title"]]
        assert len(cipher_findings) == 1

    async def test_ssl_cert_verification_error_returns_high_finding(self):
        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("engine.scanners.socket.create_connection", return_value=mock_raw_sock), \
             patch("engine.scanners.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
            findings = await check_ssl("example.com")

        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["category"] == "misconfiguration"

    async def test_generic_exception_returns_info_finding(self):
        with patch("engine.scanners.socket.create_connection", side_effect=OSError("timeout")):
            findings = await check_ssl("example.com")

        assert len(findings) == 1
        assert findings[0]["category"] == "error"
        assert findings[0]["severity"] == "info"

    async def test_hostname_stripped_of_scheme(self):
        with patch("engine.scanners.socket.create_connection", side_effect=OSError("x")) as mock_conn:
            await check_ssl("https://example.com/path")

        mock_conn.assert_called_once_with(("example.com", 443), timeout=5)

    async def test_custom_port_used(self):
        with patch("engine.scanners.socket.create_connection", side_effect=OSError("x")) as mock_conn:
            await check_ssl("example.com", port=8443)

        mock_conn.assert_called_once_with(("example.com", 8443), timeout=5)


# ---------------------------------------------------------------------------
# Common path scanning
# ---------------------------------------------------------------------------


class TestCheckPath:
    async def test_found_path_returns_finding(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = "admin panel content here"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/admin", "/admin")

        assert result.get("found") is None or result.get("found")  # either "found" key or truthy dict
        assert result["category"] == "discovery"
        assert result["severity"] == "medium"

    async def test_not_found_returns_found_false(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404
        resp.text = "not found"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/missing", "/missing")

        assert result == {"found": False}

    async def test_empty_body_returns_found_false(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = ""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/empty", "/empty")

        assert result == {"found": False}

    async def test_env_file_gets_critical_severity(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = "DB_PASSWORD=secret"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/.env", "/.env")

        assert result["severity"] == "critical"

    async def test_git_config_gets_critical_severity(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = "[core] repositoryformatversion = 0"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/.git/config", "/.git/config")

        assert result["severity"] == "critical"

    async def test_backup_sql_gets_critical_severity(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = "INSERT INTO users..."
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/backup.sql", "/backup.sql")

        assert result["severity"] == "critical"

    async def test_phpmyadmin_gets_high_severity(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.text = "phpMyAdmin login page"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)

        result = await _check_path(mock_client, "https://example.com/phpmyadmin", "/phpmyadmin")

        assert result["severity"] == "high"

    async def test_exception_returns_found_false(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        result = await _check_path(mock_client, "https://example.com/admin", "/admin")

        assert result == {"found": False}


class TestScanCommonPaths:
    async def test_found_paths_returned(self):
        async def fake_check_path(client, url, path):
            if path == "/.env":
                return {
                    "found": True,
                    "title": "Accessible path: /.env",
                    "severity": "critical",
                    "category": "discovery",
                    "tool_source": "pentest-tools-path-scan",
                    "target": url,
                    "evidence": "GET /.env returned 200 (50 bytes)",
                }
            return {"found": False}

        with patch("engine.scanners._check_path", side_effect=fake_check_path):
            findings = await scan_common_paths("https://example.com")

        assert len(findings) == 1
        assert "/.env" in findings[0]["title"]

    async def test_no_accessible_paths_returns_empty(self):
        async def fake_check_path(client, url, path):
            return {"found": False}

        with patch("engine.scanners._check_path", side_effect=fake_check_path):
            findings = await scan_common_paths("https://example.com")

        assert findings == []

    async def test_target_without_scheme_gets_https_prefix(self):
        captured_urls = []

        async def fake_check_path(client, url, path):
            captured_urls.append(url)
            return {"found": False}

        with patch("engine.scanners._check_path", side_effect=fake_check_path):
            await scan_common_paths("example.com")

        assert all(u.startswith("https://example.com") for u in captured_urls)


# ---------------------------------------------------------------------------
# DNS checking
# ---------------------------------------------------------------------------


class TestCheckDns:
    async def test_a_record_returns_finding(self):
        mock_addrinfo = [(socket.AF_INET, None, None, None, ("1.2.3.4", 0))]

        with patch("engine.scanners.socket.getaddrinfo", return_value=mock_addrinfo):
            findings = await check_dns("example.com")

        a_records = [f for f in findings if "DNS A record" in f["title"]]
        assert len(a_records) == 1
        assert "1.2.3.4" in a_records[0]["title"]
        assert a_records[0]["severity"] == "info"
        assert a_records[0]["category"] == "recon"

    async def test_subdomain_discovery(self):
        def fake_getaddrinfo(host, port, family=None):
            if host == "www.example.com":
                return [(socket.AF_INET, None, None, None, ("1.2.3.4", 0))]
            if host == "example.com":
                return [(socket.AF_INET, None, None, None, ("1.2.3.4", 0))]
            raise socket.gaierror("NXDOMAIN")

        with patch("engine.scanners.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            findings = await check_dns("example.com")

        subdomain_findings = [f for f in findings if "Subdomain discovered" in f["title"]]
        assert any("www.example.com" in f["title"] for f in subdomain_findings)

    async def test_nxdomain_returns_error_finding(self):
        with patch("engine.scanners.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            findings = await check_dns("nonexistent.invalid")

        assert len(findings) == 1
        assert findings[0]["category"] == "error"
        assert "resolution failed" in findings[0]["title"].lower()

    async def test_hostname_stripped_of_scheme(self):
        mock_addrinfo = [(socket.AF_INET, None, None, None, ("9.9.9.9", 0))]

        with patch("engine.scanners.socket.getaddrinfo", return_value=mock_addrinfo) as mock_fn:
            await check_dns("https://example.com/path")

        # First call should be with bare hostname
        first_call_host = mock_fn.call_args_list[0].args[0]
        assert first_call_host == "example.com"

    async def test_multiple_ips_all_reported(self):
        mock_addrinfo = [
            (socket.AF_INET, None, None, None, ("1.1.1.1", 0)),
            (socket.AF_INET, None, None, None, ("2.2.2.2", 0)),
        ]

        with patch("engine.scanners.socket.getaddrinfo", return_value=mock_addrinfo):
            findings = await check_dns("example.com")

        a_record_findings = [f for f in findings if "DNS A record" in f["title"]]
        ips = {f["evidence"].replace("A record: ", "") for f in a_record_findings}
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------


class TestScanSecretsInResponse:
    def _make_response(self, body: str) -> MagicMock:
        resp = MagicMock(spec=httpx.Response)
        resp.text = body
        return resp

    async def test_aws_access_key_detected(self):
        body = "config: AKIAIOSFODNN7EXAMPLE123"
        resp = self._make_response(body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        aws_findings = [f for f in findings if "AWS Access Key" in f["title"]]
        assert len(aws_findings) >= 1
        assert aws_findings[0]["severity"] == "critical"
        assert aws_findings[0]["category"] == "secret"

    async def test_private_key_detected(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        resp = self._make_response(body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        key_findings = [f for f in findings if "Private Key" in f["title"]]
        assert len(key_findings) >= 1

    async def test_jwt_token_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123defXYZ"
        body = f"Authorization: Bearer {jwt}"
        resp = self._make_response(body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        jwt_findings = [f for f in findings if "JWT" in f["title"]]
        assert len(jwt_findings) >= 1

    async def test_connection_string_detected(self):
        body = "DATABASE_URL=postgres://admin:password@localhost:5432/mydb"
        resp = self._make_response(body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        conn_findings = [f for f in findings if "Connection String" in f["title"]]
        assert len(conn_findings) >= 1

    async def test_clean_response_returns_empty(self):
        body = "<html><body>Welcome to our site!</body></html>"
        resp = self._make_response(body)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        assert findings == []

    async def test_matches_limited_to_three_per_type(self):
        # Four AWS key-like patterns — only first 3 should be reported
        keys = " ".join([f"AKIA{'A' * 16}{i}" for i in range(4)])
        resp = self._make_response(keys)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        aws_findings = [f for f in findings if "AWS Access Key" in f["title"]]
        assert len(aws_findings) <= 3

    async def test_http_error_returns_empty(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            findings = await scan_secrets_in_response("https://example.com")

        assert findings == []

    async def test_target_without_scheme_gets_https_prefix(self):
        resp = self._make_response("")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("engine.scanners.httpx.AsyncClient", return_value=mock_client):
            await scan_secrets_in_response("example.com")

        mock_client.get.assert_called_once_with("https://example.com")


# ---------------------------------------------------------------------------
# run_builtin_scan orchestrator
# ---------------------------------------------------------------------------


class TestRunBuiltinScan:
    async def test_returns_expected_structure(self):
        with patch("engine.scanners.scan_ports", return_value=[]), \
             patch("engine.scanners.scan_http_headers", return_value=[]), \
             patch("engine.scanners.check_ssl", return_value=[]), \
             patch("engine.scanners.scan_common_paths", return_value=[]), \
             patch("engine.scanners.check_dns", return_value=[]), \
             patch("engine.scanners.scan_secrets_in_response", return_value=[]):
            result = await run_builtin_scan("https://example.com")

        assert result["target"] == "https://example.com"
        assert result["scan_type"] == "all"
        assert result["status"] == "complete"
        assert result["builtin"] is True
        assert isinstance(result["findings"], list)
        assert isinstance(result["by_severity"], dict)

    async def test_findings_deduplicated_by_title(self):
        duplicate_finding = {
            "title": "Open port 80/tcp — http",
            "severity": "info",
            "category": "network",
        }

        with patch("engine.scanners.scan_ports", return_value=[duplicate_finding, duplicate_finding]), \
             patch("engine.scanners.scan_http_headers", return_value=[]), \
             patch("engine.scanners.check_ssl", return_value=[]), \
             patch("engine.scanners.scan_common_paths", return_value=[]), \
             patch("engine.scanners.check_dns", return_value=[]), \
             patch("engine.scanners.scan_secrets_in_response", return_value=[]):
            result = await run_builtin_scan("https://example.com")

        titles = [f["title"] for f in result["findings"]]
        assert titles.count("Open port 80/tcp — http") == 1

    async def test_by_severity_counts_are_accurate(self):
        findings = [
            {"title": "A", "severity": "high"},
            {"title": "B", "severity": "high"},
            {"title": "C", "severity": "medium"},
        ]

        with patch("engine.scanners.scan_ports", return_value=findings), \
             patch("engine.scanners.scan_http_headers", return_value=[]), \
             patch("engine.scanners.check_ssl", return_value=[]), \
             patch("engine.scanners.scan_common_paths", return_value=[]), \
             patch("engine.scanners.check_dns", return_value=[]), \
             patch("engine.scanners.scan_secrets_in_response", return_value=[]):
            result = await run_builtin_scan("https://example.com")

        assert result["by_severity"]["high"] == 2
        assert result["by_severity"]["medium"] == 1

    async def test_specific_scan_type_runs_only_that_scanner(self):
        with patch("engine.scanners.scan_ports", return_value=[]) as mock_ports, \
             patch("engine.scanners.check_dns", return_value=[]) as mock_dns:
            result = await run_builtin_scan("example.com", scan_type="ports")

        mock_ports.assert_called_once()
        mock_dns.assert_not_called()
        assert result["scan_type"] == "ports"

    async def test_findings_count_matches_findings_list(self):
        some_findings = [
            {"title": f"Finding {i}", "severity": "info"} for i in range(5)
        ]

        with patch("engine.scanners.scan_ports", return_value=some_findings), \
             patch("engine.scanners.scan_http_headers", return_value=[]), \
             patch("engine.scanners.check_ssl", return_value=[]), \
             patch("engine.scanners.scan_common_paths", return_value=[]), \
             patch("engine.scanners.check_dns", return_value=[]), \
             patch("engine.scanners.scan_secrets_in_response", return_value=[]):
            result = await run_builtin_scan("https://example.com")

        assert result["findings_count"] == len(result["findings"])
