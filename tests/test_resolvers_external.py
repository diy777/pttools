"""Phase 3 tests: op / vault / aws-sm resolvers (with mocked backends)."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from cli.credential_resolvers import SecurityError
from cli.credential_resolvers.op import OpResolver
from cli.credential_resolvers.vault import VaultResolver

# aws_sm depends on boto3 which is in [cloud] extra; skip aws-sm tests if missing
try:
    import boto3  # noqa: F401

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# ---------- op resolver ----------


def _completed(stdout="", stderr="", code=0):
    cp = subprocess.CompletedProcess(args=["op", "read"], returncode=code)
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


def test_op_resolver_resolves(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("subprocess.run", return_value=_completed(stdout="hunter2")):
        cred = OpResolver().resolve("op://Vault/Item/password")
    assert cred.reveal() == "hunter2"
    assert cred.source == "op"


def test_op_resolver_rejects_invalid_uri():
    with pytest.raises(SecurityError) as exc:
        OpResolver().resolve("not-an-op-uri")
    assert "op://" in str(exc.value)


def test_op_resolver_fails_closed_when_op_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(SecurityError) as exc:
        OpResolver().resolve("op://Vault/Item/password")
    assert "not installed" in str(exc.value).lower()


def test_op_resolver_fails_closed_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("subprocess.run", return_value=_completed(code=1, stderr="auth required")), pytest.raises(SecurityError):
        OpResolver().resolve("op://Vault/Item/password")


def test_op_resolver_fails_closed_on_empty_value(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("subprocess.run", return_value=_completed(stdout="")), pytest.raises(SecurityError):
        OpResolver().resolve("op://Vault/Item/password")


def test_op_resolver_value_does_not_leak_in_error(monkeypatch):
    SENTINEL = "supersecret-does-not-leak"
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("subprocess.run", return_value=_completed(code=2, stderr=SENTINEL)):
        try:
            OpResolver().resolve("op://X/Y/password")
        except SecurityError as e:
            assert SENTINEL not in str(e)


# ---------- vault resolver ----------


def _vault_response(json_payload, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_payload
    return resp


def test_vault_resolver_kv_v2(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "v.test.tok")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    with patch(
        "httpx.get",
        return_value=_vault_response(
            {"data": {"data": {"password": "kv2pass"}}}
        ),
    ):
        cred = VaultResolver().resolve("secret/data/pentests/x")
    assert cred.reveal() == "kv2pass"


def test_vault_resolver_kv_v1(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "v.test.tok")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    with patch(
        "httpx.get",
        return_value=_vault_response({"data": {"password": "kv1pass"}}),
    ):
        cred = VaultResolver().resolve("secret/pentests/x")
    assert cred.reveal() == "kv1pass"


def test_vault_resolver_custom_field(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "v.test.tok")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    with patch(
        "httpx.get",
        return_value=_vault_response({"data": {"data": {"api_key": "abc123"}}}),
    ):
        cred = VaultResolver().resolve(
            "secret/data/x", password_field="api_key"
        )
    assert cred.reveal() == "abc123"


def test_vault_resolver_no_token(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(SecurityError) as exc:
        VaultResolver().resolve("secret/data/x")
    assert "VAULT_TOKEN" in str(exc.value)


def test_vault_resolver_no_addr(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "x")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    with pytest.raises(SecurityError) as exc:
        VaultResolver().resolve("secret/data/x")
    assert "VAULT_ADDR" in str(exc.value)


def test_vault_resolver_404(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "x")
    monkeypatch.setenv("VAULT_ADDR", "https://v.example")
    with patch("httpx.get", return_value=_vault_response({}, status=404)), pytest.raises(SecurityError) as exc:
        VaultResolver().resolve("secret/data/missing")
    assert "404" in str(exc.value)


def test_vault_resolver_403(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "x")
    monkeypatch.setenv("VAULT_ADDR", "https://v.example")
    with patch("httpx.get", return_value=_vault_response({}, status=403)), pytest.raises(SecurityError):
        VaultResolver().resolve("secret/data/x")


def test_vault_resolver_empty_field(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "x")
    monkeypatch.setenv("VAULT_ADDR", "https://v.example")
    with patch(
        "httpx.get",
        return_value=_vault_response({"data": {"data": {"password": ""}}}),
    ), pytest.raises(SecurityError):
        VaultResolver().resolve("secret/data/x")


# ---------- aws-sm resolver ----------


@pytest.mark.skipif(not BOTO3_AVAILABLE, reason="boto3 not installed")
class TestAwsSmResolver:
    def test_string_secret(self):
        from cli.credential_resolvers.aws_sm import AwsSmResolver

        with patch("boto3.client") as MockClient:
            client = MockClient.return_value
            client.get_secret_value.return_value = {"SecretString": "rawpass"}
            cred = AwsSmResolver().resolve("pentests/staging")
        assert cred.reveal() == "rawpass"

    def test_json_secret_with_field(self):
        from cli.credential_resolvers.aws_sm import AwsSmResolver

        with patch("boto3.client") as MockClient:
            client = MockClient.return_value
            client.get_secret_value.return_value = {
                "SecretString": json.dumps({"username": "admin", "password": "jsonpass"})
            }
            cred = AwsSmResolver().resolve(
                "pentests/staging", password_field="password"
            )
        assert cred.reveal() == "jsonpass"

    def test_get_secret_value_failure(self):
        from cli.credential_resolvers.aws_sm import AwsSmResolver

        with patch("boto3.client") as MockClient:
            client = MockClient.return_value
            client.get_secret_value.side_effect = Exception("AccessDenied")
            with pytest.raises(SecurityError) as exc:
                AwsSmResolver().resolve("pentests/staging")
            assert "GetSecretValue failed" in str(exc.value)


def test_aws_sm_fails_closed_without_boto3(monkeypatch):
    """Even without boto3, requesting aws-sm should fail with a clear message."""
    if BOTO3_AVAILABLE:
        # Simulate boto3 being unimportable
        import sys

        monkeypatch.setitem(sys.modules, "boto3", None)
    from cli.credential_resolvers.aws_sm import AwsSmResolver

    with pytest.raises(SecurityError) as exc:
        AwsSmResolver().resolve("pentests/staging")
    assert "boto3" in str(exc.value)
