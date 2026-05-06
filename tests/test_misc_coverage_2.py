"""Coverage fill batch 2: aws_sm resolver, recon agent, chain CLI helpers,
report renderer write_report."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ─── cli/credential_resolvers/aws_sm ────────────────────────────────────


def test_aws_sm_empty_ref_raises():
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    with pytest.raises(SecurityError):
        AwsSmResolver().resolve("")


def test_aws_sm_returns_plain_string():
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretString": "supersecret"}
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client

    with patch.dict("sys.modules", {"boto3": fake_boto}):
        cred = AwsSmResolver().resolve("arn:aws:secretsmanager:us-east-1:1:secret:x")
    assert cred.reveal() == "supersecret"


def test_aws_sm_returns_json_field():
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"password": "pw1", "user": "u"})
    }
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client

    with patch.dict("sys.modules", {"boto3": fake_boto}):
        cred = AwsSmResolver().resolve("ref", password_field="password")
    assert cred.reveal() == "pw1"


def test_aws_sm_json_field_missing_raises():
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"other": "x"})
    }
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client
    with patch.dict("sys.modules", {"boto3": fake_boto}), pytest.raises(SecurityError):
        AwsSmResolver().resolve("ref", password_field="password")


def test_aws_sm_binary_secret_raises():
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretBinary": b"\x00\x01"}
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client
    with patch.dict("sys.modules", {"boto3": fake_boto}), pytest.raises(SecurityError):
        AwsSmResolver().resolve("ref")


def test_aws_sm_empty_secret_raises():
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretString": ""}
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client
    with patch.dict("sys.modules", {"boto3": fake_boto}), pytest.raises(SecurityError):
        AwsSmResolver().resolve("ref")


def test_aws_sm_get_secret_value_failure_wrapped():
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver
    fake_client = MagicMock()
    fake_client.get_secret_value.side_effect = RuntimeError("AccessDenied")
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client
    with patch.dict("sys.modules", {"boto3": fake_boto}), pytest.raises(SecurityError) as exc_info:
        AwsSmResolver().resolve("ref")
    assert "GetSecretValue" in str(exc_info.value)


def test_aws_sm_missing_boto3_raises_security_error():
    """When boto3 isn't installed, the resolver raises SecurityError, not ImportError."""
    from cli.credential_resolvers import SecurityError
    from cli.credential_resolvers.aws_sm import AwsSmResolver

    real_import = __import__

    def _import(name, *a, **kw):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **kw)

    with patch("builtins.__import__", side_effect=_import), pytest.raises(SecurityError) as exc_info:
        AwsSmResolver().resolve("ref")
    assert "boto3" in str(exc_info.value)


# ─── agents/recon ───────────────────────────────────────────────────────


def test_recon_env_int_default():
    from agents.recon.recon_agent import _env_int
    assert _env_int("DEFINITELY_NOT_SET", 100) == 100


def test_recon_env_int_valid_override(monkeypatch):
    from agents.recon.recon_agent import _env_int
    monkeypatch.setenv("PT_TEST_RECON_ENV", "42")
    assert _env_int("PT_TEST_RECON_ENV", 100) == 42


def test_recon_env_int_invalid_value_falls_back(monkeypatch):
    from agents.recon.recon_agent import _env_int
    monkeypatch.setenv("PT_TEST_RECON_ENV", "not-a-number")
    assert _env_int("PT_TEST_RECON_ENV", 100) == 100


def test_recon_env_int_zero_or_negative_falls_back(monkeypatch):
    from agents.recon.recon_agent import _env_int
    monkeypatch.setenv("PT_TEST_RECON_ENV", "0")
    assert _env_int("PT_TEST_RECON_ENV", 100) == 100
    monkeypatch.setenv("PT_TEST_RECON_ENV", "-5")
    assert _env_int("PT_TEST_RECON_ENV", 100) == 100


# ─── agents/report/renderer write_report ────────────────────────────────


def test_write_report_html_only(tmp_path):
    """write_report writes html and skips pdf when formats=('html',)."""
    from agents.report.renderer import write_report
    outputs = write_report(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[{"title": "f", "severity": "high"}],
        chains=[],
        summary={"by_severity": {"high": 1}, "total_findings": 1},
        output_dir=str(tmp_path),
        formats=("html",),
    )
    assert "html" in outputs
    assert "pdf" not in outputs


def test_write_report_html_and_pdf_skips_pdf_on_runtime_error(tmp_path, monkeypatch):
    """If render_pdf raises RuntimeError (missing weasyprint), html still emits."""
    from agents.report import renderer
    monkeypatch.setattr(renderer, "render_pdf",
                        MagicMock(side_effect=RuntimeError("WeasyPrint not installed")))
    outputs = renderer.write_report(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[],
        chains=[],
        summary={"by_severity": {}, "total_findings": 0},
        output_dir=str(tmp_path),
        formats=("html", "pdf"),
    )
    assert "html" in outputs
    assert "pdf" not in outputs


def test_write_report_pdf_success(tmp_path, monkeypatch):
    from agents.report import renderer
    monkeypatch.setattr(renderer, "render_pdf", MagicMock(return_value=b"%PDF"))
    outputs = renderer.write_report(
        engagement={"id": "eng-1", "target": "x", "scope": "full", "intensity": "normal"},
        findings=[],
        chains=[],
        summary={"by_severity": {}, "total_findings": 0},
        output_dir=str(tmp_path),
        formats=("html", "pdf"),
    )
    assert "html" in outputs
    assert "pdf" in outputs
