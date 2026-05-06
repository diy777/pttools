"""Phase 5 tests: playbooks recognize auth_profile and reject bare credential keys."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.playbook import PlaybookError, load_playbook


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_playbook_with_auth_profile_loads(tmp_path):
    yaml_content = """
name: test-pb
phases:
  - id: recon
    tools: [nmap]
auth_profile: staging-acme
"""
    pb_path = tmp_path / "test.yaml"
    _write_yaml(pb_path, yaml_content)
    pb = load_playbook(pb_path)
    pb.validate()
    assert pb.auth_profile == "staging-acme"


def test_playbook_without_auth_profile_loads(tmp_path):
    yaml_content = """
name: test-pb
phases:
  - id: recon
    tools: [nmap]
"""
    pb_path = tmp_path / "test.yaml"
    _write_yaml(pb_path, yaml_content)
    pb = load_playbook(pb_path)
    pb.validate()
    assert pb.auth_profile == ""


def test_playbook_with_bare_password_rejected(tmp_path):
    yaml_content = """
name: bad-pb
password: actualPlaintextPassword
phases:
  - id: recon
    tools: [nmap]
"""
    pb_path = tmp_path / "bad.yaml"
    _write_yaml(pb_path, yaml_content)
    with pytest.raises(PlaybookError) as exc:
        load_playbook(pb_path)
    assert "auth_profile" in str(exc.value).lower()


def test_playbook_with_bare_token_rejected(tmp_path):
    yaml_content = """
name: bad-pb
token: realToken123
phases:
  - id: recon
    tools: [nmap]
"""
    pb_path = tmp_path / "bad.yaml"
    _write_yaml(pb_path, yaml_content)
    with pytest.raises(PlaybookError):
        load_playbook(pb_path)


def test_playbook_with_bare_secret_rejected(tmp_path):
    yaml_content = """
name: bad-pb
secret: oops-leaked
phases:
  - id: recon
    tools: [nmap]
"""
    pb_path = tmp_path / "bad.yaml"
    _write_yaml(pb_path, yaml_content)
    with pytest.raises(PlaybookError):
        load_playbook(pb_path)


def test_existing_builtin_playbooks_still_load():
    """Regression: built-in playbooks must not have regressed."""
    from engine.playbook import discover_playbooks

    pbs = discover_playbooks()
    assert len(pbs) >= 1
    for pb in pbs:
        pb.validate()
