"""Coverage fill for engine/tool_installer.py.

Targets uncovered branches: detect_os, print_audit, install_tool (apt/go/pip
paths plus failure cases), install_tier (the no-op short-circuit, apt-update
fan-out, success/failure tally), and interactive_setup.

All subprocess.run calls are mocked; no real tools are invoked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from engine.tool_installer import (
    InstallMethod,
    InstallTier,
    ToolSpec,
    audit_tools,
    detect_os,
    has_go,
    has_pip,
    install_tier,
    install_tool,
    interactive_setup,
    print_audit,
)

# ─── detect_os ──────────────────────────────────────────────────────────


def test_detect_os_debian(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/debian_version")
    assert detect_os() == "debian"


def test_detect_os_redhat(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/redhat-release")
    assert detect_os() == "redhat"


def test_detect_os_macos(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    assert detect_os() == "macos"


def test_detect_os_unknown(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr("platform.system", lambda: "Plan9")
    assert detect_os() == "unknown"


# ─── has_go / has_pip ───────────────────────────────────────────────────


def test_has_go_true(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: "/usr/bin/go")
    assert has_go() is True


def test_has_go_false(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    assert has_go() is False


def test_has_pip_falls_back_to_pip3(monkeypatch):
    def fake_which(cmd):
        return "/usr/bin/pip3" if cmd == "pip3" else None
    monkeypatch.setattr("engine.tool_installer.shutil.which", fake_which)
    assert has_pip() is True


# ─── audit_tools tier filter ────────────────────────────────────────────


def test_audit_tools_with_tier_skips_higher(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    result = audit_tools(tier=InstallTier.CORE)
    # No tool in 'recommended' or 'full' tiers should be in the list
    for tool in result["installed"] + result["missing"]:
        assert tool.tier == InstallTier.CORE


# ─── print_audit ────────────────────────────────────────────────────────


def test_print_audit_renders_table(capsys, monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: False)
    audit = audit_tools(tier=InstallTier.CORE)
    print_audit(audit)
    out = capsys.readouterr().out
    assert "Tool" in out or "nmap" in out
    # Go-not-available branch (line 222)
    assert "Go" in out


def test_print_audit_shows_installed_and_missing(capsys, monkeypatch):
    spec_installed = ToolSpec(
        "fake", "fake", InstallTier.CORE, InstallMethod.APT,
        ("apt-get", "install", "-y", "fake"), "test", 1, "fake tool",
    )
    spec_missing = ToolSpec(
        "missing", "missing", InstallTier.CORE, InstallMethod.APT,
        ("apt-get", "install", "-y", "missing"), "test", 1, "missing tool",
    )
    audit = {
        "installed": [spec_installed],
        "missing": [spec_missing],
        "total_missing_mb": 1,
        "go_available": True,
        "pip_available": True,
    }
    print_audit(audit)
    out = capsys.readouterr().out
    assert "fake" in out


# ─── install_tool happy paths ───────────────────────────────────────────


def _spec(method: InstallMethod, name="fake", cmd="fake") -> ToolSpec:
    if method == InstallMethod.APT:
        argv = ("apt-get", "install", "-y", name)
    elif method == InstallMethod.GO:
        argv = ("go", "install", "github.com/x/y@latest")
    elif method == InstallMethod.PIP:
        argv = ("pip", "install", name)
    else:
        argv = (name,)
    return ToolSpec(name, cmd, InstallTier.CORE, method, argv, "test", 1, "x")


def test_install_tool_already_installed(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: "/usr/bin/" + c)
    ok, msg = install_tool(_spec(InstallMethod.APT))
    assert ok is True
    assert "already" in msg


def test_install_tool_apt_with_sudo_password(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, msg = install_tool(_spec(InstallMethod.APT), sudo_password="secret")
    assert ok is True
    args, kwargs = fake_run.call_args
    assert args[0][0] == "sudo" and args[0][1] == "-S"
    assert kwargs["input"] == "secret\n"


def test_install_tool_apt_no_sudo_password(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, _ = install_tool(_spec(InstallMethod.APT))
    assert ok is True
    args, _ = fake_run.call_args
    assert args[0][0] == "sudo"
    assert "-S" not in args[0]


def test_install_tool_apt_failure(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    fake_run = MagicMock(return_value=MagicMock(returncode=100, stderr="E: package not found"))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, msg = install_tool(_spec(InstallMethod.APT))
    assert ok is False
    assert "Failed" in msg


def test_install_tool_go_no_toolchain(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: False)
    ok, msg = install_tool(_spec(InstallMethod.GO))
    assert ok is False
    assert "Go" in msg


def test_install_tool_go_success_sets_gopath(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: True)
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, _ = install_tool(_spec(InstallMethod.GO))
    assert ok is True
    _, kwargs = fake_run.call_args
    assert "GOPATH" in kwargs["env"]


def test_install_tool_pip_uses_pip3_if_present(monkeypatch):
    monkeypatch.setattr(
        "engine.tool_installer.shutil.which",
        lambda c: "/usr/bin/pip3" if c == "pip3" else None,
    )
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, _ = install_tool(_spec(InstallMethod.PIP))
    assert ok is True
    args, _ = fake_run.call_args
    assert args[0][0] == "pip3"


def test_install_tool_pip_falls_back_to_pip(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)
    ok, _ = install_tool(_spec(InstallMethod.PIP))
    assert ok is True
    args, _ = fake_run.call_args
    assert args[0][0] == "pip"


def test_install_tool_unsupported_method():
    spec = ToolSpec(
        "x", "x", InstallTier.CORE, InstallMethod.MANUAL,
        ("manual",), "test", 1, "x",
    )
    ok, msg = install_tool(spec)
    assert ok is False
    assert "Unsupported" in msg


def test_install_tool_snap_unsupported(monkeypatch):
    """SNAP method falls into the 'else' unsupported branch."""
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    spec = ToolSpec(
        "y", "y", InstallTier.CORE, InstallMethod.SNAP,
        ("snap", "install", "y"), "test", 1, "x",
    )
    ok, msg = install_tool(spec)
    assert ok is False


# ─── install_tier ───────────────────────────────────────────────────────


def test_install_tier_all_already_installed(monkeypatch, capsys):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: "/usr/bin/" + c)
    result = install_tier(InstallTier.CORE)
    assert result == {"installed": 0, "failed": 0, "skipped": 0}


def test_install_tier_runs_apt_update_when_apt_tools_present(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: True)

    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)

    result = install_tier(InstallTier.CORE, skip_tools=("nuclei",))
    # apt-get update should be among the calls
    update_calls = [
        c for c in fake_run.call_args_list
        if "update" in (c.args[0] if c.args else [])
    ]
    assert len(update_calls) >= 1
    assert result["installed"] >= 1


def test_install_tier_with_sudo_password(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: True)
    fake_run = MagicMock(return_value=MagicMock(returncode=0, stderr=""))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)

    install_tier(InstallTier.CORE, sudo_password="hunter2", skip_tools=("nuclei",))
    # The apt-update call should use -S and pipe the password
    update_with_S = [
        c for c in fake_run.call_args_list
        if "-S" in (c.args[0] if c.args else [])
        and "update" in (c.args[0] if c.args else [])
    ]
    assert len(update_with_S) >= 1


def test_install_tier_records_failures(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: True)

    fake_run = MagicMock(return_value=MagicMock(returncode=2, stderr="boom"))
    monkeypatch.setattr("engine.tool_installer.subprocess.run", fake_run)

    result = install_tier(InstallTier.CORE)
    assert result["failed"] >= 1


# ─── interactive_setup ──────────────────────────────────────────────────


def test_interactive_setup_returns_audit(monkeypatch):
    monkeypatch.setattr("engine.tool_installer.shutil.which", lambda c: None)
    monkeypatch.setattr("engine.tool_installer.has_go", lambda: False)
    result = interactive_setup()
    assert "installed" in result
    assert "missing" in result
