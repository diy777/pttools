"""Tests for engine/tool_installer.py."""

from unittest.mock import patch

from engine.tool_installer import (
    TOOL_CATALOG,
    InstallMethod,
    InstallTier,
    ToolSpec,
    audit_tools,
    detect_os,
    has_go,
    has_pip,
    install_tool,
)


class TestToolCatalog:
    def test_catalog_not_empty(self):
        assert len(TOOL_CATALOG) > 20

    def test_all_tools_have_required_fields(self):
        for tool in TOOL_CATALOG:
            assert tool.name
            assert tool.command
            assert tool.tier in InstallTier
            assert tool.method in InstallMethod
            assert len(tool.install_cmd) >= 2
            assert tool.category

    def test_core_tier_has_essentials(self):
        core_names = {t.name for t in TOOL_CATALOG if t.tier == InstallTier.CORE}
        assert "nmap" in core_names
        assert "nuclei" in core_names
        assert "nikto" in core_names

    def test_tiers_are_incremental(self):
        core = [t for t in TOOL_CATALOG if t.tier == InstallTier.CORE]
        recommended = [t for t in TOOL_CATALOG if t.tier == InstallTier.RECOMMENDED]
        full = [t for t in TOOL_CATALOG if t.tier == InstallTier.FULL]
        assert len(core) >= 5
        assert len(recommended) >= 5
        assert len(full) >= 5

    def test_no_duplicate_names(self):
        names = [t.name for t in TOOL_CATALOG]
        assert len(names) == len(set(names))

    def test_no_duplicate_commands(self):
        commands = [t.command for t in TOOL_CATALOG]
        assert len(commands) == len(set(commands))


class TestDetection:
    def test_detect_os_returns_string(self):
        result = detect_os()
        assert result in ("debian", "redhat", "macos", "unknown")

    @patch("shutil.which", return_value="/usr/local/go/bin/go")
    def test_has_go_true(self, _mock):
        assert has_go() is True

    @patch("shutil.which", return_value=None)
    def test_has_go_false(self, _mock):
        assert has_go() is False

    @patch("shutil.which", return_value="/usr/bin/pip3")
    def test_has_pip_true(self, _mock):
        assert has_pip() is True


class TestAudit:
    @patch("shutil.which", return_value=None)
    def test_audit_all_missing(self, _mock):
        result = audit_tools()
        assert len(result["missing"]) == len(TOOL_CATALOG)
        assert len(result["installed"]) == 0
        assert result["total_missing_mb"] > 0

    @patch("shutil.which", return_value="/usr/bin/tool")
    def test_audit_all_installed(self, _mock):
        result = audit_tools()
        assert len(result["installed"]) == len(TOOL_CATALOG)
        assert len(result["missing"]) == 0
        assert result["total_missing_mb"] == 0


class TestInstallTool:
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_already_installed(self, _mock):
        tool = ToolSpec("nmap", "nmap", InstallTier.CORE, InstallMethod.APT,
                        ("apt-get", "install", "-y", "nmap"), "network", 25)
        ok, msg = install_tool(tool)
        assert ok is True
        assert "already installed" in msg

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_apt_install(self, mock_run, _mock_which):
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        tool = ToolSpec("testpkg", "testpkg", InstallTier.CORE, InstallMethod.APT,
                        ("apt-get", "install", "-y", "testpkg"), "test", 5)
        ok, msg = install_tool(tool)
        assert ok is True

    @patch("shutil.which", side_effect=lambda x: "/usr/local/go/bin/go" if x == "go" else None)
    @patch("subprocess.run")
    def test_go_install(self, mock_run, _mock_which):
        mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        tool = ToolSpec("testtool", "testtool", InstallTier.CORE, InstallMethod.GO,
                        ("go", "install", "github.com/test/tool@latest"), "test", 10)
        ok, msg = install_tool(tool)
        assert ok is True

    @patch("shutil.which", side_effect=lambda x: None if x == "go" else None)
    def test_go_install_no_go(self, _mock_which):
        tool = ToolSpec("testtool", "testtool", InstallTier.CORE, InstallMethod.GO,
                        ("go", "install", "github.com/test/tool@latest"), "test", 10)
        ok, msg = install_tool(tool)
        assert ok is False
        assert "Go" in msg
