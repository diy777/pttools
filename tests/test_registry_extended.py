"""Tests for extended tool registry (mobile, wireless, social, AD tools)."""

from tools.registry import ToolRegistry


class TestMobileTools:
    def test_mobile_tools_registered(self):
        registry = ToolRegistry()
        mobile = registry.list_tools(category="mobile")
        assert len(mobile) >= 8
        names = {t.name for t in mobile}
        assert "jadx" in names
        assert "apktool" in names
        assert "frida" in names
        assert "objection" in names
        assert "drozer" in names

    def test_apktool_build_args(self):
        registry = ToolRegistry()
        tool = registry.get_tool("apktool")
        cmd = tool._build_command("test.apk")
        assert "d" in cmd
        assert "test.apk" in cmd


class TestWirelessTools:
    def test_wireless_tools_registered(self):
        registry = ToolRegistry()
        wireless = registry.list_tools(category="wireless")
        assert len(wireless) >= 6
        names = {t.name for t in wireless}
        assert "airodump-ng" in names
        assert "kismet" in names
        assert "hashcat" in names

    def test_airodump_build_args(self):
        registry = ToolRegistry()
        tool = registry.get_tool("airodump-ng")
        cmd = tool._build_command("wlan0")
        assert "airodump-ng" in cmd
        assert "wlan0" in cmd


class TestSocialTools:
    def test_social_tools_registered(self):
        registry = ToolRegistry()
        social = registry.list_tools(category="social")
        assert len(social) >= 4
        names = {t.name for t in social}
        assert "gophish" in names
        assert "setoolkit" in names
        assert "evilginx2" in names

    def test_dmarc_build_args(self):
        registry = ToolRegistry()
        tool = registry.get_tool("dmarc-report")
        cmd = tool._build_command("example.com")
        assert "checkdmarc" in cmd


class TestWebToolBuildArgs:
    def test_ffuf_uses_auto_calibration(self):
        """Regression guard: -ac is required to filter SPA wildcard responses.

        Juice Shop and similar SPAs return 200 for every path. Without -ac
        ffuf surfaces the entire wordlist as findings; with -ac it learns the
        wildcard fingerprint from a random non-existent path and filters
        responses that match it.
        """
        registry = ToolRegistry()
        tool = registry.get_tool("ffuf")
        cmd = tool._build_command("http://test.local")
        assert "-ac" in cmd, "ffuf invocation must include -ac for SPA wildcard filtering"
        assert "-mc" in cmd

    def test_katana_uses_url_flag(self):
        """katana needs -u to take a target URL; previously called bare and printed help."""
        registry = ToolRegistry()
        tool = registry.get_tool("katana")
        cmd = tool._build_command("http://test.local")
        assert "-u" in cmd
        assert "http://test.local" in cmd
        assert "-silent" in cmd


class TestADTools:
    def test_ad_tools_registered(self):
        registry = ToolRegistry()
        ad = registry.list_tools(category="ad")
        assert len(ad) >= 8
        names = {t.name for t in ad}
        assert "enum4linux" in names
        assert "netexec" in names
        assert "kerbrute" in names
        assert "bloodhound-python" in names

    def test_secretsdump_build_args(self):
        registry = ToolRegistry()
        tool = registry.get_tool("impacket-secretsdump")
        cmd = tool._build_command("DOMAIN/user@dc.example.com")
        assert "secretsdump.py" in cmd


class TestTotalToolCount:
    def test_total_tools_with_new_categories(self):
        registry = ToolRegistry()
        all_tools = registry.list_tools()
        assert len(all_tools) >= 170

    def test_all_categories_present(self):
        registry = ToolRegistry()
        cats = {t.category for t in registry.list_tools()}
        for expected in ["network", "web", "password", "binary", "cloud", "osint", "mobile", "wireless", "social", "ad"]:
            assert expected in cats, f"Missing category: {expected}"
