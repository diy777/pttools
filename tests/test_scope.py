"""Tests for scope enforcement (engine/scope.py)."""


from engine.scope import ScopeEnforcer


class TestScopeEnforcerDomains:
    def test_allowed_domain(self):
        enforcer = ScopeEnforcer(allowed_targets=["example.com"])
        allowed, reason = enforcer.check("example.com")
        assert allowed

    def test_blocked_domain(self):
        enforcer = ScopeEnforcer(allowed_targets=["example.com"])
        allowed, reason = enforcer.check("evil.com")
        assert not allowed
        assert "not in scope" in reason.lower() or "outside" in reason.lower() or reason

    def test_wildcard_domain(self):
        enforcer = ScopeEnforcer(allowed_targets=["*.example.com"])
        allowed, _ = enforcer.check("sub.example.com")
        assert allowed

    def test_wildcard_also_matches_parent(self):
        enforcer = ScopeEnforcer(allowed_targets=["*.example.com"])
        allowed, _ = enforcer.check("example.com")
        assert allowed

    def test_excluded_domain(self):
        enforcer = ScopeEnforcer(
            allowed_targets=["*.example.com"],
            excluded_targets=["admin.example.com"],
        )
        allowed, _ = enforcer.check("admin.example.com")
        assert not allowed

    def test_excluded_takes_precedence(self):
        enforcer = ScopeEnforcer(
            allowed_targets=["example.com"],
            excluded_targets=["example.com"],
        )
        allowed, _ = enforcer.check("example.com")
        assert not allowed


class TestScopeEnforcerCIDR:
    def test_allowed_ip(self):
        enforcer = ScopeEnforcer(allowed_targets=["192.168.1.0/24"])
        allowed, _ = enforcer.check("192.168.1.50")
        assert allowed

    def test_blocked_ip(self):
        enforcer = ScopeEnforcer(allowed_targets=["192.168.1.0/24"])
        allowed, _ = enforcer.check("10.0.0.1")
        assert not allowed

    def test_single_ip(self):
        enforcer = ScopeEnforcer(allowed_targets=["192.168.1.1"])
        allowed, _ = enforcer.check("192.168.1.1")
        assert allowed

    def test_single_ip_blocks_other(self):
        enforcer = ScopeEnforcer(allowed_targets=["192.168.1.1"])
        allowed, _ = enforcer.check("192.168.1.2")
        assert not allowed


class TestScopeEnforcerPorts:
    def test_allowed_port(self):
        enforcer = ScopeEnforcer(
            allowed_targets=["example.com"],
            allowed_ports=[80, 443, 8080],
        )
        allowed, _ = enforcer.check_port(80)
        assert allowed

    def test_blocked_port(self):
        enforcer = ScopeEnforcer(
            allowed_targets=["example.com"],
            allowed_ports=[80, 443],
        )
        allowed, _ = enforcer.check_port(22)
        assert not allowed

    def test_no_port_restriction(self):
        enforcer = ScopeEnforcer(allowed_targets=["example.com"])
        allowed, _ = enforcer.check_port(9999)
        assert allowed


class TestScopeEnforcerModes:
    def test_strict_no_scope_blocks(self):
        enforcer = ScopeEnforcer(allowed_targets=[], mode="strict")
        allowed, _ = enforcer.check("anything.com")
        assert not allowed

    def test_permissive_no_scope_allows(self):
        enforcer = ScopeEnforcer(allowed_targets=[], mode="permissive")
        allowed, _ = enforcer.check("anything.com")
        assert allowed

    def test_violation_recording(self):
        enforcer = ScopeEnforcer(allowed_targets=["example.com"])
        enforcer.check("evil.com", tool_name="nmap")
        assert len(enforcer.violations) == 1
        assert enforcer.violations[0].target == "evil.com"
        assert enforcer.violations[0].tool == "nmap"
