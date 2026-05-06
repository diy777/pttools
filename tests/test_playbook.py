"""Tests for engine.playbook + engine.playbook_conditions."""

from __future__ import annotations

import pytest

from engine.playbook import (
    Playbook,
    PlaybookError,
    builtin_dir,
    discover_playbooks,
    find_playbook,
    load_playbook,
    plan_phases,
    resolve_inputs,
)
from engine.playbook_conditions import ConditionContext, ConditionError, eval_condition


class TestSchema:
    def test_load_builtin_web_app_quick(self):
        pb = load_playbook(builtin_dir() / "web-app-quick.yaml")
        assert pb.name == "web-app-quick"
        assert pb.intensity == "normal"
        assert any(p.id == "recon" for p in pb.phases)
        assert "target" in pb.inputs
        assert pb.inputs["target"].required is True

    def test_load_nonexistent_raises(self, tmp_path):
        with pytest.raises(PlaybookError):
            load_playbook(tmp_path / "missing.yaml")

    def test_missing_name_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("phases: [{id: recon}]")
        with pytest.raises(PlaybookError, match="missing required 'name'"):
            load_playbook(p)

    def test_missing_phases_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("name: no-phases\n")
        with pytest.raises(PlaybookError, match="at least one phase"):
            load_playbook(p)

    def test_bad_intensity_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("name: x\nintensity: brutal\nphases: [{id: a}]\n")
        with pytest.raises(PlaybookError, match="intensity must be"):
            load_playbook(p)

    def test_duplicate_phase_id_raises(self, tmp_path):
        p = tmp_path / "dup.yaml"
        p.write_text("name: x\nphases:\n  - id: a\n  - id: a\n")
        with pytest.raises(PlaybookError, match="duplicate phase id"):
            load_playbook(p)

    def test_dangling_depends_on_raises(self, tmp_path):
        p = tmp_path / "dang.yaml"
        p.write_text("name: x\nphases:\n  - id: a\n    depends_on: [missing]\n")
        with pytest.raises(PlaybookError, match="unknown phase"):
            load_playbook(p)

    def test_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "broken.yaml"
        p.write_text("::: not yaml :::")
        with pytest.raises(PlaybookError):
            load_playbook(p)


class TestDiscovery:
    def test_discover_returns_builtin_playbooks(self):
        names = {pb.name for pb in discover_playbooks()}
        assert {"web-app-quick", "external-recon", "llm-app-redteam"}.issubset(names)

    def test_find_by_name(self):
        pb = find_playbook("web-app-quick")
        assert pb.name == "web-app-quick"

    def test_find_by_path(self):
        pb = find_playbook(str(builtin_dir() / "web-app-quick.yaml"))
        assert pb.name == "web-app-quick"

    def test_find_unknown_raises(self):
        with pytest.raises(PlaybookError, match="not found"):
            find_playbook("does-not-exist")

    def test_extra_dirs_scanned(self, tmp_path):
        p = tmp_path / "extra.yaml"
        p.write_text("name: extra-pb\nphases:\n  - id: one\n")
        pbs = discover_playbooks(extra_dirs=[tmp_path])
        assert any(pb.name == "extra-pb" for pb in pbs)


class TestInputs:
    def test_resolve_uses_provided(self):
        pb = Playbook.from_dict({
            "name": "x",
            "inputs": {"target": {"required": True}},
            "phases": [{"id": "a"}],
        })
        out = resolve_inputs(pb, {"target": "https://example.com"})
        assert out["target"] == "https://example.com"

    def test_resolve_required_missing_raises(self):
        pb = Playbook.from_dict({
            "name": "x",
            "inputs": {"target": {"required": True}},
            "phases": [{"id": "a"}],
        })
        with pytest.raises(PlaybookError, match="required input 'target'"):
            resolve_inputs(pb, {})

    def test_resolve_env_fallback(self, monkeypatch):
        pb = Playbook.from_dict({
            "name": "x",
            "inputs": {"target": {"required": True}},
            "phases": [{"id": "a"}],
        })
        monkeypatch.setenv("PTAI_INPUT_TARGET", "env-value")
        out = resolve_inputs(pb, {})
        assert out["target"] == "env-value"

    def test_resolve_default(self):
        pb = Playbook.from_dict({
            "name": "x",
            "inputs": {"schema": {"default": "openai"}},
            "phases": [{"id": "a"}],
        })
        out = resolve_inputs(pb, {})
        assert out["schema"] == "openai"


class TestPlanner:
    def _pb(self, phases):
        return Playbook.from_dict({"name": "x", "phases": phases})

    def test_all_phases_run_by_default(self):
        pb = self._pb([{"id": "a"}, {"id": "b"}])
        plan = plan_phases(pb, findings=[])
        assert all(will for _, will, _ in plan)

    def test_dependency_skip_propagates(self):
        pb = self._pb([
            {"id": "a", "condition": "has_finding(severity='high')"},
            {"id": "b", "depends_on": ["a"]},
        ])
        plan = plan_phases(pb, findings=[])
        assert plan[0][1] is False
        assert plan[1][1] is False
        assert "dependency 'a' was skipped" in plan[1][2]

    def test_condition_met_runs(self):
        pb = self._pb([
            {"id": "a", "condition": "has_finding(severity='high')"},
        ])
        plan = plan_phases(pb, findings=[{"severity": "high"}])
        assert plan[0][1] is True

    def test_bad_condition_skips_with_reason(self):
        pb = self._pb([{"id": "a", "condition": "open('/etc/passwd')"}])
        plan = plan_phases(pb, findings=[])
        assert plan[0][1] is False
        assert "condition" in plan[0][2].lower()


class TestConditions:
    def _ctx(self, findings=None, phases=None):
        return ConditionContext(findings=findings or [], phase_results=phases or {})

    def test_empty_expression_true(self):
        assert eval_condition("", self._ctx()) is True

    def test_has_finding_by_severity(self):
        ctx = self._ctx(findings=[{"severity": "high"}])
        assert eval_condition("has_finding(severity='high')", ctx) is True
        assert eval_condition("has_finding(severity='low')", ctx) is False

    def test_has_finding_by_category(self):
        ctx = self._ctx(findings=[{"category": "web"}])
        assert eval_condition("has_finding(category='web')", ctx) is True

    def test_count_findings_comparison(self):
        ctx = self._ctx(findings=[{"severity": "high"}, {"severity": "high"}])
        assert eval_condition("count_findings(severity='high') > 1", ctx) is True
        assert eval_condition("count_findings(severity='high') >= 3", ctx) is False

    def test_any_finding(self):
        assert eval_condition("any_finding()", self._ctx()) is False
        assert eval_condition("any_finding()", self._ctx(findings=[{}])) is True

    def test_phase_ran_and_skipped(self):
        ctx = self._ctx(phases={"recon": True, "vuln": False})
        assert eval_condition("phase_ran('recon')", ctx) is True
        assert eval_condition("phase_skipped('vuln')", ctx) is True
        assert eval_condition("phase_skipped('missing')", ctx) is False

    def test_boolean_ops(self):
        ctx = self._ctx(findings=[{"severity": "high"}])
        assert eval_condition("has_finding(severity='high') or False", ctx) is True
        assert eval_condition("has_finding(severity='high') and not False", ctx) is True

    def test_attribute_access_rejected(self):
        with pytest.raises(ConditionError):
            eval_condition("x.y", self._ctx())

    def test_unknown_function_rejected(self):
        with pytest.raises(ConditionError, match="not permitted"):
            eval_condition("open('foo')", self._ctx())

    def test_bare_name_rejected(self):
        with pytest.raises(ConditionError, match="not allowed"):
            eval_condition("foobar", self._ctx())

    def test_syntax_error_wrapped(self):
        with pytest.raises(ConditionError, match="syntax error"):
            eval_condition("has_finding(", self._ctx())
