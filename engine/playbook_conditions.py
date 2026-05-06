"""Sandboxed condition evaluator for playbook phase gating.

Supports a tiny expression language:
  - ``has_finding(severity='high')`` — returns True if any finding matches
  - ``has_finding(category='web')``
  - ``count_findings(severity='high') > 2``
  - ``any_finding()`` — True when at least one finding exists
  - ``phase_ran('recon')`` / ``phase_skipped('recon')``
  - boolean ops ``and`` / ``or`` / ``not``, parentheses, comparisons

Parsing goes through ``ast`` with a whitelist — no ``eval`` against user
input, no attribute access, no function calls outside the registered
helpers. Errors bubble up as ``ConditionError``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


class ConditionError(Exception):
    pass


@dataclass
class ConditionContext:
    findings: list[dict[str, Any]] = field(default_factory=list)
    phase_results: dict[str, bool] = field(default_factory=dict)

    def _match(self, f: dict[str, Any], severity: str, category: str) -> bool:
        if severity and (f.get("severity") or "").lower() != severity.lower():
            return False
        return not (category and (f.get("category") or "").lower() != category.lower())

    def has_finding(self, severity: str = "", category: str = "") -> bool:
        return any(self._match(f, severity, category) for f in self.findings)

    def count_findings(self, severity: str = "", category: str = "") -> int:
        return sum(1 for f in self.findings if self._match(f, severity, category))

    def any_finding(self) -> bool:
        return bool(self.findings)

    def phase_ran(self, phase_id: str) -> bool:
        return self.phase_results.get(phase_id, False)

    def phase_skipped(self, phase_id: str) -> bool:
        return phase_id in self.phase_results and not self.phase_results[phase_id]


_ALLOWED_CALLS = {"has_finding", "count_findings", "any_finding", "phase_ran", "phase_skipped"}


def _evaluate(node: ast.AST, ctx: ConditionContext) -> Any:
    if isinstance(node, ast.Expression):
        return _evaluate(node.body, ctx)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BoolOp):
        values = [_evaluate(v, ctx) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise ConditionError(f"unsupported boolean op: {ast.dump(node.op)}")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _evaluate(node.operand, ctx)
    if isinstance(node, ast.Compare):
        left = _evaluate(node.left, ctx)
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = _evaluate(comparator, ctx)
            if isinstance(op, ast.Gt) and not (left > right):
                return False
            if isinstance(op, ast.GtE) and not (left >= right):
                return False
            if isinstance(op, ast.Lt) and not (left < right):
                return False
            if isinstance(op, ast.LtE) and not (left <= right):
                return False
            if isinstance(op, ast.Eq) and left != right:
                return False
            if isinstance(op, ast.NotEq) and left == right:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ConditionError("only bare function calls are allowed")
        name = node.func.id
        if name not in _ALLOWED_CALLS:
            raise ConditionError(f"function '{name}' is not permitted")
        args = [_evaluate(a, ctx) for a in node.args]
        kwargs = {kw.arg: _evaluate(kw.value, ctx) for kw in node.keywords if kw.arg}
        return getattr(ctx, name)(*args, **kwargs)
    if isinstance(node, ast.Name):
        if node.id in {"True", "False"}:
            return node.id == "True"
        raise ConditionError(f"bare name '{node.id}' is not allowed")
    raise ConditionError(f"unsupported expression: {ast.dump(node)}")


def eval_condition(expr: str, ctx: ConditionContext) -> bool:
    if not expr.strip():
        return True
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ConditionError(f"syntax error in condition: {e}") from e
    return bool(_evaluate(tree, ctx))
