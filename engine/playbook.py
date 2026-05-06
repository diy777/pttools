"""YAML playbook engine for pentest-tools.

A playbook encodes a methodology: an ordered list of phases, each with tools
to invoke, optional gating conditions against the live findings DB, and
optional dependencies on earlier phases. Playbooks are how pentesters share
repeatable testing approaches the same way Nuclei templates share detection
rules.

This module handles: parsing, validating, listing, and previewing
playbooks. Execution happens via ``PlaybookRunner`` which walks phases
and delegates tool invocation. The MVP executes standalone phases
inline (e.g. ``llm_redteam``); registry-backed tools get enumerated in
the preview but require the MCP orchestrator to actually run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .playbook_conditions import ConditionContext, eval_condition

_BUILTIN_DIR = Path(__file__).resolve().parent.parent / "playbooks" / "builtin"
_USER_DIR = Path.home() / ".pentest-tools" / "playbooks"


class PlaybookError(Exception):
    """Raised on any invalid playbook state."""


@dataclass
class PlaybookInput:
    name: str
    required: bool = False
    default: str = ""
    prompt: str = ""

    @classmethod
    def from_raw(cls, name: str, raw: Any) -> PlaybookInput:
        if isinstance(raw, dict):
            return cls(
                name=name,
                required=bool(raw.get("required", False)),
                default=str(raw.get("default", "")),
                prompt=str(raw.get("prompt", "")),
            )
        return cls(name=name, default=str(raw))


@dataclass
class Phase:
    id: str
    tools: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    condition: str = ""
    args: dict[str, str] = field(default_factory=dict)
    manual: bool = False
    checklist: list[str] = field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> Phase:
        if "id" not in raw:
            raise PlaybookError("phase missing required field 'id'")
        return cls(
            id=str(raw["id"]),
            tools=list(raw.get("tools", [])),
            depends_on=list(raw.get("depends_on", [])),
            condition=str(raw.get("condition", "")),
            args={k: str(v) for k, v in (raw.get("args") or {}).items()},
            manual=bool(raw.get("manual", False)),
            checklist=list(raw.get("checklist", [])),
        )


@dataclass
class Playbook:
    name: str
    description: str = ""
    version: str = "0.1.0"
    authors: list[str] = field(default_factory=list)
    intensity: str = "normal"
    inputs: dict[str, PlaybookInput] = field(default_factory=dict)
    phases: list[Phase] = field(default_factory=list)
    path: str = ""
    auth_profile: str = ""  # name of an auth profile to use for the whole playbook run

    @classmethod
    def from_dict(cls, raw: dict[str, Any], path: str = "") -> Playbook:
        if "name" not in raw:
            raise PlaybookError(f"{path or 'playbook'}: missing required 'name'")
        if "phases" not in raw or not raw["phases"]:
            raise PlaybookError(f"{raw.get('name', path)}: must declare at least one phase")

        inputs_raw = raw.get("inputs") or {}
        if not isinstance(inputs_raw, dict):
            raise PlaybookError(f"{raw['name']}: 'inputs' must be a mapping")

        # Refuse to load any playbook that has bare credential keys.
        for forbidden in ("password", "token", "secret"):
            if forbidden in raw:
                raise PlaybookError(
                    f"{raw['name']}: refusing to load playbook with bare {forbidden!r} key. "
                    f"Use auth_profile: <name> instead, and store credentials via "
                    f"`pentest-tools auth profile add`."
                )

        return cls(
            name=str(raw["name"]),
            description=str(raw.get("description", "")),
            version=str(raw.get("version", "0.1.0")),
            authors=[str(a) for a in raw.get("authors", [])],
            intensity=str(raw.get("intensity", "normal")),
            inputs={n: PlaybookInput.from_raw(n, v) for n, v in inputs_raw.items()},
            phases=[Phase.from_raw(p) for p in raw["phases"]],
            path=path,
            auth_profile=str(raw.get("auth_profile", "")),
        )

    def validate(self) -> None:
        """Raise ``PlaybookError`` on semantic issues (dupes, dangling deps, ...)."""
        seen: set[str] = set()
        for phase in self.phases:
            if phase.id in seen:
                raise PlaybookError(f"{self.name}: duplicate phase id '{phase.id}'")
            seen.add(phase.id)
        for phase in self.phases:
            for dep in phase.depends_on:
                if dep not in seen:
                    raise PlaybookError(
                        f"{self.name}: phase '{phase.id}' depends on unknown phase '{dep}'"
                    )
        if self.intensity not in {"stealth", "normal", "aggressive"}:
            raise PlaybookError(
                f"{self.name}: intensity must be stealth|normal|aggressive (got '{self.intensity}')"
            )


def load_playbook(path: str | Path) -> Playbook:
    """Load and validate a single playbook from a YAML file."""
    p = Path(path)
    if not p.exists():
        raise PlaybookError(f"playbook not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise PlaybookError(f"{p}: invalid YAML: {e}") from e
    pb = Playbook.from_dict(data, path=str(p))
    pb.validate()
    return pb


def discover_playbooks(extra_dirs: list[Path] | None = None) -> list[Playbook]:
    """Return all playbooks found under builtin + user + extra directories."""
    dirs: list[Path] = [_BUILTIN_DIR, _USER_DIR]
    if extra_dirs:
        dirs.extend(extra_dirs)
    seen: set[str] = set()
    out: list[Playbook] = []
    for d in dirs:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                pb = load_playbook(f)
            except PlaybookError:
                continue
            if pb.name in seen:
                continue
            seen.add(pb.name)
            out.append(pb)
    return out


def find_playbook(name_or_path: str) -> Playbook:
    """Resolve by bare name (searches builtin + user dirs) or by path."""
    p = Path(name_or_path)
    if p.exists() and p.is_file():
        return load_playbook(p)
    for pb in discover_playbooks():
        if pb.name == name_or_path:
            return pb
    raise PlaybookError(
        f"playbook '{name_or_path}' not found (searched {_BUILTIN_DIR} and {_USER_DIR})"
    )


def plan_phases(
    playbook: Playbook, findings: list[dict[str, Any]] | None = None
) -> list[tuple[Phase, bool, str]]:
    """Return [(phase, will_run, reason), ...] — honours conditions + depends_on."""
    findings = findings or []
    ctx = ConditionContext(findings=findings, phase_results={})
    skipped: set[str] = set()
    out: list[tuple[Phase, bool, str]] = []

    for phase in playbook.phases:
        reason = ""
        will_run = True

        missing_dep = next((d for d in phase.depends_on if d in skipped), None)
        if missing_dep:
            will_run = False
            reason = f"dependency '{missing_dep}' was skipped"

        if will_run and phase.condition:
            try:
                if not eval_condition(phase.condition, ctx):
                    will_run = False
                    reason = f"condition did not match: {phase.condition}"
            except Exception as e:
                will_run = False
                reason = f"condition error: {e}"

        if not will_run:
            skipped.add(phase.id)
        out.append((phase, will_run, reason))
    return out


def builtin_dir() -> Path:
    """Exposed so tests and CLI can locate bundled playbooks."""
    return _BUILTIN_DIR


def user_dir() -> Path:
    return _USER_DIR


def resolve_inputs(playbook: Playbook, provided: dict[str, str]) -> dict[str, str]:
    """Fill defaults + env expansions; raise if a required input is missing."""
    out: dict[str, str] = {}
    for name, spec in playbook.inputs.items():
        value = provided.get(name, spec.default)
        if not value:
            value = os.environ.get(f"PTAI_INPUT_{name.upper()}", "")
        if not value and spec.required:
            raise PlaybookError(f"{playbook.name}: required input '{name}' not provided")
        out[name] = value
    for k, v in provided.items():
        if k not in out:
            out[k] = v
    return out
