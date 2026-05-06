"""Prompt corpus loader for the LLM red-team phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_CORPUS = Path(__file__).parent / "corpus.yaml"


@dataclass
class Detector:
    type: str
    patterns: list[str] = field(default_factory=list)
    case_sensitive: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Detector:
        return cls(
            type=raw.get("type", "string_match"),
            patterns=list(raw.get("patterns", [])),
            case_sensitive=bool(raw.get("case_sensitive", False)),
        )


@dataclass
class Probe:
    id: str
    category: str
    severity: str
    prompt: str
    detect: Detector
    rationale: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Probe:
        return cls(
            id=raw["id"],
            category=raw["category"],
            severity=raw.get("severity", "medium"),
            prompt=raw["prompt"],
            detect=Detector.from_dict(raw.get("detect", {})),
            rationale=raw.get("rationale", ""),
        )


def load_corpus(path: str | Path | None = None) -> list[Probe]:
    """Load probes from a YAML corpus file. Defaults to the built-in corpus."""
    p = Path(path) if path else _DEFAULT_CORPUS
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return [Probe.from_dict(item) for item in data.get("probes", [])]
