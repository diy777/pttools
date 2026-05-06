"""Response detectors for LLM red-team probes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .corpus import Detector


@dataclass
class DetectionResult:
    fired: bool
    matched: str = ""


def evaluate(detector: Detector, response: str) -> DetectionResult:
    """Return (fired, matched_pattern) for the detector against a response."""
    if not response or not detector.patterns:
        return DetectionResult(fired=False)

    haystack = response if detector.case_sensitive else response.lower()

    if detector.type == "string_match":
        for pat in detector.patterns:
            needle = pat if detector.case_sensitive else pat.lower()
            if needle in haystack:
                return DetectionResult(fired=True, matched=pat)
        return DetectionResult(fired=False)

    if detector.type == "regex":
        flags = 0 if detector.case_sensitive else re.IGNORECASE
        for pat in detector.patterns:
            try:
                match = re.search(pat, response, flags=flags)
            except re.error:
                continue
            if match:
                return DetectionResult(fired=True, matched=match.group(0))
        return DetectionResult(fired=False)

    return DetectionResult(fired=False)
