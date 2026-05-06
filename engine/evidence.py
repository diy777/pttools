"""Evidence collection engine. Auto-captures timestamped artifacts for every finding.

Stores tool output, HTTP interactions, and screenshots with SHA-256 integrity hashes.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("pentest-tools.evidence")


@dataclass(frozen=True)
class EvidenceArtifact:
    id: str
    finding_id: str
    artifact_type: str  # tool_output, http_request, http_response, screenshot, pcap, config
    filename: str
    sha256: str
    size_bytes: int
    created_at: str


class EvidenceCollector:
    def __init__(self, base_dir: str = "evidence"):
        self.base_dir = Path(base_dir)
        self._artifacts: list[EvidenceArtifact] = []

    def _engagement_dir(self, engagement_id: str) -> Path:
        safe_id = Path(engagement_id).name
        path = self.base_dir / safe_id
        resolved = path.resolve()
        if not str(resolved).startswith(str(self.base_dir.resolve())):
            raise ValueError(f"Invalid engagement_id: {engagement_id}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    async def store_tool_output(
        self,
        engagement_id: str,
        finding_id: str,
        tool_name: str,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        duration_ms: int,
    ) -> EvidenceArtifact:
        timestamp = datetime.now(timezone.utc).isoformat()
        content = (
            f"Tool: {tool_name}\n"
            f"Command: {command}\n"
            f"Exit Code: {exit_code}\n"
            f"Duration: {duration_ms}ms\n"
            f"Timestamp: {timestamp}\n"
            f"{'=' * 60}\n"
            f"STDOUT:\n{stdout}\n"
            f"{'=' * 60}\n"
            f"STDERR:\n{stderr}\n"
        )
        filename = f"{tool_name}_{finding_id}_{_safe_timestamp()}.txt"
        return await self._write_artifact(engagement_id, finding_id, "tool_output", filename, content)

    async def store_http_exchange(
        self,
        engagement_id: str,
        finding_id: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: str,
        status_code: int,
        response_headers: dict[str, str],
        response_body: str,
    ) -> EvidenceArtifact:
        req_lines = [f"{method} {url}"]
        req_lines.extend(f"{k}: {v}" for k, v in request_headers.items())
        req_lines.append("")
        req_lines.append(request_body)

        resp_lines = [f"HTTP {status_code}"]
        resp_lines.extend(f"{k}: {v}" for k, v in response_headers.items())
        resp_lines.append("")
        resp_lines.append(response_body[:50000])

        content = "REQUEST:\n" + "\n".join(req_lines) + "\n\nRESPONSE:\n" + "\n".join(resp_lines)
        filename = f"http_{finding_id}_{_safe_timestamp()}.txt"
        return await self._write_artifact(engagement_id, finding_id, "http_request", filename, content)

    async def store_raw(
        self,
        engagement_id: str,
        finding_id: str,
        artifact_type: str,
        filename: str,
        content: str | bytes,
    ) -> EvidenceArtifact:
        return await self._write_artifact(engagement_id, finding_id, artifact_type, filename, content)

    async def _write_artifact(
        self,
        engagement_id: str,
        finding_id: str,
        artifact_type: str,
        filename: str,
        content: str | bytes,
    ) -> EvidenceArtifact:
        dir_path = self._engagement_dir(engagement_id)
        safe_filename = Path(filename).name
        file_path = dir_path / safe_filename

        data = content.encode("utf-8") if isinstance(content, str) else content

        file_path.write_bytes(data)
        sha256 = hashlib.sha256(data).hexdigest()
        artifact_id = sha256[:12]

        artifact = EvidenceArtifact(
            id=artifact_id,
            finding_id=finding_id,
            artifact_type=artifact_type,
            filename=filename,
            sha256=sha256,
            size_bytes=len(data),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._artifacts.append(artifact)
        logger.info(f"Evidence stored: {filename} ({len(data)} bytes, sha256={sha256[:12]}...)")
        return artifact

    def get_artifacts(self, finding_id: str = "", engagement_id: str = "") -> list[EvidenceArtifact]:
        results = self._artifacts
        if finding_id:
            results = [a for a in results if a.finding_id == finding_id]
        return results

    def verify_integrity(self, engagement_id: str) -> list[dict[str, Any]]:
        issues = []
        dir_path = self.base_dir / engagement_id
        if not dir_path.exists():
            return [{"error": f"Evidence directory not found: {dir_path}"}]

        for artifact in self._artifacts:
            file_path = dir_path / artifact.filename
            if not file_path.exists():
                issues.append({"artifact": artifact.filename, "error": "File missing"})
                continue
            actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            if actual_hash != artifact.sha256:
                issues.append({"artifact": artifact.filename, "error": "SHA-256 mismatch", "expected": artifact.sha256, "actual": actual_hash})
        return issues


def _safe_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
