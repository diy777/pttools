"""
Findings Database — Persistent SQLite storage for all pentest findings.

Stores engagements, findings, attack chains, PoCs, and detection rules.
Survives across sessions and supports complex queries for chain discovery.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import aiosqlite

logger = logging.getLogger("pentest-tools.findings_db")


EVIDENCE_REQUIRED_SEVERITIES = {"critical", "high", "medium"}

DETERMINISTIC_TOOL_SOURCES = frozenset({
    "pentest-tools-dns-check",
    "pentest-tools-port-scan",
    "pentest-tools-web-check",
    "pentest-tools-tls-check",
    "authenticated_scan",
    "sqlmap",
    "nmap",
    "nuclei",
    "nikto",
})


class EvidenceMissingError(ValueError):
    """Raised when a high-severity finding lacks any evidence in strict mode."""


def _evidence_present(finding: dict[str, Any]) -> bool:
    return bool(
        (finding.get("evidence") or "").strip()
        or (finding.get("poc") or "").strip()
        or (finding.get("raw_output") or "").strip()
        or finding.get("tool_result_id")
    )


def _validate_finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Enforce the evidence-required contract.

    Rules:
      - severity in {critical, high, medium} must carry evidence, poc, raw_output,
        or a tool_result_id foreign key. Otherwise strict mode raises; lax mode
        coerces status to 'unverified' and logs a warning.
      - A finding whose tool_source claims a deterministic scanner (dns_check,
        nmap, authenticated_scan, ...) but has no raw_output and no
        tool_result_id is treated as orphan / hallucinated and gated the same
        way. This is the primary gate for LLM agents fabricating findings with
        spoofed tool_source.

    Strict mode: PTAI_STRICT_EVIDENCE=1 in env → raises EvidenceMissingError.
    """
    strict = os.getenv("PTAI_STRICT_EVIDENCE", "0") == "1"
    severity = (finding.get("severity") or "info").lower()
    tool_source = (finding.get("tool_source") or "").strip()
    title = finding.get("title", "?")

    needs_evidence = (
        severity in EVIDENCE_REQUIRED_SEVERITIES
        or tool_source in DETERMINISTIC_TOOL_SOURCES
    )
    if needs_evidence and not _evidence_present(finding):
        msg = (
            f"finding '{title}' (severity={severity}, tool_source='{tool_source}') "
            "has no evidence, poc, raw_output, or tool_result_id"
        )
        if strict:
            raise EvidenceMissingError(msg)
        logger.warning("%s — coercing status to 'unverified'", msg)
        finding = {**finding, "status": "unverified"}
    return finding


def _default_db_path() -> str:
    """Return a stable absolute DB path so engagements don't scatter across CWDs.

    Resolution order:
      1. PTAI_DB_PATH env var (lets ops pin the location explicitly)
      2. XDG_DATA_HOME/pentest-tools/findings.db
      3. ~/.local/share/pentest-tools/findings.db
    """
    # Both names accepted for backwards compatibility (PENTEST_DB_PATH was used
    # in CLI handlers; PTAI_DB_PATH is the new short-name alias).
    env_path = os.environ.get("PTAI_DB_PATH", "").strip() or os.environ.get("PENTEST_DB_PATH", "").strip()
    if env_path:
        return env_path
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".local", "share")
    db_dir = os.path.join(base, "pentest-tools")
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, "findings.db")


class FindingsDB:
    def __init__(self, db_path: str | None = None):
        # None → default absolute path. Caller can still pass an explicit path
        # for tests or alternate engagements (legacy callers passing the old
        # default "pentest_findings.db" continue to work because that's still
        # a valid relative path).
        self.db_path = db_path if db_path is not None else _default_db_path()
        self._db: aiosqlite.Connection | None = None

    async def _get_db(self) -> aiosqlite.Connection:
        if self._db is None:
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
            await self._db.executescript("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'full',
                    rules_of_engment TEXT DEFAULT '',
                    intensity TEXT DEFAULT 'normal',
                    status TEXT DEFAULT 'running',
                    current_phase TEXT,
                    completed_phases TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tool_source TEXT,
                    target TEXT NOT NULL,
                    evidence TEXT,
                    poc TEXT,
                    poc_status TEXT DEFAULT 'pending',
                    status TEXT DEFAULT 'confirmed',
                    cve TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe_id TEXT,
                    owasp_category TEXT,
                    compliance_mapping TEXT,
                    fingerprint TEXT,
                    remediation TEXT,
                    detection_rules TEXT,
                    raw_output TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS attack_chains (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    finding_ids TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    status TEXT DEFAULT 'discovered',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    format TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (finding_id) REFERENCES findings(id),
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS stage_events (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress REAL NOT NULL,
                    details TEXT,
                    description TEXT,
                    automated INTEGER DEFAULT 1,
                    depends_on TEXT DEFAULT '[]',
                    started_at TEXT,
                    completed_at TEXT,
                    duration_ms REAL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS tool_results (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    args TEXT,
                    output TEXT,
                    exit_code INTEGER,
                    duration REAL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    flow TEXT NOT NULL,
                    login_url TEXT,
                    username TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT DEFAULT 'created',
                    target_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_chains_engagement ON attack_chains(engagement_id);
            """)
            await self._add_column_if_missing("engagements", "campaign_id", "TEXT")
            await self._add_column_if_missing("engagements", "parent_engagement_id", "TEXT")
            await self._add_column_if_missing("findings", "tool_result_id", "TEXT")
            await self._db.commit()
        return self._db

    async def _add_column_if_missing(self, table: str, column: str, col_type: str) -> None:
        db = self._db
        if not db:
            return
        async with db.execute(f"PRAGMA table_info({table})") as cursor:
            cols = {row[1] for row in await cursor.fetchall()}
        if column not in cols:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            await db.commit()

    async def init(self):
        await self._get_db()

    async def record_auth_session(
        self,
        *,
        engagement_id: str,
        flow: str,
        login_url: str = "",
        username: str = "",
        expires_at: float | None = None,
    ) -> str:
        """Audit trail for an authenticated session bound to an engagement."""
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        session_id = str(uuid.uuid4())[:12]
        expires_iso = (
            datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
            if expires_at
            else None
        )
        await db.execute(
            """INSERT INTO auth_sessions
               (id, engagement_id, flow, login_url, username, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, engagement_id, flow, login_url, username, now, expires_iso),
        )
        await db.commit()
        return session_id

    async def get_auth_sessions(self, engagement_id: str) -> list[dict[str, Any]]:
        db = await self._get_db()
        async with db.execute(
            "SELECT * FROM auth_sessions WHERE engagement_id = ? ORDER BY created_at DESC",
            (engagement_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None

    async def create_engagement(
        self,
        target: str,
        scope: str = "full",
        rules_of_engment: str = "",
        intensity: str = "normal",
        campaign_id: str | None = None,
        parent_engagement_id: str | None = None,
    ) -> dict[str, Any]:
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        engagement_id = str(uuid.uuid4())[:8]
        await db.execute(
            """INSERT INTO engagements
               (id, target, scope, rules_of_engment, intensity, status,
                campaign_id, parent_engagement_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id, target, scope, rules_of_engment, intensity, "running",
                campaign_id, parent_engagement_id, now, now,
            ),
        )
        await db.commit()
        return {
            "id": engagement_id,
            "target": target,
            "scope": scope,
            "rules_of_engment": rules_of_engment,
            "intensity": intensity,
            "status": "running",
            "parent_engagement_id": parent_engagement_id,
            "created_at": now,
        }

    async def get_engagement(self, engagement_id: str) -> dict[str, Any] | None:
        db = await self._get_db()
        async with db.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def add_finding(self, finding: dict[str, Any]) -> str:
        db = await self._get_db()
        finding = _validate_finding_evidence(finding)
        finding_id = finding.get("id", str(uuid.uuid4())[:12])
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT OR REPLACE INTO findings
               (id, engagement_id, title, description, severity, category, tool_source,
                target, evidence, poc, poc_status, status, cve, cvss_score, cvss_vector,
                cwe_id, owasp_category, compliance_mapping, fingerprint,
                remediation, detection_rules, raw_output, tool_result_id,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                finding.get("engagement_id", ""),
                finding.get("title", "Unknown Finding"),
                finding.get("description", ""),
                finding.get("severity", "info"),
                finding.get("category", "general"),
                finding.get("tool_source", ""),
                finding.get("target", ""),
                finding.get("evidence", ""),
                finding.get("poc", ""),
                finding.get("poc_status", "pending"),
                finding.get("status", "confirmed"),
                finding.get("cve", ""),
                finding.get("cvss_score", 0.0),
                finding.get("cvss_vector", ""),
                finding.get("cwe_id", ""),
                finding.get("owasp_category", ""),
                json.dumps(finding.get("compliance_mapping", {})),
                finding.get("fingerprint", ""),
                finding.get("remediation", ""),
                json.dumps(finding.get("detection_rules", [])),
                finding.get("raw_output", ""),
                finding.get("tool_result_id"),
                now,
                now,
            ),
        )
        await db.commit()
        return finding_id

    async def get_findings(
        self,
        engagement_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        db = await self._get_db()
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        async with db.execute(query, params) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def add_attack_chain(self, chain: dict[str, Any]) -> str:
        db = await self._get_db()
        chain_id = chain.get("id", str(uuid.uuid4())[:12])
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT OR REPLACE INTO attack_chains
               (id, engagement_id, name, description, severity, steps, finding_ids, impact, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                chain_id,
                chain["engagement_id"],
                chain["name"],
                chain["description"],
                chain["severity"],
                json.dumps(chain["steps"]),
                json.dumps(chain["finding_ids"]),
                chain["impact"],
                chain.get("status", "discovered"),
                now,
            ),
        )
        await db.commit()
        return chain_id

    async def get_attack_chains(self, engagement_id: str) -> list[dict[str, Any]]:
        db = await self._get_db()
        query = (
            "SELECT * FROM attack_chains WHERE engagement_id = ? "
            "ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        )
        async with db.execute(query, (engagement_id,)) as cursor:
            results = []
            for row in await cursor.fetchall():
                d = dict(row)
                d["steps"] = json.loads(d["steps"])
                d["finding_ids"] = json.loads(d["finding_ids"])
                results.append(d)
            return results

    async def update_chain_status(self, chain_id: str, status: str) -> None:
        """Update an attack chain's status (discovered/confirmed/unvalidated/rejected)."""
        db = await self._get_db()
        await db.execute(
            "UPDATE attack_chains SET status = ? WHERE id = ?",
            (status, chain_id),
        )
        await db.commit()

    async def update_finding_poc_status(
        self, finding_id: str, status: str, poc: str | None = None
    ) -> None:
        """Update a finding's poc_status (and optionally its poc text)."""
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        if poc is None:
            await db.execute(
                "UPDATE findings SET poc_status = ?, updated_at = ? WHERE id = ?",
                (status, now, finding_id),
            )
        else:
            await db.execute(
                "UPDATE findings SET poc_status = ?, poc = ?, updated_at = ? WHERE id = ?",
                (status, poc, now, finding_id),
            )
        await db.commit()

    async def add_detection_rule(self, rule: dict[str, Any]) -> str:
        db = await self._get_db()
        rule_id = rule.get("id", str(uuid.uuid4())[:12])
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT OR REPLACE INTO detection_rules
               (id, finding_id, engagement_id, format, rule, description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                rule_id,
                rule["finding_id"],
                rule["engagement_id"],
                rule["format"],
                rule["rule"],
                rule["description"],
                now,
            ),
        )
        await db.commit()
        return rule_id

    async def get_detection_rules(self, engagement_id: str) -> list[dict[str, Any]]:
        db = await self._get_db()
        async with db.execute(
            "SELECT * FROM detection_rules WHERE engagement_id = ?",
            (engagement_id,),
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def get_tool_results(
        self,
        engagement_id: str,
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        db = await self._get_db()
        sql = "SELECT * FROM tool_results WHERE engagement_id = ? ORDER BY created_at DESC"
        params: tuple[Any, ...] = (engagement_id,)
        if limit:
            sql += " LIMIT ?"
            params = (engagement_id, limit)
        async with db.execute(sql, params) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def add_stage_record(self, record: dict[str, Any]) -> str:
        db = await self._get_db()
        record_id = str(uuid.uuid4())[:12]
        await db.execute(
            """INSERT INTO stage_events
               (id, engagement_id, stage, title, status, progress, details, description, automated, depends_on, started_at, completed_at, duration_ms, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record_id,
                record.get("engagement_id", ""),
                record.get("stage", ""),
                record.get("title", ""),
                record.get("status", ""),
                record.get("progress", 0.0),
                record.get("details"),
                record.get("description"),
                1 if record.get("automated", True) else 0,
                json.dumps(record.get("depends_on", [])),
                record.get("started_at"),
                record.get("completed_at"),
                record.get("duration_ms"),
                record.get("recorded_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )
        await db.commit()
        return record_id

    async def get_stage_records(self, engagement_id: str) -> list[dict[str, Any]]:
        db = await self._get_db()
        async with db.execute(
            "SELECT * FROM stage_events WHERE engagement_id = ? ORDER BY recorded_at ASC",
            (engagement_id,),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        for row in rows:
            row["depends_on"] = json.loads(row["depends_on"] or "[]")
            row["automated"] = bool(row.get("automated", 1))
        return rows

    async def add_tool_result(self, result: dict[str, Any]) -> str:
        db = await self._get_db()
        result_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT INTO tool_results
               (id, engagement_id, tool_name, target, args, output, exit_code, duration, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result_id,
                result.get("engagement_id", ""),
                result.get("tool_name", ""),
                result.get("target", ""),
                json.dumps(result.get("args", {})),
                result.get("output", ""),
                result.get("exit_code", 0),
                result.get("duration", 0.0),
                now,
            ),
        )
        await db.commit()
        return result_id

    async def get_engagement_summary(self, engagement_id: str) -> dict[str, Any]:
        db = await self._get_db()
        async with db.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE engagement_id = ? GROUP BY severity",
            (engagement_id,),
        ) as cursor:
            severity_counts = {row["severity"]: row["count"] for row in await cursor.fetchall()}

        async with db.execute(
            "SELECT COUNT(*) as count FROM attack_chains WHERE engagement_id = ?",
            (engagement_id,),
        ) as cursor:
            row = await cursor.fetchone()
            chain_count = row["count"] if row else 0

        async with db.execute(
            "SELECT COUNT(*) as count FROM detection_rules WHERE engagement_id = ?",
            (engagement_id,),
        ) as cursor:
            row = await cursor.fetchone()
            rule_count = row["count"] if row else 0

        return {
            "engagement_id": engagement_id,
            "total_findings": sum(severity_counts.values()),
            "by_severity": severity_counts,
            "attack_chains": chain_count,
            "detection_rules": rule_count,
        }

    async def list_engagements(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        db = await self._get_db()
        query = "SELECT * FROM engagements WHERE 1=1"
        params: list[Any] = []
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        async with db.execute(query, params) as cursor:
            rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            summary = await self.get_engagement_summary(row["id"])
            row["total_findings"] = summary["total_findings"]
            row["by_severity"] = summary["by_severity"]
        return rows

    async def update_engagement_phase(
        self,
        engagement_id: str,
        phase: str,
        completed: bool = False,
    ) -> None:
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        if completed:
            async with db.execute(
                "SELECT completed_phases FROM engagements WHERE id = ?",
                (engagement_id,),
            ) as cursor:
                row = await cursor.fetchone()
            phases = json.loads(row["completed_phases"]) if row and row["completed_phases"] else []
            if phase not in phases:
                phases.append(phase)
            await db.execute(
                "UPDATE engagements SET current_phase = ?, completed_phases = ?, updated_at = ? WHERE id = ?",
                (phase, json.dumps(phases), now, engagement_id),
            )
        else:
            await db.execute(
                "UPDATE engagements SET current_phase = ?, updated_at = ? WHERE id = ?",
                (phase, now, engagement_id),
            )
        await db.commit()

    async def get_checkpoint(self, engagement_id: str) -> dict[str, Any] | None:
        db = await self._get_db()
        async with db.execute(
            "SELECT current_phase, completed_phases, status FROM engagements WHERE id = ?",
            (engagement_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "current_phase": row["current_phase"],
                "completed_phases": json.loads(row["completed_phases"] or "[]"),
                "status": row["status"],
            }

    async def update_engagement_status(
        self,
        engagement_id: str,
        status: str,
    ) -> None:
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        updates = "status = ?, updated_at = ?"
        params: list[Any] = [status, now]
        if status == "completed":
            updates += ", completed_at = ?"
            params.append(now)
        params.append(engagement_id)
        await db.execute(f"UPDATE engagements SET {updates} WHERE id = ?", params)
        await db.commit()

    async def reconcile_stale_engagements(self, max_age_minutes: int = 30) -> int:
        """Mark engagements stuck in 'running' as 'interrupted'.

        When pttools dies mid-engagement (kill, crash, laptop sleep) the row stays
        in 'running' forever and clutters `pttools list`. Anything in 'running'
        with no updates for max_age_minutes is treated as orphaned. Called at
        startup of every new engagement.

        Returns the count of engagements that were reconciled.
        """
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)).isoformat()
        db = await self._get_db()
        cursor = await db.execute(
            "UPDATE engagements SET status = 'interrupted', updated_at = ? "
            "WHERE status = 'running' AND COALESCE(updated_at, created_at) < ?",
            [datetime.now(timezone.utc).isoformat(), cutoff],
        )
        await db.commit()
        return cursor.rowcount or 0

    async def update_engagement_intensity(
        self,
        engagement_id: str,
        intensity: str,
    ) -> None:
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            "UPDATE engagements SET intensity = ?, updated_at = ? WHERE id = ?",
            (intensity, now, engagement_id),
        )
        await db.commit()

    async def create_campaign(
        self,
        name: str,
        targets: list[str],
    ) -> str:
        db = await self._get_db()
        now = datetime.now(timezone.utc).isoformat()
        campaign_id = str(uuid.uuid4())[:8]
        await db.execute(
            "INSERT INTO campaigns (id, name, status, target_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (campaign_id, name, "created", len(targets), now, now),
        )
        await db.commit()
        return campaign_id

    async def get_campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        db = await self._get_db()
        async with db.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ) as cursor:
            campaign = await cursor.fetchone()
            if not campaign:
                return {"error": f"Campaign {campaign_id} not found"}
            campaign = dict(campaign)

        async with db.execute(
            "SELECT id, target, status FROM engagements WHERE campaign_id = ?",
            (campaign_id,),
        ) as cursor:
            engagements = [dict(row) for row in await cursor.fetchall()]

        total_findings = 0
        severity_totals: dict[str, int] = {}
        for eng in engagements:
            summary = await self.get_engagement_summary(eng["id"])
            total_findings += summary["total_findings"]
            for sev, count in summary["by_severity"].items():
                severity_totals[sev] = severity_totals.get(sev, 0) + count

        return {
            "campaign_id": campaign_id,
            "name": campaign["name"],
            "status": campaign["status"],
            "target_count": campaign["target_count"],
            "engagements": engagements,
            "total_findings": total_findings,
            "by_severity": severity_totals,
        }
