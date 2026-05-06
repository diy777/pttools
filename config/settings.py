"""Configuration management for pentest-tools"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

CONFIG_SEARCH_PATHS = [
    Path("config/pentest-tools.yaml"),
    Path.home() / ".pentest-tools" / "config.yaml",
    Path("pentest-tools.yaml"),
]


def _interpolate_env(value: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.getenv(m.group(1), ""), value)


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.0
    max_tokens: int = 4096

    def __post_init__(self):
        self.api_key = self.api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = self.base_url or os.getenv("OPENAI_BASE_URL", "")


@dataclass
class ScanConfig:
    default_intensity: str = "normal"
    default_scope: str = "full"

    def __post_init__(self):
        valid = {"stealth", "normal", "aggressive"}
        if self.default_intensity not in valid:
            self.default_intensity = "normal"


@dataclass
class AgentConfig:
    max_concurrent_tools: int = 5
    tool_timeout: int = 300
    auto_chain: bool = True
    auto_validate_pocs: bool = True
    auto_generate_detections: bool = True
    hitl_mode: bool = True
    approval_required_for: list[str] = field(default_factory=lambda: ["exploitation", "credential_use", "data_access"])


@dataclass
class DBConfig:
    path: str = "pentest_findings.db"
    backup_enabled: bool = True
    backup_interval_hours: int = 24


@dataclass
class ReportConfig:
    default_format: str = "markdown"
    include_pocs: bool = True
    include_detections: bool = True
    include_raw_output: bool = False
    output_dir: str = "reports"


@dataclass
class LicenseConfig:
    api_url: str = "https://app.pentest-tools.local/api/cli/validate"
    cache_ttl_hours: int = 24


@dataclass
class WebhookConfig:
    url: str = ""
    webhook_type: str = "generic"
    events: list[str] = field(default_factory=lambda: [
        "engagement.started",
        "engagement.completed",
        "finding.critical",
    ])
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        import os
        self.url = self.url or os.getenv("PENTEST_WEBHOOK_URL", "")
        self.webhook_type = self.webhook_type or os.getenv("PENTEST_WEBHOOK_TYPE", "generic")


@dataclass
class PentestConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    db: DBConfig = field(default_factory=DBConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    license: LicenseConfig = field(default_factory=LicenseConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    plugins_dir: str = str(Path.home() / ".pentest-tools" / "plugins")
    evidence_dir: str = str(Path.home() / ".pentest-tools" / "evidence")
    scope: dict[str, Any] = field(
        default_factory=lambda: {"allowed_targets": [], "excluded_targets": [], "max_depth": 3}
    )

    @classmethod
    def from_file(cls, path: str | None = None) -> "PentestConfig":
        config_path = _find_config(path)
        if config_path and config_path.exists():
            raw = config_path.read_text()
            raw = _interpolate_env(raw)
            data = yaml.safe_load(raw) or {}
            return cls(
                llm=LLMConfig(**data.get("llm", {})),
                agent=AgentConfig(**data.get("agent", {})),
                scan=ScanConfig(**data.get("scan", {})),
                db=DBConfig(**data.get("database", data.get("db", {}))),
                report=ReportConfig(**data.get("report", {})),
                license=LicenseConfig(**data.get("license", {})),
                webhook=WebhookConfig(**data.get("webhook", data.get("webhooks", {}))),
                plugins_dir=data.get("plugins_dir", str(Path.home() / ".pentest-tools" / "plugins")),
                evidence_dir=data.get("evidence_dir", str(Path.home() / ".pentest-tools" / "evidence")),
                scope=data.get("scope", {}),
            )
        return cls()

    def to_dict(self, mask_secrets: bool = False) -> dict[str, Any]:
        api_key = self.llm.api_key
        if mask_secrets and api_key:
            api_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        return {
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "api_key": api_key,
                "base_url": self.llm.base_url,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
            },
            "agent": {
                "max_concurrent_tools": self.agent.max_concurrent_tools,
                "tool_timeout": self.agent.tool_timeout,
                "auto_chain": self.agent.auto_chain,
                "auto_validate_pocs": self.agent.auto_validate_pocs,
                "auto_generate_detections": self.agent.auto_generate_detections,
                "hitl_mode": self.agent.hitl_mode,
                "approval_required_for": self.agent.approval_required_for,
            },
            "scan": {
                "default_intensity": self.scan.default_intensity,
                "default_scope": self.scan.default_scope,
            },
            "database": {
                "path": self.db.path,
                "backup_enabled": self.db.backup_enabled,
                "backup_interval_hours": self.db.backup_interval_hours,
            },
            "report": {
                "default_format": self.report.default_format,
                "include_pocs": self.report.include_pocs,
                "include_detections": self.report.include_detections,
                "include_raw_output": self.report.include_raw_output,
                "output_dir": self.report.output_dir,
            },
            "license": {
                "api_url": self.license.api_url,
                "cache_ttl_hours": self.license.cache_ttl_hours,
            },
            "webhooks": {
                "url": self.webhook.url,
                "webhook_type": self.webhook.webhook_type,
                "events": self.webhook.events,
            },
            "plugins_dir": self.plugins_dir,
            "evidence_dir": self.evidence_dir,
            "scope": self.scope,
        }


def _find_config(explicit_path: str | None = None) -> Path | None:
    if explicit_path:
        return Path(explicit_path)
    for p in CONFIG_SEARCH_PATHS:
        if p.exists():
            return p
    return None


_GLOBAL_CONFIG: PentestConfig | None = None


def load_config(path: str | None = None) -> PentestConfig:
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = PentestConfig.from_file(path)
    return _GLOBAL_CONFIG


def reset_config() -> None:
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = None


DEFAULT_CONFIG_TEMPLATE = """\
# pentest-tools configuration
# Env var interpolation: ${VAR_NAME}

llm:
  provider: openai           # openai | anthropic | ollama
  model: gpt-4o
  api_key: ${OPENAI_API_KEY}
  temperature: 0.0

scan:
  default_intensity: normal  # stealth | normal | aggressive
  default_scope: full        # recon | web | ad | cloud | full

database:
  path: pentest_findings.db

report:
  default_format: markdown
  output_dir: reports

webhooks:
  url: ""                    # Slack incoming webhook or generic HTTP POST
  webhook_type: generic      # generic | slack
  events:
    - engagement.completed
    - finding.critical

plugins_dir: ~/.pentest-tools/plugins
evidence_dir: ~/.pentest-tools/evidence
"""


def generate_default_config(output_path: Path | None = None) -> Path:
    path = output_path or (Path.home() / ".pentest-tools" / "config.yaml")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_CONFIG_TEMPLATE)
    return path
