"""Authentication handler for injecting credentials into tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthCredentials:
    auth_type: str = ""
    cookies: str = ""
    bearer_token: str = ""
    basic_auth: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    form_fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AuthCredentials:
        if not data:
            return cls()
        return cls(
            auth_type=data.get("type", ""),
            cookies=data.get("cookies", data.get("cookie", "")),
            bearer_token=data.get("bearer_token", data.get("token", "")),
            basic_auth=data.get("basic_auth", data.get("username", "")),
            headers=data.get("headers", {}),
            form_fields=data.get("form_fields", {}),
        )

    @classmethod
    def from_cli_args(
        cls,
        cookie: str = "",
        header: str = "",
        basic_auth: str = "",
    ) -> AuthCredentials:
        headers = {}
        if header:
            parts = header.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip()] = parts[1].strip()
        auth_type = ""
        if cookie:
            auth_type = "cookie"
        elif basic_auth:
            auth_type = "basic"
        elif header and "authorization" in header.lower():
            auth_type = "bearer"
        return cls(
            auth_type=auth_type,
            cookies=cookie,
            basic_auth=basic_auth,
            headers=headers,
        )

    @property
    def is_set(self) -> bool:
        return bool(self.cookies or self.bearer_token or self.basic_auth or self.headers)


TOOL_AUTH_FLAGS: dict[str, dict[str, str]] = {
    "nuclei": {"cookie": "-H 'Cookie: {value}'", "bearer": "-H 'Authorization: Bearer {value}'", "header": "-H '{key}: {value}'"},
    "sqlmap": {"cookie": "--cookie={value}", "basic": "--auth-type=basic --auth-cred={value}"},
    "nikto": {"cookie": "-cookie {value}"},
    "ffuf": {"cookie": "-H 'Cookie: {value}'", "bearer": "-H 'Authorization: Bearer {value}'", "header": "-H '{key}: {value}'"},
    "gobuster": {"cookie": "-c {value}", "bearer": "-H 'Authorization: Bearer {value}'"},
    "httpx": {"cookie": "-H 'Cookie: {value}'", "bearer": "-H 'Authorization: Bearer {value}'"},
    "whatweb": {"cookie": "--cookie={value}"},
    "wpscan": {"cookie": "--cookie-string {value}"},
    "curl": {"cookie": "-b {value}", "bearer": "-H 'Authorization: Bearer {value}'", "basic": "-u {value}"},
    "hydra": {"basic": "-l {user} -p {password}"},
}


def build_auth_args(tool_name: str, creds: AuthCredentials) -> list[str]:
    if not creds.is_set:
        return []

    flags = TOOL_AUTH_FLAGS.get(tool_name, {})
    args: list[str] = []

    if creds.cookies and "cookie" in flags:
        flag = flags["cookie"].replace("{value}", creds.cookies)
        args.extend(_split_flag(flag))

    if creds.bearer_token and "bearer" in flags:
        flag = flags["bearer"].replace("{value}", creds.bearer_token)
        args.extend(_split_flag(flag))

    if creds.basic_auth and "basic" in flags:
        flag = flags["basic"].replace("{value}", creds.basic_auth)
        args.extend(_split_flag(flag))

    for key, value in creds.headers.items():
        if "header" in flags:
            flag = flags["header"].replace("{key}", key).replace("{value}", value)
            args.extend(_split_flag(flag))

    return args


def _split_flag(flag: str) -> list[str]:
    if flag.startswith("-H '") and flag.endswith("'"):
        return ["-H", flag[4:-1]]
    if "=" in flag and flag.startswith("-"):
        return [flag]
    parts = flag.split(" ", 1)
    return parts if len(parts) == 2 else [flag]
