"""Auth profile manager.

Profiles live in ~/.pentest-tools/auth-profiles.yaml (perms 0600). Each profile
is a named set of authentication parameters for a target. Credentials are
NEVER stored in this file — only references (env var names, vault paths,
1Password URIs, AWS Secrets Manager ARNs).

The manager is the only code that reads the file. It hands resolved
credentials to the engine via SecureCredential. It refuses to load a file
that has insecure permissions.

Schema (Appendix B of the ULTRAPLAN):

    version: 1
    active: <profile-name>             # optional, name of default profile
    profiles:
      <name>:
        flow: form_post|basic|bearer|ntlm|oauth_password
        login_url: <url>               # form_post / oauth_password
        username: <str>                # not a secret in most contexts
        username_field: <str>          # form_post, default "username"
        password_field: <str>          # form_post, default "password"
        success_marker: <str>          # form_post, optional
        domain: <str>                  # ntlm
        target_pattern: <glob>         # optional, hint only
        password_source: env|op|vault|aws-sm
        password_ref: <ref>
        # for bearer-flow profiles use token_source / token_ref instead
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cli.credential_resolvers import SecurityError, get_resolver
from cli.secure_credential import SecureCredential

PENTEST_TOOLS_DIR = Path.home() / ".pentest-tools"
PROFILES_FILE = PENTEST_TOOLS_DIR / "auth-profiles.yaml"

VALID_FLOWS = {"form_post", "basic", "bearer", "ntlm", "oauth_password"}
VALID_SOURCES = {"env", "op", "vault", "aws-sm"}
SECRET_FIELDS = {"password", "token", "secret"}


class ProfileError(Exception):
    """Profile not found, malformed, or otherwise unusable."""


@dataclass
class AuthProfile:
    """One named authentication profile."""

    name: str
    flow: str
    username: str = ""
    username_field: str = "username"
    password_field: str = "password"
    login_url: str = ""
    success_marker: str = ""
    domain: str = ""
    target_pattern: str = ""
    password_source: str = ""
    password_ref: str = ""
    token_source: str = ""
    token_ref: str = ""
    # extra resolver-specific fields (e.g. vault_addr, password_field for vault)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"flow": self.flow}
        for key in (
            "login_url",
            "username",
            "username_field",
            "password_field",
            "success_marker",
            "domain",
            "target_pattern",
            "password_source",
            "password_ref",
            "token_source",
            "token_ref",
        ):
            value = getattr(self, key)
            if value and (key not in ("username_field", "password_field") or value not in ("username", "password")):
                out[key] = value
        if self.extra:
            out.update(self.extra)
        return out

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> AuthProfile:
        if "flow" not in data:
            raise ProfileError(f"profile {name!r}: missing required key 'flow'")
        flow = data["flow"]
        if flow not in VALID_FLOWS:
            raise ProfileError(
                f"profile {name!r}: invalid flow {flow!r}. "
                f"Must be one of {sorted(VALID_FLOWS)}"
            )

        # Validate source keys
        password_source = data.get("password_source", "")
        token_source = data.get("token_source", "")
        if password_source and password_source not in VALID_SOURCES:
            raise ProfileError(
                f"profile {name!r}: invalid password_source {password_source!r}. "
                f"Must be one of {sorted(VALID_SOURCES)}"
            )
        if token_source and token_source not in VALID_SOURCES:
            raise ProfileError(
                f"profile {name!r}: invalid token_source {token_source!r}. "
                f"Must be one of {sorted(VALID_SOURCES)}"
            )

        # Reject any plaintext-looking keys (defense in depth)
        for forbidden in ("password", "token", "secret"):
            if forbidden in data:
                raise ProfileError(
                    f"profile {name!r}: refusing to load profile with bare "
                    f"{forbidden!r} key. Use {forbidden}_source / {forbidden}_ref."
                )

        known = {
            "flow",
            "login_url",
            "username",
            "username_field",
            "password_field",
            "success_marker",
            "domain",
            "target_pattern",
            "password_source",
            "password_ref",
            "token_source",
            "token_ref",
        }
        extra = {k: v for k, v in data.items() if k not in known}

        return cls(
            name=name,
            flow=flow,
            username=data.get("username", ""),
            username_field=data.get("username_field", "username"),
            password_field=data.get("password_field", "password"),
            login_url=data.get("login_url", ""),
            success_marker=data.get("success_marker", ""),
            domain=data.get("domain", ""),
            target_pattern=data.get("target_pattern", ""),
            password_source=password_source,
            password_ref=data.get("password_ref", ""),
            token_source=token_source,
            token_ref=data.get("token_ref", ""),
            extra=extra,
        )


@dataclass
class ProfilesFile:
    """The whole auth-profiles.yaml document."""

    version: int = 1
    active: str = ""
    profiles: dict[str, AuthProfile] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            **({"active": self.active} if self.active else {}),
            "profiles": {name: p.to_dict() for name, p in self.profiles.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProfilesFile:
        if not isinstance(data, dict):
            raise ProfileError("profiles file: top-level must be a mapping")
        version = data.get("version", 1)
        if version != 1:
            raise ProfileError(f"profiles file: unsupported version {version!r}, expected 1")
        active = data.get("active", "")
        raw_profiles = data.get("profiles", {})
        if not isinstance(raw_profiles, dict):
            raise ProfileError("profiles file: 'profiles' must be a mapping")
        profiles = {
            name: AuthProfile.from_dict(name, p_data) for name, p_data in raw_profiles.items()
        }
        if active and active not in profiles:
            raise ProfileError(
                f"profiles file: active profile {active!r} not found in profiles"
            )
        return cls(version=version, active=active, profiles=profiles)


# ---------- file-level operations ----------


def _ensure_dir() -> None:
    PENTEST_TOOLS_DIR.mkdir(mode=0o700, exist_ok=True)


def _check_perms(path: Path) -> None:
    """Refuse to load a profile file with permissions wider than 0600.

    Windows uses ACLs, not Unix mode bits, so st_mode always reads back as
    0o666 regardless of access. The check is a no-op there; users wanting
    real ACL hardening on Windows should set DACLs out-of-band.
    """
    import sys
    if sys.platform == "win32":
        return
    st = path.stat()
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SecurityError(
            f"profile file {path} has insecure permissions {oct(mode)}; "
            f"expected 0600. Run: chmod 600 {path}"
        )


def _resolve_path(path: Path | None) -> Path:
    """Resolve `path` to PROFILES_FILE module constant if None.

    Looking up the module attribute at call time (not def time) lets tests
    monkeypatch cli.auth_profiles.PROFILES_FILE and have it take effect.
    """
    if path is not None:
        return path
    import sys

    return sys.modules[__name__].PROFILES_FILE


def load_profiles_file(path: Path | None = None) -> ProfilesFile:
    """Load and validate the profiles YAML. Returns empty file if absent."""
    path = _resolve_path(path)
    if not path.exists():
        return ProfilesFile()
    _check_perms(path)
    try:
        with path.open() as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ProfileError(f"profile file {path}: malformed YAML: {e}") from e
    return ProfilesFile.from_dict(data)


def save_profiles_file(pf: ProfilesFile, path: Path | None = None) -> None:
    """Atomically write the profiles file with 0600 perms."""
    path = _resolve_path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        yaml.safe_dump(pf.to_dict(), f, sort_keys=False)
    tmp.chmod(0o600)
    os.replace(tmp, path)


# ---------- public API used by CLI / MCP ----------


def add_profile(profile: AuthProfile, path: Path | None = None) -> None:
    path = _resolve_path(path)
    pf = load_profiles_file(path)
    if profile.name in pf.profiles:
        raise ProfileError(
            f"profile {profile.name!r} already exists. "
            f"Remove it first: pentest-tools auth profile remove {profile.name}"
        )
    pf.profiles[profile.name] = profile
    if not pf.active:
        pf.active = profile.name
    save_profiles_file(pf, path)


def remove_profile(name: str, path: Path | None = None) -> None:
    path = _resolve_path(path)
    pf = load_profiles_file(path)
    if name not in pf.profiles:
        raise ProfileError(f"profile {name!r} not found")
    del pf.profiles[name]
    if pf.active == name:
        # pick another profile if any remain, else clear
        pf.active = next(iter(pf.profiles), "")
    save_profiles_file(pf, path)


def list_profiles(path: Path | None = None) -> list[AuthProfile]:
    pf = load_profiles_file(path)
    return list(pf.profiles.values())


def get_profile(name: str, path: Path | None = None) -> AuthProfile:
    pf = load_profiles_file(path)
    if name not in pf.profiles:
        raise ProfileError(
            f"profile {name!r} not found. List available: pentest-tools auth profile list"
        )
    return pf.profiles[name]


def get_active_name(path: Path | None = None) -> str:
    return load_profiles_file(path).active


def set_active(name: str, path: Path | None = None) -> None:
    path = _resolve_path(path)
    pf = load_profiles_file(path)
    if name not in pf.profiles:
        raise ProfileError(f"cannot set active: profile {name!r} not found")
    pf.active = name
    save_profiles_file(pf, path)


# ---------- credential resolution ----------


@dataclass
class ResolvedAuth:
    """A profile with its credentials resolved into SecureCredential objects."""

    profile: AuthProfile
    password: SecureCredential | None = None
    token: SecureCredential | None = None


def resolve(profile: AuthProfile) -> ResolvedAuth:
    """Resolve a profile's credential references into SecureCredentials.

    Calls the appropriate resolver for password_source and/or token_source.
    Returns ResolvedAuth with any retrieved credentials. Caller is responsible
    for ensuring the profile has the credentials its flow needs.
    """
    resolved = ResolvedAuth(profile=profile)
    if profile.password_source:
        resolver = get_resolver(profile.password_source)
        resolved.password = resolver.resolve(profile.password_ref, **profile.extra)
    if profile.token_source:
        resolver = get_resolver(profile.token_source)
        resolved.token = resolver.resolve(profile.token_ref, **profile.extra)
    return resolved


__all__ = [
    "AuthProfile",
    "ProfileError",
    "ProfilesFile",
    "ResolvedAuth",
    "PROFILES_FILE",
    "VALID_FLOWS",
    "VALID_SOURCES",
    "add_profile",
    "get_active_name",
    "get_profile",
    "list_profiles",
    "load_profiles_file",
    "remove_profile",
    "resolve",
    "save_profiles_file",
    "set_active",
]
