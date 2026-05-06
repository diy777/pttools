"""1Password CLI resolver.

Reference is an op:// URI like ``op://Vault/Item/field``. Resolution
shells out to ``op read <ref>``. The user is expected to have run
``op signin`` separately.

Security:
- ``op`` reads the value to stdout; we capture stdout, never log it.
- If ``op`` is not installed, we fail closed (no plaintext fallback).
- If the user is not signed in, ``op`` prints to stderr; we surface a
  clean error without echoing stderr (which can sometimes contain refs).
"""

from __future__ import annotations

import shutil
import subprocess

from cli.credential_resolvers import SecurityError
from cli.secure_credential import SecureCredential


class OpResolver:
    name: str = "op"

    def resolve(self, ref: str, **kwargs: object) -> SecureCredential:
        if not ref:
            raise SecurityError("op resolver: reference is empty")
        if not ref.startswith("op://"):
            raise SecurityError(
                f"op resolver: reference must start with op://, got {ref!r}"
            )
        if shutil.which("op") is None:
            raise SecurityError(
                "op resolver: 1Password CLI ('op') is not installed. "
                "Install: https://developer.1password.com/docs/cli/get-started"
            )
        try:
            proc = subprocess.run(
                ["op", "read", "--no-newline", ref],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise SecurityError("op resolver: timeout waiting for 1Password CLI") from e
        if proc.returncode != 0:
            # Don't surface stderr verbatim — could contain the ref or hints.
            raise SecurityError(
                f"op resolver: 'op read' exited {proc.returncode}. "
                "Run `op signin` if not signed in, or check the reference path."
            )
        value = proc.stdout
        if not value:
            raise SecurityError("op resolver: empty value returned")
        return SecureCredential(value=value, source=self.name, ref=ref)
