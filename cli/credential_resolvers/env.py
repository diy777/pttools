"""Environment variable resolver.

Reference is the env var name. Resolution is os.environ[ref].
Fails if env var is unset or empty.
"""

from __future__ import annotations

import os
import re

from cli.credential_resolvers import SecurityError
from cli.secure_credential import SecureCredential

_VALID_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class EnvResolver:
    name: str = "env"

    def resolve(self, ref: str, **kwargs: object) -> SecureCredential:
        if not ref:
            raise SecurityError("env resolver: reference is empty")
        if not _VALID_NAME.match(ref):
            raise SecurityError(
                f"env resolver: {ref!r} is not a valid env var name "
                "(letters, digits, underscores; cannot start with digit)"
            )
        value = os.environ.get(ref, "")
        if not value:
            raise SecurityError(
                f"env resolver: env var {ref!r} is unset or empty. "
                f"Set it before running: export {ref}=..."
            )
        return SecureCredential(value=value, source=self.name, ref=ref)
