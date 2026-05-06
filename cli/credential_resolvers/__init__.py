"""Credential resolvers fetch credential values from named sources.

Each resolver implements the Resolver protocol: given a reference string,
return a SecureCredential or raise SecurityError. Resolvers MUST fail
closed: never fall back to an interactive prompt for plaintext, never
return a partial credential, never log the resolved value.
"""

from __future__ import annotations

from typing import Protocol

from cli.secure_credential import SecureCredential


class SecurityError(Exception):
    """Raised when a resolver cannot satisfy a credential request safely.

    Includes: backend unreachable, reference malformed, dependency missing,
    permission denied. Never raised for "wrong password" — that's an auth
    error, not a security error.
    """


class Resolver(Protocol):
    """Protocol every resolver implements."""

    name: str  # e.g. "env", "op", "vault", "aws-sm"

    def resolve(self, ref: str, **kwargs: object) -> SecureCredential:
        """Fetch the credential pointed at by ref.

        Args:
            ref: Reference string (env var name, vault path, ARN, op:// URI).
            **kwargs: Resolver-specific extras (e.g. vault_addr, password_field).

        Returns:
            SecureCredential containing the resolved value.

        Raises:
            SecurityError: backend failure, missing dep, malformed ref.
        """
        ...


def get_resolver(source: str) -> Resolver:
    """Look up a resolver by its source name."""
    from cli.credential_resolvers.env import EnvResolver

    resolvers: dict[str, Resolver] = {
        "env": EnvResolver(),
    }

    # Optional resolvers loaded lazily so missing deps don't break the import.
    try:
        from cli.credential_resolvers.op import OpResolver

        resolvers["op"] = OpResolver()
    except ImportError:
        pass
    try:
        from cli.credential_resolvers.vault import VaultResolver

        resolvers["vault"] = VaultResolver()
    except ImportError:
        pass
    try:
        from cli.credential_resolvers.aws_sm import AwsSmResolver

        resolvers["aws-sm"] = AwsSmResolver()
    except ImportError:
        pass

    if source not in resolvers:
        raise SecurityError(
            f"unknown credential source: {source!r}. "
            f"Supported: {sorted(resolvers)}"
        )
    return resolvers[source]


__all__ = ["Resolver", "SecurityError", "get_resolver"]
