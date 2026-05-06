"""HashiCorp Vault resolver.

Reference is a Vault path like ``secret/data/pentests/staging-acme``
(KV v2) or ``secret/pentests/staging-acme`` (KV v1).

Required env: ``VAULT_TOKEN``. Optional env: ``VAULT_ADDR`` (also
overridable via the profile's ``extra`` dict as ``vault_addr``).

By default, the resolver reads ``data.password`` from KV v2 responses
or ``password`` from KV v1. Override with ``password_field`` in the
profile's ``extra`` dict.
"""

from __future__ import annotations

import os

import httpx

from cli.credential_resolvers import SecurityError
from cli.secure_credential import SecureCredential


class VaultResolver:
    name: str = "vault"

    def resolve(self, ref: str, **kwargs: object) -> SecureCredential:
        if not ref:
            raise SecurityError("vault resolver: reference is empty")
        token = os.environ.get("VAULT_TOKEN", "")
        if not token:
            raise SecurityError(
                "vault resolver: VAULT_TOKEN env var is unset. "
                "Run `vault login` and export VAULT_TOKEN before scanning."
            )
        addr = str(kwargs.get("vault_addr", "")) or os.environ.get("VAULT_ADDR", "")
        if not addr:
            raise SecurityError(
                "vault resolver: VAULT_ADDR not configured. "
                "Set VAULT_ADDR env var or add vault_addr: <url> to the profile."
            )
        password_field = str(kwargs.get("password_field", "password"))

        url = f"{addr.rstrip('/')}/v1/{ref.lstrip('/')}"
        try:
            resp = httpx.get(
                url,
                headers={"X-Vault-Token": token},
                timeout=15.0,
            )
        except httpx.RequestError as e:
            raise SecurityError(f"vault resolver: request failed: {e}") from e
        if resp.status_code == 403:
            raise SecurityError(
                f"vault resolver: 403 forbidden — token lacks permission for {ref!r}"
            )
        if resp.status_code == 404:
            raise SecurityError(f"vault resolver: 404 not found — path {ref!r}")
        if resp.status_code >= 400:
            raise SecurityError(f"vault resolver: HTTP {resp.status_code}")
        try:
            payload = resp.json()
        except ValueError as e:
            raise SecurityError("vault resolver: response was not JSON") from e

        # KV v2 wraps the secret as data.data.<field>; KV v1 is data.<field>.
        data = payload.get("data") or {}
        value = data["data"].get(password_field, "") if isinstance(data.get("data"), dict) else data.get(password_field, "")
        if not value:
            raise SecurityError(
                f"vault resolver: field {password_field!r} is empty or missing in response"
            )
        return SecureCredential(value=str(value), source=self.name, ref=ref)
