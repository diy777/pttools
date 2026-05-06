"""AWS Secrets Manager resolver.

Reference is a Secrets Manager ARN or secret ID, e.g.
``arn:aws:secretsmanager:us-east-1:123456789012:secret:pentests/staging-acme``
or just ``pentests/staging-acme``.

Requires the ``cloud`` extra (``pip install pttools[cloud]``) for boto3.

If the SecretString is JSON, ``password_field`` (in the profile's extra
dict) selects which field. If it's a plain string, ``password_field`` is
ignored.
"""

from __future__ import annotations

import json

from cli.credential_resolvers import SecurityError
from cli.secure_credential import SecureCredential


class AwsSmResolver:
    name: str = "aws-sm"

    def resolve(self, ref: str, **kwargs: object) -> SecureCredential:
        if not ref:
            raise SecurityError("aws-sm resolver: reference is empty")
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as e:
            raise SecurityError(
                "aws-sm resolver: boto3 is not installed. "
                "Install: pip install 'pttools[cloud]'"
            ) from e

        password_field = kwargs.get("password_field")
        client = boto3.client("secretsmanager")
        try:
            resp = client.get_secret_value(SecretId=ref)
        except Exception as e:  # noqa: BLE001 — boto3 surfaces many error types
            raise SecurityError(f"aws-sm resolver: GetSecretValue failed: {e}") from e

        if "SecretString" not in resp:
            raise SecurityError(
                "aws-sm resolver: SecretString missing (binary secret not supported)"
            )
        raw = resp["SecretString"]
        # Try to parse as JSON; if it parses and password_field is set, extract.
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and password_field:
                value = parsed.get(str(password_field), "")
                if not value:
                    raise SecurityError(
                        f"aws-sm resolver: field {password_field!r} not found in JSON secret"
                    )
                return SecureCredential(value=str(value), source=self.name, ref=ref)
        except (ValueError, TypeError):
            pass
        # Fall back to raw string
        if not raw:
            raise SecurityError("aws-sm resolver: empty SecretString")
        return SecureCredential(value=raw, source=self.name, ref=ref)
