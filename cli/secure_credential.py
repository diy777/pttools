"""In-memory credential holder that refuses to leak.

A SecureCredential wraps a resolved credential value (password, token, etc.) and
never exposes it via repr/str/JSON serialization. The only way to read the value
is via .reveal(), which is a deliberate explicit call that's easy to grep for in
review.

Security invariants:
- repr/str return "[REDACTED]"
- json.dumps refuses to serialize (TypeError)
- Logging the object yields "[REDACTED]"
- The wrapped value is stored in a private attribute, not on the public surface
"""

from __future__ import annotations

from typing import Any


class SecureCredential:
    """Holds a resolved credential value. Refuses serialization."""

    __slots__ = ("_value", "_source", "_ref")

    def __init__(self, value: str, source: str = "", ref: str = "") -> None:
        if not isinstance(value, str):
            raise TypeError("SecureCredential value must be str")
        self._value = value
        self._source = source
        self._ref = ref

    def reveal(self) -> str:
        """Return the underlying credential value. Use sparingly."""
        return self._value

    @property
    def source(self) -> str:
        """The resolver source that produced this credential (env, op, vault, aws-sm)."""
        return self._source

    @property
    def ref(self) -> str:
        """The reference used to fetch this credential (env var name, vault path, etc)."""
        return self._ref

    def __repr__(self) -> str:
        return f"SecureCredential(source={self._source!r}, ref={self._ref!r}, value=[REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __format__(self, format_spec: str) -> str:
        return "[REDACTED]"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SecureCredential):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(("SecureCredential", self._value))

    def __reduce__(self) -> Any:
        raise TypeError("SecureCredential refuses pickling to prevent credential persistence")

    def __getstate__(self) -> Any:
        raise TypeError("SecureCredential refuses pickling to prevent credential persistence")
