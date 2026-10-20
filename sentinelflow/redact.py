"""Strip secrets and file contents before data leaves the API."""

from __future__ import annotations

from typing import Any

REDACT_KEYS = {"body", "content"}
REDACT_IDENTIFIER_KEYS = {"path", "to", "toaccount", "amount", "subject"}
SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "credential",
)
SENSITIVE_KEY_NAMES = {"apikey", "privatekey", "signingkey"}
MAX_PUBLIC_STRING = 500


def _normalize_key(key: Any) -> str:
    return "".join(char for char in str(key).casefold() if char.isalnum())


def _is_sensitive_key(key: Any) -> bool:
    """Recognize common separator and camel-case variants of secret fields."""

    normalized = _normalize_key(key)
    return (
        normalized in REDACT_KEYS
        or normalized in SENSITIVE_KEY_NAMES
        or any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)
    )


def redact_value(value: Any, *, redact_identifiers: bool = False) -> Any:
    """Copy nested data, replacing sensitive values and truncating long strings.

    Identifier-like arguments remain visible in fixed synthetic scenarios so
    the simulator can submit those examples. They are redacted in audit and
    execution responses, where the values may come from real callers.
    """

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(key) or (
                redact_identifiers and _normalize_key(key) in REDACT_IDENTIFIER_KEYS
            ):
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = redact_value(inner, redact_identifiers=redact_identifiers)
        return cleaned
    if isinstance(value, list):
        return [redact_value(item, redact_identifiers=redact_identifiers) for item in value[:50]]
    if isinstance(value, str) and len(value) > MAX_PUBLIC_STRING:
        return value[:MAX_PUBLIC_STRING] + "…"
    return value
