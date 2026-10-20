"""Environment-backed API settings. No secrets are stored here."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Mapping

from sentinelflow.audit import resolve_audit_db_path

MIN_AGENT_TOKEN_LENGTH = 32
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _parse_origins(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _parse_agent_tokens(raw: str) -> dict[str, str]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("SENTINELFLOW_AGENT_TOKENS must be a JSON object.") from exc
    if not isinstance(value, dict):
        raise ValueError("SENTINELFLOW_AGENT_TOKENS must be a JSON object.")
    if any(not isinstance(agent_id, str) or not isinstance(token, str) for agent_id, token in value.items()):
        raise ValueError("SENTINELFLOW_AGENT_TOKENS must map agent IDs to token strings.")
    return value


def _validate_agent_tokens(tokens: Mapping[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    for agent_id, token in tokens.items():
        if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
            raise ValueError("Agent token configuration contains an invalid agent ID.")
        if not isinstance(token, str) or len(token) < MIN_AGENT_TOKEN_LENGTH:
            raise ValueError("Each configured agent token must be at least 32 characters.")
        if not token.isascii() or any(character.isspace() for character in token):
            raise ValueError("Configured agent tokens must be ASCII and contain no whitespace.")
        validated[agent_id] = token
    if len(set(validated.values())) != len(validated):
        raise ValueError("Each configured agent must have a unique token.")
    return validated


class ApiSettings:
    """API CORS, request-size, agent identity, and approval access settings."""

    def __init__(
        self,
        *,
        environment: str | None = None,
        cors_origins: list[str] | None = None,
        max_body_bytes: int | None = None,
        approval_token: str | None = None,
        audit_db_path: str | Path | None = None,
        agent_tokens: Mapping[str, str] | None = None,
    ) -> None:
        self.environment = (
            environment
            if environment is not None
            else os.getenv("SENTINELFLOW_ENV", "development")
        ).lower()
        if cors_origins is not None:
            self.cors_origins = cors_origins
        else:
            raw = os.getenv("SENTINELFLOW_CORS_ORIGINS", "")
            if raw.strip():
                self.cors_origins = _parse_origins(raw)
            elif self.environment == "production":
                # Never fall back to "*" in production.
                self.cors_origins = []
            else:
                self.cors_origins = [
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                ]
        if "*" in self.cors_origins and self.environment == "production":
            self.cors_origins = [origin for origin in self.cors_origins if origin != "*"]
        self.max_body_bytes = (
            max_body_bytes
            if max_body_bytes is not None
            else int(os.getenv("SENTINELFLOW_MAX_BODY_BYTES", "16384"))
        )
        self.approval_token = (
            approval_token
            if approval_token is not None
            else os.getenv("SENTINELFLOW_APPROVAL_TOKEN")
        )
        if agent_tokens is not None:
            configured_tokens = dict(agent_tokens)
        else:
            raw_tokens = os.getenv("SENTINELFLOW_AGENT_TOKENS", "").strip()
            configured_tokens = _parse_agent_tokens(raw_tokens) if raw_tokens else {}
        self.agent_tokens = _validate_agent_tokens(configured_tokens)
        self.audit_db_path = resolve_audit_db_path(audit_db_path)
