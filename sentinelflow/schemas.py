"""Pydantic models for the HTTP API. Extra fields are forbidden."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_ACTION_LEN = 64
MAX_AGENT_LEN = 64
MAX_ARGUMENT_KEYS = 20
MAX_ARGUMENTS_JSON_BYTES = 8192


class EvaluateRequest(BaseModel):
    """A proposed tool call. There is no 'decision' field on purpose."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., min_length=1, max_length=MAX_ACTION_LEN)
    # Keep the wire value intact so the policy engine can classify malformed
    # argument shapes as BLOCK instead of turning them into transport errors.
    arguments: Any = Field(default_factory=dict)
    agent_id: str = Field(..., min_length=1, max_length=MAX_AGENT_LEN)

    @field_validator("action", "agent_id")
    @classmethod
    def must_be_simple_token(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must be a non-empty string")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        if any(char not in allowed for char in cleaned):
            raise ValueError("may only contain letters, digits, underscore, and hyphen")
        return cleaned

    @field_validator("arguments")
    @classmethod
    def arguments_must_stay_small(cls, value: Any) -> Any:
        if isinstance(value, dict) and len(value) > MAX_ARGUMENT_KEYS:
            raise ValueError(f"at most {MAX_ARGUMENT_KEYS} argument keys are allowed")
        encoded = json.dumps(value, default=str)
        if len(encoded.encode("utf-8")) > MAX_ARGUMENTS_JSON_BYTES:
            raise ValueError("arguments are too large")
        return value


class EvaluateResponse(BaseModel):
    request_id: str
    decision: str
    rule_id: str
    reason: str
    executed: bool
    execution_success: bool
    pending: bool
    error: str | None = None
    output: dict[str, Any] | None = None
    audit_integrity_error: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str


class AgentIdentityResponse(BaseModel):
    """Server-resolved identity for the credential on this request."""

    agent_id: str


class PendingRequestResponse(BaseModel):
    request_id: str
    action: str
    arguments: dict[str, Any]
    agent_id: str
    rule_id: str
    reason: str


class PendingRequestsResponse(BaseModel):
    requests: list[PendingRequestResponse]
    count: int


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[dict[str, str]] | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
