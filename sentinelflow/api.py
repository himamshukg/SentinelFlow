"""HTTP API. Authorization is never taken from the client."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinelflow import __version__
from sentinelflow.gateway import (
    AUDIT_FINALIZATION_ERROR,
    AuditPreExecutionError,
    SentinelGateway,
    execute_proposed_action,
)
from sentinelflow.redact import redact_value
from sentinelflow.scenarios import SCENARIOS
from sentinelflow.schemas import (
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
    AgentIdentityResponse,
    PendingRequestsResponse,
)
from sentinelflow.settings import ApiSettings

ALLOWED_DECISIONS = {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}
MAX_ACTION_QUERY = 64


class LimitBodySizeMiddleware:
    """Bound request buffering before passing a body to FastAPI."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                await _error("invalid_request", "Content-Length is invalid.", 400)(
                    scope, receive, send
                )
                return
            if length > self.max_body_bytes:
                await _error("payload_too_large", "Request body is too large.", 413)(
                    scope, receive, send
                )
                return

        # Content-Length is optional (for example, chunked requests). Read the
        # body in ASGI chunks and stop as soon as it crosses the configured cap.
        # At most the permitted body plus the current ASGI chunk is buffered.
        messages: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            total += len(message.get("body", b""))
            if total > self.max_body_bytes:
                await _error("payload_too_large", "Request body is too large.", 413)(
                    scope, receive, send
                )
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)


def _error(
    code: str,
    message: str,
    status_code: int,
    details: list[dict[str, str]] | None = None,
) -> JSONResponse:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return JSONResponse(payload, status_code=status_code)


def _public_execution_error(
    error: str | None, *, audit_integrity_error: bool = False
) -> str | None:
    """Do not expose raw executor exception text over the API."""

    if audit_integrity_error:
        return AUDIT_FINALIZATION_ERROR
    return "Mock tool execution failed." if error is not None else None


def create_app(
    *,
    gateway: SentinelGateway | None = None,
    settings: ApiSettings | None = None,
) -> FastAPI:
    """Build the API. Tests pass a fresh gateway so logs stay isolated."""

    config = settings if settings is not None else ApiSettings()
    app = FastAPI(
        title="SentinelFlow",
        version=__version__,
        description="AI Agent Security Gateway",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.gateway = (
        gateway
        if gateway is not None
        else SentinelGateway(audit_db_path=config.audit_db_path)
    )
    app.state.settings = config

    app.add_middleware(LimitBodySizeMiddleware, max_body_bytes=config.max_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept", "Authorization", "X-Approval-Token"],
        allow_origin_regex=None,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = []
        for err in exc.errors():
            location = ".".join(str(part) for part in err.get("loc", ()) if part != "body")
            details.append(
                {
                    "field": location or "body",
                    "message": "This field is invalid.",
                }
            )
        return _error(
            "validation_error",
            "Request is invalid.",
            422,
            details=details,
        )

    @app.exception_handler(Exception)
    async def unexpected_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return _error("internal_error", "An unexpected error occurred.", 500)

    def authenticate_agent(authorization: str | None) -> str | JSONResponse:
        """Resolve a bearer credential to its server-configured agent identity."""

        if not config.agent_tokens:
            return _error(
                "authentication_unavailable",
                "Agent credentials are not configured on the server.",
                503,
            )
        scheme, separator, credential = (authorization or "").partition(" ")
        if not separator or scheme.lower() != "bearer" or not credential or not credential.isascii():
            return _error("unauthorized", "A valid agent bearer token is required.", 401)
        matched_agent: str | None = None
        for agent_id, expected_token in config.agent_tokens.items():
            if hmac.compare_digest(credential, expected_token):
                matched_agent = agent_id
        if matched_agent is None:
            return _error("unauthorized", "A valid agent bearer token is required.", 401)
        return matched_agent

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.get("/api/scenarios")
    def list_scenarios() -> dict[str, Any]:
        items = []
        for scenario in SCENARIOS:
            items.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "title": scenario.title,
                    "explanation": scenario.explanation,
                    "action": scenario.action,
                    "agent_id": scenario.agent_id,
                    "arguments": redact_value(scenario.arguments),
                    "expected_decision": scenario.expected_decision.value,
                    "expected_executed": scenario.expected_executed,
                    "expected_rule_id": scenario.expected_rule_id,
                }
            )
        return {"scenarios": items}

    @app.get("/api/identity", response_model=AgentIdentityResponse)
    def get_authenticated_identity(
        authorization: str | None = Header(default=None),
    ) -> AgentIdentityResponse | JSONResponse:
        """Return only the identity mapped to the supplied bearer credential."""

        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent
        return AgentIdentityResponse(agent_id=authenticated_agent)

    @app.post("/api/evaluate", response_model=EvaluateResponse)
    def evaluate(
        payload: EvaluateRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> EvaluateResponse | JSONResponse:
        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent
        # The JSON identity is only a consistency check. The authenticated,
        # server-mapped identity is passed to policy and the executor.
        if payload.agent_id != authenticated_agent:
            return _error(
                "agent_identity_mismatch",
                "The authenticated credential does not match the requested agent.",
                403,
            )
        try:
            result = execute_proposed_action(
                payload.action,
                payload.arguments,
                authenticated_agent,
                gateway=request.app.state.gateway,
            )
        except AuditPreExecutionError:
            return _error(
                "audit_unavailable",
                "The action was not executed because its pre-execution audit record could not be saved.",
                503,
            )
        output = result.output
        if isinstance(output, dict):
            output = redact_value(output, redact_identifiers=True)
        return EvaluateResponse(
            request_id=result.request_id,
            decision=result.policy.decision.value,
            rule_id=result.policy.rule_id,
            reason=result.policy.reason,
            executed=result.executed,
            execution_success=result.execution_success,
            pending=result.pending,
            error=_public_execution_error(
                result.error, audit_integrity_error=result.audit_integrity_error
            ),
            output=output,
            audit_integrity_error=result.audit_integrity_error,
        )

    @app.get("/api/events")
    def list_events(
        request: Request,
        authorization: str | None = Header(default=None),
        decision: str | None = Query(default=None, max_length=32),
        action: str | None = Query(default=None, max_length=MAX_ACTION_QUERY),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent  # type: ignore[return-value]
        if decision is not None:
            decision = decision.strip().upper()
            if decision not in ALLOWED_DECISIONS:
                return _error(  # type: ignore[return-value]
                    "invalid_query",
                    "decision must be ALLOW, BLOCK, or REQUIRE_APPROVAL.",
                    400,
                )
        if action is not None:
            action = action.strip()
        events = request.app.state.gateway.audit_log.recent(
            decision=decision,
            action=action,
            agent_id=authenticated_agent,
            limit=limit,
        )
        public = []
        for event in events:
            public.append(
                {
                    "request_id": event.request_id,
                    "event": event.event,
                    "action": event.action,
                    "arguments": redact_value(event.arguments, redact_identifiers=True),
                    "agent_id": event.agent_id,
                    "decision": event.decision,
                    "rule_id": event.rule_id,
                    "reason": event.reason,
                    "executed": event.executed,
                    "execution_success": event.execution_success,
                    "pending": event.pending,
                    "error": _public_execution_error(event.error),
                    "timestamp": event.timestamp,
                }
            )
        return {"events": public, "count": len(public)}

    def check_approval_authorization(approval_token: str | None) -> JSONResponse | None:
        token = config.approval_token
        if not token or not token.isascii() or any(character.isspace() for character in token):
            return _error(
                "approval_unavailable",
                "HTTP approvals are disabled until SENTINELFLOW_APPROVAL_TOKEN is configured.",
                503,
            )
        supplied = approval_token or ""
        if not supplied.isascii() or not hmac.compare_digest(supplied, token):
            return _error("unauthorized", "A valid approval token is required.", 401)
        return None

    @app.get("/api/pending", response_model=PendingRequestsResponse)
    def list_pending(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any] | JSONResponse:
        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent
        items = [
            item
            for item in request.app.state.gateway.pending_requests()
            if item["agent_id"] == authenticated_agent
        ]
        for item in items:
            item["arguments"] = redact_value(item["arguments"], redact_identifiers=True)
        return {"requests": items, "count": len(items)}

    @app.post("/api/requests/{request_id}/approve", response_model=EvaluateResponse)
    def approve_request(
        request_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
        x_approval_token: str | None = Header(default=None, alias="X-Approval-Token"),
    ) -> EvaluateResponse | JSONResponse:
        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent
        auth_error = check_approval_authorization(x_approval_token)
        if auth_error is not None:
            return auth_error
        pending = next(
            (
                item
                for item in request.app.state.gateway.pending_requests()
                if item["request_id"] == request_id
            ),
            None,
        )
        if pending is not None and pending["agent_id"] != authenticated_agent:
            return _error("not_found", "Pending request was not found.", 404)
        try:
            result = request.app.state.gateway.approve(request_id)
        except AuditPreExecutionError:
            return _error(
                "audit_unavailable",
                "The approved action was not executed because its pre-execution audit record could not be saved.",
                503,
            )
        output = (
            redact_value(result.output, redact_identifiers=True)
            if result.output is not None
            else None
        )
        return EvaluateResponse(
            request_id=result.request_id,
            decision=result.policy.decision.value,
            rule_id=result.policy.rule_id,
            reason=result.policy.reason,
            executed=result.executed,
            execution_success=result.execution_success,
            pending=result.pending,
            error=_public_execution_error(
                result.error, audit_integrity_error=result.audit_integrity_error
            ),
            output=output,
            audit_integrity_error=result.audit_integrity_error,
        )

    @app.post("/api/requests/{request_id}/deny", response_model=EvaluateResponse)
    def deny_request(
        request_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
        x_approval_token: str | None = Header(default=None, alias="X-Approval-Token"),
    ) -> EvaluateResponse | JSONResponse:
        authenticated_agent = authenticate_agent(authorization)
        if isinstance(authenticated_agent, JSONResponse):
            return authenticated_agent
        auth_error = check_approval_authorization(x_approval_token)
        if auth_error is not None:
            return auth_error
        pending = next(
            (
                item
                for item in request.app.state.gateway.pending_requests()
                if item["request_id"] == request_id
            ),
            None,
        )
        if pending is not None and pending["agent_id"] != authenticated_agent:
            return _error("not_found", "Pending request was not found.", 404)
        result = request.app.state.gateway.deny(request_id)
        return EvaluateResponse(
            request_id=result.request_id,
            decision=result.policy.decision.value,
            rule_id=result.policy.rule_id,
            reason=result.policy.reason,
            executed=result.executed,
            execution_success=result.execution_success,
            pending=result.pending,
            error=_public_execution_error(result.error),
            output=None,
        )

    return app


app = create_app()
