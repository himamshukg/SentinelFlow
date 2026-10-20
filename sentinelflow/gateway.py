"""Secure execution pipeline: policy first, mock tools second.

Callers (frontend or an AI agent) only *propose* work. This module
authorizes in the backend immediately before any mock runs.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sentinelflow.audit import AuditEvent, AuditLog
from sentinelflow.policy import Decision, PolicyEngine, PolicyResult
from sentinelflow.tools import MockToolRunner

AUDIT_FINALIZATION_ERROR = (
    "Audit integrity failure: the simulated action may have run, but its final "
    "outcome could not be saved. Check the audit log before retrying."
)


class AuditPreExecutionError(RuntimeError):
    """Raised when an ALLOW action could not be recorded before execution."""


@dataclass(frozen=True)
class GatewayResult:
    """What happened after one proposed (or approved) action."""

    request_id: str
    policy: PolicyResult
    executed: bool
    output: dict[str, Any] | None
    pending: bool = False
    execution_success: bool = False
    error: str | None = None
    audit_integrity_error: bool = False


@dataclass
class _Pending:
    request_id: str
    action: str
    arguments: dict[str, Any]
    agent_id: str
    policy: PolicyResult


def execute_proposed_action(
    action: str,
    arguments: Mapping[str, Any] | None,
    agent_id: str,
    *,
    gateway: SentinelGateway | None = None,
) -> GatewayResult:
    """Central pipeline entry: validate → policy → maybe mock-execute.

    Steps:
        1. Receive the proposed action, arguments, and agent identity.
        2. The policy engine validates arguments and looks up permissions.
        3. Execute the mock tool only when the decision is ALLOW.
        4. BLOCK and REQUIRE_APPROVAL never run a tool.
        5. Always write a structured audit event.

    Pass an existing gateway to keep one mock filesystem and audit log.
    """

    runner = gateway if gateway is not None else SentinelGateway()
    return runner.handle(action, arguments, agent_id)


class SentinelGateway:
    """Single backend entry point for agent tool calls."""

    def __init__(
        self,
        policy: Mapping[str, Any] | None = None,
        tools: MockToolRunner | None = None,
        audit_db_path: str | Path | None = None,
    ) -> None:
        self.engine = PolicyEngine(policy)
        self.tools = tools if tools is not None else MockToolRunner()
        self.audit_log = AuditLog(audit_db_path)
        self._pending: dict[str, _Pending] = {}
        self._next_id = 1

    def handle(
        self,
        action: str,
        arguments: Mapping[str, Any] | None,
        agent_id: str,
    ) -> GatewayResult:
        """Evaluate policy, then execute only on ALLOW."""

        args = dict(arguments) if isinstance(arguments, Mapping) else arguments
        policy = self.engine.evaluate(action, args, agent_id)
        request_id = self._new_id()

        if policy.decision is Decision.ALLOW:
            return self._execute_allowed(request_id, action, args, agent_id, policy)

        if policy.decision is Decision.REQUIRE_APPROVAL:
            stored_args = deepcopy(dict(args)) if isinstance(args, Mapping) else {}
            result = GatewayResult(
                request_id=request_id,
                policy=policy,
                executed=False,
                output=None,
                pending=True,
                execution_success=False,
            )
            self._record(result, action, args, agent_id, event="handle")
            self._pending[request_id] = _Pending(
                request_id=request_id,
                action=action,
                arguments=stored_args,
                agent_id=agent_id,
                policy=policy,
            )
            return result

        result = GatewayResult(
            request_id=request_id,
            policy=policy,
            executed=False,
            output=None,
            execution_success=False,
        )
        self._record(result, action, args, agent_id, event="handle")
        return result

    def approve(self, request_id: str) -> GatewayResult:
        """Human override after REQUIRE_APPROVAL.

        Arguments and agent permission are checked again. Approval does not
        skip validation, and it cannot run a request the engine now BLOCKs.
        """

        pending = self._pending.pop(request_id, None)
        if pending is None:
            missing = PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_UNKNOWN_PENDING",
                reason=f"No pending request '{request_id}'.",
            )
            result = GatewayResult(
                request_id=request_id,
                policy=missing,
                executed=False,
                output=None,
            )
            self._record(result, None, None, None, event="approve")
            return result

        fresh = self.engine.evaluate(
            pending.action,
            pending.arguments,
            pending.agent_id,
        )
        if fresh.decision is Decision.BLOCK:
            result = GatewayResult(
                request_id=request_id,
                policy=fresh,
                executed=False,
                output=None,
            )
            try:
                self._record(
                    result,
                    pending.action,
                    pending.arguments,
                    pending.agent_id,
                    event="approve",
                )
            except Exception:
                self._pending[request_id] = pending
                raise
            return result

        try:
            result = self._execute_allowed(
                request_id,
                pending.action,
                pending.arguments,
                pending.agent_id,
                pending.policy,
                event="approve",
            )
        except AuditPreExecutionError:
            # The approval was atomically claimed; restore it only when we
            # know execution never began due to the failed pre-audit write.
            self._pending[request_id] = pending
            raise
        # Once execution is attempted, consume the approval even if the final
        # audit update fails, preventing an approval retry from running twice.
        return result

    def deny(self, request_id: str) -> GatewayResult:
        """Human override: drop a pending request without executing."""

        pending = self._pending.pop(request_id, None)
        if pending is None:
            missing = PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_UNKNOWN_PENDING",
                reason=f"No pending request '{request_id}'.",
            )
            result = GatewayResult(
                request_id=request_id,
                policy=missing,
                executed=False,
                output=None,
            )
            self._record(result, None, None, None, event="deny")
            return result

        denied = PolicyResult(
            decision=Decision.BLOCK,
            rule_id="DENY_HUMAN_REJECTED",
            reason=f"Pending '{pending.action}' was denied by a human.",
        )
        result = GatewayResult(
            request_id=request_id,
            policy=denied,
            executed=False,
            output=None,
        )
        try:
            self._record(
                result,
                pending.action,
                pending.arguments,
                pending.agent_id,
                event="deny",
            )
        except Exception:
            self._pending[request_id] = pending
            raise
        return result

    def pending_requests(self) -> list[dict[str, Any]]:
        """Snapshot of requests waiting for a human."""

        return [
            {
                "request_id": item.request_id,
                "action": item.action,
                "arguments": deepcopy(item.arguments),
                "agent_id": item.agent_id,
                "rule_id": item.policy.rule_id,
                "reason": item.policy.reason,
            }
            for item in self._pending.values()
        ]

    def _execute_allowed(
        self,
        request_id: str,
        action: str,
        arguments: Any,
        agent_id: str,
        policy: PolicyResult,
        event: str = "handle",
    ) -> GatewayResult:
        """Run a mock only after policy has already said the action may proceed."""

        started = GatewayResult(
            request_id=request_id,
            policy=policy,
            executed=False,
            output=None,
            execution_success=False,
        )
        try:
            audit_id = self._record(
                started,
                action,
                arguments,
                agent_id,
                event="execution_started",
                return_id=True,
            )
            assert isinstance(audit_id, int)
        except Exception as exc:
            # Fail closed: the executor must never be reached if the durable
            # pre-execution record cannot be committed.
            raise AuditPreExecutionError(
                "The action was not executed because its audit record could not be saved."
            ) from exc

        try:
            output = self.tools.run(action, dict(arguments))
        except Exception:
            result = GatewayResult(
                request_id=request_id,
                policy=policy,
                executed=False,
                output=None,
                execution_success=False,
                error="Mock tool execution failed.",
            )
            return self._finish_execution(audit_id, result, event)

        result = GatewayResult(
            request_id=request_id,
            policy=policy,
            executed=True,
            output=output,
            execution_success=True,
        )
        return self._finish_execution(audit_id, result, event)

    def _finish_execution(
        self, audit_id: int, result: GatewayResult, event: str
    ) -> GatewayResult:
        try:
            self.audit_log.update_execution(
                audit_id,
                event=event,
                executed=result.executed,
                execution_success=result.execution_success,
                pending=result.pending,
                error=result.error,
            )
        except Exception:
            return GatewayResult(
                request_id=result.request_id,
                policy=result.policy,
                executed=result.executed,
                output=result.output,
                pending=result.pending,
                execution_success=result.execution_success,
                error=AUDIT_FINALIZATION_ERROR,
                audit_integrity_error=True,
            )
        return result

    def _new_id(self) -> str:
        request_id = f"req-{self._next_id}"
        self._next_id += 1
        return request_id

    def _record(
        self,
        result: GatewayResult,
        action: str | None,
        arguments: Any,
        agent_id: str | None,
        event: str,
        return_id: bool = False,
    ) -> int | None:
        record = AuditEvent(
            request_id=result.request_id,
            event=event,
            action=action,
            arguments=deepcopy(arguments),
            agent_id=agent_id,
            decision=result.policy.decision.value,
            rule_id=result.policy.rule_id,
            reason=result.policy.reason,
            executed=result.executed,
            execution_success=result.execution_success,
            pending=result.pending,
            error=result.error,
        )
        if return_id:
            return self.audit_log.append_with_id(record)
        self.audit_log.append(record)
        return None
