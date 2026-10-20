"""SentinelFlow: an AI agent security gateway."""

__version__ = "0.1.0"

from sentinelflow.audit import AuditEvent, AuditLog
from sentinelflow.gateway import GatewayResult, SentinelGateway, execute_proposed_action
from sentinelflow.policy import (
    DEFAULT_POLICY,
    Decision,
    PolicyEngine,
    PolicyResult,
    evaluate_action,
)
from sentinelflow.tools import DUMMY_FILES, MockToolRunner, ToolExecutionError

__all__ = [
    "DEFAULT_POLICY",
    "DUMMY_FILES",
    "AuditEvent",
    "AuditLog",
    "Decision",
    "GatewayResult",
    "MockToolRunner",
    "PolicyEngine",
    "PolicyResult",
    "SentinelGateway",
    "ToolExecutionError",
    "evaluate_action",
    "execute_proposed_action",
]
