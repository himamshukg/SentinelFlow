"""Deterministic policy engine for proposed agent tool actions.

This module is the source of truth for authorization. An LLM may propose
an action, but it never chooses ALLOW / BLOCK / REQUIRE_APPROVAL.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Any, Mapping

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Decision(str, Enum):
    """The three outcomes the gateway can return."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class PolicyResult:
    """Structured answer from the policy engine.

    Attributes:
        decision: ALLOW, BLOCK, or REQUIRE_APPROVAL.
        rule_id: Stable identifier for the rule that fired.
        reason: Short explanation a human (or auditor) can read.
    """

    decision: Decision
    rule_id: str
    reason: str


# Default rules are explicit data, not model-generated text.
# You can pass a different mapping into PolicyEngine to change behavior.
DEFAULT_POLICY: dict[str, Any] = {
    "read_file": {
        "agents": {
            "docs_agent": {
                "allowed_path_prefixes": ["/workspace/docs"],
            }
        }
    },
    "send_email": {
        "agents": {
            "mail_agent": {
                "internal_domains": ["company.com"],
            }
        }
    },
    "delete_file": {
        "agents": {
            "ops_agent": {
                "allowed_path_prefixes": ["/workspace/tmp"],
            }
        }
    },
    "transfer_funds": {
        "agents": {
            "finance_agent": {
                "max_amount": 10_000.0,
                "approval_threshold": 1_000.0,
            }
        }
    },
}


def evaluate_action(
    action: str,
    arguments: Mapping[str, Any] | None,
    agent_id: str,
    policy: Mapping[str, Any] | None = None,
) -> PolicyResult:
    """Decide whether a proposed tool call may proceed.

    Parameters:
        action: Name of the tool the agent wants to use.
        arguments: Key/value inputs for that tool.
        agent_id: Who is asking (a string identity, not a model).
        policy: Optional custom rules. Defaults to DEFAULT_POLICY.

    Returns:
        A PolicyResult. Unknown tools and bad input are blocked.
    """

    engine = PolicyEngine(policy)
    return engine.evaluate(action, arguments, agent_id)


class PolicyEngine:
    """Looks up rules and validates arguments. No side effects."""

    def __init__(self, policy: Mapping[str, Any] | None = None) -> None:
        # Deep copy so later edits to nested lists cannot change live rules.
        source = policy if policy is not None else DEFAULT_POLICY
        self._policy = deepcopy(dict(source))

    def evaluate(
        self,
        action: Any,
        arguments: Any,
        agent_id: Any,
    ) -> PolicyResult:
        """Run every check in a fixed order. First failure wins."""

        malformed = self._reject_malformed(action, arguments, agent_id)
        if malformed is not None:
            return malformed

        handler = {
            "read_file": self._evaluate_read_file,
            "send_email": self._evaluate_send_email,
            "delete_file": self._evaluate_delete_file,
            "transfer_funds": self._evaluate_transfer_funds,
        }.get(action)

        if handler is None:
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_UNKNOWN_ACTION",
                reason="Unknown actions are blocked by default.",
            )

        agent_rules = self._agent_rules_for(action, agent_id)
        if agent_rules is None:
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_AGENT_NOT_PERMITTED",
                reason="This agent is not permitted to call the requested action.",
            )

        return handler(arguments, agent_id, agent_rules)

    def _reject_malformed(
        self,
        action: Any,
        arguments: Any,
        agent_id: Any,
    ) -> PolicyResult | None:
        """Block requests that are not a named action + dict + identity."""

        if not isinstance(action, str) or not action.strip():
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_MALFORMED_REQUEST",
                reason="Action must be a non-empty string.",
            )
        if not isinstance(agent_id, str) or not agent_id.strip():
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_MALFORMED_REQUEST",
                reason="Agent identity must be a non-empty string.",
            )
        if not isinstance(arguments, Mapping):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_MALFORMED_REQUEST",
                reason="Arguments must be a mapping of names to values.",
            )
        return None

    def _agent_rules_for(self, action: str, agent_id: str) -> dict[str, Any] | None:
        """Return this agent's config for an action, or None if missing."""

        action_policy = self._policy.get(action)
        if not isinstance(action_policy, Mapping):
            return None
        agents = action_policy.get("agents")
        if not isinstance(agents, Mapping):
            return None
        rules = agents.get(agent_id)
        if not isinstance(rules, Mapping):
            return None
        return dict(rules)

    def _evaluate_read_file(
        self,
        arguments: Mapping[str, Any],
        agent_id: str,
        rules: Mapping[str, Any],
    ) -> PolicyResult:
        path_result = _require_safe_path(arguments)
        if path_result.decision is Decision.BLOCK:
            return path_result

        path = str(arguments["path"])
        prefixes = _string_list(rules.get("allowed_path_prefixes"))
        if not _path_allowed(path, prefixes):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_PATH_NOT_ALLOWED",
                reason="Requested path is outside this agent's allowed prefixes.",
            )

        return PolicyResult(
            decision=Decision.ALLOW,
            rule_id="ALLOW_READ_FILE",
            reason="This agent may read the requested documentation path.",
        )

    def _evaluate_send_email(
        self,
        arguments: Mapping[str, Any],
        agent_id: str,
        rules: Mapping[str, Any],
    ) -> PolicyResult:
        recipients = _email_recipients(arguments.get("to"))
        if recipients is None:
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="send_email requires 'to' as an email or list of emails.",
            )

        subject = arguments.get("subject")
        body = arguments.get("body")
        if not isinstance(subject, str) or not subject.strip():
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="send_email requires a non-empty string 'subject'.",
            )
        if not isinstance(body, str):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="send_email requires a string 'body'.",
            )

        internal_domains = {
            domain.lower()
            for domain in _string_list(rules.get("internal_domains"))
        }
        external = [
            address
            for address in recipients
            if address.split("@", 1)[1].lower() not in internal_domains
        ]
        if external:
            return PolicyResult(
                decision=Decision.REQUIRE_APPROVAL,
                rule_id="APPROVE_EXTERNAL_EMAIL",
                reason="Email to an external recipient requires human approval.",
            )

        return PolicyResult(
            decision=Decision.ALLOW,
            rule_id="ALLOW_INTERNAL_EMAIL",
            reason="This agent may email recipients in the configured internal domain.",
        )

    def _evaluate_delete_file(
        self,
        arguments: Mapping[str, Any],
        agent_id: str,
        rules: Mapping[str, Any],
    ) -> PolicyResult:
        path_result = _require_safe_path(arguments)
        if path_result.decision is Decision.BLOCK:
            return path_result

        path = str(arguments["path"])
        prefixes = _string_list(rules.get("allowed_path_prefixes"))
        if not _path_allowed(path, prefixes):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_PATH_NOT_ALLOWED",
                reason="Requested path is outside this agent's allowed prefixes.",
            )

        # Destructive actions never auto-run, even for permitted agents.
        return PolicyResult(
            decision=Decision.REQUIRE_APPROVAL,
            rule_id="APPROVE_DELETE_FILE",
            reason="Deleting a file requires human approval.",
        )

    def _evaluate_transfer_funds(
        self,
        arguments: Mapping[str, Any],
        agent_id: str,
        rules: Mapping[str, Any],
    ) -> PolicyResult:
        amount = arguments.get("amount")
        if not isinstance(amount, (int, float)) or isinstance(amount, bool):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="transfer_funds requires a numeric 'amount'.",
            )
        if isinstance(amount, float) and not math.isfinite(amount):
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="transfer_funds 'amount' must be a finite number.",
            )
        if amount <= 0:
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="transfer_funds 'amount' must be greater than zero.",
            )

        to_account = arguments.get("to_account")
        if not isinstance(to_account, str) or not to_account.strip():
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_INVALID_ARGUMENTS",
                reason="transfer_funds requires a non-empty string 'to_account'.",
            )

        max_amount = float(rules.get("max_amount", 0))
        approval_threshold = float(rules.get("approval_threshold", 0))

        if amount > max_amount:
            return PolicyResult(
                decision=Decision.BLOCK,
                rule_id="DENY_AMOUNT_EXCEEDS_MAX",
                reason="Transfer exceeds the configured maximum amount.",
            )
        if amount > approval_threshold:
            return PolicyResult(
                decision=Decision.REQUIRE_APPROVAL,
                rule_id="APPROVE_LARGE_TRANSFER",
                reason="Transfer exceeds the approval threshold and needs human approval.",
            )

        return PolicyResult(
            decision=Decision.ALLOW,
            rule_id="ALLOW_TRANSFER_FUNDS",
            reason="This agent may transfer within the configured limit.",
        )


def _require_safe_path(arguments: Mapping[str, Any]) -> PolicyResult:
    """Shared checks for read_file and delete_file path arguments."""

    path = arguments.get("path")
    if not isinstance(path, str) or not path.strip():
        return PolicyResult(
            decision=Decision.BLOCK,
            rule_id="DENY_INVALID_ARGUMENTS",
            reason="A non-empty string 'path' is required.",
        )
    if "\x00" in path:
        return PolicyResult(
            decision=Decision.BLOCK,
            rule_id="DENY_INVALID_ARGUMENTS",
            reason="Path contains a null byte.",
        )
    decoded = _decode_dotted_path(path)
    if ".." in decoded.replace("\\", "/").split("/"):
        return PolicyResult(
            decision=Decision.BLOCK,
            rule_id="DENY_PATH_TRAVERSAL",
            reason="Path traversal ('..') is not allowed.",
        )
    if not path.startswith("/"):
        return PolicyResult(
            decision=Decision.BLOCK,
            rule_id="DENY_INVALID_ARGUMENTS",
            reason="Path must be absolute (start with '/').",
        )
    return PolicyResult(
        decision=Decision.ALLOW,
        rule_id="PATH_OK",
        reason="Path passed validation.",
    )


def _decode_dotted_path(path: str) -> str:
    """Turn encoded dots such as %2e into '.' so traversal cannot hide."""

    text = path.replace("\\", "/")
    lowered = text.replace("%2E", "%2e")
    while "%2e" in lowered:
        lowered = lowered.replace("%2e", ".")
    return lowered


def _path_allowed(path: str, prefixes: list[str]) -> bool:
    """True if path equals a prefix or is nested under one."""

    normalized = path.rstrip("/") or "/"
    for prefix in prefixes:
        clean_prefix = prefix.rstrip("/") or "/"
        if normalized == clean_prefix or normalized.startswith(clean_prefix + "/"):
            return True
    return False


def _string_list(value: Any) -> list[str]:
    """Turn a config list into strings; ignore anything else."""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _email_recipients(value: Any) -> list[str] | None:
    """Parse one email or a list of emails. None means invalid."""

    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        return None

    recipients: list[str] = []
    for item in candidates:
        if not isinstance(item, str) or not EMAIL_PATTERN.match(item.strip()):
            return None
        recipients.append(item.strip())
    if not recipients:
        return None
    return recipients
