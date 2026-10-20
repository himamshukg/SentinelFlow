"""Gateway must consult policy before any mock tool runs."""

import pytest

from sentinelflow.audit import AuditStorageError
from sentinelflow.gateway import (
    AuditPreExecutionError,
    SentinelGateway,
    execute_proposed_action,
)
from sentinelflow.policy import Decision
from sentinelflow.tools import MockToolRunner


def test_allowed_read_runs_mock_not_disk():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    result = execute_proposed_action(
        "read_file",
        {"path": "/workspace/docs/readme.md"},
        "docs_agent",
        gateway=gateway,
    )

    assert result.policy.decision is Decision.ALLOW
    assert result.executed is True
    assert result.execution_success is True
    assert result.output["status"] == "ok"
    assert "mock filesystem" in result.output["content"]
    assert gateway.audit_log[-1].executed is True
    assert gateway.audit_log[-1].execution_success is True


def test_blocked_action_does_not_run_tool():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    result = gateway.handle(
        "send_email",
        {"to": "alice@company.com", "subject": "Hi", "body": "x"},
        "docs_agent",
    )

    assert result.policy.decision is Decision.BLOCK
    assert result.executed is False
    assert result.output is None
    assert tools.sent_emails == []


def test_unknown_tool_is_not_executed():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    result = gateway.handle("shell_exec", {"command": "echo hi"}, "docs_agent")

    assert result.policy.rule_id == "DENY_UNKNOWN_ACTION"
    assert result.executed is False


def test_malformed_arguments_are_rejected_and_audited():
    gateway = SentinelGateway()
    result = execute_proposed_action("read_file", None, "docs_agent", gateway=gateway)
    assert result.policy.rule_id == "DENY_MALFORMED_REQUEST"
    assert result.executed is False
    assert len(gateway.audit_log) == 1
    assert gateway.audit_log[0].execution_success is False


def test_require_approval_does_not_execute_until_approved():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    held = gateway.handle(
        "delete_file",
        {"path": "/workspace/tmp/cache.bin"},
        "ops_agent",
    )

    assert held.policy.decision is Decision.REQUIRE_APPROVAL
    assert held.executed is False
    assert held.pending is True
    assert "/workspace/tmp/cache.bin" in tools.files
    assert tools.deleted_paths == []

    approved = gateway.approve(held.request_id)

    assert approved.executed is True
    assert approved.output["status"] == "deleted_mock"
    assert "/workspace/tmp/cache.bin" not in tools.files
    assert gateway.pending_requests() == []


def test_deny_pending_does_not_execute():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    held = gateway.handle(
        "send_email",
        {
            "to": "eve@outside.test",
            "subject": "Hello",
            "body": "Hi",
        },
        "mail_agent",
    )
    denied = gateway.deny(held.request_id)

    assert denied.executed is False
    assert denied.policy.rule_id == "DENY_HUMAN_REJECTED"
    assert tools.sent_emails == []
    assert gateway.pending_requests() == []


def test_allowed_email_and_transfer_are_mocks_only():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    mail = gateway.handle(
        "send_email",
        {"to": "alice@company.com", "subject": "Status", "body": "All good"},
        "mail_agent",
    )
    money = gateway.handle(
        "transfer_funds",
        {"amount": 250, "to_account": "ACC-100"},
        "finance_agent",
    )

    assert mail.executed is True
    assert money.executed is True
    assert tools.sent_emails[0]["to"] == "alice@company.com"
    assert tools.transfers[0]["amount"] == 250


def test_approve_unknown_id_is_blocked():
    gateway = SentinelGateway()
    result = gateway.approve("req-missing")
    assert result.executed is False
    assert result.policy.rule_id == "DENY_UNKNOWN_PENDING"


def test_failed_tool_is_not_logged_as_success():
    tools = MockToolRunner()
    tools.fail_on("read_file")
    gateway = SentinelGateway(tools=tools)

    result = execute_proposed_action(
        "read_file",
        {"path": "/workspace/docs/readme.md"},
        "docs_agent",
        gateway=gateway,
    )

    assert result.policy.decision is Decision.ALLOW
    assert result.executed is False
    assert result.execution_success is False
    assert result.error is not None
    event = gateway.audit_log[-1]
    assert event.executed is False
    assert event.execution_success is False
    assert event.error is not None
    assert event.decision == "ALLOW"
    assert event.event == "handle"
    assert event.error == "Mock tool execution failed."


def test_initial_audit_failure_prevents_execution():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    def fail_append(_event):
        raise AuditStorageError("database details must stay private")

    gateway.audit_log.append_with_id = fail_append  # type: ignore[method-assign]
    with pytest.raises(AuditPreExecutionError):
        gateway.handle(
            "send_email",
            {"to": "alice@company.com", "subject": "Hello", "body": "synthetic"},
            "mail_agent",
        )

    assert tools.sent_emails == []


def test_final_audit_failure_reports_action_was_executed():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)

    def fail_update(*_args, **_kwargs):
        raise AuditStorageError("private sqlite path")

    gateway.audit_log.update_execution = fail_update  # type: ignore[method-assign]
    result = gateway.handle(
        "send_email",
        {"to": "alice@company.com", "subject": "Hello", "body": "synthetic"},
        "mail_agent",
    )

    assert result.executed is True
    assert result.execution_success is True
    assert result.audit_integrity_error is True
    assert "may have run" in result.error
    assert len(tools.sent_emails) == 1
    assert gateway.audit_log[0].event == "execution_started"
    assert gateway.audit_log[0].executed is False


def test_approval_pre_audit_failure_keeps_request_pending_and_unexecuted():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)
    held = gateway.handle(
        "send_email",
        {"to": "eve@outside.test", "subject": "Review", "body": "synthetic"},
        "mail_agent",
    )
    original_append = gateway.audit_log.append_with_id

    def fail_append(_event):
        raise AuditStorageError("private sqlite path")

    gateway.audit_log.append_with_id = fail_append  # type: ignore[method-assign]
    with pytest.raises(AuditPreExecutionError):
        gateway.approve(held.request_id)
    assert gateway.pending_requests()[0]["request_id"] == held.request_id
    assert tools.sent_emails == []

    gateway.audit_log.append_with_id = original_append  # type: ignore[method-assign]
    approved = gateway.approve(held.request_id)
    assert approved.executed is True
    assert len(tools.sent_emails) == 1


def test_every_attempt_writes_an_audit_event():
    gateway = SentinelGateway()
    execute_proposed_action(
        "read_file",
        {"path": "/workspace/docs/readme.md"},
        "docs_agent",
        gateway=gateway,
    )
    execute_proposed_action(
        "read_file",
        {"path": "/etc/passwd"},
        "docs_agent",
        gateway=gateway,
    )
    execute_proposed_action(
        "run_shell",
        {"cmd": "id"},
        "docs_agent",
        gateway=gateway,
    )
    assert len(gateway.audit_log) == 3
    assert [event.decision for event in gateway.audit_log] == [
        "ALLOW",
        "BLOCK",
        "BLOCK",
    ]


def test_prefix_sibling_path_is_not_treated_as_allowed():
    """Regression: /workspace/docs-leaked must not match /workspace/docs."""

    result = execute_proposed_action(
        "read_file",
        {"path": "/workspace/docs-leaked/secrets.md"},
        "docs_agent",
    )
    assert result.policy.rule_id == "DENY_PATH_NOT_ALLOWED"
    assert result.executed is False


def test_encoded_path_traversal_is_blocked():
    """Regression: %2e%2e must not bypass the '..' check."""

    result = execute_proposed_action(
        "read_file",
        {"path": "/workspace/docs/%2e%2e/hr/salaries.txt"},
        "docs_agent",
    )
    assert result.policy.rule_id == "DENY_PATH_TRAVERSAL"
    assert result.executed is False


def test_approve_revalidates_and_will_not_run_a_block():
    """Regression: stored approval cannot skip a later BLOCK decision."""

    from sentinelflow.policy import DEFAULT_POLICY
    from copy import deepcopy

    policy = deepcopy(DEFAULT_POLICY)
    gateway = SentinelGateway(policy=policy)
    held = gateway.handle(
        "transfer_funds",
        {"amount": 2500.0, "to_account": "ACC-200"},
        "finance_agent",
    )
    assert held.pending is True

    gateway.engine._policy["transfer_funds"]["agents"] = {}
    result = gateway.approve(held.request_id)
    assert result.executed is False
    assert result.policy.decision is Decision.BLOCK
    assert gateway.tools.transfers == []
