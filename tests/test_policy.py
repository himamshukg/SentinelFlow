"""Tests for the deterministic policy engine."""

from copy import deepcopy

from sentinelflow.policy import DEFAULT_POLICY, Decision, PolicyEngine, evaluate_action


def test_permitted_read_file_is_allowed():
    result = evaluate_action(
        "read_file",
        {"path": "/workspace/docs/readme.md"},
        "docs_agent",
    )
    assert result.decision is Decision.ALLOW
    assert result.rule_id == "ALLOW_READ_FILE"


def test_permitted_internal_email_is_allowed():
    result = evaluate_action(
        "send_email",
        {
            "to": "alice@company.com",
            "subject": "Status",
            "body": "All good",
        },
        "mail_agent",
    )
    assert result.decision is Decision.ALLOW
    assert result.rule_id == "ALLOW_INTERNAL_EMAIL"


def test_permitted_small_transfer_is_allowed():
    result = evaluate_action(
        "transfer_funds",
        {"amount": 250, "to_account": "ACC-100"},
        "finance_agent",
    )
    assert result.decision is Decision.ALLOW
    assert result.rule_id == "ALLOW_TRANSFER_FUNDS"


def test_forbidden_agent_cannot_read_file():
    result = evaluate_action(
        "read_file",
        {"path": "/workspace/docs/readme.md"},
        "mail_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_AGENT_NOT_PERMITTED"


def test_forbidden_path_is_blocked():
    result = evaluate_action(
        "read_file",
        {"path": "/etc/passwd"},
        "docs_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_PATH_NOT_ALLOWED"


def test_delete_file_requires_approval_even_when_permitted():
    result = evaluate_action(
        "delete_file",
        {"path": "/workspace/tmp/cache.bin"},
        "ops_agent",
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.rule_id == "APPROVE_DELETE_FILE"


def test_external_email_requires_approval():
    result = evaluate_action(
        "send_email",
        {
            "to": ["bob@company.com", "eve@outside.test"],
            "subject": "Hello",
            "body": "Hi",
        },
        "mail_agent",
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.rule_id == "APPROVE_EXTERNAL_EMAIL"


def test_large_transfer_requires_approval():
    result = evaluate_action(
        "transfer_funds",
        {"amount": 2500.0, "to_account": "ACC-200"},
        "finance_agent",
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.rule_id == "APPROVE_LARGE_TRANSFER"


def test_transfer_above_max_is_blocked():
    result = evaluate_action(
        "transfer_funds",
        {"amount": 50_000, "to_account": "ACC-200"},
        "finance_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_AMOUNT_EXCEEDS_MAX"


def test_invalid_missing_path_is_blocked():
    result = evaluate_action("read_file", {}, "docs_agent")
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_INVALID_ARGUMENTS"


def test_invalid_path_traversal_is_blocked():
    result = evaluate_action(
        "read_file",
        {"path": "/workspace/docs/../secrets.txt"},
        "docs_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_PATH_TRAVERSAL"


def test_invalid_email_arguments_are_blocked():
    result = evaluate_action(
        "send_email",
        {"to": "not-an-email", "subject": "Hi", "body": ""},
        "mail_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_INVALID_ARGUMENTS"


def test_invalid_transfer_amount_is_blocked():
    result = evaluate_action(
        "transfer_funds",
        {"amount": "100", "to_account": "ACC-1"},
        "finance_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_INVALID_ARGUMENTS"


def test_malformed_arguments_are_blocked():
    result = evaluate_action("read_file", None, "docs_agent")
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_MALFORMED_REQUEST"


def test_unknown_tool_is_blocked():
    result = evaluate_action(
        "shell_exec",
        {"command": "rm -rf /"},
        "docs_agent",
    )
    assert result.decision is Decision.BLOCK
    assert result.rule_id == "DENY_UNKNOWN_ACTION"
    assert "Unknown action" in result.reason


def test_custom_policy_can_grant_a_new_agent():
    custom_policy = {
        "read_file": {
            "agents": {
                "intern_agent": {
                    "allowed_path_prefixes": ["/workspace/docs/public"],
                }
            }
        }
    }
    result = evaluate_action(
        "read_file",
        {"path": "/workspace/docs/public/faq.md"},
        "intern_agent",
        policy=custom_policy,
    )
    assert result.decision is Decision.ALLOW


def test_mutating_shared_policy_lists_does_not_change_default_engine():
    """Regression: nested permission lists must be copied, not aliased."""

    engine = PolicyEngine()
    engine._policy["read_file"]["agents"]["docs_agent"]["allowed_path_prefixes"].append(
        "/etc"
    )
    result = evaluate_action(
        "read_file",
        {"path": "/etc/passwd"},
        "docs_agent",
    )
    assert result.rule_id == "DENY_PATH_NOT_ALLOWED"
    # DEFAULT_POLICY itself must also stay unchanged.
    prefixes = DEFAULT_POLICY["read_file"]["agents"]["docs_agent"]["allowed_path_prefixes"]
    assert prefixes == ["/workspace/docs"]
    copied = deepcopy(DEFAULT_POLICY)
    copied["read_file"]["agents"]["docs_agent"]["allowed_path_prefixes"].append("/tmp")
    assert DEFAULT_POLICY["read_file"]["agents"]["docs_agent"]["allowed_path_prefixes"] == [
        "/workspace/docs"
    ]
