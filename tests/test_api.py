"""HTTP API tests. Policy still decides; the API only transports proposals."""

from fastapi.testclient import TestClient

from sentinelflow.api import create_app
from sentinelflow.gateway import SentinelGateway
from sentinelflow.settings import ApiSettings
from sentinelflow.audit import AuditStorageError
from sentinelflow.tools import MockToolRunner, ToolExecutionError
from conftest import TEST_AGENT_TOKENS, TEST_APPROVAL_TOKEN, agent_headers


def test_health_returns_status_and_version(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    dumped = response.text.lower()
    assert "secret" not in dumped
    assert "password" not in dumped
    assert "allowed_path" not in dumped


def test_scenarios_lists_predefined_attacks(client: TestClient):
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    items = response.json()["scenarios"]
    ids = {item["scenario_id"] for item in items}
    assert len(items) >= 6
    assert "legit-read-permitted-file" in ids
    assert "attack-read-restricted-file" in ids
    email = next(item for item in items if item["scenario_id"] == "attack-email-confidential-external")
    assert email["arguments"]["body"] == "[redacted]"
    assert email["expected_decision"] == "REQUIRE_APPROVAL"


def test_identity_endpoint_reports_server_mapped_agent_and_requires_auth(client: TestClient):
    assert client.get("/api/identity").json() == {"agent_id": "docs_agent"}
    unauthenticated = TestClient(client.app).get("/api/identity")
    assert unauthenticated.status_code == 401


def test_evaluate_allows_permitted_read(client: TestClient):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["rule_id"] == "ALLOW_READ_FILE"
    assert body["executed"] is True
    assert body["execution_success"] is True
    assert body["output"]["content"] == "[redacted]"


def test_unauthenticated_evaluate_is_rejected_before_execution():
    gateway = SentinelGateway()
    api = TestClient(
        create_app(
            gateway=gateway,
            settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS),
        )
    )
    response = api.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert gateway.tools.files["/workspace/docs/readme.md"].startswith("# Docs")


def test_invalid_agent_credential_is_rejected_for_protected_routes():
    api = TestClient(
        create_app(
            gateway=SentinelGateway(),
            settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS),
        )
    )
    invalid_headers = {"Authorization": "Bearer invalid-agent-token"}
    events = api.get("/api/events", headers=invalid_headers)
    evaluation = api.post(
        "/api/evaluate",
        headers=invalid_headers,
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )
    assert events.status_code == 401
    assert evaluation.status_code == 401
    assert "invalid-agent-token" not in events.text + evaluation.text


def test_authenticated_caller_cannot_impersonate_another_agent(
    client: TestClient, gateway: SentinelGateway
):
    response = client.post(
        "/api/evaluate",
        headers=agent_headers("docs_agent"),
        json={
            "action": "send_email",
            "arguments": {
                "to": "alice@company.com",
                "subject": "Test",
                "body": "synthetic",
            },
            "agent_id": "mail_agent",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "agent_identity_mismatch"
    assert gateway.tools.sent_emails == []


def test_agent_identity_auth_does_not_bypass_policy(
    client: TestClient, gateway: SentinelGateway
):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/hr/salaries.txt"},
            "agent_id": "docs_agent",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["executed"] is False
    assert "/workspace/hr/salaries.txt" in gateway.tools.files


def test_evaluate_blocked_action_never_executes(client: TestClient, gateway: SentinelGateway):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/hr/salaries.txt"},
            "agent_id": "docs_agent",
        },
    )
    body = response.json()
    assert response.status_code == 200
    assert body["decision"] == "BLOCK"
    assert body["executed"] is False
    assert "/workspace/hr/salaries.txt" in gateway.tools.files


def test_evaluate_approval_required_never_executes(client: TestClient, gateway: SentinelGateway):
    response = client.post(
        "/api/evaluate",
        headers=agent_headers("finance_agent"),
        json={
            "action": "transfer_funds",
            "arguments": {"amount": 2500.0, "to_account": "ACC-SYNTH-999"},
            "agent_id": "finance_agent",
        },
    )
    body = response.json()
    assert body["decision"] == "REQUIRE_APPROVAL"
    assert body["executed"] is False
    assert body["pending"] is True
    assert gateway.tools.transfers == []


def test_non_finite_transfer_amount_is_blocked_before_execution(
    client: TestClient, gateway: SentinelGateway
):
    response = client.post(
        "/api/evaluate",
        content=(
            b'{"action":"transfer_funds","arguments":'
            b'{"amount":NaN,"to_account":"ACC-SYNTH-999"},'
            b'"agent_id":"finance_agent"}'
        ),
        headers={**agent_headers("finance_agent"), "Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["rule_id"] == "DENY_INVALID_ARGUMENTS"
    assert response.json()["executed"] is False
    assert gateway.tools.transfers == []


def test_evaluate_unknown_action_is_blocked(client: TestClient):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "run_shell",
            "arguments": {"command": "id"},
            "agent_id": "docs_agent",
        },
    )
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["rule_id"] == "DENY_UNKNOWN_ACTION"
    assert body["executed"] is False


def test_evaluate_malformed_arguments_are_blocked(client: TestClient):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {},
            "agent_id": "docs_agent",
        },
    )
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["rule_id"] == "DENY_INVALID_ARGUMENTS"
    assert body["executed"] is False


def test_event_api_redacts_secret_key_variants(client: TestClient):
    secret_values = {
        "apiKey": "synthetic-api-key-value",
        "access_token": "synthetic-access-token-value",
        "client-secret": "synthetic-client-secret-value",
        "nested": {"Authorization": "Bearer synthetic-auth-value"},
    }
    response = client.post(
        "/api/evaluate",
        json={
            "action": "unknown_tool",
            "arguments": secret_values,
            "agent_id": "docs_agent",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"

    events_response = client.get("/api/events")
    events = events_response.json()["events"]
    arguments = events[0]["arguments"]
    assert arguments == {
        "apiKey": "[redacted]",
        "access_token": "[redacted]",
        "client-secret": "[redacted]",
        "nested": {"Authorization": "[redacted]"},
    }
    assert all(value not in events_response.text for value in (
        "synthetic-api-key-value",
        "synthetic-access-token-value",
        "synthetic-client-secret-value",
        "synthetic-auth-value",
    ))


def test_execution_and_event_responses_redact_argument_identifiers(client: TestClient):
    address = "private.person@company.com"
    subject = "Sensitive case subject"
    response = client.post(
        "/api/evaluate",
        headers=agent_headers("mail_agent"),
        json={
            "action": "send_email",
            "arguments": {"to": address, "subject": subject, "body": "synthetic text"},
            "agent_id": "mail_agent",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert address not in response.text
    assert subject not in response.text
    assert body["output"]["email"]["to"] == "[redacted]"
    assert body["output"]["email"]["subject"] == "[redacted]"

    events_response = client.get("/api/events", headers=agent_headers("mail_agent"))
    event = events_response.json()["events"][0]
    assert event["arguments"]["to"] == "[redacted]"
    assert event["arguments"]["subject"] == "[redacted]"
    assert address not in events_response.text
    assert subject not in events_response.text


def test_approval_reason_does_not_echo_external_recipient(client: TestClient):
    address = "private.person@outside.test"
    response = client.post(
        "/api/evaluate",
        headers=agent_headers("mail_agent"),
        json={
            "action": "send_email",
            "arguments": {"to": address, "subject": "Review", "body": "synthetic"},
            "agent_id": "mail_agent",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "REQUIRE_APPROVAL"
    assert address not in response.text

    events_response = client.get("/api/events", headers=agent_headers("mail_agent"))
    event = events_response.json()["events"][0]
    assert address not in events_response.text
    assert event["arguments"]["to"] == "[redacted]"


def test_unknown_action_with_non_object_arguments_is_blocked_by_policy():
    class SpyToolRunner:
        def __init__(self):
            self.calls = []

        def run(self, action, arguments):
            self.calls.append((action, arguments))
            raise AssertionError("Blocked proposal reached the mock executor")

    tools = SpyToolRunner()
    gateway = SentinelGateway(tools=tools)  # type: ignore[arg-type]
    api = TestClient(
        create_app(gateway=gateway, settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS)),
        headers=agent_headers("docs_agent"),
    )
    scenario = next(
        item
        for item in api.get("/api/scenarios").json()["scenarios"]
        if item["scenario_id"] == "attack-unknown-tool-malformed"
    )

    response = api.post(
        "/api/evaluate",
        json={
            "action": scenario["action"],
            "arguments": scenario["arguments"],
            "agent_id": scenario["agent_id"],
        },
        headers=agent_headers(scenario["agent_id"]),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["rule_id"] == "DENY_MALFORMED_REQUEST"
    assert response.json()["executed"] is False
    assert tools.calls == []


def test_evaluate_rejects_client_supplied_decision(client: TestClient):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
            "decision": "ALLOW",
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert "traceback" not in response.text.lower()


def test_evaluate_rejects_invalid_agent_id(client: TestClient):
    response = client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs agent; DROP TABLE",
        },
    )
    assert response.status_code == 422


def test_events_filter_and_limit(client: TestClient):
    client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )
    client.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/etc/passwd"},
            "agent_id": "docs_agent",
        },
    )
    client.post(
        "/api/evaluate",
        headers=agent_headers("mail_agent"),
        json={
            "action": "send_email",
            "arguments": {
                "to": "alice@company.com",
                "subject": "Hi",
                "body": "SYNTHETIC secret text",
            },
            "agent_id": "mail_agent",
        },
    )

    blocked = client.get("/api/events", params={"decision": "BLOCK"})
    assert blocked.status_code == 200
    events = blocked.json()["events"]
    assert events
    assert all(item["decision"] == "BLOCK" for item in events)
    assert all(item["executed"] is False for item in events)

    reads = client.get("/api/events", params={"action": "read_file", "limit": 1})
    assert reads.json()["count"] == 1
    assert reads.json()["events"][0]["action"] == "read_file"

    mail = client.get(
        "/api/events",
        params={"action": "send_email"},
        headers=agent_headers("mail_agent"),
    )
    assert mail.json()["events"][0]["arguments"]["body"] == "[redacted]"
    assert mail.json()["events"][0]["timestamp"].endswith("+00:00")


def test_events_reject_invalid_decision_filter(client: TestClient):
    response = client.get("/api/events", params={"decision": "MAYBE"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_query"


def test_event_and_pending_retrieval_require_agent_authentication():
    api = TestClient(
        create_app(
            gateway=SentinelGateway(),
            settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS),
        )
    )
    assert api.get("/api/events").status_code == 401
    assert api.get("/api/pending").status_code == 401


def test_event_retrieval_is_scoped_to_authenticated_agent(client: TestClient):
    client.post(
        "/api/evaluate",
        headers=agent_headers("mail_agent"),
        json={
            "action": "send_email",
            "arguments": {"to": "alice@company.com", "subject": "Demo", "body": "synthetic"},
            "agent_id": "mail_agent",
        },
    )
    docs_events = client.get("/api/events", headers=agent_headers("docs_agent"))
    mail_events = client.get("/api/events", headers=agent_headers("mail_agent"))
    assert docs_events.json()["count"] == 0
    assert mail_events.json()["count"] == 1
    assert mail_events.json()["events"][0]["agent_id"] == "mail_agent"


def test_approval_requires_agent_authentication_and_separate_approval_token():
    gateway = SentinelGateway()
    held = gateway.handle(
        "send_email",
        {"to": "outside@example.test", "subject": "Review", "body": "synthetic"},
        "mail_agent",
    )
    api = TestClient(
        create_app(
            gateway=gateway,
            settings=ApiSettings(
                agent_tokens=TEST_AGENT_TOKENS,
                approval_token=TEST_APPROVAL_TOKEN,
            ),
        )
    )
    path = f"/api/requests/{held.request_id}/approve"
    approval_only = api.post(path, headers={"X-Approval-Token": TEST_APPROVAL_TOKEN})
    assert approval_only.status_code == 401
    assert gateway.tools.sent_emails == []

    agent_only = api.post(path, headers=agent_headers("mail_agent"))
    assert agent_only.status_code == 401
    assert gateway.tools.sent_emails == []

    authorized = api.post(
        path,
        headers={**agent_headers("mail_agent"), "X-Approval-Token": TEST_APPROVAL_TOKEN},
    )
    assert authorized.status_code == 200
    assert len(gateway.tools.sent_emails) == 1


def test_oversized_request_is_rejected():
    app = create_app(
        gateway=SentinelGateway(),
        settings=ApiSettings(max_body_bytes=64, cors_origins=["http://localhost:5173"]),
    )
    tiny = TestClient(app)
    response = tiny.post(
        "/api/evaluate",
        content=b"x" * 200,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_oversized_chunked_request_is_rejected():
    """Bodies without Content-Length must be capped while they are read."""
    app = create_app(
        gateway=SentinelGateway(),
        settings=ApiSettings(max_body_bytes=64, cors_origins=["http://localhost:5173"]),
    )
    tiny = TestClient(app)
    response = tiny.post(
        "/api/evaluate",
        content=iter([b"x" * 40, b"y" * 40, b"z" * 40]),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_invalid_json_is_rejected(client: TestClient):
    response = client.post(
        "/api/evaluate",
        content=b"{not-json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_unexpected_server_error_is_safe_and_does_not_expose_exception():
    class ExplodingGateway:
        def handle(self, *_args, **_kwargs):
            raise RuntimeError("private secret and stack details")

    api = TestClient(
        create_app(
            gateway=ExplodingGateway(),  # type: ignore[arg-type]
            settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS),
        ),
        headers=agent_headers("docs_agent"),
        raise_server_exceptions=False,
    )
    response = api.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "An unexpected error occurred.",
        }
    }
    assert "private secret" not in response.text
    assert "traceback" not in response.text.lower()


def test_executor_exception_details_are_not_returned_by_api():
    class LeakingFailureToolRunner(MockToolRunner):
        def run(self, _action, _arguments):
            raise ToolExecutionError("failed for apiKey=synthetic-secret-value")

    gateway = SentinelGateway(tools=LeakingFailureToolRunner())
    api = TestClient(
        create_app(gateway=gateway, settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS)),
        headers=agent_headers("docs_agent"),
    )
    response = api.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )
    assert response.status_code == 200
    assert response.json()["error"] == "Mock tool execution failed."
    assert "synthetic-secret-value" not in response.text

    event_response = api.get("/api/events")
    assert event_response.json()["events"][0]["error"] == "Mock tool execution failed."
    assert "synthetic-secret-value" not in event_response.text


def test_pre_execution_audit_failure_returns_safe_503_and_does_not_execute():
    gateway = SentinelGateway()

    def fail_append(_event):
        raise AuditStorageError("private database location")

    gateway.audit_log.append_with_id = fail_append  # type: ignore[method-assign]
    api = TestClient(
        create_app(gateway=gateway, settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS)),
        headers=agent_headers("docs_agent"),
    )
    response = api.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "audit_unavailable"
    assert "was not executed" in response.json()["error"]["message"]
    assert "private database" not in response.text


def test_final_audit_failure_response_says_action_may_have_run():
    gateway = SentinelGateway()

    def fail_update(*_args, **_kwargs):
        raise AuditStorageError("private database location")

    gateway.audit_log.update_execution = fail_update  # type: ignore[method-assign]
    api = TestClient(
        create_app(gateway=gateway, settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS)),
        headers=agent_headers("docs_agent"),
    )
    response = api.post(
        "/api/evaluate",
        json={
            "action": "read_file",
            "arguments": {"path": "/workspace/docs/readme.md"},
            "agent_id": "docs_agent",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["executed"] is True
    assert body["execution_success"] is True
    assert body["audit_integrity_error"] is True
    assert "may have run" in body["error"]
    assert "private database" not in response.text


def test_cors_allows_configured_origin_only():
    app = create_app(
        gateway=SentinelGateway(),
        settings=ApiSettings(
            environment="production",
            cors_origins=["http://localhost:5173"],
        ),
    )
    api = TestClient(app)
    allowed = api.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    denied = api.get("/api/health", headers={"Origin": "http://evil.example"})
    assert denied.headers.get("access-control-allow-origin") != "http://evil.example"

    preflight = api.options(
        "/api/evaluate",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code in {200, 204}
    assert preflight.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_pending_requests_are_listed_with_sensitive_arguments_redacted():
    gateway = SentinelGateway()
    held = gateway.handle(
        "send_email",
        {
            "to": "eve@outside.test",
            "subject": "Confidential",
            "body": "synthetic secret text",
        },
        "mail_agent",
    )
    api = TestClient(
        create_app(
            gateway=gateway,
            settings=ApiSettings(approval_token=TEST_APPROVAL_TOKEN, agent_tokens=TEST_AGENT_TOKENS),
        ),
        headers=agent_headers("mail_agent"),
    )

    response = api.get("/api/pending")
    assert response.status_code == 200
    assert response.json()["count"] == 1
    request = response.json()["requests"][0]
    assert request["request_id"] == held.request_id
    assert request["arguments"]["body"] == "[redacted]"
    other_agent = api.get("/api/pending", headers=agent_headers("docs_agent"))
    assert other_agent.json()["count"] == 0


def test_http_approval_requires_token_and_executes_only_after_authorization():
    gateway = SentinelGateway()
    held = gateway.handle(
        "send_email",
        {
            "to": "eve@outside.test",
            "subject": "Hello",
            "body": "synthetic text",
        },
        "mail_agent",
    )
    api = TestClient(
        create_app(
            gateway=gateway,
            settings=ApiSettings(approval_token=TEST_APPROVAL_TOKEN, agent_tokens=TEST_AGENT_TOKENS),
        ),
        headers=agent_headers("mail_agent"),
    )
    path = f"/api/requests/{held.request_id}/approve"

    wrong_agent = api.post(
        path,
        headers={**agent_headers("docs_agent"), "X-Approval-Token": TEST_APPROVAL_TOKEN},
    )
    assert wrong_agent.status_code == 404
    assert gateway.tools.sent_emails == []

    unauthorized = api.post(path, headers=agent_headers("mail_agent"))
    assert unauthorized.status_code == 401
    assert gateway.tools.sent_emails == []

    approved = api.post(
        path,
        headers={**agent_headers("mail_agent"), "X-Approval-Token": TEST_APPROVAL_TOKEN},
    )
    assert approved.status_code == 200
    assert approved.json()["executed"] is True
    assert approved.json()["output"]["email"]["body"] == "[redacted]"
    assert len(gateway.tools.sent_emails) == 1


def test_http_approval_is_disabled_without_configured_token():
    api = TestClient(
        create_app(
            gateway=SentinelGateway(),
            settings=ApiSettings(agent_tokens=TEST_AGENT_TOKENS),
        )
    )
    response = api.post(
        "/api/requests/req-missing/deny",
        headers={**agent_headers("mail_agent"), "X-Approval-Token": "anything"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "approval_unavailable"
