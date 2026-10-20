"""Shared pytest fixtures for the HTTP API."""

import pytest
from fastapi.testclient import TestClient

from sentinelflow.api import create_app
from sentinelflow.gateway import SentinelGateway
from sentinelflow.settings import ApiSettings
from sentinelflow.tools import MockToolRunner

TEST_AGENT_TOKENS = {
    "docs_agent": "test-token-docs-agent-0000000000000000",
    "mail_agent": "test-token-mail-agent-0000000000000000",
    "ops_agent": "test-token-ops-agent-0000000000000000",
    "finance_agent": "test-token-finance-agent-0000000000000000",
}
TEST_APPROVAL_TOKEN = "test-approval-token-0000000000000000"


def agent_headers(agent_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_AGENT_TOKENS[agent_id]}"}


@pytest.fixture
def gateway() -> SentinelGateway:
    return SentinelGateway(tools=MockToolRunner())


@pytest.fixture(autouse=True)
def isolate_audit_database(tmp_path, monkeypatch):
    """Keep persistent audit data isolated between tests."""

    monkeypatch.setenv("SENTINELFLOW_AUDIT_DB_PATH", str(tmp_path / "audit.sqlite3"))


@pytest.fixture
def client(gateway: SentinelGateway) -> TestClient:
    app = create_app(
        gateway=gateway,
        settings=ApiSettings(
            environment="development",
            cors_origins=["http://localhost:5173"],
            max_body_bytes=16384,
            agent_tokens=TEST_AGENT_TOKENS,
        ),
    )
    return TestClient(app, headers=agent_headers("docs_agent"))
