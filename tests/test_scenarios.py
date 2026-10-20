"""Attack simulations must match expected decisions and never skip policy."""

from sentinelflow.gateway import SentinelGateway
from sentinelflow.scenarios import SCENARIOS, run_all_scenarios, run_scenario
from sentinelflow.tools import MockToolRunner


def test_six_required_scenarios_are_defined():
    ids = {item.scenario_id for item in SCENARIOS}
    assert len(SCENARIOS) >= 6
    assert "legit-read-permitted-file" in ids
    assert "attack-read-restricted-file" in ids
    assert "attack-email-confidential-external" in ids
    assert "attack-delete-protected-file" in ids
    assert "attack-transfer-without-approval" in ids
    assert "attack-unknown-tool-malformed" in ids


def test_all_scenarios_match_expected_security_decisions():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)
    rows = run_all_scenarios(gateway)
    failed = [
        (scenario.scenario_id, result.policy.rule_id)
        for scenario, result, ok in rows
        if not ok
    ]
    assert failed == []
    assert len(gateway.audit_log) == len(SCENARIOS)


def test_attack_scenarios_never_execute_mocks():
    tools = MockToolRunner()
    gateway = SentinelGateway(tools=tools)
    run_all_scenarios(gateway)
    assert tools.sent_emails == []
    assert tools.transfers == []
    assert tools.deleted_paths == []
    assert "/workspace/docs/readme.md" in tools.files
    assert "/workspace/hr/salaries.txt" in tools.files


def test_legitimate_read_is_the_only_executed_default_scenario():
    gateway = SentinelGateway()
    executed_ids = []
    for scenario in SCENARIOS:
        result = run_scenario(scenario, gateway=gateway)
        if result.executed:
            executed_ids.append(scenario.scenario_id)
    assert executed_ids == ["legit-read-permitted-file"]
