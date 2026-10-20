from sentinelflow.audit import AuditEvent, AuditLog, AuditStorageError


def make_event(request_id, decision="BLOCK", action="read_file"):
    return AuditEvent(
        request_id=request_id,
        event="handle",
        action=action,
        arguments={"path": f"/workspace/{request_id}"},
        agent_id="docs_agent",
        decision=decision,
        rule_id=f"RULE_{request_id}",
        reason=f"Reason for {request_id}",
        executed=False,
        execution_success=False,
        pending=False,
        error=None,
    )


def test_audit_events_survive_database_reopen_with_all_fields(tmp_path):
    database = tmp_path / "audit" / "events.sqlite3"
    first_log = AuditLog(database)
    event = make_event("req-1", decision="REQUIRE_APPROVAL", action="send_email")

    first_log.append(event)
    del first_log

    reopened_log = AuditLog(database)
    recovered = reopened_log[0]
    assert recovered == event
    assert recovered.timestamp.endswith("+00:00")
    assert recovered.arguments == {"path": "/workspace/req-1"}
    assert recovered.agent_id == "docs_agent"
    assert recovered.decision == "REQUIRE_APPROVAL"
    assert recovered.reason == "Reason for req-1"
    assert recovered.executed is False
    assert recovered.execution_success is False
    assert recovered.pending is False


def test_audit_recent_is_newest_first_filtered_and_limited(tmp_path):
    log = AuditLog(tmp_path / "events.sqlite3")
    log.append(make_event("req-1", decision="ALLOW"))
    log.append(make_event("req-2", decision="BLOCK", action="delete_file"))
    log.append(make_event("req-3", decision="BLOCK"))

    assert [event.request_id for event in log] == ["req-1", "req-2", "req-3"]
    assert [event.request_id for event in log.recent(limit=2)] == ["req-3", "req-2"]
    assert [event.request_id for event in log.recent(decision="block", limit=10)] == [
        "req-3",
        "req-2",
    ]
    assert [event.request_id for event in log.recent(action="read_file", limit=10)] == [
        "req-3",
        "req-1",
    ]
    assert len(log.recent(limit=500)) == 3


def test_audit_execution_outcome_updates_the_original_row(tmp_path):
    log = AuditLog(tmp_path / "events.sqlite3")
    event_id = log.append_with_id(make_event("req-1", decision="ALLOW"))

    log.update_execution(
        event_id,
        event="handle",
        executed=True,
        execution_success=True,
        pending=False,
        error=None,
    )

    assert len(log) == 1
    updated = log[0]
    assert updated.event == "handle"
    assert updated.executed is True
    assert updated.execution_success is True
    assert updated.error is None


def test_audit_update_failure_for_missing_row_is_reported(tmp_path):
    log = AuditLog(tmp_path / "events.sqlite3")
    try:
        log.update_execution(
            999,
            event="handle",
            executed=True,
            execution_success=True,
            pending=False,
            error=None,
        )
    except AuditStorageError as exc:
        assert str(exc) == "The audit execution record could not be updated."
    else:
        raise AssertionError("Updating an unknown audit row must fail")


def test_audit_database_errors_are_reported_without_raw_sqlite_details(tmp_path):
    log = AuditLog(tmp_path)
    try:
        log.append(make_event("req-1"))
    except AuditStorageError as exc:
        assert str(exc) == "Could not initialize the audit database."
    else:
        raise AssertionError("A directory cannot be used as a SQLite database file")
