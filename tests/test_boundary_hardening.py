"""Regression probes for failure paths missing from the inherited suite."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agentguard.workbench import api, runtime
from agentguard.workbench.audit import AuditUnavailable, append_audit, verify_audit
from agentguard.workbench.db import read_connection, transaction
from agentguard.workbench.enforcement import propose
from agentguard.workbench.errors import ConflictError
from agentguard.workbench.settings import Settings

from .conftest import WorkbenchHarness


@pytest.mark.parametrize(
    "raw",
    [b'{"a":1e999}', b'{"a":"\\ud800"}', b'{"a":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}", b"null"],
    ids=["overflow", "surrogate", "nesting", "null"],
)
def test_hostile_json_is_a_bounded_client_error(workbench: WorkbenchHarness, raw: bytes) -> None:
    response = workbench.client.post(
        "/api/v1/audit/verifications", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_JSON"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_origin_must_match_the_actual_host(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post(
        "/api/v1/audit/verifications", json={}, headers={"Origin": "http://localhost:8765"}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "UNTRUSTED_ORIGIN"


def test_unexpected_api_failure_retains_security_headers(workbench: WorkbenchHarness, monkeypatch) -> None:
    def failure(*args):
        raise OSError("Internal test-only failure details must stay private")

    monkeypatch.setattr(api, "build_overview", failure)
    with TestClient(workbench.app, base_url=workbench.base_url, raise_server_exceptions=False) as client:
        client.cookies.update(workbench.client.cookies)
        response = client.get("/api/v1/overview")
    assert response.status_code == 500
    assert response.json()["code"] == "INTERNAL_ERROR"
    assert "test-only" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_gateway_enforces_budget_even_if_adapter_does_not(workbench: WorkbenchHarness, monkeypatch) -> None:
    monkeypatch.setattr(runtime, "_execute_scripted", lambda *args: None)
    run = workbench.run()
    for _ in range(8):
        propose(
            workbench.settings,
            run_id=run["id"],
            actor="trusted:test",
            tool="read_report",
            args={"report_id": "quarterly-synthetic"},
        )
    with pytest.raises(ConflictError, match="budget"):
        propose(
            workbench.settings,
            run_id=run["id"],
            actor="trusted:test",
            tool="read_report",
            args={"report_id": "quarterly-synthetic"},
        )
    with read_connection(workbench.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM execution_results").fetchone()[0] == 8


def test_non_loopback_server_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="loopback"):
        Settings(host="0.0.0.0")  # noqa: S104 - verify wildcard binding is refused


@pytest.mark.parametrize(
    "column,value",
    [("actor", "changed:actor"), ("resource_ref", "changed:target"), ("tool_schema_version", "changed-schema")],
)
def test_approval_recomputes_the_entire_stored_request_binding(
    workbench: WorkbenchHarness, column: str, value: str
) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    # Simulate a faulty trusted writer; this is not a host-compromise claim.
    with transaction(workbench.db_path) as conn:
        conn.execute(f"UPDATE tool_requests SET {column} = ? WHERE id = ?", (value, approval["request_id"]))
    response = workbench.decide(approval, idempotency_key="changed-binding")
    assert response.status_code == 409
    assert response.json()["details"]["code"] == "REQUEST_BINDING_CHANGED"
    with read_connection(workbench.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM simulated_receipts").fetchone()[0] == 0
    assert workbench.approval_for(run)["state"] == "INVALIDATED"


def test_policy_semantics_are_rechecked_before_approval(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    with transaction(workbench.db_path) as conn:
        conn.execute("UPDATE policy_presets SET mode = 'DENY' WHERE id = 'approve-v1'")
    response = workbench.decide(approval, idempotency_key="changed-policy-content")
    assert response.status_code == 409
    assert response.json()["details"]["code"] == "POLICY_CHANGED"
    assert workbench.approval_for(run)["state"] == "INVALIDATED"


def test_idempotency_key_cannot_replay_on_another_approval_url(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    assert workbench.decide(approval, idempotency_key="same-url-key").status_code == 200
    forged_url = {**approval, "id": "apr_different_resource"}
    response = workbench.decide(forged_url, idempotency_key="same-url-key")
    assert response.status_code == 409


@pytest.mark.parametrize("corruption", ["delete_all", "edit_payload", "edit_timestamp"])
def test_every_audit_append_refuses_corrupt_existing_history(workbench: WorkbenchHarness, corruption: str) -> None:
    with transaction(workbench.db_path) as conn:
        if corruption == "delete_all":
            conn.execute("DELETE FROM audit_events")
        elif corruption == "edit_timestamp":
            conn.execute("UPDATE audit_events SET created_at = '2000-01-01T00:00:00Z' WHERE seq = 1")
        else:
            conn.execute("UPDATE audit_events SET payload_json = ? WHERE seq = 1", (json.dumps({"tampered": True}),))
    with pytest.raises(AuditUnavailable), transaction(workbench.db_path) as conn:
        append_audit(
            conn,
            workbench.runtime_dir,
            action="test.append",
            actor="test",
            entity_type="test",
            entity_id="test",
            details={},
        )
    with read_connection(workbench.db_path) as conn:
        assert not verify_audit(conn, workbench.runtime_dir).safe_for_mutations
