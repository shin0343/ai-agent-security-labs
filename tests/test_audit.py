"""Audit integrity, completeness checkpoint and explicit assurance limits."""

from __future__ import annotations

import json
import os
import stat

from agentguard.workbench.audit import key_path_for, verify_audit
from agentguard.workbench.db import read_connection, transaction

from .conftest import WorkbenchHarness


def _verify(workbench: WorkbenchHarness) -> dict:
    with read_connection(workbench.db_path) as conn:
        return verify_audit(conn, workbench.runtime_dir).as_dict()


def test_fresh_chain_is_valid_and_key_is_private(workbench: WorkbenchHarness) -> None:
    report = _verify(workbench)
    assert report["integrity"] == "valid"
    assert report["completeness"] == "checkpoint_matched"
    assert report["consistency"] == "ok"
    assert report["safe_for_mutations"] is True
    assert report["checked_events"] > 0
    key_path = key_path_for(workbench.runtime_dir)
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(workbench.runtime_dir).st_mode) == 0o700


def test_payload_tampering_is_detected(workbench: WorkbenchHarness) -> None:
    with transaction(workbench.db_path) as conn:
        row = conn.execute("SELECT payload_json FROM audit_events WHERE seq = 2").fetchone()
        payload = json.loads(row["payload_json"])
        payload["actor"] = "tampered-actor"
        conn.execute(
            "UPDATE audit_events SET payload_json = ? WHERE seq = 2",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )
    report = _verify(workbench)
    assert report["integrity"] == "invalid"
    assert report["safe_for_mutations"] is False
    assert report["first_failure_seq"] == 2
    with transaction(workbench.db_path) as conn:
        conn.execute(
            "UPDATE audit_events SET payload_json = ?, mac = ? WHERE seq = 2", (row["payload_json"], "🚫" * 64)
        )
    malformed_mac = _verify(workbench)
    assert malformed_mac["integrity"] == "invalid"
    assert malformed_mac["safe_for_mutations"] is False


def test_deleting_a_middle_event_is_detected(workbench: WorkbenchHarness) -> None:
    workbench.run("normal", "deny-v1")
    with transaction(workbench.db_path) as conn:
        conn.execute("DELETE FROM audit_events WHERE seq = 2")
    report = _verify(workbench)
    assert report["integrity"] == "invalid"
    assert report["first_failure_seq"] == 3
    assert report["safe_for_mutations"] is False


def test_reordering_retained_records_is_detected(workbench: WorkbenchHarness) -> None:
    with transaction(workbench.db_path) as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY seq LIMIT 2").fetchall()
        for target_seq, source in ((1, rows[1]), (2, rows[0])):
            conn.execute(
                "UPDATE audit_events SET prev_mac = ?, payload_json = ?, mac = ?, key_id = ?, created_at = ? "
                "WHERE seq = ?",
                (
                    source["prev_mac"],
                    source["payload_json"],
                    source["mac"],
                    source["key_id"],
                    source["created_at"],
                    target_seq,
                ),
            )
    report = _verify(workbench)
    assert report["integrity"] == "invalid"
    assert report["safe_for_mutations"] is False


def test_suffix_deletion_breaks_checkpoint_not_retained_chain(workbench: WorkbenchHarness) -> None:
    with transaction(workbench.db_path) as conn:
        head = conn.execute("SELECT MAX(seq) AS seq FROM audit_events").fetchone()["seq"]
        conn.execute("DELETE FROM audit_events WHERE seq = ?", (head,))
    report = _verify(workbench)
    assert report["integrity"] == "valid"
    assert report["completeness"] == "checkpoint_mismatch"
    assert report["consistency"] == "failed"
    assert report["safe_for_mutations"] is False


def test_deleting_all_events_breaks_checkpoint(workbench: WorkbenchHarness) -> None:
    with transaction(workbench.db_path) as conn:
        conn.execute("DELETE FROM audit_events")
    report = _verify(workbench)
    assert report["integrity"] == "unverifiable"
    assert report["completeness"] == "checkpoint_mismatch"
    assert report["safe_for_mutations"] is False
    response = workbench.client.post(
        "/api/v1/runs",
        json={
            "dataset_id": workbench.dataset_id,
            "scenario_key": "normal",
            "policy_preset_id": "deny-v1",
        },
    )
    assert response.status_code == 503
    assert response.json()["code"] == "AUDIT_INTEGRITY_FAILED"


def test_broad_key_permissions_are_rejected(workbench: WorkbenchHarness) -> None:
    key_path = key_path_for(workbench.runtime_dir)
    key_path.chmod(0o644)
    report = _verify(workbench)
    assert report["integrity"] == "unverifiable"
    assert report["key_status"] == "invalid"
    assert report["safe_for_mutations"] is False


def test_symlink_key_is_rejected(workbench: WorkbenchHarness) -> None:
    key_path = key_path_for(workbench.runtime_dir)
    target = workbench.runtime_dir / "real-key"
    key_path.rename(target)
    key_path.symlink_to(target)
    report = _verify(workbench)
    assert report["integrity"] == "unverifiable"
    assert report["safe_for_mutations"] is False


def test_missing_key_blocks_mutations(workbench: WorkbenchHarness) -> None:
    key_path_for(workbench.runtime_dir).unlink()
    report = _verify(workbench)
    assert report["key_status"] == "missing"
    assert report["safe_for_mutations"] is False


def test_audit_does_not_store_raw_tool_arguments(workbench: WorkbenchHarness) -> None:
    workbench.run("injection", "monitor-v1")
    with read_connection(workbench.db_path) as conn:
        rows = conn.execute("SELECT payload_json FROM audit_events").fetchall()
    serialized = "\n".join(str(row["payload_json"]) for row in rows)
    assert "demo-internal-outbox" not in serialized
    assert "quarterly-synthetic" not in serialized
    assert "args_digest" in serialized
    assert "synthetic" in serialized


def test_verification_api_claims_are_separate(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post(
        "/api/v1/audit/verifications",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["integrity"] == "valid"
    assert report["completeness"] == "checkpoint_matched"
    assert report["consistency"] == "ok"
    assert "not independent tamper-proof storage" in report["message"]
    verification_id = report["verification_id"]
    fetched = workbench.client.get(f"/api/v1/audit/verifications/{verification_id}")
    assert fetched.status_code == 200
    assert fetched.json() == report


def test_audit_summary_and_events_are_read_only(workbench: WorkbenchHarness) -> None:
    before = _verify(workbench)["checked_events"]
    workbench.client.get("/api/v1/audit/summary")
    workbench.client.get("/api/v1/audit/events?limit=20")
    after = _verify(workbench)["checked_events"]
    assert before == after


def test_audit_event_pagination(workbench: WorkbenchHarness) -> None:
    workbench.run("normal", "deny-v1")
    first = workbench.client.get("/api/v1/audit/events?limit=3")
    assert first.status_code == 200
    items = first.json()["items"]
    assert len(items) == 3
    seqs = [item["seq"] for item in items]
    assert seqs == sorted(seqs, reverse=True)
    older = workbench.client.get(f"/api/v1/audit/events?before_seq={seqs[-1]}&limit=3")
    assert older.status_code == 200
    assert all(item["seq"] < seqs[-1] for item in older.json()["items"])


def test_audit_key_is_not_in_api_responses(workbench: WorkbenchHarness) -> None:
    key = key_path_for(workbench.runtime_dir).read_bytes().hex()
    responses = [
        workbench.client.get("/api/v1/audit/summary"),
        workbench.client.get("/api/v1/audit/events?limit=100"),
        workbench.client.get("/api/v1/overview"),
    ]
    for response in responses:
        assert response.status_code == 200
        assert key not in response.text
