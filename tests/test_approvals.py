"""Approval binding, expiry, idempotency, concurrency and invalidation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentguard.workbench.db import read_connection, transaction
from agentguard.workbench.enforcement import decide_approval
from agentguard.workbench.errors import ConflictError

from .conftest import WorkbenchHarness


def _receipt_count(workbench: WorkbenchHarness) -> int:
    with read_connection(workbench.db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM simulated_receipts").fetchone()
        return int(row["count"])


def test_wrong_digest_and_version_leave_approval_pending(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)

    wrong_digest = workbench.decide(approval, digest="0" * 64, idempotency_key="wrong-digest")
    assert wrong_digest.status_code == 409
    assert wrong_digest.json()["details"]["code"] == "REQUEST_DIGEST_MISMATCH"

    wrong_version = workbench.decide(approval, version=99, idempotency_key="wrong-version")
    assert wrong_version.status_code == 409
    assert wrong_version.json()["details"]["code"] == "STALE_VERSION"

    still_pending = workbench.approval_for(run)
    assert still_pending["state"] == "PENDING"
    assert _receipt_count(workbench) == 0

    approved = workbench.decide(approval, idempotency_key="correct-decision")
    assert approved.status_code == 200, approved.text
    assert approved.json()["request"]["status"] == "AUTHORIZED"
    assert approved.json()["request"]["execution_status"] == "SUCCEEDED"
    assert _receipt_count(workbench) == 1


def test_idempotency_replay_is_exact_and_new_key_conflicts(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)

    first = workbench.decide(approval, idempotency_key="same-key")
    assert first.status_code == 200
    replay = workbench.decide(approval, idempotency_key="same-key")
    assert replay.status_code == 200
    assert replay.json() == first.json()

    mismatch = workbench.decide(
        approval,
        idempotency_key="same-key",
        reason="A different decision body must not reuse the key.",
    )
    assert mismatch.status_code == 409
    assert mismatch.json()["details"]["code"] == "IDEMPOTENCY_BODY_MISMATCH"

    second_decision = workbench.decide(approval, idempotency_key="new-key")
    assert second_decision.status_code == 409
    assert "no longer pending" in second_decision.json()["message"]
    assert _receipt_count(workbench) == 1


def test_idempotency_header_is_required(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    response = workbench.client.post(
        f"/api/v1/approvals/{approval['id']}/decision",
        json={
            "decision": "approve",
            "reviewed_request_digest": approval["request_digest"],
            "expected_version": approval["expected_version"],
            "reason": "Missing idempotency key should fail.",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_replayed_mutable_state_cannot_duplicate_a_committed_receipt(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    assert workbench.decide(approval, idempotency_key="before-state-replay").status_code == 200
    # Restore only mutable workflow state, retaining the committed receipt/audit.
    # Replacing the entire database and local checkpoint is outside this claim.
    with transaction(workbench.db_path) as conn:
        conn.execute("UPDATE approvals SET state = 'PENDING', consumed_at = NULL WHERE id = ?", (approval["id"],))
        conn.execute(
            "UPDATE tool_requests SET status = 'PENDING', execution_status = 'NOT_STARTED', result_json = NULL "
            "WHERE id = ?",
            (approval["request_id"],),
        )
        conn.execute("UPDATE runs SET status = 'WAITING_APPROVAL', ended_at = NULL WHERE id = ?", (run["id"],))
    response = workbench.decide(approval, idempotency_key="after-state-replay")
    assert response.status_code == 409
    assert response.json()["code"] == "STATE_CONFLICT"
    assert _receipt_count(workbench) == 1


def test_approval_is_bound_to_one_operator_session(workbench: WorkbenchHarness, second_session) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    second_client, _ = second_session
    response = workbench.decide(approval, client=second_client, idempotency_key="other-session")
    assert response.status_code == 403
    assert response.json()["code"] == "FORBIDDEN"
    assert _receipt_count(workbench) == 0


def test_expired_approval_is_refused_without_effect(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    with transaction(workbench.db_path) as conn:
        conn.execute(
            "UPDATE approvals SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            (approval["id"],),
        )
    response = workbench.decide(approval, idempotency_key="expired-decision")
    assert response.status_code == 409
    assert response.json()["details"]["code"] == "APPROVAL_EXPIRED"
    after = workbench.approval_for(run)
    assert after["state"] == "EXPIRED"
    assert after["request"]["status"] == "EXPIRED"
    assert _receipt_count(workbench) == 0


def test_policy_change_invalidates_pending_approval(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    changed = workbench.client.post(
        f"/api/v1/runs/{run['id']}/policy",
        json={"policy_preset_id": "deny-v1", "expected_revision": 1},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["invalidated"] == 1
    after = workbench.approval_for(run)
    assert after["state"] == "INVALIDATED"
    assert after["request"]["status"] == "INVALIDATED"
    decision = workbench.decide(approval, idempotency_key="after-policy-change")
    assert decision.status_code == 409
    assert _receipt_count(workbench) == 0


def test_run_cancel_invalidates_pending_approval(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    cancelled = workbench.client.post(f"/api/v1/runs/{run['id']}/cancel", json={})
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["invalidated"] == 1
    after = workbench.approval_for(run)
    assert after["state"] == "INVALIDATED"
    decision = workbench.decide(approval, idempotency_key="after-cancel")
    assert decision.status_code == 409
    assert _receipt_count(workbench) == 0


def test_concurrent_approvals_commit_exactly_once(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    session_id = workbench.session_id

    def attempt(key: str):
        try:
            result = decide_approval(
                workbench.settings,
                session_id=session_id,
                approval_id=approval["id"],
                decision="approve",
                reviewed_request_digest=approval["request_digest"],
                expected_version=int(approval["expected_version"]),
                reason="Concurrent approval test.",
                idempotency_key=key,
            )
            return ("committed", result["request"]["status"])
        except ConflictError:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, ["concurrent-a", "concurrent-b"]))

    assert sorted(item[0] for item in outcomes) == ["committed", "conflict"]
    assert _receipt_count(workbench) == 1
    after = workbench.approval_for(run)
    assert after["state"] == "CONSUMED"
    assert after["request"]["status"] == "AUTHORIZED"


def test_approval_for_unknown_id_is_404(workbench: WorkbenchHarness) -> None:
    response = workbench.client.get("/api/v1/approvals/apr_does_not_exist")
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


def test_audit_blocks_approval_when_chain_is_tampered(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    db_path: Path = workbench.db_path
    with transaction(db_path) as conn:
        row = conn.execute("SELECT payload_json FROM audit_events ORDER BY seq LIMIT 1").fetchone()
        tampered = str(row["payload_json"])[:-1] + ',"tampered":true}'
        conn.execute("UPDATE audit_events SET payload_json = ? WHERE seq = 1", (tampered,))
    response = workbench.decide(approval, idempotency_key="tampered-audit")
    assert response.status_code == 503
    assert response.json()["code"] == "AUDIT_INTEGRITY_FAILED"
    assert _receipt_count(workbench) == 0
