"""Independent security audit suite.

Written from a red-team perspective and kept separate from the functional
suites: it asserts gateway, approval-session, audit and export properties that
must hold even when the caller is hostile. Everything is local and synthetic.
"""

from __future__ import annotations

import pytest

from agentguard.workbench.db import read_connection, transaction
from agentguard.workbench.settings import Settings
from agentguard.workbench.util import FIXTURE_DIR

# Every mutating API route. The session/CSRF guards must hold uniformly.
MUTATING_ROUTES: list[tuple[str, str, dict]] = [
    ("POST", "/api/v1/datasets/sample/import", {}),
    ("POST", "/api/v1/datasets/anything/detect", {}),
    ("POST", "/api/v1/session/exchange", {"code": "FAKE-CODE-NOT-REAL-0000"}),
    ("POST", "/api/v1/evaluations", {"dataset_id": "x"}),
    ("POST", "/api/v1/runs", {"dataset_id": "x", "scenario_key": "normal", "policy_preset_id": "deny-v1"}),
    ("POST", "/api/v1/runs/abc/cancel", {}),
    ("POST", "/api/v1/runs/abc/policy", {"policy_preset_id": "deny-v1", "expected_revision": 1}),
    (
        "POST",
        "/api/v1/investigations",
        {"dataset_id": "x", "title": "t", "finding_ids": ["f"]},
    ),
    (
        "POST",
        "/api/v1/investigations/abc/verdicts",
        {"verdict": "INSUFFICIENT_EVIDENCE", "rationale": "r", "expected_revision": 1},
    ),
    (
        "POST",
        "/api/v1/approvals/abc/decision",
        {
            "decision": "approve",
            "reviewed_request_digest": "0" * 64,
            "expected_version": 1,
            "reason": "r",
        },
    ),
    (
        "POST",
        "/api/v1/cases",
        {
            "dataset_id": "x",
            "title": "t",
            "finding_ids": ["f"],
            "summary": "s",
            "scope": "c",
            "analyst_conclusion": "a",
        },
    ),
    (
        "POST",
        "/api/v1/cases/abc/revisions",
        {
            "expected_revision": 1,
            "title": "t",
            "summary": "s",
            "scope": "c",
            "analyst_conclusion": "a",
        },
    ),
    ("POST", "/api/v1/cases/abc/exports", {"format": "markdown"}),
    ("POST", "/api/v1/audit/verifications", {}),
]

NO_SESSION_ROUTES = [route for route in MUTATING_ROUTES if route[1] != "/api/v1/session/exchange"]
REAL_SESSION_ROUTES = [route for route in MUTATING_ROUTES if route[1] != "/api/v1/session/exchange"]


def _client(workbench, token: str | None):
    from fastapi.testclient import TestClient

    fresh = TestClient(workbench.app, base_url=workbench.base_url)
    if token:
        fresh.cookies.set("ag_session", token, domain="127.0.0.1", path="/")
    fresh.headers.update({"Origin": workbench.base_url})
    return fresh


def _csrfless_client(workbench, token: str):
    """A real cookie without the CSRF header: authenticated but not mutation-safe."""
    fresh = _client(workbench, token)
    return fresh


@pytest.mark.parametrize("method,path,body", NO_SESSION_ROUTES)
def test_mutation_without_session_is_never_processed(method: str, path: str, body: dict, workbench) -> None:
    """No cookie at all: nothing mutating may execute (401) or fall through oddly."""
    fresh = _client(workbench, None)
    response = fresh.request(method, path, json=body)
    assert response.status_code == 401, (path, response.text, response.status_code)


@pytest.mark.parametrize("method,path,body", NO_SESSION_ROUTES)
def test_forged_cookie_is_rejected(method: str, path: str, body: dict, workbench) -> None:
    fresh = _client(workbench, "forged-token-not-in-store")
    response = fresh.request(method, path, json=body)
    assert response.status_code == 401, (path, response.text, response.status_code)


@pytest.mark.parametrize("method,path,body", REAL_SESSION_ROUTES)
def test_authenticated_mutation_without_csrf_is_forbidden(
    method: str, path: str, body: dict, workbench, second_session
) -> None:
    """Cookie present, CSRF header absent: mutation must fail closed."""
    _second_client, second_meta = second_session
    fresh = _csrfless_client(workbench, second_meta["token"])
    response = fresh.request(method, path, json=body)
    assert response.status_code == 403, (path, response.text, response.status_code)
    assert response.json()["code"] == "FORBIDDEN"


def test_bootstrap_code_cannot_be_reused(workbench) -> None:
    # The fixture consumed the real bootstrap code during setup.
    fresh = _client(workbench, None)
    response = fresh.post(
        "/api/v1/session/exchange",
        json={"code": workbench.bootstrap_code},
    )
    assert response.status_code == 403
    assert "already been used" in response.json()["message"]


def test_no_browser_reachable_proposal_route_exists(workbench) -> None:
    """No API surface lets a client submit a raw tool proposal or execution."""
    for path in ("/api/v1/propose", "/api/v1/tool/call", "/api/v1/executions", "/api/v1/tools/read_report"):
        response = workbench.client.get(
            path,
        )
        assert response.status_code == 404, path
    for scenario in ("raw_shell", "self_approve", "monitor_bulk"):
        response = workbench.client.post(
            "/api/v1/runs",
            json={
                "dataset_id": workbench.dataset_id,
                "scenario_key": scenario,
                "policy_preset_id": "deny-v1",
            },
        )
        assert response.status_code in {422, 403}, scenario  # strict literal enum


def test_untrusted_note_is_inert_and_approval_claims_stay_untrusted(workbench) -> None:
    with read_connection(workbench.db_path) as conn:
        sources = {
            str(row["filename"]): dict(row) for row in conn.execute("SELECT filename, parser_version FROM source_blobs")
        }
        assert "untrusted_note.txt" in sources
        assert sources["untrusted_note.txt"]["parser_version"] == "text-inert-v1"
        note_events = conn.execute(
            """SELECT COUNT(*) FROM events e
               JOIN source_blobs s ON s.id = e.source_id WHERE s.filename = 'untrusted_note.txt'"""
        ).fetchone()[0]
        assert note_events == 0, "the untrusted note must not become queryable events"
        limitations = " ".join(str(row["limitations"]) for row in conn.execute("SELECT limitations FROM findings"))
    assert "untrusted" in limitations.lower()


def test_hostile_approval_sequence_leaves_one_commit(workbench, second_session) -> None:
    second_client, _second_meta = second_session
    run_a = workbench.run("injection", "approve-v1")
    approval_a = workbench.approval_for(run_a)

    # 1. Wrong digest: decision refused, approval stays pending.
    wrong = workbench.decide(approval_a, digest="f" * 64, idempotency_key="indep-1")
    assert wrong.status_code == 409
    assert wrong.json()["details"]["code"] == "REQUEST_DIGEST_MISMATCH"
    after = workbench.client.get(f"/api/v1/approvals/{approval_a['id']}").json()
    assert after["state"] == "PENDING"

    # 2. A different local operator session cannot decide someone else's approval.
    stolen = second_client.post(
        f"/api/v1/approvals/{approval_a['id']}/decision",
        json={
            "decision": "approve",
            "reviewed_request_digest": approval_a["request_digest"],
            "expected_version": 1,
            "reason": "attempt to decide another operator's approval",
        },
        headers={"Idempotency-Key": "indep-2"},
    )
    assert stolen.status_code == 403
    assert "bound to a different local operator session" in stolen.json()["message"]

    # 3. Booleans are not integers (strict typing) even at the version check.
    malformed = workbench.client.post(
        f"/api/v1/approvals/{approval_a['id']}/decision",
        json={
            "decision": "approve",
            "reviewed_request_digest": approval_a["request_digest"],
            "expected_version": True,
            "reason": "bool version",
        },
        headers={"Idempotency-Key": "indep-3"},
    )
    assert malformed.status_code == 422

    # 4. Commit exactly once; replay returns the stored response; new key conflicts.
    ok = workbench.decide(approval_a, idempotency_key="indep-4")
    assert ok.status_code == 200
    assert ok.json()["committed"] is True
    request_id = run_a["requests"][0]["id"]
    with read_connection(workbench.db_path) as conn:
        assert (
            conn.execute("SELECT COUNT(*) FROM simulated_receipts WHERE request_id = ?", (request_id,)).fetchone()[0]
            == 1
        )
    replay = workbench.decide(approval_a, idempotency_key="indep-4")
    assert replay.status_code == 200
    assert replay.json()["request"]["id"] == request_id
    fresh_key = workbench.decide(approval_a, idempotency_key="indep-5")
    assert fresh_key.status_code == 409
    with read_connection(workbench.db_path) as conn:
        assert (
            conn.execute("SELECT COUNT(*) FROM simulated_receipts WHERE request_id = ?", (request_id,)).fetchone()[0]
            == 1
        )


def test_idempotency_keys_are_scoped_per_session(workbench, second_session) -> None:
    second_client, _meta = second_session
    run_a = workbench.run("injection", "approve-v1")
    approval_a = workbench.approval_for(run_a)
    ok_a = workbench.decide(approval_a, idempotency_key="shared-key")
    assert ok_a.status_code == 200
    assert ok_a.json()["approval_id"] == approval_a["id"]

    run_b = second_client.post(
        "/api/v1/runs",
        json={
            "dataset_id": workbench.dataset_id,
            "scenario_key": "injection",
            "policy_preset_id": "approve-v1",
        },
    )
    assert run_b.status_code == 200, run_b.text
    approval_b = run_b.json()["requests"][0]["approval_id"]
    ok_b = second_client.post(
        f"/api/v1/approvals/{approval_b}/decision",
        json={
            "decision": "approve",
            "reviewed_request_digest": run_b.json()["requests"][0]["request_digest"],
            "expected_version": 1,
            "reason": "different session, same key value",
        },
        headers={"Idempotency-Key": "shared-key"},
    )
    assert ok_b.status_code == 200, ok_b.text
    assert ok_b.json()["approval_id"] == approval_b
    with read_connection(workbench.db_path) as conn:
        receipts = conn.execute("SELECT COUNT(*) FROM simulated_receipts").fetchone()[0]
        assert receipts >= 2


def test_markdown_export_neutralises_backticks_in_every_code_span(workbench) -> None:
    """Analyst text may contain backticks; exported Markdown must not change meaning."""
    needle = "' [audit-exfiltration](https://attacker.invalid/) '"
    backticked = (needle + " `span`", needle)
    run = workbench.run("injection", "deny-v1")
    findings = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}").json()
    assert findings["items"]
    case = workbench.client.post(
        "/api/v1/cases",
        json={
            "dataset_id": workbench.dataset_id,
            "title": "Backtick breakout probe `span`",
            "finding_ids": [findings["items"][0]["id"]],
            "request_ids": [run["requests"][0]["id"]],
            "summary": f"Summary mentions {backticked[0]} in prose.",
            "scope": "Local synthetic scope only.",
            "analyst_conclusion": f"Conclusion citing {backticked[1]} verbatim.",
        },
    )
    assert case.status_code == 200, case.text
    case_id = case.json()["id"]
    export = workbench.client.post(f"/api/v1/cases/{case_id}/exports", json={"format": "markdown"})
    assert export.status_code == 200
    content = export.json()["content"]
    parameters_line = next(line for line in content.splitlines() if line.startswith("- Parameters: `"))
    # After the opening backtick there must be no second backtick before the closing one.
    inner = parameters_line.removeprefix("- Parameters: `")
    assert "`" not in inner.rstrip("`"), parameters_line
    # Raw breakout constructs must be gone; text must remain auditable.
    assert "span`" not in content  # backticks of analyst text replaced
    assert "audit-exfiltration" in content


def test_audit_tamper_blocks_mutations_and_honest_valid_chain_message(workbench) -> None:
    # First: the untampered chain reports validity while disclaiming independence.
    baseline = workbench.client.get("/api/v1/audit/summary").json()
    assert baseline["integrity"] == "valid"
    assert "not independent tamper-proof storage" in baseline["message"]

    # Tamper with a retained payload directly in the local database.
    with transaction(workbench.db_path) as conn:
        row = conn.execute("SELECT payload_json FROM audit_events WHERE seq = 2").fetchone()
        assert row is not None
        original = str(row["payload_json"])
        needle = '"findings":4'
        if needle not in original:
            pytest.skip("fixture layout changed; keep this test data-honest")
        tampered = original.replace(needle, '"findings":3', 1)
        conn.execute("UPDATE audit_events SET payload_json = ? WHERE seq = 2", (tampered,))

    report = workbench.client.get("/api/v1/audit/summary").json()
    assert report["integrity"] == "invalid"
    assert report["safe_for_mutations"] is False
    failed = workbench.client.post(
        "/api/v1/runs",
        json={
            "dataset_id": workbench.dataset_id,
            "scenario_key": "normal",
            "policy_preset_id": "deny-v1",
        },
    )
    assert failed.status_code == 503
    assert failed.json()["code"] == "AUDIT_INTEGRITY_FAILED"


def test_evaluation_keeps_model_observations_separate(workbench) -> None:
    created = workbench.client.post("/api/v1/evaluations", json={"dataset_id": workbench.dataset_id})
    assert created.status_code == 200
    summary = created.json()["summary"]
    model = summary["local_model_observations"]
    assert model["count"] == 0
    assert model["included_in_metrics"] is False
    assert "No local model run is part of this suite" in model["note"]
    enforcement = summary["scripted_enforcement"]
    assert enforcement["policy_bypass_tests_passed"] == 7
    assert enforcement["policy_bypass_tests_total"] == 7
    assert "not natural-language model susceptibility" in enforcement["note"]
    detection = summary["synthetic_detection"]
    assert (detection["TP"], detection["FP"], detection["TN"], detection["FN"]) == (2, 0, 1, 0)
    assert detection["unlabeled"] == 1


def test_cross_dataset_case_references_are_rejected(workbench) -> None:
    second_settings = Settings(
        db_path=workbench.runtime_dir / "probe-second.db",
        runtime_dir=workbench.runtime_dir / "probe-second",
        fixture_dir=FIXTURE_DIR,
        frontend_dist=workbench.settings.frontend_dist,
    )
    from agentguard.workbench.bootstrap import initialize

    second = initialize(second_settings)
    assert second["status"] == "READY"
    with read_connection(second_settings.db_path) as conn:
        foreign_finding = str(conn.execute("SELECT id FROM findings LIMIT 1").fetchone()[0])
    response = workbench.client.post(
        "/api/v1/cases",
        json={
            "dataset_id": workbench.dataset_id,
            "title": "Foreign reference probe",
            "finding_ids": [foreign_finding],
            "summary": "Should not resolve.",
            "scope": "Local.",
            "analyst_conclusion": "Local.",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_unknown_api_prefix_falls_back_to_json_404(workbench) -> None:
    fresh = _client(workbench, None)
    response = fresh.get("/api/v1/nonexistent")
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"
    assert response.headers.get("content-type", "").startswith("application/json")
