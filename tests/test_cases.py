"""Investigation revisions, scoped cases, export integrity and XSS-safe text."""

from __future__ import annotations

import csv
import io
import json

from agentguard.workbench.db import transaction

from .conftest import WorkbenchHarness


def _findings(workbench: WorkbenchHarness) -> list[dict]:
    response = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}&limit=20")
    assert response.status_code == 200
    return response.json()["items"]


def _create_investigation(workbench: WorkbenchHarness) -> dict:
    finding = _findings(workbench)[0]
    response = workbench.client.post(
        "/api/v1/investigations",
        json={
            "dataset_id": workbench.dataset_id,
            "title": "Synthetic Data publish review",
            "finding_ids": [finding["id"]],
            "notes": "Evidence-only review. No attribution claim.",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _evidence_ids(detail: dict) -> list[str]:
    return [item["event_id"] for item in detail["findings"][0]["evidence"]]


def _save_verdict(workbench: WorkbenchHarness, investigation: dict, **overrides):
    evidence_ids = overrides.pop("evidence_ids", _evidence_ids(investigation)[:2])
    body = {
        "verdict": "POLICY_VIOLATION_SUPPORTED",
        "rationale": "The synthetic HTTP and IDS records support review of a policy outcome.",
        "evidence_ids": evidence_ids,
        "expected_revision": investigation["revision"],
        **overrides,
    }
    return workbench.client.post(f"/api/v1/investigations/{investigation['id']}/verdicts", json=body)


def _create_case(workbench: WorkbenchHarness, investigation: dict | None = None) -> dict:
    finding = _findings(workbench)[0]
    run = workbench.run("injection", "monitor-v1")
    body = {
        "dataset_id": workbench.dataset_id,
        "title": "Synthetic shared-host publish review",
        "finding_ids": [finding["id"]],
        "request_ids": [run["requests"][0]["id"]],
        "investigation_id": investigation["id"] if investigation else None,
        "summary": "Synthetic records show a publish attempt with correlated observations.",
        "scope": "Synthetic dataset; one finding and one simulated request.",
        "analyst_conclusion": "The evidence supports a policy-outcome review, not proven compromise.",
        "recommendations": ["Retain scoped hashes.", "Do not treat IP association as ownership."],
    }
    response = workbench.client.post("/api/v1/cases", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_export_retains_selected_evidence_without_a_timestamp(workbench: WorkbenchHarness) -> None:
    case = _create_case(workbench)
    finding_id = case["current"]["finding_ids"][0]
    evidence = workbench.client.get(f"/api/v1/findings/{finding_id}").json()["evidence"]
    unknown_event = evidence[0]["event_id"]
    # Exercise the normalized unknown-time state without changing captured bytes.
    with transaction(workbench.db_path) as conn:
        conn.execute("UPDATE events SET ts_utc = NULL, parse_status = 'invalid_time' WHERE id = ?", (unknown_event,))
    exported = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "json"})
    assert exported.status_code == 200
    manifest = json.loads(exported.json()["content"])
    assert {item["event_id"] for item in manifest["evidence"]} == {item["event_id"] for item in evidence}
    assert unknown_event in {item["event_id"] for item in manifest["time_unavailable"]}
    csv_export = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "csv"})
    rows = list(csv.DictReader(io.StringIO(csv_export.json()["content"])))
    assert {item["evidence_ref"] for item in rows} == {item["ref"] for item in evidence}


def test_investigation_verdict_requires_valid_evidence_and_revision(
    workbench: WorkbenchHarness,
) -> None:
    investigation = _create_investigation(workbench)
    unsupported = _save_verdict(workbench, investigation, verdict="WITHIN_OBSERVED_SCOPE", evidence_ids=[])
    assert unsupported.status_code == 422
    stale = _save_verdict(workbench, investigation, expected_revision=99)
    assert stale.status_code == 409
    foreign = workbench.client.post(
        f"/api/v1/investigations/{investigation['id']}/verdicts",
        json={
            "verdict": "INSUFFICIENT_EVIDENCE",
            "rationale": "No valid citation.",
            "evidence_ids": ["evt_missing"],
            "expected_revision": investigation["revision"],
        },
    )
    assert foreign.status_code == 422
    saved = _save_verdict(workbench, investigation)
    assert saved.status_code == 200, saved.text
    detail = saved.json()
    assert detail["revision"] == 2
    assert detail["status"] == "REVIEWED"
    assert detail["latest_verdict"]["verdict"] == "POLICY_VIOLATION_SUPPORTED"
    assert detail["latest_verdict"]["revision"] == 2
    assert len(detail["verdicts"]) == 1


def test_stale_case_revision_is_rejected_then_appended(workbench: WorkbenchHarness) -> None:
    investigation = _create_investigation(workbench)
    saved = _save_verdict(workbench, investigation)
    assert saved.status_code == 200
    case = _create_case(workbench, investigation)
    assert case["revision"] == 1
    assert case["current"]["investigation_id"] == investigation["id"]
    assert case["current"]["request_ids"]

    body = {
        "expected_revision": 1,
        "title": "Synthetic shared-host publish review — revised",
        "summary": "Revised summary with an escaped <script>alert(1)</script> marker.",
        "scope": "Same synthetic scope.",
        "analyst_conclusion": "Policy-outcome review remains supported; attribution remains unknown.",
        "recommendations": ["Retain this revision."],
        "status": "CLOSED",
    }
    stale = workbench.client.post(f"/api/v1/cases/{case['id']}/revisions", json={**body, "expected_revision": 99})
    assert stale.status_code == 409
    revised = workbench.client.post(f"/api/v1/cases/{case['id']}/revisions", json=body)
    assert revised.status_code == 200, revised.text
    detail = revised.json()
    assert detail["revision"] == 2
    assert detail["status"] == "CLOSED"
    assert detail["current"]["title"].endswith("revised")
    assert len(detail["revisions"]) == 2
    assert detail["revisions"][1]["revision"] == 1


def test_case_exports_use_current_revision_and_escape_markdown(
    workbench: WorkbenchHarness,
) -> None:
    case = _create_case(workbench)
    body = {
        "expected_revision": 1,
        "title": "Case with <script>alert(1)</script>",
        "summary": "Summary with a pipe | and <img src=x onerror=alert(1)> marker.",
        "scope": "Synthetic scope.",
        "analyst_conclusion": "No external effect.",
        "recommendations": [],
        "status": "OPEN",
    }
    revised = workbench.client.post(f"/api/v1/cases/{case['id']}/revisions", json=body)
    assert revised.status_code == 200
    assert revised.json()["revision"] == 2

    markdown = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "markdown"})
    assert markdown.status_code == 200, markdown.text
    exported = markdown.json()
    assert exported["revision"] == 2
    assert exported["filename"].endswith("-r2.md")
    assert "Revision: 2" in exported["content"]
    assert "<script>" not in exported["content"]
    assert "&lt;script&gt;" in exported["content"]
    assert "&lt;img src=x onerror=alert(1)&gt;" in exported["content"]
    assert "Unresolved questions" in exported["content"]
    assert "which local process" in exported["content"].lower()
    assert "Synthetic case" in exported["content"]
    assert "independent tamper-proof storage" in exported["content"]
    assert exported["integration_status"] == "manual_export_only"
    assert exported["audit_verification"]["integrity"] == "valid"

    json_export = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "json"})
    assert json_export.status_code == 200
    manifest = json.loads(json_export.json()["content"])
    assert manifest["revision"] == 2
    assert manifest["synthetic_classification"].startswith("synthetic")
    assert manifest["requests"][0]["request_id"] == case["current"]["request_ids"][0]
    assert manifest["evidence"]

    csv_export = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "csv"})
    assert csv_export.status_code == 200
    rows = list(csv.DictReader(io.StringIO(csv_export.json()["content"])))
    assert rows
    assert rows[0]["revision"] == "2"
    assert rows[0]["synthetic"] == "true"

    detail = workbench.client.get(f"/api/v1/cases/{case['id']}").json()
    assert len(detail["exports"]) == 3
    assert all(item["revision"] == 2 for item in detail["exports"])


def test_case_scope_validation_rejects_foreign_findings(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post(
        "/api/v1/cases",
        json={
            "dataset_id": "ds_foreign",
            "title": "Invalid case",
            "finding_ids": [_findings(workbench)[0]["id"]],
            "summary": "Summary.",
            "scope": "Scope.",
            "analyst_conclusion": "Conclusion.",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_case_export_fails_closed_when_evidence_is_mutated(workbench: WorkbenchHarness) -> None:
    case = _create_case(workbench)
    with transaction(workbench.db_path) as conn:
        source = conn.execute(
            """SELECT e.source_id FROM finding_evidence fe
               JOIN events e ON e.id = fe.event_id LIMIT 1"""
        ).fetchone()
        conn.execute(
            "UPDATE source_blobs SET content = ? WHERE id = ?",
            (b"mutated snapshot", source["source_id"]),
        )
    response = workbench.client.post(f"/api/v1/cases/{case['id']}/exports", json={"format": "markdown"})
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    assert "immutable-snapshot integrity" in response.json()["message"]
