"""API read models, dataset state and scoped run validation."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agentguard.workbench.db import transaction
from agentguard.workbench.errors import ValidationError
from agentguard.workbench.runtime import create_run
from agentguard.workbench.util import utc_iso

from .conftest import WorkbenchHarness


def test_dataset_and_overview_are_derived_from_persisted_state(
    workbench: WorkbenchHarness,
) -> None:
    datasets = workbench.client.get("/api/v1/datasets")
    assert datasets.status_code == 200
    items = datasets.json()["items"]
    assert len(items) == 1
    dataset = items[0]
    assert dataset["id"] == workbench.dataset_id
    assert dataset["data_class"] == "synthetic"
    assert dataset["is_sample"] == 1
    assert dataset["event_count"] == 14
    assert dataset["manifest"]["event_count"] == 14
    assert len(dataset["manifest"]["files"]) == 8

    overview = workbench.client.get(f"/api/v1/overview?dataset_id={workbench.dataset_id}")
    assert overview.status_code == 200
    body = overview.json()
    assert body["empty"] is False
    assert body["finding_counts"] == {"REVIEW": 2, "LOW": 1, "UNKNOWN": 1}
    assert body["investigation_counts"] == {"OPEN": 0, "REVIEWED": 0, "CLOSED": 0}
    assert body["case_counts"] == {"OPEN": 0, "CLOSED": 0}
    assert body["audit_summary"]["integrity"] == "valid"
    assert body["coverage"]["event_count"] == 14
    assert body["coverage"]["source_count"] == 8
    assert all(
        source["event_count"] >= 1
        for source in body["coverage"]["sources"]
        if source["filename"] != "untrusted_note.txt"
    )
    assert "not a probability" in body["disclaimer"]
    assert body["scope"]["data_class"] == "synthetic"


def test_findings_expose_correlation_edges_and_uncertainty(
    workbench: WorkbenchHarness,
) -> None:
    response = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}&limit=100")
    assert response.status_code == 200
    assert response.json()["counts"] == {"REVIEW": 2, "LOW": 1, "UNKNOWN": 1}
    findings = response.json()["items"]
    assert [item["agent_label"] for item in findings[:2]] == ["data", "helpdesk"]
    data_finding = findings[0]
    detail = workbench.client.get(f"/api/v1/findings/{data_finding['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["disposition"] == "REVIEW"
    assert body["priority_score"] == 95
    assert body["correlation_edges"]
    assert body["evidence_integrity"] == "valid"
    assert "do not prove" in body["limitations"]
    assert any("process" in unknown.lower() for unknown in body["unknowns"])
    assert body["evidence"]
    assert all(item["ref"].count(":") == 1 for item in body["evidence"])

    docs = next(item for item in findings if item["agent_label"] == "docs")
    assert docs["disposition"] == "UNKNOWN"
    docs_detail = workbench.client.get(f"/api/v1/findings/{docs['id']}").json()
    assert "insufficient" in docs_detail["interpretation"].lower() or "unknown" in docs_detail["interpretation"].lower()


def test_sample_import_is_idempotent_and_policy_registry_is_server_owned(
    workbench: WorkbenchHarness,
) -> None:
    imported = workbench.client.post("/api/v1/datasets/sample/import", json={})
    assert imported.status_code == 200, imported.text
    assert imported.json()["status"] == "READY"
    assert imported.json()["created"] is False
    assert imported.json()["dataset_id"] == workbench.dataset_id

    policies = workbench.client.get("/api/v1/policies")
    assert policies.status_code == 200
    body = policies.json()
    assert {preset["id"] for preset in body["presets"]} == {
        "deny-v1",
        "approve-v1",
        "monitor-v1",
    }
    assert {tool["name"] for tool in body["tools"]} == {
        "read_report",
        "publish_simulated",
        "read_secret",
    }
    assert next(tool for tool in body["tools"] if tool["name"] == "read_secret")["always_blocked"] is True
    assert "cannot select" in body["note"]


def test_run_contract_rejects_unknown_values_and_disabled_model(
    workbench: WorkbenchHarness,
) -> None:
    base = {
        "dataset_id": workbench.dataset_id,
        "scenario_key": "normal",
        "policy_preset_id": "deny-v1",
        "runtime_kind": "scripted",
    }
    unknown_dataset = workbench.client.post("/api/v1/runs", json={**base, "dataset_id": "ds_missing"})
    assert unknown_dataset.status_code == 404
    unknown_preset = workbench.client.post("/api/v1/runs", json={**base, "policy_preset_id": "bypass-v1"})
    assert unknown_preset.status_code == 422
    unknown_scenario = workbench.client.post("/api/v1/runs", json={**base, "scenario_key": "unsupported"})
    assert unknown_scenario.status_code == 422
    model_disabled = workbench.client.post("/api/v1/runs", json={**base, "runtime_kind": "ollama"})
    assert model_disabled.status_code == 422
    assert "disabled" in model_disabled.json()["message"].lower()


def test_linked_investigation_must_match_dataset(workbench: WorkbenchHarness) -> None:
    finding = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}&limit=1").json()["items"][0]
    investigation = workbench.client.post(
        "/api/v1/investigations",
        json={
            "dataset_id": workbench.dataset_id,
            "title": "Dataset scope test",
            "finding_ids": [finding["id"]],
        },
    ).json()
    with transaction(workbench.db_path) as conn:
        conn.execute(
            """INSERT INTO datasets(id, name, scenario_key, data_class, manifest_json,
               manifest_sha256, is_sample, created_at)
               VALUES ('ds_other', 'Other synthetic dataset', 'other-v1', 'synthetic',
               '{}', 'other-manifest', 0, ?)""",
            (utc_iso(),),
        )
        conn.execute(
            "UPDATE investigations SET dataset_id = 'ds_other' WHERE id = ?",
            (investigation["id"],),
        )
    response = workbench.client.post(
        "/api/v1/runs",
        json={
            "dataset_id": workbench.dataset_id,
            "scenario_key": "normal",
            "policy_preset_id": "deny-v1",
            "investigation_id": investigation["id"],
        },
    )
    assert response.status_code == 422
    assert "different dataset" in response.json()["message"]


def test_ollama_endpoint_must_remain_loopback(workbench: WorkbenchHarness) -> None:
    for endpoint in (
        "http://example.org:11434/api/chat",
        "https://127.0.0.1:11434/api/chat",
        "http://user:pass@127.0.0.1:11434/api/chat",
    ):
        settings = replace(
            workbench.settings,
            enable_ollama=True,
            ollama_endpoint=endpoint,
        )
        with pytest.raises(ValidationError, match="loopback"):
            create_run(
                settings,
                session_id=workbench.session_id,
                dataset_id=workbench.dataset_id,
                scenario_key="normal",
                policy_preset_id="deny-v1",
                runtime_kind="ollama",
            )


def test_pending_approval_appears_in_overview_attention(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    overview = workbench.client.get(f"/api/v1/overview?dataset_id={workbench.dataset_id}").json()
    attention = overview["attention"]
    assert any(item["kind"] == "approval" and item["id"] == approval["id"] for item in attention)
    pending = overview["pending_approvals"]
    assert pending[0]["approval_id"] == approval["id"]
    assert pending[0]["tool"] == "publish_simulated"
    assert overview["policy_counts"]["REQUIRE_APPROVAL"] == 1


def test_session_expiry_is_enforced(workbench: WorkbenchHarness) -> None:
    with transaction(workbench.db_path) as conn:
        conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z' WHERE revoked_at IS NULL")
    response = workbench.client.get("/api/v1/session")
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHENTICATED"


def test_trace_and_request_detail_are_complete(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "deny-v1")
    assert run["trace"][0]["kind"] == "input"
    assert any(item["kind"] == "proposal" for item in run["trace"])
    request = run["requests"][0]
    assert request["run_id"] == run["id"]
    assert request["request_digest"]
    assert request["args_digest"]
    assert request["effect"]
    assert request["args_digest"] != request["request_digest"]
    detail = workbench.client.get(f"/api/v1/requests/{request['id']}")
    assert detail.status_code == 200
    assert detail.json()["tool"] == "publish_simulated"
    listing = workbench.client.get(f"/api/v1/requests?dataset_id={workbench.dataset_id}&limit=10")
    assert listing.status_code == 200
    assert listing.json()["items"]
    traces = workbench.client.get(f"/api/v1/runs?dataset_id={workbench.dataset_id}")
    assert traces.status_code == 200
    assert traces.json()["items"][0]["id"] == run["id"]
    detail_run = workbench.client.get(f"/api/v1/runs/{run['id']}")
    assert detail_run.status_code == 200
    assert detail_run.json()["requests"][0]["id"] == request["id"]
