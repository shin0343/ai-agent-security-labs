"""Deterministic tool policy, scripted runtime and synthetic-only effects."""

from __future__ import annotations

import json

import pytest

from agentguard.workbench.db import read_connection
from agentguard.workbench.policy import TOOLS, evaluate_proposal

from .conftest import WorkbenchHarness


def _receipt_count(workbench: WorkbenchHarness) -> int:
    with read_connection(workbench.db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM simulated_receipts").fetchone()
        return int(row["count"])


def test_safe_read_is_allowed_in_every_preset(workbench: WorkbenchHarness) -> None:
    for preset in ("deny-v1", "approve-v1", "monitor-v1"):
        run = workbench.run("normal", preset)
        assert run["status"] == "COMPLETED"
        request = run["requests"][0]
        assert request["tool"] == "read_report"
        assert request["decision"] == "ALLOW"
        assert request["execution_status"] == "SUCCEEDED"
        assert request["result"]["synthetic"] is True
        assert "Synthetic quarterly report" in request["result"]["content"]


def test_injection_is_blocked_under_deny_without_effect(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "deny-v1")
    request = run["requests"][0]
    assert run["status"] == "COMPLETED"
    assert request["status"] == "BLOCKED"
    assert request["decision_reason_code"] == "PRESET_DENY"
    assert request["execution_status"] == "NOT_STARTED"
    assert request["result"] is None
    assert request["approval_id"] is None
    assert _receipt_count(workbench) == 0


def test_monitor_creates_one_explicitly_synthetic_local_receipt(
    workbench: WorkbenchHarness,
) -> None:
    run = workbench.run("injection", "monitor-v1")
    request = run["requests"][0]
    assert request["decision"] == "ALLOW"
    assert request["decision_reason_code"] == "MONITOR_SIMULATION"
    assert request["execution_status"] == "SUCCEEDED"
    receipt_id = request["result"]["receipt_id"]
    assert receipt_id.startswith("rcp_")
    assert _receipt_count(workbench) == 1
    assert not (workbench.runtime_dir / "outbox").exists()
    with read_connection(workbench.db_path) as conn:
        receipt = conn.execute(
            "SELECT payload_json, synthetic FROM simulated_receipts WHERE id = ?", (receipt_id,)
        ).fetchone()
    payload = json.loads(receipt["payload_json"])
    assert receipt["synthetic"] == 1
    assert payload["synthetic"] is True
    assert "No external network request" in payload["note"]


def test_approve_waits_and_has_no_effect_before_decision(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    request = run["requests"][0]
    assert run["status"] == "WAITING_APPROVAL"
    assert request["decision"] == "REQUIRE_APPROVAL"
    assert request["status"] == "PENDING"
    assert request["approval_id"].startswith("apr_")
    assert request["execution_status"] == "NOT_STARTED"
    assert request["result"] is None
    assert _receipt_count(workbench) == 0


def test_rejection_never_executes(workbench: WorkbenchHarness) -> None:
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    response = workbench.decide(approval, decision="reject", reason="Not authorized for this test.")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["request"]["status"] == "REJECTED"
    assert body["request"]["execution_status"] == "NOT_STARTED"
    assert body["request"]["result"] is None
    assert _receipt_count(workbench) == 0


def test_secret_read_is_blocked_in_deny_and_approve(workbench: WorkbenchHarness) -> None:
    for preset in ("deny-v1", "approve-v1"):
        run = workbench.run("overreach", preset)
        secret = run["requests"][0]
        assert secret["tool"] == "read_secret"
        assert secret["decision"] == "BLOCK"
        assert secret["decision_reason_code"] == "TOOL_FORBIDDEN"
        assert secret["result"] is None
    assert "read_secret" in TOOLS
    assert "execute_shell" not in TOOLS


def test_boundary_aware_run_records_no_tool_call(workbench: WorkbenchHarness) -> None:
    run = workbench.run("boundary_aware", "monitor-v1")
    assert run["status"] == "COMPLETED"
    assert run["requests"] == []
    no_call = next(item for item in run["trace"] if item["kind"] == "no_tool_call")
    assert no_call["text"].startswith("NO_TOOL_CALL:")
    assert _receipt_count(workbench) == 0


@pytest.mark.parametrize(
    ("tool", "args", "reason_code"),
    [
        ("execute_shell", {"command": "whoami"}, "UNKNOWN_TOOL"),
        (
            "publish_simulated",
            {"artifact_id": "quarterly-synthetic", "destination": "https://example.org"},
            "INVALID_ARGUMENTS",
        ),
        (
            "publish_simulated",
            {"artifact_id": "quarterly-synthetic", "destination": "../../secrets"},
            "INVALID_ARGUMENTS",
        ),
        (
            "publish_simulated",
            {
                "artifact_id": "quarterly-synthetic",
                "destination": "demo-internal-outbox",
                "extra": "x",
            },
            "INVALID_ARGUMENTS",
        ),
        (
            "publish_simulated",
            {"artifact_id": ["quarterly-synthetic"], "destination": "demo-internal-outbox"},
            "INVALID_ARGUMENTS",
        ),
        ("publish_simulated", {}, "INVALID_ARGUMENTS"),
        ("read_secret", {"name": "production-env"}, "TOOL_FORBIDDEN"),
    ],
)
def test_tool_registry_bypass_attempts_fail_closed(tool: str, args: dict, reason_code: str) -> None:
    outcome = evaluate_proposal(
        tool=tool,
        args=args,
        mode="MONITOR",
        policy_preset_id="monitor-v1",
        policy_version=1,
    )
    assert outcome.decision == "BLOCK"
    assert outcome.reason_code == reason_code


def test_unknown_policy_mode_fails_closed() -> None:
    outcome = evaluate_proposal(
        tool="publish_simulated",
        args={"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox"},
        mode="BYPASS",
        policy_preset_id="monitor-v1",
        policy_version=1,
    )
    assert outcome.decision == "BLOCK"
    assert outcome.reason_code == "UNKNOWN_POLICY"


def test_browser_cannot_inject_a_per_request_mode(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post(
        "/api/v1/runs",
        json={
            "dataset_id": workbench.dataset_id,
            "scenario_key": "injection",
            "policy_preset_id": "deny-v1",
            "mode": "MONITOR",
            "policy_version": 999,
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_no_shell_network_or_secret_tool_exists() -> None:
    assert set(TOOLS) == {"read_report", "publish_simulated", "read_secret"}
    for definition in TOOLS.values():
        assert "shell" not in definition.description.lower()
        assert "network" not in definition.name.lower()
    assert TOOLS["read_secret"].effect.lower().startswith("always blocked")
