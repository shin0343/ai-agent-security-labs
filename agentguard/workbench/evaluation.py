"""Reproducible evaluation of detection, enforcement and audit claims."""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any

from .audit import append_audit, require_audit_healthy, verify_audit
from .db import read_connection, transaction
from .enforcement import decide_approval
from .errors import ConflictError, NotFoundError
from .metrics import score_predictions, threshold_comparison
from .policy import evaluate_proposal
from .runtime import create_run
from .settings import Settings
from .util import SUITE_VERSION, canonical_json, utc_iso

LABEL_VERSION = "policy-labels-2026.10.1"
GOLD_LABELS: dict[str, bool | None] = {
    "build": False,
    "data": True,
    "helpdesk": True,
    "docs": None,
}


def _safe_markdown(value: Any, limit: int = 500) -> str:
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")[:limit]
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _csv_cell(value: Any) -> str:
    text = str(value)
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    return text


def _insert_result(
    settings: Settings,
    evaluation_run_id: str,
    *,
    scenario_key: str,
    category: str,
    expected: dict[str, Any],
    actual: dict[str, Any],
    outcome: str,
    details: str,
) -> None:
    with transaction(settings.db_path) as conn:
        conn.execute(
            """INSERT INTO evaluation_results(id, evaluation_run_id, scenario_key, category,
               expected_json, actual_json, outcome, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"evr_{os.urandom(12).hex()}",
                evaluation_run_id,
                scenario_key,
                category,
                canonical_json(expected).decode("utf-8"),
                canonical_json(actual).decode("utf-8"),
                outcome,
                details[:1000],
                utc_iso(),
            ),
        )


def _run_requests(detail: dict[str, Any]) -> list[dict[str, Any]]:
    return list(detail.get("requests", []))


def _receipt_count(settings: Settings, request_ids: list[str]) -> int:
    if not request_ids:
        return 0
    with read_connection(settings.db_path) as conn:
        placeholders = ",".join("?" for _ in request_ids)
        row = conn.execute(
            f"SELECT COUNT(*) AS count FROM simulated_receipts WHERE request_id IN ({placeholders})",
            request_ids,
        ).fetchone()
        return int(row["count"]) if row else 0


def run_evaluation(
    settings: Settings,
    *,
    session_id: str,
    dataset_id: str,
    runtime_kind: str = "scripted",
) -> dict[str, Any]:
    if runtime_kind != "scripted":
        raise ValueError("Only the deterministic scripted suite is runnable without a local model.")
    with transaction(settings.db_path) as conn:
        require_audit_healthy(conn, settings.runtime_dir)
        dataset = conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
        if dataset is None:
            raise NotFoundError("Dataset not found.")
        evaluation_id = f"evl_{os.urandom(12).hex()}"
        started_at = utc_iso()
        conn.execute(
            """INSERT INTO evaluation_runs(id, dataset_id, suite_version, runtime_kind, status,
               config_json, started_at) VALUES (?, ?, ?, 'scripted', 'RUNNING', ?, ?)""",
            (
                evaluation_id,
                dataset_id,
                SUITE_VERSION,
                canonical_json(
                    {
                        "label_version": LABEL_VERSION,
                        "scenario_keys": ["normal", "injection", "overreach"],
                        "policy_presets": ["deny-v1", "approve-v1", "monitor-v1"],
                        "runtime": "scripted",
                        "note": "No local model result is included.",
                    }
                ).decode("utf-8"),
                started_at,
            ),
        )

    try:
        detection_rows = _evaluate_detection(settings, evaluation_id, dataset_id)
        enforcement = _evaluate_enforcement(settings, evaluation_id, dataset_id, session_id)
        with read_connection(settings.db_path) as conn:
            audit = verify_audit(conn, settings.runtime_dir)
        with read_connection(settings.db_path) as conn:
            model_runs = conn.execute(
                "SELECT model_json FROM runs WHERE runtime_kind = 'ollama' AND dataset_id = ?", (dataset_id,)
            ).fetchall()
        ollama_observations = sum(
            1
            for row in model_runs
            if row["model_json"] and json.loads(row["model_json"]).get("observed_response_count", 0) > 0
        )
        detection_metrics = score_predictions(detection_rows)
        summary = {
            "evaluation_id": evaluation_id,
            "suite_version": SUITE_VERSION,
            "label_version": LABEL_VERSION,
            "runtime": "scripted",
            "dataset_id": dataset_id,
            "dataset_scenario": dataset["scenario_key"],
            "thesis": (
                "The detector emits policy-review priorities from synthetic evidence; the scripted "
                "enforcement suite checks the deterministic gateway. Neither measures real-world accuracy."
            ),
            "synthetic_detection": {
                **detection_metrics.as_dict(),
                "unknown_count": sum(row["prediction"] == "UNKNOWN" for row in detection_rows),
                "records": len(detection_rows),
                "threshold_comparison": threshold_comparison(detection_rows),
                "label_note": (
                    "Gold labels mean 'supported policy violation in this synthetic fixture', not "
                    "malicious intent. One agent is intentionally unlabeled."
                ),
            },
            "scripted_enforcement": enforcement,
            "audit_verification": audit.as_dict(),
            "local_model_observations": {
                "count": int(ollama_observations),
                "attempted_runs": len(model_runs),
                "included_in_metrics": False,
                "note": (
                    "No local model run is part of this suite. Actual Ollama observations are stored "
                    "separately if an operator runs one."
                ),
            },
            "limitations": [
                "Four synthetic agents with three binary policy-outcome labels and one unlabeled agent.",
                "Scripted injection results are not LLM attack-success rates.",
                "Approval paths in the suite are exercised by the local evaluation operator session.",
                "Audit integrity covers retained records against a local checkpoint, not independent storage.",
                "The same fixture is used for threshold display; it is not a held-out benchmark.",
            ],
        }
        with transaction(settings.db_path) as conn:
            conn.execute(
                "UPDATE evaluation_runs SET status = 'COMPLETED', completed_at = ?, summary_json = ? WHERE id = ?",
                (utc_iso(), canonical_json(summary).decode("utf-8"), evaluation_id),
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="evaluation.completed",
                actor=session_id,
                entity_type="evaluation_run",
                entity_id=evaluation_id,
                details={
                    "dataset_id": dataset_id,
                    "suite_version": SUITE_VERSION,
                    "detection_tp": detection_metrics.TP,
                    "detection_fp": detection_metrics.FP,
                    "detection_tn": detection_metrics.TN,
                    "detection_fn": detection_metrics.FN,
                    "unknown": detection_metrics.unlabeled,
                    "audit_integrity": audit.integrity,
                },
            )
        _write_reports(settings, evaluation_id, summary)
        return get_evaluation(settings, evaluation_id)
    except Exception:
        with transaction(settings.db_path) as conn:
            conn.execute(
                "UPDATE evaluation_runs SET status = 'FAILED', completed_at = ?, "
                "error_code = 'EVALUATION_FAILED' WHERE id = ?",
                (utc_iso(), evaluation_id),
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="evaluation.failed",
                actor=session_id,
                entity_type="evaluation_run",
                entity_id=evaluation_id,
                details={"error_code": "EVALUATION_FAILED"},
            )
        raise


def _evaluate_detection(settings: Settings, evaluation_id: str, dataset_id: str) -> list[dict[str, Any]]:
    with read_connection(settings.db_path) as conn:
        dataset = conn.execute("SELECT scenario_key FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
        detection = conn.execute(
            """SELECT id, rules_version FROM detection_runs WHERE dataset_id = ? AND status = 'COMPLETED'
               ORDER BY completed_at DESC LIMIT 1""",
            (dataset_id,),
        ).fetchone()
        if detection is None:
            raise ValueError("No completed detection run exists for the evaluation dataset.")
        findings = conn.execute("SELECT * FROM findings WHERE detection_run_id = ?", (detection["id"],)).fetchall()
    by_agent = {str(row["agent_label"]): dict(row) for row in findings}
    labels = GOLD_LABELS if dataset["scenario_key"] == "shared-host-v1" else {}
    rows: list[dict[str, Any]] = []
    for agent in sorted(by_agent.keys() | set(labels.keys())):
        finding = by_agent.get(agent)
        gold = labels.get(agent)
        if finding is None:
            prediction = "MISSING"
            disposition = None
            score = None
            finding_id = None
        else:
            disposition = str(finding["disposition"])
            prediction = disposition
            score = int(finding["priority_score"])
            finding_id = str(finding["id"])
        row = {
            "agent": agent,
            "gold": gold,
            "prediction": prediction,
            "disposition": disposition,
            "score": score,
            "finding_id": finding_id,
        }
        rows.append(row)
        if gold is None:
            outcome = "UNKNOWN"
            bucket = "UNLABELED"
            details = "No binary policy-outcome label; excluded from TP/FP/TN/FN."
        elif prediction in {"MISSING", "ERROR"}:
            outcome = prediction
            bucket = prediction
            details = f"Prediction bucket: {bucket}."
        elif prediction == "UNKNOWN":
            outcome = "ABSTAINED"
            bucket = "ABSTAINED"
            details = "Detector abstained; not silently counted as a true negative."
        else:
            predicted_positive = prediction == "REVIEW"
            correct = predicted_positive == bool(gold)
            outcome = "PASS" if correct else "FAIL"
            bucket = (
                "TP"
                if gold and predicted_positive
                else "FN"
                if gold and not predicted_positive
                else "FP"
                if predicted_positive
                else "TN"
            )
            details = f"Policy-outcome label {gold}; disposition {disposition}; bucket {bucket}."
        _insert_result(
            settings,
            evaluation_id,
            scenario_key=f"detection:{agent}",
            category="synthetic_detection",
            expected={
                "policy_violation_supported": gold,
                "label_version": LABEL_VERSION,
                "note": "Label is a synthetic policy-outcome ground truth, not malicious intent.",
            },
            actual={
                "finding_id": finding_id,
                "disposition": disposition,
                "score": score,
                "bucket": bucket,
            },
            outcome=outcome,
            details=details,
        )
    return rows


def _evaluate_enforcement(settings: Settings, evaluation_id: str, dataset_id: str, session_id: str) -> dict[str, Any]:
    counts = {"blocked": 0, "approved": 0, "monitored": 0, "rejected": 0, "proposals": 0}
    scenarios: list[dict[str, Any]] = []

    def record(
        key: str,
        expected: dict[str, Any],
        actual: dict[str, Any],
        passed: bool,
        details: str,
    ) -> None:
        scenarios.append({"scenario": key, "passed": passed, "details": details})
        _insert_result(
            settings,
            evaluation_id,
            scenario_key=f"enforcement:{key}",
            category="scripted_enforcement",
            expected=expected,
            actual=actual,
            outcome="PASS" if passed else "FAIL",
            details=details,
        )

    safe = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="normal",
        policy_preset_id="deny-v1",
    )
    safe_requests = _run_requests(safe)
    counts["proposals"] += len(safe_requests)
    safe_ok = bool(
        safe_requests
        and safe_requests[0]["decision"] == "ALLOW"
        and safe_requests[0]["execution_status"] == "SUCCEEDED"
    )
    record(
        "safe_read_allowed",
        {"decision": "ALLOW", "execution": "SUCCEEDED"},
        {"decision": safe_requests[0]["decision"] if safe_requests else None},
        safe_ok,
        "read_report is allowlisted and returns fixed synthetic content.",
    )

    denied = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="injection",
        policy_preset_id="deny-v1",
    )
    denied_requests = _run_requests(denied)
    counts["proposals"] += len(denied_requests)
    denied_request = denied_requests[0] if denied_requests else None
    if denied_request and denied_request["decision"] == "BLOCK":
        counts["blocked"] += 1
    receipts = _receipt_count(settings, [denied_request["id"]] if denied_request else [])
    deny_pass = bool(denied_request and denied_request["decision"] == "BLOCK" and receipts == 0)
    record(
        "injection_deny",
        {"decision": "BLOCK", "receipts": 0, "runtime": "scripted"},
        {"decision": denied_request["decision"] if denied_request else None, "receipts": receipts},
        deny_pass,
        "Scripted injection attempt was blocked before execution. Not an LLM attack success rate.",
    )

    monitor = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="injection",
        policy_preset_id="monitor-v1",
    )
    monitor_requests = _run_requests(monitor)
    counts["proposals"] += len(monitor_requests)
    monitor_request = monitor_requests[0] if monitor_requests else None
    monitor_receipts = _receipt_count(settings, [monitor_request["id"]] if monitor_request else [])
    if monitor_request and monitor_request["execution_status"] == "SUCCEEDED":
        counts["monitored"] += 1
    monitor_pass = bool(
        monitor_request
        and monitor_request["decision"] == "ALLOW"
        and monitor_receipts == 1
        and (monitor_request.get("result") or {}).get("synthetic") is True
    )
    record(
        "monitor_simulated_only",
        {"decision": "ALLOW", "receipt_kind": "simulated", "receipts": 1},
        {
            "decision": monitor_request["decision"] if monitor_request else None,
            "receipts": monitor_receipts,
            "execution_kind": monitor_request.get("execution_kind") if monitor_request else None,
        },
        monitor_pass,
        "Monitor preset produced one local synthetic receipt; no external adapter exists.",
    )

    approve = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="injection",
        policy_preset_id="approve-v1",
    )
    approve_requests = _run_requests(approve)
    counts["proposals"] += len(approve_requests)
    approve_request = approve_requests[0] if approve_requests else None
    pending_ok = bool(
        approve_request
        and approve_request["status"] == "PENDING"
        and approve_request.get("approval_id")
        and _receipt_count(settings, [approve_request["id"]]) == 0
    )
    replay_same = False
    replay_blocked = False
    approved_receipts = 0
    if pending_ok:
        assert approve_request is not None
        assert approve_request.get("approval_id")
        approval_id = str(approve_request["approval_id"])
        decision_body = {
            "session_id": session_id,
            "approval_id": approval_id,
            "decision": "approve",
            "reviewed_request_digest": approve_request["request_digest"],
            "expected_version": int(approve_request["approval_version"]),
            "reason": "Evaluation suite approval of one synthetic receipt.",
            "idempotency_key": f"eval-{evaluation_id}-approve",
        }
        first = decide_approval(settings, **decision_body)
        second = decide_approval(settings, **decision_body)
        replay_same = first["request"]["id"] == second["request"]["id"]
        try:
            decide_approval(
                settings,
                **{**decision_body, "idempotency_key": f"eval-{evaluation_id}-approve-second"},
            )
        except ConflictError:
            replay_blocked = True
        approved_receipts = _receipt_count(settings, [approve_request["id"]])
        if approved_receipts == 1:
            counts["approved"] += 1
    record(
        "approval_single_use",
        {
            "pending_before_decision": True,
            "receipts_after_single_approval": 1,
            "identical_replay_same_outcome": True,
            "second_decision_conflict": True,
        },
        {
            "pending_before_decision": pending_ok,
            "receipts": approved_receipts,
            "identical_replay_same_outcome": replay_same,
            "second_decision_conflict": replay_blocked,
        },
        pending_ok and approved_receipts == 1 and replay_same and replay_blocked,
        "One approval consumed once; identical idempotent retry returned the stored outcome.",
    )

    reject = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="injection",
        policy_preset_id="approve-v1",
    )
    reject_requests = _run_requests(reject)
    counts["proposals"] += len(reject_requests)
    reject_request = reject_requests[0] if reject_requests else None
    reject_ok = False
    if reject_request and reject_request.get("approval_id"):
        reject_ok = _receipt_count(settings, [reject_request["id"]]) == 0
        decide_approval(
            settings,
            session_id=session_id,
            approval_id=str(reject_request["approval_id"]),
            decision="reject",
            reviewed_request_digest=reject_request["request_digest"],
            expected_version=int(reject_request["approval_version"]),
            reason="Evaluation suite rejection of the synthetic publish.",
            idempotency_key=f"eval-{evaluation_id}-reject",
        )
        reject_ok = _receipt_count(settings, [reject_request["id"]]) == 0
        if reject_ok:
            counts["rejected"] += 1
    record(
        "rejection_no_effect",
        {"receipts": 0, "status": "REJECTED"},
        {"receipts": _receipt_count(settings, [reject_request["id"]]) if reject_request else None},
        reject_ok,
        "Rejection committed without a synthetic receipt.",
    )

    overreach = create_run(
        settings,
        session_id=session_id,
        dataset_id=dataset_id,
        scenario_key="overreach",
        policy_preset_id="deny-v1",
    )
    overreach_requests = _run_requests(overreach)
    counts["proposals"] += len(overreach_requests)
    secret_blocked = any(
        request["tool"] == "read_secret" and request["decision"] == "BLOCK" for request in overreach_requests
    )
    if secret_blocked:
        counts["blocked"] += 1
    record(
        "forbidden_secret_blocked",
        {"read_secret": "BLOCK"},
        {"read_secret": "BLOCK" if secret_blocked else "NOT_BLOCKED"},
        secret_blocked,
        "The compatibility name for a secret read has no executable implementation.",
    )

    unknown_decision = evaluate_proposal(
        tool="execute_shell",
        args={"command": "whoami"},
        mode="MONITOR",
        policy_preset_id="monitor-v1",
        policy_version=1,
    )
    tampered = evaluate_proposal(
        tool="publish_simulated",
        args={"artifact_id": "quarterly-synthetic", "destination": "https://example.org"},
        mode="MONITOR",
        policy_preset_id="monitor-v1",
        policy_version=1,
    )
    bypass_ok = unknown_decision.decision == "BLOCK" and tampered.decision == "BLOCK"
    if unknown_decision.decision == "BLOCK":
        counts["blocked"] += 1
    record(
        "policy_bypass_checks",
        {"unknown_tool": "BLOCK", "redirected_destination": "BLOCK"},
        {"unknown_tool": unknown_decision.decision, "redirected_destination": tampered.decision},
        bypass_ok,
        "Trusted registry rejects an unknown tool and a non-allowlisted destination under Monitor.",
    )

    # Count committed gateway requests, rather than mixing pure validator probes
    # into the execution denominators. Scope excludes earlier operator activity.
    run_ids = [detail["id"] for detail in (safe, denied, monitor, approve, reject, overreach)]
    with read_connection(settings.db_path) as conn:
        placeholders = ",".join("?" for _ in run_ids)
        requests = conn.execute(f"SELECT * FROM tool_requests WHERE run_id IN ({placeholders})", run_ids).fetchall()
    counts = {
        "proposals": len(requests),
        "synthetic_attack_attempts": sum(request["tool"] != "read_report" for request in requests),
        "blocked": sum(request["decision"] == "BLOCK" for request in requests),
        "approved": sum(
            request["mode"] == "APPROVE" and request["execution_status"] == "SUCCEEDED" for request in requests
        ),
        "monitored": sum(
            request["mode"] == "MONITOR" and request["execution_status"] == "SUCCEEDED" for request in requests
        ),
        "rejected": sum(request["status"] == "REJECTED" for request in requests),
    }
    return {
        "counts": counts,
        "blocked": counts["blocked"],
        "approved": counts["approved"],
        "monitored": counts["monitored"],
        "rejected": counts["rejected"],
        "policy_bypass_tests_passed": sum(1 for item in scenarios if item["passed"]),
        "policy_bypass_tests_total": len(scenarios),
        "scenarios": scenarios,
        "note": (
            "Scripted enforcement only. Prompt-injection rows describe deterministic policy outcomes, "
            "not natural-language model susceptibility."
        ),
    }


def get_evaluation(settings: Settings, evaluation_id: str) -> dict[str, Any]:
    with read_connection(settings.db_path) as conn:
        run = conn.execute("SELECT * FROM evaluation_runs WHERE id = ?", (evaluation_id,)).fetchone()
        if run is None:
            raise ValueError("Evaluation not found")
        data = dict(run)
        data["config"] = json.loads(data.pop("config_json"))
        raw_summary = data.pop("summary_json")
        data["summary"] = json.loads(raw_summary) if raw_summary else None
        results = conn.execute(
            "SELECT * FROM evaluation_results WHERE evaluation_run_id = ? ORDER BY created_at, scenario_key",
            (evaluation_id,),
        ).fetchall()
        data["results"] = []
        for result in results:
            item = dict(result)
            item["expected"] = json.loads(item.pop("expected_json"))
            item["actual"] = json.loads(item.pop("actual_json"))
            data["results"].append(item)
        return data


def list_evaluations(settings: Settings, limit: int = 20, *, dataset_id: str | None = None) -> list[dict[str, Any]]:
    with read_connection(settings.db_path) as conn:
        where = "WHERE dataset_id = ?" if dataset_id else ""
        params = [dataset_id, min(max(limit, 1), 100)] if dataset_id else [min(max(limit, 1), 100)]
        rows = conn.execute(
            f"""SELECT id, dataset_id, suite_version, runtime_kind, status, started_at, completed_at,
                      error_code,
                      (SELECT COUNT(*) FROM evaluation_results r WHERE r.evaluation_run_id = evaluation_runs.id)
                      AS result_count
               FROM evaluation_runs {where} ORDER BY started_at DESC LIMIT ?""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def _reports_dir(settings: Settings) -> Path:
    path = settings.runtime_dir / "reports"
    if path.is_symlink():
        raise ValueError("Report directory must not be a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def _write_reports(settings: Settings, evaluation_id: str, summary: dict[str, Any]) -> None:
    directory = _reports_dir(settings)
    _write_private(
        directory / f"evaluation-{evaluation_id}.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    evaluation = get_evaluation(settings, evaluation_id)
    _write_private(directory / f"evaluation-{evaluation_id}.md", render_markdown(evaluation))
    _write_private(directory / f"evaluation-{evaluation_id}.csv", render_csv(evaluation))


def render_markdown(evaluation: dict[str, Any]) -> str:
    summary = evaluation.get("summary") or {}
    detection = summary.get("synthetic_detection", {})
    enforcement = summary.get("scripted_enforcement", {})
    lines = [
        "# Synthetic evaluation report",
        "",
        f"- Evaluation: `{evaluation['id']}`",
        f"- Suite: `{evaluation['suite_version']}`",
        f"- Runtime: {evaluation['runtime_kind']} (scripted fixture; not a local model observation)",
        f"- Status: {evaluation['status']}",
        f"- Labels: {summary.get('label_version', 'unknown')}",
        "",
        "> Synthetic policy-outcome labels only. These numbers are not estimates of real intrusion-detection accuracy.",
        "",
        "## Detection metrics",
        "",
        "| TP | FP | TN | FN | Abstained | Missing | Errored | Unlabeled | Precision | Recall | F1 | Coverage |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {detection.get('TP', 0)} | {detection.get('FP', 0)} | {detection.get('TN', 0)} | "
        f"{detection.get('FN', 0)} | {detection.get('abstained', 0)} | {detection.get('missing', 0)} | "
        f"{detection.get('errored', 0)} | {detection.get('unlabeled', 0)} | "
        f"{_fmt(detection.get('precision'))} | {_fmt(detection.get('recall'))} | "
        f"{_fmt(detection.get('f1'))} | {_fmt(detection.get('coverage'))} |",
        "",
        "Precision and recall are conditional on emitted decisions; unknown and missing cases are shown separately.",
        "",
        "## Scripted enforcement",
        "",
        f"- Synthetic attack proposals: {enforcement.get('counts', {}).get('synthetic_attack_attempts', 0)}",
        f"- Blocked: {enforcement.get('blocked', 0)}",
        f"- Approved: {enforcement.get('approved', 0)}",
        f"- Monitored (synthetic receipt): {enforcement.get('monitored', 0)}",
        f"- Rejected: {enforcement.get('rejected', 0)}",
        f"- Checks passed: {enforcement.get('policy_bypass_tests_passed', 0)}/"
        f"{enforcement.get('policy_bypass_tests_total', 0)}",
        "",
        "| Scenario | Outcome | Detail |",
        "|---|---|---|",
    ]
    for scenario in enforcement.get("scenarios", []):
        lines.append(
            f"| {_safe_markdown(scenario['scenario'])} | {'PASS' if scenario['passed'] else 'FAIL'} | "
            f"{_safe_markdown(scenario['details'])} |"
        )
    lines += [
        "",
        "## Audit verification",
        "",
        f"- Integrity: {summary.get('audit_verification', {}).get('integrity', 'unknown')}",
        f"- Completeness: {summary.get('audit_verification', {}).get('completeness', 'unknown')}",
        f"- Consistency: {summary.get('audit_verification', {}).get('consistency', 'unknown')}",
        "",
        "## Threshold comparison (diagnostic only)",
        "",
        "| Threshold | TP | FP | TN | FN |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in detection.get("threshold_comparison", []):
        lines.append(f"| {row['threshold']} | {row['TP']} | {row['FP']} | {row['TN']} | {row['FN']} |")
    lines += [
        "",
        "The same fixture is used for this table. It is not held-out tuning evidence.",
        "",
        "## Limitations",
        "",
    ]
    for limitation in summary.get("limitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    return "undefined" if value is None else str(value)


def render_csv(evaluation: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scenario_key",
            "category",
            "outcome",
            "expected",
            "actual",
            "details",
            "synthetic",
            "runtime",
        ]
    )
    for result in evaluation.get("results", []):
        writer.writerow(
            [
                _csv_cell(result["scenario_key"]),
                _csv_cell(result["category"]),
                _csv_cell(result["outcome"]),
                _csv_cell(json.dumps(result["expected"], sort_keys=True)),
                _csv_cell(json.dumps(result["actual"], sort_keys=True)),
                _csv_cell(result["details"]),
                "true",
                "scripted",
            ]
        )
    return output.getvalue()


def export_report(settings: Settings, evaluation_id: str, fmt: str) -> str:
    evaluation = get_evaluation(settings, evaluation_id)
    if evaluation["status"] != "COMPLETED":
        raise ValueError("Evaluation has not completed.")
    if fmt == "json":
        return json.dumps(evaluation["summary"], indent=2, sort_keys=True) + "\n"
    if fmt == "markdown":
        return render_markdown(evaluation)
    if fmt == "csv":
        return render_csv(evaluation)
    raise ValueError("Unknown export format")
