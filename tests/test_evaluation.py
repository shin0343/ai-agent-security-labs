"""Metric math, reproducible scripted evaluation and report exports."""

from __future__ import annotations

import csv
import io
import json
import stat

from agentguard.workbench.metrics import score_predictions, threshold_comparison

from .conftest import WorkbenchHarness


def test_metric_math_keeps_unknown_and_abstention_separate() -> None:
    records = [
        {"gold": True, "prediction": "REVIEW"},
        {"gold": True, "prediction": "LOW"},
        {"gold": False, "prediction": "REVIEW"},
        {"gold": False, "prediction": "LOW"},
        {"gold": True, "prediction": "UNKNOWN"},
        {"gold": False, "prediction": "MISSING"},
        {"gold": True, "prediction": "ERROR"},
        {"gold": None, "prediction": "REVIEW"},
    ]
    metrics = score_predictions(records).as_dict()
    assert metrics["TP"] == 1
    assert metrics["FP"] == 1
    assert metrics["TN"] == 1
    assert metrics["FN"] == 1
    assert metrics["abstained"] == 1
    assert metrics["missing"] == 1
    assert metrics["errored"] == 1
    assert metrics["unlabeled"] == 1
    assert metrics["known_total"] == 7
    assert metrics["emitted"] == 4
    assert metrics["coverage"] == 0.5714
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5


def test_metric_undefined_cases_are_none() -> None:
    metrics = score_predictions([{"gold": None, "prediction": "UNKNOWN"}]).as_dict()
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["f1"] is None
    assert metrics["coverage"] is None
    assert metrics["unlabeled"] == 1


def test_threshold_comparison_is_explicitly_diagnostic() -> None:
    rows = threshold_comparison(
        [
            {"gold": True, "prediction": "REVIEW", "disposition": "REVIEW", "score": 90},
            {"gold": False, "prediction": "LOW", "disposition": "LOW", "score": 10},
            {"gold": None, "prediction": "UNKNOWN", "disposition": "UNKNOWN", "score": 30},
        ]
    )
    assert len(rows) == 6
    assert all("not tuning evidence" in row["caveat"] for row in rows)
    assert {row["threshold"] for row in rows} == {0, 20, 40, 60, 80, 90}


def test_full_evaluation_is_reproducible_and_keeps_claims_separate(
    workbench: WorkbenchHarness,
) -> None:
    response = workbench.client.post("/api/v1/evaluations", json={"dataset_id": workbench.dataset_id})
    assert response.status_code == 200, response.text
    evaluation = response.json()
    assert evaluation["status"] == "COMPLETED"
    assert evaluation["runtime_kind"] == "scripted"
    summary = evaluation["summary"]
    detection = summary["synthetic_detection"]
    assert (detection["TP"], detection["FP"], detection["TN"], detection["FN"]) == (2, 0, 1, 0)
    assert detection["precision"] == 1.0
    assert detection["recall"] == 1.0
    assert detection["f1"] == 1.0
    assert detection["unlabeled"] == 1
    assert detection["coverage"] == 1.0
    assert "not" in detection["label_note"].lower()

    enforcement = summary["scripted_enforcement"]
    assert enforcement["blocked"] == 3
    assert enforcement["approved"] == 1
    assert enforcement["monitored"] == 1
    assert enforcement["rejected"] == 1
    assert enforcement["policy_bypass_tests_passed"] == enforcement["policy_bypass_tests_total"] == 7
    assert all(item["passed"] for item in enforcement["scenarios"])
    assert "not natural-language model susceptibility" in enforcement["note"]

    assert summary["audit_verification"]["integrity"] == "valid"
    assert summary["audit_verification"]["completeness"] == "checkpoint_matched"
    assert summary["local_model_observations"]["count"] == 0
    assert summary["local_model_observations"]["included_in_metrics"] is False
    assert evaluation["config"]["runtime"] == "scripted"
    assert {item["category"] for item in evaluation["results"]} == {
        "synthetic_detection",
        "scripted_enforcement",
    }

    reports = workbench.runtime_dir / "reports"
    for suffix in ("json", "md", "csv"):
        path = reports / f"evaluation-{evaluation['id']}.{suffix}"
        assert path.is_file(), path
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_evaluation_exports_json_markdown_and_csv(workbench: WorkbenchHarness) -> None:
    evaluation = workbench.client.post("/api/v1/evaluations", json={"dataset_id": workbench.dataset_id}).json()
    evaluation_id = evaluation["id"]

    json_export = workbench.client.get(f"/api/v1/evaluations/{evaluation_id}/export?format=json")
    assert json_export.status_code == 200
    assert json_export.headers["content-type"].startswith("application/json")
    assert json_export.headers["content-disposition"].endswith(f'evaluation-{evaluation_id}.json"')
    assert json.loads(json_export.text)["synthetic_detection"]["TP"] == 2

    markdown_export = workbench.client.get(f"/api/v1/evaluations/{evaluation_id}/export?format=markdown")
    assert markdown_export.status_code == 200
    assert markdown_export.headers["content-disposition"].endswith(f'evaluation-{evaluation_id}.md"')
    assert "Synthetic evaluation report" in markdown_export.text
    assert "not estimates of real intrusion-detection accuracy" in markdown_export.text

    csv_export = workbench.client.get(f"/api/v1/evaluations/{evaluation_id}/export?format=csv")
    assert csv_export.status_code == 200
    assert csv_export.headers["content-disposition"].endswith(f'evaluation-{evaluation_id}.csv"')
    reader = csv.DictReader(io.StringIO(csv_export.text))
    rows = list(reader)
    assert rows
    assert {row["synthetic"] for row in rows} == {"true"}
    assert {row["runtime"] for row in rows} == {"scripted"}
    assert any(row["category"] == "synthetic_detection" for row in rows)
    assert any(row["category"] == "scripted_enforcement" for row in rows)

    listed = workbench.client.get("/api/v1/evaluations")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["id"] == evaluation_id


def test_evaluation_unknown_id_and_format_are_rejected(workbench: WorkbenchHarness) -> None:
    missing = workbench.client.get("/api/v1/evaluations/evl_missing")
    assert missing.status_code == 404
    bad_format = workbench.client.get("/api/v1/evaluations/evl_missing/export?format=pdf")
    assert bad_format.status_code == 422


def test_evaluation_requires_existing_dataset(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post("/api/v1/evaluations", json={"dataset_id": "ds_does_not_exist"})
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"
