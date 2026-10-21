"""Idempotent local bootstrap for the bundled synthetic dataset."""

from __future__ import annotations

from typing import Any

from .audit import AuditUnavailable, append_audit, require_audit_healthy, verify_audit
from .db import migrate, read_connection, transaction
from .detection import run_detection
from .evidence import collect_dataset, latest_sample, persist_dataset
from .settings import Settings
from .util import canonical_json


def initialize(settings: Settings) -> dict[str, Any]:
    migrate(settings.db_path)
    settings.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with read_connection(settings.db_path) as conn:
        report = verify_audit(conn, settings.runtime_dir)
        if not report.safe_for_mutations:
            return {
                "status": "AUDIT_BLOCKED",
                "dataset_id": None,
                "detection_run_id": None,
                "audit": report.as_dict(),
            }
        sample = latest_sample(conn)
        if sample is not None:
            detection = conn.execute(
                """SELECT id FROM detection_runs WHERE dataset_id = ? AND status = 'COMPLETED'
                   ORDER BY completed_at DESC LIMIT 1""",
                (sample["id"],),
            ).fetchone()
            if detection is not None:
                return {
                    "status": "READY",
                    "dataset_id": sample["id"],
                    "detection_run_id": detection["id"],
                    "created": False,
                    "audit": report.as_dict(),
                }
    return import_sample(settings, run_detection_if_missing=True)


def import_sample(settings: Settings, *, run_detection_if_missing: bool = True) -> dict[str, Any]:
    prepared = collect_dataset(
        settings.fixture_dir,
        name="Shared-host agent scenario",
        scenario_key="shared-host-v1",
    )
    dataset_id = ""
    created = False
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            return {
                "status": "AUDIT_BLOCKED",
                "dataset_id": None,
                "detection_run_id": None,
                "message": str(exc),
            }
        dataset_id, created = persist_dataset(conn, prepared, is_sample=True)
        if created:
            append_audit(
                conn,
                settings.runtime_dir,
                action="dataset.imported",
                actor="workbench:bootstrap",
                entity_type="dataset",
                entity_id=dataset_id,
                details={
                    "scenario_key": prepared.scenario_key,
                    "manifest_sha256": prepared.manifest_sha256,
                    "event_count": prepared.event_count,
                    "sources": len(prepared.sources),
                    "data_class": "synthetic",
                },
            )
    detection_id = None
    if run_detection_if_missing:
        with read_connection(settings.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM detection_runs WHERE dataset_id = ? AND status = 'COMPLETED' LIMIT 1",
                (dataset_id,),
            ).fetchone()
        if existing is not None:
            detection_id = existing["id"]
        else:
            with transaction(settings.db_path) as conn:
                outcome = run_detection(conn, settings.runtime_dir, dataset_id)
            detection_id = outcome["detection_run_id"]
    return {
        "status": "READY",
        "dataset_id": dataset_id,
        "detection_run_id": detection_id,
        "created": created,
        "manifest_sha256": prepared.manifest_sha256,
        "event_count": prepared.event_count,
        "manifest": canonical_json(prepared.manifest).decode("utf-8"),
    }
