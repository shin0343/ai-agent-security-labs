"""Investigation and append-only analyst verdict services."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .audit import AuditUnavailable, append_audit, require_audit_healthy
from .db import read_connection, transaction
from .errors import AuditIntegrityError, ConflictError, NotFoundError, ValidationError
from .evidence import EvidenceError, resolve_evidence
from .findings import finding_detail
from .settings import Settings
from .util import canonical_json, parse_iso, utc_iso, utcnow

VERDICTS = {
    "POLICY_VIOLATION_SUPPORTED",
    "WITHIN_OBSERVED_SCOPE",
    "INSUFFICIENT_EVIDENCE",
    "NEEDS_MORE_DATA",
}


def _session_valid(conn, session_id: str) -> None:
    row = conn.execute("SELECT revoked_at, expires_at FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None or row["revoked_at"] is not None:
        raise NotFoundError("Local session not found.")
    if parse_iso(str(row["expires_at"])) <= utcnow():
        raise NotFoundError("Local session expired.")


def investigation_detail(conn, investigation_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    finding_ids = json.loads(data.pop("finding_ids_json"))
    data["finding_ids"] = finding_ids
    loaded = []
    for finding_id in finding_ids:
        detail = finding_detail(conn, finding_id)
        if detail is not None:
            loaded.append(detail)
    data["findings"] = loaded
    verdicts = conn.execute(
        "SELECT * FROM verdict_revisions WHERE investigation_id = ? ORDER BY revision", (investigation_id,)
    ).fetchall()
    data["verdicts"] = []
    for verdict in verdicts:
        item = dict(verdict)
        item["evidence_ids"] = json.loads(item.pop("evidence_ids_json"))
        data["verdicts"].append(item)
    data["latest_verdict"] = data["verdicts"][-1] if data["verdicts"] else None
    return data


def list_investigations(conn, dataset_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if dataset_id:
        where = "WHERE dataset_id = ?"
        params.append(dataset_id)
    params.append(min(max(limit, 1), 200))
    rows = conn.execute(
        f"""SELECT i.*, (SELECT COUNT(*) FROM verdict_revisions v WHERE v.investigation_id = i.id)
            AS verdict_count FROM investigations i {where}
            ORDER BY i.updated_at DESC, i.id DESC LIMIT ?""",
        params,
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["finding_ids"] = json.loads(item.pop("finding_ids_json"))
        result.append(item)
    return result


def create_investigation(
    settings: Settings,
    *,
    session_id: str,
    dataset_id: str,
    title: str,
    finding_ids: list[str],
    notes: str = "",
) -> dict[str, Any]:
    title = title.strip()
    if not title or len(title) > 160:
        raise ValidationError("Investigation title must be between 1 and 160 characters.")
    if not finding_ids or len(finding_ids) > 50 or len(set(finding_ids)) != len(finding_ids):
        raise ValidationError("Select between 1 and 50 distinct findings.")
    if len(notes) > 4000:
        raise ValidationError("Notes are too long.")
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        dataset = conn.execute("SELECT id FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
        if dataset is None:
            raise NotFoundError("Dataset not found.")
        placeholders = ",".join("?" for _ in finding_ids)
        rows = conn.execute(f"SELECT id, dataset_id FROM findings WHERE id IN ({placeholders})", finding_ids).fetchall()
        if len(rows) != len(finding_ids) or any(row["dataset_id"] != dataset_id for row in rows):
            raise ValidationError("All findings must exist in the selected dataset.")
        investigation_id = f"inv_{os.urandom(12).hex()}"
        now = utc_iso()
        conn.execute(
            """INSERT INTO investigations(id, dataset_id, title, status, finding_ids_json, notes,
               revision, created_by, created_at, updated_at)
               VALUES (?, ?, ?, 'OPEN', ?, ?, 1, ?, ?, ?)""",
            (
                investigation_id,
                dataset_id,
                title,
                canonical_json(finding_ids).decode("utf-8"),
                notes,
                session_id,
                now,
                now,
            ),
        )
        append_audit(
            conn,
            settings.runtime_dir,
            action="investigation.created",
            actor=session_id,
            entity_type="investigation",
            entity_id=investigation_id,
            details={"dataset_id": dataset_id, "finding_ids": finding_ids},
        )
        result = investigation_detail(conn, investigation_id)
        assert result is not None
        return result


def save_verdict(
    settings: Settings,
    *,
    session_id: str,
    investigation_id: str,
    verdict: str,
    rationale: str,
    evidence_ids: list[str],
    expected_revision: int,
) -> dict[str, Any]:
    if verdict not in VERDICTS:
        raise ValidationError("Unknown analyst verdict.")
    rationale = rationale.strip()
    if not rationale or len(rationale) > 4000:
        raise ValidationError("A rationale between 1 and 4000 characters is required.")
    if len(evidence_ids) > 100 or len(set(evidence_ids)) != len(evidence_ids):
        raise ValidationError("Evidence selection is invalid.")
    if verdict in {"POLICY_VIOLATION_SUPPORTED", "WITHIN_OBSERVED_SCOPE"} and not evidence_ids:
        raise ValidationError("This verdict requires at least one cited evidence record.")
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        if int(row["revision"]) != int(expected_revision):
            raise ConflictError(
                "Investigation changed; reload before saving another verdict.",
                details={"current_revision": row["revision"]},
            )
        finding_ids = json.loads(row["finding_ids_json"])
        placeholders = ",".join("?" for _ in finding_ids)
        allowed_rows = conn.execute(
            f"""SELECT fe.event_id FROM finding_evidence fe
                WHERE fe.finding_id IN ({placeholders})""",
            finding_ids,
        ).fetchall()
        allowed = {str(item["event_id"]) for item in allowed_rows}
        if any(event_id not in allowed for event_id in evidence_ids):
            raise ValidationError("A cited evidence record does not belong to this investigation.")
        for event_id in evidence_ids:
            try:
                resolve_evidence(conn, event_id)
            except EvidenceError as exc:
                raise ConflictError(
                    "Cited evidence is unavailable or failed its integrity check.",
                    details={"event_id": event_id, "message": str(exc)},
                ) from exc
        next_revision = int(row["revision"]) + 1
        now = utc_iso()
        verdict_id = f"vrd_{os.urandom(12).hex()}"
        conn.execute(
            """INSERT INTO verdict_revisions(id, investigation_id, verdict, rationale,
               evidence_ids_json, revision, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                verdict_id,
                investigation_id,
                verdict,
                rationale,
                canonical_json(evidence_ids).decode("utf-8"),
                next_revision,
                session_id,
                now,
            ),
        )
        updated = conn.execute(
            """UPDATE investigations SET status = 'REVIEWED', revision = ?, updated_at = ?
               WHERE id = ? AND revision = ?""",
            (next_revision, now, investigation_id, int(expected_revision)),
        )
        if updated.rowcount != 1:
            raise ConflictError("Investigation revision changed concurrently.")
        append_audit(
            conn,
            settings.runtime_dir,
            action="verdict.saved",
            actor=session_id,
            entity_type="investigation",
            entity_id=investigation_id,
            details={
                "verdict": verdict,
                "revision": next_revision,
                "evidence_ids": evidence_ids,
                "rationale_sha256": hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            },
        )
        result = investigation_detail(conn, investigation_id)
        assert result is not None
        return result


def get_investigation(settings: Settings, investigation_id: str) -> dict[str, Any]:
    with read_connection(settings.db_path) as conn:
        result = investigation_detail(conn, investigation_id)
        if result is None:
            raise NotFoundError("Investigation not found.")
        return result
