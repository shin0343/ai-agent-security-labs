"""Explicit case records, immutable revisions and scoped synthetic exports."""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Any

from .audit import AuditUnavailable, append_audit, require_audit_healthy, verify_audit
from .db import read_connection, transaction
from .enforcement import _request_detail_conn
from .errors import AuditIntegrityError, ConflictError, NotFoundError, ValidationError
from .evidence import EvidenceError, resolve_evidence
from .findings import finding_detail
from .settings import Settings
from .util import canonical_json, sha256_json, utc_iso

FORMATS = {"markdown", "json", "csv"}


def _session_valid(conn, session_id: str) -> None:
    from .util import parse_iso, utcnow

    row = conn.execute("SELECT revoked_at, expires_at FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None or row["revoked_at"] is not None:
        raise NotFoundError("Local session not found.")
    if parse_iso(str(row["expires_at"])) <= utcnow():
        raise NotFoundError("Local session expired.")


def _validate_case_input(
    conn,
    *,
    dataset_id: str,
    finding_ids: list[str],
    request_ids: list[str],
    investigation_id: str | None,
) -> None:
    if not finding_ids or len(finding_ids) > 50 or len(set(finding_ids)) != len(finding_ids):
        raise ValidationError("Select between 1 and 50 distinct findings.")
    placeholders = ",".join("?" for _ in finding_ids)
    rows = conn.execute(f"SELECT id, dataset_id FROM findings WHERE id IN ({placeholders})", finding_ids).fetchall()
    if len(rows) != len(finding_ids) or any(row["dataset_id"] != dataset_id for row in rows):
        raise ValidationError("All selected findings must exist in the selected dataset.")
    if investigation_id:
        inv = conn.execute("SELECT dataset_id FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if inv is None or inv["dataset_id"] != dataset_id:
            raise ValidationError("Investigation does not belong to the selected dataset.")
    if request_ids:
        if len(request_ids) > 50 or len(set(request_ids)) != len(request_ids):
            raise ValidationError("Request selection is invalid.")
        placeholders = ",".join("?" for _ in request_ids)
        req_rows = conn.execute(
            f"""SELECT r.id FROM tool_requests r JOIN runs run ON run.id = r.run_id
                WHERE r.id IN ({placeholders}) AND run.dataset_id = ?""",
            [*request_ids, dataset_id],
        ).fetchall()
        if len(req_rows) != len(request_ids):
            raise ValidationError("A selected request does not belong to the dataset.")


def _make_content(
    *,
    title: str,
    dataset_id: str,
    investigation_id: str | None,
    finding_ids: list[str],
    request_ids: list[str],
    summary: str,
    scope: str,
    analyst_conclusion: str,
    recommendations: list[str],
) -> dict[str, Any]:
    return {
        "schema": 1,
        "synthetic_classification": "synthetic / educational / not a real compromise",
        "title": title,
        "dataset_id": dataset_id,
        "investigation_id": investigation_id,
        "finding_ids": finding_ids,
        "request_ids": request_ids,
        "summary": summary,
        "scope": scope,
        "analyst_conclusion": analyst_conclusion,
        "recommendations": recommendations,
        "integration_status": "manual_export_only",
        "external_equivalence": None,
    }


def create_case(
    settings: Settings,
    *,
    session_id: str,
    title: str,
    dataset_id: str,
    finding_ids: list[str],
    request_ids: list[str] | None = None,
    investigation_id: str | None = None,
    summary: str,
    scope: str,
    analyst_conclusion: str,
    recommendations: list[str] | None = None,
) -> dict[str, Any]:
    title = title.strip()
    if not title or len(title) > 160:
        raise ValidationError("Case title must be between 1 and 160 characters.")
    if not summary.strip() or len(summary) > 4000:
        raise ValidationError("Case summary is required and bounded to 4000 characters.")
    if not scope.strip() or len(scope) > 2000:
        raise ValidationError("Case scope is required and bounded to 2000 characters.")
    if not analyst_conclusion.strip() or len(analyst_conclusion) > 4000:
        raise ValidationError("Analyst conclusion is required and bounded to 4000 characters.")
    recommendations = [item.strip()[:500] for item in (recommendations or []) if item.strip()]
    request_ids = request_ids or []
    content = _make_content(
        title=title,
        dataset_id=dataset_id,
        investigation_id=investigation_id,
        finding_ids=finding_ids,
        request_ids=request_ids,
        summary=summary.strip(),
        scope=scope.strip(),
        analyst_conclusion=analyst_conclusion.strip(),
        recommendations=recommendations,
    )
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        _validate_case_input(
            conn,
            dataset_id=dataset_id,
            finding_ids=finding_ids,
            request_ids=request_ids,
            investigation_id=investigation_id,
        )
        case_id = f"case_{os.urandom(12).hex()}"
        now = utc_iso()
        conn.execute(
            """INSERT INTO cases(id, dataset_id, investigation_id, title, status, revision,
               created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'OPEN', 1, ?, ?, ?)""",
            (case_id, dataset_id, investigation_id, title, session_id, now, now),
        )
        conn.execute(
            """INSERT INTO case_revisions(id, case_id, revision, content_json, created_at, author)
               VALUES (?, ?, 1, ?, ?, ?)""",
            (
                f"crv_{os.urandom(12).hex()}",
                case_id,
                canonical_json(content).decode("utf-8"),
                now,
                session_id,
            ),
        )
        append_audit(
            conn,
            settings.runtime_dir,
            action="case.created",
            actor=session_id,
            entity_type="case",
            entity_id=case_id,
            details={
                "dataset_id": dataset_id,
                "finding_ids": finding_ids,
                "request_ids": request_ids,
                "investigation_id": investigation_id,
            },
        )
        return _case_detail_conn(conn, case_id)


def revise_case(
    settings: Settings,
    *,
    session_id: str,
    case_id: str,
    expected_revision: int,
    title: str,
    summary: str,
    scope: str,
    analyst_conclusion: str,
    recommendations: list[str] | None = None,
    status: str = "OPEN",
) -> dict[str, Any]:
    if status not in {"OPEN", "CLOSED"}:
        raise ValidationError("Case status is invalid.")
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("Case not found.")
        if int(row["revision"]) != int(expected_revision):
            raise ConflictError(
                "Case changed; reload before saving a new revision.",
                details={"current_revision": row["revision"]},
            )
        current = conn.execute(
            "SELECT content_json FROM case_revisions WHERE case_id = ? AND revision = ?",
            (case_id, int(row["revision"])),
        ).fetchone()
        content = json.loads(current["content_json"])
        content.update(
            {
                "title": title.strip()[:160],
                "summary": summary.strip()[:4000],
                "scope": scope.strip()[:2000],
                "analyst_conclusion": analyst_conclusion.strip()[:4000],
                "recommendations": [item.strip()[:500] for item in (recommendations or []) if item.strip()],
            }
        )
        if not content["title"] or not content["summary"] or not content["scope"]:
            raise ValidationError("Title, summary and scope are required.")
        next_revision = int(row["revision"]) + 1
        now = utc_iso()
        updated = conn.execute(
            "UPDATE cases SET title = ?, status = ?, revision = ?, updated_at = ? WHERE id = ? AND revision = ?",
            (content["title"], status, next_revision, now, case_id, int(expected_revision)),
        )
        if updated.rowcount != 1:
            raise ConflictError("Case changed concurrently.")
        conn.execute(
            """INSERT INTO case_revisions(id, case_id, revision, content_json, created_at, author)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                f"crv_{os.urandom(12).hex()}",
                case_id,
                next_revision,
                canonical_json(content).decode("utf-8"),
                now,
                session_id,
            ),
        )
        append_audit(
            conn,
            settings.runtime_dir,
            action="case.revised",
            actor=session_id,
            entity_type="case",
            entity_id=case_id,
            details={"revision": next_revision, "status": status},
        )
        return _case_detail_conn(conn, case_id)


def _case_detail_conn(conn, case_id: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT c.*, d.name AS dataset_name, d.scenario_key FROM cases c
           JOIN datasets d ON d.id = c.dataset_id WHERE c.id = ?""",
        (case_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("Case not found.")
    data = dict(row)
    revisions = conn.execute(
        "SELECT * FROM case_revisions WHERE case_id = ? ORDER BY revision DESC", (case_id,)
    ).fetchall()
    data["revisions"] = []
    for revision in revisions:
        item = dict(revision)
        item["content"] = json.loads(item.pop("content_json"))
        data["revisions"].append(item)
    data["current"] = data["revisions"][0]["content"] if data["revisions"] else None
    exports = conn.execute(
        """SELECT id, revision, format, sha256, integration_status, created_at
           FROM case_exports WHERE case_id = ? ORDER BY created_at DESC""",
        (case_id,),
    ).fetchall()
    data["exports"] = [dict(item) for item in exports]
    return data


def get_case(settings: Settings, case_id: str) -> dict[str, Any]:
    with read_connection(settings.db_path) as conn:
        return _case_detail_conn(conn, case_id)


def list_cases(settings: Settings, dataset_id: str | None = None) -> list[dict[str, Any]]:
    with read_connection(settings.db_path) as conn:
        params: list[Any] = []
        where = ""
        if dataset_id:
            where = "WHERE c.dataset_id = ?"
            params.append(dataset_id)
        rows = conn.execute(
            f"""SELECT c.*, d.name AS dataset_name,
                       (SELECT COUNT(*) FROM case_revisions r WHERE r.case_id = c.id) AS revision_count,
                       (SELECT COUNT(*) FROM case_exports e WHERE e.case_id = c.id) AS export_count
                FROM cases c JOIN datasets d ON d.id = c.dataset_id {where}
                ORDER BY c.updated_at DESC, c.id DESC""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def _md_escape(value: Any) -> str:
    text = str(value)
    # Backslash-escaped backticks do not neutralize backticks inside CommonMark
    # code spans (backslashes are literal there), so analyst text containing a
    # backtick would terminate the span and inject arbitrary Markdown. Replace
    # backticks outright; outside code spans the apostrophe also renders safely.
    return (
        text.replace("`", "'")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("\r", " ")
    )


def _csv_cell(value: Any) -> str:
    text = str(value)
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    if len(text) > 8000:
        text = text[:8000]
    return text


def _build_export(
    conn, case: dict[str, Any], fmt: str, verification: Any
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    content = case["current"]
    findings = []
    evidence: dict[str, dict[str, Any]] = {}
    for finding_id in content["finding_ids"]:
        detail = finding_detail(conn, finding_id)
        if detail is None:
            raise ConflictError("A case finding is no longer available.")
        findings.append(detail)
        for item in detail["evidence"]:
            evidence[item["event_id"]] = item
    resolved_evidence = {}
    for event_id in evidence:
        try:
            resolved_evidence[event_id] = resolve_evidence(conn, event_id)
        except EvidenceError as exc:
            raise ConflictError(
                "Case evidence failed its immutable-snapshot integrity check.",
                details={"event_id": event_id, "message": str(exc)},
            ) from exc
    requests = [_request_detail_conn(conn, request_id) for request_id in content["request_ids"]]
    timeline = sorted(
        [item for item in resolved_evidence.values() if item.get("ts_utc")],
        key=lambda item: (item["ts_utc"], item["event_id"]),
    )
    time_unavailable = [item for item in resolved_evidence.values() if not item.get("ts_utc")]
    all_evidence = timeline + sorted(time_unavailable, key=lambda item: item["event_id"])
    unknowns: list[str] = []
    facts: list[str] = []
    for finding in findings:
        for fact in finding["observed_facts"]:
            if isinstance(fact, dict):
                facts.append(str(fact.get("text", "")))
            else:
                facts.append(str(fact))
        unknowns.extend(finding["unknowns"])
    manifest = {
        "case_id": case["id"],
        "title": content["title"],
        "revision": int(case["revision"]),
        "synthetic_classification": content["synthetic_classification"],
        "dataset_id": content["dataset_id"],
        "dataset_name": case["dataset_name"],
        "scenario_key": case["scenario_key"],
        "generated_at": utc_iso(),
        "integration_status": "manual_export_only",
        "external_vigil_case_id": None,
        "findings": [
            {
                "finding_id": finding["id"],
                "agent": finding["agent_label"],
                "title": finding["title"],
                "disposition": finding["disposition"],
                "priority_score": finding["priority_score"],
                "interpretation": finding["interpretation"],
                "limitations": finding["limitations"],
            }
            for finding in findings
        ],
        "evidence": [
            {
                "event_id": item["event_id"],
                "ref": item["ref"],
                "source": item["source_filename"],
                "line": item["line"],
                "raw_sha256": item["raw_sha256"],
                "source_sha256": item["source_sha256"],
                "captured_record": item["raw"],
                "integrity": item["integrity"],
                "ts_utc": item["ts_utc"],
                "original_ts": item["original_ts"],
                "parse_status": item["parse_status"],
            }
            for item in all_evidence
        ],
        "timeline": [{"event_id": item["event_id"], "ts_utc": item["ts_utc"], "ref": item["ref"]} for item in timeline],
        "time_unavailable": [
            {
                "event_id": item["event_id"],
                "ref": item["ref"],
                "reason": "No valid timestamp; evidence retained outside the ordered timeline.",
            }
            for item in time_unavailable
        ],
        "requests": [
            {
                "request_id": request["id"],
                "tool": request["tool"],
                "decision": request["decision"],
                "status": request["status"],
                "execution_status": request["execution_status"],
                "request_digest": request["request_digest"],
                "arguments": request["arguments"],
                "result": request["result"],
            }
            for request in requests
        ],
        "confirmed_facts": facts,
        "unresolved_questions": unknowns,
        "analyst_conclusion": content["analyst_conclusion"],
        "recommendations": content["recommendations"],
        "summary": content["summary"],
        "scope": content["scope"],
        "audit_verification": verification.as_dict(),
    }
    if fmt == "json":
        text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "case_id",
                "revision",
                "synthetic",
                "agent",
                "finding_title",
                "evidence_ref",
                "raw_sha256",
                "captured_record",
                "unknown",
                "audit_integrity",
                "audit_completeness",
            ]
        )
        for finding in findings:
            for evidence_ref in finding["evidence"]:
                captured = resolved_evidence[evidence_ref["event_id"]]
                writer.writerow(
                    [
                        _csv_cell(case["id"]),
                        int(case["revision"]),
                        "true",
                        _csv_cell(finding["agent_label"]),
                        _csv_cell(finding["title"]),
                        _csv_cell(captured["ref"]),
                        _csv_cell(captured["raw_sha256"]),
                        _csv_cell(json.dumps(captured["raw"], sort_keys=True)),
                        _csv_cell("\n".join(finding["unknowns"])),
                        verification.integrity,
                        verification.completeness,
                    ]
                )
        text = output.getvalue()
    else:
        lines = [
            f"# [SYNTHETIC] {_md_escape(content['title'])}",
            "",
            "> **Synthetic case.** Educational data only. This is not a real compromise, not a Vigil case, and "
            "not evidence of external delivery.",
            "",
            f"- Internal case ID: `{case['id']}`",
            f"- Revision: {int(case['revision'])}",
            f"- Dataset: {_md_escape(case['dataset_name'])} (`{case['scenario_key']}`)",
            f"- Synthetic classification: {_md_escape(content['synthetic_classification'])}",
            "- Integration status: `manual_export_only`",
            "",
            "## Summary",
            "",
            _md_escape(content["summary"]),
            "",
            "## Scope",
            "",
            _md_escape(content["scope"]),
            "",
            "## Timeline and evidence",
            "",
            "| Time (UTC) | Ref | Type | Actor hint | Integrity |",
            "|---|---|---|---|---|",
        ]
        for item in all_evidence:
            lines.append(
                f"| {_md_escape(item['ts_utc'] or 'unknown — not ordered')} | `{_md_escape(item['ref'])}` | "
                f"{_md_escape(item['event_type'])} | {_md_escape(item.get('actor_hint') or 'unknown')} | "
                f"{item['integrity']} |"
            )
        lines += ["", "### Captured records", ""]
        for item in all_evidence:
            payload = json.dumps(item["raw"], ensure_ascii=False, sort_keys=True)
            payload = payload.replace("```", "'''")
            lines += [
                f"**{_md_escape(item['ref'])}** — SHA-256 `{item['raw_sha256']}`",
                "",
                "```json",
                payload,
                "```",
                "",
            ]
        lines += ["## Policy decisions", ""]
        if not requests:
            lines.append("No tool requests were selected for this case.")
        for request in requests:
            lines += [
                f"### `{request['tool']}` — {request['decision']} / {request['status']}",
                f"- Request ID: `{request['id']}`",
                f"- Execution: {request['execution_status']}",
                f"- Parameters: `{_md_escape(json.dumps(request['arguments'], sort_keys=True))}`",
                f"- Request digest: `{request['request_digest']}`",
                f"- Result: {_md_escape(json.dumps(request.get('result'), sort_keys=True))}",
                "",
            ]
        lines += ["## Confirmed facts", ""]
        lines += [f"- {_md_escape(fact)}" for fact in facts] or ["- None recorded."]
        lines += ["", "## Unresolved questions", ""]
        lines += [f"- {_md_escape(unknown)}" for unknown in unknowns] or ["- None recorded."]
        lines += ["", "## Analyst conclusion", "", _md_escape(content["analyst_conclusion"]), ""]
        lines += ["## Recommendations", ""]
        lines += [f"- {_md_escape(item)}" for item in content["recommendations"]] or ["- None recorded."]
        lines += [
            "",
            "## Limitations",
            "",
            "- IP/host association does not prove agent process ownership.",
            "- The local HMAC chain and checkpoint are not independent tamper-proof storage.",
            "- Vigil entry is manual. This export does not call a Vigil API.",
            "",
            "## Audit verification snapshot",
            "",
            f"- Integrity: {_md_escape(verification.integrity)}",
            f"- Completeness: {_md_escape(verification.completeness)}",
            f"- Consistency: {_md_escape(verification.consistency)}",
            f"- Checked events: {verification.checked_events}",
            f"- Head: `{_md_escape(verification.head_mac or 'none')}`",
            f"- Verification note: {_md_escape(verification.message)}",
            "",
        ]
        text = "\n".join(lines)
    return text, manifest, resolved_evidence


def export_case(
    settings: Settings,
    *,
    session_id: str,
    case_id: str,
    fmt: str = "markdown",
) -> dict[str, Any]:
    if fmt not in FORMATS:
        raise ValidationError("Unsupported export format.")
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        case = _case_detail_conn(conn, case_id)
        if case["current"] is None:
            raise ConflictError("Case has no revision.")
        verification = verify_audit(conn, settings.runtime_dir)
        if not verification.safe_for_mutations:
            raise AuditIntegrityError(verification.message)
        text, manifest, _ = _build_export(conn, case, fmt, verification)
        if fmt == "json":
            text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        export_id = f"exp_{os.urandom(12).hex()}"
        content_hash = sha256_json({"text": text})
        now = utc_iso()
        conn.execute(
            """INSERT INTO case_exports(id, case_id, revision, format, content, sha256,
               verification_json, integration_status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'manual_export_only', ?)""",
            (
                export_id,
                case_id,
                int(case["revision"]),
                fmt,
                text,
                content_hash,
                canonical_json(verification.as_dict()).decode("utf-8"),
                now,
            ),
        )
        append_audit(
            conn,
            settings.runtime_dir,
            action="case.exported",
            actor=session_id,
            entity_type="case_export",
            entity_id=export_id,
            details={
                "case_id": case_id,
                "revision": int(case["revision"]),
                "format": fmt,
                "content_sha256": content_hash,
                "integration_status": "manual_export_only",
                "audit_integrity": verification.integrity,
            },
        )
        extension = {"markdown": "md", "json": "json", "csv": "csv"}[fmt]
        return {
            "export_id": export_id,
            "case_id": case_id,
            "revision": int(case["revision"]),
            "format": fmt,
            "filename": f"{case_id}-r{case['revision']}.{extension}",
            "sha256": content_hash,
            "integration_status": "manual_export_only",
            "content": text,
            "audit_verification": verification.as_dict(),
        }


def get_export(settings: Settings, export_id: str) -> dict[str, Any]:
    with read_connection(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM case_exports WHERE id = ?", (export_id,)).fetchone()
        if row is None:
            raise NotFoundError("Case export not found.")
        data = dict(row)
        data["verification"] = json.loads(data.pop("verification_json"))
        return data
