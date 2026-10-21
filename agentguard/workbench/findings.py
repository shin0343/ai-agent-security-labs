"""Read models for findings, evidence and timelines."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .evidence import EvidenceError, resolve_evidence


def _json_list(raw: str | None) -> list:
    if not raw:
        return []
    value = json.loads(raw)
    return value if isinstance(value, list) else []


def _event_summary(conn: sqlite3.Connection, event_id: str, role: str | None = None) -> dict[str, Any]:
    row = conn.execute(
        """SELECT e.id, e.event_type, e.ts_utc, e.original_ts, e.parse_status, e.actor_hint,
                  e.src_ip, e.dst_ip, e.action, e.resource, e.raw_sha256, e.line_no,
                  s.filename, s.sha256 AS source_sha256
           FROM events e JOIN source_blobs s ON s.id = e.source_id WHERE e.id = ?""",
        (event_id,),
    ).fetchone()
    if row is None:
        return {
            "event_id": event_id,
            "ref": "unavailable",
            "integrity": "missing",
            "role": role,
        }
    data = dict(row)
    data["event_id"] = data.pop("id")
    data["ref"] = f"{data.pop('filename')}:{data.pop('line_no')}"
    if role:
        data["role"] = role
    try:
        resolved = resolve_evidence(conn, event_id)
        data["integrity"] = resolved["integrity"]
    except EvidenceError as exc:
        data["integrity"] = "invalid"
        data["integrity_message"] = str(exc)
    return data


def finding_detail(conn: sqlite3.Connection, finding_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT f.*, d.name AS dataset_name, d.scenario_key, d.data_class,
                  dr.rules_version, dr.started_at AS detection_started_at
           FROM findings f
           JOIN datasets d ON d.id = f.dataset_id
           JOIN detection_runs dr ON dr.id = f.detection_run_id
           WHERE f.id = ?""",
        (finding_id,),
    ).fetchone()
    if row is None:
        return None
    data = dict(row)
    for key in (
        "observed_facts_json",
        "supporting_json",
        "contradicting_json",
        "unknowns_json",
    ):
        data[key.replace("_json", "")] = _json_list(data.pop(key))
    evidence_rows = conn.execute(
        """SELECT fe.event_id, fe.role FROM finding_evidence fe
           WHERE fe.finding_id = ? ORDER BY fe.role, fe.event_id""",
        (finding_id,),
    ).fetchall()
    evidence = [_event_summary(conn, str(item["event_id"]), str(item["role"])) for item in evidence_rows]
    evidence.sort(key=lambda item: (item.get("ts_utc") is None, item.get("ts_utc") or "", item["event_id"]))
    data["evidence"] = evidence
    edges = []
    for edge in conn.execute("SELECT * FROM correlation_edges WHERE finding_id = ?", (finding_id,)).fetchall():
        item = dict(edge)
        item["join_fields"] = json.loads(item.pop("join_fields_json"))
        item["left"] = _event_summary(conn, str(item["left_event_id"]))
        item["right"] = _event_summary(conn, str(item["right_event_id"]))
        edges.append(item)
    data["correlation_edges"] = edges
    data["timeline"] = sorted(
        [item for item in evidence if item.get("ts_utc")],
        key=lambda item: (item.get("ts_utc"), item["event_id"]),
    )
    data["time_unavailable"] = [item for item in evidence if not item.get("ts_utc")]
    data["evidence_integrity"] = "valid" if all(item.get("integrity") == "verified" for item in evidence) else "invalid"
    return data


def list_findings(
    conn: sqlite3.Connection,
    *,
    dataset_id: str | None = None,
    disposition: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if dataset_id:
        clauses.append("f.dataset_id = ?")
        params.append(dataset_id)
    if disposition:
        clauses.append("f.disposition = ?")
        params.append(disposition)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(limit, 1), 200))
    rows = conn.execute(
        f"""SELECT f.id, f.dataset_id, f.agent_label, f.title, f.disposition, f.priority_score,
                   f.interpretation, f.created_at, f.detection_run_id, d.name AS dataset_name,
                   (SELECT COUNT(*) FROM finding_evidence fe WHERE fe.finding_id = f.id) AS evidence_count
            FROM findings f JOIN datasets d ON d.id = f.dataset_id
            {where}
            ORDER BY CASE f.disposition WHEN 'REVIEW' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END,
                     f.priority_score DESC, f.created_at DESC, f.id
            LIMIT ?""",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def finding_counts(conn: sqlite3.Connection, dataset_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT disposition, COUNT(*) AS count FROM findings WHERE dataset_id = ? GROUP BY disposition",
        (dataset_id,),
    ).fetchall()
    counts = {"REVIEW": 0, "LOW": 0, "UNKNOWN": 0}
    for row in rows:
        counts[str(row["disposition"])] = int(row["count"])
    return counts


def raw_evidence_context(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    return resolve_evidence(conn, event_id)


def dataset_timeline(conn: sqlite3.Connection, dataset_id: str, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT e.id FROM events e WHERE e.dataset_id = ?
           ORDER BY e.ts_utc IS NULL, e.ts_utc, e.source_id, e.line_no LIMIT ?""",
        (dataset_id, min(max(limit, 1), 500)),
    ).fetchall()
    return [_event_summary(conn, str(row["id"])) for row in rows]
