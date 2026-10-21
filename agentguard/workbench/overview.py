"""Derived overview from persisted workbench state; no fabricated metrics."""

from __future__ import annotations

from typing import Any

from .audit import read_events, verify_audit
from .db import read_connection
from .evidence import source_coverage
from .settings import Settings
from .util import parse_iso, utc_iso, utcnow


def build_overview(settings: Settings, dataset_id: str | None = None) -> dict[str, Any]:
    with read_connection(settings.db_path) as conn:
        dataset = (
            conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
            if dataset_id
            else conn.execute(
                "SELECT * FROM datasets WHERE is_sample = 1 ORDER BY created_at DESC, id DESC LIMIT 1"
            ).fetchone()
        )
        if dataset is None:
            audit = verify_audit(conn, settings.runtime_dir)
            return {
                "scope": {"dataset_id": None, "dataset_name": None, "as_of": utc_iso()},
                "empty": True,
                "audit_summary": audit.as_dict(),
                "attention": [],
            }
        ds_id = str(dataset["id"])
        finding_counts = {"REVIEW": 0, "LOW": 0, "UNKNOWN": 0}
        for row in conn.execute(
            "SELECT disposition, COUNT(*) AS count FROM findings WHERE dataset_id = ? GROUP BY disposition",
            (ds_id,),
        ):
            finding_counts[str(row["disposition"])] = int(row["count"])
        investigation_rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM investigations WHERE dataset_id = ? GROUP BY status",
            (ds_id,),
        ).fetchall()
        investigation_counts = {"OPEN": 0, "REVIEWED": 0, "CLOSED": 0}
        for row in investigation_rows:
            investigation_counts[str(row["status"])] = int(row["count"])
        case_rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM cases WHERE dataset_id = ? GROUP BY status",
            (ds_id,),
        ).fetchall()
        case_counts = {"OPEN": 0, "CLOSED": 0}
        for row in case_rows:
            case_counts[str(row["status"])] = int(row["count"])
        policy_rows = conn.execute(
            """SELECT r.decision, COUNT(*) AS count FROM tool_requests r
               JOIN runs run ON run.id = r.run_id WHERE run.dataset_id = ?
               GROUP BY r.decision""",
            (ds_id,),
        ).fetchall()
        policy_counts = {"ALLOW": 0, "BLOCK": 0, "REQUIRE_APPROVAL": 0}
        for row in policy_rows:
            policy_counts[str(row["decision"])] = int(row["count"])
        pending_rows = conn.execute(
            """SELECT a.id, a.expires_at, r.id AS request_id, r.tool, run.scenario_key
               FROM approvals a JOIN tool_requests r ON r.id = a.request_id
               JOIN runs run ON run.id = r.run_id
               WHERE run.dataset_id = ? AND a.state = 'PENDING' AND r.status = 'PENDING'
               ORDER BY a.expires_at""",
            (ds_id,),
        ).fetchall()
        pending = []
        now = utcnow()
        for row in pending_rows:
            pending.append(
                {
                    "approval_id": row["id"],
                    "request_id": row["request_id"],
                    "tool": row["tool"],
                    "expires_at": row["expires_at"],
                    "expired": parse_iso(str(row["expires_at"])) <= now,
                    "scenario_key": row["scenario_key"],
                }
            )
        investigated: set[str] = set()
        for row in conn.execute("SELECT finding_ids_json FROM investigations WHERE dataset_id = ?", (ds_id,)):
            import json

            investigated.update(json.loads(row["finding_ids_json"]))
        unreviewed = conn.execute(
            """SELECT id, agent_label, title, priority_score, disposition, created_at
               FROM findings WHERE dataset_id = ? AND disposition IN ('REVIEW', 'UNKNOWN')
               ORDER BY priority_score DESC, created_at LIMIT 20""",
            (ds_id,),
        ).fetchall()
        attention: list[dict[str, Any]] = []
        for approval in pending:
            if approval["expired"]:
                continue
            attention.append(
                {
                    "kind": "approval",
                    "id": approval["approval_id"],
                    "title": f"Pending approval: {approval['tool']}",
                    "reason": f"One local operator decision required before {approval['expires_at']}.",
                    "recorded_at": approval["expires_at"],
                    "href": f"/policies/approvals/{approval['approval_id']}",
                }
            )
        for finding in unreviewed:
            if finding["id"] in investigated:
                continue
            attention.append(
                {
                    "kind": "finding",
                    "id": finding["id"],
                    "title": f"{finding['agent_label']} · {finding['title']}",
                    "reason": (
                        f"{finding['disposition']} / rule priority {finding['priority_score']}; "
                        "not yet linked to an investigation."
                    ),
                    "recorded_at": finding["created_at"],
                    "href": f"/investigations/findings/{finding['id']}",
                }
            )
        audit = verify_audit(conn, settings.runtime_dir)
        if not audit.safe_for_mutations:
            attention.insert(
                0,
                {
                    "kind": "audit",
                    "id": "audit",
                    "title": "Audit verification blocks state changes",
                    "reason": audit.message,
                    "recorded_at": utc_iso(),
                    "href": "/audit",
                },
            )
        coverage = source_coverage(conn, ds_id)
        event_count = conn.execute("SELECT COUNT(*) AS count FROM events WHERE dataset_id = ?", (ds_id,)).fetchone()[
            "count"
        ]
        recent = []
        for event in read_events(conn, limit=12):
            payload = event["payload"]
            recent.append(
                {
                    "seq": event["seq"],
                    "action": payload.get("action"),
                    "actor": payload.get("actor"),
                    "entity_type": payload.get("entity_type"),
                    "entity_id": payload.get("entity_id"),
                    "recorded_at": payload.get("recorded_at"),
                }
            )
        return {
            "scope": {
                "dataset_id": ds_id,
                "dataset_name": dataset["name"],
                "scenario_key": dataset["scenario_key"],
                "dataset_sha256": dataset["manifest_sha256"],
                "data_class": "synthetic",
                "as_of": utc_iso(),
            },
            "empty": False,
            "attention": attention,
            "investigation_counts": investigation_counts,
            "finding_counts": finding_counts,
            "case_counts": case_counts,
            "policy_counts": policy_counts,
            "pending_approvals": pending,
            "coverage": {
                "sources": coverage,
                "event_count": int(event_count),
                "source_count": len(coverage),
            },
            "audit_summary": audit.as_dict(),
            "recent_activity": recent,
            "disclaimer": (
                "All telemetry and effects are synthetic. Rule priority is an explainable ranking, "
                "not a probability or a live risk score."
            ),
        }
