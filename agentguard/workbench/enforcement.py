"""Transactional tool authorization, single-use approval and synthetic execution."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Any

from .audit import AuditUnavailable, append_audit, require_audit_healthy
from .db import transaction
from .errors import AuditIntegrityError, ConflictError, ForbiddenError, NotFoundError, ValidationError
from .policy import (
    POLICY_MODES,
    SYNTHETIC_REPORT,
    TOOLS,
    args_digest,
    evaluate_proposal,
    request_binding,
    request_digest,
    resource_for,
)
from .settings import Settings
from .util import MAX_PROPOSALS, canonical_json, iso_in, parse_iso, sha256_json, utc_iso, utcnow

TERMINAL_RUN_STATES = {"COMPLETED", "CANCELLED", "FAILED"}


@dataclass(frozen=True)
class DecisionResult:
    response: dict[str, Any]
    committed: bool = True


def _append_trace(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    text: str,
    *,
    tool_request_id: str | None = None,
    input_refs: list[str] | None = None,
    output_refs: list[str] | None = None,
    error_code: str | None = None,
) -> str:
    row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM trace_events WHERE run_id = ?", (run_id,)).fetchone()
    seq = int(row["seq"]) + 1
    trace_id = f"trc_{os.urandom(12).hex()}"
    conn.execute(
        """INSERT INTO trace_events(id, run_id, seq, parent_id, kind, text, tool_request_id,
           input_refs_json, output_refs_json, error_code, created_at)
           VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
        (
            trace_id,
            run_id,
            seq,
            kind,
            text[:2000],
            tool_request_id,
            canonical_json(input_refs or []).decode("utf-8"),
            canonical_json(output_refs or []).decode("utf-8"),
            error_code,
            utc_iso(),
        ),
    )
    return trace_id


def _session_valid(conn: sqlite3.Connection, session_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None or row["revoked_at"] is not None:
        raise ForbiddenError("Local operator session is not valid.")
    if parse_iso(str(row["expires_at"])) <= utcnow():
        raise ForbiddenError("Local operator session has expired.")
    return row


def _run_or_404(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise NotFoundError("Agent run not found.")
    return row


def _execute_synthetic(conn: sqlite3.Connection, request: sqlite3.Row) -> dict[str, Any]:
    now = utc_iso()
    tool = str(request["tool"])
    args = json.loads(request["args_json"])
    if tool == "read_report":
        result = {
            "kind": "synthetic_report",
            "summary": "Fixed local synthetic report returned by the read_report adapter.",
            "content": SYNTHETIC_REPORT,
            "synthetic": True,
            "resource_ref": request["resource_ref"],
        }
    elif tool == "publish_simulated":
        receipt_payload = {
            "synthetic": True,
            "artifact_id": args["artifact_id"],
            "destination": args["destination"],
            "request_id": request["id"],
            "request_digest": request["request_digest"],
            "note": "Local database receipt only. No external network request or file was created.",
        }
        receipt_json = canonical_json(receipt_payload).decode("utf-8")
        receipt_id = f"rcp_{os.urandom(12).hex()}"
        conn.execute(
            """INSERT INTO simulated_receipts(id, request_id, payload_json, sha256, synthetic, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            (receipt_id, request["id"], receipt_json, sha256_json(receipt_payload), now),
        )
        result = {
            "kind": "simulated_publish",
            "receipt_id": receipt_id,
            "summary": "One local synthetic receipt created. No external publish occurred.",
            "synthetic": True,
            "resource_ref": request["resource_ref"],
        }
    else:  # pragma: no cover - policy blocks unknown tools before execution
        raise RuntimeError("Forbidden tool reached synthetic executor")
    result_json = canonical_json(result).decode("utf-8")
    result_hash = sha256_json(result)
    conn.execute(
        """INSERT INTO execution_results(id, request_id, kind, result_json, result_sha256,
           status, started_at, finished_at) VALUES (?, ?, ?, ?, ?, 'SUCCEEDED', ?, ?)""",
        (f"exe_{os.urandom(12).hex()}", request["id"], result["kind"], result_json, result_hash, now, now),
    )
    return {"result": result, "result_hash": result_hash}


def propose(
    settings: Settings,
    *,
    run_id: str,
    actor: str,
    tool: str,
    args: Any,
) -> dict[str, Any]:
    tool_name = tool[:100] if isinstance(tool, str) else "<invalid>"
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        run = _run_or_404(conn, run_id)
        _session_valid(conn, str(run["created_by_session"]))
        if str(run["status"]) in TERMINAL_RUN_STATES or str(run["status"]) == "WAITING_APPROVAL":
            raise ConflictError("Run is not accepting new proposals.", details={"status": run["status"]})
        proposal_count = conn.execute("SELECT COUNT(*) FROM tool_requests WHERE run_id = ?", (run_id,)).fetchone()[0]
        if proposal_count >= MAX_PROPOSALS:
            raise ConflictError("Gateway proposal budget exhausted.", details={"code": "PROPOSAL_BUDGET_EXHAUSTED"})
        preset = conn.execute("SELECT * FROM policy_presets WHERE id = ?", (run["policy_preset_id"],)).fetchone()
        if preset is None or int(preset["version"]) != int(run["policy_version"]):
            raise ConflictError("Run policy version is no longer current.")
        mode = str(preset["mode"])
        if mode not in POLICY_MODES:
            raise ConflictError("Run policy mode is invalid.")
        outcome = evaluate_proposal(
            tool=tool_name,
            args=args,
            mode=mode,
            policy_preset_id=str(preset["id"]),
            policy_version=int(preset["version"]),
        )
        valid_shape = isinstance(args, dict) and set(args.keys()) == set(
            TOOLS.get(tool_name, TOOLS["read_report"]).allowed_args.keys()
        )
        safe_args: dict[str, str] = {}
        digest_args: dict[str, Any] = {"redacted": True}
        if outcome.decision != "BLOCK" and tool_name in TOOLS and valid_shape:
            safe_args = {key: str(value) for key, value in args.items()}
            digest_args = dict(safe_args)
        request_id = f"req_{os.urandom(12).hex()}"
        expires_at = iso_in(settings.approval_ttl_seconds) if outcome.decision == "REQUIRE_APPROVAL" else None
        binding = request_binding(
            request_id=request_id,
            run_id=run_id,
            actor=actor[:120],
            tool=tool_name,
            tool_schema_version=TOOLS[tool_name].schema_version if tool_name in TOOLS else "unknown",
            args=safe_args,
            resource_ref=outcome.resource_ref,
            resource_hash=outcome.resource_hash,
            policy_preset_id=str(preset["id"]),
            policy_version=int(preset["version"]),
            expires_at=expires_at,
        )
        binding_digest = request_digest(binding)
        created_at = utc_iso()
        status = {
            "ALLOW": "AUTHORIZED",
            "BLOCK": "BLOCKED",
            "REQUIRE_APPROVAL": "PENDING",
        }[outcome.decision]
        conn.execute(
            """INSERT INTO tool_requests(id, run_id, actor, tool, tool_schema_version, args_json,
               args_digest, request_digest, resource_ref, resource_hash, policy_preset_id,
               policy_version, mode, decision, decision_reason_code, decision_reason, status,
               execution_status, result_json, version, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NOT_STARTED', NULL, 1, ?, ?)""",
            (
                request_id,
                run_id,
                actor[:120],
                tool_name,
                TOOLS[tool_name].schema_version if tool_name in TOOLS else "unknown",
                canonical_json(safe_args).decode("utf-8"),
                args_digest(digest_args),
                binding_digest,
                outcome.resource_ref,
                outcome.resource_hash,
                str(preset["id"]),
                int(preset["version"]),
                mode,
                outcome.decision,
                outcome.reason_code,
                outcome.reason,
                status,
                created_at,
                expires_at,
            ),
        )
        _append_trace(
            conn,
            run_id,
            "proposal",
            f"Proposed {tool_name}.",
            tool_request_id=request_id,
            input_refs=[],
        )
        request = conn.execute("SELECT * FROM tool_requests WHERE id = ?", (request_id,)).fetchone()
        assert request is not None

        approval_id = None
        if outcome.decision == "ALLOW":
            execution = _execute_synthetic(conn, request)
            conn.execute(
                """UPDATE tool_requests SET status = 'AUTHORIZED', execution_status = 'SUCCEEDED',
                   result_json = ? WHERE id = ?""",
                (canonical_json(execution["result"]).decode("utf-8"), request_id),
            )
            _append_trace(
                conn,
                run_id,
                "execution",
                str(execution["result"]["summary"]),
                tool_request_id=request_id,
                output_refs=[str(execution["result"].get("receipt_id", request_id))],
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="tool.executed",
                actor=actor[:120],
                entity_type="tool_request",
                entity_id=request_id,
                details={
                    "decision": "ALLOW",
                    "mode": mode,
                    "tool": tool_name,
                    "args_digest": args_digest(digest_args),
                    "policy_version": int(preset["version"]),
                    "result_hash": execution["result_hash"],
                    "synthetic": True,
                },
            )
        elif outcome.decision == "REQUIRE_APPROVAL":
            approval_id = f"apr_{os.urandom(12).hex()}"
            assert expires_at is not None
            conn.execute(
                """INSERT INTO approvals(id, request_id, session_id, request_digest, state,
                   expected_version, created_at, expires_at)
                   VALUES (?, ?, ?, ?, 'PENDING', 1, ?, ?)""",
                (
                    approval_id,
                    request_id,
                    run["created_by_session"],
                    binding_digest,
                    created_at,
                    expires_at,
                ),
            )
            conn.execute("UPDATE runs SET status = 'WAITING_APPROVAL' WHERE id = ?", (run_id,))
            _append_trace(
                conn,
                run_id,
                "approval",
                f"Waiting for one local operator decision. Expires at {expires_at}.",
                tool_request_id=request_id,
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="approval.requested",
                actor=actor[:120],
                entity_type="tool_request",
                entity_id=request_id,
                details={
                    "tool": tool_name,
                    "args_digest": args_digest(digest_args),
                    "request_digest": binding_digest,
                    "policy_version": int(preset["version"]),
                    "expires_at": expires_at,
                },
            )
        else:
            _append_trace(
                conn,
                run_id,
                "decision",
                f"Blocked: {outcome.reason}",
                tool_request_id=request_id,
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="tool.decision",
                actor=actor[:120],
                entity_type="tool_request",
                entity_id=request_id,
                details={
                    "decision": "BLOCK",
                    "reason_code": outcome.reason_code,
                    "tool": tool_name,
                    "policy_version": int(preset["version"]),
                },
            )
        detail = _request_detail_conn(conn, request_id)
        detail["approval_id"] = approval_id
        return detail


def _request_detail_conn(conn: sqlite3.Connection, request_id: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT r.*, a.id AS approval_id, a.state AS approval_state, a.expires_at AS approval_expires_at,
                  a.decided_at AS approval_decided_at, a.reason AS approval_reason,
                  a.expected_version AS approval_version, a.session_id AS approval_session_id,
                  e.kind AS execution_kind, e.result_sha256, sr.id AS receipt_id,
                  run.scenario_key, run.runtime_kind, run.status AS run_status
           FROM tool_requests r
           LEFT JOIN approvals a ON a.request_id = r.id
           LEFT JOIN execution_results e ON e.request_id = r.id
           LEFT JOIN simulated_receipts sr ON sr.request_id = r.id
           JOIN runs run ON run.id = r.run_id
           WHERE r.id = ?""",
        (request_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("Tool request not found.")
    data = dict(row)
    for key, target in (
        ("args_json", "arguments"),
        ("result_json", "result"),
    ):
        raw = data.pop(key)
        try:
            data[target] = json.loads(raw) if raw else None
        except ValueError:
            data[target] = None
    for key in ("decision_reason", "decision_reason_code", "resource_hash", "request_digest"):
        data[key] = str(data[key])
    definition = TOOLS.get(str(row["tool"]))
    data["effect"] = definition.effect if definition is not None else "None."
    if data.get("approval_expires_at"):
        data["approval_expired"] = parse_iso(str(data["approval_expires_at"])) <= utcnow()
    else:
        data["approval_expired"] = False
    return data


def get_request_detail(settings: Settings, request_id: str) -> dict[str, Any]:
    from .db import read_connection

    with read_connection(settings.db_path) as conn:
        return _request_detail_conn(conn, request_id)


def _invalidate_pending(
    conn: sqlite3.Connection,
    settings: Settings,
    run_id: str,
    *,
    reason_code: str,
    actor: str,
) -> list[str]:
    rows = conn.execute(
        """SELECT r.id, a.id AS approval_id FROM tool_requests r
           LEFT JOIN approvals a ON a.request_id = r.id
           WHERE r.run_id = ? AND r.status = 'PENDING'""",
        (run_id,),
    ).fetchall()
    request_ids: list[str] = []
    now = utc_iso()
    for row in rows:
        request_ids.append(str(row["id"]))
        conn.execute(
            """UPDATE tool_requests SET status = 'INVALIDATED', decided_at = ?, decided_by = 'system'
               WHERE id = ? AND status = 'PENDING'""",
            (now, row["id"]),
        )
        if row["approval_id"]:
            conn.execute(
                """UPDATE approvals SET state = 'INVALIDATED', decided_at = ?, decided_by = 'system',
                   reason = ? WHERE id = ? AND state = 'PENDING'""",
                (now, reason_code, row["approval_id"]),
            )
        _append_trace(
            conn,
            run_id,
            "approval",
            f"Approval invalidated: {reason_code}.",
            tool_request_id=str(row["id"]),
            error_code=reason_code,
        )
    if request_ids:
        append_audit(
            conn,
            settings.runtime_dir,
            action="approval.invalidated",
            actor=actor,
            entity_type="run",
            entity_id=run_id,
            details={"reason_code": reason_code, "request_ids": request_ids},
        )
    return request_ids


def _binding_matches(request: sqlite3.Row, approval: sqlite3.Row) -> bool:
    binding = request_binding(
        request_id=request["id"],
        run_id=request["run_id"],
        actor=request["actor"],
        tool=request["tool"],
        tool_schema_version=request["tool_schema_version"],
        args=json.loads(request["args_json"]),
        resource_ref=request["resource_ref"],
        resource_hash=request["resource_hash"],
        policy_preset_id=request["policy_preset_id"],
        policy_version=int(request["policy_version"]),
        expires_at=request["expires_at"],
    )
    return (
        request_digest(binding) == request["request_digest"] == approval["request_digest"]
        and args_digest(binding["arguments"]) == request["args_digest"]
        and request["expires_at"] == approval["expires_at"]
        and request["tool"] in TOOLS
        and request["tool_schema_version"] == TOOLS[request["tool"]].schema_version
    )


def _invalidate_approval(conn, settings: Settings, row: sqlite3.Row, approval_id: str, code: str) -> None:
    now = utc_iso()
    conn.execute(
        "UPDATE approvals SET state = 'INVALIDATED', decided_by = 'system', decided_at = ?, reason = ? "
        "WHERE id = ? AND state = 'PENDING'",
        (now, code, approval_id),
    )
    conn.execute(
        "UPDATE tool_requests SET status = 'INVALIDATED', decided_by = 'system', decided_at = ? "
        "WHERE id = ? AND status = 'PENDING'",
        (now, row["request_id"]),
    )
    conn.execute(
        "UPDATE runs SET status = 'COMPLETED', ended_at = ? WHERE id = ? AND status = 'WAITING_APPROVAL'",
        (now, row["run_id"]),
    )
    _append_trace(
        conn,
        row["run_id"],
        "approval",
        f"Approval invalidated: {code}.",
        tool_request_id=row["request_id"],
        error_code=code,
    )
    append_audit(
        conn,
        settings.runtime_dir,
        action="approval.invalidated",
        actor="system:gateway",
        entity_type="tool_request",
        entity_id=row["request_id"],
        details={"approval_id": approval_id, "reason_code": code},
    )


def decide_approval(
    settings: Settings,
    *,
    session_id: str,
    approval_id: str,
    decision: str,
    reviewed_request_digest: str,
    expected_version: int,
    reason: str,
    idempotency_key: str,
) -> dict[str, Any]:
    if decision not in {"approve", "reject"}:
        raise ValidationError("Decision must be approve or reject.")
    reason = reason.strip()
    if not reason or len(reason) > 500:
        raise ValidationError("A decision reason between 1 and 500 characters is required.")
    if not idempotency_key or len(idempotency_key) > 120:
        raise ValidationError("A bounded Idempotency-Key is required.")
    if expected_version < 1:
        raise ValidationError("Expected version must be positive.")
    body = {
        "approval_id": approval_id,
        "decision": decision,
        "reviewed_request_digest": reviewed_request_digest,
        "expected_version": expected_version,
        "reason": reason,
    }
    body_hash = sha256_json(body)
    post_error: ConflictError | None = None
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        existing = conn.execute(
            """SELECT body_sha256, response_json FROM idempotency_records
               WHERE scope = ? AND operation = 'approval_decision' AND key = ?""",
            (session_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            if existing["body_sha256"] != body_hash:
                raise ConflictError(
                    "Idempotency key was already used with different decision content.",
                    details={"code": "IDEMPOTENCY_BODY_MISMATCH"},
                )
            return json.loads(existing["response_json"])

        row = conn.execute(
            """SELECT a.*, r.status AS request_status, r.execution_status, r.request_digest,
                      r.policy_version, r.policy_preset_id, r.tool, r.args_json, r.resource_hash,
                      r.run_id, run.status AS run_status, run.policy_version AS run_policy_version,
                      run.policy_preset_id AS run_policy_preset_id, p.version AS preset_version,
                      p.mode AS preset_mode, r.mode AS request_mode
               FROM approvals a
               JOIN tool_requests r ON r.id = a.request_id
               JOIN runs run ON run.id = r.run_id
               JOIN policy_presets p ON p.id = r.policy_preset_id
               WHERE a.id = ?""",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("Approval not found.")
        if str(row["session_id"]) != session_id:
            raise ForbiddenError("This approval is bound to a different local operator session.")
        if str(row["state"]) != "PENDING" or str(row["request_status"]) != "PENDING":
            raise ConflictError(
                "Approval is no longer pending.",
                details={
                    "approval_state": row["state"],
                    "request_status": row["request_status"],
                    "execution_status": row["execution_status"],
                },
            )
        now = utcnow()
        stored_request = conn.execute("SELECT * FROM tool_requests WHERE id = ?", (row["request_id"],)).fetchone()
        assert stored_request is not None
        expires = parse_iso(str(row["expires_at"]))
        if now >= expires:
            now_iso = utc_iso(now)
            conn.execute(
                """UPDATE approvals SET state = 'EXPIRED', decided_at = ?, decided_by = 'system',
                   reason = 'Approval expired before a decision.' WHERE id = ? AND state = 'PENDING'""",
                (now_iso, approval_id),
            )
            conn.execute(
                """UPDATE tool_requests SET status = 'EXPIRED', decided_at = ?, decided_by = 'system'
                   WHERE id = ? AND status = 'PENDING'""",
                (now_iso, row["request_id"]),
            )
            conn.execute(
                "UPDATE runs SET status = 'COMPLETED', ended_at = ? WHERE id = ? AND status = 'WAITING_APPROVAL'",
                (now_iso, row["run_id"]),
            )
            _append_trace(
                conn,
                str(row["run_id"]),
                "approval",
                "Approval expired; submit a new request.",
                tool_request_id=str(row["request_id"]),
                error_code="APPROVAL_EXPIRED",
            )
            append_audit(
                conn,
                settings.runtime_dir,
                action="approval.expired",
                actor="system:expiry",
                entity_type="tool_request",
                entity_id=str(row["request_id"]),
                details={"approval_id": approval_id, "expires_at": row["expires_at"]},
            )
            post_error = ConflictError(
                "Approval expired. Submit a new request for a new decision.",
                details={"code": "APPROVAL_EXPIRED", "approval_state": "EXPIRED"},
            )
        elif reviewed_request_digest != row["request_digest"]:
            post_error = ConflictError(
                "Reviewed request digest does not match the stored immutable request.",
                details={"code": "REQUEST_DIGEST_MISMATCH"},
            )
        elif int(expected_version) != int(row["expected_version"]):
            post_error = ConflictError(
                "Approval version changed; refresh the request before deciding.",
                details={"code": "STALE_VERSION", "current_version": row["expected_version"]},
            )
        elif not _binding_matches(stored_request, row):
            _invalidate_approval(conn, settings, row, approval_id, "REQUEST_BINDING_CHANGED")
            post_error = ConflictError(
                "The stored request changed after review. Submit a new request.",
                details={"code": "REQUEST_BINDING_CHANGED"},
            )
        elif (
            int(row["preset_version"]) != int(row["policy_version"])
            or int(row["run_policy_version"]) != int(row["policy_version"])
            or row["run_policy_preset_id"] != row["policy_preset_id"]
            or row["preset_mode"] != row["request_mode"]
            or row["run_status"] != "WAITING_APPROVAL"
            or evaluate_proposal(
                tool=row["tool"],
                args=json.loads(row["args_json"]),
                mode=row["preset_mode"],
                policy_preset_id=row["policy_preset_id"],
                policy_version=row["policy_version"],
            ).decision
            != "REQUIRE_APPROVAL"
        ):
            _invalidate_approval(conn, settings, row, approval_id, "POLICY_CHANGED")
            post_error = ConflictError(
                "Policy version changed; the pending approval was invalidated.",
                details={"code": "POLICY_CHANGED"},
            )
        else:
            current_resource_ref, current_resource_hash = resource_for(str(row["tool"]), json.loads(row["args_json"]))
            if current_resource_hash != row["resource_hash"] or current_resource_ref != stored_request["resource_ref"]:
                _invalidate_approval(conn, settings, row, approval_id, "RESOURCE_CHANGED")
                post_error = ConflictError(
                    "The execution resource changed; the pending approval was invalidated.",
                    details={"code": "RESOURCE_CHANGED"},
                )
            else:
                now_iso = utc_iso(now)
                approval_update = conn.execute(
                    """UPDATE approvals SET state = ?, decided_at = ?, decided_by = ?, reason = ?,
                       consumed_at = ? WHERE id = ? AND state = 'PENDING' AND expected_version = ?""",
                    (
                        "CONSUMED" if decision == "approve" else "REJECTED",
                        now_iso,
                        session_id,
                        reason,
                        now_iso if decision == "approve" else None,
                        approval_id,
                        int(expected_version),
                    ),
                )
                if approval_update.rowcount != 1:
                    raise ConflictError(
                        "Approval changed concurrently; fetch current state.",
                        details={"code": "CONCURRENT_DECISION"},
                    )
                request_row = conn.execute("SELECT * FROM tool_requests WHERE id = ?", (row["request_id"],)).fetchone()
                assert request_row is not None
                response: dict[str, Any]
                if decision == "approve":
                    execution = _execute_synthetic(conn, request_row)
                    conn.execute(
                        """UPDATE tool_requests SET status = 'AUTHORIZED', execution_status = 'SUCCEEDED',
                           result_json = ?, decided_at = ?, decided_by = ?, version = version + 1
                           WHERE id = ?""",
                        (
                            canonical_json(execution["result"]).decode("utf-8"),
                            now_iso,
                            session_id,
                            row["request_id"],
                        ),
                    )
                    _append_trace(
                        conn,
                        str(row["run_id"]),
                        "execution",
                        str(execution["result"]["summary"]),
                        tool_request_id=str(row["request_id"]),
                        output_refs=[str(execution["result"].get("receipt_id", row["request_id"]))],
                    )
                    append_audit(
                        conn,
                        settings.runtime_dir,
                        action="approval.consumed",
                        actor=session_id,
                        entity_type="tool_request",
                        entity_id=str(row["request_id"]),
                        details={
                            "approval_id": approval_id,
                            "decision": "approve",
                            "request_digest": row["request_digest"],
                            "reason_sha256": sha256_json({"reason": reason}),
                            "result_hash": execution["result_hash"],
                            "synthetic": True,
                        },
                    )
                else:
                    conn.execute(
                        """UPDATE tool_requests SET status = 'REJECTED', execution_status = 'NOT_STARTED',
                           decided_at = ?, decided_by = ?, version = version + 1 WHERE id = ?""",
                        (now_iso, session_id, row["request_id"]),
                    )
                    append_audit(
                        conn,
                        settings.runtime_dir,
                        action="approval.rejected",
                        actor=session_id,
                        entity_type="tool_request",
                        entity_id=str(row["request_id"]),
                        details={
                            "approval_id": approval_id,
                            "decision": "reject",
                            "request_digest": row["request_digest"],
                            "reason_sha256": sha256_json({"reason": reason}),
                        },
                    )
                conn.execute(
                    "UPDATE runs SET status = 'COMPLETED', ended_at = ? WHERE id = ? AND status = 'WAITING_APPROVAL'",
                    (now_iso, row["run_id"]),
                )
                response = {
                    "approval_id": approval_id,
                    "decision": decision,
                    "request": _request_detail_conn(conn, str(row["request_id"])),
                    "committed": True,
                }
                conn.execute(
                    """INSERT INTO idempotency_records(id, scope, operation, key, body_sha256,
                       response_json, resource_id, created_at) VALUES (?, ?, 'approval_decision', ?, ?, ?, ?, ?)""",
                    (
                        f"idm_{os.urandom(12).hex()}",
                        session_id,
                        idempotency_key,
                        body_hash,
                        canonical_json(response).decode("utf-8"),
                        row["request_id"],
                        now_iso,
                    ),
                )
                return response
    if post_error is not None:
        raise post_error
    raise ConflictError("Approval decision did not commit.")


def cancel_run(settings: Settings, *, run_id: str, session_id: str) -> dict[str, Any]:
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        run = _run_or_404(conn, run_id)
        if str(run["created_by_session"]) != session_id:
            raise ForbiddenError("Run belongs to a different local operator session.")
        if str(run["status"]) in {"COMPLETED", "CANCELLED", "FAILED"}:
            raise ConflictError("Run is already terminal.", details={"status": run["status"]})
        invalidated = _invalidate_pending(conn, settings, run_id, reason_code="RUN_CANCELLED", actor=session_id)
        now = utc_iso()
        conn.execute("UPDATE runs SET status = 'CANCELLED', ended_at = ? WHERE id = ?", (now, run_id))
        _append_trace(conn, run_id, "cancelled", "Run cancelled by the local operator.")
        append_audit(
            conn,
            settings.runtime_dir,
            action="run.cancelled",
            actor=session_id,
            entity_type="run",
            entity_id=run_id,
            details={"invalidated_request_ids": invalidated},
        )
        return {"run_id": run_id, "status": "CANCELLED", "invalidated": len(invalidated)}


def change_run_policy(
    settings: Settings,
    *,
    run_id: str,
    session_id: str,
    policy_preset_id: str,
    expected_revision: int,
) -> dict[str, Any]:
    with transaction(settings.db_path) as conn:
        try:
            require_audit_healthy(conn, settings.runtime_dir)
        except AuditUnavailable as exc:
            raise AuditIntegrityError(str(exc)) from exc
        _session_valid(conn, session_id)
        run = _run_or_404(conn, run_id)
        if str(run["created_by_session"]) != session_id:
            raise ForbiddenError("Run belongs to a different local operator session.")
        if int(run["revision"]) != int(expected_revision):
            raise ConflictError(
                "Run revision changed; refresh before changing policy.",
                details={"current_revision": run["revision"]},
            )
        if str(run["status"]) in TERMINAL_RUN_STATES:
            raise ConflictError("A terminal run cannot change policy.", details={"status": run["status"]})
        preset = conn.execute("SELECT * FROM policy_presets WHERE id = ?", (policy_preset_id,)).fetchone()
        if preset is None:
            raise ValidationError("Unknown policy preset.")
        invalidated = _invalidate_pending(conn, settings, run_id, reason_code="POLICY_CHANGED", actor=session_id)
        conn.execute(
            """UPDATE runs SET policy_preset_id = ?, policy_version = ?, revision = revision + 1,
               status = CASE WHEN status = 'WAITING_APPROVAL' THEN 'COMPLETED' ELSE status END,
               ended_at = CASE WHEN status = 'WAITING_APPROVAL' THEN ? ELSE ended_at END
               WHERE id = ?""",
            (preset["id"], int(preset["version"]), utc_iso(), run_id),
        )
        now = utc_iso()
        _append_trace(
            conn,
            run_id,
            "policy",
            f"Policy changed to {preset['name']} version {preset['version']}; pending approvals invalidated.",
        )
        append_audit(
            conn,
            settings.runtime_dir,
            action="run.policy_changed",
            actor=session_id,
            entity_type="run",
            entity_id=run_id,
            details={
                "policy_preset_id": preset["id"],
                "policy_version": int(preset["version"]),
                "invalidated_request_ids": invalidated,
                "changed_at": now,
            },
        )
        return {
            "run_id": run_id,
            "policy_preset_id": preset["id"],
            "policy_version": int(preset["version"]),
            "invalidated": len(invalidated),
        }
