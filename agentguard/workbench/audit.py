"""Transactional HMAC audit chain with explicit integrity/completeness limits."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import canonical_json, safe_json_loads, sha256_bytes, utc_iso

GENESIS = "0" * 64
KEY_ID = "local-v1"


class AuditUnavailable(RuntimeError):
    """Raised when audit state cannot support a safe mutation."""


@dataclass(frozen=True)
class AuditReport:
    integrity: str
    completeness: str
    consistency: str
    safe_for_mutations: bool
    checked_events: int
    checked_from: int | None
    checked_to: int | None
    head_mac: str | None
    key_status: str
    first_failure_seq: int | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "integrity": self.integrity,
            "completeness": self.completeness,
            "consistency": self.consistency,
            "safe_for_mutations": self.safe_for_mutations,
            "checked_events": self.checked_events,
            "checked_from": self.checked_from,
            "checked_to": self.checked_to,
            "head_mac": self.head_mac,
            "key_status": self.key_status,
            "first_failure_seq": self.first_failure_seq,
            "message": self.message,
        }


def key_path_for(runtime_dir: Path) -> Path:
    return Path(runtime_dir) / "audit.key"


def _load_key(path: Path, *, create: bool) -> bytes | None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise AuditUnavailable("audit key is not a regular file")
        key = path.read_bytes()
        if len(key) != 32:
            raise AuditUnavailable("audit key has an invalid length")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise AuditUnavailable("audit key permissions are too broad")
        return key
    if not create:
        return None
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(os.urandom(32))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path.read_bytes()


def _mac(key: bytes, seq: int, prev_mac: str, payload_json: str) -> str:
    signed = {"seq": seq, "prev_mac": prev_mac, "payload": payload_json, "key_id": KEY_ID}
    return hmac.new(key, canonical_json(signed), hashlib.sha256).hexdigest()


def _event_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()
    return int(row["count"])


def append_audit(
    conn: sqlite3.Connection,
    runtime_dir: Path,
    *,
    action: str,
    actor: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any],
    correlation_id: str | None = None,
) -> int:
    """Append an audit event inside the caller's existing transaction."""
    if not conn.in_transaction:
        raise AuditUnavailable("audit append requires an explicit transaction")
    require_audit_healthy(conn, runtime_dir)
    count = _event_count(conn)
    key = _load_key(key_path_for(runtime_dir), create=count == 0)
    if key is None:
        raise AuditUnavailable("audit key is missing for existing history")

    state = conn.execute("SELECT head_seq, head_mac FROM audit_state WHERE id = 1").fetchone()
    if state is None:
        raise AuditUnavailable("audit state is missing")
    last = conn.execute("SELECT seq, mac FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    expected_seq = int(state["head_seq"]) + 1
    if last is not None and (int(last["seq"]) != int(state["head_seq"]) or last["mac"] != state["head_mac"]):
        raise AuditUnavailable("audit head does not match retained events")

    payload = {
        "schema": 1,
        "action": action,
        "actor": actor,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": details,
        "correlation_id": correlation_id,
        "recorded_at": utc_iso(),
    }
    payload_json = canonical_json(payload).decode("utf-8")
    prev = str(state["head_mac"])
    mac = _mac(key, expected_seq, prev, payload_json)
    conn.execute(
        """INSERT INTO audit_events(seq, prev_mac, payload_json, mac, key_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (expected_seq, prev, payload_json, mac, KEY_ID, payload["recorded_at"]),
    )
    conn.execute(
        "UPDATE audit_state SET head_seq = ?, head_mac = ?, updated_at = ? WHERE id = 1",
        (expected_seq, mac, payload["recorded_at"]),
    )
    return expected_seq


def read_events(conn: sqlite3.Connection, *, limit: int = 200, before_seq: int | None = None) -> list[dict]:
    params: list[Any] = []
    where = ""
    if before_seq is not None:
        where = "WHERE seq < ?"
        params.append(before_seq)
    params.append(limit)
    rows = conn.execute(
        f"""SELECT seq, prev_mac, payload_json, mac, key_id, created_at
            FROM audit_events {where} ORDER BY seq DESC LIMIT ?""",
        params,
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        payload = sqlite3_row_payload(row["payload_json"])
        events.append(
            {
                "seq": int(row["seq"]),
                "prev_mac": row["prev_mac"],
                "mac": row["mac"],
                "key_id": row["key_id"],
                "created_at": row["created_at"],
                "payload": payload,
            }
        )
    return events


def sqlite3_row_payload(raw: str) -> Any:
    try:
        return safe_json_loads(raw)
    except ValueError:
        return {"parse_error": "INVALID_AUDIT_PAYLOAD", "raw_text": str(raw)[:2000]}


def verify_audit(conn: sqlite3.Connection, runtime_dir: Path) -> AuditReport:
    try:
        key = _load_key(key_path_for(runtime_dir), create=False)
    except (AuditUnavailable, OSError) as exc:
        return AuditReport(
            integrity="unverifiable",
            completeness="unanchored",
            consistency="unknown",
            safe_for_mutations=False,
            checked_events=0,
            checked_from=None,
            checked_to=None,
            head_mac=None,
            key_status="invalid",
            first_failure_seq=None,
            message=str(exc),
        )

    rows = conn.execute(
        "SELECT seq, prev_mac, payload_json, mac, key_id, created_at FROM audit_events ORDER BY seq ASC"
    ).fetchall()
    count = len(rows)
    state = conn.execute("SELECT head_seq, head_mac FROM audit_state WHERE id = 1").fetchone()
    checkpoint_empty = bool(state is not None and int(state["head_seq"]) == 0 and str(state["head_mac"]) == GENESIS)
    if count == 0:
        if not checkpoint_empty:
            return AuditReport(
                integrity="unverifiable",
                completeness="checkpoint_mismatch",
                consistency="failed",
                safe_for_mutations=False,
                checked_events=0,
                checked_from=None,
                checked_to=None,
                head_mac=None,
                key_status="available" if key else "absent",
                first_failure_seq=None,
                message=(
                    "No audit events are retained but the local checkpoint records prior history. "
                    "Deletion or database substitution is possible."
                ),
            )
        return AuditReport(
            integrity="unverifiable",
            completeness="unanchored",
            consistency="unknown",
            safe_for_mutations=True,
            checked_events=0,
            checked_from=None,
            checked_to=None,
            head_mac=None,
            key_status="available" if key else "absent",
            first_failure_seq=None,
            message="No audit events recorded. Empty history is not a positive completeness claim.",
        )
    if key is None:
        return AuditReport(
            integrity="unverifiable",
            completeness="unanchored",
            consistency="unknown",
            safe_for_mutations=False,
            checked_events=count,
            checked_from=int(rows[0]["seq"]),
            checked_to=int(rows[-1]["seq"]),
            head_mac=rows[-1]["mac"],
            key_status="missing",
            first_failure_seq=None,
            message="Audit key is missing; retained history cannot be verified.",
        )

    prev = GENESIS
    first_failure: int | None = None
    for index, row in enumerate(rows, 1):
        seq = int(row["seq"])
        if seq != index or row["prev_mac"] != prev:
            first_failure = seq
            break
        expected = _mac(key, seq, row["prev_mac"], row["payload_json"])
        if (
            not hmac.compare_digest(str(row["mac"]).encode("utf-8"), expected.encode("ascii"))
            or row["key_id"] != KEY_ID
        ):
            first_failure = seq
            break
        try:
            payload = safe_json_loads(row["payload_json"])
            if not isinstance(payload, dict) or payload.get("recorded_at") != row["created_at"]:
                first_failure = seq
                break
        except ValueError:
            first_failure = seq
            break
        prev = str(row["mac"])

    state_matches = bool(
        state is not None
        and int(state["head_seq"]) == int(rows[-1]["seq"])
        and str(state["head_mac"]) == str(rows[-1]["mac"])
    )
    if first_failure is not None:
        return AuditReport(
            integrity="invalid",
            completeness="unanchored",
            consistency="failed",
            safe_for_mutations=False,
            checked_events=count,
            checked_from=int(rows[0]["seq"]),
            checked_to=int(rows[-1]["seq"]),
            head_mac=rows[-1]["mac"],
            key_status="available",
            first_failure_seq=first_failure,
            message=f"Audit chain verification failed at sequence {first_failure}.",
        )
    if not state_matches:
        return AuditReport(
            integrity="valid",
            completeness="checkpoint_mismatch",
            consistency="failed",
            safe_for_mutations=False,
            checked_events=count,
            checked_from=int(rows[0]["seq"]),
            checked_to=int(rows[-1]["seq"]),
            head_mac=rows[-1]["mac"],
            key_status="available",
            first_failure_seq=None,
            message=(
                "Retained events form a valid chain but do not match the local head checkpoint; "
                "suffix deletion or database substitution is possible."
            ),
        )
    return AuditReport(
        integrity="valid",
        completeness="checkpoint_matched",
        consistency="ok",
        safe_for_mutations=True,
        checked_events=count,
        checked_from=int(rows[0]["seq"]),
        checked_to=int(rows[-1]["seq"]),
        head_mac=rows[-1]["mac"],
        key_status="available",
        first_failure_seq=None,
        message=(
            "HMAC chain and local head checkpoint match. This detects alteration of retained records "
            "relative to this local checkpoint; it is not independent tamper-proof storage."
        ),
    )


def require_audit_healthy(conn: sqlite3.Connection, runtime_dir: Path) -> AuditReport:
    report = verify_audit(conn, runtime_dir)
    if not report.safe_for_mutations:
        raise AuditUnavailable(report.message)
    return report


def head_digest(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT head_seq, head_mac FROM audit_state WHERE id = 1").fetchone()
    if row is None:
        return "uninitialized"
    return sha256_bytes(f"{row['head_seq']}:{row['head_mac']}".encode())
