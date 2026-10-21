"""Local operator session tokens and CSRF values."""

from __future__ import annotations

import hmac
import secrets
from typing import Any

from .db import read_connection, transaction
from .util import iso_in, parse_iso, sha256_bytes, utc_iso, utcnow


def _token_hash(token: str) -> str:
    return sha256_bytes(token.encode("utf-8"))


def create_session(settings, operator_id: str) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    session_id = f"ses_{secrets.token_hex(12)}"
    now = utc_iso()
    expires = iso_in(settings.session_ttl_seconds)
    with transaction(settings.db_path) as conn:
        conn.execute(
            """INSERT INTO sessions(id, token_hash, csrf_token, operator_id, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, _token_hash(token), csrf, operator_id[:80], now, expires),
        )
    return {
        "session_id": session_id,
        "token": token,
        "csrf_token": csrf,
        "operator_id": operator_id[:80],
        "created_at": now,
        "expires_at": expires,
    }


def resolve_session(settings, token: str | None) -> dict[str, Any] | None:
    if not token or len(token) > 200:
        return None
    with read_connection(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (_token_hash(token),)).fetchone()
        if row is None or row["revoked_at"] is not None:
            return None
        if parse_iso(str(row["expires_at"])) <= utcnow():
            return None
        return {
            "session_id": row["id"],
            "csrf_token": row["csrf_token"],
            "operator_id": row["operator_id"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
        }


def revoke_session(settings, session_id: str) -> None:
    with transaction(settings.db_path) as conn:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (utc_iso(), session_id),
        )


def csrf_matches(expected: str, supplied: str | None) -> bool:
    if not supplied:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def constant_time_code(expected: str, supplied: str) -> bool:
    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def generate_bootstrap_code() -> str:
    # Human-transferable, high entropy, grouped for terminal copy.
    raw = secrets.token_hex(8).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
