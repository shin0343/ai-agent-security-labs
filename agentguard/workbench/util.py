"""Shared deterministic helpers and constants for the workbench."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RUN_DIR = ROOT / "run"
DEFAULT_DB = DEFAULT_RUN_DIR / "workbench.db"
FIXTURE_DIR = ROOT / "examples" / "logs"
FRONTEND_DIST = ROOT / "frontend" / "dist"
SCHEMA_VERSION = 1
RULES_VERSION = "rules-2026.10.1"
SUITE_VERSION = "suite-2026.10.2"
TOOL_SCHEMA_VERSION = "tools-2026.10.1"
API_PREFIX = "/api/v1"
UTC = UTC

# Bounded ingestion defaults; these are enforced limits, not measured capacity claims.
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MAX_DATASET_BYTES = 50 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_LINE_BYTES = 64 * 1024
MAX_JSON_DEPTH = 20
CORRELATION_WINDOW_SECONDS = 60
APPROVAL_TTL_SECONDS = 10 * 60
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_PROPOSALS = 8


def utcnow() -> datetime:
    return datetime.now(UTC)


def utc_iso(value: datetime | None = None) -> str:
    value = value or utcnow()
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def iso_in(seconds: int) -> str:
    return utc_iso(utcnow() + timedelta(seconds=seconds))


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


def safe_json_loads(text: str) -> Any:
    """Reject ambiguous, non-finite, excessively nested or invalid Unicode JSON."""

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key[:40]}")
            out[key] = value
        return out

    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        result = json.loads(text, object_pairs_hook=pairs_hook, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds limit") from exc
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(value, dict):
            for key, child in value.items():
                key.encode("utf-8", errors="strict")
                pending.append((child, depth + 1))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        elif isinstance(value, str):
            value.encode("utf-8", errors="strict")
    return result


def json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((json_depth(v, depth + 1) for v in value.values()), default=depth)
    if isinstance(value, list):
        return max((json_depth(v, depth + 1) for v in value), default=depth)
    return depth


def normalize_epoch(value: Any) -> datetime | None:
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float, str)):
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                return None
            return datetime.fromtimestamp(number, UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return None


def normalize_timestamp(value: Any) -> datetime | None:
    """Accept RFC 3339 strings or Zeek epoch seconds; return UTC or None."""
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        if candidate.replace(".", "", 1).isdigit():
            return normalize_epoch(candidate)
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
        except ValueError:
            return None
    return normalize_epoch(value)


def require_within(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError("path escapes allowed root")
    return resolved
