"""Bounded evidence ingestion with immutable source snapshots and exact refs."""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import (
    MAX_DATASET_BYTES,
    MAX_JSON_DEPTH,
    MAX_LINE_BYTES,
    MAX_RECORDS,
    MAX_SOURCE_BYTES,
    canonical_json,
    json_depth,
    normalize_timestamp,
    safe_json_loads,
    sha256_bytes,
    sha256_json,
    stable_id,
    utc_iso,
)

REQUIRED_SOURCES = (
    "conn.log",
    "dns.log",
    "http.log",
    "ssl.log",
    "suricata.ndjson",
    "windows-events.ndjson",
    "agent-actions.ndjson",
)
OPTIONAL_SOURCES = ("untrusted_note.txt",)
ALLOWED_SOURCES = REQUIRED_SOURCES + OPTIONAL_SOURCES
PARSER_VERSION = "parser-2026.10.2"


class EvidenceError(ValueError):
    """A source failed validation or an evidence reference cannot be resolved."""


@dataclass(frozen=True)
class ParsedEvent:
    line_no: int
    raw_sha256: str
    event_type: str
    ts_utc: str | None
    original_ts: str | None
    actor_hint: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    uid: str | None
    action: str | None
    resource: str | None
    attrs: dict[str, Any]
    parse_status: str


@dataclass(frozen=True)
class ParsedSource:
    filename: str
    content: bytes
    sha256: str
    line_count: int
    events: tuple[ParsedEvent, ...]
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class PreparedDataset:
    name: str
    scenario_key: str
    sources: tuple[ParsedSource, ...]
    manifest: dict[str, Any]
    manifest_sha256: str

    @property
    def event_count(self) -> int:
        return sum(len(source.events) for source in self.sources)


def _text(value: Any, *, limit: int = 512) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped[:limit]
    return None


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 5:
        parsed = int(value)
        return parsed if parsed <= 65535 else None
    return None


def _timestamp_fields(
    payload: dict[str, Any], candidates: tuple[str, ...], line_label: str
) -> tuple[str | None, str | None, str]:
    original: Any = None
    for key in candidates:
        if key in payload:
            original = payload[key]
            break
    if original is None:
        return None, None, "invalid_time"
    if not isinstance(original, (str, int, float)) or isinstance(original, bool):
        return None, str(original)[:120], "invalid_time"
    normalized = normalize_timestamp(original)
    if normalized is None:
        return None, str(original)[:120], "invalid_time"
    return normalized.isoformat().replace("+00:00", "Z"), str(original)[:120], "parsed"


def _normalize(filename: str, payload: dict[str, Any], line_no: int, raw_hash: str) -> ParsedEvent:
    if json_depth(payload) > MAX_JSON_DEPTH:
        raise EvidenceError(f"JSON nesting exceeds limit at {filename}:{line_no}")
    if "EventData" in payload and payload["EventData"] is not None and not isinstance(payload["EventData"], dict):
        raise EvidenceError(f"EventData must be an object at {filename}:{line_no}")

    ts: str | None = None
    original_ts: str | None = None
    parse_status = "parsed"
    event_type = "unknown"
    actor_hint = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    uid = None
    action = None
    resource = None

    if filename in {"conn.log", "dns.log", "http.log", "ssl.log"}:
        ts, original_ts, parse_status = _timestamp_fields(payload, ("ts",), f"{filename}:{line_no}")
        src_ip = _text(payload.get("id.orig_h"), limit=64)
        dst_ip = _text(payload.get("id.resp_h"), limit=64)
        src_port = _integer(payload.get("id.orig_p"))
        dst_port = _integer(payload.get("id.resp_p"))
        uid = _text(payload.get("uid"), limit=128)
        if filename == "conn.log":
            event_type = "network_connection"
            resource = _text(payload.get("service")) or (str(dst_port) if dst_port is not None else None)
        elif filename == "dns.log":
            event_type = "dns_query"
            resource = _text(payload.get("query"))
        elif filename == "http.log":
            event_type = "http_request"
            action = _text(payload.get("method"), limit=16)
            resource = _text(payload.get("host"))
        else:
            event_type = "tls_connection"
            resource = _text(payload.get("server_name"))
    elif filename == "suricata.ndjson":
        ts, original_ts, parse_status = _timestamp_fields(payload, ("timestamp", "@timestamp"), f"{filename}:{line_no}")
        suri_type = _text(payload.get("event_type"), limit=64) or "event"
        event_type = "ids_alert" if suri_type == "alert" else "ids_event"
        src_ip = _text(payload.get("src_ip"), limit=64)
        dst_ip = _text(payload.get("dest_ip"), limit=64)
        src_port = _integer(payload.get("src_port"))
        dst_port = _integer(payload.get("dest_port"))
        flow = payload.get("flow_id")
        uid = str(flow)[:128] if isinstance(flow, (str, int)) else None
        action = suri_type
        alert = payload.get("alert")
        if suri_type == "alert" and not isinstance(alert, dict):
            raise EvidenceError(f"Suricata alert must be an object at {filename}:{line_no}")
        resource = _text(alert.get("signature"), limit=256) if isinstance(alert, dict) else None
    elif filename == "windows-events.ndjson":
        ts, original_ts, parse_status = _timestamp_fields(payload, ("@timestamp", "timestamp"), f"{filename}:{line_no}")
        event_id = payload.get("EventID")
        event_data = payload.get("EventData") or {}
        mapping = {4688: "windows_process", 4625: "windows_logon_failure"}
        event_type = mapping.get(event_id, "windows_event") if isinstance(event_id, int) else "windows_event"
        actor_hint = _text(event_data.get("SubjectUserName")) if isinstance(event_data, dict) else None
        src_ip = _text(event_data.get("IpAddress")) if isinstance(event_data, dict) else None
        dst_ip = _text(event_data.get("TargetHost")) if isinstance(event_data, dict) else None
        resource = dst_ip or _text(payload.get("Computer"))
        action = "process_start" if event_id == 4688 else ("logon_failure" if event_id == 4625 else None)
    elif filename == "agent-actions.ndjson":
        ts, original_ts, parse_status = _timestamp_fields(
            payload, ("timestamp", "@timestamp", "time"), f"{filename}:{line_no}"
        )
        event_type = "agent_action"
        actor_hint = _text(payload.get("agent"))
        action = _text(payload.get("action"))
        resource = _text(payload.get("resource"))
        if actor_hint is None or action is None:
            raise EvidenceError(f"Agent action requires agent and action at {filename}:{line_no}")
    else:
        raise EvidenceError(f"Unsupported source {filename}")

    port_fields = ("id.orig_p", "id.resp_p") if filename.endswith(".log") else ("src_port", "dest_port")
    for field in port_fields:
        if payload.get(field) is not None and _integer(payload[field]) is None:
            raise EvidenceError(f"Invalid port at {filename}:{line_no}")

    return ParsedEvent(
        line_no=line_no,
        raw_sha256=raw_hash,
        event_type=event_type,
        ts_utc=ts,
        original_ts=original_ts,
        actor_hint=actor_hint,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        uid=uid,
        action=action,
        resource=resource,
        attrs=payload,
        parse_status=parse_status,
    )


def _parse_source(filename: str, content: bytes) -> ParsedSource:
    if len(content) > MAX_SOURCE_BYTES:
        raise EvidenceError(f"Source exceeds size limit: {filename}")
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"Source is not valid UTF-8: {filename}") from exc
    if "\x00" in text:
        raise EvidenceError(f"Source contains NUL bytes: {filename}")
    raw_lines = text.splitlines()
    events: list[ParsedEvent] = []
    if filename in OPTIONAL_SOURCES:
        return ParsedSource(
            filename=filename,
            content=content,
            sha256=sha256_bytes(content),
            line_count=len(raw_lines),
            events=(),
            parser_version="text-inert-v1",
        )
    for line_no, line in enumerate(raw_lines, 1):
        if not line.strip():
            continue
        encoded = line.encode("utf-8")
        if len(encoded) > MAX_LINE_BYTES:
            raise EvidenceError(f"Line exceeds size limit at {filename}:{line_no}")
        try:
            payload = safe_json_loads(line)
        except ValueError as exc:
            raise EvidenceError(f"Invalid JSON at {filename}:{line_no}: {exc}") from exc
        if not isinstance(payload, dict):
            raise EvidenceError(f"Expected JSON object at {filename}:{line_no}")
        events.append(_normalize(filename, payload, line_no, sha256_bytes(encoded)))
    return ParsedSource(
        filename=filename,
        content=content,
        sha256=sha256_bytes(content),
        line_count=len(raw_lines),
        events=tuple(events),
    )


def collect_dataset(
    root: Path,
    *,
    name: str,
    scenario_key: str,
    required: tuple[str, ...] = REQUIRED_SOURCES,
    optional: tuple[str, ...] = OPTIONAL_SOURCES,
) -> PreparedDataset:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError("Dataset directory not found")
    available = {entry.name: entry for entry in root.iterdir()}
    sources: list[ParsedSource] = []
    total_bytes = 0
    total_events = 0
    for filename in required + optional:
        if filename not in ALLOWED_SOURCES:
            raise EvidenceError(f"Source is not allowlisted: {filename}")
        path = available.get(filename)
        if path is None:
            if filename in required:
                raise EvidenceError(f"Missing required source: {filename}")
            continue
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"Source must be a regular file: {filename}")
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError as exc:
            raise EvidenceError(f"Source escapes dataset root: {filename}") from exc
        size = path.stat().st_size
        if size > MAX_SOURCE_BYTES:
            raise EvidenceError(f"Source exceeds size limit: {filename}")
        try:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
                with os.fdopen(fd, "rb") as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise EvidenceError(f"Source must be a regular file: {filename}")
                    content = source.read(MAX_SOURCE_BYTES + 1)
            finally:
                os.close(root_fd)
        except OSError as exc:
            raise EvidenceError(f"Unable to read source: {filename}") from exc
        total_bytes += len(content)
        if total_bytes > MAX_DATASET_BYTES:
            raise EvidenceError("Dataset exceeds size limit")
        parsed = _parse_source(filename, content)
        total_events += len(parsed.events)
        if total_events > MAX_RECORDS:
            raise EvidenceError("Dataset exceeds record limit")
        sources.append(parsed)
    if total_events == 0:
        raise EvidenceError("Dataset contains no parseable events")

    manifest = {
        "schema": 1,
        "name": name,
        "scenario_key": scenario_key,
        "data_class": "synthetic",
        "parser_version": PARSER_VERSION,
        "files": [
            {
                "filename": source.filename,
                "sha256": source.sha256,
                "bytes": len(source.content),
                "lines": source.line_count,
                "events": len(source.events),
                "parser_version": source.parser_version,
            }
            for source in sources
        ],
        "event_count": total_events,
        "total_bytes": total_bytes,
    }
    return PreparedDataset(
        name=name,
        scenario_key=scenario_key,
        sources=tuple(sources),
        manifest=manifest,
        manifest_sha256=sha256_json(manifest),
    )


def persist_dataset(
    conn: sqlite3.Connection,
    prepared: PreparedDataset,
    *,
    is_sample: bool = False,
) -> tuple[str, bool]:
    existing = conn.execute(
        """SELECT id FROM datasets
           WHERE scenario_key = ? AND manifest_sha256 = ?""",
        (prepared.scenario_key, prepared.manifest_sha256),
    ).fetchone()
    if existing is not None:
        return str(existing["id"]), False

    dataset_id = f"ds_{os.urandom(12).hex()}"
    now = utc_iso()
    conn.execute(
        """INSERT INTO datasets(id, name, scenario_key, data_class, manifest_json,
           manifest_sha256, is_sample, created_at) VALUES (?, ?, ?, 'synthetic', ?, ?, ?, ?)""",
        (
            dataset_id,
            prepared.name,
            prepared.scenario_key,
            canonical_json(prepared.manifest).decode("utf-8"),
            prepared.manifest_sha256,
            1 if is_sample else 0,
            now,
        ),
    )
    for source in prepared.sources:
        source_id = f"src_{os.urandom(12).hex()}"
        conn.execute(
            """INSERT INTO source_blobs(id, dataset_id, filename, content, sha256, byte_count,
               line_count, parser_version, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                source_id,
                dataset_id,
                source.filename,
                source.content,
                source.sha256,
                len(source.content),
                source.line_count,
                source.parser_version,
                now,
            ),
        )
        for event in source.events:
            event_id = stable_id("evt", dataset_id, source.filename, str(event.line_no))
            conn.execute(
                """INSERT INTO events(id, dataset_id, source_id, line_no, raw_sha256, event_type,
                   ts_utc, original_ts, actor_hint, src_ip, dst_ip, src_port, dst_port, uid,
                   action, resource, attrs_json, parse_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id,
                    dataset_id,
                    source_id,
                    event.line_no,
                    event.raw_sha256,
                    event.event_type,
                    event.ts_utc,
                    event.original_ts,
                    event.actor_hint,
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.uid,
                    event.action,
                    event.resource,
                    canonical_json(event.attrs).decode("utf-8"),
                    event.parse_status,
                ),
            )
    return dataset_id, True


def get_dataset(conn: sqlite3.Connection, dataset_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["manifest"] = safe_json_loads(data.pop("manifest_json"))
    return data


def latest_sample(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM datasets WHERE is_sample = 1 ORDER BY created_at DESC, id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["manifest"] = safe_json_loads(data.pop("manifest_json"))
    return data


def list_datasets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT d.*, COUNT(e.id) AS event_count
           FROM datasets d LEFT JOIN events e ON e.dataset_id = d.id
           GROUP BY d.id ORDER BY d.created_at DESC"""
    ).fetchall()
    result = []
    for row in rows:
        data = dict(row)
        data["manifest"] = safe_json_loads(data.pop("manifest_json"))
        result.append(data)
    return result


def source_coverage(conn: sqlite3.Connection, dataset_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT s.id, s.filename, s.sha256, s.byte_count, s.line_count, s.parser_version,
                  COUNT(e.id) AS event_count,
                  MAX(CASE WHEN e.parse_status != 'parsed' THEN e.parse_status END) AS parse_warning
           FROM source_blobs s LEFT JOIN events e ON e.source_id = s.id
           WHERE s.dataset_id = ? GROUP BY s.id ORDER BY s.filename""",
        (dataset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def resolve_evidence(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT e.*, s.filename, s.content, s.sha256 AS source_sha256, s.parser_version,
                  s.byte_count, d.name AS dataset_name, d.scenario_key, d.data_class
           FROM events e
           JOIN source_blobs s ON s.id = e.source_id
           JOIN datasets d ON d.id = e.dataset_id
           WHERE e.id = ?""",
        (event_id,),
    ).fetchone()
    if row is None:
        raise EvidenceError("Evidence not found")
    raw_content: bytes = row["content"]
    if sha256_bytes(raw_content) != str(row["source_sha256"]):
        raise EvidenceError("Captured source snapshot hash mismatch")
    try:
        lines = raw_content.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise EvidenceError("Captured source is not valid UTF-8") from exc
    line_index = int(row["line_no"]) - 1
    if line_index < 0 or line_index >= len(lines):
        raise EvidenceError("Captured line is no longer present in the immutable source snapshot")
    raw_line = lines[line_index]
    if sha256_bytes(raw_line.encode("utf-8")) != row["raw_sha256"]:
        raise EvidenceError("Evidence hash mismatch against the immutable source snapshot")
    payload = safe_json_loads(raw_line)
    context_start = max(0, line_index - 2)
    context_end = min(len(lines), line_index + 3)
    context = [{"line": index + 1, "text": lines[index]} for index in range(context_start, context_end)]
    return {
        "event_id": row["id"],
        "dataset_id": row["dataset_id"],
        "dataset_name": row["dataset_name"],
        "scenario_key": row["scenario_key"],
        "data_class": row["data_class"],
        "source_id": row["source_id"],
        "source_filename": row["filename"],
        "source_sha256": row["source_sha256"],
        "parser_version": row["parser_version"],
        "line": int(row["line_no"]),
        "ref": f"{row['filename']}:{row['line_no']}",
        "raw_sha256": row["raw_sha256"],
        "event_type": row["event_type"],
        "ts_utc": row["ts_utc"],
        "original_ts": row["original_ts"],
        "parse_status": row["parse_status"],
        "actor_hint": row["actor_hint"],
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "uid": row["uid"],
        "action": row["action"],
        "resource": row["resource"],
        "raw": payload,
        "context": context,
        "integrity": "verified",
    }


def resolve_ref(conn: sqlite3.Connection, dataset_id: str, ref: str) -> dict[str, Any]:
    filename, sep, line = ref.partition(":")
    if not sep or filename not in ALLOWED_SOURCES or not line.isascii() or not line.isdigit():
        raise EvidenceError("Invalid evidence reference")
    if int(line) < 1:
        raise EvidenceError("Invalid evidence reference")
    row = conn.execute(
        """SELECT e.id FROM events e JOIN source_blobs s ON s.id = e.source_id
           WHERE e.dataset_id = ? AND s.filename = ? AND e.line_no = ?""",
        (dataset_id, filename, int(line)),
    ).fetchone()
    if row is None:
        raise EvidenceError("Evidence reference not found")
    return resolve_evidence(conn, str(row["id"]))


def event_ids_for_dataset(conn: sqlite3.Connection, dataset_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT id FROM events WHERE dataset_id = ? ORDER BY ts_utc IS NULL, ts_utc, source_id, line_no",
        (dataset_id,),
    ).fetchall()
    return [str(row["id"]) for row in rows]
