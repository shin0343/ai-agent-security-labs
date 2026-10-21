"""SQLite lifecycle, migrations and short transaction helpers."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .util import DEFAULT_DB, SCHEMA_VERSION, sha256_bytes, utc_iso

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(
        db_path,
        timeout=5.0,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def _split_statements(sql: str) -> list[str]:
    # Migrations are first-party SQL with no quoted semicolons. Keeping this
    # explicit avoids sqlite3.executescript's implicit COMMIT.
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def migrate(db_path: Path = DEFAULT_DB) -> None:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(db_path.parent, 0o700)
    except OSError:
        pass
    conn = _connect(db_path)
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )"""
        )
        applied = {
            int(row["version"]): str(row["checksum"])
            for row in conn.execute("SELECT version, checksum FROM schema_migrations")
        }
        files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        for path in files:
            version = int(path.name.split("_", 1)[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(f"unsupported schema version {version}")
            sql = path.read_text(encoding="utf-8")
            checksum = sha256_bytes(sql.encode("utf-8"))
            if version in applied:
                if applied[version] != checksum:
                    raise RuntimeError(f"migration {version} checksum mismatch")
                continue
            statements = _split_statements(sql)
            conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)",
                    (version, checksum, utc_iso()),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        current = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        if not current or int(current["v"] or 0) != SCHEMA_VERSION:
            raise RuntimeError("database schema is not at the expected version")
        _seed_presets(conn)
    finally:
        conn.close()
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass


def _seed_presets(conn: sqlite3.Connection) -> None:
    presets = (
        (
            "deny-v1",
            "Deny",
            "DENY",
            "Risky tool calls are blocked before execution. Safe reads remain available.",
            1,
        ),
        (
            "approve-v1",
            "Approve",
            "APPROVE",
            "Risky tool calls wait for one local operator approval bound to the exact request.",
            1,
        ),
        (
            "monitor-v1",
            "Monitor (simulation)",
            "MONITOR",
            "Risky calls are recorded and executed only against the local synthetic adapter.",
            1,
        ),
    )
    now = utc_iso()
    conn.executemany(
        """INSERT OR IGNORE INTO policy_presets
           (id, name, mode, description, version, created_at) VALUES (?, ?, ?, ?, ?, ?)""",
        [(*preset, now) for preset in presets],
    )
    conn.execute(
        """INSERT OR IGNORE INTO audit_state(id, head_seq, head_mac, updated_at)
           VALUES (1, 0, ?, ?)""",
        ("0" * 64, now),
    )


@contextmanager
def transaction(db_path: Path = DEFAULT_DB, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
    """Open one connection and one explicit transaction, committing all or nothing."""
    conn = _connect(Path(db_path))
    try:
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


@contextmanager
def read_connection(db_path: Path = DEFAULT_DB) -> Iterator[sqlite3.Connection]:
    conn = _connect(Path(db_path))
    try:
        yield conn
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
