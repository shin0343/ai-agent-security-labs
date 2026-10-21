"""Evidence refs, bounded ingestion, symlink rejection and immutable snapshots."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentguard.workbench.db import read_connection, transaction
from agentguard.workbench.evidence import (
    REQUIRED_SOURCES,
    EvidenceError,
    collect_dataset,
    resolve_evidence,
    resolve_ref,
)
from agentguard.workbench.util import FIXTURE_DIR

from .conftest import WorkbenchHarness


def _copied_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "logs"
    shutil.copytree(FIXTURE_DIR, root)
    return root


def _evidence_id(workbench: WorkbenchHarness) -> str:
    listing = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}&limit=20")
    assert listing.status_code == 200
    finding_id = listing.json()["items"][0]["id"]
    detail = workbench.client.get(f"/api/v1/findings/{finding_id}")
    assert detail.status_code == 200
    return str(detail.json()["evidence"][0]["event_id"])


def test_resolved_evidence_is_exact_and_hashed(workbench: WorkbenchHarness) -> None:
    event_id = _evidence_id(workbench)
    response = workbench.client.get(f"/api/v1/events/{event_id}")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["event_id"] == event_id
    assert data["ref"].count(":") == 1
    assert data["integrity"] == "verified"
    assert len(data["raw_sha256"]) == 64
    assert len(data["source_sha256"]) == 64
    assert data["raw"]
    assert any(line["line"] == data["line"] for line in data["context"])
    assert "does not prove" in str(data) or data["source_filename"]


@pytest.mark.parametrize(
    "bad_ref",
    [
        "../conn.log:1",
        "/etc/passwd:1",
        "conn.log:0",
        "conn.log:-1",
        "conn.log:abc",
        "conn.log:999999",
        "conn.log:１",
        "http.log:1:extra",
        "not-a-source.log:1",
    ],
)
def test_invalid_evidence_refs_fail(workbench: WorkbenchHarness, bad_ref: str) -> None:
    with read_connection(workbench.db_path) as conn:
        with pytest.raises(EvidenceError):
            resolve_ref(conn, workbench.dataset_id, bad_ref)


def test_unknown_event_and_mutated_snapshot_are_rejected(workbench: WorkbenchHarness) -> None:
    assert workbench.client.get("/api/v1/events/evt_missing").status_code == 409
    event_id = _evidence_id(workbench)
    with transaction(workbench.db_path) as conn:
        row = conn.execute(
            "SELECT content FROM source_blobs WHERE id = (SELECT source_id FROM events WHERE id = ?)",
            (event_id,),
        ).fetchone()
        conn.execute(
            "UPDATE source_blobs SET content = ? WHERE id = (SELECT source_id FROM events WHERE id = ?)",
            (bytes(row["content"]) + b"\n", event_id),
        )
    response = workbench.client.get(f"/api/v1/events/{event_id}")
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    with read_connection(workbench.db_path) as conn:
        with pytest.raises(EvidenceError, match="hash mismatch"):
            resolve_evidence(conn, event_id)


def test_symlinked_source_is_rejected(tmp_path: Path) -> None:
    root = _copied_fixture(tmp_path)
    target = root / "conn-real.log"
    (root / "conn.log").rename(target)
    (root / "conn.log").symlink_to(target)
    with pytest.raises(EvidenceError, match="regular file"):
        collect_dataset(root, name="symlink", scenario_key="test")


def test_missing_required_source_fails_closed(tmp_path: Path) -> None:
    root = _copied_fixture(tmp_path)
    (root / "windows-events.ndjson").unlink()
    with pytest.raises(EvidenceError, match="Missing required source"):
        collect_dataset(root, name="missing", scenario_key="test")


def test_malformed_json_line_fails_closed(tmp_path: Path) -> None:
    root = _copied_fixture(tmp_path)
    with (root / "conn.log").open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
    with pytest.raises(EvidenceError, match="Invalid JSON"):
        collect_dataset(root, name="bad-json", scenario_key="test")


def test_oversized_line_fails_closed(tmp_path: Path) -> None:
    root = _copied_fixture(tmp_path)
    with (root / "conn.log").open("a", encoding="utf-8") as handle:
        handle.write('{"ts": 1, "pad": "' + ("x" * (64 * 1024)) + '"}\n')
    with pytest.raises(EvidenceError, match="Line exceeds size limit"):
        collect_dataset(root, name="big-line", scenario_key="test")


def test_invalid_utf8_and_nul_fail_closed(tmp_path: Path) -> None:
    root = _copied_fixture(tmp_path)
    (root / "dns.log").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(EvidenceError):
        collect_dataset(root, name="binary", scenario_key="test")


def test_optional_untrusted_note_is_stored_as_inert_text(tmp_path: Path) -> None:
    prepared = collect_dataset(FIXTURE_DIR, name="sample", scenario_key="test")
    note = next(source for source in prepared.sources if source.filename == "untrusted_note.txt")
    assert note.events == ()
    assert note.content
    assert all(
        source.filename in REQUIRED_SOURCES or source.filename == "untrusted_note.txt" for source in prepared.sources
    )


def test_finding_evidence_integrity_exposes_invalid_snapshot(workbench: WorkbenchHarness) -> None:
    event_id = _evidence_id(workbench)
    finding_id = workbench.client.get(f"/api/v1/findings?dataset_id={workbench.dataset_id}&limit=1").json()["items"][0][
        "id"
    ]
    with transaction(workbench.db_path) as conn:
        conn.execute(
            "UPDATE source_blobs SET content = ? WHERE id = (SELECT source_id FROM events WHERE id = ?)",
            (b"mutated", event_id),
        )
    detail = workbench.client.get(f"/api/v1/findings/{finding_id}")
    assert detail.status_code == 200
    assert detail.json()["evidence_integrity"] == "invalid"
