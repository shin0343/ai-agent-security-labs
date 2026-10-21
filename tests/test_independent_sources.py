"""Independent parser corpus; no demo generator or detection gold labels."""

from __future__ import annotations

import json

import pytest

from agentguard.workbench.db import transaction
from agentguard.workbench.evidence import EvidenceError, collect_dataset, persist_dataset, resolve_evidence
from agentguard.workbench.util import normalize_timestamp


def _sources(root):
    root.mkdir()
    records = {
        "conn.log": {
            "ts": 1700000000.125,
            "uid": "independent-flow",
            "id.orig_h": "192.0.2.11",
            "id.resp_h": "198.51.100.9",
            "id.orig_p": 49321,
            "id.resp_p": 443,
        },
        "dns.log": {"ts": "1700000000.125", "uid": "independent-dns", "query": "assets.example.invalid"},
        "http.log": {
            "ts": 1700000001,
            "uid": "independent-http",
            "method": "GET",
            "host": "assets.example.invalid",
            "uri": "/synthetic",
        },
        "ssl.log": {"ts": 1700000002, "uid": "independent-tls", "server_name": "assets.example.invalid"},
        "suricata.ndjson": {
            "timestamp": "2023-11-14T23:13:23.250+01:00",
            "event_type": "alert",
            "flow_id": 8142,
            "alert": {"signature": "Synthetic independent alert"},
        },
        "windows-events.ndjson": {
            "@timestamp": "2023-11-14T22:13:24Z",
            "EventID": 4625,
            "EventData": {
                "SubjectUserName": "SyntheticOperator",
                "IpAddress": "192.0.2.11",
                "TargetHost": "198.51.100.9",
            },
        },
        "agent-actions.ndjson": {
            "timestamp": "2023-11-14T22:13:25Z",
            "agent": "independent-agent",
            "action": "read",
            "resource": "synthetic-record",
        },
    }
    for name, record in records.items():
        (root / name).write_text(json.dumps(record) + "\n", encoding="utf-8")
    return records


def test_all_seven_parsers_preserve_independent_provenance(workbench, tmp_path):
    root = tmp_path / "independent"
    records = _sources(root)
    prepared = collect_dataset(root, name="Independent parser corpus", scenario_key="parser-validation-v1")
    assert prepared.event_count == 7
    events = {source.filename: source.events[0] for source in prepared.sources}
    assert events["conn.log"].ts_utc == events["dns.log"].ts_utc == "2023-11-14T22:13:20.125000Z"
    assert events["suricata.ndjson"].ts_utc == "2023-11-14T22:13:23.250000Z"
    assert events["windows-events.ndjson"].event_type == "windows_logon_failure"
    with transaction(workbench.db_path) as conn:
        dataset_id, created = persist_dataset(conn, prepared)
        assert created
        for row in conn.execute("SELECT id FROM events WHERE dataset_id = ?", (dataset_id,)).fetchall():
            evidence = resolve_evidence(conn, row["id"])
            assert evidence["line"] == 1
            assert evidence["raw"] == records[evidence["source_filename"]]
            assert evidence["integrity"] == "verified"


@pytest.mark.parametrize("port", [-1, 65536, True, "9" * 100, 2**100])
def test_invalid_port_is_a_source_validation_error(tmp_path, port):
    root = tmp_path / "invalid-port"
    records = _sources(root)
    records["conn.log"]["id.orig_p"] = port
    (root / "conn.log").write_text(json.dumps(records["conn.log"]) + "\n")
    with pytest.raises(EvidenceError, match="Invalid port"):
        collect_dataset(root, name="Invalid port", scenario_key="parser-validation-v1")


def test_timezone_free_timestamp_remains_unknown():
    assert normalize_timestamp("2023-11-14T22:13:20") is None


def test_missing_timestamp_is_an_explicit_parse_warning(tmp_path):
    root = tmp_path / "missing-time"
    _sources(root)
    (root / "dns.log").write_text('{"query":"assets.example.invalid"}\n')
    prepared = collect_dataset(root, name="Missing time", scenario_key="parser-validation-v1")
    event = next(source for source in prepared.sources if source.filename == "dns.log").events[0]
    assert event.ts_utc is None and event.parse_status == "invalid_time"
