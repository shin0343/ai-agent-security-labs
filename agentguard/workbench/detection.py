"""Explainable, versioned detection rules over normalized evidence."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .audit import append_audit, require_audit_healthy
from .util import (
    CORRELATION_WINDOW_SECONDS,
    RULES_VERSION,
    canonical_json,
    parse_iso,
    utc_iso,
)

EVENT_COLUMNS = """e.id, e.dataset_id, e.source_id, e.line_no, e.raw_sha256, e.event_type,
    e.ts_utc, e.original_ts, e.actor_hint, e.src_ip, e.dst_ip, e.src_port, e.dst_port,
    e.uid, e.action, e.resource, e.attrs_json, e.parse_status, s.filename"""


@dataclass(frozen=True)
class LoadedEvent:
    row: sqlite3.Row
    attrs: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.row["id"])

    @property
    def ts(self) -> datetime | None:
        value = self.row["ts_utc"]
        return parse_iso(value) if value else None

    @property
    def ref(self) -> str:
        return f"{self.row['filename']}:{self.row['line_no']}"


def _load_events(conn: sqlite3.Connection, dataset_id: str) -> list[LoadedEvent]:
    rows = conn.execute(
        f"SELECT {EVENT_COLUMNS} FROM events e JOIN source_blobs s ON s.id = e.source_id "
        "WHERE e.dataset_id = ? ORDER BY e.ts_utc IS NULL, e.ts_utc, s.filename, e.line_no",
        (dataset_id,),
    ).fetchall()
    events: list[LoadedEvent] = []
    for row in rows:
        try:
            attrs = json.loads(row["attrs_json"])
        except (TypeError, ValueError):
            attrs = {}
        events.append(LoadedEvent(row=row, attrs=attrs if isinstance(attrs, dict) else {}))
    return events


def _delta(left: LoadedEvent, right: LoadedEvent) -> float | None:
    if left.ts is None or right.ts is None:
        return None
    return abs((right.ts - left.ts).total_seconds())


def _within_window(left: LoadedEvent, right: LoadedEvent, window: int = CORRELATION_WINDOW_SECONDS) -> bool:
    delta = _delta(left, right)
    return delta is not None and delta <= window


def _finding_payload(
    *,
    agent_label: str,
    title: str,
    disposition: str,
    priority_score: int,
    observed: list[dict[str, Any]],
    interpretation: str,
    supporting: list[str],
    contradicting: list[str],
    unknowns: list[str],
    confidence: str,
    next_step: str,
    limitations: str,
) -> dict[str, Any]:
    return {
        "agent_label": agent_label,
        "title": title,
        "disposition": disposition,
        "priority_score": priority_score,
        "observed_facts_json": canonical_json(observed).decode("utf-8"),
        "interpretation": interpretation,
        "supporting_json": canonical_json(supporting).decode("utf-8"),
        "contradicting_json": canonical_json(contradicting).decode("utf-8"),
        "unknowns_json": canonical_json(unknowns).decode("utf-8"),
        "confidence_rationale": confidence,
        "next_step": next_step,
        "limitations": limitations,
    }


def _insert_finding(
    conn: sqlite3.Connection,
    *,
    detection_run_id: str,
    dataset_id: str,
    payload: dict[str, Any],
    evidence: list[tuple[LoadedEvent, str]],
    edges: list[tuple[LoadedEvent, LoadedEvent, str, dict[str, Any], str, str]],
    rules_version: str,
) -> str:
    finding_id = f"fnd_{os.urandom(12).hex()}"
    now = utc_iso()
    conn.execute(
        """INSERT INTO findings(id, detection_run_id, dataset_id, agent_label, title, disposition,
           priority_score, observed_facts_json, interpretation, supporting_json, contradicting_json,
           unknowns_json, confidence_rationale, next_step, limitations, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            detection_run_id,
            dataset_id,
            payload["agent_label"],
            payload["title"],
            payload["disposition"],
            payload["priority_score"],
            payload["observed_facts_json"],
            payload["interpretation"],
            payload["supporting_json"],
            payload["contradicting_json"],
            payload["unknowns_json"],
            payload["confidence_rationale"],
            payload["next_step"],
            payload["limitations"],
            now,
        ),
    )
    for event, role in evidence:
        conn.execute(
            "INSERT OR IGNORE INTO finding_evidence(finding_id, event_id, role) VALUES (?, ?, ?)",
            (finding_id, event.id, role),
        )
    for left, right, join_type, fields, limitation, _window_text in edges:
        conn.execute(
            """INSERT INTO correlation_edges(id, dataset_id, finding_id, left_event_id, right_event_id,
               rule_version, join_type, join_fields_json, time_delta_seconds, limitation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"edge_{os.urandom(12).hex()}",
                dataset_id,
                finding_id,
                left.id,
                right.id,
                rules_version,
                join_type,
                canonical_json(fields).decode("utf-8"),
                _delta(left, right),
                limitation,
            ),
        )
    return finding_id


def run_detection(
    conn: sqlite3.Connection,
    runtime_dir: Path,
    dataset_id: str,
    *,
    rules_version: str = RULES_VERSION,
) -> dict[str, Any]:
    require_audit_healthy(conn, runtime_dir)
    dataset = conn.execute("SELECT id, name, scenario_key FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
    if dataset is None:
        raise ValueError("Dataset not found")
    detection_run_id = f"det_{os.urandom(12).hex()}"
    now = utc_iso()
    conn.execute(
        """INSERT INTO detection_runs(id, dataset_id, rules_version, status, started_at)
           VALUES (?, ?, ?, 'RUNNING', ?)""",
        (detection_run_id, dataset_id, rules_version, now),
    )
    events = _load_events(conn, dataset_id)
    agent_actions = [event for event in events if event.row["event_type"] == "agent_action" and event.row["actor_hint"]]
    network_events = [
        event
        for event in events
        if event.row["event_type"] in {"network_connection", "http_request", "dns_query", "tls_connection"}
    ]
    alerts = [event for event in events if event.row["event_type"] == "ids_alert"]
    windows_events = [event for event in events if str(event.row["event_type"]).startswith("windows_")]
    findings: list[str] = []

    grouped: dict[str, list[LoadedEvent]] = {}
    for action in agent_actions:
        grouped.setdefault(str(action.row["actor_hint"]), []).append(action)

    for agent, actions in sorted(grouped.items()):
        action = actions[0]
        if agent == "data":
            unapproved = next(
                (item for item in actions if item.row["action"] == "publish_external" and item_attrs_false(item)),
                None,
            )
            if unapproved is None:
                findings.append(
                    _insert_finding(
                        conn,
                        detection_run_id=detection_run_id,
                        dataset_id=dataset_id,
                        payload=_finding_payload(
                            agent_label="data",
                            title="Data agent activity without an unapproved publish marker",
                            disposition="LOW",
                            priority_score=20,
                            observed=[
                                {
                                    "text": f"Agent action {action.row['action']} observed.",
                                    "event_ids": [action.id],
                                }
                            ],
                            interpretation="No rule for unapproved publish currently matches.",
                            supporting=[f"{action.ref} records Data agent activity."],
                            contradicting=["No unapproved publish action was observed in this dataset."],
                            unknowns=[
                                "Whether source action labels are complete.",
                                "Whether other telemetry sources are missing.",
                            ],
                            confidence="Low rule priority; absence of a match is not evidence of benign behavior.",
                            next_step="Check source coverage and request additional process telemetry.",
                            limitations="Detection rules only see the selected dataset.",
                        ),
                        evidence=[(action, "agent_action")],
                        edges=[],
                        rules_version=rules_version,
                    )
                )
                continue
            action = unapproved
            post = next(
                (
                    item
                    for item in network_events
                    if item.row["event_type"] == "http_request"
                    and str(item.row["action"]).upper() == "POST"
                    and _within_window(action, item)
                ),
                None,
            )
            conn_flow = None
            dns_event = None
            if post is not None and post.row["uid"]:
                conn_flow = next(
                    (
                        item
                        for item in network_events
                        if item.row["event_type"] == "network_connection" and item.row["uid"] == post.row["uid"]
                    ),
                    None,
                )
                dns_event = next(
                    (
                        item
                        for item in network_events
                        if item.row["event_type"] == "dns_query"
                        and post.row["dst_ip"] in (item.attrs.get("answers") or [])
                        and _within_window(post, item)
                    ),
                    None,
                )
            alert = None
            if post is not None:
                alert = next(
                    (
                        item
                        for item in alerts
                        if item.row["dst_ip"] == post.row["dst_ip"] and _within_window(post, item)
                    ),
                    None,
                )
            evidence: list[tuple[LoadedEvent, str]] = [(action, "agent_action")]
            facts: list[dict[str, Any]] = [
                {
                    "text": "Agent action records an unapproved external publish attempt.",
                    "event_ids": [action.id],
                }
            ]
            supporting = [
                f"{action.ref} records Data agent action publish_external with approved=false.",
                "The approved flag is a source claim, not an authorization record.",
            ]
            edges: list[tuple[LoadedEvent, LoadedEvent, str, dict[str, Any], str, str]] = []
            score = 70
            if post is not None:
                evidence.append((post, "network"))
                facts.append(
                    {
                        "text": (
                            f"HTTP {post.row['action']} to {post.row['resource']} "
                            f"({post.row['dst_ip']}) observed within the correlation window."
                        ),
                        "event_ids": [post.id],
                    }
                )
                supporting.append(
                    f"{post.ref} shows POST body length {post.attrs.get('request_body_len', 'unknown')} "
                    f"and status {post.attrs.get('status_code', 'unknown')}."
                )
                edges.append(
                    (
                        action,
                        post,
                        "time_proximity_host_association",
                        {
                            "window_seconds": CORRELATION_WINDOW_SECONDS,
                            "join": "agent action time and outbound HTTP POST time",
                        },
                        "The agent action has no process or host identifier. This is a time association, "
                        "not proof that the Data agent generated the HTTP flow.",
                        "60s",
                    )
                )
                score = 85
            if conn_flow is not None:
                assert post is not None
                evidence.append((conn_flow, "correlated_network"))
                edges.append(
                    (
                        post,
                        conn_flow,
                        "zeek_uid",
                        {"uid": conn_flow.row["uid"]},
                        "Zeek UID links the HTTP record and connection record, not an agent process.",
                        "exact UID",
                    )
                )
                supporting.append(f"{conn_flow.ref} shares Zeek UID {conn_flow.row['uid']} with the HTTP flow.")
            if dns_event is not None:
                assert post is not None
                evidence.append((dns_event, "correlated_network"))
                edges.append(
                    (
                        post,
                        dns_event,
                        "dns_answer_time_window",
                        {
                            "query": dns_event.attrs.get("query"),
                            "answer": post.row["dst_ip"],
                            "window_seconds": CORRELATION_WINDOW_SECONDS,
                        },
                        "DNS resolution precedes the flow but does not identify the requesting process.",
                        "60s",
                    )
                )
            if alert is not None:
                assert post is not None
                evidence.append((alert, "detection_alert"))
                facts.append(
                    {
                        "text": f"IDS alert references destination {alert.row['dst_ip']}.",
                        "event_ids": [alert.id],
                    }
                )
                supporting.append(f"{alert.ref} raises: {alert.row['resource']}.")
                edges.append(
                    (
                        post,
                        alert,
                        "endpoint_time_window",
                        {
                            "dst_ip": post.row["dst_ip"],
                            "window_seconds": CORRELATION_WINDOW_SECONDS,
                        },
                        "The IDS alert corroborates an endpoint/time association; it does not prove "
                        "payload content, successful exfiltration or agent ownership.",
                        "60s",
                    )
                )
                score = 95
            payload = _finding_payload(
                agent_label="data",
                title="Unapproved publish attempt with correlated outbound upload",
                disposition="REVIEW",
                priority_score=score,
                observed=facts,
                interpretation=(
                    "A policy-relevant publish attempt and an outbound upload occur in the same short "
                    "window. The evidence supports review of an attempted policy violation; it does not "
                    "prove data exfiltration."
                ),
                supporting=supporting,
                contradicting=[
                    "HTTP status 202 acknowledges the request; it does not prove the payload was accepted or retained.",
                    "Build and Data actions are associated with the same synthetic host address; network "
                    "identity does not establish process ownership.",
                ],
                unknowns=[
                    "Which local process generated the HTTP POST.",
                    "Whether the 115,000-byte request body contained report data.",
                    "Whether any remote system retained the payload.",
                ],
                confidence=(
                    f"Rule priority {score}/100 is an explainable ranking from matched rules, not a "
                    "probability that the agent is malicious."
                ),
                next_step=(
                    "Collect endpoint process/network telemetry for 192.0.2.80, inspect payload metadata "
                    "from an authorized source, and verify whether the destination is sanctioned."
                ),
                limitations=(
                    "Shared host/IP and time proximity do not prove that the Data agent executed the "
                    "network flow. The source approved flag is untrusted telemetry."
                ),
            )
            findings.append(
                _insert_finding(
                    conn,
                    detection_run_id=detection_run_id,
                    dataset_id=dataset_id,
                    payload=payload,
                    evidence=evidence,
                    edges=edges,
                    rules_version=rules_version,
                )
            )
        elif agent == "helpdesk":
            outside = next(
                (
                    item
                    for item in actions
                    if item.row["action"] == "winrm_login"
                    and isinstance(item.attrs.get("approved_scope"), list)
                    and item.row["resource"] not in item.attrs["approved_scope"]
                ),
                None,
            )
            if outside is None:
                continue
            failed = next(
                (
                    item
                    for item in windows_events
                    if str(item.row["event_type"]) == "windows_logon_failure"
                    and item.row["dst_ip"] == outside.row["resource"]
                    and _within_window(outside, item)
                ),
                None,
            )
            facts = [
                {
                    "text": (
                        f"Helpdesk action targets {outside.row['resource']}, outside the source-declared "
                        f"scope {outside.attrs.get('approved_scope')}."
                    ),
                    "event_ids": [outside.id],
                }
            ]
            evidence = [(outside, "agent_action")]
            supporting = [
                f"{outside.ref} records a WinRM login attempt to a host outside its declared scope.",
                "The declared scope is untrusted source metadata; only server policy is authoritative.",
            ]
            edges = []
            score = 80
            if failed is not None:
                evidence.append((failed, "correlated_logon"))
                facts.append(
                    {
                        "text": "A Windows logon failure targets the same host one second later.",
                        "event_ids": [failed.id],
                    }
                )
                supporting.append(f"{failed.ref} records Windows Event 4625 for the target host.")
                edges.append(
                    (
                        outside,
                        failed,
                        "target_host_time_window",
                        {
                            "target_host": outside.row["resource"],
                            "window_seconds": CORRELATION_WINDOW_SECONDS,
                        },
                        "The Windows event uses a host name rather than the agent identity; correlation "
                        "does not prove the agent generated the failed logon.",
                        "60s",
                    )
                )
                score = 90
            payload = _finding_payload(
                agent_label="helpdesk",
                title="Helpdesk login attempt outside declared scope",
                disposition="REVIEW",
                priority_score=score,
                observed=facts,
                interpretation=(
                    "The agent attempted access outside its source-declared scope. This supports a policy "
                    "review; the failed logon does not support a claim of successful remote access."
                ),
                supporting=supporting,
                contradicting=[
                    "Windows Event 4625 records failure, not a successful session.",
                    "Source-declared approved_scope has no authorization signature or trusted issuer.",
                ],
                unknowns=[
                    "Whether the declared scope reflects the authoritative server policy.",
                    "Which process initiated the WinRM attempt.",
                    "Whether other login attempts exist outside the captured sources.",
                ],
                confidence=(
                    f"Rule priority {score}/100 reflects a scope mismatch and a correlated failure; it is "
                    "not a calibrated probability."
                ),
                next_step=(
                    "Compare the target against trusted authorization records and inspect WinRM client "
                    "process telemetry on the agent host."
                ),
                limitations=(
                    "The scope claim is untrusted telemetry. A failed logon is not evidence of successful "
                    "access or malicious intent."
                ),
            )
            findings.append(
                _insert_finding(
                    conn,
                    detection_run_id=detection_run_id,
                    dataset_id=dataset_id,
                    payload=payload,
                    evidence=evidence,
                    edges=edges,
                    rules_version=rules_version,
                )
            )
        elif agent == "docs":
            tls = next(
                (
                    item
                    for item in network_events
                    if item.row["event_type"] == "tls_connection" and _within_window(action, item)
                ),
                None,
            )
            facts = [
                {
                    "text": f"Docs agent recorded action {action.row['action']} on {action.row['resource']}.",
                    "event_ids": [action.id],
                }
            ]
            evidence = [(action, "agent_action")]
            supporting = [f"{action.ref} records a document read action."]
            edges = []
            contradicting: list[str] = []
            unknowns = [
                "Whether the document read was authorized.",
                "Which local process owned the TLS connection, if any.",
                "TLS payload content and whether data left the host.",
            ]
            if tls is not None:
                evidence.append((tls, "correlated_network"))
                facts.append(
                    {
                        "text": f"TLS/SNI connection to {tls.row['resource']} observed within the window.",
                        "event_ids": [tls.id],
                    }
                )
                supporting.append(f"{tls.ref} shows a TLS connection with SNI {tls.row['resource']}.")
                contradicting.append(
                    "No policy rule prohibits TLS to this synthetic destination in the captured evidence."
                )
                edges.append(
                    (
                        action,
                        tls,
                        "time_proximity_host_association",
                        {
                            "window_seconds": CORRELATION_WINDOW_SECONDS,
                            "join": "agent action time and TLS connection time",
                        },
                        "The agent action has no host/process identifier. The TLS connection may belong "
                        "to another process on a shared host.",
                        "60s",
                    )
                )
            payload = _finding_payload(
                agent_label="docs",
                title="Docs external TLS context remains unresolved",
                disposition="UNKNOWN",
                priority_score=30 if tls is not None else 20,
                observed=facts,
                interpretation=(
                    "A document read and an external TLS connection are time-associated, but policy and "
                    "payload content are unknown. The evidence cannot support either a policy violation or "
                    "benign intent."
                ),
                supporting=supporting,
                contradicting=contradicting,
                unknowns=unknowns,
                confidence=(
                    "Rule priority 30/100 is an investigation ordering signal for an unresolved context; "
                    "it is not a maliciousness probability."
                ),
                next_step=(
                    "Obtain authorized endpoint process telemetry and policy records for the TLS destination "
                    "before assigning a verdict."
                ),
                limitations=(
                    "TLS metadata alone cannot prove intent, payload content or agent identity. UNKNOWN is "
                    "not a synonym for benign or malicious."
                ),
            )
            findings.append(
                _insert_finding(
                    conn,
                    detection_run_id=detection_run_id,
                    dataset_id=dataset_id,
                    payload=payload,
                    evidence=evidence,
                    edges=edges,
                    rules_version=rules_version,
                )
            )
        elif agent == "build":
            build_flows = [
                item
                for item in network_events
                if item.row["event_type"] == "network_connection" and _within_window(action, item, 30)
            ]
            evidence = [(action, "agent_action")]
            if build_flows:
                evidence.extend((item, "correlated_network") for item in build_flows)
            payload = _finding_payload(
                agent_label="build",
                title="Build activity within observed scope",
                disposition="LOW",
                priority_score=10,
                observed=[
                    {
                        "text": f"Build agent action {action.row['action']} on {action.row['resource']}.",
                        "event_ids": [action.id],
                    }
                ],
                interpretation=(
                    "No matching violation rule fired for the observed Build action. This is a low-priority "
                    "observation, not proof that all Build behavior is benign."
                ),
                supporting=[f"{action.ref} records build execution against internal-ci."],
                contradicting=["No explicit authorization record is present; the source action label is untrusted."],
                unknowns=[
                    "Whether the build network flow belongs to the Build agent process.",
                    "Whether additional unreported Build actions occurred.",
                ],
                confidence="Rule priority 10/100 indicates no matched violation rule.",
                next_step="Confirm build provenance and retained authorization records if required.",
                limitations="Absence of a rule match is not a security clearance.",
            )
            findings.append(
                _insert_finding(
                    conn,
                    detection_run_id=detection_run_id,
                    dataset_id=dataset_id,
                    payload=payload,
                    evidence=evidence,
                    edges=[],
                    rules_version=rules_version,
                )
            )

    conn.execute(
        "UPDATE detection_runs SET status = 'COMPLETED', completed_at = ? WHERE id = ?",
        (utc_iso(), detection_run_id),
    )
    append_audit(
        conn,
        runtime_dir,
        action="detection.completed",
        actor="workbench:detection",
        entity_type="detection_run",
        entity_id=detection_run_id,
        details={
            "dataset_id": dataset_id,
            "rules_version": rules_version,
            "findings": len(findings),
            "events": len(events),
        },
    )
    return {
        "detection_run_id": detection_run_id,
        "dataset_id": dataset_id,
        "rules_version": rules_version,
        "finding_ids": findings,
        "findings": len(findings),
    }


def item_attrs_false(event: LoadedEvent) -> bool:
    return event.attrs.get("approved") is False
