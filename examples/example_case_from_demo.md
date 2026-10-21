# [LAB] Synthetic Agent Incident — Analyst Case Draft

**Classification:** synthetic / educational / not a real compromise.
**Workflow:** Triage → Investigation → Finding → Case → Approval Audit.
**Vigil:** manually enter this case into your local Vigil SOC; NO API POST or automatic finding creation.

## Triage — evidence-based priorities

### BUILD — LOW (illustrative risk score 0.00)
- Observation: Synthetic build action within declared scope
- What remains unknown: No proof that all activity is benign
- Source evidence: `agent-actions.ndjson:1`

  - `agent-actions.ndjson:1`: `{"action": "run_build", "agent": "build", "resource": "internal-ci", "timestamp": "2026-09-02T09:00:20Z"}`

### DATA — REVIEW (illustrative risk score 1.00)
- Observation: Unapproved publish request alongside outbound POST and IDS alert
- What remains unknown: The shared host IP does not establish process/agent ownership of the network flow or successful exfiltration
- Source evidence: `agent-actions.ndjson:2`, `http.log:1`, `suricata.ndjson:1`

  - `agent-actions.ndjson:2`: `{"action": "publish_external", "agent": "data", "approved": false, "resource": "monthly-report", "timestamp": "2026-09-02T09:02:18Z"}`
  - `http.log:1`: `{"host": "sync.demo.invalid", "id.orig_h": "192.0.2.80", "id.resp_h": "203.0.113.77", "method": "POST", "request_body_len": 115000, "status_code": 202, "ts": 1788339740.0, "uid": "C-DATA-1", "uri": "/upload"}`
  - `suricata.ndjson:1`: `{"alert": {"severity": 2, "signature": "SYNTHETIC suspicious outbound upload"}, "dest_ip": "203.0.113.77", "event_type": "alert", "flow_id": 711, "src_ip": "192.0.2.80", "timestamp": "2026-09-02T09:02:20Z"}`

### HELPDESK — REVIEW (illustrative risk score 0.90)
- Observation: Attempted WinRM login outside one-host approved scope
- What remains unknown: Login failure is not evidence of successful remote access
- Source evidence: `agent-actions.ndjson:3`, `windows-events.ndjson:2`

  - `agent-actions.ndjson:3`: `{"action": "winrm_login", "agent": "helpdesk", "approved_scope": ["192.0.2.20"], "resource": "192.0.2.44", "timestamp": "2026-09-02T09:04:00Z"}`
  - `windows-events.ndjson:2`: `{"@timestamp": "2026-09-02T09:04:01Z", "Computer": "HOST-UNAPPROVED", "EventData": {"IpAddress": "192.0.2.10", "SubjectUserName": "helpdesk_svc", "TargetHost": "192.0.2.44"}, "EventID": 4625}`

### DOCS — UNKNOWN (illustrative risk score 0.30)
- Observation: External TLS/SNI observed; authorization and payload unknown
- What remains unknown: TLS metadata alone cannot prove intent or data loss
- Source evidence: `ssl.log:1`

  - `ssl.log:1`: `{"id.orig_h": "192.0.2.120", "id.resp_h": "203.0.113.27", "server_name": "docs.demo.invalid", "ts": 1788339840.0, "uid": "C-DOCS-1"}`

## Investigation / tool execution gate
- Audit HMAC chain verified: **True**
- Tool decisions recorded: **9**
- Audit contains request metadata and argument digests, not sensitive tool bodies.

- `fbfefdee110f8e3cb5825a38` `read_report` → **ALLOW** (deny)
- `f7d46b3f241826c06b636920` `read_report` → **ALLOW** (approve)
- `ea66dac49adf6ce231dc25ae` `read_secret` → **BLOCK** (approve)
- `de5f1325c1f2087825e214a3` `read_report` → **ALLOW** (monitor)
- `d6a49ad43d9d6a85f00f4f03` `read_secret` → **BLOCK** (deny)
- `9cfd17812b34e309e64e6dce` `read_secret` → **BLOCK** (monitor)
- `9bbef611ae447e462be8ca51` `publish_external` → **PENDING** (approve)
- `9586d5713c7db4a572b1ceec` `publish_external` → **BLOCK** (deny)
- `58121bd76e68fa4de53e195e` `publish_external` → **MONITORED** (monitor)

## Case adjudication and limitations
- Do not equate an IDS alert or TLS session with successful exfiltration.
- Build and Data share a host/IP: network identity does NOT confirm process or agent attribution.
- `APPROVED` and `MONITORED` only write local receipts; no real external publishing.
- Unknown Docs authorization remains UNKNOWN rather than automatically malicious.
- Next steps: verify asset and process telemetry, scope approvals, real-world baselines, and independent data.
