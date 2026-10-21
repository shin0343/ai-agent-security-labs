-- Agent Security Workbench schema v1.
-- SQLite stores synthetic source bytes, findings, immutable authorization
-- requests, approvals, synthetic receipts, audit records and case revisions.

CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scenario_key TEXT NOT NULL,
    data_class TEXT NOT NULL CHECK (data_class = 'synthetic'),
    manifest_json TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    is_sample INTEGER NOT NULL DEFAULT 0 CHECK (is_sample IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_blobs (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    line_count INTEGER NOT NULL,
    parser_version TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    UNIQUE (dataset_id, filename, sha256)
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES source_blobs(id) ON DELETE CASCADE,
    line_no INTEGER NOT NULL CHECK (line_no >= 1),
    raw_sha256 TEXT NOT NULL,
    event_type TEXT NOT NULL,
    ts_utc TEXT,
    original_ts TEXT,
    actor_hint TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    uid TEXT,
    action TEXT,
    resource TEXT,
    attrs_json TEXT NOT NULL,
    parse_status TEXT NOT NULL CHECK (parse_status IN ('parsed', 'invalid_time', 'ignored')),
    UNIQUE (source_id, line_no)
);

CREATE INDEX IF NOT EXISTS idx_events_dataset_time ON events(dataset_id, ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_uid ON events(dataset_id, uid);

CREATE TABLE IF NOT EXISTS detection_runs (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    rules_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    detection_run_id TEXT NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    agent_label TEXT NOT NULL,
    title TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('REVIEW', 'LOW', 'UNKNOWN')),
    priority_score INTEGER NOT NULL CHECK (priority_score BETWEEN 0 AND 100),
    observed_facts_json TEXT NOT NULL,
    interpretation TEXT NOT NULL,
    supporting_json TEXT NOT NULL,
    contradicting_json TEXT NOT NULL,
    unknowns_json TEXT NOT NULL,
    confidence_rationale TEXT NOT NULL,
    next_step TEXT NOT NULL,
    limitations TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_dataset ON findings(dataset_id, disposition, priority_score);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    PRIMARY KEY (finding_id, event_id, role)
);

CREATE TABLE IF NOT EXISTS correlation_edges (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    left_event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    right_event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_version TEXT NOT NULL,
    join_type TEXT NOT NULL,
    join_fields_json TEXT NOT NULL,
    time_delta_seconds REAL,
    limitation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'REVIEWED', 'CLOSED')),
    finding_ids_json TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdict_revisions (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    verdict TEXT NOT NULL CHECK (verdict IN (
        'POLICY_VIOLATION_SUPPORTED', 'WITHIN_OBSERVED_SCOPE',
        'INSUFFICIENT_EVIDENCE', 'NEEDS_MORE_DATA')),
    rationale TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_presets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('DENY', 'APPROVE', 'MONITOR')),
    description TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
    scenario_key TEXT NOT NULL,
    runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('scripted', 'ollama')),
    policy_preset_id TEXT NOT NULL REFERENCES policy_presets(id),
    policy_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'RUNNING', 'WAITING_APPROVAL', 'COMPLETED', 'CANCELLED', 'FAILED')),
    seed TEXT NOT NULL,
    config_json TEXT NOT NULL,
    model_json TEXT,
    error_code TEXT,
    created_by_session TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_dataset ON runs(dataset_id, created_at);

CREATE TABLE IF NOT EXISTS trace_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    parent_id TEXT,
    kind TEXT NOT NULL,
    text TEXT NOT NULL,
    tool_request_id TEXT,
    input_refs_json TEXT NOT NULL,
    output_refs_json TEXT NOT NULL,
    error_code TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, seq)
);

CREATE TABLE IF NOT EXISTS tool_requests (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_schema_version TEXT NOT NULL,
    args_json TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    resource_hash TEXT NOT NULL,
    policy_preset_id TEXT NOT NULL REFERENCES policy_presets(id),
    policy_version INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('DENY', 'APPROVE', 'MONITOR')),
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL')),
    decision_reason_code TEXT NOT NULL,
    decision_reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'PENDING', 'AUTHORIZED', 'BLOCKED', 'REJECTED', 'EXPIRED', 'INVALIDATED', 'CANCELLED')),
    execution_status TEXT NOT NULL CHECK (execution_status IN ('NOT_STARTED', 'SUCCEEDED', 'FAILED')),
    result_json TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    decided_at TEXT,
    decided_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_requests_run ON tool_requests(run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_requests_status ON tool_requests(status, created_at);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'PENDING', 'REJECTED', 'EXPIRED', 'INVALIDATED', 'CONSUMED')),
    expected_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT,
    reason TEXT,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS execution_results (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED')),
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulated_receipts (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    synthetic INTEGER NOT NULL DEFAULT 1 CHECK (synthetic = 1),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    operation TEXT NOT NULL,
    key TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (scope, operation, key)
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    prev_mac TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    mac TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    head_seq INTEGER NOT NULL,
    head_mac TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED')),
    revision INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_revisions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    content_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    author TEXT NOT NULL,
    UNIQUE (case_id, revision)
);

CREATE TABLE IF NOT EXISTS case_exports (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('markdown', 'json', 'csv')),
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    verification_json TEXT NOT NULL,
    integration_status TEXT NOT NULL DEFAULT 'manual_export_only',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    suite_version TEXT NOT NULL,
    runtime_kind TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    config_json TEXT NOT NULL,
    summary_json TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT
);

CREATE TABLE IF NOT EXISTS evaluation_results (
    id TEXT PRIMARY KEY,
    evaluation_run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    scenario_key TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN (
        'synthetic_detection', 'scripted_enforcement', 'local_model_observation')),
    expected_json TEXT NOT NULL,
    actual_json TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('PASS', 'FAIL', 'UNKNOWN', 'ERROR', 'MISSING', 'ABSTAINED')),
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eval_results_run ON evaluation_results(evaluation_run_id);
