export interface ListResponse<T> {
  items: T[];
  as_of?: string;
}

export interface DatasetList extends ListResponse<Dataset> {
  as_of: string;
}

export interface FindingList extends ListResponse<FindingSummary> {
  counts: { REVIEW: number; LOW: number; UNKNOWN: number } | null;
  as_of: string;
}

export interface SessionInfo {
  session_id: string;
  operator_id: string;
  csrf_token: string;
  expires_at: string;
  scope: string;
}

export interface Dataset {
  id: string;
  name: string;
  scenario_key: string;
  data_class: "synthetic";
  manifest_sha256: string;
  is_sample: number;
  event_count?: number;
  created_at: string;
  manifest: {
    files: Array<{ filename: string; sha256: string; bytes: number; events: number; lines: number }>;
    event_count: number;
  };
}

export interface FindingSummary {
  id: string;
  dataset_id: string;
  dataset_name: string;
  agent_label: string;
  title: string;
  disposition: "REVIEW" | "LOW" | "UNKNOWN";
  priority_score: number;
  interpretation: string;
  created_at: string;
  detection_run_id: string;
  evidence_count: number;
}

export interface EvidenceItem {
  event_id: string;
  ref: string;
  event_type: string;
  ts_utc: string | null;
  original_ts: string | null;
  parse_status: string;
  actor_hint: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  action: string | null;
  resource: string | null;
  raw_sha256: string;
  source_sha256: string;
  integrity: "verified" | "invalid" | "missing";
  integrity_message?: string;
  role?: string;
}

export interface CorrelationEdge {
  id: string;
  join_type: string;
  join_fields: Record<string, unknown>;
  time_delta_seconds: number | null;
  limitation: string;
  left: EvidenceItem;
  right: EvidenceItem;
}

export interface FindingDetail extends FindingSummary {
  scenario_key: string;
  data_class: string;
  rules_version: string;
  observed_facts: Array<{ text: string; event_ids: string[] }>;
  supporting: string[];
  contradicting: string[];
  unknowns: string[];
  confidence_rationale: string;
  next_step: string;
  limitations: string;
  evidence: EvidenceItem[];
  correlation_edges: CorrelationEdge[];
  timeline: EvidenceItem[];
  time_unavailable: EvidenceItem[];
  evidence_integrity: "valid" | "invalid";
}

export interface EvidenceDetail {
  event_id: string;
  dataset_id: string;
  dataset_name: string;
  scenario_key: string;
  data_class: string;
  source_id: string;
  source_filename: string;
  source_sha256: string;
  parser_version: string;
  line: number;
  ref: string;
  raw_sha256: string;
  event_type: string;
  ts_utc: string | null;
  original_ts: string | null;
  parse_status: string;
  actor_hint: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  uid: string | null;
  action: string | null;
  resource: string | null;
  raw: Record<string, unknown>;
  context: Array<{ line: number; text: string }>;
  integrity: string;
}

export interface Verdict {
  id: string;
  investigation_id: string;
  verdict: string;
  rationale: string;
  evidence_ids: string[];
  revision: number;
  created_by: string;
  created_at: string;
}

export interface Investigation {
  id: string;
  dataset_id: string;
  title: string;
  status: "OPEN" | "REVIEWED" | "CLOSED";
  finding_ids: string[];
  notes: string;
  revision: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  findings: FindingDetail[];
  verdicts: Verdict[];
  latest_verdict: Verdict | null;
  verdict_count?: number;
}

export interface AuditReport {
  integrity: "valid" | "invalid" | "unverifiable";
  completeness: "unanchored" | "checkpoint_matched" | "checkpoint_mismatch";
  consistency: "ok" | "failed" | "unknown";
  safe_for_mutations: boolean;
  checked_events: number;
  checked_from: number | null;
  checked_to: number | null;
  head_mac: string | null;
  key_status: string;
  first_failure_seq: number | null;
  message: string;
  verification_id?: string;
  generated_at?: string;
}

export interface Overview {
  scope: {
    dataset_id: string | null;
    dataset_name: string | null;
    scenario_key?: string;
    dataset_sha256?: string;
    data_class?: string;
    as_of: string;
  };
  empty?: boolean;
  attention: Array<{
    kind: string;
    id: string;
    title: string;
    reason: string;
    recorded_at: string;
    href: string;
  }>;
  finding_counts?: { REVIEW: number; LOW: number; UNKNOWN: number };
  investigation_counts?: { OPEN: number; REVIEWED: number; CLOSED: number };
  case_counts?: { OPEN: number; CLOSED: number };
  policy_counts?: { ALLOW: number; BLOCK: number; REQUIRE_APPROVAL: number };
  pending_approvals?: Array<{
    approval_id: string;
    request_id: string;
    tool: string;
    expires_at: string;
    expired: boolean;
    scenario_key: string;
  }>;
  coverage?: {
    event_count: number;
    source_count: number;
    sources: Array<{
      id: string;
      filename: string;
      sha256: string;
      byte_count: number;
      line_count: number;
      parser_version: string;
      event_count: number;
      parse_warning: string | null;
    }>;
  };
  audit_summary?: AuditReport;
  recent_activity?: Array<{
    seq: number;
    action: string;
    actor: string;
    entity_type: string;
    entity_id: string;
    recorded_at: string;
  }>;
  disclaimer?: string;
}

export interface PolicyPreset {
  id: string;
  name: string;
  mode: "DENY" | "APPROVE" | "MONITOR";
  description: string;
  version: number;
  created_at: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  effect: string;
  allowed_args: Record<string, string[]>;
  schema_version: string;
  always_blocked: boolean;
}

export interface ToolRequest {
  id: string;
  run_id: string;
  actor: string;
  tool: string;
  tool_schema_version: string;
  arguments: Record<string, string>;
  args_digest: string;
  request_digest: string;
  resource_ref: string;
  resource_hash: string;
  policy_preset_id: string;
  policy_version: number;
  mode: "DENY" | "APPROVE" | "MONITOR";
  decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  decision_reason_code: string;
  decision_reason: string;
  status: string;
  execution_status: "NOT_STARTED" | "SUCCEEDED" | "FAILED";
  result: Record<string, unknown> | null;
  result_hash?: string | null;
  execution_kind?: string | null;
  receipt_id?: string | null;
  approval_id?: string | null;
  approval_state?: string | null;
  approval_expires_at?: string | null;
  approval_expired?: boolean;
  approval_version?: number;
  approval_session_id?: string | null;
  approval_reason?: string | null;
  scenario_key: string;
  runtime_kind: string;
  run_status: string;
  created_at: string;
  expires_at: string | null;
  decided_at: string | null;
  decided_by: string | null;
  effect: string;
}

export interface Approval {
  id: string;
  request_id: string;
  session_id: string;
  request_digest: string;
  state: "PENDING" | "REJECTED" | "EXPIRED" | "INVALIDATED" | "CONSUMED";
  expected_version: number;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  decided_by: string | null;
  reason: string | null;
  consumed_at: string | null;
  tool: string;
  request_status: string;
  run_id: string;
  scenario_key: string;
  expired: boolean;
  detail?: ToolRequest;
  request?: ToolRequest;
}

export interface TraceEvent {
  id: string;
  run_id: string;
  seq: number;
  parent_id: string | null;
  kind: string;
  text: string;
  tool_request_id: string | null;
  input_refs: string[];
  output_refs: string[];
  error_code: string | null;
  created_at: string;
}

export interface AgentRun {
  id: string;
  dataset_id: string;
  investigation_id: string | null;
  scenario_key: string;
  runtime_kind: "scripted" | "ollama";
  policy_preset_id: string;
  policy_version: number;
  policy_name: string;
  policy_mode: string;
  status: "RUNNING" | "WAITING_APPROVAL" | "COMPLETED" | "CANCELLED" | "FAILED";
  seed: string;
  config: Record<string, unknown>;
  model: Record<string, unknown> | null;
  error_code: string | null;
  revision: number;
  created_at: string;
  started_at: string;
  ended_at: string | null;
  request_count?: number;
  trace_count?: number;
  trace?: TraceEvent[];
  requests?: ToolRequest[];
}

export interface Scenario {
  key: string;
  label: string;
  description: string;
  runtime: string;
}

export interface EvaluationSummary {
  evaluation_id: string;
  suite_version: string;
  label_version: string;
  runtime: string;
  dataset_id: string;
  dataset_scenario: string;
  thesis: string;
  synthetic_detection: {
    TP: number;
    FP: number;
    TN: number;
    FN: number;
    abstained: number;
    missing: number;
    errored: number;
    unlabeled: number;
    unknown_count?: number;
    known_total: number;
    emitted: number;
    coverage: number | null;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    records: number;
    label_note: string;
    metric_note: string;
    threshold_comparison: Array<{
      threshold: number;
      TP: number;
      FP: number;
      TN: number;
      FN: number;
      precision: number | null;
      recall: number | null;
      f1: number | null;
    }>;
  };
  scripted_enforcement: {
    counts: { blocked: number; approved: number; monitored: number; rejected: number; proposals: number; synthetic_attack_attempts?: number };
    blocked: number;
    approved: number;
    monitored: number;
    rejected: number;
    policy_bypass_tests_passed: number;
    policy_bypass_tests_total: number;
    scenarios: Array<{ scenario: string; passed: boolean; details: string }>;
    note: string;
  };
  audit_verification: AuditReport;
  local_model_observations: { count: number; attempted_runs?: number; included_in_metrics: boolean; note: string };
  limitations: string[];
}

export interface EvaluationResult {
  id: string;
  scenario_key: string;
  category: string;
  expected: Record<string, unknown>;
  actual: Record<string, unknown>;
  outcome: string;
  details: string;
  created_at: string;
}

export interface Evaluation {
  id: string;
  dataset_id: string;
  suite_version: string;
  runtime_kind: string;
  status: string;
  config: Record<string, unknown>;
  summary: EvaluationSummary | null;
  started_at: string;
  completed_at: string | null;
  error_code: string | null;
  results: EvaluationResult[];
}

export interface EvaluationListItem {
  id: string;
  dataset_id: string;
  suite_version: string;
  runtime_kind: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  error_code: string | null;
  result_count: number;
}

export interface AuditEvent {
  seq: number;
  prev_mac: string;
  payload_json?: string;
  mac: string;
  key_id: string;
  created_at: string;
  payload: {
    schema: number;
    action: string;
    actor: string;
    entity_type: string;
    entity_id: string;
    details: Record<string, unknown>;
    correlation_id: string | null;
    recorded_at: string;
  };
}

export interface CaseContent {
  schema: number;
  synthetic_classification: string;
  title: string;
  dataset_id: string;
  investigation_id: string | null;
  finding_ids: string[];
  request_ids: string[];
  summary: string;
  scope: string;
  analyst_conclusion: string;
  recommendations: string[];
  integration_status: string;
}

export interface CaseRevision {
  id: string;
  case_id: string;
  revision: number;
  content: CaseContent;
  created_at: string;
  author: string;
}

export interface CaseSummary {
  id: string;
  dataset_id: string;
  investigation_id: string | null;
  title: string;
  status: "OPEN" | "CLOSED";
  revision: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  dataset_name: string;
  revision_count: number;
  export_count: number;
}

export interface CaseDetail extends CaseSummary {
  revisions: CaseRevision[];
  current: CaseContent;
  exports: Array<{
    id: string;
    revision: number;
    format: string;
    sha256: string;
    integration_status: string;
    created_at: string;
  }>;
}

export interface PolicyList {
  presets: PolicyPreset[];
  tools: ToolDefinition[];
  modes: string[];
  note: string;
}

export interface ScenarioList {
  items: Scenario[];
  ollama: {
    enabled: boolean;
    model: string;
    note: string;
  };
}

export interface ApprovalDecisionResponse {
  approval_id: string;
  decision: "approve" | "reject";
  request: ToolRequest;
  committed: boolean;
}

export interface CaseExportResponse {
  export_id: string;
  case_id: string;
  revision: number;
  format: "markdown" | "json" | "csv";
  filename: string;
  sha256: string;
  integration_status: string;
  content: string;
  audit_verification: AuditReport;
}

export interface DatasetImportResult {
  status: string;
  dataset_id: string | null;
  detection_run_id: string | null;
  created?: boolean;
  message?: string;
  event_count?: number;
  manifest_sha256?: string;
}

export interface RunSummary extends AgentRun {
  dataset_name: string;
  dataset_scenario: string;
}

export interface AgentRunDetail extends AgentRun {
  trace: TraceEvent[];
  requests: ToolRequest[];
}

export interface RunList extends ListResponse<RunSummary> {
  as_of: string;
}

