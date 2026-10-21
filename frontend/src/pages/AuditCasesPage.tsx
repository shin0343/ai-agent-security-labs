import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { apiRequest, errorMessage } from "../api/client";
import type {
  AuditEvent,
  AuditReport,
  CaseDetail,
  CaseSummary,
  FindingList,
  Investigation,
  ListResponse,
  ToolRequest,
} from "../api/types";
import {
  Button,
  CodeBlock,
  Definition,
  EmptyState,
  ErrorNotice,
  Field,
  Hash,
  LastUpdated,
  LoadingState,
  Notice,
  PageHeader,
  Section,
  StatusBadge,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { formatTimestamp, plural } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

type Tab = "audit" | "cases";

export function AuditCasesPage() {
  const { activeDatasetId, zone, refreshKey, audit: workspaceAudit, refresh } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "cases" ? "cases" : "audit";
  const statusFilter = params.get("status") ?? "";
  const [beforeSeq, setBeforeSeq] = useState<number | null>(null);
  const auditSummary = useApi<AuditReport>("/audit/summary", `${refreshKey}`);
  const auditEvents = useApi<ListResponse<AuditEvent>>(
    beforeSeq ? `/audit/events?before_seq=${beforeSeq}&limit=100` : "/audit/events?limit=100",
    `${refreshKey}`,
  );
  const cases = useApi<ListResponse<CaseSummary>>(
    activeDatasetId ? `/cases?dataset_id=${encodeURIComponent(activeDatasetId)}` : null,
    `${refreshKey}`,
  );
  const findings = useApi<FindingList>(
    activeDatasetId ? `/findings?dataset_id=${encodeURIComponent(activeDatasetId)}&limit=200` : null,
  );
  const investigations = useApi<ListResponse<Investigation>>(
    activeDatasetId ? `/investigations?dataset_id=${encodeURIComponent(activeDatasetId)}` : null,
  );
  const requests = useApi<ListResponse<ToolRequest>>(
    activeDatasetId ? `/requests?dataset_id=${encodeURIComponent(activeDatasetId)}&limit=100` : null,
  );

  const [verification, setVerification] = useState<AuditReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(params.get("create") === "1");
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [scope, setScope] = useState("");
  const [conclusion, setConclusion] = useState("");
  const [recommendations, setRecommendations] = useState("");
  const [findingIds, setFindingIds] = useState<string[]>(
    (params.get("findings") ?? "").split(",").filter(Boolean),
  );
  const [requestIds, setRequestIds] = useState<string[]>([]);
  const [investigationId, setInvestigationId] = useState(params.get("investigation") ?? "");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const navigate = useNavigate();

  const currentAudit = verification ?? auditSummary.data ?? workspaceAudit;
  const filteredCases = (cases.data?.items ?? []).filter(
    (item) => !statusFilter || item.status === statusFilter,
  );

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    setParams(next, { replace: true });
  };

  const runVerification = async () => {
    setVerifying(true);
    setVerifyError(null);
    try {
      const result = await apiRequest<AuditReport>("/audit/verifications", { method: "POST" });
      setVerification(result);
      auditSummary.reload();
      refresh();
    } catch (cause) {
      setVerifyError(errorMessage(cause));
    } finally {
      setVerifying(false);
    }
  };

  const toggleFinding = (id: string) => {
    setFindingIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const toggleRequest = (id: string) => {
    setRequestIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const createCase = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!activeDatasetId) return;
    setCreating(true);
    setCreateError(null);
    try {
      const result = await apiRequest<CaseDetail>("/cases", {
        method: "POST",
        body: {
          dataset_id: activeDatasetId,
          title,
          finding_ids: findingIds,
          request_ids: requestIds,
          investigation_id: investigationId || null,
          summary,
          scope,
          analyst_conclusion: conclusion,
          recommendations: recommendations
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean),
        },
      });
      navigate(`/audit/cases/${result.id}`);
    } catch (cause) {
      setCreateError(errorMessage(cause));
    } finally {
      setCreating(false);
    }
  };

  const openCreate = () => {
    setShowCreate(true);
    updateParam("create", "1");
  };

  return (
    <>
      <PageHeader
        eyebrow="Local audit and scoped handoff"
        title="Audit & cases"
        description="Verify the recorded chain, inspect exact transitions, and create a scoped synthetic case. Audit and cases share links, not identity."
        actions={
          <LastUpdated
            at={auditSummary.refreshedAt ?? cases.refreshedAt}
            refreshing={auditSummary.refreshing || cases.refreshing}
            onRefresh={() => {
              auditSummary.reload();
              auditEvents.reload();
              cases.reload();
            }}
          />
        }
      />

      <div className="tab-bar" role="tablist" aria-label="Audit and cases">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "audit"}
          className={tab === "audit" ? "tab tab--active" : "tab"}
          onClick={() => updateParam("tab", "audit")}
        >
          Audit
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "cases"}
          className={tab === "cases" ? "tab tab--active" : "tab"}
          onClick={() => updateParam("tab", "cases")}
        >
          Cases
          {cases.data ? <span className="tab__count">{cases.data.items.length}</span> : null}
        </button>
      </div>

      {tab === "audit" ? (
        <>
          <div className="detail-grid">
            <Section
              title="Verification status"
              description="Derived read-only report. Running verification does not append to the chain."
              actions={
                <Button size="sm" variant="primary" onClick={runVerification} disabled={verifying}>
                  {verifying ? "Verifying…" : "Run verification"}
                </Button>
              }
            >
              {verifyError ? <ErrorNotice message={verifyError} /> : null}
              {currentAudit ? (
                <>
                  <div className="claim-list">
                    <div className="claim">
                      <span className="claim__key">Integrity</span>
                      <StatusBadge status={currentAudit.integrity} />
                      <span className="claim__note">Retained rows match their local HMAC chain.</span>
                    </div>
                    <div className="claim">
                      <span className="claim__key">Completeness</span>
                      <StatusBadge status={currentAudit.completeness} />
                      <span className="claim__note">Compared with the local head checkpoint.</span>
                    </div>
                    <div className="claim">
                      <span className="claim__key">Consistency</span>
                      <StatusBadge status={currentAudit.consistency} />
                      <span className="claim__note">Referenced record checks where implemented.</span>
                    </div>
                  </div>
                  <Definition
                    columns={2}
                    items={[
                      { term: "Safe for mutations", description: currentAudit.safe_for_mutations ? "yes" : "no" },
                      { term: "Events checked", description: currentAudit.checked_events, mono: true },
                      { term: "Checked range", description: `${currentAudit.checked_from ?? "—"} … ${currentAudit.checked_to ?? "—"}`, mono: true },
                      { term: "First failure", description: currentAudit.first_failure_seq ?? "none", mono: true },
                      { term: "Key status", description: currentAudit.key_status },
                      { term: "Head MAC", description: <Hash value={currentAudit.head_mac} /> },
                      { term: "Verification ID", description: currentAudit.verification_id ?? "summary only", mono: true },
                      { term: "Generated", description: formatTimestamp(currentAudit.generated_at, zone) },
                    ]}
                  />
                  <p className="small">{currentAudit.message}</p>
                </>
              ) : auditSummary.loading ? (
                <LoadingState label="Reading audit verification" />
              ) : (
                <EmptyState title="Audit summary unavailable" />
              )}
            </Section>

            <Section title="Assurance limits">
              <p className="small">
                The local HMAC key and checkpoint live on the same host. These checks detect retained-row
                tampering against the checkpoint; they cannot prove completeness against a compromised host
                or independent storage.
              </p>
              <p className="small muted">
                Integrity, completeness, consistency, and authorization are separate claims. A valid chain
                does not make the policy decision or the synthetic finding true.
              </p>
              <Link className="text-link" to="/policies">
                Review policy decisions
              </Link>
            </Section>
          </div>

          <Section
            title="Audit events"
            description="Append-only sequence with previous and current MAC. Expand a row to inspect linked details."
            actions={
              <Button
                size="sm"
                variant="quiet"
                onClick={() => setBeforeSeq(auditEvents.data?.items[0]?.seq ?? null)}
                disabled={!auditEvents.data || auditEvents.data.items.length === 0 || beforeSeq !== null}
              >
                Load older
              </Button>
            }
          >
            {beforeSeq ? (
              <div className="inline-state">
                <span className="muted">
                  Showing events before sequence {beforeSeq}.
                </span>
                <Button size="sm" variant="quiet" onClick={() => setBeforeSeq(null)}>
                  Return to latest
                </Button>
              </div>
            ) : null}
            {auditEvents.error && !auditEvents.data ? (
              <ErrorNotice message={auditEvents.error} action={<Button onClick={auditEvents.reload}>Retry</Button>} />
            ) : auditEvents.loading && !auditEvents.data ? (
              <LoadingState label="Reading audit events" />
            ) : !auditEvents.data || auditEvents.data.items.length === 0 ? (
              <EmptyState title="No audit events recorded" />
            ) : (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Audit events</caption>
                  <thead>
                    <tr>
                      <th scope="col" className="numeric">Seq</th>
                      <th scope="col">Action</th>
                      <th scope="col">Entity</th>
                      <th scope="col">Actor</th>
                      <th scope="col">Recorded</th>
                      <th scope="col">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.data.items.map((event) => (
                      <tr key={event.seq}>
                        <td className="numeric mono">{event.seq}</td>
                        <td>{event.payload.action}</td>
                        <td>
                          <span className="muted">{event.payload.entity_type}</span>
                          <div className="row-subtitle mono">{event.payload.entity_id}</div>
                        </td>
                        <td className="mono">{event.payload.actor}</td>
                        <td className="nowrap">{formatTimestamp(event.payload.recorded_at, zone)}</td>
                        <td>
                          <details className="details">
                            <summary>Inspect</summary>
                            <div className="details__body">
                              <p className="small">
                                Key <span className="mono">{event.key_id}</span> · previous{" "}
                                <span className="mono">{event.prev_mac.slice(0, 12)}…</span>
                              </p>
                              <p className="small">
                                MAC <span className="mono">{event.mac}</span>
                              </p>
                              <CodeBlock label="Audit payload">
                                {JSON.stringify(event.payload, null, 2)}
                              </CodeBlock>
                            </div>
                          </details>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="table-caption">
                  {plural(auditEvents.data.items.length, "event")} loaded. Latest head sequence{" "}
                  <span className="mono">{auditEvents.data.items[0]?.seq ?? "none"}</span>.
                </p>
              </div>
            )}
          </Section>
        </>
      ) : (
        <>
          <div className="filter-bar">
            <label>
              <span>Case status</span>
              <select value={statusFilter} onChange={(event) => updateParam("status", event.target.value)}>
                <option value="">All cases</option>
                <option value="OPEN">Open</option>
                <option value="CLOSED">Closed</option>
              </select>
            </label>
            {statusFilter ? (
              <Button size="sm" variant="quiet" onClick={() => updateParam("status", "")}>
                Clear filter
              </Button>
            ) : null}
            <span className="filter-bar__note">
              Cases select an explicit finding/request scope. Exports are marked synthetic and manual-only.
            </span>
            <Button variant="primary" size="sm" onClick={openCreate} disabled={!activeDatasetId}>
              Create case
            </Button>
          </div>

          {showCreate ? (
            <Section
              title="Create scoped case"
              description="Only selected findings and tool requests are included. Internal IDs are not external SOC case IDs."
              actions={
                <Button
                  size="sm"
                  variant="quiet"
                  onClick={() => {
                    setShowCreate(false);
                    updateParam("create", "");
                  }}
                >
                  Close
                </Button>
              }
            >
              <form className="form-grid" onSubmit={createCase}>
                <Field label="Case title" htmlFor="case-title" hint="1–160 characters.">
                  <input
                    id="case-title"
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={160}
                    required
                  />
                </Field>
                <Field label="Linked investigation" htmlFor="case-investigation" optional hint="Must belong to the active dataset.">
                  <select
                    id="case-investigation"
                    value={investigationId}
                    onChange={(event) => setInvestigationId(event.target.value)}
                  >
                    <option value="">Not linked</option>
                    {investigations.data?.items.map((investigation) => (
                      <option value={investigation.id} key={investigation.id}>
                        {investigation.title}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Summary" htmlFor="case-summary" hint="What the selected observations support. Required.">
                  <textarea
                    id="case-summary"
                    value={summary}
                    onChange={(event) => setSummary(event.target.value)}
                    rows={3}
                    maxLength={4000}
                    required
                  />
                </Field>
                <Field label="Scope" htmlFor="case-scope" hint="Dataset, time range, selected findings/requests, and exclusions.">
                  <textarea
                    id="case-scope"
                    value={scope}
                    onChange={(event) => setScope(event.target.value)}
                    rows={3}
                    maxLength={2000}
                    required
                  />
                </Field>
                <Field label="Analyst conclusion" htmlFor="case-conclusion" hint="Do not claim proven compromise without evidence.">
                  <textarea
                    id="case-conclusion"
                    value={conclusion}
                    onChange={(event) => setConclusion(event.target.value)}
                    rows={3}
                    maxLength={4000}
                    required
                  />
                </Field>
                <Field
                  label="Recommendations"
                  htmlFor="case-recommendations"
                  optional
                  hint="One recommendation per line. Stored as a list."
                >
                  <textarea
                    id="case-recommendations"
                    value={recommendations}
                    onChange={(event) => setRecommendations(event.target.value)}
                    rows={3}
                    maxLength={2000}
                  />
                </Field>

                <div className="form-grid__full">
                  <fieldset className="fieldset">
                    <legend>Findings in scope ({findingIds.length} selected)</legend>
                    {findings.loading ? (
                      <p className="muted small">Loading findings…</p>
                    ) : findings.data?.items.length ? (
                      <div className="citation-list citation-list--scroll">
                        {findings.data.items.map((finding) => (
                          <label className="citation" key={finding.id}>
                            <input
                              type="checkbox"
                              checked={findingIds.includes(finding.id)}
                              onChange={() => toggleFinding(finding.id)}
                            />
                            <span>
                              <span className="mono">{finding.agent_label}</span> — {finding.title}
                              <span className="citation__time">{finding.disposition}</span>
                            </span>
                          </label>
                        ))}
                      </div>
                    ) : (
                      <p className="muted small">No findings available in this dataset.</p>
                    )}
                  </fieldset>
                </div>

                <div className="form-grid__full">
                  <fieldset className="fieldset">
                    <legend>Tool requests in scope ({requestIds.length} selected)</legend>
                    {requests.data?.items.length ? (
                      <div className="citation-list citation-list--scroll">
                        {requests.data.items.map((request) => (
                          <label className="citation" key={request.id}>
                            <input
                              type="checkbox"
                              checked={requestIds.includes(request.id)}
                              onChange={() => toggleRequest(request.id)}
                            />
                            <span>
                              <span className="mono">{request.tool}</span> · {request.decision} ·{" "}
                              {request.execution_status}
                              <span className="citation__time">{formatTimestamp(request.created_at, zone)}</span>
                            </span>
                          </label>
                        ))}
                      </div>
                    ) : (
                      <p className="muted small">No tool requests available. The case can still select findings.</p>
                    )}
                  </fieldset>
                </div>

                {createError ? (
                  <div className="form-grid__full">
                    <ErrorNotice message={createError} />
                  </div>
                ) : null}
                <div className="form-actions form-grid__full">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={creating || findingIds.length === 0 || (currentAudit ? !currentAudit.safe_for_mutations : false)}
                  >
                    {creating ? "Creating case…" : "Create case revision 1"}
                  </Button>
                  <span className="small muted">
                    Case creation is recorded in the audit chain. Export does not contact an external SOC.
                  </span>
                </div>
              </form>
            </Section>
          ) : null}

          <Section title="Case records" description="Revisioned incident handoff records with manual export status.">
            {cases.error && !cases.data ? (
              <ErrorNotice message={cases.error} action={<Button onClick={cases.reload}>Retry</Button>} />
            ) : cases.loading && !cases.data ? (
              <LoadingState label="Reading cases" />
            ) : filteredCases.length === 0 ? (
              <EmptyState
                title={statusFilter ? `No ${statusFilter.toLowerCase()} cases` : "No incident cases created"}
                action={
                  <Button onClick={openCreate} disabled={!activeDatasetId}>
                    Create a case from this dataset
                  </Button>
                }
              >
                A case is an explicit, scoped synthesis. It is not created automatically from a finding or
                verdict.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Incident cases</caption>
                  <thead>
                    <tr>
                      <th scope="col">Status</th>
                      <th scope="col">Case</th>
                      <th scope="col">Dataset</th>
                      <th scope="col" className="numeric">Revisions</th>
                      <th scope="col" className="numeric">Exports</th>
                      <th scope="col">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredCases.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <StatusBadge status={item.status} />
                        </td>
                        <td>
                          <Link className="row-title" to={`/audit/cases/${item.id}`}>
                            {item.title}
                          </Link>
                          <div className="row-subtitle mono">{item.id}</div>
                        </td>
                        <td>{item.dataset_name}</td>
                        <td className="numeric">{item.revision_count}</td>
                        <td className="numeric">{item.export_count}</td>
                        <td className="nowrap">{formatTimestamp(item.updated_at, zone)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          <Notice tone="info" title="Export boundary">
            A case export is a local file creation. <span className="mono">integration_status</span> is always{" "}
            <span className="mono">manual_export_only</span>; no Vigil API call or external delivery occurs.
          </Notice>
        </>
      )}
    </>
  );
}
