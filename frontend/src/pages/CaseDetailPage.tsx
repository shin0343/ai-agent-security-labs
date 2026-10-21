import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, apiRequest, downloadCaseExport, errorMessage, saveTextFile } from "../api/client";
import type { AuditReport, CaseDetail } from "../api/types";
import {
  Button,
  Definition,
  EmptyState,
  ErrorNotice,
  Field,
  Hash,
  LastUpdated,
  LinkButton,
  LoadingState,
  Notice,
  PageHeader,
  Section,
  StatusBadge,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { formatTimestamp } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

const EXTENSION: Record<string, string> = { markdown: "md", json: "json", csv: "csv" };
const MEDIA: Record<string, string> = {
  markdown: "text/markdown",
  json: "application/json",
  csv: "text/csv",
};

interface GeneratedExport {
  filename: string;
  sha256: string;
  content: string;
  auditVerification: AuditReport;
}

export function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const caseRecord = useApi<CaseDetail>(caseId ? `/cases/${caseId}` : null);
  const { zone } = useWorkspace();
  const navigate = useNavigate();
  const data = caseRecord.data;
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportResult, setExportResult] = useState<GeneratedExport | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [showRevision, setShowRevision] = useState(false);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [scope, setScope] = useState("");
  const [conclusion, setConclusion] = useState("");
  const [recommendations, setRecommendations] = useState("");
  const [status, setStatus] = useState<"OPEN" | "CLOSED">("OPEN");
  const [saving, setSaving] = useState(false);

  if (caseRecord.loading && !data) {
    return (
      <>
        <PageHeader title="Case" eyebrow="Audit & cases" />
        <LoadingState label="Reading case revisions" />
      </>
    );
  }
  if (caseRecord.error && !data) {
    return (
      <>
        <PageHeader title="Case" eyebrow="Audit & cases" />
        <ErrorNotice message={caseRecord.error} action={<Button onClick={caseRecord.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data || !data.current) {
    return (
      <>
        <PageHeader title="Case" eyebrow="Audit & cases" />
        <EmptyState title="Case not found" action={<LinkButton to="/audit?tab=cases">Back to cases</LinkButton>} />
      </>
    );
  }

  const content = data.current;

  const startRevision = () => {
    setTitle(content.title);
    setSummary(content.summary);
    setScope(content.scope);
    setConclusion(content.analyst_conclusion);
    setRecommendations(content.recommendations.join("\n"));
    setStatus(data.status);
    setShowRevision(true);
  };

  const exportNow = async (format: "markdown" | "json" | "csv") => {
    if (!caseId) return;
    setExporting(format);
    setActionError(null);
    setActionMessage(null);
    setExportResult(null);
    try {
      const result = await downloadCaseExport(caseId, format);
      saveTextFile(result.filename, result.text, MEDIA[format]);
      setExportResult({
        filename: result.filename,
        sha256: result.sha256,
        content: result.text,
        auditVerification: result.auditVerification,
      });
      setActionMessage(`Created ${result.filename}. This is a local file download, not external delivery.`);
      caseRecord.reload();
    } catch (cause) {
      setActionError(cause);
    } finally {
      setExporting(null);
    }
  };

  const downloadSavedExport = async (exportId: string) => {
    setExporting(exportId);
    setActionError(null);
    try {
      const result = await apiRequest<{
        content: string;
        format: string;
        revision: number;
        sha256: string;
      }>(`/exports/${exportId}`);
      const filename = `${data.id}-r${result.revision}.${EXTENSION[result.format] ?? "txt"}`;
      saveTextFile(filename, result.content, MEDIA[result.format] ?? "text/plain");
      setActionMessage(`Downloaded saved export ${exportId}.`);
    } catch (cause) {
      setActionError(cause);
    } finally {
      setExporting(null);
    }
  };

  const revise = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!caseId) return;
    setSaving(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const result = await apiRequest<CaseDetail>(`/cases/${caseId}/revisions`, {
        method: "POST",
        body: {
          expected_revision: data.revision,
          title,
          summary,
          scope,
          analyst_conclusion: conclusion,
          recommendations: recommendations
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean),
          status,
        },
      });
      setActionMessage(`Case revision ${result.revision} saved. Previous revisions remain immutable.`);
      setShowRevision(false);
      caseRecord.reload();
    } catch (cause) {
      setActionError(cause);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="breadcrumb">
        <Link to="/audit?tab=cases">Cases</Link>
        <span aria-hidden="true">/</span>
        <span className="mono">{data.id}</span>
      </div>
      <PageHeader
        eyebrow={`${content.synthetic_classification} · revision ${data.revision}`}
        title={content.title}
        description={
          <>
            Scoped handoff for <strong>{data.dataset_name}</strong>. Integration status is{" "}
            <span className="mono">{content.integration_status}</span>. Exports embed the selected scope and
            audit snapshot; no SOC API is contacted.
          </>
        }
        actions={
          <div className="button-group">
            <StatusBadge status={data.status} />
            <Button size="sm" onClick={startRevision}>
              New revision
            </Button>
            <LastUpdated at={caseRecord.refreshedAt} refreshing={caseRecord.refreshing} onRefresh={caseRecord.reload} />
          </div>
        }
      />

      {caseRecord.error ? <ErrorNotice message={caseRecord.error} /> : null}
      {actionError ? (
        <ErrorNotice
          message={errorMessage(actionError)}
          code={actionError instanceof ApiError ? actionError.code : null}
          requestId={actionError instanceof ApiError ? actionError.requestId : null}
        />
      ) : null}
      {actionMessage ? <Notice tone="success">{actionMessage}</Notice> : null}

      <div className="detail-grid">
        <div className="stack">
          <Section title="Case narrative" description="Current revision. The export includes the exact captured records and hashes.">
            <div className="prose-block">
              <h3>Summary</h3>
              <p>{content.summary}</p>
              <h3>Scope</h3>
              <p>{content.scope}</p>
              <h3>Analyst conclusion</h3>
              <p>{content.analyst_conclusion}</p>
              <h3>Recommendations</h3>
              {content.recommendations.length === 0 ? (
                <p className="muted">None recorded.</p>
              ) : (
                <ol className="compact-list">
                  {content.recommendations.map((recommendation) => (
                    <li key={recommendation}>{recommendation}</li>
                  ))}
                </ol>
              )}
            </div>
          </Section>

          {showRevision ? (
            <Section
              title={`Create revision ${data.revision + 1}`}
              description="Saving appends a new case revision. The server rejects a stale expected revision."
              actions={
                <Button size="sm" variant="quiet" onClick={() => setShowRevision(false)}>
                  Close
                </Button>
              }
            >
              <form className="form-grid" onSubmit={revise}>
                <Field label="Title" htmlFor="revise-title">
                  <input
                    id="revise-title"
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={160}
                    required
                  />
                </Field>
                <Field label="Status" htmlFor="revise-status">
                  <select
                    id="revise-status"
                    value={status}
                    onChange={(event) => setStatus(event.target.value as "OPEN" | "CLOSED")}
                  >
                    <option value="OPEN">Open</option>
                    <option value="CLOSED">Closed</option>
                  </select>
                </Field>
                <Field label="Summary" htmlFor="revise-summary">
                  <textarea
                    id="revise-summary"
                    value={summary}
                    onChange={(event) => setSummary(event.target.value)}
                    rows={3}
                    maxLength={4000}
                    required
                  />
                </Field>
                <Field label="Scope" htmlFor="revise-scope">
                  <textarea
                    id="revise-scope"
                    value={scope}
                    onChange={(event) => setScope(event.target.value)}
                    rows={3}
                    maxLength={2000}
                    required
                  />
                </Field>
                <Field label="Analyst conclusion" htmlFor="revise-conclusion">
                  <textarea
                    id="revise-conclusion"
                    value={conclusion}
                    onChange={(event) => setConclusion(event.target.value)}
                    rows={3}
                    maxLength={4000}
                    required
                  />
                </Field>
                <Field label="Recommendations" htmlFor="revise-recommendations" optional hint="One per line.">
                  <textarea
                    id="revise-recommendations"
                    value={recommendations}
                    onChange={(event) => setRecommendations(event.target.value)}
                    rows={3}
                    maxLength={2000}
                  />
                </Field>
                <div className="form-actions form-grid__full">
                  <Button type="submit" variant="primary" disabled={saving}>
                    {saving ? "Saving revision…" : `Save revision ${data.revision + 1}`}
                  </Button>
                  <span className="small muted">Expected revision: {data.revision}</span>
                </div>
              </form>
            </Section>
          ) : null}

          <Section title="Selected scope" description="IDs are internal. They are not presented as external case IDs.">
            <div className="scope-columns">
              <div>
                <h3>Findings ({content.finding_ids.length})</h3>
                {content.finding_ids.length === 0 ? (
                  <p className="muted">None.</p>
                ) : (
                  <ul className="compact-list mono small">
                    {content.finding_ids.map((id) => (
                      <li key={id}>
                        <Link to={`/investigations/findings/${id}`}>{id}</Link>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <h3>Tool requests ({content.request_ids.length})</h3>
                {content.request_ids.length === 0 ? (
                  <p className="muted">No requests selected.</p>
                ) : (
                  <ul className="compact-list mono small">
                    {content.request_ids.map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
            <Definition
              columns={1}
              items={[
                { term: "Linked investigation", description: content.investigation_id ? <Link className="mono" to={`/investigations/${content.investigation_id}`}>{content.investigation_id}</Link> : "not linked" },
                { term: "Dataset ID", description: content.dataset_id, mono: true },
                { term: "Synthetic classification", description: content.synthetic_classification },
                { term: "Integration status", description: content.integration_status, mono: true },
              ]}
            />
          </Section>

          <Section
            title="Export case"
            description="A local synthetic Markdown/JSON/CSV creation. The export omits nothing silently; scoped records only."
          >
            <div className="button-row">
              {(["markdown", "json", "csv"] as const).map((format) => (
                <Button
                  key={format}
                  onClick={() => exportNow(format)}
                  disabled={exporting !== null}
                  variant={format === "markdown" ? "primary" : "secondary"}
                >
                  {exporting === format ? "Creating export…" : `Export ${format === "markdown" ? "Markdown" : format.toUpperCase()}`}
                </Button>
              ))}
            </div>
            <p className="small muted">
              Exports require a healthy audit chain. CSV cells are formula-escaped. Markdown is escaped and
              explicitly labelled synthetic.
            </p>
            {exportResult ? (
              <details className="details" open>
                <summary>Preview generated file · {exportResult.filename}</summary>
                <div className="details__body">
                  <p className="small">
                    SHA-256 <Hash value={exportResult.sha256} />
                  </p>
                  <p className="small">
                    Embedded audit snapshot: integrity{" "}
                    <StatusBadge status={exportResult.auditVerification.integrity} /> completeness{" "}
                    <StatusBadge status={exportResult.auditVerification.completeness} /> consistency{" "}
                    <StatusBadge status={exportResult.auditVerification.consistency} />.
                  </p>
                  <pre className="export-preview">{exportResult.content.slice(0, 12000)}</pre>
                  <p className="small muted">
                    Preview is truncated in the UI after 12,000 characters. The downloaded file contains the full
                    export.
                  </p>
                </div>
              </details>
            ) : null}
          </Section>

          <Section title="Revision history" description="Every saved revision remains available for inspection.">
            <ol className="revision-list">
              {data.revisions.map((revision) => (
                <li key={revision.id}>
                  <div className="revision-list__head">
                    <strong>Revision {revision.revision}</strong>
                    <span className="muted">
                      {formatTimestamp(revision.created_at, zone)} · {revision.author}
                    </span>
                  </div>
                  <p className="small">
                    {revision.content.title} · {revision.content.recommendations.length} recommendation(s)
                  </p>
                </li>
              ))}
            </ol>
          </Section>
        </div>

        <div className="stack">
          <Section title="Case record">
            <Definition
              columns={1}
              items={[
                { term: "Case ID", description: data.id, mono: true },
                { term: "Status", description: <StatusBadge status={data.status} /> },
                { term: "Revision", description: data.revision, mono: true },
                { term: "Created by", description: data.created_by, mono: true },
                { term: "Created", description: formatTimestamp(data.created_at, zone) },
                { term: "Updated", description: formatTimestamp(data.updated_at, zone) },
                { term: "Dataset", description: data.dataset_name },
              ]}
            />
          </Section>

          <Section title="Saved exports" description="Files created by this case. Download re-reads the stored immutable export.">
            {data.exports.length === 0 ? (
              <EmptyState title="No exports created" />
            ) : (
              <ul className="export-list">
                {data.exports.map((item) => (
                  <li key={item.id}>
                    <div>
                      <strong>{item.format}</strong> · revision {item.revision}
                      <div className="row-subtitle">{formatTimestamp(item.created_at, zone)}</div>
                      <div className="row-subtitle mono">SHA {item.sha256.slice(0, 12)}…</div>
                      <div className="row-subtitle">{item.integration_status}</div>
                    </div>
                    <Button
                      size="sm"
                      variant="quiet"
                      onClick={() => downloadSavedExport(item.id)}
                      disabled={exporting !== null}
                    >
                      {exporting === item.id ? "Loading…" : "Download"}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Notice tone="warning" title="Synthetic, manual handoff only">
            This case is not a real compromise, not a Vigil case, and not proof of external delivery. Internal
            finding IDs are not external SOC case IDs.
          </Notice>

          <Section title="Related records">
            <div className="stack stack--tight">
              {content.investigation_id ? (
                <Link className="text-link" to={`/investigations/${content.investigation_id}`}>
                  Linked investigation
                </Link>
              ) : null}
              <Link className="text-link" to="/audit">
                Audit verification and event sequence
              </Link>
              <Link className="text-link" to="/audit?tab=cases">
                All cases
              </Link>
            </div>
          </Section>

          <Section title="Generate another case">
            <p className="small">
              Cases are created from explicit selected findings and requests. Use the cases tab to start a new
              scope.
            </p>
            <Button
              size="sm"
              onClick={() => navigate("/audit?tab=cases&create=1")}
            >
              Create case
            </Button>
          </Section>
        </div>
      </div>
    </>
  );
}
