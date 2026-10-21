import { useMemo, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, apiRequest, errorMessage } from "../api/client";
import type { EvidenceItem, Investigation } from "../api/types";
import {
  Button,
  Definition,
  EmptyState,
  ErrorNotice,
  Field,
  LastUpdated,
  LinkButton,
  LoadingState,
  Notice,
  PageHeader,
  Section,
  StatusBadge,
  type BadgeTone,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { formatTimestamp } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

const VERDICT_OPTIONS = [
  {
    value: "POLICY_VIOLATION_SUPPORTED",
    label: "Policy violation supported",
    hint: "The cited evidence supports a policy violation in this synthetic scenario. Requires evidence.",
  },
  {
    value: "WITHIN_OBSERVED_SCOPE",
    label: "Within observed scope",
    hint: "The cited evidence supports that the action was within the observed authorization scope. Requires evidence.",
  },
  {
    value: "INSUFFICIENT_EVIDENCE",
    label: "Insufficient evidence",
    hint: "The available evidence does not support a defensible conclusion. Evidence is optional.",
  },
  {
    value: "NEEDS_MORE_DATA",
    label: "Needs more data",
    hint: "A concrete additional observation is required. Evidence is optional.",
  },
];

const EVIDENCE_VERDICTS = new Set(["POLICY_VIOLATION_SUPPORTED", "WITHIN_OBSERVED_SCOPE"]);

function uniqueEvidence(investigation: Investigation): EvidenceItem[] {
  const seen = new Map<string, EvidenceItem>();
  for (const finding of investigation.findings) {
    for (const item of finding.evidence) {
      if (!seen.has(item.event_id)) {
        seen.set(item.event_id, item);
      }
    }
  }
  return [...seen.values()].sort((left, right) => {
    if (!left.ts_utc && right.ts_utc) return 1;
    if (left.ts_utc && !right.ts_utc) return -1;
    return (left.ts_utc ?? "").localeCompare(right.ts_utc ?? "");
  });
}

export function InvestigationDetailPage() {
  const { investigationId } = useParams<{ investigationId: string }>();
  const investigation = useApi<Investigation>(
    investigationId ? `/investigations/${investigationId}` : null,
  );
  const { zone } = useWorkspace();
  const [verdict, setVerdict] = useState("POLICY_VIOLATION_SUPPORTED");
  const [rationale, setRationale] = useState("");
  const [cited, setCited] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const data = investigation.data;
  const evidence = useMemo(() => (data ? uniqueEvidence(data) : []), [data]);
  const conflict =
    saveError instanceof ApiError && saveError.status === 409 ? saveError : null;

  if (investigation.loading && !data) {
    return (
      <>
        <PageHeader title="Investigation" eyebrow="Investigations" />
        <LoadingState label="Reading investigation" />
      </>
    );
  }
  if (investigation.error && !data) {
    return (
      <>
        <PageHeader title="Investigation" eyebrow="Investigations" />
        <ErrorNotice message={investigation.error} action={<Button onClick={investigation.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Investigation" eyebrow="Investigations" />
        <EmptyState title="Investigation not found" action={<LinkButton to="/investigations">Back to investigations</LinkButton>} />
      </>
    );
  }

  const toggleCited = (eventId: string) => {
    setCited((current) =>
      current.includes(eventId) ? current.filter((id) => id !== eventId) : [...current, eventId],
    );
  };

  const submitVerdict = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!investigationId) return;
    setSaving(true);
    setSaveError(null);
    setSaved(null);
    try {
      const result = await apiRequest<Investigation>(`/investigations/${investigationId}/verdicts`, {
        method: "POST",
        body: {
          verdict,
          rationale,
          evidence_ids: cited,
          expected_revision: data.revision,
        },
      });
      setSaved(`Verdict revision ${result.revision} saved. The previous revision remains in history.`);
      setRationale("");
      setCited([]);
      investigation.reload();
    } catch (cause) {
      setSaveError(cause);
    } finally {
      setSaving(false);
    }
  };

  const citedEvidence = evidence.filter((item) => cited.includes(item.event_id));
  const caseLink =
    `/audit?tab=cases&create=1&investigation=${data.id}` +
    `&dataset=${data.dataset_id}` +
    `&findings=${encodeURIComponent(data.finding_ids.join(","))}`;

  return (
    <>
      <div className="breadcrumb">
        <Link to="/investigations?tab=investigations">Investigations</Link>
        <span aria-hidden="true">/</span>
        <span>{data.id}</span>
      </div>
      <PageHeader
        eyebrow={`Investigation · revision ${data.revision}`}
        title={data.title}
        description={
          <>
            {data.findings.length} linked finding{data.findings.length === 1 ? "" : "s"};{" "}
            {data.verdicts.length} saved verdict revision{data.verdicts.length === 1 ? "" : "s"}. Analyst
            judgment is revisioned separately from detector disposition.
          </>
        }
        actions={
          <div className="button-group">
            <StatusBadge status={data.status} />
            <LinkButton to={caseLink} variant="secondary">
              Create case from scope
            </LinkButton>
            <LastUpdated at={investigation.refreshedAt} refreshing={investigation.refreshing} onRefresh={investigation.reload} />
          </div>
        }
      />

      {investigation.error ? <ErrorNotice message={investigation.error} /> : null}
      {saved ? <Notice tone="success">{saved}</Notice> : null}
      {conflict ? (
        <Notice tone="danger" title="Revision conflict">
          <p>{conflict.message}</p>
          <p className="small">
            Your draft rationale and citations remain on screen. Reload the current investigation revision
            before saving; nothing is overwritten.
          </p>
          <Button size="sm" onClick={investigation.reload}>
            Reload current revision
          </Button>
        </Notice>
      ) : saveError ? (
        <ErrorNotice
          message={errorMessage(saveError)}
          code={saveError instanceof ApiError ? saveError.code : null}
          requestId={saveError instanceof ApiError ? saveError.requestId : null}
        />
      ) : null}

      <div className="detail-grid">
        <div className="stack">
          <Section title="Linked findings" description="Detector conclusions and uncertainty carried into this investigation.">
            {data.findings.length === 0 ? (
              <EmptyState title="No linked findings available" />
            ) : (
              <div className="stack stack--tight">
                {data.findings.map((finding) => (
                  <article className="finding-summary" key={finding.id}>
                    <div className="finding-summary__head">
                      <div>
                        <Link className="row-title" to={`/investigations/findings/${finding.id}`}>
                          {finding.title}
                        </Link>
                        <p className="row-subtitle">
                          {finding.agent_label} · rules {finding.rules_version} · {finding.evidence.length} evidence records
                        </p>
                      </div>
                      <div className="button-group">
                        <StatusBadge status={finding.disposition} />
                        <span className="priority">Priority {finding.priority_score}</span>
                      </div>
                    </div>
                    <p className="small">{finding.interpretation}</p>
                    <details className="details">
                      <summary>Observed facts and unknowns</summary>
                      <div className="details__body">
                        <h4>Observed facts</h4>
                        <ul className="compact-list">
                          {finding.observed_facts.map((fact) => (
                            <li key={fact.text}>{fact.text}</li>
                          ))}
                        </ul>
                        <h4>Unknowns</h4>
                        {finding.unknowns.length === 0 ? (
                          <p className="muted small">None recorded.</p>
                        ) : (
                          <ul className="compact-list">
                            {finding.unknowns.map((unknown) => (
                              <li key={unknown} className="text-warning">
                                {unknown}
                              </li>
                            ))}
                          </ul>
                        )}
                        <p className="small muted">{finding.limitations}</p>
                      </div>
                    </details>
                  </article>
                ))}
              </div>
            )}
          </Section>

          <Section title="Analyst notes">
            {data.notes ? <p className="prose">{data.notes}</p> : <p className="muted">No initial notes recorded.</p>}
          </Section>

          <Section
            title="Verdict history"
            description="Append-only revisions. A verdict means the cited synthetic evidence supports this conclusion, not proven compromise."
          >
            {data.verdicts.length === 0 ? (
              <EmptyState title="Not reviewed">
                There is no analyst verdict yet. This is distinct from the detector's disposition.
              </EmptyState>
            ) : (
              <ol className="verdict-history">
                {[...data.verdicts].reverse().map((item) => (
                  <li key={item.id}>
                    <div className="verdict-history__head">
                      <div>
                        <strong>Revision {item.revision}</strong>
                        <span className="muted"> · {formatTimestamp(item.created_at, zone)}</span>
                      </div>
                      <BadgeForVerdict verdict={item.verdict} />
                    </div>
                    <p className="prose">{item.rationale}</p>
                    <p className="small muted">
                      Cited evidence:{" "}
                      {item.evidence_ids.length === 0 ? "none" : item.evidence_ids.join(", ")} · author{" "}
                      <span className="mono">{item.created_by}</span>
                    </p>
                  </li>
                ))}
              </ol>
            )}
          </Section>

          <Section
            title="Record a verdict"
            description={`This creates revision ${data.revision + 1}. The current expected revision is ${data.revision}.`}
          >
            <form onSubmit={submitVerdict} className="form-grid">
              <Field
                label="Verdict"
                htmlFor="verdict-type"
                hint="Supported conclusions require at least one cited evidence record. IP attribution alone is not sufficient."
              >
                <select id="verdict-type" value={verdict} onChange={(event) => setVerdict(event.target.value)}>
                  {VERDICT_OPTIONS.map((option) => (
                    <option value={option.value} key={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </Field>
              <div className="form-grid__full">
                <p className="small muted">{VERDICT_OPTIONS.find((option) => option.value === verdict)?.hint}</p>
              </div>
              <Field
                label="Rationale"
                htmlFor="verdict-rationale"
                hint="Required. State what the evidence supports and what remains unresolved."
              >
                <textarea
                  id="verdict-rationale"
                  value={rationale}
                  onChange={(event) => setRationale(event.target.value)}
                  rows={5}
                  maxLength={4000}
                  required
                />
              </Field>

              <div className="form-grid__full">
                <fieldset className="fieldset">
                  <legend>Cited evidence ({cited.length} selected)</legend>
                  {evidence.length === 0 ? (
                    <p className="muted small">This investigation has no evidence to cite.</p>
                  ) : (
                    <div className="citation-list">
                      {evidence.map((item) => (
                        <label className="citation" key={item.event_id}>
                          <input
                            type="checkbox"
                            checked={cited.includes(item.event_id)}
                            onChange={() => toggleCited(item.event_id)}
                          />
                          <span>
                            <span className="mono">{item.ref}</span>{" "}
                            <span className="muted">{item.event_type}</span>
                            {item.ts_utc ? (
                              <span className="citation__time">{formatTimestamp(item.ts_utc, zone)}</span>
                            ) : (
                              <span className="citation__time text-warning">time unavailable</span>
                            )}
                            <StatusBadge status={item.integrity} />
                          </span>
                        </label>
                      ))}
                    </div>
                  )}
                  {EVIDENCE_VERDICTS.has(verdict) && cited.length === 0 ? (
                    <p className="field__error">This verdict requires at least one cited evidence record.</p>
                  ) : null}
                  {citedEvidence.some((item) => item.integrity !== "verified") ? (
                    <p className="field__error">
                      A selected record failed integrity verification. The server will reject this citation.
                    </p>
                  ) : null}
                </fieldset>
              </div>

              <div className="form-actions form-grid__full">
                <Button type="submit" variant="primary" disabled={saving}>
                  {saving ? "Saving revision…" : `Save verdict revision ${data.revision + 1}`}
                </Button>
                <Button
                  type="button"
                  variant="quiet"
                  onClick={() => {
                    setRationale("");
                    setCited([]);
                  }}
                >
                  Clear draft
                </Button>
                <span className="small muted">
                  The server checks the expected revision, evidence ownership, and integrity in one transaction.
                </span>
              </div>
            </form>
          </Section>
        </div>

        <div className="stack">
          <Section title="Scope">
            <Definition
              columns={1}
              items={[
                { term: "Status", description: <StatusBadge status={data.status} /> },
                { term: "Investigation ID", description: data.id, mono: true },
                { term: "Dataset ID", description: data.dataset_id, mono: true },
                { term: "Revision", description: data.revision, mono: true },
                { term: "Created by", description: data.created_by, mono: true },
                { term: "Created", description: formatTimestamp(data.created_at, zone) },
                { term: "Updated", description: formatTimestamp(data.updated_at, zone) },
              ]}
            />
          </Section>

          <Section title="Latest verdict">
            {data.latest_verdict ? (
              <>
                <BadgeForVerdict verdict={data.latest_verdict.verdict} />
                <p className="small">{data.latest_verdict.rationale}</p>
                <p className="small muted">
                  Revision {data.latest_verdict.revision} · {formatTimestamp(data.latest_verdict.created_at, zone)}
                </p>
              </>
            ) : (
              <p className="muted">
                Not reviewed. The detector disposition is{" "}
                {data.findings.map((finding) => finding.disposition).join(", ") || "not available"}.
              </p>
            )}
          </Section>

          <Section title="Handoff">
            <p className="small">
              A case selects this investigation&apos;s scope explicitly. Exports are marked synthetic and
              manual-only; no external SOC is contacted.
            </p>
            <div className="stack stack--tight">
              <Link className="text-link" to={caseLink}>
                Create a case draft from this investigation
              </Link>
              <Link className="text-link" to={`/traces?new=1&investigation=${data.id}`}>
                Start a linked scripted review
              </Link>
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}

function BadgeForVerdict({ verdict }: { verdict: string }) {
  const label = verdict.replaceAll("_", " ");
  const tone: BadgeTone =
    verdict === "POLICY_VIOLATION_SUPPORTED"
      ? "warning"
      : verdict === "INSUFFICIENT_EVIDENCE" || verdict === "NEEDS_MORE_DATA"
        ? "unknown"
        : "info";
  return <StatusBadge status={label} explicit={tone} />;
}
