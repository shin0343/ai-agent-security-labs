import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { apiRequest, errorMessage } from "../api/client";
import type { FindingList, Investigation, ListResponse } from "../api/types";
import {
  Button,
  EmptyState,
  ErrorNotice,
  Field,
  LastUpdated,
  LoadingState,
  PageHeader,
  Section,
  StatusBadge,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { formatTimestamp, plural, shortHash } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

type Tab = "findings" | "investigations";

export function InvestigationsPage() {
  const { activeDatasetId, activeDataset, zone, refreshKey } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "investigations" ? "investigations" : "findings";
  const disposition = params.get("disposition") ?? "";
  const status = params.get("status") ?? "";
  const findingPath = activeDatasetId
    ? `/findings?dataset_id=${encodeURIComponent(activeDatasetId)}${disposition ? `&disposition=${disposition}` : ""}&limit=200`
    : null;
  const investigationPath = activeDatasetId
    ? `/investigations?dataset_id=${encodeURIComponent(activeDatasetId)}`
    : null;
  const findings = useApi<FindingList>(findingPath, `${refreshKey}`);
  const investigations = useApi<ListResponse<Investigation>>(investigationPath, `${refreshKey}`);
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    setParams(next, { replace: true });
  };

  const toggleSelected = (id: string) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const openCreate = () => {
    if (!creating && selected.length === 0 && findings.data?.items[0]) {
      const first = findings.data.items[0];
      setSelected([first.id]);
      setTitle(`${first.agent_label} · ${first.title}`);
    }
    setCreating(true);
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!activeDatasetId) {
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      const result = await apiRequest<Investigation>("/investigations", {
        method: "POST",
        body: {
          dataset_id: activeDatasetId,
          title,
          finding_ids: selected,
          notes,
        },
      });
      navigate(`/investigations/${result.id}`);
    } catch (cause) {
      setFormError(errorMessage(cause));
    } finally {
      setSaving(false);
    }
  };

  const findingCounts = findings.data?.counts;
  const filteredInvestigations = (investigations.data?.items ?? []).filter(
    (item) => !status || item.status === status,
  );

  return (
    <>
      <PageHeader
        eyebrow="Evidence and analyst judgment"
        title="Investigations"
        description={
          <>
            Inspect source-linked findings, what the evidence supports, what remains unknown, and save a
            revisioned analyst verdict. Scope: <strong>{activeDataset?.name ?? "no dataset"}</strong>.
          </>
        }
        actions={
          <LastUpdated
            at={findings.refreshedAt ?? investigations.refreshedAt}
            refreshing={findings.refreshing || investigations.refreshing}
            onRefresh={() => {
              findings.reload();
              investigations.reload();
            }}
          />
        }
      />

      <div className="tab-bar" role="tablist" aria-label="Investigation views">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "findings"}
          className={tab === "findings" ? "tab tab--active" : "tab"}
          onClick={() => updateParam("tab", "findings")}
        >
          Review queue
          {findingCounts ? (
            <span className="tab__count">{findingCounts.REVIEW + findingCounts.UNKNOWN}</span>
          ) : null}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "investigations"}
          className={tab === "investigations" ? "tab tab--active" : "tab"}
          onClick={() => updateParam("tab", "investigations")}
        >
          Investigations
          {investigations.data ? (
            <span className="tab__count">{investigations.data.items.length}</span>
          ) : null}
        </button>
      </div>

      {tab === "findings" ? (
        <>
          <div className="filter-bar">
            <label>
              <span>Disposition</span>
              <select
                value={disposition}
                onChange={(event) => updateParam("disposition", event.target.value)}
              >
                <option value="">All dispositions</option>
                <option value="REVIEW">Review</option>
                <option value="UNKNOWN">Unknown</option>
                <option value="LOW">Low</option>
              </select>
            </label>
            {disposition ? (
              <Button size="sm" variant="quiet" onClick={() => updateParam("disposition", "")}>
                Clear filter
              </Button>
            ) : null}
            <span className="filter-bar__note">
              Sorted by actionable disposition, then rule priority. Priority is not a probability.
            </span>
            <Button variant="primary" size="sm" onClick={openCreate} disabled={!activeDatasetId}>
              {creating ? "New investigation form open" : "New investigation"}
            </Button>
          </div>

          {creating ? (
            <Section
              title="Create investigation"
              description="Select one or more findings from this dataset. The investigation preserves exactly those finding links."
              actions={
                <Button size="sm" variant="quiet" onClick={() => setCreating(false)}>
                  Close
                </Button>
              }
            >
              <form onSubmit={submit} className="form-grid">
                <Field label="Title" htmlFor="investigation-title" hint="1–160 characters.">
                  <input
                    id="investigation-title"
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={160}
                    required
                  />
                </Field>
                <Field
                  label="Analyst notes"
                  htmlFor="investigation-notes"
                  hint="Initial observations only. Verdict rationale is stored separately as a revision."
                  optional
                >
                  <textarea
                    id="investigation-notes"
                    value={notes}
                    onChange={(event) => setNotes(event.target.value)}
                    rows={3}
                    maxLength={4000}
                  />
                </Field>
                <div className="form-grid__full">
                  <p className="small">
                    <strong>{selected.length}</strong> finding{selected.length === 1 ? "" : "s"} selected.
                    Select findings in the table below.
                  </p>
                </div>
                {formError ? (
                  <div className="form-grid__full">
                    <ErrorNotice message={formError} />
                  </div>
                ) : null}
                <div className="form-actions form-grid__full">
                  <Button type="submit" variant="primary" disabled={saving || selected.length === 0}>
                    {saving ? "Creating…" : "Create investigation"}
                  </Button>
                  <span className="muted small">The server records this transition in the audit chain.</span>
                </div>
              </form>
            </Section>
          ) : null}

          <Section title="Finding queue">
            {findings.error && !findings.data ? (
              <ErrorNotice message={findings.error} action={<Button onClick={findings.reload}>Retry</Button>} />
            ) : findings.loading && !findings.data ? (
              <LoadingState label="Reading findings" />
            ) : !findings.data || findings.data.items.length === 0 ? (
              <EmptyState
                title={disposition ? `No ${disposition.toLowerCase()} findings match this filter` : "No findings recorded"}
                action={
                  disposition ? (
                    <Button onClick={() => updateParam("disposition", "")}>Clear filter</Button>
                  ) : (
                    <Link className="text-link" to="/">
                      Return to overview
                    </Link>
                  )
                }
              >
                {disposition
                  ? "Change the disposition filter to inspect other findings."
                  : "Import the synthetic sample dataset from Overview to produce findings."}
              </EmptyState>
            ) : (
              <>
                {findings.error ? <ErrorNotice message={findings.error} /> : null}
                <div className="table-wrap">
                  <table>
                    <caption className="sr-only">Finding review queue</caption>
                    <thead>
                      <tr>
                        {creating ? <th scope="col" className="select-cell">Select</th> : null}
                        <th scope="col">Disposition</th>
                        <th scope="col">Agent / finding</th>
                        <th scope="col">Interpretation</th>
                        <th scope="col" className="numeric">Priority</th>
                        <th scope="col" className="numeric">Evidence</th>
                        <th scope="col">Recorded</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.data.items.map((finding) => {
                        const isSelected = selected.includes(finding.id);
                        return (
                          <tr key={finding.id} className={isSelected ? "row--selected" : undefined}>
                            {creating ? (
                              <td className="select-cell">
                                <input
                                  type="checkbox"
                                  aria-label={`Select ${finding.agent_label} finding: ${finding.title}`}
                                  checked={isSelected}
                                  onChange={() => toggleSelected(finding.id)}
                                />
                              </td>
                            ) : null}
                            <td>
                              <StatusBadge status={finding.disposition} />
                            </td>
                            <td>
                              <Link className="row-title" to={`/investigations/findings/${finding.id}`}>
                                {finding.title}
                              </Link>
                              <div className="row-subtitle">
                                {finding.agent_label} · <span className="mono">{shortHash(finding.id)}</span>
                              </div>
                            </td>
                            <td className="prose-cell">{finding.interpretation}</td>
                            <td className="numeric mono">{finding.priority_score}</td>
                            <td className="numeric">{finding.evidence_count}</td>
                            <td className="nowrap">{formatTimestamp(finding.created_at, zone)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <p className="table-caption">
                  Showing {plural(findings.data.items.length, "finding")}
                  {findingCounts
                    ? ` · ${findingCounts.REVIEW} review, ${findingCounts.UNKNOWN} unknown, ${findingCounts.LOW} low`
                    : ""}
                  . Each row opens the immutable evidence record.
                </p>
              </>
            )}
          </Section>
        </>
      ) : (
        <>
          <div className="filter-bar">
            <label>
              <span>Status</span>
              <select value={status} onChange={(event) => updateParam("status", event.target.value)}>
                <option value="">All statuses</option>
                <option value="OPEN">Open</option>
                <option value="REVIEWED">Reviewed</option>
                <option value="CLOSED">Closed</option>
              </select>
            </label>
            {status ? (
              <Button size="sm" variant="quiet" onClick={() => updateParam("status", "")}>
                Clear filter
              </Button>
            ) : null}
            <span className="filter-bar__note">
              A saved analyst verdict sets the investigation to reviewed. It does not prove compromise.
            </span>
          </div>
          <Section title="Investigation records">
            {investigations.error && !investigations.data ? (
              <ErrorNotice
                message={investigations.error}
                action={<Button onClick={investigations.reload}>Retry</Button>}
              />
            ) : investigations.loading && !investigations.data ? (
              <LoadingState label="Reading investigations" />
            ) : filteredInvestigations.length === 0 ? (
              <EmptyState
                title={status ? `No ${status.toLowerCase()} investigations` : "No investigations yet"}
                action={
                  <Button onClick={() => updateParam("tab", "findings")}>Open review queue</Button>
                }
              >
                Create an investigation from one or more findings to preserve an explicit evidence scope.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Investigations in the active dataset</caption>
                  <thead>
                    <tr>
                      <th scope="col">Status</th>
                      <th scope="col">Investigation</th>
                      <th scope="col" className="numeric">Findings</th>
                      <th scope="col" className="numeric">Verdicts</th>
                      <th scope="col">Latest verdict</th>
                      <th scope="col">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredInvestigations.map((investigation) => (
                      <tr key={investigation.id}>
                        <td>
                          <StatusBadge status={investigation.status} />
                        </td>
                        <td>
                          <Link className="row-title" to={`/investigations/${investigation.id}`}>
                            {investigation.title}
                          </Link>
                          <div className="row-subtitle mono">{investigation.id}</div>
                        </td>
                        <td className="numeric">{investigation.finding_ids.length}</td>
                        <td className="numeric">{investigation.verdict_count ?? 0}</td>
                        <td>
                          {investigation.latest_verdict
                            ? investigation.latest_verdict.verdict.replaceAll("_", " ")
                            : "Not reviewed"}
                        </td>
                        <td className="nowrap">{formatTimestamp(investigation.updated_at, zone)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </>
      )}
    </>
  );
}
