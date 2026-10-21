import { Link, useParams } from "react-router-dom";
import { API_PREFIX } from "../api/client";
import type { Evaluation } from "../api/types";
import {
  Button,
  CodeBlock,
  Definition,
  EmptyState,
  ErrorNotice,
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
import { formatTimestamp, numeric, percent } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

export function EvaluationDetailPage() {
  const { evaluationId } = useParams<{ evaluationId: string }>();
  const evaluation = useApi<Evaluation>(evaluationId ? `/evaluations/${evaluationId}` : null);
  const { zone } = useWorkspace();
  const data = evaluation.data;
  const summary = data?.summary ?? null;
  const detection = summary?.synthetic_detection;
  const enforcement = summary?.scripted_enforcement;

  if (evaluation.loading && !data) {
    return (
      <>
        <PageHeader title="Evaluation" eyebrow="Evaluation" />
        <LoadingState label="Reading evaluation" />
      </>
    );
  }
  if (evaluation.error && !data) {
    return (
      <>
        <PageHeader title="Evaluation" eyebrow="Evaluation" />
        <ErrorNotice message={evaluation.error} action={<Button onClick={evaluation.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Evaluation" eyebrow="Evaluation" />
        <EmptyState title="Evaluation not found" action={<LinkButton to="/evaluation">Back to evaluations</LinkButton>} />
      </>
    );
  }

  return (
    <>
      <div className="breadcrumb">
        <Link to="/evaluation">Evaluation</Link>
        <span aria-hidden="true">/</span>
        <span className="mono">{data.id}</span>
      </div>
      <PageHeader
        eyebrow={`${data.suite_version} · ${data.runtime_kind} runtime`}
        title="Evaluation run"
        description={
          summary?.thesis ??
          "This run did not complete with a summary. Completed results are preserved and no smaller successful benchmark is implied."
        }
        actions={
          <div className="button-group">
            <StatusBadge status={data.status} />
            <LastUpdated at={evaluation.refreshedAt} refreshing={evaluation.refreshing} onRefresh={evaluation.reload} />
          </div>
        }
      />

      {evaluation.error ? <ErrorNotice message={evaluation.error} /> : null}
      {data.status === "FAILED" ? (
        <Notice tone="danger" title={`Evaluation failed${data.error_code ? `: ${data.error_code}` : ""}`}>
          The run is not a smaller successful benchmark. {data.results.length} result(s) were recorded before
          failure and remain visible.
        </Notice>
      ) : null}

      {data.status === "COMPLETED" && summary ? (
        <>
          <div className="export-bar" aria-label="Evaluation report exports">
            <span className="small muted">Download the same recorded summary:</span>
            {(["json", "markdown", "csv"] as const).map((format) => (
              <a
                className="button button--secondary button--sm"
                key={format}
                href={`${API_PREFIX}/evaluations/${data.id}/export?format=${format}`}
              >
                {format === "markdown" ? "Markdown" : format.toUpperCase()}
              </a>
            ))}
            <span className="small muted">Files are generated from this completed run.</span>
          </div>

          {detection ? (
            <Section
              title="Synthetic detection metrics"
              description="Known labels are synthetic policy-outcome labels. Metrics are conditional on emitted binary decisions."
            >
              <div className="metric-strip">
                <div>
                  <span className="metric-strip__label">True positive</span>
                  <strong>{detection.TP}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">False positive</span>
                  <strong>{detection.FP}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">True negative</span>
                  <strong>{detection.TN}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">False negative</span>
                  <strong>{detection.FN}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Abstained</span>
                  <strong>{detection.abstained}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Unlabeled</span>
                  <strong>{detection.unlabeled}</strong>
                </div>
              </div>
              <div className="table-wrap metrics-table">
                <table>
                  <caption className="sr-only">Detection metric denominators</caption>
                  <thead>
                    <tr>
                      <th scope="col">Quantity</th>
                      <th scope="col" className="numeric">Value</th>
                      <th scope="col">Definition</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">Known-label total</th>
                      <td className="numeric mono">{detection.known_total}</td>
                      <td>TP + FP + TN + FN + abstained + missing + errored</td>
                    </tr>
                    <tr>
                      <th scope="row">Emitted decisions</th>
                      <td className="numeric mono">{detection.emitted}</td>
                      <td>Denominator for conditional precision and recall</td>
                    </tr>
                    <tr>
                      <th scope="row">Prediction coverage</th>
                      <td className="numeric mono">{percent(detection.coverage)}</td>
                      <td>(TP + FP + TN + FN) / known total</td>
                    </tr>
                    <tr>
                      <th scope="row">Missing / errored</th>
                      <td className="numeric mono">
                        {detection.missing} / {detection.errored}
                      </td>
                      <td>Kept separate from abstention and true negatives</td>
                    </tr>
                    <tr>
                      <th scope="row">Precision</th>
                      <td className="numeric mono">{numeric(detection.precision)}</td>
                      <td>TP / (TP + FP), conditional on coverage</td>
                    </tr>
                    <tr>
                      <th scope="row">Recall</th>
                      <td className="numeric mono">{numeric(detection.recall)}</td>
                      <td>TP / (TP + FN), conditional on coverage</td>
                    </tr>
                    <tr>
                      <th scope="row">F1</th>
                      <td className="numeric mono">{numeric(detection.f1)}</td>
                      <td>Undefined when required precision or recall is undefined</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="small muted">{detection.label_note}</p>
              <p className="small muted">{detection.metric_note}</p>

              <h3>Threshold comparison</h3>
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Diagnostic threshold comparison</caption>
                  <thead>
                    <tr>
                      <th scope="col" className="numeric">Threshold</th>
                      <th scope="col" className="numeric">TP</th>
                      <th scope="col" className="numeric">FP</th>
                      <th scope="col" className="numeric">TN</th>
                      <th scope="col" className="numeric">FN</th>
                      <th scope="col" className="numeric">Precision</th>
                      <th scope="col" className="numeric">Recall</th>
                      <th scope="col" className="numeric">F1</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detection.threshold_comparison.map((row) => (
                      <tr key={row.threshold}>
                        <td className="numeric mono">{row.threshold}</td>
                        <td className="numeric">{row.TP}</td>
                        <td className="numeric">{row.FP}</td>
                        <td className="numeric">{row.TN}</td>
                        <td className="numeric">{row.FN}</td>
                        <td className="numeric mono">{numeric(row.precision)}</td>
                        <td className="numeric mono">{numeric(row.recall)}</td>
                        <td className="numeric mono">{numeric(row.f1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="small muted">
                The same fixture is reused for this diagnostic table. It is not held-out tuning evidence.
              </p>
            </Section>
          ) : null}

          {enforcement ? (
            <Section
              title="Scripted enforcement checks"
              description="Deterministic outcomes from the server gateway. Not a model susceptibility measurement."
            >
              <div className="metric-strip metric-strip--six">
                <div>
                  <span className="metric-strip__label">Checks passed</span>
                  <strong>
                    {enforcement.policy_bypass_tests_passed}/{enforcement.policy_bypass_tests_total}
                  </strong>
                </div>
                <div>
                  <span className="metric-strip__label">Blocked</span>
                  <strong>{enforcement.blocked}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Approved</span>
                  <strong>{enforcement.approved}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Monitored</span>
                  <strong>{enforcement.monitored}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Rejected</span>
                  <strong>{enforcement.rejected}</strong>
                </div>
                <div>
                  <span className="metric-strip__label">Proposals</span>
                  <strong>{enforcement.counts.proposals}</strong>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Scripted enforcement scenario outcomes</caption>
                  <thead>
                    <tr>
                      <th scope="col">Scenario</th>
                      <th scope="col">Outcome</th>
                      <th scope="col">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {enforcement.scenarios.map((scenario) => (
                      <tr key={scenario.scenario}>
                        <td className="mono">{scenario.scenario}</td>
                        <td>
                          <StatusBadge status={scenario.passed ? "PASS" : "FAIL"} />
                        </td>
                        <td className="prose-cell small">{scenario.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="small muted">{enforcement.note}</p>
              <p className="small">
                Synthetic attack proposals: <strong>{enforcement.counts.synthetic_attack_attempts ?? "not recorded"}</strong>.
                Counts include committed gateway requests from this suite only.
              </p>
            </Section>
          ) : null}

          <div className="detail-grid">
            <Section title="Audit verification snapshot" description="Integrity, completeness, and consistency remain separate claims.">
              {summary.audit_verification ? (
                <Definition
                  columns={1}
                  items={[
                    { term: "Integrity", description: <StatusBadge status={summary.audit_verification.integrity} /> },
                    { term: "Completeness", description: <StatusBadge status={summary.audit_verification.completeness} /> },
                    { term: "Consistency", description: <StatusBadge status={summary.audit_verification.consistency} /> },
                    { term: "Safe for mutations", description: summary.audit_verification.safe_for_mutations ? "yes" : "no" },
                    { term: "Events checked", description: summary.audit_verification.checked_events, mono: true },
                    { term: "Head MAC", description: <Hash value={summary.audit_verification.head_mac} /> },
                    { term: "Message", description: summary.audit_verification.message },
                  ]}
                />
              ) : (
                <EmptyState title="No audit snapshot recorded" />
              )}
            </Section>

            <Section title="Local model observations">
              <p className="small">
                Local Ollama runs with an observed response: <strong>{summary.local_model_observations.count}</strong>.
                Attempted runs: <strong>{summary.local_model_observations.attempted_runs ?? "not recorded"}</strong>.
                Included in these metrics:{" "}
                <strong>{summary.local_model_observations.included_in_metrics ? "yes" : "no"}</strong>.
              </p>
              <p className="small muted">{summary.local_model_observations.note}</p>
            </Section>
          </div>

          <Section title="Limitations" description="Carry these into any interpretation or portfolio claim.">
            <ul className="compact-list">
              {summary.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </Section>
        </>
      ) : null}

      <Section title="Recorded results" description="Raw expected and actual outcomes, including failures and unlabeled cases.">
        {data.results.length === 0 ? (
          <EmptyState title="No results recorded" />
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Evaluation result rows</caption>
              <thead>
                <tr>
                  <th scope="col">Category</th>
                  <th scope="col">Scenario</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Detail</th>
                  <th scope="col">Expected / actual</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((result) => (
                  <tr key={result.id}>
                    <td>{result.category}</td>
                    <td className="mono">{result.scenario_key}</td>
                    <td>
                      <StatusBadge status={result.outcome} />
                    </td>
                    <td className="prose-cell small">{result.details}</td>
                    <td>
                      <details className="details">
                        <summary>JSON</summary>
                        <div className="details__body">
                          <CodeBlock label="Expected">{JSON.stringify(result.expected, null, 2)}</CodeBlock>
                          <CodeBlock label="Actual">{JSON.stringify(result.actual, null, 2)}</CodeBlock>
                        </div>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Run provenance">
        <Definition
          columns={2}
          items={[
            { term: "Evaluation ID", description: data.id, mono: true },
            { term: "Dataset ID", description: data.dataset_id, mono: true },
            { term: "Suite", description: data.suite_version, mono: true },
            { term: "Runtime", description: data.runtime_kind },
            { term: "Label version", description: summary?.label_version ?? "not available", mono: true },
            { term: "Dataset scenario", description: summary?.dataset_scenario ?? "not available" },
            { term: "Started", description: formatTimestamp(data.started_at, zone) },
            { term: "Completed", description: formatTimestamp(data.completed_at, zone) },
          ]}
        />
        <h3>Configuration</h3>
        <CodeBlock>{JSON.stringify(data.config, null, 2)}</CodeBlock>
      </Section>
    </>
  );
}
