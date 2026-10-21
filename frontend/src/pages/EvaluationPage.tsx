import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiRequest, errorMessage } from "../api/client";
import type { Evaluation, ListResponse, EvaluationListItem } from "../api/types";
import {
  Button,
  EmptyState,
  ErrorNotice,
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

export function EvaluationPage() {
  const { activeDatasetId, activeDataset, zone, refreshKey } = useWorkspace();
  const evaluations = useApi<ListResponse<EvaluationListItem>>(
    activeDatasetId ? `/evaluations?dataset_id=${encodeURIComponent(activeDatasetId)}` : null, `${refreshKey}`);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const navigate = useNavigate();

  const run = async () => {
    if (!activeDatasetId) return;
    setRunning(true);
    setRunError(null);
    try {
      const result = await apiRequest<Evaluation>("/evaluations", {
        method: "POST",
        body: { dataset_id: activeDatasetId },
      });
      navigate(`/evaluation/${result.id}`);
    } catch (cause) {
      setRunError(errorMessage(cause));
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Reproducible synthetic checks"
        title="Evaluation"
        description={
          <>
            Which scenarios were tested, under which versions, and what the results actually measure.
            Scripted enforcement and synthetic detection labels are kept separate. Scope:{" "}
            <strong>{activeDataset?.name ?? "no dataset"}</strong>.
          </>
        }
        actions={
          <div className="button-group">
            <LastUpdated at={evaluations.refreshedAt} refreshing={evaluations.refreshing} onRefresh={evaluations.reload} />
            <Button variant="primary" onClick={run} disabled={running || !activeDatasetId}>
              {running ? "Running suite…" : "Run synthetic baseline suite"}
            </Button>
          </div>
        }
      />

      <Notice tone="info" title="What this evaluation is">
        The suite uses a four-agent synthetic fixture with three binary policy-outcome labels and one
        intentionally unlabeled agent. It validates plumbing and expected outcomes. It is not a held-out
        benchmark, a real intrusion-detection accuracy estimate, or an LLM attack-success rate.
      </Notice>
      {runError ? <ErrorNotice message={runError} /> : null}

      <Section title="Evaluation runs" description="Only versions recorded by the server are compared.">
        {evaluations.error && !evaluations.data ? (
          <ErrorNotice message={evaluations.error} action={<Button onClick={evaluations.reload}>Retry</Button>} />
        ) : evaluations.loading && !evaluations.data ? (
          <LoadingState label="Reading evaluation runs" />
        ) : !evaluations.data || evaluations.data.items.length === 0 ? (
          <EmptyState
            title="No evaluations recorded"
            action={
              <Button variant="primary" onClick={run} disabled={running || !activeDatasetId}>
                Run the synthetic baseline suite
              </Button>
            }
          >
            The scripted suite creates its own runs through the same deterministic gateway. It never calls an
            external model.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Evaluation runs</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Suite</th>
                  <th scope="col">Runtime</th>
                  <th scope="col" className="numeric">Results</th>
                  <th scope="col">Started</th>
                  <th scope="col">Completed</th>
                </tr>
              </thead>
              <tbody>
                {evaluations.data.items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <StatusBadge status={item.status} />
                      {item.error_code ? <div className="row-subtitle text-danger">{item.error_code}</div> : null}
                    </td>
                    <td>
                      <Link className="row-title" to={`/evaluation/${item.id}`}>
                        {item.suite_version}
                      </Link>
                      <div className="row-subtitle mono">{item.id}</div>
                    </td>
                    <td>{item.runtime_kind}</td>
                    <td className="numeric">{item.result_count}</td>
                    <td className="nowrap">{formatTimestamp(item.started_at, zone)}</td>
                    <td className="nowrap">{formatTimestamp(item.completed_at, zone)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="table-caption">{plural(evaluations.data.items.length, "evaluation run")} recorded.</p>
          </div>
        )}
      </Section>

      <Section title="Evaluation scope">
        <div className="card-grid card-grid--three">
          <div>
            <h3>Synthetic detection</h3>
            <p className="small">
              Known labels mean &quot;supported policy violation in this synthetic fixture&quot;, not
              malicious intent. Abstentions, missing predictions, and unlabeled agents stay visible.
            </p>
          </div>
          <div>
            <h3>Scripted enforcement</h3>
            <p className="small">
              Deterministic proposals exercise deny, approve, monitor, rejection, single-use consumption, and
              bypass checks through the server gateway.
            </p>
          </div>
          <div>
            <h3>Local model observations</h3>
            <p className="small">
              Ollama observations, if any, are stored separately and are never silently included in the
              scripted metrics.
            </p>
          </div>
        </div>
      </Section>
    </>
  );
}
