import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { apiRequest, errorMessage } from "../api/client";
import type { AgentRun, Investigation, ListResponse, PolicyList, RunList, ScenarioList } from "../api/types";
import {
  Button,
  EmptyState,
  ErrorNotice,
  Field,
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

export function TracesPage() {
  const { activeDatasetId, activeDataset, zone, refreshKey } = useWorkspace();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const runs = useApi<RunList>(
    activeDatasetId ? `/runs?dataset_id=${encodeURIComponent(activeDatasetId)}&limit=100` : null,
    `${refreshKey}`,
  );
  const scenarios = useApi<ScenarioList>("/scenarios");
  const policies = useApi<PolicyList>("/policies");
  const investigations = useApi<ListResponse<Investigation>>(
    activeDatasetId ? `/investigations?dataset_id=${encodeURIComponent(activeDatasetId)}` : null,
  );
  const [showForm, setShowForm] = useState(params.get("new") === "1");
  const [scenarioKey, setScenarioKey] = useState("injection");
  const [presetId, setPresetId] = useState("approve-v1");
  const [runtime, setRuntime] = useState("scripted");
  const [investigationId, setInvestigationId] = useState(params.get("investigation") ?? "");
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const selectedScenario = scenarios.data?.items.find((item) => item.key === scenarioKey);
  const ollamaEnabled = scenarios.data?.ollama.enabled ?? false;

  const startRun = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!activeDatasetId) return;
    setStarting(true);
    setStartError(null);
    try {
      const run = await apiRequest<AgentRun>("/runs", {
        method: "POST",
        body: {
          dataset_id: activeDatasetId,
          scenario_key: scenarioKey,
          policy_preset_id: presetId,
          runtime_kind: runtime,
          investigation_id: investigationId || null,
        },
      });
      navigate(`/traces/${run.id}`);
    } catch (cause) {
      setStartError(errorMessage(cause));
    } finally {
      setStarting(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Runtime and tool proposals"
        title="Agent traces"
        description={
          <>
            What the agent received, which tool calls it proposed, and how the deterministic gateway and
            execution layer responded. Scope: <strong>{activeDataset?.name ?? "no dataset"}</strong>.
          </>
        }
        actions={
          <div className="button-group">
            <LastUpdated at={runs.refreshedAt} refreshing={runs.refreshing} onRefresh={runs.reload} />
            <Button
              variant="primary"
              onClick={() => setShowForm((value) => !value)}
              disabled={!activeDatasetId}
            >
              {showForm ? "Close run form" : "Run scripted scenario"}
            </Button>
          </div>
        }
      />

      {runs.error ? <ErrorNotice message={runs.error} action={<Button onClick={runs.reload}>Retry</Button>} /> : null}

      {showForm ? (
        <Section
          title="Start an agent run"
          description="The scenario and server policy preset are explicit. The model or script never selects its own authorization mode."
        >
          <form className="form-grid" onSubmit={startRun}>
            <Field
              label="Scenario"
              htmlFor="run-scenario"
              hint={selectedScenario?.description ?? "Select a bounded scripted scenario."}
            >
              <select
                id="run-scenario"
                value={scenarioKey}
                onChange={(event) => setScenarioKey(event.target.value)}
                disabled={!scenarios.data}
              >
                {scenarios.data?.items.map((scenario) => (
                  <option value={scenario.key} key={scenario.key}>
                    {scenario.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Server policy preset"
              htmlFor="run-policy"
              hint="The preset is loaded server-side and bound into every request digest."
            >
              <select
                id="run-policy"
                value={presetId}
                onChange={(event) => setPresetId(event.target.value)}
                disabled={!policies.data}
              >
                {policies.data?.presets.map((preset) => (
                  <option value={preset.id} key={preset.id}>
                    {preset.name} · {preset.mode} · v{preset.version}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Runtime"
              htmlFor="run-runtime"
              hint={
                ollamaEnabled
                  ? "Optional local Ollama proposes the same tool DTOs through the same gateway."
                  : "Ollama is disabled on this server. The deterministic scripted runtime is the default."
              }
            >
              <select
                id="run-runtime"
                value={runtime}
                onChange={(event) => setRuntime(event.target.value)}
              >
                <option value="scripted">Scripted runtime (deterministic)</option>
                <option value="ollama" disabled={!ollamaEnabled}>
                  Local Ollama {ollamaEnabled ? "" : "(disabled)"}
                </option>
              </select>
            </Field>
            <Field
              label="Link investigation"
              htmlFor="run-investigation"
              hint="Optional. Links the run to an existing investigation in this dataset."
              optional
            >
              <select
                id="run-investigation"
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
            <div className="form-grid__full">
              <Notice tone="info" title="What this run can do">
                {selectedScenario?.description} All effects are local and synthetic. The agent cannot choose
                the policy mode, alter tool arguments after proposal, or execute a blocked request.
                {!ollamaEnabled ? " No local model observation is produced by this run." : ""}
              </Notice>
              {startError ? <ErrorNotice message={startError} /> : null}
            </div>
            <div className="form-actions form-grid__full">
              <Button type="submit" variant="primary" disabled={starting || !activeDatasetId}>
                {starting ? "Starting run…" : "Start run"}
              </Button>
              <span className="small muted">
                Approve-preset injection runs stop at <span className="mono">WAITING_APPROVAL</span> until an
                operator decides.
              </span>
            </div>
          </form>
        </Section>
      ) : null}

      <Section
        title="Recorded runs"
        description="Proposal, policy decision, approval, and execution are separate recorded fields."
      >
        {runs.loading && !runs.data ? (
          <LoadingState label="Reading agent runs" />
        ) : !runs.data || runs.data.items.length === 0 ? (
          <EmptyState
            title="No agent runs recorded"
            action={
              <Button variant="primary" onClick={() => setShowForm(true)} disabled={!activeDatasetId}>
                Open run form
              </Button>
            }
          >
            Run a scripted scenario to record a visible trace. Nothing runs automatically on page load.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Recorded agent runs</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Scenario</th>
                  <th scope="col">Runtime</th>
                  <th scope="col">Policy</th>
                  <th scope="col" className="numeric">Proposals</th>
                  <th scope="col" className="numeric">Trace steps</th>
                  <th scope="col">Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.data.items.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <StatusBadge status={run.status} />
                      {run.error_code ? <div className="row-subtitle text-danger">{run.error_code}</div> : null}
                    </td>
                    <td>
                      <Link className="row-title" to={`/traces/${run.id}`}>
                        {run.scenario_key}
                      </Link>
                      <div className="row-subtitle mono">{run.id}</div>
                    </td>
                    <td>{run.runtime_kind}</td>
                    <td>
                      {run.policy_name} <span className="muted">v{run.policy_version}</span>
                      <div className="row-subtitle">{run.policy_mode}</div>
                    </td>
                    <td className="numeric">{run.request_count ?? 0}</td>
                    <td className="numeric">{run.trace_count ?? 0}</td>
                    <td className="nowrap">{formatTimestamp(run.started_at, zone)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="table-caption">
              {plural(runs.data.items.length, "run")} in the active dataset. Runs with zero proposals are
              recorded as <span className="mono">NO_TOOL_CALL</span>, not as runtime failures.
            </p>
          </div>
        )}
      </Section>

      <Section title="Runtime boundary">
        <div className="card-grid card-grid--two">
          <div>
            <h3>Scripted (default)</h3>
            <p className="small">
              Deterministic actors produce fixed proposals for normal, injection, overreach, and
              boundary-aware scenarios. The suite runs without a model or network access.
            </p>
            <p className="small muted">
              Scripted injection results are not natural-language model susceptibility or LLM attack-success
              rates.
            </p>
          </div>
          <div>
            <h3>Optional local Ollama</h3>
            <p className="small">
              {scenarios.data?.ollama.note ?? "Loading constrained local-model configuration."}
            </p>
            <p className="small muted">
              Enabled: <strong>{ollamaEnabled ? "yes" : "no"}</strong> · configured model:{" "}
              <span className="mono">{scenarios.data?.ollama.model ?? "unknown"}</span>. No live model
              observation is claimed until a real run is recorded.
            </p>
          </div>
        </div>
      </Section>
    </>
  );
}
