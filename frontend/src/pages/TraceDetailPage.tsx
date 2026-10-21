import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { apiRequest, errorMessage } from "../api/client";
import type { AgentRunDetail, PolicyList } from "../api/types";
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
import { formatTimestamp, shortHash } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

export function TraceDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const run = useApi<AgentRunDetail>(runId ? `/runs/${runId}` : null);
  const policies = useApi<PolicyList>("/policies");
  const { zone } = useWorkspace();
  const [policyId, setPolicyId] = useState("");
  const [changing, setChanging] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const data = run.data;

  if (run.loading && !data) {
    return (
      <>
        <PageHeader title="Agent trace" eyebrow="Agent traces" />
        <LoadingState label="Reading run trace" />
      </>
    );
  }
  if (run.error && !data) {
    return (
      <>
        <PageHeader title="Agent trace" eyebrow="Agent traces" />
        <ErrorNotice message={run.error} action={<Button onClick={run.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Agent trace" eyebrow="Agent traces" />
        <EmptyState title="Run not found" />
      </>
    );
  }

  const canChangePolicy = ["RUNNING", "WAITING_APPROVAL"].includes(data.status);
  const noToolCall = data.trace.some((event) => event.kind === "no_tool_call");

  const changePolicy = async () => {
    if (!policyId || !runId) return;
    setChanging(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const result = await apiRequest<{ invalidated: number; policy_version: number }>(
        `/runs/${runId}/policy`,
        {
          method: "POST",
          body: { policy_preset_id: policyId, expected_revision: data.revision },
        },
      );
      setActionMessage(
        `Policy changed to version ${result.policy_version}. ${result.invalidated} pending approval(s) invalidated.`,
      );
      run.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setChanging(false);
    }
  };

  const cancelRun = async () => {
    if (!runId) return;
    setChanging(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const result = await apiRequest<{ invalidated: number; status: string }>(
        `/runs/${runId}/cancel`,
        { method: "POST" },
      );
      setActionMessage(`Run ${result.status.toLowerCase()}. ${result.invalidated} pending approval(s) invalidated.`);
      run.reload();
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setChanging(false);
    }
  };

  return (
    <>
      <div className="breadcrumb">
        <Link to="/traces">Agent traces</Link>
        <span aria-hidden="true">/</span>
        <span className="mono">{data.id}</span>
      </div>
      <PageHeader
        eyebrow={`${data.scenario_key} · ${data.runtime_kind} runtime`}
        title={`Run ${data.id}`}
        description={
          <>
            Input, proposals, policy decisions, approvals, and execution are separate recorded facts.{" "}
            {data.status === "WAITING_APPROVAL" ? "This run is paused for a local operator decision." : null}
          </>
        }
        actions={
          <div className="button-group">
            <StatusBadge status={data.status} />
            <LastUpdated at={run.refreshedAt} refreshing={run.refreshing} onRefresh={run.reload} />
          </div>
        }
      />

      {run.error ? <ErrorNotice message={run.error} /> : null}
      {actionError ? <ErrorNotice message={actionError} /> : null}
      {actionMessage ? <Notice tone="success">{actionMessage}</Notice> : null}
      {data.error_code ? (
        <Notice tone="danger" title={`Run failed: ${data.error_code}`}>
          Completed trace steps are preserved below. No successful final response is synthesized.
        </Notice>
      ) : null}
      {data.status === "WAITING_APPROVAL" ? (
        <Notice tone="warning" title="Waiting for approval">
          The proposal has no committed effect. Review the exact request, digest, policy version, and expiry
          before deciding.{" "}
          {(() => {
            const pending = data.requests.find((request) => request.approval_state === "PENDING");
            return pending?.approval_id ? (
              <Link to={`/policies/approvals/${pending.approval_id}`}>Open approval detail</Link>
            ) : null;
          })()}
        </Notice>
      ) : null}
      {noToolCall ? (
        <Notice tone="info" title="No tool calls proposed">
          The run completed visibly with <span className="mono">NO_TOOL_CALL</span>. This is a valid runtime
          outcome, not a failure and not a blocked request.
        </Notice>
      ) : null}

      <div className="detail-grid">
        <div className="stack">
          <Section title="Visible trace" description="Recorded runtime steps in sequence. No hidden reasoning transcript is invented.">
            {data.trace.length === 0 ? (
              <EmptyState title="No trace events recorded" />
            ) : (
              <ol className="trace">
                {data.trace.map((event) => (
                  <li className="trace__item" key={event.id}>
                    <div className="trace__seq mono" aria-hidden="true">
                      {String(event.seq).padStart(2, "0")}
                    </div>
                    <div className="trace__body">
                      <div className="trace__head">
                        <span className={`trace__kind trace__kind--${event.kind}`}>{event.kind}</span>
                        <span className="muted small">{formatTimestamp(event.created_at, zone)}</span>
                        {event.error_code ? <StatusBadge status={event.error_code} explicit="danger" /> : null}
                      </div>
                      <p className="trace__text">{event.text}</p>
                      {event.tool_request_id ? (
                        <p className="small">
                          Tool request{" "}
                          <span className="mono">{shortHash(event.tool_request_id, 10, 6)}</span>
                        </p>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Section>

          <Section
            title="Tool proposals and decisions"
            description="One row per immutable proposal. A blocked request cannot be shown as executed."
            id="requests"
          >
            {data.requests.length === 0 ? (
              <EmptyState title="No tool calls proposed">
                The runtime completed without a tool proposal. This is distinct from a policy block.
              </EmptyState>
            ) : (
              <div className="stack stack--tight">
                {data.requests.map((request) => (
                  <article className="request-card" key={request.id}>
                    <div className="request-card__head">
                      <div>
                        <h3 className="mono">{request.tool}</h3>
                        <p className="row-subtitle mono">{request.id}</p>
                      </div>
                      <div className="button-group">
                        <StatusBadge status={request.decision} />
                        <StatusBadge status={request.status} />
                        <StatusBadge status={request.execution_status} />
                      </div>
                    </div>
                    <div className="request-card__grid">
                      <div>
                        <p className="label">Arguments</p>
                        <CodeBlock>{JSON.stringify(request.arguments, null, 2)}</CodeBlock>
                      </div>
                      <div>
                        <p className="label">Policy reason</p>
                        <p className="small">
                          <span className="mono">{request.decision_reason_code}</span> —{" "}
                          {request.decision_reason}
                        </p>
                        <p className="small muted">
                          {request.policy_preset_id} v{request.policy_version} · mode {request.mode}
                        </p>
                        <Hash value={request.request_digest} label="Request digest" />
                      </div>
                    </div>
                    <Definition
                      columns={2}
                      items={[
                        { term: "Effect", description: request.effect },
                        { term: "Resource", description: request.resource_ref, mono: true },
                        { term: "Approval", description: request.approval_id ? <Link className="mono" to={`/policies/approvals/${request.approval_id}`}>{request.approval_id}</Link> : "not required", mono: false },
                        { term: "Approval state", description: request.approval_state ?? "not applicable" },
                        { term: "Executed at", description: formatTimestamp(request.decided_at, zone) },
                      ]}
                    />
                    {request.result ? (
                      <details className="details">
                        <summary>Execution result and receipt</summary>
                        <div className="details__body">
                          <CodeBlock label="Stored synthetic execution result">
                            {JSON.stringify(request.result, null, 2)}
                          </CodeBlock>
                          {request.receipt_id ? (
                            <p className="small">
                              Local synthetic receipt <span className="mono">{request.receipt_id}</span>
                            </p>
                          ) : null}
                        </div>
                      </details>
                    ) : request.execution_status === "NOT_STARTED" ? (
                      <p className="small muted">No execution result exists for this request.</p>
                    ) : null}
                  </article>
                ))}
              </div>
            )}
          </Section>
        </div>

        <div className="stack">
          <Section title="Run provenance">
            <Definition
              columns={1}
              items={[
                { term: "Scenario", description: data.scenario_key },
                { term: "Runtime", description: data.runtime_kind },
                { term: "Status", description: <StatusBadge status={data.status} /> },
                { term: "Policy", description: `${data.policy_name} (${data.policy_mode}) v${data.policy_version}` },
                { term: "Server revision", description: data.revision, mono: true },
                { term: "Seed", description: data.seed, mono: true },
                { term: "Dataset", description: data.dataset_id, mono: true },
                { term: "Investigation", description: data.investigation_id ?? "not linked", mono: true },
                { term: "Started", description: formatTimestamp(data.started_at, zone) },
                { term: "Ended", description: formatTimestamp(data.ended_at, zone) },
              ]}
            />
          </Section>

          <Section title="Runtime configuration">
            <CodeBlock>{JSON.stringify(data.config, null, 2)}</CodeBlock>
            {data.model ? (
              <>
                <h3>Model metadata</h3>
                <CodeBlock>{JSON.stringify(data.model, null, 2)}</CodeBlock>
                <p className="small muted">
                  Missing version or digest fields are shown as unknown; they are not inferred.
                </p>
              </>
            ) : (
              <p className="small muted">No model metadata for a scripted run.</p>
            )}
          </Section>

          <Section title="Run controls">
            {canChangePolicy ? (
              <div className="stack">
                <Field
                  label="Change server policy preset"
                  htmlFor="run-policy-change"
                  hint={`Expected run revision ${data.revision}. Changing policy invalidates pending approvals in the same transaction.`}
                >
                  <select
                    id="run-policy-change"
                    value={policyId}
                    onChange={(event) => setPolicyId(event.target.value)}
                  >
                    <option value="">Select a preset</option>
                    {policies.data?.presets.map((preset) => (
                      <option value={preset.id} key={preset.id}>
                        {preset.name} · {preset.mode} · v{preset.version}
                      </option>
                    ))}
                  </select>
                </Field>
                <div className="button-row">
                  <Button size="sm" onClick={changePolicy} disabled={!policyId || changing}>
                    {changing ? "Applying…" : "Change policy"}
                  </Button>
                  <Button size="sm" variant="danger" onClick={cancelRun} disabled={changing}>
                    Cancel run
                  </Button>
                </div>
                <p className="small muted">
                  Cancelling stops future proposals. It does not delete prior recorded decisions or produce
                  an effect.
                </p>
              </div>
            ) : (
              <p className="small muted">This run is terminal. Policy and cancellation controls are disabled.</p>
            )}
          </Section>

          <Section title="Related records">
            <div className="stack stack--tight">
              <Link className="text-link" to="/policies#requests">
                All tool requests and decisions
              </Link>
              {data.investigation_id ? (
                <Link className="text-link" to={`/investigations/${data.investigation_id}`}>
                  Linked investigation
                </Link>
              ) : null}
              <Link className="text-link" to="/audit">
                Audit chain for these transitions
              </Link>
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}
