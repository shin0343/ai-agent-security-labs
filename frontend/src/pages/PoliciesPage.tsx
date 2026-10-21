import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { Approval, ListResponse, PolicyList, ToolRequest } from "../api/types";
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
import { formatTimestamp, plural } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

export function PoliciesPage() {
  const { activeDatasetId, activeDataset, zone, refreshKey, audit } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const decision = params.get("decision") ?? "";
  const policies = useApi<PolicyList>("/policies");
  const approvals = useApi<ListResponse<Approval>>(
    activeDatasetId ? `/approvals?dataset_id=${encodeURIComponent(activeDatasetId)}` : null,
    `${refreshKey}`,
  );
  const requests = useApi<ListResponse<ToolRequest>>(
    activeDatasetId ? `/requests?dataset_id=${encodeURIComponent(activeDatasetId)}&limit=200` : null,
    `${refreshKey}`,
  );
  const [selectedRequest, setSelectedRequest] = useState<string | null>(null);

  const pending = (approvals.data?.items ?? []).filter(
    (approval) => approval.state === "PENDING" && !approval.expired,
  );
  const history = (approvals.data?.items ?? []).filter(
    (approval) => approval.state !== "PENDING" || approval.expired,
  );
  const filteredRequests = (requests.data?.items ?? []).filter(
    (request) => !decision || request.decision === decision,
  );
  const inspected = requests.data?.items.find((request) => request.id === selectedRequest) ?? null;

  const setDecision = (next: string) => {
    const updated = new URLSearchParams(params);
    if (next) {
      updated.set("decision", next);
    } else {
      updated.delete("decision");
    }
    setParams(updated, { replace: true });
  };

  return (
    <>
      <PageHeader
        eyebrow="Deterministic authorization"
        title="Policy & approvals"
        description={
          <>
            What the server allows, what it blocks, and exactly what an operator authorizes. The active
            preset is selected at run creation and cannot be chosen by the agent. Scope:{" "}
            <strong>{activeDataset?.name ?? "no dataset"}</strong>.
          </>
        }
        actions={
          <LastUpdated
            at={approvals.refreshedAt ?? requests.refreshedAt}
            refreshing={approvals.refreshing || requests.refreshing}
            onRefresh={() => {
              approvals.reload();
              requests.reload();
            }}
          />
        }
      />

      {audit && !audit.safe_for_mutations ? (
        <Notice tone="danger" title="Audit failure disables decisions">
          Approval and policy mutations are blocked by the server until audit verification is healthy.{" "}
          <Link to="/audit">Open audit</Link>.
        </Notice>
      ) : null}
      {approvals.error ? <ErrorNotice message={approvals.error} action={<Button onClick={approvals.reload}>Retry</Button>} /> : null}
      {requests.error ? <ErrorNotice message={requests.error} action={<Button onClick={requests.reload}>Retry</Button>} /> : null}

      <Section
        title="Pending approval queue"
        description="No bulk approval. Open one request, verify its digest and exact effect, then approve once or reject with a reason."
      >
        {approvals.loading && !approvals.data ? (
          <LoadingState label="Reading approvals" />
        ) : pending.length === 0 ? (
          <EmptyState title="No pending approvals">
            Allowed and blocked decision history remains below. Zero pending requests does not mean all
            threats were prevented.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Pending approvals</caption>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Request</th>
                  <th scope="col">Scenario</th>
                  <th scope="col">Created</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {pending.map((approval) => (
                  <tr key={approval.id}>
                    <td className="mono">{approval.tool}</td>
                    <td>
                      <span className="mono">{approval.request_id}</span>
                      <div className="row-subtitle mono">{approval.id}</div>
                    </td>
                    <td>{approval.scenario_key}</td>
                    <td className="nowrap">{formatTimestamp(approval.created_at, zone)}</td>
                    <td className="nowrap">{formatTimestamp(approval.expires_at, zone)}</td>
                    <td>
                      <LinkButton size="sm" to={`/policies/approvals/${approval.id}`}>
                        Review request
                      </LinkButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title="Policy presets"
        description="Readable, versioned server presets. There is no user-defined rule builder in this MVP."
      >
        {policies.loading && !policies.data ? (
          <LoadingState label="Reading policy registry" />
        ) : policies.error && !policies.data ? (
          <ErrorNotice message={policies.error} />
        ) : (
          <>
            <div className="preset-grid">
              {policies.data?.presets.map((preset) => (
                <article className="preset" key={preset.id}>
                  <div className="preset__head">
                    <h3>{preset.name}</h3>
                    <StatusBadge status={preset.mode} />
                  </div>
                  <p className="mono small">{preset.id} · version {preset.version}</p>
                  <p className="small">{preset.description}</p>
                  <p className="small muted">Created {formatTimestamp(preset.created_at, zone)}</p>
                </article>
              ))}
            </div>
            <p className="small muted policy-note">{policies.data?.note}</p>
          </>
        )}
      </Section>

      <Section title="Tool registry" description="Only these exact tools and allowlisted arguments reach execution.">
        {policies.data ? (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Trusted tool registry</caption>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Schema</th>
                  <th scope="col">Allowed arguments</th>
                  <th scope="col">Effect</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {policies.data.tools.map((tool) => (
                  <tr key={tool.name}>
                    <td>
                      <span className="mono">{tool.name}</span>
                      <div className="row-subtitle">{tool.description}</div>
                    </td>
                    <td className="mono">{tool.schema_version}</td>
                    <td>
                      <div className="stack stack--tight">
                        {Object.entries(tool.allowed_args).map(([key, values]) => (
                          <div key={key}>
                            <span className="mono">{key}</span> ={" "}
                            <span className="mono small">{values.join(" | ")}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                    <td className="prose-cell small">{tool.effect}</td>
                    <td>
                      {tool.always_blocked ? <StatusBadge status="BLOCK" explicit="danger" /> : <StatusBadge status="ALLOW" explicit="success" />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <LoadingState label="Reading tool registry" />
        )}
      </Section>

      <Section
        title="Approval history"
        description="Consumed, rejected, expired, and invalidated decisions remain visible. Consumption is not execution success by itself."
      >
        {history.length === 0 ? (
          <EmptyState title="No approval history in this dataset" />
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Approval decision history</caption>
              <thead>
                <tr>
                  <th scope="col">State</th>
                  <th scope="col">Tool</th>
                  <th scope="col">Request</th>
                  <th scope="col">Decided</th>
                  <th scope="col">Decision reason</th>
                  <th scope="col">Request status</th>
                </tr>
              </thead>
              <tbody>
                {history.map((approval) => (
                  <tr key={approval.id}>
                    <td>
                      <StatusBadge status={approval.expired && approval.state === "PENDING" ? "EXPIRED" : approval.state} />
                    </td>
                    <td className="mono">{approval.tool}</td>
                    <td>
                      <Link className="mono" to={`/policies/approvals/${approval.id}`}>
                        {approval.id}
                      </Link>
                    </td>
                    <td className="nowrap">{formatTimestamp(approval.decided_at, zone)}</td>
                    <td className="prose-cell small">{approval.reason ?? "No reason recorded."}</td>
                    <td>
                      <StatusBadge status={approval.request_status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title="Request decision history"
        description="Every proposal records its own policy version, request digest, resource hash, and execution state."
        id="requests"
        actions={
          <div className="filter-bar filter-bar--inline">
            <label>
              <span>Decision</span>
              <select value={decision} onChange={(event) => setDecision(event.target.value)}>
                <option value="">All decisions</option>
                <option value="ALLOW">Allow</option>
                <option value="BLOCK">Block</option>
                <option value="REQUIRE_APPROVAL">Require approval</option>
              </select>
            </label>
          </div>
        }
      >
        {requests.loading && !requests.data ? (
          <LoadingState label="Reading tool requests" />
        ) : filteredRequests.length === 0 ? (
          <EmptyState title={decision ? `No ${decision.replaceAll("_", " ").toLowerCase()} requests` : "No tool requests recorded"}>
            Start a scripted run from Agent traces to produce a proposal and policy decision.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Tool requests and policy decisions</caption>
              <thead>
                <tr>
                  <th scope="col">Decision</th>
                  <th scope="col">Tool</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Status</th>
                  <th scope="col">Execution</th>
                  <th scope="col">Recorded</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {filteredRequests.map((request) => (
                  <tr key={request.id}>
                    <td>
                      <StatusBadge status={request.decision} />
                    </td>
                    <td>
                      <span className="mono">{request.tool}</span>
                      <div className="row-subtitle mono">{request.id}</div>
                    </td>
                    <td className="prose-cell small">
                      <span className="mono">{request.decision_reason_code}</span>
                      <div>{request.decision_reason}</div>
                    </td>
                    <td>
                      <StatusBadge status={request.status} />
                    </td>
                    <td>
                      <StatusBadge status={request.execution_status} />
                    </td>
                    <td className="nowrap">{formatTimestamp(request.created_at, zone)}</td>
                    <td>
                      <Button size="sm" variant="quiet" onClick={() => setSelectedRequest(request.id)}>
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="table-caption">{plural(filteredRequests.length, "request")} in this filter.</p>
          </div>
        )}

        {inspected ? (
          <div className="inspector">
            <div className="inspector__head">
              <div>
                <p className="eyebrow">Request inspector</p>
                <h3 className="mono">{inspected.tool}</h3>
                <p className="mono small">{inspected.id}</p>
              </div>
              <div className="button-group">
                <StatusBadge status={inspected.decision} />
                <Button size="sm" variant="quiet" onClick={() => setSelectedRequest(null)}>
                  Close
                </Button>
              </div>
            </div>
            <div className="inspector__grid">
              <div>
                <h4>Exact arguments</h4>
                <CodeBlock>{JSON.stringify(inspected.arguments, null, 2)}</CodeBlock>
                <h4>Effect</h4>
                <p className="small">{inspected.effect}</p>
              </div>
              <div>
                <Definition
                  columns={1}
                  items={[
                    { term: "Request digest", description: <Hash value={inspected.request_digest} /> },
                    { term: "Resource hash", description: <Hash value={inspected.resource_hash} /> },
                    { term: "Policy", description: `${inspected.policy_preset_id} v${inspected.policy_version} (${inspected.mode})` },
                    { term: "Approval", description: inspected.approval_id ? <Link className="mono" to={`/policies/approvals/${inspected.approval_id}`}>{inspected.approval_id}</Link> : "not required" },
                    { term: "Result hash", description: inspected.result_hash ?? "no execution result" },
                  ]}
                />
                {inspected.approval_id ? (
                  <LinkButton to={`/policies/approvals/${inspected.approval_id}`} size="sm">
                    Open approval
                  </LinkButton>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}
      </Section>
    </>
  );
}
