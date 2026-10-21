import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, apiRequest, errorMessage, newIdempotencyKey } from "../api/client";
import type { Approval, ToolRequest } from "../api/types";
import {
  Button,
  CodeBlock,
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

interface DecisionResponse {
  approval_id: string;
  decision: "approve" | "reject";
  request: ToolRequest;
  committed: boolean;
}

export function ApprovalDetailPage() {
  const { approvalId } = useParams<{ approvalId: string }>();
  const approval = useApi<Approval>(approvalId ? `/approvals/${approvalId}` : null);
  const { zone, audit } = useWorkspace();
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [reason, setReason] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<unknown>(null);
  const [result, setResult] = useState<DecisionResponse | null>(null);

  const data = approval.data;
  const request = data?.request ?? data?.detail ?? null;
  const pending = data?.state === "PENDING" && !data.expired;
  const mutationBlocked = audit ? !audit.safe_for_mutations : false;

  useEffect(() => {
    // A new decision body needs a new idempotency key. An unchanged retry
    // after a lost response keeps the previous key and returns the stored outcome.
    setIdempotencyKey(null);
  }, [decision, reason]);

  useEffect(() => {
    setReviewed(false);
    setReason("");
    setResult(null);
    setSubmitError(null);
    setIdempotencyKey(null);
  }, [approvalId]);

  if (approval.loading && !data) {
    return (
      <>
        <PageHeader title="Approval" eyebrow="Policy & approvals" />
        <LoadingState label="Reading immutable approval request" />
      </>
    );
  }
  if (approval.error && !data) {
    return (
      <>
        <PageHeader title="Approval" eyebrow="Policy & approvals" />
        <ErrorNotice message={approval.error} action={<Button onClick={approval.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data || !request) {
    return (
      <>
        <PageHeader title="Approval" eyebrow="Policy & approvals" />
        <EmptyState title="Approval not found" action={<LinkButton to="/policies">Back to policy queue</LinkButton>} />
      </>
    );
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!approvalId || !reviewed || !reason.trim()) return;
    const key = idempotencyKey ?? newIdempotencyKey();
    setIdempotencyKey(key);
    setSubmitting(true);
    setSubmitError(null);
    try {
      const response = await apiRequest<DecisionResponse>(`/approvals/${approvalId}/decision`, {
        method: "POST",
        headers: { "Idempotency-Key": key },
        body: {
          decision,
          reviewed_request_digest: request.request_digest,
          expected_version: data.expected_version,
          reason: reason.trim(),
        },
      });
      setResult(response);
      setReviewed(false);
      setReason("");
      approval.reload();
    } catch (cause) {
      setSubmitError(cause);
      if (cause instanceof ApiError && cause.status === 409) {
        approval.reload();
      }
    } finally {
      setSubmitting(false);
    }
  };

  const conflict = submitError instanceof ApiError && submitError.status === 409 ? submitError : null;

  return (
    <>
      <div className="breadcrumb">
        <Link to="/policies">Policy &amp; approvals</Link>
        <span aria-hidden="true">/</span>
        <span className="mono">{data.id}</span>
      </div>
      <PageHeader
        eyebrow={`${data.scenario_key} · ${data.tool}`}
        title="Review one exact request"
        description="Approval authorizes exactly one immutable request, once. It is not a claim that execution succeeded or that the underlying finding is malicious."
        actions={
          <div className="button-group">
            <StatusBadge status={data.expired && data.state === "PENDING" ? "EXPIRED" : data.state} />
            <StatusBadge status={request.execution_status} />
            <LastUpdated at={approval.refreshedAt} refreshing={approval.refreshing} onRefresh={approval.reload} />
          </div>
        }
      />

      {approval.error ? <ErrorNotice message={approval.error} /> : null}
      {result ? (
        <Notice tone="success" title={`${result.decision === "approve" ? "Approved once" : "Rejected"} · committed`}>
          <p>
            {result.decision === "approve"
              ? "The single local synthetic effect committed. This confirms the recorded approval path, not real-world delivery."
              : "The request was rejected without creating an effect."}
          </p>
          <p className="small">
            Request status <span className="mono">{result.request.status}</span>, execution{" "}
            <span className="mono">{result.request.execution_status}</span>.{" "}
            <Link to={`/traces/${data.run_id}`}>Open the run trace</Link>.
          </p>
        </Notice>
      ) : null}
      {conflict ? (
        <Notice tone="danger" title="Decision did not commit">
          <p>{conflict.message}</p>
          <p className="small">
            Current server state has been reloaded. No forced override is offered. If the approval was
            consumed or expired, submit a new request from a new run.
          </p>
        </Notice>
      ) : submitError ? (
        <ErrorNotice
          message={errorMessage(submitError)}
          code={submitError instanceof ApiError ? submitError.code : null}
          requestId={submitError instanceof ApiError ? submitError.requestId : null}
          action={
            <span className="small">
              If the response was lost, verify current state before retrying. An unchanged retry reuses the
              idempotency key.
            </span>
          }
        />
      ) : null}
      {mutationBlocked ? (
        <Notice tone="danger" title="Audit health blocks decisions">
          Approval cannot be committed while the server considers the audit chain unsafe. Diagnosis remains
          available.
        </Notice>
      ) : null}
      {!pending && !result ? (
        <Notice tone="warning" title="This approval is not actionable">
          State is <span className="mono">{data.state}</span> and request status is{" "}
          <span className="mono">{request.status}</span>.{" "}
          {data.expired ? "Approval expired; submit a new request." : "No second decision is accepted."}
        </Notice>
      ) : null}

      <div className="detail-grid approval-layout">
        <div className="stack">
          <Section title="Requested effect" description="This is the only effect that a positive decision authorizes.">
            <div className="effect-box">
              <p className="effect-box__tool mono">{request.tool}</p>
              <p>{request.effect}</p>
              <p className="small muted">
                Execution adapter: local synthetic only. No network request, outbox file, shell command, or
                secret read exists for this tool.
              </p>
            </div>
            <h3>Exact arguments</h3>
            <CodeBlock>{JSON.stringify(request.arguments, null, 2)}</CodeBlock>
            <div className="table-wrap request-facts">
              <table>
                <caption className="sr-only">Immutable request facts</caption>
                <thead>
                  <tr>
                    <th scope="col">Property</th>
                    <th scope="col">Recorded value</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <th scope="row">Tool / schema</th>
                    <td className="mono">{request.tool} · {request.tool_schema_version}</td>
                  </tr>
                  <tr>
                    <th scope="row">Resource reference</th>
                    <td className="mono">{request.resource_ref}</td>
                  </tr>
                  <tr>
                    <th scope="row">Resource version hash</th>
                    <td><Hash value={request.resource_hash} /></td>
                  </tr>
                  <tr>
                    <th scope="row">Policy</th>
                    <td>
                      {request.policy_preset_id} v{request.policy_version} · mode {request.mode}
                      <div className="row-subtitle">{request.decision_reason_code}</div>
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Policy reason</th>
                    <td>{request.decision_reason}</td>
                  </tr>
                  <tr>
                    <th scope="row">Request digest</th>
                    <td><Hash value={request.request_digest} /></td>
                  </tr>
                  <tr>
                    <th scope="row">Expected approval version</th>
                    <td className="mono">{data.expected_version}</td>
                  </tr>
                  <tr>
                    <th scope="row">Created / expires</th>
                    <td>
                      {formatTimestamp(data.created_at, zone)}
                      <div className="row-subtitle">{formatTimestamp(data.expires_at, zone)}</div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </Section>

          <Section title="Decision" description="Approval is bound to this local operator session, exact digest, expected version, and expiry.">
            {pending ? (
              <form className="form-grid" onSubmit={submit}>
                <fieldset className="fieldset form-grid__full">
                  <legend>Decision</legend>
                  <div className="radio-row">
                    <label className="radio-card">
                      <input
                        type="radio"
                        name="decision"
                        value="approve"
                        checked={decision === "approve"}
                        onChange={() => setDecision("approve")}
                      />
                      <span>
                        <strong>Approve once</strong>
                        <span className="small">
                          Commit one synthetic local effect. The approval is consumed transactionally.
                        </span>
                      </span>
                    </label>
                    <label className="radio-card">
                      <input
                        type="radio"
                        name="decision"
                        value="reject"
                        checked={decision === "reject"}
                        onChange={() => setDecision("reject")}
                      />
                      <span>
                        <strong>Reject</strong>
                        <span className="small">
                          Record the rejection with no execution. This is terminal for this request.
                        </span>
                      </span>
                    </label>
                  </div>
                </fieldset>
                <Field
                  label="Decision reason"
                  htmlFor="decision-reason"
                  hint="Required. This is stored with the decision and its hash is written to the audit record."
                >
                  <textarea
                    id="decision-reason"
                    rows={3}
                    maxLength={500}
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    required
                  />
                </Field>
                <div className="form-grid__full">
                  <label className="checkbox-row">
                    <input
                      type="checkbox"
                      checked={reviewed}
                      onChange={(event) => setReviewed(event.target.checked)}
                    />
                    <span>
                      I reviewed the exact arguments, effect, request digest{" "}
                      <span className="mono">{request.request_digest.slice(0, 12)}…</span>, policy version, and
                      expiry shown above.
                    </span>
                  </label>
                </div>
                <div className="form-actions form-grid__full">
                  <Button
                    type="submit"
                    variant={decision === "approve" ? "primary" : "danger"}
                    disabled={submitting || !reviewed || !reason.trim() || mutationBlocked}
                  >
                    {submitting
                      ? "Committing decision…"
                      : decision === "approve"
                        ? "Approve once and execute"
                        : "Reject request"}
                  </Button>
                  <span className="small muted">
                    Duplicate submission is locally disabled; the server independently enforces idempotency
                    and single-use state.
                  </span>
                </div>
              </form>
            ) : (
              <Definition
                columns={1}
                items={[
                  { term: "Approval state", description: <StatusBadge status={data.state} /> },
                  { term: "Request status", description: <StatusBadge status={request.status} /> },
                  { term: "Execution", description: <StatusBadge status={request.execution_status} /> },
                  { term: "Decided at", description: formatTimestamp(data.decided_at, zone) },
                  { term: "Decided by", description: data.decided_by ?? "not decided", mono: true },
                  { term: "Recorded reason", description: data.reason ?? "No reason recorded." },
                ]}
              />
            )}
          </Section>

          {request.result ? (
            <Section title="Recorded execution result" description="Stored after the decision commits. Approval state alone is not execution success.">
              <CodeBlock>{JSON.stringify(request.result, null, 2)}</CodeBlock>
              {request.receipt_id ? (
                <p className="small">
                  Local synthetic receipt <span className="mono">{request.receipt_id}</span>. No external
                  delivery occurred.
                </p>
              ) : null}
            </Section>
          ) : null}
        </div>

        <div className="stack">
          <Section title="Decision scope">
            <Definition
              columns={1}
              items={[
                { term: "Approval ID", description: data.id, mono: true },
                { term: "Request ID", description: data.request_id, mono: true },
                { term: "Run ID", description: data.run_id, mono: true },
                { term: "Scenario", description: data.scenario_key },
                { term: "Bound session", description: data.session_id, mono: true },
                { term: "Session scope", description: "local operator; identity not verified" },
                { term: "State", description: <StatusBadge status={data.state} /> },
                { term: "Expires", description: formatTimestamp(data.expires_at, zone) },
              ]}
            />
          </Section>

          <Notice tone="info" title="What approval does not mean">
            It does not prove the requested action is safe, that the finding is malicious, that a human
            identity was verified, or that any external case or system received data.
          </Notice>

          <Section title="Linked records">
            <div className="stack stack--tight">
              <Link className="text-link" to={`/traces/${data.run_id}`}>
                Open the agent run and trace
              </Link>
              <Link className="text-link" to="/policies#requests">
                Inspect all policy decisions
              </Link>
              <Link className="text-link" to="/audit">
                Verify the audit record
              </Link>
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}
