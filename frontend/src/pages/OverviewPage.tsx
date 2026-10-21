import { useState } from "react";
import { Link } from "react-router-dom";
import type { Overview } from "../api/types";
import { errorMessage } from "../api/client";
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
import { formatTimestamp, shortHash } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

export function OverviewPage() {
  const { activeDatasetId, importSample, importingSample, zone, refresh } = useWorkspace();
  const path = activeDatasetId ? `/overview?dataset_id=${encodeURIComponent(activeDatasetId)}` : "/overview";
  const overview = useApi<Overview>(path);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const data = overview.data;

  const loadSample = async () => {
    setActionError(null);
    setActionMessage(null);
    try {
      await importSample();
      setActionMessage("Synthetic dataset imported. Detection ran against the captured evidence.");
      refresh();
    } catch (cause) {
      setActionError(errorMessage(cause));
    }
  };

  if (overview.loading && !data) {
    return (
      <>
        <PageHeader title="Overview" eyebrow="Dataset posture" />
        <LoadingState label="Reading dataset posture" />
      </>
    );
  }

  if (overview.error && !data) {
    return (
      <>
        <PageHeader title="Overview" eyebrow="Dataset posture" />
        <ErrorNotice message={overview.error} action={<Button onClick={overview.reload}>Try again</Button>} />
      </>
    );
  }

  if (!data || data.empty) {
    return (
      <>
        <PageHeader
          eyebrow="Dataset posture"
          title="Overview"
          description="What needs attention in this synthetic dataset, and can the current investigation state be trusted?"
        />
        <Section>
          <EmptyState
            title="No dataset loaded"
            action={
              <Button onClick={loadSample} variant="primary" disabled={importingSample}>
                {importingSample ? "Importing…" : "Load the synthetic shared-host scenario"}
              </Button>
            }
          >
            <p>
              The registered fixture contains Zeek, Suricata, Windows event, and agent-action records.
              Importing runs bounded parsing and rule-based detection. No external data is fetched.
            </p>
            {actionError ? <p className="text-danger">{actionError}</p> : null}
            {actionMessage ? <p>{actionMessage}</p> : null}
          </EmptyState>
        </Section>
        {data?.audit_summary ? (
          <Section title="Audit state" description="No positive completeness claim is made for an empty chain.">
            <div className="inline-state">
              <StatusBadge status={data.audit_summary.integrity} />
              <StatusBadge status={data.audit_summary.completeness} />
              <span className="muted">{data.audit_summary.message}</span>
            </div>
          </Section>
        ) : null}
      </>
    );
  }

  const findingCounts = data.finding_counts ?? { REVIEW: 0, LOW: 0, UNKNOWN: 0 };
  const investigationCounts = data.investigation_counts ?? { OPEN: 0, REVIEWED: 0, CLOSED: 0 };
  const caseCounts = data.case_counts ?? { OPEN: 0, CLOSED: 0 };
  const policyCounts = data.policy_counts ?? { ALLOW: 0, BLOCK: 0, REQUIRE_APPROVAL: 0 };
  const pending = data.pending_approvals ?? [];
  const audit = data.audit_summary;

  return (
    <>
      <PageHeader
        eyebrow="Dataset posture"
        title="Overview"
        description={
          <>
            What needs attention in <strong>{data.scope.dataset_name}</strong>, and what do the recorded
            controls support? Counts are scoped to this dataset only.
          </>
        }
        actions={<LastUpdated at={overview.refreshedAt} refreshing={overview.refreshing} />}
      />

      {overview.error ? <ErrorNotice message={overview.error} action={<Button onClick={overview.reload}>Retry</Button>} /> : null}
      {actionError ? <ErrorNotice message={actionError} /> : null}
      {actionMessage ? <Notice tone="success">{actionMessage}</Notice> : null}

      {!audit?.safe_for_mutations ? (
        <Notice tone="danger" title="Audit verification blocks state changes">
          The queues remain visible for diagnosis, but mutations are disabled by the server.{" "}
          <Link to="/audit">Inspect the audit record</Link>.
        </Notice>
      ) : null}

      <div className="signal-strip" aria-label="Scoped queue summary">
        <Link className="signal" to="/investigations?tab=findings&disposition=REVIEW">
          <span className="signal__label">Review findings</span>
          <span className="signal__value">{findingCounts.REVIEW}</span>
          <span className="signal__note">of {findingCounts.REVIEW + findingCounts.LOW + findingCounts.UNKNOWN} findings</span>
        </Link>
        <Link className="signal" to="/investigations?status=OPEN">
          <span className="signal__label">Open investigations</span>
          <span className="signal__value">{investigationCounts.OPEN}</span>
          <span className="signal__note">{investigationCounts.REVIEWED} reviewed · {investigationCounts.CLOSED} closed</span>
        </Link>
        <Link className="signal" to="/policies?decision=REQUIRE_APPROVAL#requests">
          <span className="signal__label">Awaiting approval</span>
          <span className="signal__value">{policyCounts.REQUIRE_APPROVAL}</span>
          <span className="signal__note">{pending.filter((item) => !item.expired).length} pending now</span>
        </Link>
        <Link className="signal" to="/audit?tab=cases&status=OPEN">
          <span className="signal__label">Open cases</span>
          <span className="signal__value">{caseCounts.OPEN}</span>
          <span className="signal__note">{caseCounts.CLOSED} closed · manual exports only</span>
        </Link>
      </div>

      <div className="overview-grid">
        <div className="stack">
          <Section
            title="Attention queue"
            description="Time-sensitive approvals, audit failures, and findings not yet linked to an investigation."
          >
            {data.attention.length === 0 ? (
              <EmptyState title="No attention items in this scope">
                No pending approvals or unlinked review findings. This is not a claim that all threats were
                prevented.
              </EmptyState>
            ) : (
              <ul className="attention-list">
                {data.attention.map((item) => (
                  <li key={`${item.kind}:${item.id}`}>
                    <Link to={item.href} className="attention-row">
                      <span className={`attention-row__kind attention-row__kind--${item.kind}`}>
                        {item.kind}
                      </span>
                      <span className="attention-row__main">
                        <span className="attention-row__title">{item.title}</span>
                        <span className="attention-row__reason">{item.reason}</span>
                      </span>
                      <span className="attention-row__time">
                        {formatTimestamp(item.recorded_at, zone)}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section
            title="Pending approvals"
            description="Pre-execution decisions bound to one immutable request digest and policy version."
          >
            {pending.length === 0 ? (
              <EmptyState title="No pending approvals">
                Denied and allowed decision history remains available under Policy &amp; approvals.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Pending approvals in the active dataset</caption>
                  <thead>
                    <tr>
                      <th scope="col">Tool</th>
                      <th scope="col">Request</th>
                      <th scope="col">Scenario</th>
                      <th scope="col">Expires</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pending.map((item) => (
                      <tr key={item.approval_id}>
                        <td className="mono">{item.tool}</td>
                        <td>
                          <Link to={`/policies/approvals/${item.approval_id}`} className="mono">
                            {item.approval_id}
                          </Link>
                        </td>
                        <td>{item.scenario_key}</td>
                        <td>{formatTimestamp(item.expires_at, zone)}</td>
                        <td>
                          <StatusBadge status={item.expired ? "EXPIRED" : "PENDING"} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          <Section
            title="Recent recorded activity"
            description="Actual audit transitions from the local HMAC chain. No synthetic live stream."
          >
            {data.recent_activity && data.recent_activity.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Recent audit activity</caption>
                  <thead>
                    <tr>
                      <th scope="col">Seq</th>
                      <th scope="col">Action</th>
                      <th scope="col">Entity</th>
                      <th scope="col">Actor</th>
                      <th scope="col">Recorded</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_activity.map((event) => (
                      <tr key={event.seq}>
                        <td className="numeric mono">{event.seq}</td>
                        <td>{event.action}</td>
                        <td>
                          <span className="muted">{event.entity_type}</span>{" "}
                          <span className="mono">{shortHash(event.entity_id, 8, 4)}</span>
                        </td>
                        <td className="mono">{event.actor}</td>
                        <td>{formatTimestamp(event.recorded_at, zone)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No audit events recorded" />
            )}
            <div className="panel__footer-link">
              <Link to="/audit">Open full audit record</Link>
            </div>
          </Section>
        </div>

        <div className="stack">
          <Section title="Audit claims" description="Integrity, completeness, and consistency are separate claims.">
            {audit ? (
              <div className="claim-list">
                <div className="claim">
                  <span className="claim__key">Integrity</span>
                  <StatusBadge status={audit.integrity} />
                  <span className="claim__note">Retained rows match the local MAC chain.</span>
                </div>
                <div className="claim">
                  <span className="claim__key">Completeness</span>
                  <StatusBadge status={audit.completeness} />
                  <span className="claim__note">Local head checkpoint comparison; not independent storage.</span>
                </div>
                <div className="claim">
                  <span className="claim__key">Consistency</span>
                  <StatusBadge status={audit.consistency} />
                  <span className="claim__note">Audit sequence and local checkpoint agreement.</span>
                </div>
                <p className="small muted">{audit.message}</p>
                <Link className="text-link" to="/audit">
                  Inspect audit events and run verification
                </Link>
              </div>
            ) : (
              <EmptyState title="Audit state unavailable" />
            )}
          </Section>

          <Section title="Source coverage" description="Captured immutable source snapshots in this dataset.">
            {data.coverage ? (
              <>
                <p className="coverage-summary">
                  <strong>{data.coverage.event_count}</strong> events across{" "}
                  <strong>{data.coverage.source_count}</strong> sources. Parser warnings are surfaced, not
                  silently discarded.
                </p>
                <div className="table-wrap">
                  <table>
                    <caption className="sr-only">Dataset source coverage</caption>
                    <thead>
                      <tr>
                        <th scope="col">Source</th>
                        <th scope="col" className="numeric">Events</th>
                        <th scope="col" className="numeric">Lines</th>
                        <th scope="col">SHA-256</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.coverage.sources.map((source) => (
                        <tr key={source.id}>
                          <td>
                            <span className="mono">{source.filename}</span>
                            {source.parse_warning ? (
                              <div className="text-warning small">Parse status: {source.parse_warning}</div>
                            ) : null}
                          </td>
                          <td className="numeric">{source.event_count}</td>
                          <td className="numeric">{source.line_count}</td>
                          <td className="mono small" title={source.sha256}>
                            {shortHash(source.sha256, 8, 4)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <EmptyState title="No source coverage recorded" />
            )}
          </Section>

          <Section title="Dataset provenance">
            <dl className="mini-definition">
              <div>
                <dt>Dataset ID</dt>
                <dd className="mono">{data.scope.dataset_id}</dd>
              </div>
              <div>
                <dt>Manifest</dt>
                <dd className="mono">{shortHash(data.scope.dataset_sha256, 14, 8)}</dd>
              </div>
              <div>
                <dt>Scenario</dt>
                <dd>{data.scope.scenario_key}</dd>
              </div>
              <div>
                <dt>Data class</dt>
                <dd>{data.scope.data_class}</dd>
              </div>
              <div>
                <dt>As of</dt>
                <dd>{formatTimestamp(data.scope.as_of, zone)}</dd>
              </div>
            </dl>
          </Section>

          <Section title="Evaluation context">
            <p className="small">
              This dataset contains four synthetic agents; only three have binary policy-outcome labels.
              Detection metrics on the Evaluation screen are functional checks, not real-world accuracy.
            </p>
            <Link className="text-link" to="/evaluation">
              Open evaluation
            </Link>
          </Section>

          <p className="disclaimer">{data.disclaimer}</p>
        </div>
      </div>
    </>
  );
}
