import { Link, useParams } from "react-router-dom";
import type { FindingDetail } from "../api/types";
import {
  Button,
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
import { formatTimestamp } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

function EvidenceTable({ finding }: { finding: FindingDetail }) {
  const { zone } = useWorkspace();
  if (finding.evidence.length === 0) {
    return (
      <EmptyState title="This result has no supporting evidence">
        An insufficiency verdict can still be recorded. A supported-violation verdict requires evidence.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Evidence supporting this finding</caption>
        <thead>
          <tr>
            <th scope="col">Source / line</th>
            <th scope="col">Type</th>
            <th scope="col">Time</th>
            <th scope="col">Actor hint</th>
            <th scope="col">Action / resource</th>
            <th scope="col">Integrity</th>
          </tr>
        </thead>
        <tbody>
          {finding.evidence.map((item) => (
            <tr key={item.event_id}>
              <td>
                <Link className="mono" to={`/investigations/evidence/${item.event_id}`}>
                  {item.ref}
                </Link>
                {item.role ? <div className="row-subtitle">role: {item.role}</div> : null}
              </td>
              <td>{item.event_type}</td>
              <td>
                {item.ts_utc ? (
                  formatTimestamp(item.ts_utc, zone)
                ) : (
                  <span className="text-warning">time unavailable</span>
                )}
                {item.original_ts ? <div className="row-subtitle mono">{item.original_ts}</div> : null}
              </td>
              <td>{item.actor_hint ?? <span className="muted">unknown</span>}</td>
              <td>
                {item.action ?? "—"}
                {item.resource ? <div className="row-subtitle mono">{item.resource}</div> : null}
                {item.src_ip || item.dst_ip ? (
                  <div className="row-subtitle mono">
                    {item.src_ip ?? "?"} → {item.dst_ip ?? "?"}
                  </div>
                ) : null}
              </td>
              <td>
                <StatusBadge status={item.integrity} />
                {item.integrity_message ? (
                  <div className="row-subtitle text-danger">{item.integrity_message}</div>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function FindingPage() {
  const { findingId } = useParams<{ findingId: string }>();
  const finding = useApi<FindingDetail>(findingId ? `/findings/${findingId}` : null);
  const { zone } = useWorkspace();
  const data = finding.data;

  if (finding.loading && !data) {
    return (
      <>
        <PageHeader title="Finding" eyebrow="Investigations / finding" />
        <LoadingState label="Reading finding and evidence" />
      </>
    );
  }
  if (finding.error && !data) {
    return (
      <>
        <PageHeader title="Finding" eyebrow="Investigations / finding" />
        <ErrorNotice message={finding.error} action={<Button onClick={finding.reload}>Retry</Button>} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Finding" eyebrow="Investigations / finding" />
        <EmptyState title="Finding not found" action={<LinkButton to="/investigations">Back to review queue</LinkButton>} />
      </>
    );
  }

  return (
    <>
      <div className="breadcrumb">
        <Link to="/investigations?tab=findings">Investigations</Link>
        <span aria-hidden="true">/</span>
        <span>Finding</span>
      </div>
      <PageHeader
        eyebrow={`${data.agent_label} · rule ${data.rules_version}`}
        title={data.title}
        description={data.interpretation}
        actions={
          <div className="button-group">
            <LinkButton to="/investigations?tab=findings" variant="primary">
              Create investigation in queue
            </LinkButton>
            <LastUpdated at={finding.refreshedAt} refreshing={finding.refreshing} onRefresh={finding.reload} />
          </div>
        }
      />

      {finding.error ? <ErrorNotice message={finding.error} /> : null}
      {data.evidence_integrity !== "valid" ? (
        <Notice tone="danger" title="Evidence integrity failed">
          At least one referenced record does not match its immutable source snapshot. Supported-violation
          verdicts that cite it will be rejected by the server.
        </Notice>
      ) : null}

      <div className="detail-grid">
        <div className="stack">
          <Section title="Observed facts" description="Statements tied to captured event IDs, not inferred intent.">
            {data.observed_facts.length === 0 ? (
              <EmptyState title="No observed facts recorded" />
            ) : (
              <ul className="fact-list">
                {data.observed_facts.map((fact, index) => (
                  <li key={index}>
                    <p>{fact.text}</p>
                    <p className="mono small muted">{fact.event_ids.join(" · ")}</p>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Evidence" description="Every row resolves to an immutable captured source snapshot.">
            <EvidenceTable finding={data} />
          </Section>

          <Section title="Timeline" description="UTC-normalized events only. Events without a usable time are listed separately.">
            {data.timeline.length === 0 ? (
              <EmptyState title="No ordered timeline available" />
            ) : (
              <ol className="timeline">
                {data.timeline.map((item) => (
                  <li key={item.event_id} className="timeline__item">
                    <div className="timeline__time mono">{formatTimestamp(item.ts_utc, zone)}</div>
                    <div className="timeline__marker" aria-hidden="true" />
                    <div className="timeline__body">
                      <div className="timeline__head">
                        <Link className="mono" to={`/investigations/evidence/${item.event_id}`}>
                          {item.ref}
                        </Link>
                        <span className="muted">{item.event_type}</span>
                        <StatusBadge status={item.integrity} />
                      </div>
                      <p>
                        {item.actor_hint ?? "unknown actor hint"}
                        {item.action ? ` · ${item.action}` : ""}
                        {item.resource ? ` · ${item.resource}` : ""}
                      </p>
                      {item.src_ip || item.dst_ip ? (
                        <p className="mono small">
                          {item.src_ip ?? "?"} → {item.dst_ip ?? "?"}
                        </p>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ol>
            )}
            {data.time_unavailable.length > 0 ? (
              <div className="subsection">
                <h3>Time unavailable</h3>
                <ul className="compact-list">
                  {data.time_unavailable.map((item) => (
                    <li key={item.event_id}>
                      <Link className="mono" to={`/investigations/evidence/${item.event_id}`}>
                        {item.ref}
                      </Link>{" "}
                      <span className="muted">{item.integrity_message ?? "No normalized timestamp"}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </Section>

          <Section
            title="Correlation"
            description="Explainable joins only. A shared IP does not prove process or agent ownership."
          >
            {data.correlation_edges.length === 0 ? (
              <EmptyState title="No cross-source correlation edges" />
            ) : (
              <div className="stack stack--tight">
                {data.correlation_edges.map((edge) => (
                  <article className="correlation" key={edge.id}>
                    <div className="correlation__head">
                      <strong>{edge.join_type.replaceAll("_", " ")}</strong>
                      <span className="muted">
                        {edge.time_delta_seconds === null
                          ? "time delta unavailable"
                          : `${edge.time_delta_seconds}s apart`}
                      </span>
                    </div>
                    <div className="correlation__rows">
                      <div>
                        <Link className="mono" to={`/investigations/evidence/${edge.left.event_id}`}>
                          {edge.left.ref}
                        </Link>
                        <p className="small">{edge.left.action ?? edge.left.event_type}</p>
                      </div>
                      <span aria-hidden="true" className="correlation__arrow">
                        ↔
                      </span>
                      <div>
                        <Link className="mono" to={`/investigations/evidence/${edge.right.event_id}`}>
                          {edge.right.ref}
                        </Link>
                        <p className="small">{edge.right.action ?? edge.right.event_type}</p>
                      </div>
                    </div>
                    <p className="small">
                      <strong>Join fields:</strong>{" "}
                      <span className="mono">{JSON.stringify(edge.join_fields)}</span>
                    </p>
                    <p className="small text-warning">{edge.limitation}</p>
                  </article>
                ))}
              </div>
            )}
          </Section>
        </div>

        <div className="stack">
          <Section title="Assessment">
            <div className="badge-line">
              <StatusBadge status={data.disposition} />
              <span className="priority">Priority {data.priority_score}</span>
            </div>
            <Definition
              columns={1}
              items={[
                { term: "Agent", description: data.agent_label },
                { term: "Detection run", description: data.detection_run_id, mono: true },
                { term: "Finding ID", description: data.id, mono: true },
                { term: "Rules version", description: data.rules_version, mono: true },
                { term: "Recorded", description: formatTimestamp(data.created_at, zone) },
                { term: "Dataset", description: data.dataset_name },
              ]}
            />
            <p className="small">
              Priority is an explainable rule ranking, not a probability or live risk score.
            </p>
          </Section>

          <Section title="Why this disposition">
            <p className="small">{data.confidence_rationale}</p>
            <h3>Supporting</h3>
            {data.supporting.length === 0 ? (
              <p className="muted small">None recorded.</p>
            ) : (
              <ul className="compact-list">
                {data.supporting.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
            <h3>Contradicting</h3>
            {data.contradicting.length === 0 ? (
              <p className="muted small">None recorded.</p>
            ) : (
              <ul className="compact-list">
                {data.contradicting.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
            <h3>Unknowns</h3>
            {data.unknowns.length === 0 ? (
              <p className="muted small">None recorded.</p>
            ) : (
              <ul className="compact-list">
                {data.unknowns.map((item) => (
                  <li key={item} className="text-warning">
                    {item}
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Next step" description="Investigation guidance, not an automatic action.">
            <p className="small">{data.next_step}</p>
          </Section>

          <Section title="Limitations">
            <p className="small">{data.limitations}</p>
            <p className="small muted">
              This synthetic finding does not prove malicious intent, agent identity, or a successful
              compromise.
            </p>
          </Section>

          <Section title="Record hashes">
            <div className="stack stack--tight">
              {data.evidence.slice(0, 4).map((item) => (
                <div key={item.event_id}>
                  <p className="small mono">{item.ref}</p>
                  <Hash value={item.raw_sha256} label="raw" />
                  <Hash value={item.source_sha256} label="source" />
                </div>
              ))}
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}
