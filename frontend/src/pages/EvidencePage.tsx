import { Link, useNavigate, useParams } from "react-router-dom";
import type { EvidenceDetail } from "../api/types";
import {
  Button,
  CodeBlock,
  CopyButton,
  Definition,
  ErrorNotice,
  Hash,
  LastUpdated,
  LoadingState,
  Notice,
  PageHeader,
  Section,
  StatusBadge,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { formatTimestamp } from "../lib/format";
import { useWorkspace } from "../state/WorkspaceContext";

export function EvidencePage() {
  const { eventId } = useParams<{ eventId: string }>();
  const evidence = useApi<EvidenceDetail>(eventId ? `/events/${eventId}` : null);
  const { zone } = useWorkspace();
  const navigate = useNavigate();
  const data = evidence.data;

  if (evidence.loading && !data) {
    return (
      <>
        <PageHeader title="Evidence" eyebrow="Captured source record" />
        <LoadingState label="Resolving immutable evidence" />
      </>
    );
  }
  if (evidence.error && !data) {
    return (
      <>
        <PageHeader title="Evidence" eyebrow="Captured source record" />
        <ErrorNotice
          message={evidence.error}
          action={<Button onClick={evidence.reload}>Retry</Button>}
        />
        <Notice tone="warning" title="Evidence unavailable or changed">
          A missing or hash-mismatched record cannot support a new supported-violation verdict. It is not
          silently replaced with mutable source content.
        </Notice>
      </>
    );
  }
  if (!data) {
    return <ErrorNotice message="Evidence not found." />;
  }

  return (
    <>
      <div className="breadcrumb">
        <button type="button" className="link-button" onClick={() => navigate(-1)}>
          Back
        </button>
        <span aria-hidden="true">/</span>
        <span>Evidence</span>
      </div>
      <PageHeader
        eyebrow={`${data.dataset_name} · ${data.scenario_key}`}
        title={data.ref}
        description={
          <>
            Captured <strong>{data.event_type}</strong> record resolved from an immutable source snapshot.
            Integrity is rechecked on every read.
          </>
        }
        actions={
          <div className="button-group">
            <StatusBadge status={data.integrity} />
            <LastUpdated at={evidence.refreshedAt} refreshing={evidence.refreshing} onRefresh={evidence.reload} />
          </div>
        }
      />

      {evidence.error ? <ErrorNotice message={evidence.error} /> : null}

      <div className="detail-grid detail-grid--evidence">
        <div className="stack">
          <Section title="Captured record" description="Inert JSON text. It is not executed or rendered as instructions.">
            <CodeBlock label={`${data.source_filename}, line ${data.line}`}>
              {JSON.stringify(data.raw, null, 2)}
            </CodeBlock>
            <div className="button-row">
              <CopyButton value={JSON.stringify(data.raw, null, 2)} label="Copy raw JSON" />
              <CopyButton value={data.raw_sha256} label="Copy record SHA-256" />
            </div>
          </Section>

          <Section title="Source context" description={`Lines ${data.context[0]?.line ?? "?"}–${data.context[data.context.length - 1]?.line ?? "?"} of ${data.source_filename}.`}>
            <div className="source-context" role="table" aria-label="Captured source context">
              {data.context.map((line) => {
                const current = line.line === data.line;
                return (
                  <div
                    className={current ? "source-context__line source-context__line--current" : "source-context__line"}
                    role="row"
                    key={line.line}
                  >
                    <span className="source-context__number" role="cell">
                      {line.line}
                    </span>
                    <span className="source-context__text" role="cell">
                      {line.text}
                    </span>
                    {current ? <span className="source-context__marker">captured line</span> : null}
                  </div>
                );
              })}
            </div>
            <p className="small muted">
              The source snapshot is stored with the import. Later edits on disk do not alter this record.
            </p>
          </Section>
        </div>

        <div className="stack">
          <Section title="Provenance">
            <Definition
              columns={1}
              items={[
                { term: "Event type", description: data.event_type },
                { term: "URL reference", description: data.ref, mono: true },
                { term: "Normalized time (UTC)", description: formatTimestamp(data.ts_utc, zone) },
                { term: "Original timestamp", description: data.original_ts ?? "not recorded", mono: true },
                { term: "Parse status", description: data.parse_status },
                { term: "Parser version", description: data.parser_version, mono: true },
                { term: "Actor hint", description: data.actor_hint ?? "unknown" },
                { term: "Source IP", description: data.src_ip ?? "not recorded", mono: true },
                { term: "Destination IP", description: data.dst_ip ?? "not recorded", mono: true },
                { term: "UID", description: data.uid ?? "not recorded", mono: true },
                { term: "Action", description: data.action ?? "not recorded" },
                { term: "Resource", description: data.resource ?? "not recorded" },
              ]}
            />
          </Section>

          <Section title="Hashes and scope">
            <div className="stack stack--tight">
              <Hash value={data.raw_sha256} label="Record SHA-256" />
              <Hash value={data.source_sha256} label="Source SHA-256" />
              <div className="small muted">
                Dataset <span className="mono">{data.dataset_id}</span>, source{" "}
                <span className="mono">{data.source_id}</span>
              </div>
            </div>
          </Section>

          <Notice tone="warning" title="Attribution boundary">
            An IP address, shared host, or record reference does not prove which process or agent produced
            this action. Treat actor hints as hints.
          </Notice>

          <Section title="Continue">
            <div className="stack stack--tight">
              <Link className="text-link" to="/investigations?tab=findings">
                Return to the finding queue
              </Link>
              <Link className="text-link" to="/traces">
                Inspect agent tool proposals
              </Link>
            </div>
          </Section>
        </div>
      </div>
    </>
  );
}
