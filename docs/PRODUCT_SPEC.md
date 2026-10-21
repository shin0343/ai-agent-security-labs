# Agent Security Workbench product specification

Status: **implemented local MVP**, 2026-10-20. This describes the screens and interactions in the rebuilt React application. Contracts and security mechanics are in [ARCHITECTURE.md](ARCHITECTURE.md); verification is in [VALIDATION.md](VALIDATION.md).

## Product job

An analyst should be able to answer:

> What was observed, what does the evidence support, what did the agent propose, why did policy allow or stop it, who approved it, and what actually happened?

The primary user is a security analyst investigating synthetic agent behaviour in one local dataset. A secondary audience is an engineering reviewer checking whether the security and reproducibility claims hold. The product is not a collection of lab pages, a live SOC, an autonomous response tool or a multi-user collaboration platform.

## Information architecture

Persistent primary navigation, in order:

1. **Overview**
2. **Investigations**
3. **Agent traces**
4. **Policy & approvals**
5. **Evaluation**
6. **Audit & cases**

Detail routes:

- `/investigations/findings/:findingId`
- `/investigations/evidence/:eventId`
- `/investigations/:investigationId`
- `/traces/:runId`
- `/policies/approvals/:approvalId`
- `/evaluation/:evaluationId`
- `/audit/cases/:caseId`

`/cases` redirects to `/audit?tab=cases`. Unknown routes show a not-found screen inside the shell.

The header shows the active dataset/scenario, **Synthetic data**, runtime, UTC/local toggle and last successful refresh. The scope line shows the manifest hash and event count. Dataset and timezone selection persist in the browser; a page reload does not silently switch datasets.

## Shared interaction rules

- **Session gate.** The app opens through a bootstrap-code screen. A failed or reused code shows a bounded error; it does not reveal the code or session secret.
- **Backend-only data.** Every count, queue, label, metric and evidence line comes from the API. There are no fabricated charts, decorative KPIs or simulated activity rows.
- **States.** Each data view has loading, ready, empty and error states. A failed refresh keeps the last data visible with a warning where available. Mutations never show success before the server commits.
- **Scope.** Dataset-scoped pages keep the selected dataset visible. Counts are not silently combined across datasets. Case selection is explicit and server-validated.
- **Time.** The operator can display UTC or local time. The underlying values remain UTC. A source with no valid timestamp appears outside the ordered timeline.
- **Provenance.** Evidence displays source filename, line, record hash and parser status. Raw payloads are inert text.
- **Accessibility.** Skip link, focusable main region, labelled navigation, table headers, visible focus, button/form labels, tab semantics and status/alert announcements. Tested in Chrome and Playwright WebKit via keyboard and responsive checks; no WCAG certification is claimed.

## 1. Overview

**Question:** What needs attention, and can I trust the current state?

Implemented:

- dataset scope and manifest/event coverage;
- review finding count, open investigation count, pending approval count and open case count;
- attention queue linking to findings and pending approvals;
- audit claims: integrity, completeness, consistency, with an explanation and link to audit;
- source coverage table with event/line counts and SHA-256;
- recent recorded audit activity;
- evaluation-context note stating that only three agents have binary labels.

Empty and error behavior:

- no pending approvals says so and keeps decision history available;
- an audit failure is shown as a claim, not a green banner, and mutation controls fail closed;
- no cases says no cases were created; it never says "all threats prevented".

Screenshot: [01-overview.png](screenshots/01-overview.png).

## 2. Investigations

**Question:** Which evidence supports this finding, what remains unknown, and what verdict can I defend?

Implemented:

- finding queue with disposition, priority score, rule context and evidence count;
- finding detail with exact source refs, observed/supporting/contradicting facts, unknowns, limitations and correlation edges;
- evidence detail with captured line content, record hash, source hash and integrity state;
- investigation creation from selected findings;
- verdict revisions with enum values `POLICY_VIOLATION_SUPPORTED`, `WITHIN_OBSERVED_SCOPE`, `INSUFFICIENT_EVIDENCE`, `NEEDS_MORE_DATA`;
- required rationale and at least one selected evidence citation for a supported verdict;
- revision history and conflict handling for stale writes.

The UI keeps `UNKNOWN` distinct from "not reviewed" and from an analyst verdict. Shared-host attribution is shown beside the evidence, not as a footnote claiming ownership. A missing or mutated evidence snapshot becomes an explicit integrity error, and a case export later fails closed if selected evidence no longer resolves.

Screenshots: [02-investigations-queue.png](screenshots/02-investigations-queue.png), [03-finding-detail.png](screenshots/03-finding-detail.png), [04-investigation-detail.png](screenshots/04-investigation-detail.png), [05-investigation-verdict.png](screenshots/05-investigation-verdict.png).

## 3. Agent traces

**Question:** What inputs did the agent receive, which tools did it propose, and how did policy and execution respond?

Implemented:

- run list with scenario, runtime, policy preset, status and timestamps;
- run creation with dataset, scenario, server preset and runtime;
- linked investigation context when a run is started from an investigation;
- ordered visible trace events: input/context, model or scripted message, proposal, policy decision, approval wait, execution, error/cancel;
- proposal detail with exact arguments, effect, decision/reason, resource hash/digest, policy version and approval link;
- explicit `NO_TOOL_CALL` result for the boundary-aware scripted scenario;
- cancel action that invalidates pending approvals; policy change with expected revision.

The trace never invents hidden chain-of-thought. A blocked proposal cannot display an execution result. The Ollama runtime is visible but only usable when the server has explicitly enabled it; no model run occurred in this delivery.

Empty/error behavior: a valid run with no proposals says "No tool calls proposed"; a failed runtime shows a bounded error and preserves prior steps.

Screenshot: [09-agent-trace-waiting.png](screenshots/09-agent-trace-waiting.png).

## 4. Policy & approvals

**Question:** What is allowed, what is blocked, and exactly what will I authorize?

Implemented:

- readable, versioned server presets with allowed/blocked/approval semantics;
- request history with tool, decision, mode, status, execution state and timestamps;
- pending approval queue and exact-request detail:
  - tool and schema version;
  - safe arguments;
  - effect description;
  - resource reference/hash;
  - request digest;
  - policy preset/version;
  - creation/expiry;
  - approval state/version;
  - bound operator session;
  - execution status/result when committed;
- "Approve once and execute" and "Reject", both requiring a reason, reviewed-digest confirmation and idempotency key from the client;
- terminal state after consumption; refresh shows no actionable buttons;
- conflict/expired/invalidated messages that direct the operator to submit a new request.

No bulk approval, natural-language approval, argument replacement, policy override or actor field exists in the decision body. "Approved once" is visually separate from "Execution succeeded".

Screenshots: [08-policy-approvals.png](screenshots/08-policy-approvals.png), [10-approval-review.png](screenshots/10-approval-review.png), [11-approval-committed.png](screenshots/11-approval-committed.png).

## 5. Evaluation

**Question:** Which scenarios were tested, under which versions, and what do the results measure?

Implemented:

- deterministic baseline run for the active dataset;
- category-separated results: `synthetic_detection`, `scripted_enforcement`, `local_model_observations`;
- TP/FP/TN/FN plus explicit abstained, missing, errored and unlabeled buckets;
- known-label total, emitted count, coverage and conditional precision/recall/F1;
- diagnostic threshold table labelled as the same fixture;
- 7 scripted enforcement checks with expected/actual and per-row result;
- audit snapshot;
- limitations, versions, timestamps and configuration;
- JSON, Markdown and CSV downloads with correct extensions.

Empty state says no evaluations are recorded. A failed run remains failed instead of becoming a smaller successful benchmark. The local-model panel reports the recorded count (zero here) and states that no model is part of the suite. It never presents the legacy mocked adapter as a real observation.

Screenshot: [12-evaluation.png](screenshots/12-evaluation.png).

## 6. Audit & cases

**Question:** Can I verify the recorded decisions, and can I hand off a scoped, defensible incident record?

### Audit tab

Implemented:

- separate **Integrity**, **Completeness** and **Consistency** claims;
- checked sequence range, head MAC, first failure when applicable, key status and safe-for-mutations state;
- "Run verification" producing a cached read-only report with an ID;
- paginated audit events with linked entity IDs and payloads;
- explicit message that a local checkpoint is not independent tamper-proof storage;
- read-only inspection when mutation is blocked.

An empty chain with prior checkpoint records fails closed. No repair button or reassuring green badge exists.

### Cases tab

Implemented:

- case list and scoped case creation from selected findings/optional investigation/requests;
- title, summary, scope, analyst conclusion and recommendations;
- append-only revisions with stale-revision conflict;
- case detail with revision history, evidence/request links and classification banner;
- Markdown, JSON and CSV export; Markdown/CSV escaping; evidence-hash validation before export;
- `manual_export_only` status; no external sync or inferred Vigil case ID.

Screenshots: [13-audit.png](screenshots/13-audit.png), [14-cases.png](screenshots/14-cases.png), [06-case-detail.png](screenshots/06-case-detail.png), [07-case-export.png](screenshots/07-case-export.png).

## Visual system

The layout is an investigation desk rather than a generic dashboard:

| Role | Value |
|---|---|
| Canvas / surface | `#F5F7F9` / `#FFFFFF` |
| Text primary / secondary | `#1D2733` / `#526172` |
| Divider / accent | `#D6DDE5` / `#2457A6` |
| UI / log type | system sans / `SFMono-Regular`, Menlo, Consolas |
| Page / section / table | 24px / 16px / 14px |

The navigation is a compact left rail above 1024px and a horizontal scrollable bar on narrow screens. Status color is always accompanied by text; color alone does not imply maliciousness. There are no external fonts, CDN assets, decorative threat maps, animated graphs or glass/neon effects. Evidence tables are dense and source links remain visible without hover.

## API contract groups

The implemented same-origin API includes:

- session: `GET /session`, `POST /session/exchange`
- evidence: `/datasets`, `/datasets/sample/import`, `/datasets/{id}/detect`, `/findings`, `/findings/{id}`, `/events/{id}`
- workbench: `/overview`, `/policies`, `/requests`, `/approvals`, `/approvals/{id}`, `/approvals/{id}/decision`
- runtime: `/runs`, `/runs/{id}`, `/runs/{id}/cancel`, `/runs/{id}/policy`, `/scenarios`
- investigations: `/investigations`, `/investigations/{id}`, `/investigations/{id}/verdicts`
- evaluation: `/evaluations`, `/evaluations/{id}`, `/evaluations/{id}/export`
- audit: `/audit/events`, `/audit/summary`, `/audit/verifications`, `/audit/verifications/{id}`
- cases: `/cases`, `/cases/{id}`, `/cases/{id}/revisions`, `/cases/{id}/exports`, `/exports/{id}`

Collections are bounded and scoped; mutations require a session, CSRF header and an Origin matching the actual allowed Host. The openapi/docs routes are disabled. See ARCHITECTURE for the exact security boundary.

## Explicit non-goals

No real tool execution, shell, arbitrary file read, secret read, external network write, EDR action, Vigil API write, remote deployment, multi-user RBAC, arbitrary log upload, model benchmark, packet capture, cloud model or production SOC workflow. Adding any of these is a new product decision, not a hidden switch.


## Continuation acceptance evidence

The analyst workflow is exercised in Chrome and Playwright WebKit with failed-resource navigation, inert XSS text, cross-origin form rejection, strict CSP checks and keyboard/responsive behavior. A resource-path change clears previous data before rendering an error; stale data is retained only for a refresh of that same resource. Approval route changes reset review state.

Evaluation history follows the selected dataset. Counts distinguish seven total proposals, six risky synthetic proposals, known-label abstentions, unknown/unlabeled evidence, attempted model runs and runs with an observed response. All remain separate from actual-model performance claims.

JSON and Markdown case exports retain unknown-time evidence outside the ordered timeline. The CSV evidence table includes every selected source reference. A valid chain/consistent local checkpoint does not imply independent audit retention or comprehensive database referential verification. Native Safari and manual accessibility certification remain unverified.
