# Agent Security Workbench

**A local, evidence-driven workbench for investigating synthetic agent behaviour and testing pre-execution tool authorization.**

Agent Security Workbench connects multi-source security telemetry to evidence-linked findings, scripted agent runs, server-owned tool policy, one-time human approval, a transactional synthetic executor, an HMAC audit trail, versioned cases and reproducible evaluation. The default demo is deterministic and needs no model, API key, container or external service.

> **Scope:** this is an educational security-engineering prototype. It is not a production SOC, EDR, malware sandbox, authenticated multi-user platform, independent audit vault, or benchmark of real intrusion-detection accuracy. All telemetry, agents, findings, effects and cases are synthetic and local.

**Status:** local MVP implemented and tested on 2026-10-20; independently audited on 2026-10-21 with all findings resolved or documented (see [docs/FINAL_AUDIT.md](docs/FINAL_AUDIT.md)). The optional Ollama runtime was **not** exercised with a real model; its observation count is zero. The GitHub Actions workflow exists but has not run. See [docs/COMPLETION_REPORT.md](docs/COMPLETION_REPORT.md) for the full delivered/deferred matrix.

## What the workbench demonstrates

- **Evidence before conclusions.** Source files are captured as immutable blobs. Every finding links to an exact `file:line`, SHA-256 and correlation edge; shared-IP proximity is labelled as a host association, not agent identity.
- **Policy before execution.** The runtime can only propose a tool call. A trusted registry and server-loaded preset produce `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL`; the agent cannot pick a mode or approve itself.
- **One approval, one request.** Approval is bound to the request digest, policy version, resource hash, local operator session and expiry. The receipt, execution result, approval consumption and audit event commit in one SQLite transaction.
- **Claims stay separate.** Audit integrity, completeness and consistency are reported independently. Detection metrics, scripted enforcement checks and local-model observations are distinct result types.
- **The UI shows recorded state.** The React workbench displays backend data only: no invented charts, fake live streams or decorative risk scores.

![Overview screen showing the synthetic dataset, review findings, audit claims and source coverage](docs/screenshots/01-overview.png)

## Measured local results

| Check | Result |
|---|---|
| Python regression/security suite | **234 passed, 12 subtests passed** (185 at delivery + 49 independent audit tests, 2026-10-21; see docs/FINAL_AUDIT.md) |
| Browser workflow | **Analyst workflow passed in Chrome and Playwright WebKit** against disposable databases |
| Static checks | Ruff, Ruff format, mypy, ESLint, TypeScript build passed |
| Dependency audit | **0 vulnerabilities** reported by the final `npm ci` audit (point-in-time) |
| Synthetic detection fixture | TP=2, FP=0, TN=1, FN=0, unlabeled=1 |
| Scripted enforcement checks | **7/7 passed** (allow, block, monitor, approve, reject, secret block, bypass checks) |
| Actual local-model observations | **0** — no Ollama run was performed |

Precision/recall/F1 are 1.0 only for this four-agent authored fixture. They are functional checks of the pipeline, not estimates of real-world detection accuracy.

## Quick start

### Prerequisites

- macOS or Linux
- Python **3.11+**
- Node.js **22.x** and npm
- Google Chrome for the local Playwright run (or install Playwright Chromium; see below)

Windows is not a tested target. The application binds to loopback only.

```bash
make setup     # create .venv, install pinned Python deps, npm ci, build the UI
make demo      # serve http://127.0.0.1:8765
```

`make demo` prints a single-use **bootstrap code** in the terminal. Open `http://127.0.0.1:8765`, enter the code, and stop the server with `Ctrl+C`. The code expires after 10 minutes and cannot open a second session.

The first startup imports the bundled 14-event synthetic dataset and runs detection automatically.

## Demo walkthrough

Start `make demo`, open `http://127.0.0.1:8765`, and follow the tour below (about three minutes end to end). It is the same flow the automated browser test asserts in [frontend/tests/e2e/workbench.spec.ts](frontend/tests/e2e/workbench.spec.ts). Every screenshot is a capture of the running application with the fixture data — `make screenshots` re-records all 14 images — not a mockup.

### Step 1 · Unlock the session gate

Paste the single-use **bootstrap code** printed by `make demo` into the gate and select **Open local workbench**.

- A wrong, stale or already-used code is rejected with *Session not established*. The code expires after 10 minutes and cannot open a second session.
- There is no login: the boundary footer states *"Local synthetic workbench. No external case writes, shell, secrets, or network tools"*, and the operator identity is a local session, not a verified human.

### Step 2 · Overview — recorded state only

![Overview screen showing dataset scope, review signals, the audit-chain badge and source coverage](docs/screenshots/01-overview.png)

*Dataset scope ("Shared-host agent scenario", 14 events), review signals, the audit-chain badge and the three audit claims all come from the backend.*

**Look for**

- The scope line pins the dataset version and manifest id — every screen below operates inside this scope.
- Signals such as **Review findings** show recorded detector output, not live streams.
- The **audit chain valid** badge sits next to independent integrity/completeness/consistency claims; a valid chain is not presented as proof of complete history.
- There are no invented charts, fake live streams or decorative risk scores anywhere in the app.

### Step 3 · Investigations — evidence before conclusions

Open *Unapproved publish attempt with correlated outbound upload* from the queue ([queue view](docs/screenshots/02-investigations-queue.png)).

![Finding detail linking the detector summary to immutable captured evidence](docs/screenshots/03-finding-detail.png)

*Finding detail: observed facts and unknowns, stated limitations, and evidence links.*

**Look for**

- Follow a **source link** to the captured bytes: the *Captured source context* table shows the recorded line and its **Record SHA-256**.
- The shared-host correlation stays labelled as host association — the finding text says it does not establish agent ownership or successful exfiltration.

### Step 4 · Investigation and verdict — findings stay analyst-owned

Select **New investigation**, link the finding, and record a verdict from the investigation page ([investigation detail](docs/screenshots/04-investigation-detail.png)).

![Investigation page with append-only verdict history, cited evidence and a revisioned verdict form](docs/screenshots/05-investigation-verdict.png)

*Verdict history is append-only; the form enforces evidence citation before saving.*

**Look for**

- A supported conclusion requires at least one cited evidence record; with zero citations the form raises *"This verdict requires at least one cited evidence record."*
- Revisions are append-only: *Verdict revision N saved. The previous revision remains in history.*
- The verdict text may cite the evidence supporting a policy-outcome review — it does not claim proven compromise.

### Step 5 · Agent traces — the run stops at the approval gate

On **Agent traces**, choose **Run scripted scenario**: scenario `injection`, policy preset `approve-v1`, runtime `scripted`, then **Start run**.

![Agent trace paused at Waiting for approval before any effect exists](docs/screenshots/09-agent-trace-waiting.png)

*The trace pauses at Waiting for approval: the tool call is a proposal, and no effect exists yet.*

**Look for**

- The runtime can only **propose** a registered tool; actor and policy are server-owned.
- Nothing in the trace executes the publish — authorization belongs to the gateway, not the agent.

### Step 6 · Policy & approvals — one approval, one request

Open the **Pending approval queue** and select **Review request**.

![Exact-request review showing the tool, exact arguments, request digest, policy version and expiry](docs/screenshots/10-approval-review.png)

*The review binds the decision to one immutable request: effect (`publish_simulated`, one local SQLite receipt), exact arguments, request digest, policy version and expiry.*

Fill in a decision reason, check **I reviewed the exact arguments**, then **Approve once and execute**:

![Committed approval showing consumed and succeeded state plus the recorded local synthetic receipt](docs/screenshots/11-approval-committed.png)

*After commitment, approval state (consumed), execution outcome (succeeded) and the receipt are shown as three separate records.*

**Look for**

- **Approved once · committed** appears, and the executor wrote one local SQLite receipt — *"No external publish occurred"*.
- Refresh the page: *This approval is not actionable* — the decision is terminal and cannot be replayed.
- **Open the agent run and trace** shows the run reaching `SUCCEEDED` with the *Execution result and receipt* recorded after the decision commits.

### Step 7 · Evaluation — claims stay separate

On **Evaluation**, run **Run synthetic baseline suite**.

![Evaluation result page showing synthetic detection metrics, scripted enforcement checks and the audit snapshot](docs/screenshots/12-evaluation.png)

*Detection metrics, 7/7 scripted enforcement checks and the audit snapshot, reported as separate result types.*

**Look for**

- TP=2 on the four-agent synthetic fixture, with explicit caveats: precision/recall are "conditional on emitted binary decisions", not real accuracy.
- **Local Ollama runs with an observed response: 0** — no live-model claim is mixed into the scripted results.
- Download JSON, Markdown and CSV with correct extensions.

### Step 8 · Audit & cases — verify, then scope a case

On the audit tab, run **Run verification**, then create a scoped case from *Create case from scope* on an investigation (or browse the [Cases tab](docs/screenshots/14-cases.png)).

![Audit verification page with integrity and completeness claims plus the event chain](docs/screenshots/13-audit.png)

*Verification reports integrity, consistency and completeness as separate claims under a verification id.*

**Look for**

- A `ver_…` id with **Integrity: VALID** and **Completeness: CHECKPOINT MATCHED**; verification is read-only and issues one explicit verdict per claim.
- Cases are scoped and append-only ([case detail](docs/screenshots/06-case-detail.png)): *Case revision 2 saved. Previous revisions remain immutable.*
- Exports ([example export](docs/screenshots/07-case-export.png)) are local file downloads, marked synthetic and manual-only — no external system was contacted.

There is no button that publishes externally, reads a secret, runs shell commands or writes to another system.

## Commands

| Command | What it does |
|---|---|
| `make setup` | Create `.venv`, install pinned dependencies, install npm packages and build the frontend |
| `make demo` | Serve the built same-origin workbench at `http://127.0.0.1:8765` |
| `make test` | Run the Python regression, recovery and security suite |
| `make lint` | Ruff check/format, mypy and frontend ESLint |
| `make build` | Type-check and build the React frontend |
| `make e2e` | Run the isolated Chrome/Chromium workflow on port 8876 |
| `make e2e-webkit` | Run the same workflow in the optional Playwright WebKit engine |
| `make screenshots` | Recapture the 14 documentation screenshots from the browser flow |
| `make eval` | Run the deterministic evaluation into `run/eval` |
| `make verify` | Build, test, lint and run browser E2E |
| `make clean` | Remove build/test caches, not runtime data |

Local E2E uses installed Google Chrome by default. On a machine without Chrome:

```bash
cd frontend
npx playwright install chromium
PW_CHANNEL=chromium npm run test:e2e
```

The E2E harness deletes and recreates `frontend/.e2e-run`; it never attaches to a developer's demo database.

## Architecture

```mermaid
flowchart LR
  F["Bundled synthetic fixtures<br/>Zeek · Suricata · Windows · agent trace · note"] --> I["Bounded ingestion<br/>immutable source blobs + hashes"]
  I --> E["Evidence store<br/>events · source lines · manifests"]
  E --> D["Deterministic detection<br/>rules + correlation edges"]
  D --> N["Findings + investigations<br/>verdict revisions"]
  N --> R["Scripted runtime<br/>optional loopback Ollama"]
  R --> P["Typed tool proposal<br/>no authority"]
  P --> G{"Server policy gateway"}
  G -->|BLOCK| A["Transactional audit<br/>HMAC chain + checkpoint"]
  G -->|ALLOW| X["Synthetic executor<br/>fixed read / DB receipt"]
  G -->|REQUIRE_APPROVAL| H["Local operator<br/>exact request review"]
  H -->|single-use decision| G
  X --> A
  E --> A
  N --> A
  A --> C["Case revisions + scoped exports"]
  E --> V["Evaluation<br/>detection · enforcement · audit"]
  G --> V
  A --> C
```

The backend is one FastAPI process serving `/api/v1` and the built React assets from the same origin. SQLite is the only datastore. Runtime state, the audit key and generated reports stay under `run/` and are gitignored. `constraints.txt` pins the resolved Python graph; the npm graph is locked in `frontend/package-lock.json`.

### Trust boundaries

| Boundary | Enforced behaviour |
|---|---|
| Fixtures → ingestion | Fixed sample dataset only; bounded bytes/lines/records; duplicate JSON keys and non-finite numbers rejected; symlinked sources rejected; raw bytes retained and hashed |
| Evidence → detection | Versioned rules return observations, evidence IDs, limitations and uncertainty; source `approved` claims are never authorization |
| Runtime → proposal | Scripted or local-model output can only propose a registered tool; actor and policy are server-owned |
| Proposal → execution | Gateway loads the run's immutable preset; exact argument allowlists; unknown tools and `read_secret` always fail closed |
| Decision → effect | Approval digest/version/session/expiry checked inside `BEGIN IMMEDIATE`; receipt, result, trace, audit and idempotency record commit together |
| State → audit | HMAC-SHA256 chain plus local head checkpoint; corruption blocks mutations with `AUDIT_INTEGRITY_FAILED` |
| Browser → API | Single-use bootstrap → HttpOnly SameSite=Strict cookie + CSRF header; exact Host/Origin; JSON-only mutations; CSP/no-store; no CORS |
| Case → external system | Scoped, revisioned synthetic export only; `integration_status=manual_export_only`; no Vigil API write |

The OS account, Python/Node runtimes, application code, local filesystem and operator browser are trusted. A local process or administrator that can replace the database, audit key and checkpoint is outside the guarantee. A local HMAC chain is **not** independent audit storage.

## Implemented surfaces

| Area | Implementation |
|---|---|
| Ingestion | Eight synthetic source files, 14 events, parser status, exact line refs, immutable blob hashes, dataset manifest |
| Detection | Three review/unknown findings over four authored agents, correlation windows, attribution limitations, rule/version metadata |
| Investigations | Evidence-cited verdict revisions: policy violation, within observed scope, insufficient evidence, needs more data |
| Runtime | Four scripted scenarios, including an explicit `NO_TOOL_CALL` result; optional loopback-only Ollama adapter |
| Policy | `deny-v1`, `approve-v1`, `monitor-v1`; server-owned registry for `read_report`, `publish_simulated`, forbidden `read_secret` |
| Approval | Digest/version/policy/resource/session/expiry binding, rejection, expiry, invalidation on cancel or policy change, idempotent replay |
| Execution | Fixed synthetic report read or one local SQLite receipt; no shell, arbitrary file, network or secret adapter |
| Audit | HMAC chain, checkpoint, explicit integrity/completeness/consistency, pagination, read-only diagnostic verification |
| Cases | Scoped creation, append-only revisions, escaped Markdown/JSON/CSV export, evidence-integrity failure closure |
| Evaluation | Synthetic detection metrics, scripted enforcement comparisons, audit snapshot, JSON/Markdown/CSV downloads |
| UI | Six primary screens plus detail routes, loading/empty/error/success states, accessible tables/forms, 1024px and 390px layouts |

### Screenshot index

| Screen | Purpose | Screenshot |
|---|---|---|
| Overview | Attention queue, audit claims, source coverage, recent activity | [01](docs/screenshots/01-overview.png) |
| Investigations | Finding queue, evidence, timeline, revisions | [02](docs/screenshots/02-investigations-queue.png) · [03](docs/screenshots/03-finding-detail.png) · [04](docs/screenshots/04-investigation-detail.png) · [05](docs/screenshots/05-investigation-verdict.png) |
| Agent traces | Scripted run, proposals, policy decisions, execution | [09](docs/screenshots/09-agent-trace-waiting.png) |
| Policy & approvals | Presets, exact-request review, one-time decision | [08](docs/screenshots/08-policy-approvals.png) · [10](docs/screenshots/10-approval-review.png) · [11](docs/screenshots/11-approval-committed.png) |
| Evaluation | Detection metrics, enforcement checks, audit snapshot, exports | [12](docs/screenshots/12-evaluation.png) |
| Audit & cases | Verification claims, audit events, case history and export | [13](docs/screenshots/13-audit.png) · [14](docs/screenshots/14-cases.png) · [06](docs/screenshots/06-case-detail.png) · [07](docs/screenshots/07-case-export.png) |

All screenshots were captured from the running application with the fixture data. They are not mockups.

## Evaluation

```bash
make eval
```

The measured baseline output was:

```text
TP=2 FP=0 TN=1 FN=0
abstained=0 missing=0 errored=0 unlabeled=1
precision=1.0 recall=1.0 f1=1.0
scripted enforcement: 7/7 passed
proposals=7 synthetic_attack_attempts=6
blocked=3 approved=1 monitored=1 rejected=1
audit_integrity=valid
```

Reports are written to `run/eval/reports/` as JSON, Markdown and formula-safe CSV. The UI also downloads all three formats with correct extensions.

**Do not read these numbers as detection quality.** There are four synthetic agents, three binary policy-outcome labels and one intentionally unlabeled agent. Scripted injection results are deterministic policy outcomes, not LLM attack-success rates. The threshold table reuses the same fixture and is diagnostic only.

### Optional local Ollama

The adapter is disabled by default and validates a fixed loopback endpoint, disables proxies/redirects and bounds calls and response size. To try it with a locally installed model:

```bash
ollama pull qwen2.5:3b
AGENTGUARD_ENABLE_OLLAMA=1 AGENTGUARD_OLLAMA_MODEL=qwen2.5:3b make demo
```

Then choose the `ollama` runtime when starting a trace. This path was **not** run in this delivery; no model accuracy, robustness or attack-success claim is made. The scripted runtime remains the reproducible default.

## Deliberate limits and deferred work

- **No real effects.** No external publish, HTTP write, shell, arbitrary file read, secret access or EDR action exists. The executor writes one SQLite receipt at most.
- **Single local operator.** The session identifies a local browser interaction, not a verified human or multi-user identity. There is no RBAC, TLS deployment or remote access.
- **No independent audit retention.** The HMAC key and checkpoint are local. Host compromise, database replacement and key theft are outside the threat model.
- **No production scale or performance claim.** Ingestion bounds are configured, not load-tested to 100,000 records. Write-failure, process-exit and separate-process approval tests pass; no power-loss, soak or fuzz campaign was run.
- **No live model result.** The Ollama adapter has no recorded local observation, and its transport contract was tested only with offline doubles.
- **No live Vigil integration.** Export is a manual, marked synthetic draft.
- **CI not executed.** `.github/workflows/ci.yml` is present and reviewable; it has not run on GitHub. No CI badge or green status is claimed.
- **Manual accessibility review incomplete.** Automated keyboard, skip-link, focus and responsive-width checks pass; Native Safari, VoiceOver and 200% zoom were not manually certified. Playwright WebKit is a separate browser-engine check.
- **Repository not published.** No commit, push, tag or deployment was performed as part of the build.

## Project layout

```text
agentguard/workbench/       FastAPI app, SQLite, ingestion, detection, policy, runtime,
                            approvals, audit, cases, evaluation, sessions
agentguard/workbench/migrations/001_initial.sql
frontend/src/               React 19 + TypeScript UI and typed API client
frontend/tests/e2e/         Playwright analyst workflow
tests/                      pytest security, integration and regression suites
examples/logs/              Bundled synthetic fixtures
docs/                       Architecture, threat model, ADRs, validation, report, screenshots
run/                        Generated local state and reports (gitignored)
Makefile                    setup, demo, test, lint, verify, eval
```

Preserved legacy AgentGuard modules (`agentguard/hunt.py`, `gateway.py`, `audit.py`, and the old CLI commands) remain as a behavioural reference and are not linted by the new workbench scope. The rebuilt system is the `agentguard/workbench/` package plus `frontend/`; see the [baseline audit](docs/BASELINE_AUDIT.md) for how it differs.

## Documentation

| Document | Contents |
|---|---|
| [Demo walkthrough](docs/DEMO_WALKTHROUGH.md) | Setup, investigation, policy comparison and case handoff |
| [Scenarios](docs/SCENARIOS.md) | Synthetic inputs, expected outcomes and failure boundaries |
| [Completion report](docs/COMPLETION_REPORT.md) | Delivered/deferred matrix, exact commands, screen status, risks, runbook |
| [Architecture](docs/ARCHITECTURE.md) | Implemented modules, data flow, schema, transactions, API security |
| [Threat model](docs/THREAT_MODEL.md) | Threat register with test evidence and assurance limits |
| [Validation](docs/VALIDATION.md) | Environment, measured output, browser/model status, unverified scope |
| [Product specification](docs/PRODUCT_SPEC.md) | Screen contracts and implemented behaviour |
| [ADRs](docs/ADR.md) | Decisions and their implementation outcomes |
| [Plan](PLANS.md) | Phase ledger and remaining gates |
| [Final audit](docs/FINAL_AUDIT.md) | Independent security/engineering audit: findings, evidence, fixes, regression tests |
| [Release readiness](docs/RELEASE_READINESS.md) | Release gate checklist and the GO/CONDITIONAL GO/NO-GO decision |
| [Baseline audit](docs/BASELINE_AUDIT.md) | Historical AgentGuard audit and preserved probes |
| [Portfolio notes](docs/PORTFOLIO.md) | Interview narrative and claim discipline |

## Resume bullets

> Rebuilt an offline-first **Agent Security Workbench** (FastAPI, SQLite, React/TypeScript) that correlates synthetic Zeek, Suricata, Windows and agent telemetry into evidence-linked findings and enforces server-owned tool policy with session-bound, expiring, single-use approvals.

> Verified the system with **234 backend tests, 12 subtests and a browser workflow in Chrome and Playwright WebKit**, including process races, write-failure rollback, process-exit recovery, idempotent replay, evidence integrity, scoped exports and responsive keyboard navigation; all runtime effects remain synthetic and local. An independent security audit (docs/FINAL_AUDIT.md) re-verified the gateway, approval and audit boundaries on 2026-10-21.

**License:** MIT. Synthetic fixtures, scenarios and tests are original educational material; do not present their results as real incident findings.
