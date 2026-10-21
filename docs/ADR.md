# Architecture decision records

Status: accepted and implemented in the local MVP unless explicitly marked deferred. Original design decisions were made on 2026-10-20; implementation outcomes and deviations are recorded below. Verification evidence is in [VALIDATION.md](VALIDATION.md).

## ADR-001 — Reference-driven modular monolith

**Context:** AgentGuard had a useful synthetic fixture, tool allowlists and 33 regression tests, but JSON state, in-memory approval ownership and execute-before-audit code could not support the target workflow.

**Decision:** Preserve the package, CLI and historical tests as a behavioural reference. Build the workbench as a modular monolith in `agentguard/workbench/`, reusing explicit allowlists, fixture semantics and uncertainty language. Do not rewrite everything or copy modules blindly.

**Outcome:** Implemented. Legacy modules remain in place and are not reformatted by the new lint scope. The new service path is used by the API and the workbench CLI commands. The historical baseline is documented separately, including reproduced gaps.

**Consequences:** Temporary coexistence is intentional. There is no claim that the legacy CLI and new workbench share one runtime authorization state; the workbench is the rebuilt system.

## ADR-002 — Python 3.11+, FastAPI and Pydantic v2

**Context:** The prototype needed a typed, testable API contract without maintaining a hand-built HTTP parser.

**Decision:** Python 3.11 minimum; FastAPI with Pydantic v2 models; strict/extra-forbid DTOs; JSON body normalization before route handling; validation errors sanitized to locations/types.

**Outcome:** Implemented with FastAPI 0.138.2 and Pydantic 2.13.2. The API returns a stable `{code,message,request_id,details}` envelope. OpenAPI/docs routes are intentionally disabled in the local build.

**Consequences:** Dependencies are pinned in `requirements*.txt`. The API's strictness is tested, but Pydantic is not treated as the authorization layer.

## ADR-003 — SQLite, explicit transactions and SQL migrations

**Context:** The baseline reproduced lost JSON updates, stale approvals and effects without audit.

**Decision:** Use stdlib `sqlite3`, one numbered SQL migration, parameterized SQL, foreign keys, a short busy timeout, `synchronous=FULL`, rollback journaling and explicit `BEGIN IMMEDIATE` for each mutation. Keep synthetic evidence and receipts in SQLite.

**Outcome:** Implemented in `db.py` and `migrations/001_initial.sql`. Migration checksums are verified. Approval, receipt, result, trace, audit and idempotency writes share one transaction. Thread and separate-process races observe one commit. Injected write failures and a process exit before commit recover without committed partial state.

**Consequences:** SQLite has one writer. Single approval contention is tested across processes; sustained contention and long-running external effects remain unsupported. No ORM or Alembic layer was added.

## ADR-004 — Approval is a transaction over an immutable request

**Context:** “Approve once” in the prototype had no expiry, operator binding, resource version or policy recheck.

**Decision:** Bind approval to request digest, exact arguments, resource hash, policy version, local operator session and expiry. Use compare-and-set consumption; replay uses a body-hashed idempotency record. Commit the synthetic receipt and audit with consumption.

**Outcome:** Implemented in `enforcement.py`. Tested: wrong digest/version, different session, expiry, policy change, cancellation, concurrent approve/approve, idempotent retry and second-key conflict. Rejection never creates a receipt.

**Consequences:** The guarantee covers committed local synthetic receipts only. There is no exactly-once guarantee for future external executors; those need a new recovery design.

## ADR-005 — Scripted default; optional Ollama

**Context:** The demo must be deterministic and runnable without a model download or GPU.

**Decision:** Default to four scripted scenarios. Make Ollama operator-enabled, loopback-only, no proxies/redirects, with bounded turns/proposals/response/time and visible metadata. Never let a model choose policy or approve.

**Outcome:** Scripted scenarios and `NO_TOOL_CALL` are implemented and browser-tested. The Ollama adapter is implemented and endpoint-validated but **not run with a real model**; observations are zero and excluded from metrics.

**Consequences:** Scripted results are never “LLM performance.” Offline transport tests exercise malformed/oversized responses, no-call, policy modes, budgets, outages, redirect refusal and endpoint validation. Do not claim model robustness or attack resistance from this delivery.

## ADR-006 — React, strict TypeScript, Vite and accessible controls

**Context:** Six linked views and detail routes need typed API access, shared evidence selection and keyboard-accessible controls.

**Decision:** React/TypeScript with strict checks, Vite, plain CSS tokens, small shared primitives and route/query state. No global state library or dashboard kit.

**Outcome:** Implemented with React 19.3.1, TypeScript 5.9.3 and Vite 7.3.7. The client has typed errors, abort handling, CSRF and idempotency headers. The UI uses semantic tables/forms, a skip link, labelled navigation and text-only evidence. **Deviation:** the client types are hand-maintained. Disabling public OpenAPI endpoints does not prevent build-time schema generation; that improvement remains deferred.

**Consequences:** No second production Node server. Vite is development-only. Component test coverage is limited to the browser workflow; there is no separate component-test suite.

## ADR-007 — Same-origin localhost product

**Context:** Loopback binding does not stop a malicious website from sending requests to localhost.

**Decision:** Serve API and built assets from one FastAPI process. Bootstrap a local session from a single-use terminal code, use an HttpOnly SameSite=Strict cookie, CSRF for mutations, exact Host/Origin and fetch-metadata checks, JSON-only bodies, CSP/frame denial and no CORS.

**Outcome:** Implemented. The bootstrap code is 64 bits, expires after 10 minutes and has a five-attempt lockout. API reads require the cookie; mutations also require the CSRF header. Header-level tests and a real-browser same-origin workflow pass. The local session is explicitly labelled “not verified human identity.”

**Consequences:** This is not remote authentication, TLS protection or multi-user RBAC. A compromised local browser or extension is outside the boundary.

## ADR-008 — HMAC audit with explicit completeness limits

**Context:** Retained-record edits are detectable, but truncation and a missing event table previously verified as success.

**Decision:** Keep HMAC-SHA256 chaining, add a local head checkpoint, verify at startup/before mutations, and report integrity, completeness and consistency separately. Fail closed; no repair/re-key over old history.

**Outcome:** Implemented. Tests cover payload edits, middle deletion, suffix deletion, delete-all, broad key permissions, symlink key and missing key. An empty table with a non-empty checkpoint is `checkpoint_mismatch` and blocks mutations.

**Consequences:** The checkpoint is local, so host-level replacement remains undetected. This is not independent audit storage or a blockchain claim.

## ADR-009 — Explicit case creation and manual Vigil export

**Context:** The prototype export aggregated all local requests and had no case identity or revision.

**Decision:** Separate findings, investigations, runtime requests and cases. Create cases from explicit scope; make revisions append-only; export marked synthetic Markdown/JSON/CSV with evidence hashes and a verification snapshot. Keep Vigil manual.

**Outcome:** Implemented. Scope validation rejects findings/requests from another dataset. Revision conflicts return 409. Exports escape Markdown/CSV hazards and fail closed on mutated evidence. `integration_status=manual_export_only`.

**Consequences:** No external SDK, API write, credential or inferred Vigil schema. A successful download is not proof of external delivery.

## ADR-010 — Layered quality with modest infrastructure

**Context:** The project needs proof of race, provenance, authorization and browser behavior, not only snapshot tests.

**Decision:** pytest, retained legacy tests, Ruff, mypy on the new package, strict TypeScript, ESLint, frontend build and Playwright E2E. Pin dependencies and actions. Keep CI read-only.

**Outcome:** Implemented locally: originally 185 pytest tests at delivery, **234 tests and 12 subtests after the 2026-10-21 independent audit**, Ruff/format/mypy, ESLint, Vite build and the Playwright workflow in Chrome and WebKit pass. `npm audit --audit-level=high` reports zero vulnerabilities after patching React Router, Vite and typescript-eslint. `.github/workflows/ci.yml` exists with backend, frontend and Chromium/WebKit E2E jobs; the audit added the `constraints.txt` gate to all three Python install steps.

**Consequences:** The workflow has **not run on GitHub**, and no Linux result is claimed. CI defines Chromium and WebKit jobs; local E2E uses installed Chrome and optional Playwright WebKit. There is no coverage threshold, performance budget or fuzz campaign.

## Deferred architecture options

Redis, Kafka, Kubernetes, microservices, PostgreSQL, vector stores, hosted telemetry, Docker-first development, remote identity and real executors are deliberately absent. They should be reconsidered only with a measured requirement for concurrency, isolation, retention or deployment. Adding a real executor requires a new ADR covering process isolation, egress, idempotent target operations, durable intent and `UNKNOWN_OUTCOME` recovery.


## ADR-011 — Revalidate authorization at consumption

**Observation:** New probes changed stored actor/resource/schema fields or policy semantics without changing a version. The previous decision path accepted them. Reusing the same idempotency key at another approval URL also returned the first response.

**Decision:** Recompute the complete immutable binding, check arguments, schema, resource and approval expiry, and re-evaluate the current preset. Invalidate changed requests transactionally. Include approval identity in the idempotency body hash. Keep the proposal budget in the gateway as well as the adapter.

**Evidence:** `tests/test_boundary_hardening.py`, `tests/test_approvals.py` and `tests/test_transaction_recovery.py`. A replay of mutable workflow state cannot create a second receipt while committed receipt state remains. Joint database/key/checkpoint replacement remains outside scope.

## ADR-012 — Audit append owns the integrity precondition

**Observation:** A direct append could extend edited history or a completely deleted event table despite the checkpoint. A displayed timestamp could differ from the signed payload. Caller-only checks did not cover every completion/failure path.

**Decision:** Require an explicit transaction and verify the chain/checkpoint at every append. Verify the displayed timestamp against its signed `recorded_at`. Keep malformed records inspectable without treating them as valid; malformed non-ASCII MACs report invalid integrity instead of raising a comparison error. Unexpected API errors retain bounded responses and security headers.

**Consequence:** Verification scans the retained local history. This is acceptable for the small MVP; large-history cost is unmeasured. It does not add independent audit retention.

## ADR-013 — Preserve unknowns through parsing, model runs and export

**Observation:** Numeric overflow, lone Unicode surrogates and deep JSON could reach inappropriate paths. Numeric string timestamps lost epoch semantics, and fractional times were truncated. Case export omitted evidence without normalized time. Every attempted model run was counted as an observation, even if connection failed.

**Decision:** Bound JSON structure and finite values; preserve fractions; keep missing/timezone-free time unknown. Retain unknown-time evidence separately from ordered events. Export all selected references in CSV. Count model attempts separately from validated-response runs and exclude both from scripted metrics. Key UI resources by path so previous evidence is not shown after failed navigation.

**Evidence:** Independent parser corpus, hostile-input tests, case completeness test, offline adapter tests and browser error navigation. These changes make no claim about real model behavior or general detector accuracy.

## ADR-014 — Narrow WebKit compatibility exception

**Observation:** A minimal native `<select>` page reproduced WebKit's CSP violation. A `securitypolicyviolation` probe identified the attribute sample `text-overflow:inherit`. A separate `body {}` sample came from Playwright screenshot preparation. The first keyboard-link traversal on macOS WebKit required Option+Tab.

**Decision:** Allow only the SHA-256 hash of that exact inert style attribute via `style-src-attr 'unsafe-hashes'`. Keep external styles same-origin and block arbitrary inline styles and all inline scripts. WebKit traces retain actions/DOM without screencast screenshots. Browser tests use macOS full-link traversal where needed and explicitly verify unrelated inline CSS and scripts remain blocked.

**Consequence:** Chrome and Playwright WebKit workflows pass. This does not certify native Safari. The exception allows only one harmless declaration; it is not `unsafe-inline`.
