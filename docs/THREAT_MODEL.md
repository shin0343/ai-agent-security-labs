# Threat model and verified claims

Revised 2026-10-20 for the implemented local MVP. The historical AgentGuard prototype and its reproduced gaps remain in [BASELINE_AUDIT.md](BASELINE_AUDIT.md) and [BASELINE_PROBES.md](BASELINE_PROBES.md); this document describes the rebuilt boundaries and what was actually tested.

**Do not read this as a certification.** The workbench is a synthetic, single-operator, local application. The strongest verified effect guarantee is "all committed synthetic receipt state and audit changes share one SQLite transaction." It is not a guarantee about real external systems, host compromise or independent retention.

## Assets, actors and scope

Protected assets:

- immutable source bytes and evidence hashes;
- exact request arguments and request digests;
- server-owned policy versions and tool allowlists;
- one-time approval state and idempotency records;
- synthetic execution receipts;
- local operator session and CSRF tokens;
- HMAC audit history, key and head checkpoint;
- analyst verdicts, case revisions and exports.

Adversaries and failure sources considered:

- untrusted fixture text, notes, logs and model output containing instructions;
- a malformed or oversized JSON/log payload;
- a malicious website visited by the operator;
- a stale client, duplicate submission or two concurrent decision attempts;
- a changed resource, policy or approval after human review;
- a corrupt/missing audit key, edited audit record, truncated suffix or empty event table;
- a local model returning malformed output, redirecting or never calling a tool;
- a crashed or inconsistent application process.

## Trusted computing base and exclusions

Trusted: the OS user account, Python/Node runtimes, dependencies from the pinned lockfiles, application code, private runtime directory, and the operator's browser.

Not trusted: third-party log content, retrieved documents, agent/model output, imported `approved`/scope claims, and client-supplied policy or actor fields.

Excluded from the isolation guarantee:

- a local process that can read the session/key or modify the application/database;
- a host administrator who can replace the database, key and checkpoint together;
- remote deployment, multi-user identity, TLS termination and network isolation;
- real external effects, EDR response, shell execution, secret access and arbitrary file/network tools.

The workbench is not a sandbox around arbitrary Python code. It constrains application-level tool execution, not an attacker already running with the same OS privileges.

## Trust boundaries

1. **Fixtures/documents → ingestion.** Bytes are data. The importer enforces fixed filenames, root containment, symlink rejection, size/count/depth limits and schema validation. Source claims are stored as evidence, never as permissions.
2. **Evidence → detection.** Rules produce a review disposition with exact evidence, correlation edges, limitations and unknowns. A shared IP is a host association, not proof of process ownership.
3. **Runtime → proposal.** Scripted or model output can only call `propose(tool, args)`; the run supplies actor/policy context. The model cannot select a preset, approve, edit policy or execute directly.
4. **Proposal → authorization.** The server registry and immutable preset decide `ALLOW`/`BLOCK`/`REQUIRE_APPROVAL`. Schema validation is not authority.
5. **Authorization → human decision.** One local session reviews one immutable request digest, exact args, resource hash, policy version and expiry.
6. **Decision → effect.** Approval consumption, synthetic receipt/result, trace, audit and idempotency response commit in one `BEGIN IMMEDIATE` transaction, or roll back.
7. **State → audit.** A local HMAC chain plus checkpoint distinguishes valid retained history from missing/truncated history. It does not prove independent completeness.
8. **Case → external system.** Cases are internal; exports are marked synthetic and `manual_export_only`. No external write path exists.

## Threat and verification register

Status meanings: **Tested** = automated test exercises the stated boundary; **Partial** = implemented with bounded automated evidence but a named gap; **Code only** = implemented but not exercised end to end; **Deferred** = not implemented.

| ID | Threat | Implemented control | Status and evidence | Remaining limit |
|---|---|---|---|---|
| T01 | Prompt injection through logs, notes or tool output | Untrusted text kept as evidence; runtime proposals always cross the gateway; no natural-language authorization; explicit `NO_TOOL_CALL` | **Partial.** Scripted injection/overreach/boundary scenarios in `tests/test_policy_gateway.py`; inert-note test in `tests/test_evidence.py`; browser path in `workbench.spec.ts`. Real LLM not run. | No claim about a real model's susceptibility. |
| T02 | Privilege escalation / confused deputy | Server-owned tool registry and presets; API rejects unknown contract fields; no client policy mode; `read_secret` and unknown tools blocked | **Tested.** `test_browser_cannot_inject_a_per_request_mode`, `test_run_contract_rejects_unknown_values_and_disabled_model`, `test_tool_registry_bypass_attempts_fail_closed`, `test_secret_read_is_blocked...` | Same-OS malicious code remains out of scope. |
| T03 | Argument tampering / schema ambiguity | Exact key/string/enum checks; recomputed full request binding; approval-scoped idempotency; current policy recheck; strict bounded JSON parsing | **Tested.** `test_wrong_digest_and_version_leave_approval_pending`, `test_idempotency_replay_is_exact_and_new_key_conflicts`, API validation tests | Approval recomputes stored request/argument/schema/resource binding and current policy semantics; a DB administrator remains outside the host guarantee. |
| T04 | Path traversal / symlinks / oversized evidence | Fixed fixture set; root containment; `is_symlink` rejection; size/line/depth/record limits; no browser path parameter | **Tested.** `test_symlinked_source_is_rejected`, `test_missing_required_source_fails_closed`, malformed/oversized/invalid UTF-8 tests | Fixture-root replacement by the OS account is outside scope. |
| T05 | Approval replay, expiry or identity confusion | Session-bound approval; request digest; policy/resource recheck; server-time expiry; conditional consume; idempotency body hash | **Tested.** `test_approval_is_bound_to_one_operator_session`, `test_expired_approval_is_refused_without_effect`, `test_policy_change_invalidates_pending_approval`, `test_run_cancel_invalidates_pending_approval` | Local session is not verified human identity. |
| T06 | Concurrent/stale decisions | `BEGIN IMMEDIATE`, reload inside transaction, conditional `WHERE state='PENDING'`, unique receipt per request | **Tested (threads and OS processes).** Approval races assert one commit, one conflict and one receipt. Mutable workflow-state replay cannot duplicate a retained committed receipt. | SQLite has one writer; busy timeout behavior under sustained contention is not load-tested. |
| T07 | TOCTOU / crash between decision and effect | Effect, receipt, result, trace, audit and idempotency committed together; audit health checked before mutation; no external executor | **Tested at selected boundaries.** Injected failures after receipt/result, trace and audit writes roll back all state. A process exit after the synthetic effect but before commit recovers the pending approval. Power loss, disk-full and arbitrary crash points remain untested. | A host crash after commit is recoverable as committed state; there is no external-effect recovery problem because effects are synthetic. |
| T08 | Audit modification/deletion/truncation | HMAC chain, key permissions/symlink checks, local head checkpoint, separate claims, fail-closed mutations | **Tested.** Payload/timestamp edit, reorder, middle/suffix/all deletion, broad key mode, symlink key, missing key, pagination and key-absence tests in `tests/test_audit.py`. | A local admin can replace DB + key + checkpoint; no independent vault. |
| T09 | Information disclosure | Session-gated reads; audit stores digests not raw args; key absent from responses; bounded errors; CSP/no-store; no CORS | **Tested.** `test_audit_does_not_store_raw_tool_arguments`, `test_audit_key_is_not_in_api_responses`, `test_security_headers_and_no_cors`, error-envelope tests | Evidence text is intentionally visible to the local operator; screenshots contain synthetic data only. |
| T10 | Provenance / attribution confusion | Source blob hashes, exact line refs, immutable evidence resolution, versioned correlation edges, explicit limitations | **Tested.** `test_resolved_evidence_is_exact_and_hashed`, `test_unknown_event_and_mutated_snapshot_are_rejected`, `test_finding_evidence_integrity_exposes_invalid_snapshot`, `test_case_export_fails_closed_when_evidence_is_mutated` | Source authenticity is not established; only captured bytes are verified. |
| T11 | Localhost CSRF / DNS rebinding / clickjacking | Single-use bootstrap, HttpOnly SameSite cookie, CSRF header, exact Host/Origin, fetch-metadata check, JSON-only, CSP frame denial, no CORS | **Tested locally.** Backend Host/Origin/CSRF contracts and a cross-origin browser form submission are rejected. Unexpected API errors retain security headers. Native Safari remains unverified. | A compromised local browser/extension is outside scope. |
| T12 | XSS / unsafe export | React text rendering; no `dangerouslySetInnerHTML`; escaped Markdown; JSON; formula-safe CSV; evidence integrity check | **Tested locally.** Case export escaping, inert HTML event-handler text and browser CSP checks pass. Arbitrary inline scripts/styles remain blocked. No XSS fuzz campaign was run. | Rich text was deliberately not implemented. |
| T13 | Resource exhaustion / malformed input | Body cap, source/line/count/depth caps, bounded lists, bounded model calls; no model call inside DB transaction | **Partial.** Oversized body and malformed source tests; no high-volume/soak test. | 100,000-record behavior is a configured limit, not a measured capacity claim. |
| T14 | Ollama redirect / non-loopback endpoint | Disabled by default; loopback-only validation; `_NoRedirect`; proxies disabled; response/time limits | **Offline-tested.** `tests/test_runtime_adapter.py` checks bounded transport contracts, invalid responses, no-call, all policy modes, budgets, outages and redirect refusal. No actual model inference. | Offline handler behavior is not actual model inference, model robustness or a live network measurement. |
| T15 | Case spoofing / external escalation | Explicit case creation with scoped findings/requests; immutable revisions; synthetic banner; `manual_export_only`; no external adapter | **Tested.** `test_case_scope_validation_rejects_foreign_findings`, revision conflict, export content and evidence-failure tests; E2E case/export flow. | A user can still label a synthetic case carelessly; UI makes the classification explicit. |
| T16 | Dependency drift / accidental publication | Pinned requirements and lockfile, `.gitignore`, `npm audit` clean, CI workflow with read-only permissions | **Partial.** Local install/build/audit pass; CI has not run. | No CI evidence, no signed artifacts, no fresh-checkout test after final changes until rerun. |

## Failure policy

- **Invalid proposal:** record a bounded rejection when audit is healthy; no execution. If audit cannot record, return failure and create no effect.
- **Corrupt/unavailable audit:** block mutations with `AUDIT_INTEGRITY_FAILED`; preserve read-only inspection and diagnostic verification. Never repair, regenerate a key over old history or show a green badge.
- **Expired/conflicting approval:** return current state or 409; require a new request after expiry, policy change or resource change.
- **Missing/changed evidence:** return an integrity error; do not silently reread a same-named file.
- **Model outage/invalid response:** fail the run or record no-call; never relax policy or synthesize success.
- **Rejected/failed case export:** fail closed if scope or evidence hashes no longer resolve; never silently drop selected evidence.
- **Process crash:** SQLite recovers committed rows. The current synthetic executor has no half-completed external operation.

## Claims that are supportable

| Claim class | Wording and boundary |
|---|---|
| Implemented | Synthetic ingest, immutable evidence, deterministic findings, four scripted scenarios, server policy, single-use approval, local receipt executor, HMAC chain/checkpoint, case revisions/exports and evaluation. |
| Automated-tested | 234 pytest tests and 12 subtests re-verified on 2026-10-21 (macOS/Python 3.11.15), including a 49-test independent audit suite (`tests/test_independent_audit.py`, see docs/FINAL_AUDIT.md); the analyst workflow passed in Chrome and Playwright WebKit against disposable databases. |
| Browser-tested | Six primary screens, detail routes, bootstrap gate, approve-once flow, exports, audit claims, keyboard skip/nav, 1024px and 390px layouts. |
| Synthetic only | Four authored agents; three binary policy-outcome labels plus one intentionally unlabeled; all telemetry and effects are authored. |
| Scripted enforcement | 7/7 deterministic checks passed. Not an LLM attack-success rate. |
| Actual local LLM | **None.** `local_model_observations.count = 0`; no model/version/result claim. |
| External integration | **None.** Manual synthetic export only; no Vigil API, packet capture, cloud model or account connection. |
| Production assurance | **Not provided.** No host-compromise resistance, multi-user RBAC, independent audit retention, network isolation, SLA, high-volume test or compliance certification. |
| CI | Workflow file exists, but **no CI run** is claimed. |

## Conditions for expanding scope

Real user/customer data requires consent, redaction, retention and deletion design. Real tools require process isolation, egress controls, independently retained audit and target-specific crash/recovery tests. Remote deployment requires authenticated identities, TLS, resource authorization and operational procedures. The current certification statement does not transfer to any of these.


## Continuation boundaries

Every audit append verifies integrity inside an explicit transaction; caller-only validation no longer leaves completion/failure paths uncovered. Finite-number, Unicode and nesting checks precede request normalization. The gateway enforces its own eight-proposal budget. Source reads are bounded and no-follow; unknown timestamps are preserved through case exports. Offline model failures are counted as attempts, not observations.

The CSP permits one exact attribute hash for WebKit's native `text-overflow:inherit` declaration. It does not enable arbitrary inline styles or scripts; browser tests exercise that restriction. WebKit engine checks do not replace native Safari or manual accessibility review.

Case Markdown/JSON preserve all selected evidence, including records outside the ordered timeline. CSV is an evidence table, not a complete case serialization. Source hashes verify captured bytes, not the authenticity or completeness of their original producer. Full database/key/checkpoint rollback remains undetectable on the same host.
