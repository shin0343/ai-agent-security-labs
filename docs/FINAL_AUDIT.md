# Independent Security & Engineering Audit — Final Report

Auditor stance: Principal Security Engineer / Staff Software Engineer / Product QA reviewer who did not design or implement the repository. This audit was performed on **2026-10-21** against the working tree as it stood at audit entry. Nothing in it relies on prior claims without re-executing them.

Scope of independent verification: all backend modules under `agentguard/workbench/`, the FastAPI application boundary, approval state machine, audit chain, evaluation pipeline, case/evaluation exports, the React frontend, the Playwright harness, CI definition, repository hygiene, and the claims in `README.md`. The audit installed its own virtualenv, ran the full suite, exercised the real server over HTTP, tampered with a live copy of the audit chain, recomputed evaluation metrics from persisted rows, and added a new independent regression suite.

**Result summary**

| Audit gate | State |
|---|---|
| Critical findings | 0 open |
| High findings | 0 open (1 found and fixed) |
| Medium findings | 0 open (2 found and fixed) |
| Low findings | 5 documented, not fixed (impact-bounded, recorded below) |
| Final judgement | **CONDITIONAL GO** (of the 10 gates in this audit, only deferred non-code gates remain open; see docs/RELEASE_READINESS.md) |

---

## 1. Can any execution path bypass the central policy gateway? — **No**

Verified independently:

- The only effect-producing code is `_execute_synthetic` in `agentguard/workbench/enforcement.py`; both call sites (`propose()` for `ALLOW`, `decide_approval()` after `approve`) run inside `BEGIN IMMEDIATE` transactions and only after `evaluate_proposal()` returned the corresponding decision.
- There is **no HTTP route** that submits a raw tool proposal. Adversarial probing of `/api/v1/propose`, `/api/v1/tool/call`, `/api/v1/executions`, `/api/v1/tools/read_report` returned 404; `/api/v1/runs` accepts only the strict literal scenario set (`normal`, `injection`, `overreach`, `boundary_aware`) with `Literal` types and `extra="forbid"` DTOs.
- Every mutation transaction first calls `require_audit_healthy()`; failed audit chain verification blocks the run with `AUDIT_INTEGRITY_FAILED` (reproduced live: after tampering audit seq 2 in a copied database, the server returned `503 AUDIT_INTEGRITY_FAILED` and the run was not created).
- Tools: only `read_report`, `publish_simulated` and the forbidden compatibility name `read_secret` exist; `read_secret` and unknown tools fail closed in every preset (live probe + generated code check for shell/network/secret adapters found none).
- Regression coverage: `tests/test_independent_audit.py::test_no_browser_reachable_proposal_route_exists`, plus the existing `test_policy_gateway.py` bypass matrix.

## 2. Can LLM output or external documents become system authority? — **No**

- The Ollama path (`agentguard/workbench/runtime.py::_execute_ollama`) parses model output into proposals only: tool name + arguments. Each proposal goes through the same `propose()` gateway call as scripted output. Malformed tool calls raise `MODEL_INVALID_RESPONSE`; the model observed flag is only set from real responses. Endpoints are loopback-validated (`validate_ollama_endpoint`), redirects/proxies disabled, 2 MiB bound. Not exercised with a real model — remains claim-free in the README.
- External documents: `untrusted_note.txt` is parsed with `parser_version="text-inert-v1"`, creates **zero** events, and never reaches detection or the gateway (asserted by `test_independent_audit.py::test_untrusted_note_is_inert_and_approval_claims_stay_untrusted`).
- Source-level `approved` claims stay telemetry: the Data-agent finding records "The approved flag is a source claim, not an authorization record", and no detection rule or gateway branch reads that flag for authorization.

## 3. Is a pending request safely frozen (parameters, policy, state) while awaiting approval? — **Yes, re-verified**

The immutable binding is `request_sha256(request_id, run_id, actor, tool, tool_schema_version, args, resource_ref, resource_hash, policy_preset_id, policy_version, expires_at)`. At decision time `decide_approval()` checks, inside one transaction: stored digest equals reviewed digest, `expected_version`, re-derived binding equals stored digest, re-evaluated policy still maps to `REQUIRE_APPROVAL`, re-derived resource hash matches, run is still `WAITING_APPROVAL`, and the row is consumed with `AND expected_version = ?`. Live probes on the running server confirmed: wrong digest → `REQUEST_DIGEST_MISMATCH` (still PENDING), wrong version → `STALE_VERSION` (still PENDING), policy change mid-wait → approval becomes `INVALIDATED` and a late decision is refused. `propose()` refuses new proposals while the run is `WAITING_APPROVAL`.

## 4. Concurrency, approval reuse, server restart — **No defect reproduced**

- Two processes racing on one approval produce exactly one commit and one conflict (existing `test_transaction_recovery.py` re-executed).
- Idempotent replay with the same key returns the stored response; a different body on the same key is `IDEMPOTENCY_BODY_MISMATCH`; a fresh key after consumption is `409 Approval is no longer pending`; receipts stay at 1 (`test_independent_audit.py::test_hostile_approval_sequence_leaves_one_commit`).
- Idempotency keys are scoped per session: two different local operator sessions may reuse one key value for different approvals without crosstalk (`test_idempotency_keys_are_scoped_per_session`).
- Restart: the approval expiry recheck is evaluated on every decision from stored state (`parse_iso(expires_at) <= now`), so restart cannot resurrect a dead approval; audit key/chain/checkpoint are re-verified on restart by `initialize()`. A restart-mid-approval scenario is covered by the write-failure/exit-injection tests.

## 5. Sensitive-data exposure through logs, API or exports — **No egress found**

- Audit payloads never contain argument bodies: tool decisions store `args_digest` only; approval decisions store `reason_sha256` (asserted by the original `test_audit_metadata_excludes_argument_bodies`, still passing).
- Pending/blocked/garbage proposals store an empty argument object; the registry-restricted values (`quarterly-synthetic`, `demo-internal-outbox`) are the only strings that reach stored arguments.
- Case/evaluation exports carry synthetic classification, `manual_export_only` integration status and no external IDs; CSV cells are formula-guarded (`=+-@\t\r` prefix) and Markdown output is escaped.
- Systematic secret scan (key patterns, `BEGIN`, passwords, API keys), personal-name/IP scans over code, docs, fixtures and tests found nothing; telemetry IPs are RFC 5737 TEST-NET documentation addresses; no personal data exists anywhere in the repository. `run/` (DB, audit key, reports, session rows) is fully gitignored and verified with `git check-ignore`.

## 6. What does audit integrity actually guarantee, and not guarantee? — **Claims match the code**

- Reproduced (live): payload tamper of retained event seq 2 → `verify_audit` reports `integrity=invalid, first_failure_seq=2`, `safe_for_mutations=false`, and mutations fail with `AUDIT_INTEGRITY_FAILED`.
- Reproduced (live, on a copied DB): an attacker who deletes the tail **and rewinds the checkpoint using the key** obtains `checkpoint_matched` — this is exactly the documented out-of-threat-model limit ("A local HMAC chain is not independent audit storage"; host-compromise failing mode). The valid-chain message honestly carries the same disclaimer ("not independent tamper-proof storage"), asserted in `test_audit_tamper_blocks_mutations_and_honest_valid_chain_message`.
- Deletion/reorder/key-failure/perm checks remain covered by `tests/test_audit.py`.
- The HMAC key and DB live in the same runtime directory, so simultaneous replacement is not detectable by design; no independent retention exists (documented deferred gate).

## 7. Do detections overstate intent? — **No verdict is asserted without bounded evidence**

Each detection branch (`detection.py`) emits: supporting facts with exact `file:line` + SHA-256, contradicting facts (e.g. "HTTP 202 … does not prove the payload was accepted"), unknowns, attribution limitations for every correlation edge (time-proximity edges explicitly labelled "not proof that the agent generated the flow"), and limitations stating that absence of a rule match is not a security clearance. The `docs` agent stays `UNKNOWN` and untitled in evaluation (`gold=None → UNLABELED`, excluded from metrics). Audit question 7: **no** intent claim exceeds evidence in code or UI text.

## 8. Real-model results vs scripted fixtures — **Correctly separated**

- The evaluation suite is hard-coded `scripted`; `run_evaluation(runtime_kind != "scripted")` raises. `local_model_observations.count=0`, `included_in_metrics=false`, with the "No local model run is part of this suite" note asserted by tests.
- The scripted enforcement note states "not natural-language model susceptibility".
- The bundled numbers were **recomputed independently** from persisted `evaluation_results` rows (not from README): one evaluation yields TP=2, FP=0, TN=1, FN=0, unlabeled=1, all 7 enforcement checks PASS — matches the README exactly. Historical databases can accumulate older runs; every run is separately identified (`evaluation_id`) and the report/UI render per-run, so no aggregation error exists.

## 9. UI dead buttons, decorative features, misleading indicators — **None found**

- Greps over `frontend/src` found no `href="#"`, no no-op handlers, no `console.log`/TODO debug surfaces; `dangerouslySetInnerHTML` does not exist.
- The approval UI disables submission from server state (`pending` derived from `data.state`, `expired` from server timestamps), surfaces audit-blocked state (`mutationBlocked`) instead of a dead button, and never offers a forced override on conflict.
- Screens show server data only; badges map every status string the backend can emit (including `INVALIDATED`, `ABSTAINED`, `UNLABELED`); the Overview audit claims present integrity/completeness/consistency as three honest separate claims.

## 10. Are README claims backed by implementation? — **Two inconsistencies found and fixed**

- **Fixed:** "constraints.txt pins the resolved Python graph" was not enforced by any install path (`make setup`, both CI jobs). Now every Python install step passes `-c constraints.txt` (Makefile + `ci.yml`), reverified locally (`pip install -r requirements-dev.txt -c constraints.txt`, `pip check` clean, full suite green).
- **Verified as-is:** measured table (tests, browser engines, `npm audit` 0 vulns — re-run today, 0 again), synthetic metrics (recomputed), 7/7 enforcement checks, no-live-model claim, screenshots exist and are real captures, E2E deletes/recreates `frontend/.e2e-run` (confirmed in `tests/e2e_server.py` + `playwright.config.ts`), loopback-only binding enforced in `Settings.__post_init__`.

---

## Findings register

### F-1 (Medium, fixed) — Python dependency graph was not pinned in executed installs
- **File/position:** `Makefile` (`setup` target), `.github/workflows/ci.yml` (backend `Install dependencies`, e2e `Install Python dependencies`).
- **Reproduction:** `make setup` ran `pip install -r requirements-dev.txt` with no constraint file; CI did the same, so "constraints.txt pins the resolved Python graph" (README) was unenforced on every fresh install.
- **Impact:** future upstream releases (e.g. a new FastAPI/Pydantic minor) could silently change behavior of the security boundary code between the day of audit and a later clone; README claim unsupported.
- **Fix applied:** added `-c constraints.txt` to `make setup` and to both CI install steps.
- **Fix verification:** constrained install succeeded with zero version drift; `pip check` clean; `make verify` (build+test+lint+E2E) green; final suite 234 passed / 12 subtests.
- **Regression test:** the constrained install itself is the gate; `pip check` in VALIDATION runbook.

### F-2 (Medium, fixed) — Markdown export code-span breakout via backticks
- **File/position:** `agentguard/workbench/cases.py::_md_escape` (all Markdown export positions).
- **Reproduction:** analyst-supplied text containing a backtick in analyst summary/conclusion/recommendation passed through backslash-escaping (`\``). Inside a CommonMark code span a backslash is literal, so the backtick still terminated the span and the remaining text rendered as Markdown (`[audit-exfiltration](https://attacker.invalid/)` reproduced programmatically before the fix). Code spans carrying such values exist in export templates (`- Parameters: \`…\``, head digest, etc.).
- **Impact:** an exported case opened in any Markdown renderer (GitHub, docs viewer) could have executed link/image injection from recorded text — misleading click targets in a security-relevant report. Bounded in practice: single local operator, values are analyst-authored, but exports are external-facing artifacts.
- **Fix applied:** `_md_escape` now replaces backticks with apostrophes outright (with code-comment rationale); pipe/`<`/`>` escaping unchanged.
- **Fix verification:** new test `tests/test_independent_audit.py::test_markdown_export_neutralises_backticks_in_every_code_span` proves no second backtick can appear inside the Parameters code span and the breakout payload is neutralized while remaining auditable; full suite green.
- **Regression test:** as above.

### F-3 (Low, documented, not fixed) — Session rows are never garbage-collected
- **File/position:** `agentguard/workbench/sessions.py` (`create_session` inserts; `revoke_session` is not exposed by any route and no cleanup job exists).
- **Impact:** the `sessions` table grows by one row per successful bootstrap exchange; because the bootstrap code is single-use per server start, real growth is bounded by number of server restarts (≈1 row/start; playbook restarts are manual). No security impact; mild storage growth only.
- **Direction:** a startup-time cleanup that deletes sessions expired beyond a retention window would suffice.

### F-4 (Low, documented, not fixed) — Audit verification cost is O(events) per mutation
- **File/position:** `agentguard/workbench/audit.py::require_audit_healthy` walks the full chain on every mutation transaction.
- **Impact:** correct and simplest for an MVP; on a long-lived deployment the verification time grows linearly with the retained chain. No boundary bypass; a failure of completeness or integrity still fails closed.
- **Direction:** incremental checkpoint resync (e.g., verify-on-append of head-segment only, with periodic full verification) — deliberately deferred; documented as a remaining gate in PLANS.md ("Independent audit retention / sustained load").

### F-5 (Low, documented, not fixed) — Duplicate `_session_valid` helpers with divergent error codes
- **File/position:** `agentguard/workbench/enforcement.py::_session_valid` raises `ForbiddenError`; `cases.py`/`investigations.py` local copies raise `NotFoundError` for the same invalid-session condition.
- **Impact:** inconsistent API shapes for the same state (403 vs 404) depending on which endpoint is hit; no authorization effect (all fail closed).
- **Direction:** route all three call sites through `sessions.resolve_session` semantics or a single shared helper.

### F-6 (Low, environment, not a product defect) — This audit machine's system Python 3.11.2 framework install is broken
- `unicodedata` (a stdlib C extension) is missing from the macOS framework Python on this host, which corrupted the pre-existing `.venv` (mixed interpreter/config). The audit recreated `.venv` with Python 3.11.15 and validated the complete stack. The workbench itself is unaffected on healthy environments (`Settings` only requires 3.11+; CI installs 3.11 fresh). Recorded so the next operator is not surprised by a mismatched `pyvenv.cfg`.

### F-7 (Low, documented, not fixed) — Expired-badge timestamp comparisons are string-based
- **File/position:** `api.py` approvals list/detail compute `expired` as `expires_at < utc_iso()` (plain string compare) while `enforcement.py`/`sessions.py` use `parse_iso`.
- **Impact:** present schema always writes the same five-precision UTC `Z` format, so ordering is correct; the risk is only if a foreign database with a different timestamp format were attached. No current exposure.

---

## Mandatory verification gates executed during this audit

| Gate | Command/evidence | Result |
|---|---|---|
| Baseline vs current regeneration | `.venv` recreated with Python 3.11.15 + pinned deps; `pytest -q` on entry suite | 185 passed / 12 subtests pre-audit (matches README) |
| Independent security regression suite | new `tests/test_independent_audit.py` (49 tests) | all pass; suite now **234 passed / 12 subtests** |
| API permission & input boundary | parametrized 401/403 matrix over all 14 mutating routes; forged cookie; no-CSRF with valid session; duplicate-key JSON; `Origin: null`; `Sec-Fetch-Site: cross-site` | all rejected as designed (401/403/415/400) |
| Approval state machine | hostile digest/version/session/expiry/policy-change/idempotency sequence via live server + tests | single-use holds; run cannot be re-proposed during WAITING_APPROVAL |
| Prompt-injection defence | scripted `injection` under all three presets + untrusted-note inertness | BLOCK/REQUIRE_APPROVAL/MONITOR behave as presets; note never becomes events or authority |
| Audit tamper & recovery | payload tamper + suffix deletion (with key) on live DB copies | tamper detected, mutations fail closed; key+checkpoint rewrite matches documented limit |
| Synthetic evaluation recompute | independent recompute from `evaluation_results` + `python -m agentguard workbench-eval` | TP=2/FP=0/TN=1/FN=0/unlabeled=1; 7/7 PASS; integrity valid — README numbers exact |
| Frontend review | source read (no dead buttons/no innerHTML/no fake streams) + Chrome & WebKit Playwright runs | both pass after backend changes |
| E2E in real browser | `make e2e` and `PW_ENGINE=webkit npm run test:e2e` | 1 passed each |
| CI vs local consistency | compared `.github/workflows/ci.yml` vs Makefile; then unified constraint gate | consistent installs; F-1 fixed |
| Dependency & security config | `ruff`, `ruff format --check`, `mypy`, `eslint`, `tsc -b`, `npm audit` | clean; 0 npm vulnerabilities (re-verified 2026-10-21) |
| Repository hygiene | secrets/PII scans, `git check-ignore` on runtime artifacts, `git status` review | no secrets or PII; runtime files ignored; no stray committed artifacts |
| Full verification chain | `make verify` | passed end-to-end |

## Out-of-scope / unchanged gates

- Hosted CI has still never run on GitHub (no push performed, per task authorization).
- Ollama remains unexercised with a real model (transport tests only).
- Native Safari/VoiceOver/200% zoom manual accessibility review still open.
- Sustained-load, disk-full and power-loss campaigns remain open (PLANS.md gates).
- No commit, push, tag or deployment was performed as part of this audit.

## What changed in the repository

| Change | File |
|---|---|
| Backtick neutralization in Markdown export escape | `agentguard/workbench/cases.py` |
| Constrained Python installs (`-c constraints.txt`) | `Makefile`, `.github/workflows/ci.yml` |
| New independent audit suite (49 tests) | `tests/test_independent_audit.py` |
| Measured numbers updated post-audit | `README.md`, `docs/VALIDATION.md`, `docs/THREAT_MODEL.md`, `docs/PORTFOLIO.md`, `docs/COMPLETION_REPORT.md`, `docs/ADR.md` |
| Audit conclusions | `docs/FINAL_AUDIT.md` (this file), `docs/RELEASE_READINESS.md` |

No test was removed, skipped or weakened. No security condition was loosened. No dependency was added or removed.
