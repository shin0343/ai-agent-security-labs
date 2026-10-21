# Portfolio notes and interview narrative

The rebuilt **Agent Security Workbench** is implemented locally. The historical baseline is retained in [BASELINE_AUDIT.md](BASELINE_AUDIT.md); measured rebuilt results are in [VALIDATION.md](VALIDATION.md) and the delivered/deferred matrix is in [COMPLETION_REPORT.md](COMPLETION_REPORT.md).

## Resume bullets

> Rebuilt an offline-first **Agent Security Workbench** (FastAPI, SQLite, React/TypeScript) that correlates synthetic Zeek, Suricata, Windows and agent telemetry into evidence-linked findings and enforces server-owned tool policy with session-bound, expiring, single-use approvals.

> Verified the system with **234 backend tests, 12 subtests and the analyst workflow in Chrome and Playwright WebKit**, including approval races, idempotent replay, evidence mutation, audit truncation, scoped-case exports and responsive keyboard navigation; all runtime effects remain synthetic and local.

These bullets are supportable for this working tree. Do not add “deployed,” “production,” “real intrusion detection,” “LLM attack resistance,” “tamper-proof audit,” “multi-user,” or “CI green” without new evidence.

## 60-second interview story

**Problem:** Agent security has two evidence problems at once. Logs and retrieved text can influence an agent, but they cannot prove who acted or whether an effect occurred. And a model proposing a tool call must not be confused with authority to execute it.

**Design:** I built a local workbench that captures synthetic source bytes with hashes and exact `file:line` references, derives explainable findings with explicit unknowns, and lets a scripted runtime propose only registered tools. A server-owned policy preset decides allow, block or approval. Approval is bound to one immutable request digest, policy version, resource hash, operator session and expiry. The receipt, result and HMAC audit event commit in one SQLite transaction. Cases are separate revisioned records with scoped exports.

**Verification:** The backend has 234 tests plus 12 subtests (including the 49-test independent audit suite) covering process recovery, persistence failure and evidence mutation, malformed input, tool bypass, approval races/replay/expiry, audit tampering/truncation and export safety. A Playwright workflow drives the real UI through bootstrap, evidence, verdict, case, approval, evaluation and audit. The synthetic fixture reports TP=2/FP=0/TN=1/FN=0 with one unlabeled agent, but I explicitly do **not** present that as real detection accuracy.

**Honest boundary:** The audit key and checkpoint are local, so this is not independent retention. Real external tools, multi-user auth, CI execution, high-volume behavior and an actual Ollama run are deferred. The optional model adapter exists but has zero observations; the reproducible demo is scripted.

**Next engineering step:** Run CI from a clean checkout, capture one clearly versioned local Ollama observation, and only then consider isolated execution adapters. Real effects need a new recovery design for `UNKNOWN_OUTCOME`.

## Claim discipline

| Category | Evidence |
|---|---|
| Implemented | Local synthetic workbench: ingest, detection, investigations, scripted runtime, policy/approval, audit, cases, evaluation, React UI |
| Automated-tested | 234 pytest tests + 12 subtests; Ruff/format/mypy/ESLint/build pass |
| Browser-tested | Analyst workflow in Chrome and Playwright WebKit against fresh databases; 14 real Chrome screenshots |
| Synthetic-only | All telemetry, agents, findings, effects, metrics and cases |
| Actual local model | **None**; `local_model_observations=0` |
| External integration | **None**; manual synthetic export only |
| CI | Workflow exists, **not executed** |
| Deployment | **None**; loopback-only, uncommitted |

## Interview prompts to prepare for

1. **Why one SQLite transaction?** Because the MVP effect is a local receipt. That makes approval consumption, receipt, result, audit and idempotency atomic. It would not solve an external side effect; that needs durable intent and outcome reconciliation.
2. **Why is the audit not tamper-proof?** The key and checkpoint share the host. HMAC detects retained-record edits and local truncation relative to the checkpoint, not an administrator replacing DB/key/checkpoint together.
3. **Why show detection metrics at all?** To demonstrate denominator handling, unlabeled/abstained buckets and report provenance — not to claim accuracy on three labels.
4. **What did the race test actually prove?** Thread and separate-process approval races produced one commit and one conflict. Injected write failures and a process exit before commit left the approval pending without a committed receipt. These tests do not simulate power loss or real external effects.
5. **What remains before real use?** Independent audit retention, authenticated multi-user identity, process isolation/egress controls, external-effect recovery, load/fault testing and an actual model evaluation.

## Showcase checklist

- [x] README with scope, quick start, architecture diagram and measured results
- [x] Six-screen React workflow with real screenshots
- [x] Reproducible scripted demo without Ollama or external services
- [x] Security-boundary and limitations documentation
- [x] Local test/lint/build/E2E evidence
- [ ] GitHub Actions run on a hosted runner
- [ ] Commit/push and repository visibility decision
- [ ] Optional screen recording
- [ ] Optional actual local Ollama observation with model/runtime metadata

## Potential extensions

1. Expand recovery validation to disk-full and power-loss scenarios; existing write-failure/process-exit tests cover narrower cases.
2. Version-pinned real Ollama observation with model digest, hardware, repeated runs and a failure taxonomy.
3. Safe read-only import adapters for user-owned sanitized telemetry.
4. Independently retained audit head or user-exported checkpoints.
5. Consented Vigil integration after inspecting a test environment and API contract.
6. Process-isolated executor with egress controls and idempotent external operations.
