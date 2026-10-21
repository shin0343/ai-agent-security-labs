# AgentGuard baseline audit

Audit date: **2026-10-20**. Scope: actual local source, tests, fixtures and documentation, followed by isolated temporary-fixture probes. No product implementation or UI replacement was performed.

**Result:** existing suite **33 passed, 0 failures, 0 errors, 0 skipped** after excluding a conflicting Python environment. Additional probes found approval/state/audit consistency gaps the suite does not cover. Passing the suite is not a security certification.

## Reproducibility and working-tree context

- Environment: macOS 26.7, Darwin arm64; Python 3.11.2; stdlib SQLite 3.39.4. Successful baseline observed at approximately 18:32 UTC.
- Interpreter: `/Library/Frameworks/Python.framework/Versions/3.11/bin/python3`.
- Git HEAD: `8d205dd`; **HEAD is not the audited source snapshot**. At entry only README was tracked; README was already modified, and `agentguard/`, `tests/`, `docs/`, `examples/`, `pyproject.toml`, LICENSE and `.DS_Store` were untracked. No existing work was reset, staged or committed.
- [BASELINE_PROBES.md](BASELINE_PROBES.md) contains a runnable reproducer, captured output and SHA-256 hashes of 20 source/test/config/fixture files. It identifies the untracked runtime by content.
- No `.gitignore`, `.github/workflows`, lock file, frontend package, Ruff or type-checker configuration existed. README previously described ignored runtime state and offline CI as though present.
- Public primary documentation for SQLite transactions, Pydantic strict validation, FastAPI middleware and Vite was read to ground ADRs. The CLI web-reader route failed DNS resolution; built-in browsing supplied the official pages. No external application/account was connected and no remote state changed.

### Actual test executions

First command:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Result: exit 1, one unittest **loader error**, zero actual project test cases executed. Inherited `PYTHONHOME` selected a uv-managed Python 3.11.15 standard-library path while the executable was Python 3.11.2. Importing `tempfile → random → math` failed with `ModuleNotFoundError: No module named 'math'`. Inspecting `/usr/bin/python3` under the same setting also failed during initialization. This is an environment failure, not a gateway assertion failure.

Successful command, without global environment changes or installation:

```bash
env -u PYTHONHOME -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests -v
```

Captured summary:

```text
Ran 33 tests in 0.060s
OK
```

There are 31 `Lab` methods and 2 `OllamaOfflineMock` methods. Counts refer to methods, not subtest assertions. pytest was not configured or run in this phase.

### What the tests establish

| Area | Existing test evidence | Important uncovered boundary |
|---|---|---|
| Fixtures/evidence | Reproducible conn fixture, source ingest, exact refs, traversal/malformed/missing-source rejection | Immutable snapshots, nested schema, timestamps, content limits, real source formats |
| Detection | Data REVIEW 1.0, Helpdesk REVIEW 0.9, Docs UNKNOWN; explicit attribution caveat | Time/flow correlation, unrelated events, missing identity, unbiased evaluation |
| Gateway | Safe read, deny/monitor simulation, exact args, forbidden/unknown tools, unknown mode | Trusted principal/policy context, immutable request/resource versions |
| Approval | Reject, restart then approve once, unknown ID/nonboolean rejection | Separate instances/processes, expiry, stale policy, session identity, transaction failure |
| Audit | Happy chain, edited-record rejection on new Audit, metadata excludes args, key mode 0600 | Live tamper, missing/truncated history, effect/audit atomicity, completeness |
| Attack lab | Three proposals blocked under deny; three effects under monitor; boundary-aware zero proposals | Actual model response to payloads |
| Reports | UNKNOWN/source refs and evaluation artifact retained | Case persistence/scope, export injection, metric edge cases |
| Ollama | Mocked publish blocked; unsupported scenario rejected | Actual inference, redirects, malformed/bounded response, result content |
| UI/API | No HTTP/browser tests in suite | Runtime Host/Origin behavior, XSS regression, concurrency UX, accessibility |

## Files inspected and disposition

Line numbers refer to the unchanged source hashes in the probe artifact.

| Area | Decision | Evidence and preservation/replacement boundary |
|---|---|---|
| `gateway.py` 9–18 | **REUSE** | Exact tool names, keys and string values are reviewable fail-closed logic. Preserve behavior and fixed safe report. |
| `gateway.py` 23–83 | **REBUILD** storage/approval; **REFACTOR** policy | In-memory dict, per-instance RLock, JSON save, execute-before-audit. Extract pure decisions; replace state ownership/transactions. Public view hides args but prevents informed approval. |
| `audit.py` 5–40 | **REUSE** HMAC concept; **REBUILD** lifecycle | Canonical JSON/HMAC/private-key creation useful. Verification only in constructor, no cross-instance append lock, no expected head, no atomic effect linkage. |
| `hunt.py` 6–53 | **REFACTOR** | Allowlist/1-based refs useful; raw dict wrapping rather than normalized schema. Ref lookup rereads all files and resolves mutable content. |
| `hunt.py` 55–75 | **REFACTOR** rules; **REBUILD** correlation | Four hardcoded agents/destinations/weights; conn/DNS unused in scoring, no time/UID join. Preserve uncertainty wording and compatibility fixture. |
| `ollama.py` 5–36 | **REFACTOR**; live validation **DEFER** | Fixed localhost/proxy disable/max 3 turns/central gateway useful. Default redirects, unchecked shapes, no per-turn call limit, status-only tool results need work. No real run here. |
| `attack.py` 7–25 | **REUSE** scenarios; **REFACTOR** harness | Deterministic policy comparisons useful. `payload` is not interpreted; naive always proposes, boundary-aware never proposes. Not an LLM experiment. |
| `report.py` 7–19 | **REFACTOR** | Explicit labels/unknown and confusion counts useful. Hardcoded gold and fixture predictions, no holdout/error/abstention policy. F1 returns null for defined zero precision/recall. |
| `report.py` 21–42 | **REBUILD** case model; **REFACTOR** export | Good synthetic/uncertainty/manual-Vigil wording. Recomputes findings, includes all local requests, no case entity/revision, raw JSON in Markdown. |
| `ui.py` 10–61 | **REBUILD** | Embedded HTML/CSS/JS/HTTP server. Reuse security expectations as tests, not template. No separate investigation/trace/evaluation/case workflow; approval only tool/short ID. |
| `tests/test_security.py` | **REUSE**, extend | Keep all 33 behaviors; passing fixture tests do not cover race/crash/browser threats. |
| `seed.py`, `examples/logs/` | **REUSE**, extend separately | All eight files match generator; seven JSON-line sources hold 14 events, plus one text note. Reserved addresses/`.invalid`, no private data. |
| `__main__.py`, `__init__.py` | **REFACTOR** | Preserve CLI/package continuity. Move logic to services; automatic fixture generation should not hide missing input. |
| `pyproject.toml` | **REFACTOR** | Setuptools, Python >=3.10, no runtime/dev dependencies. Add >=3.11 target, locks and quality config in implementation. |
| README/docs/example case | **REFACTOR** | Preserve English narrative, Korean guide and synthetic/manual handoff limits. Correct unsupported state/CI claims; static example is not a fresh run. |
| External execution, Vigil API, real SOC ingestion, deployment | **DEFER** | No verified contracts, identity/isolation or recovery; not needed for local MVP. |

## Additional executed observations

The reproducible script has **13 observation groups**, not 13 new regression tests. It exercises original source and confines changes to temporary directories. Some observations intentionally demonstrate missing defenses; these are not “passing security tests.”

| ID | Observed result | Implication / target |
|---|---|---|
| B01 Fixture/evaluation | 14 events; eight fixture files match; TP=2, FP=0, TN=1, FN=0, UNKNOWN=1; P/R/F1=1.0 | Three known synthetic labels, functional fixture result, not real accuracy. P1/P5. |
| B02 Modes | Deny ALLOW/BLOCK/BLOCK; approve ALLOW/PENDING/BLOCK; monitor ALLOW/MONITORED/BLOCK; all chains valid | Preserve safe-tool behavior and simulated semantics. P2. |
| B03 Tail truncation | Two-event log reduced to first event; new Audit verify true | Prefix integrity does not prove completeness. P2/P5. |
| B04 Missing audit | Deleted temporary log with two persisted requests; new verify true | Empty-history success does not detect missing history. P2. |
| B05 Live tamper | Edited first event after gateway construction, then monitor publish: MONITORED, one receipt, verify false | Constructor verification does not stop subsequent effects on corrupt history. P2. |
| B06 Audit failure | Patched append raises OSError: one receipt, one saved request, zero audit events | Execution/state/audit not atomic. P2. |
| B07 Stale instances | Two Gateway objects each submit read: one persisted request, two audit events, valid chain | Lost JSON update; HMAC validity is not state consistency. P2. |
| B08 Conflicting decisions | Second gateway loads pending before first approves, then accepts REJECTED. Final rejected, one receipt, valid audit | Sequential stale-instance reproduction, not a timed multiprocess test. P2. |
| B09 Same-instance concurrency | Two threads approve through one Gateway: one APPROVED, one ValueError, one receipt | RLock works in this limited scope; preserve and extend. P2. |
| B10 Mutable evidence | Same `http.log:1` returned changed host after temporary edit | Capture immutable bytes/hash. P1. |
| B11 Nested schema | EventData=null causes AttributeError in hunt | Object-only validation is insufficient. P1. |
| B12 Correlation time | IDS timestamp moved to year 2000; Data score still 1.0 with IDS evidence | No time-window correlation; unrelated stale evidence boosts score. P1. |
| B13 Export | Markdown, evaluation JSON and CSV created; UNKNOWN/source ref retained | Useful export baseline, not persisted case/external delivery. P5. |

These controlled probes require application/storage access. They do not demonstrate remote compromise or real exfiltration.

## Additional source-review findings

- `Gateway.request` stores caller dict references and raw rejected args. `public()` omits args/result; analyst cannot review exact parameters, and model receives decision metadata instead of report content.
- `_event` records time/ID/tool/status/mode/argument digest, not actor/policy version, approval rationale or execution result. Results only exist in mutable request state.
- `Audit.append` rereads the chain without verifying; append/summary scale linearly with history. A JSON array entry can escape expected exception handling through `.get`. No capacity guarantee is justified.
- `hunt.analyze` treats source `approved`/`approved_scope` as fixture evidence, not trusted authorization facts for a general system. Build is always LOW even without supporting events.
- `export_case` instantiates Gateway and may create runtime/key state. It does not select incident scope. Current fixture strings are safe, but future arbitrary data requires escaping/redaction.
- `ui.py` checks Host, optional Origin and process token, limits JSON size, uses no-store/frame headers and textContent. It also permits inline scripts/styles, accepts per-request policy mode, caches findings at startup and uses single-threaded HTTPServer. These are inspected properties, not new browser test results.
- Ollama disables proxies, not redirects; bounds bytes, not proposal count; assumes nested response shapes. Its note is embedded in source; `untrusted_note.txt` is not read by this adapter or the attack harness.

## Scope and claim ledger

| State | Evidence |
|---|---|
| Implemented | Existing CLI, fixture rules, tool gate, fake outbox, JSON approvals, HMAC chain, export/dashboard. |
| Automated-tested | 33 unittest methods on this Mac; mocked Ollama only. |
| Additional observed | 13 probe groups and source hashes, with limits above. |
| Synthetic-only | Detection counts, scripted injections, telemetry, effects and incident draft. |
| Actual local LLM | **Not run.** No model performance/robustness claim. |
| External integration | **Not run/implemented.** Manual Vigil draft only; no capture, LogLM, cloud or service account connection. |
| Browser/UI | Source inspected; **no HTTP server, Playwright, pixel or accessibility test run in this audit**. Historical HTTP claims remain separate in VALIDATION. |
| Future | FastAPI/Pydantic/SQLite, React/TS/Vite, pytest/Playwright/quality tooling/Actions are target choices, not present features. |

## Documentation reconciliation and remaining risks

[VALIDATION.md](VALIDATION.md) retains the prior generated-build record as historical, not newly reproduced evidence. README links this audit/plan; nonexistent CI/ignore assets are labelled planned. Threat model distinguishes per-instance approval, live audit failure and truncation limits.

Before implementation, retain this snapshot by hash, choose tested dependency pins and keep legacy approvals inactive. Before claiming MVP completion, require P2 atomicity/concurrency, P1 immutable provenance and P3/P4 browser security gates. Host compromise and independent audit retention remain limitations after those gates pass.

## Design-phase completion checks

- All seven requested design documents are present; original learning material and historical validation context were preserved.
- A local Markdown check inspected 13 files and 37 local links: no missing targets, unclosed fenced blocks or trailing whitespace.
- SHA-256 comparison confirmed all 20 recorded source/test/config/fixture files are unchanged. Static test inventory still contains 33 methods; this inventory check is separate from the actual unittest run above.
- `git diff --check` passed. Since most files were initially untracked, the explicit Markdown/hash checks also covered material omitted from ordinary Git diff output.
- Deliverables added: `AGENTS.md`, `PLANS.md`, `docs/ARCHITECTURE.md`, `docs/ADR.md`, `docs/PRODUCT_SPEC.md`, `docs/BASELINE_AUDIT.md`, `docs/BASELINE_PROBES.md`. Existing documents revised: README, THREAT_MODEL, VALIDATION and PORTFOLIO.
- No dependency installation, product-source edit, service integration, repository push or deployment. Browser/E2E/lint/type-check tooling remains future implementation work, not a reported passing check.
