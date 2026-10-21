# Validation record

Date: **2026-10-20**. This records commands actually executed during continuation. The inherited implementation first passed 132 tests; additional boundary tests exposed failures before the corresponding fixes. The historical 33-test prototype audit remains in [BASELINE_AUDIT.md](BASELINE_AUDIT.md).

## Environment and isolation

| Item | Observed environment |
|---|---|
| Host | macOS 26.7, arm64 |
| Python / SQLite | 3.11.2 / 3.39.4 |
| FastAPI / Pydantic / Starlette | 0.138.2 / 2.13.2 / 1.9.0 |
| Node / npm | v22.23.1 / 10.9.8 |
| Browser tooling | Playwright 1.64.1, installed Google Chrome and Playwright WebKit 27.2 |
| Source state | HEAD `8d205dd`; implementation remains uncommitted, largely untracked |

The Makefile clears the inherited conflicting `PYTHONHOME` and `PYTHONPATH`. Tests use temporary databases. Browser checks start their own server at `127.0.0.1:8876` and recreate only `frontend/.e2e-run`; they do not attach to or reset a demo instance. Browser commands run sequentially because they share that isolated port/state directory.

## Setup and dependencies

Executed:

```bash
make setup VENV=run/setup-check/.venv
env -u PYTHONHOME -u PYTHONPATH run/setup-check/.venv/bin/python -m pip check
env -u PYTHONHOME -u PYTHONPATH run/setup-check/.venv/bin/python -m pip install -r requirements-dev.txt
```

A new project-local virtual environment was created; pinned dependencies installed, `npm ci` completed, and the UI built successfully. `pip check` reported no broken requirements. The resolved Python graph was captured in `constraints.txt` and the constrained install was rechecked. `npm ci` audited 188 packages and reported **0 vulnerabilities** at execution time. This is not independent supply-chain assurance.

The install emitted a maintenance notice for ESLint 9.38.0 and an available pip update. Those are not failed checks or measured security findings. No global Python packages, interpreter settings, accounts or services were changed. This verifies a fresh environment in this workspace, not a pristine macOS installation or a clean Git checkout.

## Full verification

```bash
make verify VENV=run/setup-check/.venv
```

Observed results:

| Gate | Result |
|---|---|
| pytest | **234 passed, 12 subtests passed** |
| Ruff check | All checks passed |
| Ruff format | 36 files already formatted |
| mypy | No issues in 20 source files |
| ESLint | No errors |
| TypeScript / Vite | Build completed |
| Chrome workflow | **1 passed** against a fresh database |

The 185 tests originally delivered included all 33 original regression tests. After the independent audit added `tests/test_independent_audit.py` (49 tests), the suite measures **234 passed with 12 subtests**. One upstream `StarletteDeprecationWarning` advises about `httpx`/TestClient; it remains visible and is not suppressed. Lint scopes the rebuilt package and tests, preserving the historical modules.

After the parser provenance identifier changed to `parser-2026.10.2`, the full Python suite was rerun. No historical database was rewritten or relabeled as newly parsed data. The final screenshots and isolated evaluation use newly imported evidence.

## Browser verification

```bash
make e2e-webkit VENV=run/setup-check/.venv
make screenshots VENV=run/setup-check/.venv
```

The analyst workflow passes in **Chrome and Playwright WebKit**. It covers:

- incorrect bootstrap code, valid single-use exchange and code-reuse rejection;
- actual Overview data and audit claims;
- finding, exact source/line/hash evidence, cited investigation revision;
- case creation, Markdown download and append-only revision;
- scripted proposal, exact-request review, approve once, terminal reload and separate receipt;
- evaluation, metrics and JSON/Markdown/CSV downloads;
- audit verification and case history;
- keyboard skip link/navigation, 1024px and 390px widths without page overflow;
- failed navigation to a different finding without retaining the old record;
- inert rendering of an HTML event-handler payload;
- an actual cross-origin browser form submission rejected with `UNTRUSTED_ORIGIN`;
- browser enforcement of CSP against arbitrary inline CSS and scripts.

Expected anonymous/wrong-code responses and the deliberately injected 503 are identified narrowly. The test fails on other console errors, page exceptions or 5xx responses. Browser failure tests use transport interception only inside the test; final product views read real API data.

WebKit originally failed the first link-focus assertion and reported CSP violations. A minimal native-select reproduction identified `text-overflow:inherit`; the application now permits only that exact attribute hash, while the browser test confirms arbitrary inline styles/scripts remain blocked. On macOS the test uses Option+Tab for full link traversal. WebKit traces retain actions and DOM snapshots without recorder screenshots that inject a `body {}` stylesheet. These findings and the narrow exception are documented in ADR-014.

**Native Safari was not run.** Playwright WebKit is a browser-engine check, not Safari certification. Firefox, manual VoiceOver and manual 200% zoom review remain unverified.

## Transaction and recovery evidence

`tests/test_transaction_recovery.py` executes:

- failures after synthetic result/receipt writes, trace writes and audit writes: approval, receipt, result, trace, audit and idempotency changes roll back together;
- two OS processes racing on the same approval: one commit, one conflict, one receipt;
- deliberate process exit after the synthetic effect but before commit: no committed partial state, approval still pending, audit healthy, subsequent approval succeeds once.

Additional tests cover thread races, expiry, cancellation, policy changes, full request rebinding, cross-resource idempotency, and mutable-state replay with a committed receipt retained. Audit tests cover record edits, malformed non-ASCII MACs, timestamp edits, middle/suffix/all deletion, reordering and missing/unsafe keys. An append itself refuses corrupt history.

These are targeted local recovery tests. No power-loss, arbitrary crash-point, disk-full or real external-effect recovery claim is made. Restoring the complete database together with its key/checkpoint is outside the detection guarantee.

## Evidence and model boundaries

`tests/test_independent_sources.py` authors a separate seven-source JSON corpus without the demo generator. It checks normalization, timezone offsets, fractional timestamps, original records and source/line/hash resolution. Invalid ports are rejected before SQLite insertion; missing or timezone-free times remain unknown. This is parser validation, not a held-out detector benchmark.

`tests/test_runtime_adapter.py` uses offline transport doubles against the rebuilt Ollama adapter. It tests valid no-call, Deny/Approve/Monitor, malformed/oversized responses, invalid call lists, proposal budgets, outages, redirect refusal and endpoint validation. A failed connection increments attempted runs, not observed-response runs.

**No real local-model inference was performed.** No model was downloaded or activated. Offline doubles run in disposable databases and do not contribute to the delivered evaluation. Runtime version/model digest are explicitly unknown until established by actual observation.

## Reproducible evaluation

```bash
make eval
make eval EVAL_DIR=run/eval-continuation
```

The second command initializes a separate current-parser dataset. Observed metrics:

```text
TP=2 FP=0 TN=1 FN=0
abstained=0 missing=0 errored=0 unlabeled=1
precision=1.0 recall=1.0 f1=1.0
proposals=7 synthetic_attack_attempts=6
blocked=3 approved=1 monitored=1 rejected=1
scripted checks=7/7
local model observations=0
audit integrity=valid, completeness=checkpoint_matched, consistency=ok
```

JSON, Markdown and CSV are generated under each runtime directory's `reports/` with mode 0600. The result includes versions, individual expected/actual rows, denominators, unknowns and limitations. These are tiny authored policy-outcome checks. They do not measure malicious intent, real detection accuracy, generalization or LLM attack success. The threshold display uses the same fixture.

## Screenshots and documentation

`make screenshots` recaptures 14 real full-page Chrome screenshots under `docs/screenshots/`. They show Overview, findings, investigations, evidence-linked decisions, case revision/export, policy, pending/committed approval, evaluation and audit. Generated IDs/times vary between captures. No fixture records or user runtime state were discarded to produce them.

The completion matrix, changes and remaining priorities are in [COMPLETION_REPORT.md](COMPLETION_REPORT.md). [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md) and [SCENARIOS.md](SCENARIOS.md) give reproducible paths and expected outcomes.

## Explicitly unverified

| Area | Status |
|---|---|
| Real Ollama inference/model robustness | Not run; zero delivered model observations |
| Native Safari / Firefox | Not run; Chrome and Playwright WebKit only |
| Manual accessibility certification | Not performed |
| Hosted CI / Linux | Workflow defined, not executed remotely |
| Pristine OS / clean-checkout install | Fresh local virtualenv verified; pristine host and published checkout unverified |
| Sustained load / maximum ingestion volume | Not measured |
| Power loss / disk corruption / arbitrary fault points | Not simulated |
| Independent audit retention / host compromise | Outside the local guarantee |
| Real external tools / Vigil API / account connections | Absent |
| Publication / deployment | Not performed |
