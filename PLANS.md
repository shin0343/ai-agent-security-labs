# Agent Security Workbench delivery plan

Status: **local synthetic MVP complete**, 2026-10-20. This continuation supersedes the former design-only restriction for local implementation. The user authorized implementation, tests, browser verification and documentation. External account connections, push and deployment remain outside scope.

The working tree was already modified and largely untracked at entry. Existing implementation, fixtures and the 33 original regression tests were preserved. Nothing was reset, staged, committed, pushed or deployed.

## Completed vertical slices

| Slice | Code and workflow | Validation gate |
|---|---|---|
| Foundation | Modular FastAPI/SQLite backend, strict DTOs, checksummed migration, sample bootstrap, Make targets, locked dependency graph | Fresh local virtualenv setup, constrained reinstall and pip check pass |
| Evidence → findings | Seven JSON parsers plus inert note, bounded no-follow reads, source snapshots, exact references, versioned rules, uncertainty and correlation | Independent parser corpus, malformed input, symlink/hash/size checks, retained original regressions |
| Proposal → approval → receipt | Server presets, exact argument registry, complete request binding, session/expiry/resource/policy checks, central budget, scoped idempotency | Binding changes, rejection/expiry/replay, thread and OS-process races, write-failure rollback and process-exit recovery |
| Audit boundary | Transaction-required append, full chain/checkpoint precondition, signed timestamp consistency, separate claims | Edit/deletion/reordering/key failures, direct corrupt-history append refusal, fail-closed mutations |
| Analyst UI | Six React/TypeScript screens, evidence links, verdicts, traces, exact-request approval, loading/empty/error/success states | Chrome and Playwright WebKit workflow, API failure navigation, XSS/CSP/hostile-origin checks, keyboard and responsive layouts |
| Cases and evaluation | Scoped immutable case revisions, full Markdown/JSON and evidence CSV, unknown-time retention, separate detection/enforcement/model categories | Evidence-complete exports, metric edge cases, 7/7 scripted checks, reproducible private reports |
| Developer/portfolio package | English README, architecture, threat model, ADRs, validation, walkthrough, scenarios, screenshots, resume bullets and CI definition | Full verify passes, 185 Python tests and 12 subtests, 14 real screenshots; hosted CI remains unrun |
| Independent audit (2026-10-21) | `tests/test_independent_audit.py` (49 tests), constraint-gated installs in Makefile/CI, export backtick hardening, live tamper/boundary probes, README claim re-verification | Suite now **234 passed + 12 subtests**; `make verify` green in Chrome and WebKit; findings and verdict in docs/FINAL_AUDIT.md and docs/RELEASE_READINESS.md (**CONDITIONAL GO**) |

## Continuation corrections

The inherited 132 tests passed before new probes were added. Reproduced failures led to full approval-binding/policy rechecks, approval-scoped idempotency, append-owned audit verification, strict JSON/Origin handling, timestamp/port fixes, truthful model observation counts, keyed frontend resource state and evidence-complete exports. A minimal browser reproduction justified one narrow WebKit native-style hash exception. See ADR-011–ADR-014.

Parser provenance is `parser-2026.10.2`; the scripted suite is `suite-2026.10.2`. Older stored snapshots keep their original metadata and are not silently reprocessed.

## Executed completion gates

```bash
make setup VENV=run/setup-check/.venv
make verify VENV=run/setup-check/.venv
make e2e-webkit VENV=run/setup-check/.venv
make screenshots VENV=run/setup-check/.venv
make eval
make eval EVAL_DIR=run/eval-continuation
```

Python regressions, Ruff/format, mypy, ESLint, strict TypeScript/Vite build, Chrome workflow and Playwright WebKit workflow pass. Dependency setup reports no broken Python requirements and npm's point-in-time audit reports zero vulnerabilities. Exact evidence and warnings are in [docs/VALIDATION.md](docs/VALIDATION.md).

Synthetic evaluation: TP=2, FP=0, TN=1, FN=0, one unknown/unlabeled agent; 7 total proposals, 6 risky proposals, 3 blocked, 1 approved, 1 monitored and 1 rejected. These are authored policy-outcome checks, not real detection accuracy or model attack-success rates.

## Remaining gates and priorities

| Gate | Status / required evidence |
|---|---|
| Hosted CI | Workflow defines Python, frontend and Chromium/WebKit jobs; not run on GitHub |
| Commit, push, deployment | Not performed; implementation remains uncommitted |
| Actual Ollama | Adapter tested offline only; no model downloaded/activated, no actual inference |
| Native Safari / Firefox | Not run; Playwright WebKit is not native Safari certification |
| Manual accessibility | VoiceOver and 200% zoom review remain unverified |
| Pristine host / clean checkout | Fresh environment in this workspace verified; pristine OS and clean published checkout unverified |
| Sustained load and capacity | Not measured; limits are enforced defaults, not performance guarantees |
| Broader failure matrix | Selected write failures and pre-commit process exit tested; no disk-full/power-loss campaign |
| Independent audit retention | Deferred; replacing local database/key/checkpoint together remains undetectable |
| Real effects / Vigil | Deliberately absent; requires separate isolation, recovery, API-contract and authorization design |

## Verification policy

Do not infer model observations from offline doubles, present synthetic metrics as generalized accuracy, call local HMAC storage tamper-proof, or claim hosted CI passed from a workflow file. Keep runtime data, keys, sessions and generated reports out of version control. Review [docs/COMPLETION_REPORT.md](docs/COMPLETION_REPORT.md) before publication.
