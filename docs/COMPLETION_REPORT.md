# Local implementation completion report

Date: 2026-10-20. Scope: the existing working tree, continued from the interrupted implementation. This is a local synthetic MVP. It has not been committed, pushed, deployed or connected to an external SOC.

## Delivered system

The workbench supports a complete analyst workflow: captured source records → deterministic findings → evidence review → investigation verdict → scripted or optional model proposal → deterministic policy → one-time approval → local synthetic receipt → audit verification → scoped case export.

One FastAPI application serves `/api/v1` and the built React/TypeScript frontend. SQLite stores evidence snapshots, findings, investigations, runs, requests, approvals, synthetic execution results, audit records, case revisions and evaluations. The default runtime is scripted. No model installation is needed for the demo.

| Requested phase | Delivered behavior | Boundary or remaining work |
|---|---|---|
| Backend foundation | Modular services, strict Pydantic request contracts, checksummed SQL migration, SQLite transactions, reproducible sample import | One local operator and one application; no remote deployment or multi-user identity |
| Evidence hunting | Zeek conn/dns/http/ssl JSON, Suricata EVE JSON, Windows event JSON and agent-action JSON; immutable bytes, source/line/hash, explicit unknowns | These are bounded synthetic JSON formats, not universal Zeek TSV/XML/EDR importers |
| Gateway | Deny/Approve/Monitor, exact allowlists, central proposal budget, immutable request review, transactional single-use approval | Only fixed synthetic reads and local receipt rows can execute |
| Agent runtime | Four scripted scenarios; optional loopback Ollama transport; explicit no-call, invalid-response and outage results | Real Ollama inference not run; runtime/model digest remains unknown until independently established |
| Dashboard | Six primary screens and linked detail views with API data and loading/empty/error/success states | Desktop and narrow viewport checks are automated; no manual accessibility certification |
| Audit and cases | HMAC chain/checkpoint, separate claims, case revisions, Markdown/JSON and evidence CSV exports | Host compromise and joint database/key/checkpoint rollback remain outside the guarantee; Vigil is manual export only |
| Evaluation | Confusion matrix, precision/recall/F1, abstention/missing/error/unlabeled buckets, threshold diagnostics, enforcement counts, JSON/Markdown/CSV | Four authored agents and three binary labels; no generalization or model-robustness claim |
| QA | Preserved regressions, boundary failures, thread/process races, injected persistence failures, process termination recovery, browser workflow | No power-loss, disk-corruption, sustained-load or arbitrary crash-point campaign |
| Developer experience | Make targets, pinned dependencies, CI definition, documentation, screenshots, scenarios and resume bullets | Hosted CI and a pristine operating-system install are not claimed |

## Changes made during continuation

The inherited 132-test suite, lint and build passed before changes. Additional probes demonstrated gaps that those checks did not cover. The fixes preserve the existing fixture, legacy regression suite and modular architecture.

1. **Approval binding.** Decisions now recompute the entire stored request binding, compare argument/resource/schema hashes and re-evaluate the current policy semantics. Changed policy content, target, actor or schema invalidates the approval. Expiry/invalidation also finishes a waiting run. Idempotency includes the approval URL's resource identity.
2. **Audit append boundary.** Every append requires an explicit transaction and verifies the retained chain and local checkpoint. An earlier caller-level check is insufficient. Verification also compares the displayed timestamp with its signed payload; malformed retained payloads remain inspectable as invalid data.
3. **Input handling.** JSON rejects numeric overflow, duplicate keys, invalid Unicode and excessive nesting. Origins must match the actual allowed Host. Unexpected API errors keep security headers and bounded error bodies. Non-loopback server configuration is refused.
4. **Evidence parsing.** Reads use bounded file descriptors with no-follow checks. Port values are bounded before SQLite insertion. Timestamp fractions are retained; missing/timezone-free times stay unknown. An independent seven-source corpus validates parsers without reusing the demonstration generator.
5. **Ollama outcomes.** Malformed calls fail explicitly; calls and responses have budgets. A failed connection is an attempt, not an observed model response. Valid tool proposals use the same gateway and never gain approval authority.
6. **Evaluation denominators.** Enforcement counts come from this suite's committed requests. Six risky synthetic proposals are distinguished from seven total proposals and from pure policy-validator probes. Model attempts and observed-response runs are separate and scoped to the selected dataset.
7. **Frontend state.** Loading a different resource cannot retain the previous resource's evidence or approval form. Failed refreshes can retain data only for the same resource. Approval review state resets when the approval changes; expired pending approvals display their expiry correctly.
8. **Case completeness.** Unknown-time evidence remains in exports outside the ordered timeline. JSON and Markdown retain all selected records, and CSV includes each selected evidence reference rather than only the first.
9. **Browser compatibility.** A minimal WebKit reproduction isolated its native select declaration, `text-overflow:inherit`, as a CSP exception. Only that exact attribute declaration is hash-allowed; arbitrary inline CSS and all inline scripts remain blocked. The browser workflow checks those restrictions directly.

The design rationale is recorded in [ADR.md](ADR.md). Historical prototype findings in [BASELINE_AUDIT.md](BASELINE_AUDIT.md) remain historical evidence.

## Screen status

| Screen | Verified actions |
|---|---|
| Overview | Dataset scope, persisted counts, attention, coverage and separate audit claims |
| Investigations | Finding → exact evidence → timeline → cited verdict revision; unknown and failed-source states |
| Agent traces | Scripted normal/injection/overreach/no-call runs; proposal, policy and execution states |
| Policy & approvals | Exact argument/resource/digest review, approve once, terminal reload; backend rejection/expiry/invalidation/races |
| Evaluation | Baseline run, metrics and denominators, enforcement outcomes, three downloadable formats |
| Audit & cases | Verification, case creation/revision, selected evidence and local exports |

Chrome and Playwright WebKit run the analyst workflow. Native Safari, Firefox, VoiceOver and manual zoom review were not run. WebKit engine testing is not native Safari certification. Documentation screenshots come from the actual Chrome workflow.

## Validation and evaluation

See [VALIDATION.md](VALIDATION.md) for exact commands and limitations. The Python suite reports **234 passed and 12 subtests passed after the independent security audit on 2026-10-21** (185 at delivery, including all 33 original regression tests). Ruff, formatting, mypy, ESLint and the TypeScript/Vite build pass. The browser workflow covers error navigation, inert XSS text, cross-origin form rejection, CSP, keyboard navigation and responsive widths in addition to the analyst flow. The audit's findings and resolutions are in [FINAL_AUDIT.md](FINAL_AUDIT.md).

Synthetic detection: **TP=2, FP=0, TN=1, FN=0; one unknown/unlabeled agent; no known-label abstentions, missing predictions or errors.** Conditional precision/recall/F1 are 1.0 on this authored fixture. The suite records **7 total proposals, 6 risky synthetic proposals, 3 blocked, 1 approved, 1 monitored and 1 rejected**, plus one safe read. Seven scripted enforcement checks pass. The local audit reports retained-chain integrity `valid`, checkpoint `matched` and consistency `ok`.

These are policy-outcome checks, not probabilities of malicious intent or estimates of real detection quality. Threshold comparisons reuse the same fixture. Actual model observations are zero in the delivered default demo; offline adapter tests use temporary databases and are not combined with the evaluation.

Generated evaluation reports stay under `run/eval/reports/` and are gitignored. Recreate them with `make eval`; do not commit databases, session material, audit keys or exports.

## Remaining risks and priorities

1. Run the defined CI jobs after the owner reviews and publishes the working tree. No hosted or Linux CI result is claimed.
2. If wanted, enable an already installed local Ollama model and capture actual model/version/digest, hardware, timestamps and outcomes. The adapter contract tests are not inference evidence.
3. Perform native Safari and manual VoiceOver/zoom checks before making wider accessibility/browser claims.
4. Measure larger sanitized datasets before changing ingestion limits or adding infrastructure. Current rules are authored for the synthetic scenario and are not a general SOC detector.
5. Use independently retained checkpoints for stronger audit retention. Replacing the local database, key and checkpoint together is undetectable here.
6. Any real executor or external integration needs a separate authorization, isolation, egress and unknown-outcome recovery design. It is intentionally absent from the MVP.

The power-loss and arbitrary external-side-effect problem has not been solved by these local transaction tests. No remaining known regression is presented as passing; assurance remains limited to the exercised local boundaries.

## Run locally

```bash
make setup
make demo
```

Open `http://127.0.0.1:8765` and enter the single-use code printed by the server. Stop with `Ctrl+C`.

```bash
make verify
make eval
# Optional second browser engine:
cd frontend && npx playwright install webkit && cd ..
make e2e-webkit
```

The [README](../README.md), [walkthrough](DEMO_WALKTHROUGH.md), [scenarios](SCENARIOS.md), [architecture](ARCHITECTURE.md), [threat model](THREAT_MODEL.md), [ADRs](ADR.md), [screenshots](screenshots/) and [portfolio notes](PORTFOLIO.md) form the portfolio package. No commit, push, account connection or deployment was performed.
