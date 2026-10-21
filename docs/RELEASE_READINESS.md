# Release readiness — Agent Security Workbench

Assessed 2026-10-21 after the independent security/engineering audit (docs/FINAL_AUDIT.md). This document answers one question: is this repository safe to publish as a public portfolio project?

## Verdict: **CONDITIONAL GO**

Suitable as a public GitHub portfolio candidate **after** the three pre-publication items in §3 are either completed or explicitly stated on the front page (they are already stated honestly; §3 defines what "resolved" means here). No known critical security defect, no reproducible high-severity defect, and no major functional defect remains open.

GO refers to publication of the local educational prototype as an open-source portfolio artifact. It is not, and does not claim to be, an approval for production SOC/EDR use — the README's scope line already forbids that reading.

---

## 1. Security gate

| # | Item | Status | Evidence |
|---|---|---|---|
| 1.1 | No gateway bypass reachable by client, agent or model output | PASS | FINAL_AUDIT §1; live probes; independent tests |
| 1.2 | Approval single-use, digest/version/session/policy/resource/expiry bound, transactional | PASS | FINAL_AUDIT §§3–4; race/recovery tests |
| 1.3 | Audit fails closed on tamper; honest limits on independence | PASS | FINAL_AUDIT §6 (live tamper reproduce) |
| 1.4 | No secrets/PII/non-public material in repository | PASS | scans + `git check-ignore`; fixtures use RFC5737 IPs |
| 1.5 | Exports carry synthetic classification and escaping | PASS, improved | F-2 backtick breakout fixed w/ regression test |
| 1.6 | Dependency graph reproducible between local and CI | PASS, improved | F-1 constraint gate added; `pip check` clean |
| 1.7 | npm dependency vulnerabilities | PASS | `npm ci` + `npm audit` → 0 (point-in-time) |
| 1.8 | Hosted CI executed | **OPEN** (not blocking a local rerun claim because the workflow file is unrun) — see §3 |

## 2. Functional gate

| # | Item | Status |
|---|---|---|
| 2.1 | Full suite green (`make verify`: build + 234 tests + lint/types + Chrome E2E) | PASS |
| 2.2 | WebKit engine workflow | PASS |
| 2.3 | Metrics recomputed independently; claims separated from scripted/model results | PASS |
| 2.4 | UI surfaces server state only; no dead buttons; accessibility basics verified in E2E | PASS (manual a11y review still open, non-blocking) |
| 2.5 | `make eval` reproduces README numbers | PASS |

## 3. Pre-publication checklist (the "CONDITIONAL" part)

1. **Run hosted CI once and drop the result into the README** (or publish green). The workflow file is complete and now constraint-pinned; it has literally never executed. Do not publish a green badge you have not seen.
2. **Commit the working tree.** Everything is currently uncommitted except the historic `Initial commit`; a public repo without a commit history loses both provenance and reproducibility. Verify `git status` is clean of the runtime/`run/` artifacts before committing (they are gitignored).
3. **State the deferred items on the published front page** (README already does; keep every line true at publication time): no real model observations, no hosted-CI run, no independent audit retention, manual a11y/VoiceOver review open, no live external integrations. If any of these changes (e.g. an actual Ollama run is recorded), re-run `make eval` and update both VALIDATION.md and the README table.
4. Optional, non-blocking: apply §5/F-3–F-5 small hardening items in a follow-up commit.

## 4. Risk acceptance for publication

- **Known accepted limits (documented, not defects):** local HMAC chain without independent retention; single local operator session; synthetic-only effects; `run/` corruption outside host compromise is the attacker model boundary.
- **Residual risk if published now:** low. The strongest residual exposure is unverified CI behavior on GitHub runners and the possibility that future dependency drifts (if someone installs without constraints) change behavior; both are mitigated by the F-1 fix and README discipline.
- **What would flip this to NO-GO:** disclosure of a committed secret/PII, a reproducible gateway-bypass or approval-reuse path, or evaluation numbers that no longer reproduce after a change. Re-run `pytest`, `make eval` and the boundary matrix before any follow-up release.

## 5. Follow-up engineering list (post-publication, ordered by value)

1. Session-row GC (F-3) — small, removes unbounded growth.
2. Incremental audit verification (F-4) — only needed for long-lived deployments.
3. Shared `_session_valid` semantics (F-5) — consistency of 403/404 shapes.
4. A standalone adversarial "audit-tamper" E2E script for reviewers who want the reproduce steps outside pytest.
5. If Ollama is ever actually run: record one local observation with counts, label it explicitly as a local-model observation, and keep it out of detection metrics.

## 6. Decision record ladder

| Step | Required for | Status |
|---|---|---|
| CONDITIONAL GO | current state | **reached 2026-10-21** |
| GO | §3 items 1–3 done, no new findings | pending |
| NO-GO trigger | §4 flip conditions | not present |
