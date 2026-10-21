# Lab 01–12 learning map

The workbench integrates the requested security concepts into one local workflow. This mapping describes the implemented synthetic system; it does not claim access to or verification of private course/event materials.

Start with `make setup` and `make demo`. Primary commands and screens use the rebuilt SQLite gateway. The old AgentGuard CLI is retained only as a historical regression reference.

| Lab | Concept | Reproducible workbench activity |
|---|---|---|
| 01 | Evidence and uncertainty | Overview: distinguish observed records, review findings and unknowns |
| 02 | Agent identity and provenance | Finding detail: compare actor hints and shared-host limitations |
| 03 | Exact source inspection | Follow evidence links to captured source, line, SHA-256 and context |
| 04 | Investigation to case | Create a cited verdict and explicitly scoped case; export Markdown/JSON |
| 05 | Pre-execution policy | Run injection with Deny; verify BLOCK and no receipt |
| 06 | Optional real local model | Explicitly enable Ollama if installed; inspect proposals, no-call/outage outcomes and metadata |
| 07 | Multi-source hunting | Compare Zeek, Suricata, Windows and agent-action evidence on a timeline |
| 08 | Explainable scoring | Read rule priority, supporting/contradicting evidence and confidence rationale |
| 09 | Prompt injection | Compare scripted follower and boundary-aware outcomes; never call this an LLM susceptibility result |
| 10 | Exact-request approval | Review one immutable request, approve/reject once and inspect replay/expiry behavior |
| 11 | Transparent evaluation | Run `make eval`; inspect confusion counts, unknowns, denominators and same-fixture threshold caveat |
| 12 | Integrated analyst workflow | Use all six UI screens, audit verification and revisioned case handoff |

## Read source records directly

These optional read-only shell commands inspect only bundled synthetic inputs:

```bash
jq -c 'select(.method=="POST") | {uid,host,uri,request_body_len}' examples/logs/http.log
jq -c 'select(.event_type=="alert") | {src_ip,dest_ip,alert}' examples/logs/suricata.ndjson
jq -c 'select(.EventID==4625) | {computer:.Computer,user:.EventData.SubjectUserName}' examples/logs/windows-events.ndjson
nl -ba examples/logs/agent-actions.ndjson
```

Byte counts do not establish transferred payloads. Login failure does not establish successful compromise. A shared address does not prove agent process ownership. Docs remains unknown without policy/identity evidence.

## Manual SOC handoff

Create a scoped case in Audit & cases and download Markdown or JSON. A human may enter that marked synthetic case into their own SOC environment. No Vigil API, account connection or automated external write exists. A local export is not proof of external delivery.

## Historical prototype

Legacy `hunt`, `demo`, `attack-lab`, `dashboard`, `evaluate`, `export-case` and `ollama` CLI commands remain for baseline regression continuity. They use the historical prototype's separate state, not the rebuilt gateway, and are not the supported workbench demo path. The known historical approval/audit gaps are recorded in [BASELINE_AUDIT.md](BASELINE_AUDIT.md).

For the supported workflow use [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md), [SCENARIOS.md](SCENARIOS.md) and the `make` targets in the README.
