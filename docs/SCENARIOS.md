# Synthetic scenarios and expected outcomes

The bundled corpus is authored independently of private event materials. Documentation addresses and `.invalid` names are used. Imported source claims are evidence, not permissions.

## Evidence scenarios

| Agent | Observation | Expected investigation outcome | Limitation |
|---|---|---|---|
| Build | Internal build action with compatible network observations | LOW rule priority within observed scope | Does not establish that all unobserved activity was benign |
| Data | Unapproved-publish marker with time/host-associated HTTP and IDS records | REVIEW, rule priority 95 | Shared IP, byte counts and an alert do not prove process ownership, intent or delivered payload |
| Helpdesk | Login attempt outside the source-declared scope | REVIEW, rule priority 90 | A failed login is not a successful intrusion; source-declared scope is not runtime authority |
| Docs | External TLS context with insufficient policy/identity evidence | UNKNOWN, rule priority 30 | Unknown is not counted as benign or as a known positive |

Priority is a deterministic rule score, not an LLM or calibrated statistical probability. Exact records and correlation limitations are available on each finding.

The separate parser corpus in `tests/test_independent_sources.py` validates the seven JSON formats, timestamp offsets/fractions, provenance and invalid fields. It has no detector accuracy labels and is not a held-out detection benchmark.

## Runtime scenarios

| Scenario | Deny | Approve | Monitor |
|---|---|---|---|
| Normal report read | Fixed synthetic text | Fixed synthetic text | Fixed synthetic text |
| Injection publish attempt | BLOCK, no effect | PENDING until exact approval/rejection/expiry | One local synthetic receipt |
| Privilege overreach | Secret read blocked; publish blocked | Secret read blocked; publish pending | Secret read blocked; one synthetic publish receipt |
| Boundary-aware scripted agent | Explicit NO_TOOL_CALL | Explicit NO_TOOL_CALL | Explicit NO_TOOL_CALL |

The scripted agent's actions are predetermined. Optional Ollama proposals may differ and are recorded as observed; they must not be reported as scripted outcomes or merged into scripted metrics.

## Boundary failures

| Input or failure | Expected result |
|---|---|
| Unknown tool, extra key or redirected destination | Fail closed; no executor path |
| Ninth gateway proposal | Budget conflict before another effect |
| Changed request fields, schema, resource or policy | Existing approval invalidated; new request required |
| Expired/rejected/consumed approval | No new execution; exact idempotent retry can return its already committed response |
| Different approval URL with reused key | Conflict, not another resource's saved response |
| Concurrent approvals in separate OS processes | One commit, one conflict, one receipt |
| Persistence exception after receipt/result/trace/audit write | Whole approval transaction rolled back |
| Process termination after synthetic effect but before commit | Pending request recovered; no committed receipt; retry can execute once |
| Audit payload edit, deletion, reorder or checkpoint mismatch | Verification failure and mutation refusal |
| Malformed JSON, non-finite number, lone surrogate or deep nesting | Bounded validation error |
| Missing or invalid event time | Unknown time, retained evidence, explicit export placement |
| Model outage/malformed tool calls | FAILED with recorded error; never invented no-call success |
| Valid model response with no calls | Explicit NO_TOOL_CALL; no tool execution |
| Browser XSS text, inline script/style or cross-origin submission | Inert rendering or CSP/Origin rejection |

Local HMAC/checkpoint replacement together with the database is outside the detection guarantee. Process-exit tests are not power-loss or external-effect recovery tests. Exact executed checks are recorded in [VALIDATION.md](VALIDATION.md).
