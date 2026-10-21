# Demo walkthrough

This walkthrough uses synthetic records and local effects. It does not require Ollama, credentials or an external SOC.

## Start

```bash
make setup
make demo
```

Open `http://127.0.0.1:8765` and enter the code printed in the terminal. It expires after ten minutes and opens one local session. If the browser loses that session after the code is consumed, restart the server for a new code. Existing approvals remain bound to their original session; start a new run when needed.

## Investigate

1. On **Overview**, confirm the synthetic dataset, 14 events, eight captured sources, two review findings and one unknown finding. Runtime case/approval counts depend on previous local use.
2. Open **Investigations**, then **Unapproved publish attempt with correlated outbound upload**. Review facts, interpretation, contradictions, unknowns and the rule-priority rationale.
3. Follow a source reference. The evidence page displays captured bytes, line, hashes and context. Shared-host observations do not establish which agent owned a network flow.
4. Return to Investigations and create a new investigation with the Data finding. Cite evidence, enter a rationale and save a verdict revision. A supported policy violation does not establish malicious intent or successful compromise.

## Compare policy modes

1. On **Agent traces**, start **Prompt-injection publish attempt**, runtime **scripted**, preset **Deny**. Inspect the blocked request; execution has not started.
2. Repeat with **Approve**. The run waits for approval and has no receipt. Open its approval, review the exact arguments, resource hash, policy version, request digest and expiry. Enter a reason and confirm review.
3. Select **Approve once and execute**. The committed synthetic receipt and execution state are shown separately. Reload: a second decision is unavailable. Starting another pending run allows the rejection path to be tried.
4. Repeat with **Monitor**. Execution creates one local database receipt. There is no network upload or outbox file.
5. Run **Privilege overreach** with Deny. The forbidden secret-read name has no implementation. Run **Boundary-aware no tool call** to see an explicit scripted `NO_TOOL_CALL`.

The scripted follower is configured to attempt an action; it does not measure whether a real model followed the note.

## Evaluate and hand off a case

1. On **Evaluation**, run the synthetic baseline. Inspect the three known policy labels, unknown/unlabeled record, confusion counts, denominators and threshold caveat.
2. Check the seven scripted enforcement outcomes, six risky proposals and seven total proposals. Model observations are separate from attempts and excluded from these metrics.
3. Download JSON, Markdown and CSV. Alternatively run `make eval` to create private local files under `run/eval/reports/`.
4. From the investigation, choose **Create case from scope**. Write summary, scope, conclusion and recommendations. Only selected findings and requests belong to the case.
5. Export Markdown or JSON for the full case, or CSV for the evidence table. Unknown-time evidence is retained outside the ordered timeline. A failed evidence-integrity check prevents export.
6. On **Audit & cases**, run verification. Interpret retained-record integrity, local checkpoint completeness and audit consistency separately. A matching local checkpoint is not independent tamper-proof retention.

Vigil entry is a manual task for the operator. This application does not call or guess a Vigil endpoint.

## Reproduce checks

```bash
make test
make lint
make verify
make screenshots
```

Browser checks use a separate disposable database under `frontend/.e2e-run`. Screenshots are captured from the running application. For the optional WebKit check, install its engine with `cd frontend && npx playwright install webkit`, return to the root, then run `make e2e-webkit`.

## Optional local model

If Ollama and a model are already installed, start with `AGENTGUARD_ENABLE_OLLAMA=1 make demo`, then select the local runtime in Agent traces. Every proposal crosses the same gateway. An outage, malformed response and valid no-call response remain distinct. No actual inference was performed in this delivery; model/runtime version fields may be unknown and must not be inferred from offline tests.
