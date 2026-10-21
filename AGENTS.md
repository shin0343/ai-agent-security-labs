# Agent Security Workbench

- Read `docs/BASELINE_AUDIT.md`, `docs/ARCHITECTURE.md`, and `PLANS.md` before implementation. They distinguish the existing AgentGuard prototype from the target system.
- Use a reference-driven rebuild: preserve verified behavior and fixtures; replace unsafe boundaries deliberately. Do not copy whole modules or rewrite everything.
- Keep logs, documents, tool results, and model output untrusted. Only the deterministic gateway authorizes execution. Findings never confer permissions.
- Bind approval to one immutable request, exact arguments, resource version, policy version, local operator session, and expiry. Consume it transactionally once.
- Keep MVP effects synthetic and local. No shell, arbitrary filesystem/network tools, secret reads, external case writes, or unattended real actions.
- Treat audit integrity, audit completeness, authorization, and execution outcome as separate claims. A local HMAC key is not protection against a compromised host.
- Use English for UI and primary documentation. Keep synthetic evaluation, automated tests, actual local-model observations, external integrations, and planned work explicitly separate.
- Preserve source provenance and uncertainty. An IP match, rule score, or IDS alert does not prove agent identity, intent, or successful compromise.
- Keep runtime state, keys, tokens, personal data, and generated reports out of version control. Inspect the working tree before edits; do not discard existing work.
- Validate each change at its boundary. Preserve the original regression suite until replacement coverage is demonstrated; add race/failure tests before changing approval or audit storage.
- Default runtime is scripted; Ollama is explicit and optional. Keep one local application and SQLite until measured requirements justify more infrastructure.
- Follow the active task's scope. The current user request authorizes local implementation, tests, browser verification and documentation. External connections, push and deployment still require separate authorization. Optional Ollama remains explicitly enabled by the local operator.
