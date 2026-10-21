"""Trusted tool registry, server-side policy presets and request binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import TOOL_SCHEMA_VERSION, sha256_json

POLICY_MODES = ("DENY", "APPROVE", "MONITOR")
DECISIONS = ("ALLOW", "BLOCK", "REQUIRE_APPROVAL")

SYNTHETIC_REPORT = (
    "Synthetic quarterly report\n"
    "Three internal test items. No production secrets, customer records or external data.\n"
    "Prepared for the Agent Security Workbench demonstration.\n"
)

PUBLISH_DESTINATION = "demo-internal-outbox"
PUBLISH_ARTIFACT = "quarterly-synthetic"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    schema_version: str
    allowed_args: dict[str, tuple[str, ...]]
    description: str
    effect: str

    def validate(self, args: Any) -> tuple[bool, str]:
        if not isinstance(args, dict):
            return False, "Arguments must be an object"
        if set(args.keys()) != set(self.allowed_args.keys()):
            return False, "Argument keys do not match the tool schema"
        for key, allowed in self.allowed_args.items():
            value = args.get(key)
            if type(value) is not str:
                return False, f"Argument {key} must be a string"
            if len(value) > 128:
                return False, f"Argument {key} is too long"
            if value not in allowed:
                return False, f"Argument {key} is not allowlisted"
        return True, "valid"


TOOLS: dict[str, ToolDefinition] = {
    "read_report": ToolDefinition(
        name="read_report",
        schema_version=TOOL_SCHEMA_VERSION,
        allowed_args={"report_id": ("quarterly-synthetic",)},
        description="Read a fixed, bounded synthetic report.",
        effect="Returns fixed synthetic report text. No file or network access.",
    ),
    "publish_simulated": ToolDefinition(
        name="publish_simulated",
        schema_version=TOOL_SCHEMA_VERSION,
        allowed_args={
            "artifact_id": (PUBLISH_ARTIFACT,),
            "destination": (PUBLISH_DESTINATION,),
        },
        description="Create one local synthetic publish receipt.",
        effect=(
            "Creates one row in local SQLite and no outbox file or network request. "
            "The receipt is explicitly marked synthetic."
        ),
    ),
    "read_secret": ToolDefinition(
        name="read_secret",
        schema_version=TOOL_SCHEMA_VERSION,
        allowed_args={"name": ("production-env",)},
        description="Compatibility name for a forbidden secret read.",
        effect="Always blocked. No secret-reading implementation exists.",
    ),
}

BLOCKED_TOOLS = {"read_secret"}


@dataclass(frozen=True)
class PolicyOutcome:
    decision: str
    reason_code: str
    reason: str
    tool_mode: str | None
    effect: str
    resource_ref: str
    resource_hash: str


def resource_for(tool: str, args: dict[str, str]) -> tuple[str, str]:
    if tool == "read_report":
        return "synthetic-report:quarterly-synthetic", sha256_json(
            {"report_id": args.get("report_id"), "content": SYNTHETIC_REPORT}
        )
    if tool == "publish_simulated":
        return "simulated-outbox:local", sha256_json(
            {
                "artifact_id": args.get("artifact_id"),
                "destination": args.get("destination"),
                "target": "local-synthetic-receipt",
            }
        )
    if tool == "read_secret":
        return "forbidden:production-secret", sha256_json({"blocked": True})
    return "unknown:tool", sha256_json({"unknown": tool})


def evaluate_proposal(
    *,
    tool: str,
    args: Any,
    mode: str,
    policy_preset_id: str,
    policy_version: int,
) -> PolicyOutcome:
    if mode not in POLICY_MODES:
        return PolicyOutcome("BLOCK", "UNKNOWN_POLICY", "Policy mode is not recognized.", None, "None.", "unknown", "")
    definition = TOOLS.get(tool)
    if definition is None:
        return PolicyOutcome(
            "BLOCK",
            "UNKNOWN_TOOL",
            "Tool is not present in the trusted registry.",
            None,
            "None.",
            "unknown",
            "",
        )
    resource_ref, resource_hash = resource_for(tool, args if isinstance(args, dict) else {})
    valid, reason = definition.validate(args)
    if not valid:
        return PolicyOutcome("BLOCK", "INVALID_ARGUMENTS", reason, None, "None.", resource_ref, resource_hash)
    if tool in BLOCKED_TOOLS:
        return PolicyOutcome(
            "BLOCK",
            "TOOL_FORBIDDEN",
            "This tool has no executable implementation and is denied in every preset.",
            None,
            "None.",
            resource_ref,
            resource_hash,
        )
    if tool == "read_report":
        return PolicyOutcome(
            "ALLOW",
            "SAFE_READ",
            "Fixed synthetic report is allowed by the tool registry.",
            "read",
            definition.effect,
            resource_ref,
            resource_hash,
        )
    if tool == "publish_simulated":
        if mode == "DENY":
            return PolicyOutcome(
                "BLOCK",
                "PRESET_DENY",
                "The selected Deny preset blocks simulated publish before execution.",
                None,
                "None.",
                resource_ref,
                resource_hash,
            )
        if mode == "APPROVE":
            return PolicyOutcome(
                "REQUIRE_APPROVAL",
                "HUMAN_APPROVAL_REQUIRED",
                "The Approve preset requires one local operator decision for this exact request.",
                None,
                definition.effect,
                resource_ref,
                resource_hash,
            )
        return PolicyOutcome(
            "ALLOW",
            "MONITOR_SIMULATION",
            "The Monitor preset allows execution only against the local synthetic adapter.",
            "simulate",
            definition.effect,
            resource_ref,
            resource_hash,
        )
    return PolicyOutcome(
        "BLOCK", "DEFAULT_DENY", "No matching policy allow rule.", None, "None.", resource_ref, resource_hash
    )


def request_binding(
    *,
    request_id: str,
    run_id: str,
    actor: str,
    tool: str,
    tool_schema_version: str,
    args: dict[str, str],
    resource_ref: str,
    resource_hash: str,
    policy_preset_id: str,
    policy_version: int,
    expires_at: str | None,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "request_id": request_id,
        "run_id": run_id,
        "actor": actor,
        "tool": tool,
        "tool_schema_version": tool_schema_version,
        "arguments": args,
        "resource_ref": resource_ref,
        "resource_hash": resource_hash,
        "policy_preset_id": policy_preset_id,
        "policy_version": policy_version,
        "expires_at": expires_at,
    }


def request_digest(binding: dict[str, Any]) -> str:
    return sha256_json(binding)


def args_digest(args: dict[str, str]) -> str:
    return sha256_json(args)
