# Baseline probe reproducer and captured output

Captured 2026-10-20 on the unchanged AgentGuard source tree. This is an audit
artifact, not a new application module or a replacement for the 33-test suite.
All destructive fixture changes occur inside TemporaryDirectory and are cleaned
up. No server, model, external target or real system is accessed. Successful
completion means observations were captured, not that the security gaps passed
an acceptance test.

From the repository root, run the following block to reproduce. The environment
prefix only excludes conflicting Python settings for this invocation.

```bash
env -u PYTHONHOME -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
"""Read-only source audit; all mutations are confined to temporary fixtures."""
import hashlib
import json
import platform
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from agentguard.audit import Audit
from agentguard.gateway import Gateway
from agentguard.hunt import hunt, ingest, inspect_ref
from agentguard.report import evaluate, export_case
from agentguard.seed import generate

REPORT = {"report_id": "quarterly-synthetic"}
PUB = {"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox"}
results = {}

with tempfile.TemporaryDirectory(prefix="agentguard-baseline-") as tmp:
    root = Path(tmp)
    logs = generate(root / "logs")
    results["fixture"] = {
        "events": len(ingest(logs)),
        "evaluation": {k: v for k, v in evaluate(logs).items() if k != "predictions"},
        "checked_in_matches_generator": all(
            p.read_bytes() == (logs / p.name).read_bytes()
            for p in Path("examples/logs").iterdir() if p.is_file()
        ),
    }
    modes = {}
    for mode in ("deny", "approve", "monitor"):
        gw = Gateway(root / mode)
        outcomes = [
            gw.request("read_report", REPORT, mode)["status"],
            gw.request("publish_external", PUB, mode)["status"],
            gw.request("read_secret", {"name": "production-env"}, mode)["status"],
        ]
        modes[mode] = {"statuses": outcomes, "audit_valid": gw.audit.verify()}
    results["modes"] = modes

    gw = Gateway(root / "tail")
    gw.request("read_report", REPORT)
    gw.request("read_report", REPORT)
    lines = gw.audit.path.read_text().splitlines()
    gw.audit.path.write_text(lines[0] + "\n")
    results["tail_truncation"] = {"remaining": len(gw.audit.read()), "verify": Audit(gw.root).verify()}
    gw.audit.path.unlink()
    results["missing_audit"] = {"verify": Audit(gw.root).verify(), "persisted_requests": len(gw.requests)}

    gw = Gateway(root / "live-tamper")
    gw.request("read_report", REPORT)
    gw.audit.path.write_text(gw.audit.path.read_text().replace("ALLOW", "BLOCK"))
    outcome = gw.request("publish_external", PUB, "monitor")
    results["live_tamper_then_request"] = {
        "status": outcome["status"], "receipts": len(list((gw.root / "outbox").glob("*.json"))),
        "verify": gw.audit.verify(),
    }

    gw = Gateway(root / "audit-failure")
    with patch.object(gw.audit, "append", side_effect=OSError("injected audit failure")):
        try:
            gw.request("publish_external", PUB, "monitor")
        except OSError as exc:
            error = str(exc)
    results["audit_failure_after_effect"] = {
        "error": error, "receipts": len(list((gw.root / "outbox").glob("*.json"))),
        "persisted_requests": len(json.loads(gw.state_path.read_text())),
        "audit_events": len(gw.audit.read()),
    }

    first = Gateway(root / "stale")
    second = Gateway(first.root)
    first.request("read_report", REPORT)
    second.request("read_report", REPORT)
    results["stale_instances"] = {
        "persisted_requests": len(json.loads(first.state_path.read_text())),
        "audit_events": len(first.audit.read()), "verify": first.audit.verify(),
    }

    gw = Gateway(root / "decisions")
    pending = gw.request("publish_external", PUB, "approve")
    other = Gateway(gw.root)
    approved = gw.decide(pending["id"], True)
    rejected = other.decide(pending["id"], False)
    results["stale_approve_then_reject"] = {
        "responses": [approved["status"], rejected["status"]],
        "persisted_status": json.loads(gw.state_path.read_text())[pending["id"]]["status"],
        "receipts": len(list((gw.root / "outbox").glob("*.json"))),
        "audit_valid": other.audit.verify(),
    }

    gw = Gateway(root / "threads")
    pending = gw.request("publish_external", PUB, "approve")
    def approve(_):
        try:
            return gw.decide(pending["id"], True)["status"]
        except ValueError:
            return "ValueError"
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(approve, range(2)))
    results["one_instance_concurrent_approval"] = {
        "outcomes": outcomes, "receipts": len(list((gw.root / "outbox").glob("*.json"))),
    }

    before = inspect_ref(logs, "http.log:1")
    altered = dict(before, host="changed.demo.invalid")
    (logs / "http.log").write_text(json.dumps(altered) + "\n")
    results["mutable_evidence_ref"] = {
        "same_ref": "http.log:1",
        "before_host": before["host"], "after_host": inspect_ref(logs, "http.log:1")["host"],
    }
    generate(logs)
    records = [json.loads(line) for line in (logs / "windows-events.ndjson").read_text().splitlines()]
    records[1]["EventData"] = None
    (logs / "windows-events.ndjson").write_text("".join(json.dumps(x) + "\n" for x in records))
    try:
        hunt(logs)
    except Exception as exc:
        results["nested_schema"] = {"error_type": type(exc).__name__, "message": str(exc)}

    generate(logs)
    records = [json.loads(line) for line in (logs / "suricata.ndjson").read_text().splitlines()]
    records[0]["timestamp"] = "2000-01-01T00:00:00Z"
    (logs / "suricata.ndjson").write_text(json.dumps(records[0]) + "\n")
    data = next(f for f in hunt(logs) if f.agent == "data")
    results["unrelated_time_correlation"] = {
        "alert_time": records[0]["timestamp"], "data_score": data.score, "evidence": data.evidence,
    }
    generate(logs)
    case = export_case(logs, root / "export")
    results["export"] = {
        "contains_unknown": "UNKNOWN" in case.read_text(),
        "contains_source": "http.log:1" in case.read_text(),
        "files": sorted(p.name for p in case.parent.iterdir()),
    }

sources = sorted(
    [Path("pyproject.toml"), *Path("agentguard").glob("*.py"),
     *Path("tests").glob("*.py"), *Path("examples/logs").glob("*")]
)
print(json.dumps({
    "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
    "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
    "results": results,
}, indent=2))
PY
```

## Captured output

```json
{
  "environment": {
    "python": "3.11.2",
    "platform": "macOS-26.7-arm64-arm-64bit"
  },
  "source_sha256": {
    "agentguard/__init__.py": "79f8406689f6d319b7d4ef303f55f5efc88aa924e250b5d3e67e73a36d2cecbb",
    "agentguard/__main__.py": "355f3b865ac98d3d3bc8de384d49c691ee39ae7b90d376ab659a71aff600a143",
    "agentguard/attack.py": "0447a2cf7b801c6d6fc14996f026aa0905edf6e4159e81906fdbd0d21739e0df",
    "agentguard/audit.py": "e8bc38f86a17c683784bdba6f31dbdad71e2637e55e3172b5e94aa15d3c435bf",
    "agentguard/gateway.py": "2a6ebc6f2073c19895f03acb58645a98df5eaadc5e167a13e34f9c9eacdec147",
    "agentguard/hunt.py": "8ff34fe0e850cda2fcbd08c62feeeca652620403f0c7e665e9c41852c1228162",
    "agentguard/ollama.py": "b6eff5ff7fef0a82eb89030c28358f9ed6c931d61afccc1894b09bd0313214d9",
    "agentguard/report.py": "df883c14f8bd02973f23cca017bbe7f9174899809ef09e9401d8cb98dfb24069",
    "agentguard/seed.py": "4648598441d74659e433039782bd70ddecbaad5dce3e15e24ad5d9958307f51d",
    "agentguard/ui.py": "224ce4534614855c90d9bb2b6d5f0b69b8eb89d9de69e37e4ddb70b139c3d08c",
    "examples/logs/agent-actions.ndjson": "4c0b67e21da91e629e8f310368475254ef5b41d193c71f75f4c71649f7116dc0",
    "examples/logs/conn.log": "f243a0c68b8c73dcc22a7629b4371da68bdeefd13a7cefc595da72494a9ff3a3",
    "examples/logs/dns.log": "d0473cb05874e0c3e8ea8544cddb9acf67f8ab8b9f8a3ab71dd9380fdad08213",
    "examples/logs/http.log": "ac9dfb189e4d421c91552031ec902fb776bf78cdb03b6d958bb7be797999b058",
    "examples/logs/ssl.log": "dcbe0a93083c1f08a0a0c7671cd31afd2aa9e5085773d447b2054edacf633eac",
    "examples/logs/suricata.ndjson": "966248a9666805bd9e381bcdc49348df59076d6f4f3e1d3748dd5572dca37881",
    "examples/logs/untrusted_note.txt": "9697fadb515240624a5b4d8f29fa2bdbe82c01d94af1c96bf3695cec17984a65",
    "examples/logs/windows-events.ndjson": "fbb6249f9a6eee65aacc9f67f0c1b54dbc7e6cc2afd86291a0ed247cc49cbc55",
    "pyproject.toml": "9b278db7d0a5d83e86857960269e84ee36fcc2b927945114cd8864f60cc79db0",
    "tests/test_security.py": "7f5bc98f48a452bc94da4cddc02efc06f1811d82981a93dffcb397ea13b6969b"
  },
  "results": {
    "fixture": {
      "events": 14,
      "evaluation": {
        "dataset": "4 independently authored synthetic agents, 3 known labels; not real-world detector performance",
        "counts": {
          "TP": 2,
          "FP": 0,
          "TN": 1,
          "FN": 0,
          "UNKNOWN": 1
        },
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0
      },
      "checked_in_matches_generator": true
    },
    "modes": {
      "deny": {
        "statuses": [
          "ALLOW",
          "BLOCK",
          "BLOCK"
        ],
        "audit_valid": true
      },
      "approve": {
        "statuses": [
          "ALLOW",
          "PENDING",
          "BLOCK"
        ],
        "audit_valid": true
      },
      "monitor": {
        "statuses": [
          "ALLOW",
          "MONITORED",
          "BLOCK"
        ],
        "audit_valid": true
      }
    },
    "tail_truncation": {
      "remaining": 1,
      "verify": true
    },
    "missing_audit": {
      "verify": true,
      "persisted_requests": 2
    },
    "live_tamper_then_request": {
      "status": "MONITORED",
      "receipts": 1,
      "verify": false
    },
    "audit_failure_after_effect": {
      "error": "injected audit failure",
      "receipts": 1,
      "persisted_requests": 1,
      "audit_events": 0
    },
    "stale_instances": {
      "persisted_requests": 1,
      "audit_events": 2,
      "verify": true
    },
    "stale_approve_then_reject": {
      "responses": [
        "APPROVED",
        "REJECTED"
      ],
      "persisted_status": "REJECTED",
      "receipts": 1,
      "audit_valid": true
    },
    "one_instance_concurrent_approval": {
      "outcomes": [
        "APPROVED",
        "ValueError"
      ],
      "receipts": 1
    },
    "mutable_evidence_ref": {
      "same_ref": "http.log:1",
      "before_host": "sync.demo.invalid",
      "after_host": "changed.demo.invalid"
    },
    "nested_schema": {
      "error_type": "AttributeError",
      "message": "'NoneType' object has no attribute 'get'"
    },
    "unrelated_time_correlation": {
      "alert_time": "2000-01-01T00:00:00Z",
      "data_score": 1.0,
      "evidence": [
        "agent-actions.ndjson:2",
        "http.log:1",
        "suricata.ndjson:1"
      ]
    },
    "export": {
      "contains_unknown": true,
      "contains_source": true,
      "files": [
        "evaluation.json",
        "findings.csv",
        "vigil_case_draft.md"
      ]
    }
  }
}
```
