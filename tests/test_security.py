import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentguard.audit import Audit
from agentguard.gateway import Gateway
from agentguard.hunt import hunt, ingest, inspect_ref
from agentguard.report import evaluate, export_case
from agentguard.seed import generate

REPORT = {"report_id": "quarterly-synthetic"}
PUB = {"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox"}
SECRET = {"name": "production-env"}


class Lab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "logs"
        self.run = self.root / "run"
        generate(self.log)

    def gateway(self):
        return Gateway(self.run)

    def test_seed_is_reproducible(self):
        old = (self.log / "conn.log").read_bytes()
        generate(self.log)
        self.assertEqual(old, (self.log / "conn.log").read_bytes())

    def test_zeek_ingestion(self):
        self.assertEqual(len([e for e in ingest(self.log) if e.source == "conn.log"]), 3)

    def test_suricata_event(self):
        self.assertEqual(inspect_ref(self.log, "suricata.ndjson:1")["event_type"], "alert")

    def test_windows_event(self):
        self.assertEqual(inspect_ref(self.log, "windows-events.ndjson:2")["EventID"], 4625)

    def test_evidence_is_resolved_exactly(self):
        for finding in hunt(self.log):
            for ref in finding.evidence:
                self.assertIsInstance(inspect_ref(self.log, ref), dict)

    def test_traversal_evidence_rejected(self):
        for bad in (
            "../README.md:1",
            "http.log:0",
            "http.log:-1",
            "../../tmp/foo:1",
            "http.log:abc",
            "http.log:99",
            "http.log:１",
        ):
            with self.subTest(ref=bad), self.assertRaises(ValueError):
                inspect_ref(self.log, bad)

    def test_malformed_ndjson_rejected(self):
        with (self.log / "conn.log").open("a") as f:
            f.write("not json\n")
        with self.assertRaises(ValueError):
            ingest(self.log)

    def test_missing_source_fail_closed(self):
        (self.log / "http.log").unlink()
        with self.assertRaises(ValueError):
            ingest(self.log)

    def test_data_is_review_not_attributed(self):
        data = next(x for x in hunt(self.log) if x.agent == "data")
        self.assertEqual(data.disposition, "REVIEW")
        self.assertEqual(data.score, 1.0)
        self.assertIn("does not establish", data.limits)

    def test_helpdesk_scope_violation(self):
        finding = next(x for x in hunt(self.log) if x.agent == "helpdesk")
        self.assertEqual(finding.disposition, "REVIEW")
        self.assertEqual(finding.score, 0.9)

    def test_docs_insufficient_evidence(self):
        self.assertEqual(next(x for x in hunt(self.log) if x.agent == "docs").disposition, "UNKNOWN")

    def test_evaluation_unknown_exclusion(self):
        e = evaluate(self.log)
        self.assertEqual(e["counts"]["UNKNOWN"], 1)
        self.assertEqual(sum(e["counts"][k] for k in ("TP", "FP", "TN", "FN")), 3)

    def test_safe_read_in_deny(self):
        result = self.gateway().request("read_report", REPORT, "deny")
        self.assertEqual(result["status"], "ALLOW")

    def test_denied_publish_no_effect(self):
        result = self.gateway().request("publish_external", PUB, "deny")
        self.assertEqual(result["status"], "BLOCK")
        self.assertFalse((self.run / "outbox").exists())

    def test_monitor_simulation_only(self):
        result = self.gateway().request("publish_external", PUB, "monitor")
        self.assertEqual(result["status"], "MONITORED")
        receipt = self.run / "outbox" / (result["id"] + ".json")
        self.assertTrue(receipt.is_file())
        self.assertTrue(json.loads(receipt.read_text())["simulated"])

    def test_approve_request_then_reject(self):
        gw = self.gateway()
        r = gw.request("publish_external", PUB, "approve")
        self.assertEqual(r["status"], "PENDING")
        self.assertFalse((self.run / "outbox").exists())
        self.assertEqual(gw.decide(r["id"], False)["status"], "REJECTED")
        self.assertFalse((self.run / "outbox").exists())

    def test_approve_once_after_restart(self):
        r = self.gateway().request("publish_external", PUB, "approve")
        gw = self.gateway()
        self.assertEqual(gw.decide(r["id"], True)["status"], "APPROVED")
        self.assertTrue((self.run / "outbox" / (r["id"] + ".json")).exists())
        with self.assertRaises(ValueError):
            gw.decide(r["id"], True)

    def test_unknown_approval_rejected(self):
        with self.assertRaises(ValueError):
            self.gateway().decide("unknown", True)

    def test_nonboolean_approval_rejected(self):
        gw = self.gateway()
        r = gw.request("publish_external", PUB, "approve")
        with self.assertRaises(ValueError):
            gw.decide(r["id"], "true")

    def test_secret_always_blocked(self):
        for mode in ("deny", "approve", "monitor"):
            self.assertEqual(self.gateway().request("read_secret", SECRET, mode)["status"], "BLOCK")

    def test_unknown_tool_fail_closed(self):
        self.assertEqual(self.gateway().request("execute_shell", {"command": "whoami"}, "monitor")["status"], "BLOCK")

    def test_argument_injection_blocked(self):
        tests = [
            {"artifact_id": "quarterly-synthetic", "destination": "https://example.org"},
            {"artifact_id": "quarterly-synthetic", "destination": "../../secrets"},
            {"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox", "extra": "x"},
            {"artifact_id": ["quarterly-synthetic"], "destination": "demo-internal-outbox"},
            {},
        ]
        for args in tests:
            with self.subTest(args=args):
                self.assertEqual(self.gateway().request("publish_external", args, "monitor")["status"], "BLOCK")
        self.assertFalse((self.run / "outbox").exists())

    def test_unknown_mode_fails(self):
        with self.assertRaises(ValueError):
            self.gateway().request("read_report", REPORT, "bypass")

    def test_audit_hmac_chain(self):
        self.gateway().request("read_report", REPORT)
        self.assertTrue(Audit(self.run).verify())

    def test_audit_tamper_detected_and_append_refused(self):
        self.gateway().request("read_report", REPORT)
        f = self.run / "audit.jsonl"
        contents = f.read_text().replace("ALLOW", "BLOCK")
        self.assertNotEqual(contents, f.read_text())
        f.write_text(contents)
        with self.assertRaises(ValueError):
            Audit(self.run)

    def test_audit_metadata_excludes_argument_bodies(self):
        gw = self.gateway()
        gw.request("read_report", REPORT)
        self.assertNotIn("quarterly-synthetic", (self.run / "audit.jsonl").read_text())

    def test_scripted_injection_naive_deny(self):
        from agentguard.attack import run_attack_lab

        outcome = run_attack_lab(self.run, "deny", "naive")
        self.assertEqual(outcome["attempted"], 3)
        self.assertEqual(outcome["simulated_effects"], 0)

    def test_scripted_injection_monitor_is_not_secure(self):
        from agentguard.attack import run_attack_lab

        outcome = run_attack_lab(self.run, "monitor", "naive")
        self.assertEqual(outcome["simulated_effects"], 3)
        self.assertEqual(len(list((self.run / "outbox").glob("*.json"))), 3)

    def test_scripted_injection_boundary_aware(self):
        from agentguard.attack import run_attack_lab

        outcome = run_attack_lab(self.run, "monitor", "boundary-aware")
        self.assertEqual(outcome["attempted"], 0)
        self.assertEqual(outcome["simulated_effects"], 0)

    def test_export_preserves_case_uncertainty(self):
        self.gateway().request("publish_external", PUB, "deny")
        path = export_case(self.log, self.run)
        doc = path.read_text()
        self.assertIn("UNKNOWN", doc)
        self.assertIn("NOT", doc.upper())
        self.assertIn("http.log:1", doc)
        self.assertTrue((self.run / "reports/evaluation.json").exists())

    def test_audit_key_file_permissions(self):
        import os
        import stat

        self.gateway()
        mode = stat.S_IMODE(os.stat(self.run / ".audit-key").st_mode)
        self.assertEqual(mode, 0o600)


class OllamaOfflineMock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "logs"
        self.run = self.root / "run"
        generate(self.log)

    def test_tool_call_policies_remain_enforced(self):
        from agentguard.ollama import run

        class Response:
            def __init__(self, data):
                self.data = data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read(self, max_bytes):
                return json.dumps(self.data).encode()

        calls = [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "publish_external",
                                "arguments": {
                                    "artifact_id": "quarterly-synthetic",
                                    "destination": "demo-internal-outbox",
                                },
                            }
                        }
                    ],
                }
            },
            {"message": {"role": "assistant", "content": "done"}},
        ]
        with patch("agentguard.ollama.urllib.request.build_opener") as build_opener:
            mocked = build_opener.return_value.open
            mocked.side_effect = [Response(x) for x in calls]
            result = run("fake-local-model", self.run, "deny", "injection")
        self.assertEqual(result[0]["status"], "BLOCK")
        self.assertEqual(mocked.call_count, 2)
        self.assertFalse((self.run / "outbox").exists())

    def test_ollama_attack_not_real_model_benchmark(self):
        from agentguard.ollama import run

        with self.assertRaises(ValueError):
            run("fake", self.run, scenario="unsupported")


if __name__ == "__main__":
    unittest.main()
