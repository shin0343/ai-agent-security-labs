"""AgentGuard / Agent Security Workbench command line."""
import argparse
import json
from pathlib import Path

from .gateway import Gateway
from .hunt import hunt, inspect_ref
from .report import evaluate, export_case
from .seed import generate

ROOT = Path(__file__).resolve().parent.parent


def _workbench_settings(args):
    from .workbench.settings import Settings

    return Settings(
        db_path=args.out / "workbench.db",
        runtime_dir=args.out,
        fixture_dir=args.data,
        frontend_dist=ROOT / "frontend" / "dist",
        host=args.host,
        port=args.port,
        enable_ollama=args.ollama,
    )


def _workbench_session(settings, operator: str = "cli-operator"):
    from .workbench.sessions import create_session

    return create_session(settings, operator)


def main():
    p = argparse.ArgumentParser(prog="python3 -m agentguard", description="Agent Security Workbench")
    p.add_argument(
        "command",
        choices=(
            "seed",
            "hunt",
            "inspect",
            "demo",
            "evaluate",
            "export-case",
            "verify",
            "dashboard",
            "ollama",
            "attack-lab",
            "workbench",
            "workbench-seed",
            "workbench-eval",
            "workbench-verify",
        ),
    )
    p.add_argument("--data", type=Path, default=ROOT / "examples/logs")
    p.add_argument("--out", type=Path, default=ROOT / "run")
    p.add_argument("--mode", choices=("deny", "approve", "monitor"), default="deny")
    p.add_argument("--agent", choices=("naive", "boundary-aware"), default="naive")
    p.add_argument("--ref", default="http.log:1")
    p.add_argument("--model", default="qwen2.5:3b")
    p.add_argument("--scenario", choices=("normal", "injection", "attack"), default="injection")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ollama", action="store_true", help="Enable the optional local Ollama runtime")
    args = p.parse_args()

    if args.command in {"workbench", "workbench-seed", "workbench-eval", "workbench-verify"}:
        settings = _workbench_settings(args)
        from .workbench.bootstrap import initialize

        state = initialize(settings)
        if args.command == "workbench-seed":
            print(json.dumps({k: state[k] for k in ("status", "dataset_id", "detection_run_id")}, indent=2))
            return
        if args.command == "workbench-verify":
            from .workbench.audit import verify_audit
            from .workbench.db import read_connection

            with read_connection(settings.db_path) as conn:
                print(json.dumps(verify_audit(conn, settings.runtime_dir).as_dict(), indent=2))
            return
        if args.command == "workbench-eval":
            from .workbench.evaluation import run_evaluation

            if not state.get("dataset_id"):
                p.error(f"Dataset initialization failed: {state.get('status')}")
            session = _workbench_session(settings)
            report = run_evaluation(
                settings, session_id=session["session_id"], dataset_id=state["dataset_id"]
            )
            summary = report["summary"]
            print(
                json.dumps(
                    {
                        "evaluation_id": report["id"],
                        "status": report["status"],
                        "detection": {
                            key: summary["synthetic_detection"][key]
                            for key in (
                                "TP",
                                "FP",
                                "TN",
                                "FN",
                                "abstained",
                                "missing",
                                "errored",
                                "unlabeled",
                                "precision",
                                "recall",
                                "f1",
                            )
                        },
                        "enforcement": summary["scripted_enforcement"]["counts"],
                        "audit_integrity": summary["audit_verification"]["integrity"],
                        "reports": f"{settings.runtime_dir / 'reports'}",
                    },
                    indent=2,
                )
            )
            return
        import uvicorn

        from .workbench.api import create_app
        from .workbench.sessions import generate_bootstrap_code

        code = generate_bootstrap_code()
        app = create_app(settings, bootstrap_code=code)
        print("Agent Security Workbench", flush=True)
        print(f"Local URL: http://{settings.host}:{settings.port}", flush=True)
        if state["status"] == "READY":
            print(f"Bootstrap code: {code} (single use, expires in 10 minutes)", flush=True)
        else:
            print(f"Bootstrap disabled: {state.get('message', state['status'])}", flush=True)
        uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")
        return

    # Preserved AgentGuard prototype commands; these do not use the new SQLite store.
    if args.command == "seed":
        generate(args.data)
        print("Generated synthetic records:", args.data)
        return
    if not (args.data / "conn.log").is_file():
        if args.data == ROOT / "examples/logs":
            generate(args.data)
        else:
            p.error("Log directory not found; run seed --data PATH")
    if args.command == "hunt":
        value = [x.json() for x in hunt(args.data)]
    elif args.command == "inspect":
        value = inspect_ref(args.data, args.ref)
    elif args.command == "evaluate":
        value = evaluate(args.data)
    elif args.command == "demo":
        gw = Gateway(args.out)
        value = [
            gw.request("read_report", {"report_id": "quarterly-synthetic"}, args.mode),
            gw.request(
                "publish_external",
                {"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox"},
                args.mode,
            ),
            gw.request("read_secret", {"name": "production-env"}, args.mode),
        ]
    elif args.command == "attack-lab":
        from .attack import run_attack_lab

        value = run_attack_lab(args.out, args.mode, args.agent)
    elif args.command == "verify":
        gw = Gateway(args.out)
        value = {
            "audit_valid": gw.audit.verify(),
            "audit_events": len(gw.audit.read()),
            "requests": len(gw.requests),
        }
    elif args.command == "export-case":
        value = {"written": str(export_case(args.data, args.out))}
    elif args.command == "dashboard":
        from .ui import serve

        serve(args.data, args.out, args.port)
        return
    elif args.command == "ollama":
        from .ollama import run

        value = run(args.model, args.out, args.mode, args.scenario)
    else:  # pragma: no cover - argparse restricts choices
        p.error("Unknown command")
    print(json.dumps(value, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
