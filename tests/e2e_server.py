"""Run one disposable local workbench for browser tests.

The production entry point generates a bootstrap code and prints it to a terminal.
Playwright cannot read a terminal, so this harness writes the same kind of code to
a 0600 file inside the disposable test state directory. It is intentionally
separate from the documented demo command and never contacts a network service.
"""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

import uvicorn

from agentguard.workbench.api import create_app
from agentguard.workbench.bootstrap import initialize
from agentguard.workbench.sessions import generate_bootstrap_code
from agentguard.workbench.settings import Settings

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch an isolated workbench for Playwright")
    parser.add_argument("--port", type=int, default=8876)
    parser.add_argument("--state-dir", type=Path, default=ROOT / "frontend" / ".e2e-run")
    parser.add_argument("--keep-state", action="store_true", help="Reuse the previous database instead of resetting")
    args = parser.parse_args()

    state_dir: Path = args.state_dir.resolve()
    if state_dir.exists() and not args.keep_state:
        shutil.rmtree(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    code = generate_bootstrap_code()
    settings = Settings(
        db_path=state_dir / "workbench.db",
        runtime_dir=state_dir,
        fixture_dir=ROOT / "examples" / "logs",
        frontend_dist=ROOT / "frontend" / "dist",
        host="127.0.0.1",
        port=args.port,
    )
    state = initialize(settings)
    if state["status"] != "READY":
        raise SystemExit(f"Workbench bootstrap failed: {state['status']}")

    code_file = state_dir / "bootstrap-code"
    code_file.write_text(code + "\n", encoding="utf-8")
    os.chmod(code_file, 0o600)

    app = create_app(settings, bootstrap_code=code)
    print(f"E2E workbench: http://127.0.0.1:{args.port}", flush=True)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")


if __name__ == "__main__":
    main()
