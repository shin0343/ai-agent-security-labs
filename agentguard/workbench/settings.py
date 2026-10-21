"""Runtime configuration for one local workbench instance."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .util import (
    APPROVAL_TTL_SECONDS,
    DEFAULT_DB,
    DEFAULT_RUN_DIR,
    FIXTURE_DIR,
    FRONTEND_DIST,
    SESSION_TTL_SECONDS,
)


@dataclass(frozen=True)
class Settings:
    db_path: Path = DEFAULT_DB
    runtime_dir: Path = DEFAULT_RUN_DIR
    fixture_dir: Path = FIXTURE_DIR
    frontend_dist: Path = FRONTEND_DIST
    host: str = "127.0.0.1"
    port: int = 8765
    approval_ttl_seconds: int = APPROVAL_TTL_SECONDS
    session_ttl_seconds: int = SESSION_TTL_SECONDS
    enable_ollama: bool = False
    ollama_model: str = "qwen2.5:3b"
    ollama_endpoint: str = "http://127.0.0.1:11434/api/chat"
    operator_id: str = "local-operator"

    def __post_init__(self) -> None:
        if self.host not in {"127.0.0.1", "localhost"}:
            raise ValueError("The workbench must bind to a loopback host.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if self.approval_ttl_seconds <= 0 or self.session_ttl_seconds <= 0:
            raise ValueError("Approval and session lifetimes must be positive.")

    @property
    def origins(self) -> tuple[str, ...]:
        return (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}")

    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        return (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    @classmethod
    def from_env(cls, **overrides: object) -> Settings:
        runtime_dir = Path(os.environ.get("AGENTGUARD_RUN_DIR", DEFAULT_RUN_DIR))
        values: dict[str, object] = {
            "db_path": Path(os.environ.get("AGENTGUARD_DB", runtime_dir / "workbench.db")),
            "runtime_dir": runtime_dir,
            "fixture_dir": Path(os.environ.get("AGENTGUARD_FIXTURES", FIXTURE_DIR)),
            "frontend_dist": Path(os.environ.get("AGENTGUARD_FRONTEND", FRONTEND_DIST)),
            "host": os.environ.get("AGENTGUARD_HOST", "127.0.0.1"),
            "port": int(os.environ.get("AGENTGUARD_PORT", "8765")),
            "approval_ttl_seconds": int(os.environ.get("AGENTGUARD_APPROVAL_TTL", str(APPROVAL_TTL_SECONDS))),
            "session_ttl_seconds": int(os.environ.get("AGENTGUARD_SESSION_TTL", str(SESSION_TTL_SECONDS))),
            "enable_ollama": os.environ.get("AGENTGUARD_ENABLE_OLLAMA", "0") == "1",
            "ollama_model": os.environ.get("AGENTGUARD_OLLAMA_MODEL", "qwen2.5:3b"),
            "ollama_endpoint": os.environ.get("AGENTGUARD_OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/chat"),
            "operator_id": os.environ.get("AGENTGUARD_OPERATOR", "local-operator"),
        }
        values.update(overrides)
        return cls(**values)  # type: ignore[arg-type]
