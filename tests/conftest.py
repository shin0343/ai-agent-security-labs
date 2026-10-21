"""Shared fixtures for the Agent Security Workbench test suites.

The fixture starts a complete local app against an isolated temporary runtime
directory. It uses the real bootstrap, SQLite migrations, synthetic fixture
dataset, audit key and HTTP middleware; no component is stubbed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentguard.workbench.api import create_app
from agentguard.workbench.bootstrap import initialize
from agentguard.workbench.sessions import create_session
from agentguard.workbench.settings import Settings
from agentguard.workbench.util import FIXTURE_DIR

BASE_URL = "http://127.0.0.1:8765"
BOOTSTRAP_CODE = "TEST-ONLY-4A7C-902E"


@dataclass
class WorkbenchHarness:
    settings: Settings
    app: Any
    client: TestClient
    csrf_token: str
    dataset_id: str
    bootstrap_code: str = BOOTSTRAP_CODE
    base_url: str = BASE_URL

    @property
    def runtime_dir(self) -> Path:
        return self.settings.runtime_dir

    @property
    def db_path(self) -> Path:
        return self.settings.db_path

    @property
    def session_id(self) -> str:
        response = self.client.get("/api/v1/session")
        assert response.status_code == 200
        return str(response.json()["session_id"])

    def run(
        self,
        scenario: str = "normal",
        preset: str = "deny-v1",
        *,
        runtime_kind: str = "scripted",
        investigation_id: str | None = None,
    ) -> dict[str, Any]:
        response = self.client.post(
            "/api/v1/runs",
            json={
                "dataset_id": self.dataset_id,
                "scenario_key": scenario,
                "policy_preset_id": preset,
                "runtime_kind": runtime_kind,
                "investigation_id": investigation_id,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    def approval_for(self, run: dict[str, Any]) -> dict[str, Any]:
        request = run["requests"][0]
        approval_id = request["approval_id"]
        assert approval_id, request
        response = self.client.get(f"/api/v1/approvals/{approval_id}")
        assert response.status_code == 200, response.text
        return response.json()

    def decide(
        self,
        approval: dict[str, Any],
        *,
        decision: str = "approve",
        digest: str | None = None,
        version: int | None = None,
        reason: str = "Approved for one local synthetic receipt.",
        idempotency_key: str = "test-decision-1",
        headers: dict[str, str] | None = None,
        client: TestClient | None = None,
    ):
        request_headers = {
            "Idempotency-Key": idempotency_key,
            **(headers or {}),
        }
        target = client or self.client
        return target.post(
            f"/api/v1/approvals/{approval['id']}/decision",
            json={
                "decision": decision,
                "reviewed_request_digest": digest or approval["request_digest"],
                "expected_version": version or approval["expected_version"],
                "reason": reason,
            },
            headers=request_headers,
        )


def _new_client(app: Any, token: str | None = None) -> TestClient:
    client = TestClient(app, base_url=BASE_URL)
    if token:
        client.cookies.set("ag_session", token, domain="127.0.0.1", path="/")
    return client


@pytest.fixture()
def workbench(tmp_path: Path) -> WorkbenchHarness:
    runtime_dir = tmp_path / "runtime"
    settings = Settings(
        db_path=runtime_dir / "workbench.db",
        runtime_dir=runtime_dir,
        fixture_dir=FIXTURE_DIR,
        frontend_dist=tmp_path / "frontend-dist",
        port=8765,
    )
    initialized = initialize(settings)
    assert initialized["status"] == "READY", initialized
    app = create_app(settings, bootstrap_code=BOOTSTRAP_CODE)
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.post(
            "/api/v1/session/exchange",
            json={"code": BOOTSTRAP_CODE},
            headers={"Origin": BASE_URL},
        )
        assert response.status_code == 200, response.text
        csrf = str(response.json()["csrf_token"])
        client.headers.update({"Origin": BASE_URL, "X-CSRF-Token": csrf})
        harness = WorkbenchHarness(
            settings=settings,
            app=app,
            client=client,
            csrf_token=csrf,
            dataset_id=str(initialized["dataset_id"]),
        )
        yield harness


@pytest.fixture()
def second_session(workbench: WorkbenchHarness):
    created = create_session(workbench.settings, "second-local-operator")
    with _new_client(workbench.app, created["token"]) as client:
        client.headers.update(
            {
                "Origin": BASE_URL,
                "X-CSRF-Token": created["csrf_token"],
            }
        )
        yield client, created
