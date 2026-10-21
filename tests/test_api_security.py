"""HTTP boundary tests: session, origin/host, CSRF, body limits and headers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.workbench.api import create_app
from agentguard.workbench.settings import Settings
from agentguard.workbench.util import FIXTURE_DIR

from .conftest import BASE_URL, BOOTSTRAP_CODE, WorkbenchHarness


@pytest.fixture()
def bootstrap_client(tmp_path: Path):
    runtime_dir = tmp_path / "bootstrap-runtime"
    settings = Settings(
        db_path=runtime_dir / "workbench.db",
        runtime_dir=runtime_dir,
        fixture_dir=FIXTURE_DIR,
        frontend_dist=tmp_path / "dist",
        port=8765,
    )
    app = create_app(settings, bootstrap_code=BOOTSTRAP_CODE)
    with TestClient(app, base_url=BASE_URL) as client:
        yield client


def test_unauthenticated_session_has_stable_error_envelope(workbench: WorkbenchHarness) -> None:
    with TestClient(workbench.app, base_url=BASE_URL) as anonymous:
        response = anonymous.get("/api/v1/session")
    assert response.status_code == 401
    body = response.json()
    assert body["code"] == "UNAUTHENTICATED"
    assert body["request_id"].startswith("reqid_")
    assert "message" in body
    assert response.headers["cache-control"] == "no-store"


def test_bootstrap_is_single_use_and_cookie_is_hardened(bootstrap_client: TestClient) -> None:
    bad = bootstrap_client.post(
        "/api/v1/session/exchange",
        json={"code": "WRONG-CODE"},
        headers={"Origin": BASE_URL},
    )
    assert bad.status_code == 403
    assert bad.json()["code"] == "FORBIDDEN"

    response = bootstrap_client.post(
        "/api/v1/session/exchange",
        json={"code": BOOTSTRAP_CODE},
        headers={"Origin": BASE_URL},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["session_id"].startswith("ses_")
    assert body["scope"] == "local_operator_not_verified_human_identity"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/" in cookie

    replay = bootstrap_client.post(
        "/api/v1/session/exchange",
        json={"code": BOOTSTRAP_CODE},
        headers={"Origin": BASE_URL},
    )
    assert replay.status_code == 403
    assert "already" in replay.json()["message"].lower()

    session = bootstrap_client.get("/api/v1/session")
    assert session.status_code == 200
    assert session.json()["session_id"] == body["session_id"]


def test_security_headers_and_no_cors(workbench: WorkbenchHarness) -> None:
    response = workbench.client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers

    preflight = workbench.client.options(
        "/api/v1/runs",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_untrusted_host_is_rejected(workbench: WorkbenchHarness) -> None:
    response = workbench.client.get("/api/v1/session", headers={"Host": "evil.example"})
    assert response.status_code == 403
    assert response.json()["code"] == "UNTRUSTED_HOST"


@pytest.mark.parametrize(
    ("header", "value", "code"),
    [
        ("Origin", "https://evil.example", "UNTRUSTED_ORIGIN"),
        ("Origin", "http://127.0.0.1:9999", "UNTRUSTED_ORIGIN"),
        ("Sec-Fetch-Site", "cross-site", "CROSS_SITE_REQUEST"),
    ],
)
def test_cross_site_mutations_are_rejected(workbench: WorkbenchHarness, header: str, value: str, code: str) -> None:
    response = workbench.client.post(
        "/api/v1/datasets/sample/import",
        json={},
        headers={header: value},
    )
    assert response.status_code == 403
    assert response.json()["code"] == code


def test_csrf_is_required_and_compared(workbench: WorkbenchHarness) -> None:
    for headers in ({"X-CSRF-Token": ""}, {"X-CSRF-Token": "wrong-token"}):
        response = workbench.client.post(
            "/api/v1/datasets/sample/import",
            json={},
            headers=headers,
        )
        assert response.status_code == 403
        assert response.json()["code"] == "FORBIDDEN"
        assert "CSRF" in response.json()["message"]


def test_json_content_type_is_required(workbench: WorkbenchHarness) -> None:
    response = workbench.client.post(
        "/api/v1/datasets/sample/import",
        content=b"{}",
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 415
    assert response.json()["code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_empty_json_body_passes_body_middleware(workbench: WorkbenchHarness) -> None:
    # This is the request shape the browser uses for body-less mutations.
    response = workbench.client.post(
        "/api/v1/audit/verifications",
        content=b"",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["verification_id"].startswith("ver_")


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b'"text"',
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"\xff",
    ],
)
def test_invalid_json_is_rejected(workbench: WorkbenchHarness, raw: bytes) -> None:
    response = workbench.client.post(
        "/api/v1/runs",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_JSON"


def test_oversized_body_is_rejected(workbench: WorkbenchHarness) -> None:
    raw = json.dumps({"value": "x" * (70 * 1024)}).encode("utf-8")
    response = workbench.client.post(
        "/api/v1/runs",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "BODY_TOO_LARGE"


def test_unknown_api_route_stays_json(workbench: WorkbenchHarness) -> None:
    response = workbench.client.get("/api/v1/not-a-route")
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"
    assert response.headers["content-type"].startswith("application/json")


def test_mutation_requires_authenticated_session(workbench: WorkbenchHarness) -> None:
    with TestClient(workbench.app, base_url=BASE_URL) as anonymous:
        response = anonymous.post(
            "/api/v1/runs",
            json={
                "dataset_id": workbench.dataset_id,
                "scenario_key": "normal",
                "policy_preset_id": "deny-v1",
            },
            headers={"Origin": BASE_URL},
        )
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHENTICATED"
