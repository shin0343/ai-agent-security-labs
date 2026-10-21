"""Same-origin FastAPI application for the local Agent Security Workbench."""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .audit import AuditUnavailable, read_events, verify_audit
from .bootstrap import import_sample, initialize
from .cases import create_case, export_case, get_case, get_export, list_cases, revise_case
from .db import migrate, read_connection, transaction
from .detection import run_detection
from .enforcement import _request_detail_conn, change_run_policy, decide_approval, get_request_detail
from .errors import (
    AuditIntegrityError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
    WorkbenchError,
)
from .evaluation import export_report, get_evaluation, list_evaluations, run_evaluation
from .evidence import EvidenceError, list_datasets, resolve_evidence
from .findings import finding_counts, finding_detail, list_findings
from .investigations import create_investigation, get_investigation, list_investigations, save_verdict
from .overview import build_overview
from .policy import POLICY_MODES, TOOLS
from .runtime import SCENARIOS, create_run, get_run_detail, list_runs
from .sessions import (
    constant_time_code,
    create_session,
    csrf_matches,
    generate_bootstrap_code,
    resolve_session,
)
from .settings import Settings
from .util import API_PREFIX, MAX_REQUEST_BODY_BYTES, canonical_json, safe_json_loads, utc_iso


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ExchangeRequest(StrictModel):
    code: str = Field(min_length=1, max_length=64)


class RunCreateRequest(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=80)
    scenario_key: Literal["normal", "injection", "overreach", "boundary_aware"]
    policy_preset_id: str = Field(min_length=1, max_length=80)
    runtime_kind: Literal["scripted", "ollama"] = "scripted"
    investigation_id: str | None = None


class ApprovalDecisionRequest(StrictModel):
    decision: Literal["approve", "reject"]
    reviewed_request_digest: str = Field(min_length=64, max_length=64)
    expected_version: int = Field(ge=1, le=1_000_000)
    reason: str = Field(min_length=1, max_length=500)


class InvestigationCreateRequest(StrictModel):
    dataset_id: str
    title: str = Field(min_length=1, max_length=160)
    finding_ids: list[str] = Field(min_length=1, max_length=50)
    notes: str = Field(default="", max_length=4000)


class VerdictRequest(StrictModel):
    verdict: Literal[
        "POLICY_VIOLATION_SUPPORTED",
        "WITHIN_OBSERVED_SCOPE",
        "INSUFFICIENT_EVIDENCE",
        "NEEDS_MORE_DATA",
    ]
    rationale: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    expected_revision: int = Field(ge=1, le=1_000_000)


class PolicyChangeRequest(StrictModel):
    policy_preset_id: str
    expected_revision: int = Field(ge=1, le=1_000_000)


class EvaluationCreateRequest(StrictModel):
    dataset_id: str


class CaseCreateRequest(StrictModel):
    dataset_id: str
    title: str = Field(min_length=1, max_length=160)
    finding_ids: list[str] = Field(min_length=1, max_length=50)
    request_ids: list[str] = Field(default_factory=list, max_length=50)
    investigation_id: str | None = None
    summary: str = Field(min_length=1, max_length=4000)
    scope: str = Field(min_length=1, max_length=2000)
    analyst_conclusion: str = Field(min_length=1, max_length=4000)
    recommendations: list[str] = Field(default_factory=list, max_length=20)


class CaseReviseRequest(StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=4000)
    scope: str = Field(min_length=1, max_length=2000)
    analyst_conclusion: str = Field(min_length=1, max_length=4000)
    recommendations: list[str] = Field(default_factory=list, max_length=20)
    status: Literal["OPEN", "CLOSED"] = "OPEN"


class ExportCreateRequest(StrictModel):
    format: Literal["markdown", "json", "csv"] = "markdown"


def _error_payload(code: str, message: str, request_id: str, details: dict | None = None) -> dict:
    return {
        "code": code,
        "message": message,
        "request_id": request_id,
        "details": details or {},
    }


def _json_error(status: int, code: str, message: str, request_id: str, details: dict | None = None) -> JSONResponse:
    return JSONResponse(
        _error_payload(code, message, request_id, details),
        status_code=status,
        headers={"Cache-Control": "no-store", "X-Request-ID": request_id},
    )


class SecurityMiddleware:
    """Exact Host/Origin checks, request IDs, browser headers and no CORS."""

    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = f"reqid_{secrets.token_hex(8)}"
        scope.setdefault("state", {})["request_id"] = request_id
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        host = headers.get("host", "")
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")
        response_started = False

        async def send_with_headers(message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                managed = {
                    b"x-request-id",
                    b"x-content-type-options",
                    b"referrer-policy",
                    b"x-frame-options",
                    b"cross-origin-resource-policy",
                    b"content-security-policy",
                    b"cache-control",
                }
                response_headers = [
                    (key, value) for key, value in message.get("headers", []) if key.lower() not in managed
                ]
                response_headers.extend(
                    [
                        (b"x-request-id", request_id.encode()),
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-frame-options", b"DENY"),
                        (b"cross-origin-resource-policy", b"same-origin"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                            # WebKit's native select applies this exact inert UA declaration.
                            # Keep arbitrary inline styles and all inline scripts forbidden.
                            b"style-src-attr 'unsafe-hashes' 'sha256-3oFxofzq3N//6J8H86e9ul4WT2OkJrtonB66gn/TLJw='; "
                            b"connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                            b"object-src 'none'; form-action 'none'",
                        ),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message["headers"] = response_headers
            await send(message)

        if host not in self.settings.allowed_hosts:
            await _json_error(403, "UNTRUSTED_HOST", "Host is not allowed.", request_id)(
                scope, receive, send_with_headers
            )
            return
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = headers.get("origin")
            if origin not in self.settings.origins or origin != f"http://{host}":
                await _json_error(
                    403, "UNTRUSTED_ORIGIN", "Mutation requires an exact same-origin request.", request_id
                )(scope, receive, send_with_headers)
                return
            fetch_site = headers.get("sec-fetch-site")
            if fetch_site and fetch_site not in {"same-origin", "none"}:
                await _json_error(403, "CROSS_SITE_REQUEST", "Cross-site mutation is not allowed.", request_id)(
                    scope, receive, send_with_headers
                )
                return
            if path.startswith(API_PREFIX):
                content_type = headers.get("content-type", "").split(";")[0].strip().lower()
                if content_type != "application/json":
                    await _json_error(415, "UNSUPPORTED_MEDIA_TYPE", "JSON content type is required.", request_id)(
                        scope, receive, send_with_headers
                    )
                    return
        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            if response_started:
                raise
            await _json_error(
                500, "INTERNAL_ERROR", "An internal error occurred. No raw exception details are exposed.", request_id
            )(scope, receive, send_with_headers)


class BodyLimitMiddleware:
    """Cap streamed bodies, reject duplicate keys and re-emit canonical JSON."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        request_id = scope.get("state", {}).get("request_id", "unknown")
        if not path.startswith(API_PREFIX):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > MAX_REQUEST_BODY_BYTES:
                await _json_error(413, "BODY_TOO_LARGE", "Request body exceeds the configured limit.", request_id)(
                    scope, receive, send
                )
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        raw = b"".join(chunks)
        try:
            text = raw.decode("utf-8", errors="strict")
            parsed = safe_json_loads(text) if text else None
        except (UnicodeDecodeError, ValueError):
            await _json_error(400, "INVALID_JSON", "Request body is not valid JSON.", request_id)(scope, receive, send)
            return
        if raw and not isinstance(parsed, dict):
            await _json_error(400, "INVALID_JSON", "Request body must be a JSON object.", request_id)(
                scope, receive, send
            )
            return
        replacement = canonical_json(parsed) if parsed is not None else b""
        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": replacement, "more_body": False}
            return await receive()

        new_headers = []
        for key, value in scope.get("headers", []):
            if key.lower() == b"content-length":
                continue
            new_headers.append((key, value))
        new_headers.append((b"content-length", str(len(replacement)).encode()))
        scope["headers"] = new_headers
        await self.app(scope, replay_receive, send)


def create_app(settings: Settings, bootstrap_code: str | None = None) -> FastAPI:
    migrate(settings.db_path)
    settings.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(settings.runtime_dir, 0o700)
    except OSError:
        pass
    app = FastAPI(
        title="Agent Security Workbench",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.bootstrap_code = bootstrap_code or generate_bootstrap_code()
    app.state.bootstrap_expires = time.time() + 10 * 60
    app.state.bootstrap_used = False
    app.state.bootstrap_attempts = 0
    app.state.bootstrap_lock = threading.Lock()
    app.state.verification_cache = {}

    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(SecurityMiddleware, settings=settings)

    @app.exception_handler(WorkbenchError)
    async def workbench_error(request: Request, exc: WorkbenchError) -> JSONResponse:
        return _json_error(
            exc.status_code,
            exc.code,
            exc.message,
            getattr(request.state, "request_id", "unknown"),
            exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = {
            "errors": [
                {"location": ".".join(str(part) for part in item.get("loc", [])), "type": item.get("type")}
                for item in exc.errors()[:20]
            ]
        }
        return _json_error(
            422,
            "VALIDATION_ERROR",
            "Request did not match the API contract.",
            getattr(request.state, "request_id", "unknown"),
            details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        return _json_error(
            exc.status_code,
            code,
            "The requested resource was not found." if exc.status_code == 404 else "Request failed.",
            getattr(request.state, "request_id", "unknown"),
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def sqlite_error(request: Request, exc: sqlite3.IntegrityError) -> JSONResponse:
        return _json_error(
            409,
            "STATE_CONFLICT",
            "The state change conflicted with a database constraint.",
            getattr(request.state, "request_id", "unknown"),
        )

    @app.exception_handler(AuditUnavailable)
    async def audit_unavailable(request: Request, exc: AuditUnavailable) -> JSONResponse:
        return _json_error(
            503,
            "AUDIT_INTEGRITY_FAILED",
            "Audit verification prevents this change.",
            getattr(request.state, "request_id", "unknown"),
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        return _json_error(
            500,
            "INTERNAL_ERROR",
            "An internal error occurred. No raw exception details are exposed.",
            getattr(request.state, "request_id", "unknown"),
        )

    def require_session(request: Request) -> dict[str, Any]:
        session = resolve_session(settings, request.cookies.get("ag_session"))
        if session is None:
            raise UnauthorizedError("A local operator session is required.")
        return session

    def mutation_session(
        request: Request,
        x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
        session: dict[str, Any] = Depends(require_session),
    ) -> dict[str, Any]:
        if not csrf_matches(str(session["csrf_token"]), x_csrf_token):
            raise ForbiddenError("CSRF token is missing or invalid.")
        return session

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "product": "Agent Security Workbench", "synthetic": True}

    @app.get(f"{API_PREFIX}/session")
    def session_info(session: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
        return {
            "session_id": session["session_id"],
            "operator_id": session["operator_id"],
            "csrf_token": session["csrf_token"],
            "expires_at": session["expires_at"],
            "scope": "local_operator_not_verified_human_identity",
        }

    @app.post(f"{API_PREFIX}/session/exchange")
    def exchange_session(body: ExchangeRequest, request: Request) -> JSONResponse:
        now = time.time()
        with app.state.bootstrap_lock:
            if app.state.bootstrap_used:
                raise ForbiddenError("Bootstrap code has already been used.")
            if now > app.state.bootstrap_expires:
                raise ForbiddenError("Bootstrap code has expired. Restart the local server.")
            if app.state.bootstrap_attempts >= 5:
                raise ForbiddenError("Too many failed bootstrap attempts. Restart the local server.")
            if not constant_time_code(app.state.bootstrap_code, body.code):
                app.state.bootstrap_attempts += 1
                raise ForbiddenError("Bootstrap code is invalid.")
            app.state.bootstrap_used = True
        created = create_session(settings, settings.operator_id)
        response = JSONResponse(
            {
                "session_id": created["session_id"],
                "operator_id": created["operator_id"],
                "csrf_token": created["csrf_token"],
                "expires_at": created["expires_at"],
                "scope": "local_operator_not_verified_human_identity",
            }
        )
        response.set_cookie(
            "ag_session",
            created["token"],
            max_age=settings.session_ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        return response

    @app.get(f"{API_PREFIX}/datasets")
    def datasets(_: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            return {"items": list_datasets(conn), "as_of": utc_iso()}

    @app.post(f"{API_PREFIX}/datasets/sample/import")
    def sample_import(_: dict = Depends(mutation_session)) -> dict[str, Any]:
        result = import_sample(settings, run_detection_if_missing=True)
        if result["status"] != "READY":
            raise AuditIntegrityError(result.get("message", "Audit blocks mutation."))
        return result

    @app.post(f"{API_PREFIX}/datasets/{{dataset_id}}/detect")
    def detect(dataset_id: str, _: dict = Depends(mutation_session)) -> dict[str, Any]:
        with transaction(settings.db_path) as conn:
            if conn.execute("SELECT id FROM datasets WHERE id = ?", (dataset_id,)).fetchone() is None:
                raise NotFoundError("Dataset not found.")
            try:
                outcome = run_detection(conn, settings.runtime_dir, dataset_id)
            except AuditUnavailable as exc:
                raise AuditIntegrityError(str(exc)) from exc
        return outcome

    @app.get(f"{API_PREFIX}/overview")
    def overview(
        dataset_id: str | None = Query(default=None, max_length=80),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        return build_overview(settings, dataset_id)

    @app.get(f"{API_PREFIX}/findings")
    def findings(
        dataset_id: str | None = Query(default=None, max_length=80),
        disposition: Literal["REVIEW", "LOW", "UNKNOWN"] | None = None,
        limit: int = Query(default=100, ge=1, le=200),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            items = list_findings(conn, dataset_id=dataset_id, disposition=disposition, limit=limit)
            counts = finding_counts(conn, dataset_id) if dataset_id else None
            return {"items": items, "counts": counts, "as_of": utc_iso()}

    @app.get(f"{API_PREFIX}/findings/{{finding_id}}")
    def finding(finding_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            result = finding_detail(conn, finding_id)
        if result is None:
            raise NotFoundError("Finding not found.")
        return result

    @app.get(f"{API_PREFIX}/events/{{event_id}}")
    def event(event_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            try:
                return resolve_evidence(conn, event_id)
            except EvidenceError as exc:
                raise ConflictError(str(exc), details={"event_id": event_id}) from exc

    @app.get(f"{API_PREFIX}/policies")
    def policies(_: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            presets = [dict(row) for row in conn.execute("SELECT * FROM policy_presets ORDER BY version, name")]
        tools = [
            {
                "name": definition.name,
                "description": definition.description,
                "effect": definition.effect,
                "allowed_args": {key: list(values) for key, values in definition.allowed_args.items()},
                "schema_version": definition.schema_version,
                "always_blocked": definition.name in {"read_secret"},
            }
            for definition in TOOLS.values()
        ]
        return {
            "presets": presets,
            "tools": tools,
            "modes": list(POLICY_MODES),
            "note": "The server loads the preset. Agents and browser clients cannot select a per-request mode.",
        }

    @app.get(f"{API_PREFIX}/requests")
    def requests_list(
        dataset_id: str | None = Query(default=None, max_length=80),
        status: str | None = Query(default=None, max_length=40),
        limit: int = Query(default=50, ge=1, le=200),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            clauses = []
            params: list[Any] = []
            if dataset_id:
                clauses.append("run.dataset_id = ?")
                params.append(dataset_id)
            if status:
                clauses.append("r.status = ?")
                params.append(status)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            params.append(limit)
            rows = conn.execute(
                f"""SELECT r.id FROM tool_requests r JOIN runs run ON run.id = r.run_id
                    {where} ORDER BY r.created_at DESC LIMIT ?""",
                params,
            ).fetchall()
            items = [_request_detail_conn(conn, str(row["id"])) for row in rows]
        return {"items": items, "as_of": utc_iso()}

    @app.get(f"{API_PREFIX}/requests/{{request_id}}")
    def request_detail(request_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        return get_request_detail(settings, request_id)

    @app.get(f"{API_PREFIX}/approvals")
    def approvals(
        state: str | None = Query(default=None, max_length=40),
        dataset_id: str | None = Query(default=None, max_length=80),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            clauses = []
            params: list[Any] = []
            if state:
                clauses.append("a.state = ?")
                params.append(state)
            if dataset_id:
                clauses.append("run.dataset_id = ?")
                params.append(dataset_id)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"""SELECT a.*, r.tool, r.status AS request_status, r.run_id, run.scenario_key
                    FROM approvals a JOIN tool_requests r ON r.id = a.request_id
                    JOIN runs run ON run.id = r.run_id {where}
                    ORDER BY CASE a.state WHEN 'PENDING' THEN 0 ELSE 1 END, a.created_at DESC""",
                params,
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["expired"] = item["state"] == "PENDING" and item["expires_at"] < utc_iso()
                item["detail"] = _request_detail_conn(conn, str(item["request_id"]))
                items.append(item)
        return {"items": items, "as_of": utc_iso()}

    @app.get(f"{API_PREFIX}/approvals/{{approval_id}}")
    def approval_detail(approval_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            row = conn.execute(
                """SELECT a.*, r.tool, r.status AS request_status, r.run_id, run.scenario_key
                   FROM approvals a JOIN tool_requests r ON r.id = a.request_id
                   JOIN runs run ON run.id = r.run_id WHERE a.id = ?""",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("Approval not found.")
            data = dict(row)
            data["expired"] = data["state"] == "PENDING" and data["expires_at"] < utc_iso()
            data["request"] = _request_detail_conn(conn, str(data["request_id"]))
            return data

    @app.post(f"{API_PREFIX}/approvals/{{approval_id}}/decision")
    def approval_decision(
        approval_id: str,
        body: ApprovalDecisionRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session: dict[str, Any] = Depends(mutation_session),
    ) -> dict[str, Any]:
        if not idempotency_key:
            raise ValidationError("Idempotency-Key header is required.")
        return decide_approval(
            settings,
            session_id=str(session["session_id"]),
            approval_id=approval_id,
            decision=body.decision,
            reviewed_request_digest=body.reviewed_request_digest,
            expected_version=body.expected_version,
            reason=body.reason,
            idempotency_key=idempotency_key,
        )

    @app.get(f"{API_PREFIX}/runs")
    def runs(
        dataset_id: str | None = Query(default=None, max_length=80),
        limit: int = Query(default=50, ge=1, le=200),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        return {"items": list_runs(settings, dataset_id=dataset_id, limit=limit), "as_of": utc_iso()}

    @app.get(f"{API_PREFIX}/scenarios")
    def scenarios(_: dict = Depends(require_session)) -> dict[str, Any]:
        return {
            "items": [{"key": key, **value} for key, value in SCENARIOS.items()],
            "ollama": {
                "enabled": settings.enable_ollama,
                "model": settings.ollama_model,
                "note": (
                    "Optional local-only runtime. It proposes the same tool DTOs and every proposal "
                    "passes the deterministic gateway."
                ),
            },
        }

    @app.post(f"{API_PREFIX}/runs")
    def start_run(body: RunCreateRequest, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        return create_run(
            settings,
            session_id=str(session["session_id"]),
            dataset_id=body.dataset_id,
            scenario_key=body.scenario_key,
            policy_preset_id=body.policy_preset_id,
            runtime_kind=body.runtime_kind,
            investigation_id=body.investigation_id,
        )

    @app.get(f"{API_PREFIX}/runs/{{run_id}}")
    def run_detail(run_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        return get_run_detail(settings, run_id)

    @app.post(f"{API_PREFIX}/runs/{{run_id}}/cancel")
    def cancel(run_id: str, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        from .enforcement import cancel_run

        return cancel_run(settings, run_id=run_id, session_id=str(session["session_id"]))

    @app.post(f"{API_PREFIX}/runs/{{run_id}}/policy")
    def run_policy(run_id: str, body: PolicyChangeRequest, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        return change_run_policy(
            settings,
            run_id=run_id,
            session_id=str(session["session_id"]),
            policy_preset_id=body.policy_preset_id,
            expected_revision=body.expected_revision,
        )

    @app.get(f"{API_PREFIX}/investigations")
    def investigations(
        dataset_id: str | None = Query(default=None, max_length=80),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            return {"items": list_investigations(conn, dataset_id=dataset_id), "as_of": utc_iso()}

    @app.post(f"{API_PREFIX}/investigations")
    def investigation_create(
        body: InvestigationCreateRequest, session: dict = Depends(mutation_session)
    ) -> dict[str, Any]:
        return create_investigation(
            settings,
            session_id=str(session["session_id"]),
            dataset_id=body.dataset_id,
            title=body.title,
            finding_ids=body.finding_ids,
            notes=body.notes,
        )

    @app.get(f"{API_PREFIX}/investigations/{{investigation_id}}")
    def investigation_detail(investigation_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        return get_investigation(settings, investigation_id)

    @app.post(f"{API_PREFIX}/investigations/{{investigation_id}}/verdicts")
    def verdict(
        investigation_id: str, body: VerdictRequest, session: dict = Depends(mutation_session)
    ) -> dict[str, Any]:
        return save_verdict(
            settings,
            session_id=str(session["session_id"]),
            investigation_id=investigation_id,
            verdict=body.verdict,
            rationale=body.rationale,
            evidence_ids=body.evidence_ids,
            expected_revision=body.expected_revision,
        )

    @app.get(f"{API_PREFIX}/evaluations")
    def evaluations(
        dataset_id: str | None = Query(default=None, max_length=80), _: dict = Depends(require_session)
    ) -> dict[str, Any]:
        return {"items": list_evaluations(settings, dataset_id=dataset_id), "as_of": utc_iso()}

    @app.post(f"{API_PREFIX}/evaluations")
    def evaluation_create(body: EvaluationCreateRequest, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        return run_evaluation(settings, session_id=str(session["session_id"]), dataset_id=body.dataset_id)

    @app.get(f"{API_PREFIX}/evaluations/{{evaluation_id}}")
    def evaluation_detail(evaluation_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        try:
            return get_evaluation(settings, evaluation_id)
        except ValueError as exc:
            raise NotFoundError(str(exc)) from exc

    @app.get(f"{API_PREFIX}/evaluations/{{evaluation_id}}/export")
    def evaluation_export(
        evaluation_id: str,
        format: Literal["json", "markdown", "csv"] = "json",
        _: dict = Depends(require_session),
    ) -> Response:
        try:
            content = export_report(settings, evaluation_id, format)
        except ValueError as exc:
            raise NotFoundError(str(exc)) from exc
        media = {
            "json": "application/json",
            "markdown": "text/markdown",
            "csv": "text/csv",
        }[format]
        extension = {"json": "json", "markdown": "md", "csv": "csv"}[format]
        return Response(
            content,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="evaluation-{evaluation_id}.{extension}"'},
        )

    @app.get(f"{API_PREFIX}/audit/events")
    def audit_events(
        before_seq: int | None = Query(default=None, ge=1),
        limit: int = Query(default=100, ge=1, le=200),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            return {
                "items": read_events(conn, limit=limit, before_seq=before_seq),
                "as_of": utc_iso(),
            }

    @app.get(f"{API_PREFIX}/audit/summary")
    def audit_summary(_: dict = Depends(require_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            return verify_audit(conn, settings.runtime_dir).as_dict()

    @app.post(f"{API_PREFIX}/audit/verifications")
    def audit_verification(_: dict = Depends(mutation_session)) -> dict[str, Any]:
        with read_connection(settings.db_path) as conn:
            report = verify_audit(conn, settings.runtime_dir).as_dict()
        report_id = f"ver_{secrets.token_hex(8)}"
        report["verification_id"] = report_id
        report["generated_at"] = utc_iso()
        app.state.verification_cache[report_id] = report
        if len(app.state.verification_cache) > 20:
            oldest = next(iter(app.state.verification_cache))
            app.state.verification_cache.pop(oldest, None)
        return report

    @app.get(f"{API_PREFIX}/audit/verifications/{{verification_id}}")
    def audit_verification_get(verification_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        report = app.state.verification_cache.get(verification_id)
        if report is None:
            raise WorkbenchError(
                "Verification report expired. Run verification again.",
                details={"code": "VERIFICATION_EXPIRED"},
            )
        return report

    @app.get(f"{API_PREFIX}/cases")
    def cases(
        dataset_id: str | None = Query(default=None, max_length=80),
        _: dict = Depends(require_session),
    ) -> dict[str, Any]:
        return {"items": list_cases(settings, dataset_id=dataset_id), "as_of": utc_iso()}

    @app.post(f"{API_PREFIX}/cases")
    def case_create(body: CaseCreateRequest, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        return create_case(
            settings,
            session_id=str(session["session_id"]),
            title=body.title,
            dataset_id=body.dataset_id,
            finding_ids=body.finding_ids,
            request_ids=body.request_ids,
            investigation_id=body.investigation_id,
            summary=body.summary,
            scope=body.scope,
            analyst_conclusion=body.analyst_conclusion,
            recommendations=body.recommendations,
        )

    @app.get(f"{API_PREFIX}/cases/{{case_id}}")
    def case_detail(case_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        return get_case(settings, case_id)

    @app.post(f"{API_PREFIX}/cases/{{case_id}}/revisions")
    def case_revise(case_id: str, body: CaseReviseRequest, session: dict = Depends(mutation_session)) -> dict[str, Any]:
        return revise_case(
            settings,
            session_id=str(session["session_id"]),
            case_id=case_id,
            expected_revision=body.expected_revision,
            title=body.title,
            summary=body.summary,
            scope=body.scope,
            analyst_conclusion=body.analyst_conclusion,
            recommendations=body.recommendations,
            status=body.status,
        )

    @app.post(f"{API_PREFIX}/cases/{{case_id}}/exports")
    def case_export(
        case_id: str, body: ExportCreateRequest, session: dict = Depends(mutation_session)
    ) -> dict[str, Any]:
        return export_case(
            settings,
            session_id=str(session["session_id"]),
            case_id=case_id,
            fmt=body.format,
        )

    @app.get(f"{API_PREFIX}/exports/{{export_id}}")
    def export_detail(export_id: str, _: dict = Depends(require_session)) -> dict[str, Any]:
        return get_export(settings, export_id)

    dist = Path(settings.frontend_dist)
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", response_class=HTMLResponse)
    def index() -> Response:
        index_file = dist / "index.html"
        if index_file.is_file():
            return FileResponse(index_file, media_type="text/html")
        return HTMLResponse(
            "<!doctype html><title>Agent Security Workbench</title>"
            "<main><h1>Frontend build not found</h1>"
            "<p>Run <code>make setup</code> and build the frontend, or use the API under "
            "<code>/api/v1</code>.</p></main>",
            status_code=503,
        )

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str, request: Request) -> Response:
        if full_path == "api" or full_path.startswith("api/"):
            raise NotFoundError("API route not found.")
        index_file = dist / "index.html"
        if index_file.is_file():
            return FileResponse(index_file, media_type="text/html")
        raise NotFoundError("Not found.")

    return app


def main() -> None:
    import uvicorn

    settings = Settings.from_env()
    code = generate_bootstrap_code()
    app = create_app(settings, bootstrap_code=code)
    result = initialize(settings)
    print("Agent Security Workbench", flush=True)
    print(f"Local URL: http://{settings.host}:{settings.port}", flush=True)
    if result["status"] == "READY":
        print(f"Bootstrap code: {code} (single use, expires in 10 minutes)", flush=True)
    else:
        print(f"Bootstrap disabled: {result.get('message', result['status'])}", flush=True)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")


if __name__ == "__main__":
    main()
