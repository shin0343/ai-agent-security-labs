"""Offline transport contract tests; these are never real model observations."""

from __future__ import annotations

import io
import json
import urllib.error
from dataclasses import replace

import pytest

from agentguard.workbench import runtime
from agentguard.workbench.errors import ValidationError
from agentguard.workbench.evaluation import run_evaluation

from .conftest import WorkbenchHarness


class FakeOllama:
    def __init__(self, answers):
        self.answers = iter(answers)
        self.requests = []

    def open(self, request, timeout):
        assert request.full_url == "http://127.0.0.1:11434/api/chat"
        assert timeout == 120
        self.requests.append(json.loads(request.data))
        answer = next(self.answers)
        if isinstance(answer, Exception):
            raise answer
        raw = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        return io.BytesIO(raw)


def _install(monkeypatch, answers):
    fake = FakeOllama(answers)

    def build(*handlers):
        assert any(isinstance(handler, runtime._NoRedirect) for handler in handlers)
        assert any(
            isinstance(handler, runtime.urllib.request.ProxyHandler) and handler.proxies == {} for handler in handlers
        )
        return fake

    monkeypatch.setattr(runtime.urllib.request, "build_opener", build)
    return fake


def _run(workbench, preset="deny-v1"):
    return runtime.create_run(
        replace(workbench.settings, enable_ollama=True),
        session_id=workbench.session_id,
        dataset_id=workbench.dataset_id,
        scenario_key="injection",
        policy_preset_id=preset,
        runtime_kind="ollama",
    )


def _answer(calls=None, content=""):
    return {
        "model": "offline-test-double",
        "created_at": "2026-10-20T00:00:00Z",
        "message": {"role": "assistant", "content": content, "tool_calls": calls or []},
    }


def _publish():
    return {
        "function": {
            "name": "publish_simulated",
            "arguments": {"artifact_id": "quarterly-synthetic", "destination": "demo-internal-outbox"},
        }
    }


def test_valid_no_tool_response_is_explicit(workbench: WorkbenchHarness, monkeypatch) -> None:
    _install(monkeypatch, [_answer(content="The retrieved note is untrusted.")])
    result = _run(workbench)
    assert result["status"] == "COMPLETED"
    assert result["requests"] == []
    assert any(trace["kind"] == "no_tool_call" and "NO_TOOL_CALL" in trace["text"] for trace in result["trace"])
    assert result["model"]["observed_response_count"] == 1
    assert result["model"]["model"] == "offline-test-double"


@pytest.mark.parametrize(
    "preset,decision,status,executed",
    [
        ("deny-v1", "BLOCK", "COMPLETED", False),
        ("approve-v1", "REQUIRE_APPROVAL", "WAITING_APPROVAL", False),
        ("monitor-v1", "ALLOW", "COMPLETED", True),
    ],
)
def test_model_proposals_use_the_same_gateway(workbench, monkeypatch, preset, decision, status, executed) -> None:
    fake = _install(monkeypatch, [_answer([_publish()]), _answer(content="Finished.")])
    result = _run(workbench, preset)
    assert result["status"] == status
    assert result["requests"][0]["decision"] == decision
    assert (result["requests"][0]["execution_status"] == "SUCCEEDED") == executed
    if executed:
        assert result["requests"][0]["result"]["synthetic"] is True
        assert "no proposed tool call" not in result["trace"][-1]["text"]
    if status != "WAITING_APPROVAL":
        assert fake.requests[1]["messages"][-1]["role"] == "tool"
        assert json.loads(fake.requests[1]["messages"][-1]["content"])["decision"] == decision


@pytest.mark.parametrize(
    "answer",
    [
        b"{",
        [],
        {"message": []},
        {"message": {"content": 1}},
        {"message": {"tool_calls": {}}},
        {"message": {"tool_calls": [None]}},
        {"message": {"tool_calls": [{"function": {"arguments": {}}}]}},
        _answer([_publish()] * 9),
        b"x" * (2 * 1024 * 1024 + 1),
    ],
    ids=["json", "root", "message", "content", "calls-type", "null-call", "missing-name", "budget", "size"],
)
def test_invalid_model_output_fails_without_invented_success(workbench, monkeypatch, answer) -> None:
    _install(monkeypatch, [answer])
    result = _run(workbench)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "MODEL_INVALID_RESPONSE"
    assert result["requests"] == []
    assert not any(trace["kind"] == "no_tool_call" for trace in result["trace"])


def test_connection_failure_is_not_a_model_observation(workbench, monkeypatch) -> None:
    _install(monkeypatch, [urllib.error.URLError("offline")])
    result = _run(workbench)
    assert result["status"] == "FAILED"
    assert result["model"]["observed"] is False
    evaluation = run_evaluation(workbench.settings, session_id=workbench.session_id, dataset_id=workbench.dataset_id)
    observations = evaluation["summary"]["local_model_observations"]
    assert observations["count"] == 0
    assert observations["attempted_runs"] == 1


def test_redirect_handler_never_follows_a_location() -> None:
    request = runtime.urllib.request.Request("http://127.0.0.1:11434/api/chat")
    with pytest.raises(urllib.error.HTTPError):
        runtime._NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://example.invalid/")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:0/api/chat",
        "http://localhost:bad/api/chat",
        "http://127.0.0.1:11434/api/chat?next=external",
        "http://localhost:11434/api/chat#fragment",
        "http://localhost:11434/other",
        "http://local\nhost:11434/api/chat",
    ],
)
def test_malformed_endpoint_is_rejected_before_transport(endpoint) -> None:
    with pytest.raises(ValidationError):
        runtime.validate_ollama_endpoint(endpoint)
