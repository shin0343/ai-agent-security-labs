"""Failure injection and OS-process tests against disposable SQLite state."""

from __future__ import annotations

import multiprocessing
import os

import pytest

from agentguard.workbench import enforcement
from agentguard.workbench.audit import verify_audit
from agentguard.workbench.db import read_connection
from agentguard.workbench.errors import ConflictError


def _decision(settings, session_id, approval, key):
    return enforcement.decide_approval(
        settings,
        session_id=session_id,
        approval_id=approval["id"],
        decision="approve",
        reviewed_request_digest=approval["request_digest"],
        expected_version=approval["expected_version"],
        reason="Transaction recovery test.",
        idempotency_key=key,
    )


def _race_worker(settings, session_id, approval, barrier, output, key):
    barrier.wait(timeout=10)
    try:
        _decision(settings, session_id, approval, key)
        output.put("committed")
    except ConflictError:
        output.put("conflict")


def _crash_worker(settings, session_id, approval):
    original = enforcement._execute_synthetic

    def crash_after_receipt(conn, request):
        original(conn, request)
        os._exit(73)  # Deliberate process termination before transaction commit.

    enforcement._execute_synthetic = crash_after_receipt
    _decision(settings, session_id, approval, "crash-before-commit")


def _snapshot(workbench):
    with read_connection(workbench.db_path) as conn:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "simulated_receipts",
                "execution_results",
                "idempotency_records",
                "audit_events",
                "trace_events",
            )
        }


@pytest.mark.parametrize("boundary", ["_execute_synthetic", "_append_trace", "append_audit"])
def test_exception_after_each_write_rolls_back_the_entire_approval(workbench, monkeypatch, boundary):
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    before = _snapshot(workbench)
    original = getattr(enforcement, boundary)

    def fail_after_write(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("Injected persistence failure")

    with monkeypatch.context() as patch:
        patch.setattr(enforcement, boundary, fail_after_write)
        with pytest.raises(OSError, match="Injected"):
            _decision(workbench.settings, workbench.session_id, approval, "fault-retry")
    assert _snapshot(workbench) == before
    assert workbench.approval_for(run)["state"] == "PENDING"
    assert workbench.decide(approval, idempotency_key="fault-retry").status_code == 200


def test_two_os_processes_consume_one_approval_once(workbench):
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    ctx = multiprocessing.get_context("spawn")
    barrier, output = ctx.Barrier(2), ctx.Queue()
    session_id = workbench.session_id
    processes = [
        ctx.Process(target=_race_worker, args=(workbench.settings, session_id, approval, barrier, output, key))
        for key in ("process-a", "process-b")
    ]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=20)
            assert process.exitcode == 0
        assert sorted([output.get(timeout=5), output.get(timeout=5)]) == ["committed", "conflict"]
        assert _snapshot(workbench)["simulated_receipts"] == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        output.close()


def test_process_exit_before_commit_recovers_pending_request(workbench):
    run = workbench.run("injection", "approve-v1")
    approval = workbench.approval_for(run)
    before = _snapshot(workbench)
    ctx = multiprocessing.get_context("spawn")
    process = ctx.Process(target=_crash_worker, args=(workbench.settings, workbench.session_id, approval))
    try:
        process.start()
        process.join(timeout=20)
        assert process.exitcode == 73
        assert _snapshot(workbench) == before
        assert workbench.approval_for(run)["state"] == "PENDING"
        with read_connection(workbench.db_path) as conn:
            assert verify_audit(conn, workbench.runtime_dir).safe_for_mutations
        assert workbench.decide(approval, idempotency_key="recover-after-exit").status_code == 200
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
