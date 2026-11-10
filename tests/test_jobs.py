import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from netagent.database import Database
from netagent.services.job_control import checkpoint
from netagent.services.jobs import JobManager, JobQueueFull
from tests.conftest import admin_headers


def eventually(check, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.01)
    assert check()


def test_fixed_workers_backpressure_and_concurrent_submit(db, settings):
    settings.job_workers, settings.job_queue_size = 2, 3
    manager = JobManager(db, settings)
    gate = threading.Event()
    first = [manager.submit("test", lambda: gate.wait(3)) for _ in range(2)]
    eventually(lambda: all(manager.get(i)["status"] == "running" for i in first))
    def submit(_):
        try:
            return manager.submit("test", lambda: None)
        except JobQueueFull:
            return None
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            accepted = [i for i in executor.map(submit, range(30)) if i]
        assert len(accepted) == 3
        assert len(manager._threads) == 3  # two workers, one deadline monitor
    finally:
        gate.set()
        manager.shutdown()


def test_cancelled_queued_job_never_executes(db, settings):
    settings.job_workers = 1
    manager = JobManager(db, settings)
    gate, executed = threading.Event(), threading.Event()
    first = manager.submit("test", lambda: gate.wait(3))
    eventually(lambda: manager.get(first)["status"] == "running")
    second = manager.submit("test", executed.set)
    assert manager.cancel(second)["status"] == "cancelled"
    gate.set()
    eventually(lambda: not manager._contexts)
    assert not executed.is_set()
    manager.shutdown()


def test_running_cancellation_and_timeout_do_not_become_success(db, settings):
    settings.job_timeout_seconds = 0.15
    manager = JobManager(db, settings)
    def cooperative():
        while True:
            checkpoint()
            time.sleep(0.01)
    timed = manager.submit("test", cooperative)
    eventually(lambda: manager.get(timed)["status"] == "failed")
    assert "JobTimedOut" in manager.get(timed)["error"]
    cancelled = manager.submit("test", cooperative)
    eventually(lambda: manager.get(cancelled)["status"] == "running")
    manager.cancel(cancelled)
    eventually(lambda: not manager._contexts)
    assert manager.get(cancelled)["status"] == "cancelled"
    manager.shutdown()


def test_noncooperative_timeout_does_not_spawn_replacement_workers(db, settings):
    settings.job_workers, settings.job_queue_size, settings.job_timeout_seconds = 1, 1, 0.1
    manager = JobManager(db, settings)
    gate = threading.Event()
    job_id = manager.submit("test", lambda: gate.wait(3))
    eventually(lambda: manager.get(job_id)["status"] == "failed")
    manager.submit("test", lambda: None)
    with pytest.raises(JobQueueFull):
        manager.submit("test", lambda: None)
    assert len(manager._threads) == 2
    gate.set()
    eventually(lambda: not manager._contexts)
    assert manager.get(job_id)["status"] == "failed"
    manager.shutdown()


def test_restart_preserves_results_and_marks_unfinished_interrupted(db, settings):
    for job_id in ("pending", "running", "completed"):
        db.create_background_job(job_id, "investigation", 60)
    db.update_background_job("running", "running")
    db.update_background_job("completed", "completed", result={"result": "preserved"})
    reconnected = Database(db.path)
    manager = JobManager(reconnected, settings)
    manager.start()
    assert manager.get("pending")["status"] == "interrupted"
    assert manager.get("running")["status"] == "interrupted"
    assert manager.get("completed")["result"] == {"result": "preserved"}
    assert manager._queue.empty()
    manager.shutdown()
    reconnected.close()


def test_shutdown_is_bounded_and_persistent(db, settings):
    settings.job_shutdown_seconds = 0.01
    manager = JobManager(db, settings)
    gate = threading.Event()
    job_id = manager.submit("test", lambda: gate.wait(3))
    eventually(lambda: manager.get(job_id)["status"] == "running")
    started = time.monotonic()
    assert manager.shutdown() is False
    assert time.monotonic() - started < 0.5
    assert manager.get(job_id)["status"] == "interrupted"
    with pytest.raises(JobQueueFull):
        manager.submit("test", lambda: None)
    gate.set()
    for thread in manager._threads:
        thread.join(2)


def test_job_api_reports_backpressure_and_audits_cancellation(full_client, db, monkeypatch):
    def full(*a):
        raise JobQueueFull("queue full")
    monkeypatch.setattr(full_client.app.state.jobs, "submit", full)
    response = full_client.post("/api/jobs/investigation", headers=admin_headers(), json={"target_ip": "192.168.1.10"})
    assert response.status_code == 429 and response.headers["retry-after"] == "5"
    db.create_background_job("test", "investigation", 60)
    assert full_client.post("/api/jobs/test/cancel").status_code == 401
    assert full_client.post("/api/jobs/test/cancel", headers=admin_headers()).json()["status"] == "cancelled"
    assert any(row["action"] == "job.cancel" for row in full_client.get("/api/admin/v1/audit", headers=admin_headers()).json()["items"])


def test_restart_does_not_archive_current_knowledge(db):
    with db.transaction():
        db._conn.execute("INSERT INTO ai_memories(memory_id,title,category,source,status,scope,created_at,created_epoch) VALUES('keep','keep','network','admin','APPROVED','global','2026-11-10',1)")
    another = Database(db.path)
    assert another.get_memory("keep")["title"] == "keep"
    another.close()
