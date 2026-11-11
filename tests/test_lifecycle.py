import pytest
from fastapi.testclient import TestClient

from netagent.services.monitoring import Monitor


def test_monitor_timeout_does_not_close_resources_still_in_use(db, settings, monkeypatch):
    monitor = Monitor(db, settings)
    class StillIngesting:
        def join(self, timeout):
            pass
        def is_alive(self):
            return True
    thread = StillIngesting()
    monitor._thread = thread
    closed = []
    monkeypatch.setattr(monitor.tailer, "close", lambda: closed.append(True))
    assert monitor.stop() is False
    assert monitor._thread is thread
    assert not closed
    monitor._thread = None
    assert monitor.stop() is True
    assert closed == [True]


def test_partial_startup_failure_closes_database_and_shared_llm(settings, monkeypatch):
    from netagent import main
    closed = []
    class Client:
        def __init__(self, settings):
            pass
        def close(self):
            closed.append(True)
    settings.llm_enabled = True
    settings.ai_analysis_enabled = False
    monkeypatch.setattr(main, "LLMClient", Client)
    app = main.create_app(settings, start_monitor=True)
    def fail():
        raise RuntimeError("monitor startup failed")
    monkeypatch.setattr(app.state.monitor, "start", fail)
    with pytest.raises(RuntimeError, match="monitor startup failed"):
        with TestClient(app):
            pass
    assert closed == [True]
    assert not any(t.is_alive() for t in app.state.jobs._threads)


def test_finished_job_cancellation_preserves_result(db, settings):
    from netagent.services.jobs import JobManager
    jobs = JobManager(db, settings)
    job_id = jobs.submit("diagnostic", lambda: {"evidence": "preserved"})
    jobs._queue.join()
    try:
        assert jobs.get(job_id)["status"] == "completed"
        assert jobs.cancel(job_id)["status"] == "completed"
        assert jobs.get(job_id)["result"] == {"evidence": "preserved"}
    finally:
        assert jobs.shutdown()
