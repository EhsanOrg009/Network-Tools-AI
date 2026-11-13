"""Persistent admission, per-row idempotency, recovery and administrator controls."""

import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from netagent.agent.llm_client import LLMBusy, LLMUnavailable, LLMTruncated
from netagent.collectors.suricata import parse_eve_line, store_event
from netagent.database import AnalysisQueueFull, Database
from netagent.services.ai_analysis import AlertAnalysisWorker
from netagent.services.monitoring import Monitor
from tests.conftest import ALERT_LINE, ADMIN_TOKEN
from tests.test_ai_analysis import FakeLLM, ai_client, admin_headers


def ingest(db, n=1, severity=4):
    payload = json.loads(ALERT_LINE)
    payload["flow_id"] = n
    payload["alert"]["severity"] = severity
    raw = json.dumps(payload)
    event, error = parse_eve_line(raw)
    assert error is None
    store_event(db, event, raw)
    return db.query_alerts(limit=1000)[0][0]["id"]


def request(db, aid, **kwargs):
    return db.request_alert_analysis(aid, actor="admin", capacity=200, **kwargs)


def test_fresh_default_and_reopen_stay_off(db, settings):
    assert not db.security_ai_auto_enabled()
    aid = ingest(db)
    assert db.get_alert_analysis(aid) is None
    other = Database(settings.database_path)
    try:
        assert not other.security_ai_auto_enabled()
        assert other.get_alert(aid)
        assert other.get_alert_analysis(aid) is None
    finally:
        other.close()


def test_enable_only_future_events_disable_pauses_queue(db, settings):
    old = ingest(db, 1)
    db.set_security_ai_auto(True, actor="admin")
    fresh = ingest(db, 2)
    db.set_security_ai_auto(False, actor="admin")
    later = ingest(db, 3)
    assert db.get_alert_analysis(old) is None
    assert db.get_alert_analysis(later) is None
    assert db.get_alert_analysis(fresh)["status"] == "PENDING"
    llm = FakeLLM()
    worker = AlertAnalysisWorker(db, settings, llm)
    assert not worker.process_one()
    assert db.get_alert_analysis(fresh)["status"] == "PENDING"
    db.set_security_ai_auto(True, actor="admin")
    assert worker.process_one()
    assert db.get_alert_analysis(fresh)["status"] == "COMPLETED"
    assert db.get_alert_analysis(old) is None


def test_enabled_setting_survives_restart_without_enqueuing_history(db, settings):
    old = ingest(db)
    db.set_security_ai_auto(True, actor="admin")
    other = Database(settings.database_path)
    try:
        assert other.security_ai_auto_enabled()
        new = ingest(other, 2)
        assert other.get_alert_analysis(new)
        assert other.get_alert_analysis(old) is None
    finally:
        other.close()


def test_intake_overflow_is_durable_and_every_severity_drains(db, settings):
    settings.ai_analysis_backlog_limit = 2
    db.set_security_ai_auto(True, actor="admin")
    ids = [ingest(db, n, severity=n % 4 + 1) for n in range(1, 13)]
    assert db.analysis_summary()["counts"]["PENDING"] == 12
    assert db.promote_analysis_intake(2) == 2
    assert db._conn.execute("SELECT COUNT(*) FROM alert_analyses").fetchone()[0] == 2
    db.set_security_ai_auto(False, actor="admin")
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    assert not worker.process_one()
    assert db.analysis_summary()["paused_automatic"] == 12
    db.set_security_ai_auto(True, actor="admin")
    for _ in range(12):
        assert worker.process_one()
    assert not worker.process_one()
    assert all(db.get_alert_analysis(aid)["status"] == "COMPLETED" for aid in ids)


def test_manual_is_single_even_when_batch_enabled(db, settings):
    ids = [ingest(db, n) for n in range(1, 4)]
    settings.ai_analysis_batch_size = 3
    first = request(db, ids[0])
    assert request(db, ids[0])["job_id"] == first["job_id"]
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    assert worker.process_one()
    assert db.get_alert_analysis(ids[0])["status"] == "COMPLETED"
    assert all(db.get_alert_analysis(aid) is None for aid in ids[1:])
    assert request(db, ids[0])["job_id"] == first["job_id"]
    assert not worker.process_one()


def test_truncated_batch_recovers_individually_after_restart(db, settings):
    db.set_security_ai_auto(True, actor="admin")
    ids = [ingest(db, n) for n in (1, 2)]
    settings.ai_analysis_batch_size = 3
    class Truncated(FakeLLM):
        def chat(self, *args, **kwargs):
            raise LLMTruncated("context exhausted")
    worker = AlertAnalysisWorker(db, settings, Truncated())
    assert worker.process_one()
    assert all(db.get_alert_analysis(aid)["provider_failures"] == 1 for aid in ids)
    with db.transaction():
        db._conn.execute("UPDATE alert_analyses SET next_retry_epoch=0")
    reopened = Database(db.path)
    try:
        resumed = AlertAnalysisWorker(reopened, settings, FakeLLM())
        assert resumed.process_one()
        statuses = [reopened.get_alert_analysis(aid)["status"] for aid in ids]
        assert sorted(statuses) == ["COMPLETED", "PENDING"]
        assert resumed.process_one()
        assert all(reopened.get_alert_analysis(aid)["status"] == "COMPLETED" for aid in ids)
    finally:
        reopened.close()


def test_concurrent_clicks_create_one_job_and_one_audit(db):
    aid = ingest(db)
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: request(db, aid), range(24)))
    assert len({r["job_id"] for r in rows}) == 1
    count = db._conn.execute("SELECT COUNT(*) FROM admin_audit WHERE action='ai_analysis.analyze'").fetchone()[0]
    assert count == 1


def test_explicit_reanalysis_archives_result_and_does_not_reset_processing(db, settings):
    aid = ingest(db)
    old = request(db, aid)
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    worker.process_one()
    new = request(db, aid, reanalyze=True)
    assert old["job_id"] != new["job_id"]
    assert db.alert_analysis_history(aid)[0]["status"] == "COMPLETED"
    assert request(db, aid, reanalyze=True)["job_id"] == new["job_id"]
    claimed = db.claim_next_alert_analysis()
    assert request(db, aid, reanalyze=True)["status"] == "PROCESSING"
    assert db.get_alert_analysis(aid)["job_id"] == claimed["job_id"]


def test_reanalysis_exposes_no_previous_output_in_current_job(db, settings):
    aid = ingest(db)
    request(db, aid)
    assert AlertAnalysisWorker(db, settings, FakeLLM()).process_one()
    previous = db.get_alert_analysis(aid)
    assert previous["summary"] and previous["analyzed_at"]
    pending = request(db, aid, reanalyze=True)
    assert pending["status"] == "PENDING"
    for key in ("summary", "importance", "evidence", "anomaly_likelihood", "confidence",
                "recommendation", "model", "prompt_version", "duration_ms", "analyzed_at"):
        assert pending.get(key) is None, key
    assert pending["memories_used"] == []
    assert db.analysis_summary()["last_processed_at"] is None
    history = db.alert_analysis_history(aid)
    assert history == [previous]


def test_queue_capacity_rejects_new_manual_but_returns_existing(db):
    a, b = ingest(db, 1), ingest(db, 2)
    existing = db.request_alert_analysis(a, actor="admin", capacity=1)
    assert db.request_alert_analysis(a, actor="admin", capacity=1)["job_id"] == existing["job_id"]
    with pytest.raises(AnalysisQueueFull):
        db.request_alert_analysis(b, actor="admin", capacity=1)
    assert db.get_alert_analysis(b) is None


def test_worker_restart_recovers_only_processing_and_waits(db, settings):
    a, b = ingest(db, 1), ingest(db, 2)
    request(db, a)
    request(db, b)
    claimed = db.claim_next_alert_analysis()
    db.recover_processing_analyses(delay_seconds=60)
    recovered = db.get_alert_analysis(claimed["alert_id"])
    assert recovered["status"] == "PENDING"
    assert recovered["job_id"] == claimed["job_id"]
    assert recovered["next_retry_epoch"] > time.time()
    assert db.claim_next_alert_analysis()["alert_id"] != claimed["alert_id"]


def test_offline_retries_are_delayed_bounded_and_resume_after_probe(db, settings):
    aid = ingest(db)
    request(db, aid)
    class Offline(FakeLLM):
        def chat(self, messages):
            raise LLMUnavailable("offline")
    worker = AlertAnalysisWorker(db, settings, Offline())
    for _ in range(settings.ai_analysis_max_attempts):
        assert worker.process_one()
        assert not worker.process_one()  # backoff: no second generation
        with db.transaction():
            db._conn.execute("UPDATE alert_analyses SET next_retry_epoch=0")
    failed = db.get_alert_analysis(aid)
    assert failed["status"] == "FAILED" and failed["error"].startswith("LLMUnavailable:")
    assert not worker.process_one()
    db.retry_provider_analyses(max_attempts=settings.ai_analysis_max_attempts)
    worker.llm = FakeLLM()
    assert worker.process_one()
    assert db.get_alert_analysis(aid)["status"] == "COMPLETED"


def test_busy_does_not_exhaust_attempts(db, settings):
    aid = ingest(db)
    request(db, aid)
    class Busy(FakeLLM):
        def chat(self, messages):
            raise LLMBusy("other generation")
    worker = AlertAnalysisWorker(db, settings, Busy())
    worker.process_one()
    row = db.get_alert_analysis(aid)
    assert row["status"] == "PENDING" and row["provider_failures"] == 0 and row["attempts"] == 0


def test_fairness_applies_before_candidate_limit(db):
    low = ingest(db, 1, severity=4)
    request(db, low)
    for n in range(2, 65):
        request(db, ingest(db, n, severity=1))
    with db.transaction():
        db._conn.execute("UPDATE alert_analyses SET created_at='2000-01-01T00:00:00+00:00' WHERE alert_id=?", (low,))
    assert db.claim_next_alert_analysis()["alert_id"] == low


def test_intake_and_event_roll_back_together_on_persistence_failure(db, monkeypatch):
    db.set_security_ai_auto(True, actor="admin")
    original = db.security_ai_auto_enabled
    def broken():
        raise RuntimeError("intake storage error")
    monkeypatch.setattr(db, "security_ai_auto_enabled", broken)
    with pytest.raises(RuntimeError):
        ingest(db)
    monkeypatch.setattr(db, "security_ai_auto_enabled", original)
    assert db.query_alerts()[1] == 0
    assert db.query_events()[1] == 0
    assert db.analysis_summary()["counts"]["PENDING"] == 0
    assert ingest(db)


def test_monitor_ingestion_obeys_auto_setting(db, settings):
    settings.suricata_eve_path.write_text("")
    monitor = Monitor(db, settings)
    try:
        monitor.poll_once()
        db.set_security_ai_auto(True, actor="admin")
        settings.suricata_eve_path.write_text(ALERT_LINE + "\n")
        assert monitor.poll_once()["ingested"] == 1
        assert db.analysis_summary()["counts"]["PENDING"] == 1
        assert monitor.poll_once()["ingested"] == 0
        assert db.analysis_summary()["counts"]["PENDING"] == 1
    finally:
        monitor.stop()


@pytest.mark.parametrize("method,path,body", [
    ("get", "/security-ai", None),
    ("put", "/security-ai/automatic", {"enabled": True}),
    ("post", "/ai-analyses/1/analyze", {}),
    ("get", "/ai-analyses/1/history", None),
])
def test_control_apis_require_admin(ai_client, method, path, body):
    kwargs = {"json": body} if body is not None else {}
    for headers in ({}, {"Authorization": "Bearer invalid"}):
        response = getattr(ai_client, method)("/api/admin/v1" + path, headers=headers, **kwargs)
        assert response.status_code == 401


def test_api_toggle_manual_retry_status_and_audit(ai_client, db):
    h = admin_headers()
    aid = ingest(db)
    ai_client.app.state.llm = None
    status = ai_client.get("/api/admin/v1/security-ai", headers=h).json()
    assert status["auto_enabled"] is False
    assert status["connection"]["ok"] is False
    assert ai_client.put("/api/admin/v1/security-ai/automatic", json={"enabled": True}, headers=h).status_code == 200
    automatic = ingest(db, 2)
    first = ai_client.post(f"/api/admin/v1/ai-analyses/{aid}/analyze", headers=h)
    assert first.status_code == 200
    again = ai_client.post(f"/api/admin/v1/ai-analyses/{aid}/analyze", headers=h)
    assert first.json()["job_id"] == again.json()["job_id"]
    items = ai_client.get(f"/api/admin/v1/ai-analyses?alert_ids={aid},{automatic}", headers=h).json()["items"]
    assert len(items) == 2
    assert len({r["job_id"] for r in items}) == 2
    assert ai_client.post("/api/admin/v1/ai-analyses/999/analyze", headers=h).status_code == 404
    actions = {r[0] for r in db._conn.execute("SELECT action FROM admin_audit")}
    assert {"ai_analysis.auto_mode", "ai_analysis.analyze"} <= actions


def test_toggle_requires_boolean_and_is_atomic_with_audit(ai_client, db, monkeypatch):
    h = admin_headers()
    assert ai_client.put("/api/admin/v1/security-ai/automatic", json={"enabled": "false"}, headers=h).status_code == 422
    def broken(**kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(db, "record_audit", broken)
    with pytest.raises(RuntimeError):
        db.set_security_ai_auto(True, actor="admin")
    assert not db.security_ai_auto_enabled()


def test_migration_preserves_existing_success_and_ids(tmp_path, monkeypatch):
    from netagent.migrations import MIGRATIONS
    path = tmp_path / "old.sqlite3"
    migration = MIGRATIONS["003_security_ai_control"]
    with monkeypatch.context() as context:
        context.delitem(MIGRATIONS, "003_security_ai_control")
        old = Database(path)
        aid = ingest(old)
        old._conn.execute(
            "INSERT INTO alert_analyses(alert_id,fingerprint,status,created_at,summary) VALUES(?,?,'COMPLETED',?,?)",
            (aid, "legacy-fingerprint", "2026-01-01T00:00:00Z", "نتیجهٔ محفوظ"),
        )
        old._conn.commit()
        old.close()
    assert MIGRATIONS["003_security_ai_control"] == migration
    for _ in range(2):
        upgraded = Database(path)
        try:
            assert not upgraded.security_ai_auto_enabled()
            row = upgraded.get_alert_analysis(aid)
            assert row["alert_id"] == aid and row["status"] == "COMPLETED"
            assert row["summary"] == "نتیجهٔ محفوظ" and row["job_id"]
            assert upgraded.get_alert(aid)
        finally:
            upgraded.close()


def test_real_worker_loop_does_not_backfill_history(db, settings, monkeypatch):
    aid = ingest(db)
    reached = threading.Event()
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    original = worker.process_one
    def cycle():
        result = original()
        reached.set()
        return result
    monkeypatch.setattr(worker, "process_one", cycle)
    worker.start()
    try:
        assert reached.wait(2)
        assert db.get_alert_analysis(aid) is None
    finally:
        assert worker.stop()


def test_existing_auto_intake_click_returns_same_job_without_duplication(db):
    db.set_security_ai_auto(True, actor="admin")
    aid = ingest(db)
    job = db.get_alert_analysis(aid)["job_id"]
    assert request(db, aid)["job_id"] == job
    assert db.pending_alert_analysis_count() == 1
    db.promote_analysis_intake(200)
    assert request(db, aid)["job_id"] == job
    assert db.pending_alert_analysis_count() == 1


def test_manual_jobs_do_not_join_other_queued_alerts_in_batch(db, settings):
    ids = [ingest(db, n) for n in range(1, 4)]
    for aid in ids:
        request(db, aid)
    settings.ai_analysis_batch_size = 3
    assert AlertAnalysisWorker(db, settings, FakeLLM()).process_one()
    assert db.analysis_summary()["counts"]["COMPLETED"] == 1
    assert db.analysis_summary()["counts"]["PENDING"] == 2


def test_failed_request_and_audit_roll_back_as_one_unit(db, monkeypatch):
    aid = ingest(db)
    def broken(**kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(db, "record_audit", broken)
    with pytest.raises(RuntimeError):
        request(db, aid)
    assert db.get_alert_analysis(aid) is None


def test_pending_intake_survives_restart_and_keeps_job_id(db, settings):
    db.set_security_ai_auto(True, actor="admin")
    aid = ingest(db)
    job = db.get_alert_analysis(aid)["job_id"]
    other = Database(settings.database_path)
    try:
        assert other.get_alert_analysis(aid)["job_id"] == job
        assert AlertAnalysisWorker(other, settings, FakeLLM()).process_one()
        assert other.get_alert_analysis(aid)["job_id"] == job
        assert other.get_alert_analysis(aid)["status"] == "COMPLETED"
    finally:
        other.close()


def test_partial_json_with_complete_fields_is_not_successfully_repaired(db, settings):
    aid = ingest(db)
    request(db, aid)
    class Partial(FakeLLM):
        def chat(self, messages):
            return super().chat(messages)[:-1]
    assert AlertAnalysisWorker(db, settings, Partial()).process_one()
    row = db.get_alert_analysis(aid)
    assert row["status"] == "FAILED" and "invalid_json" in row["error"]


def test_outage_recovery_respects_active_capacity(db):
    ids = [ingest(db, n) for n in range(1, 4)]
    for aid in ids:
        request(db, aid)
        for _ in range(3):
            db.defer_alert_analysis(aid, error="LLMUnavailable: offline", delay_seconds=0)
    db.retry_provider_analyses(max_attempts=3, capacity=1)
    assert db.analysis_summary()["counts"]["PENDING"] == 1
    assert db.analysis_summary()["counts"]["FAILED"] == 2
