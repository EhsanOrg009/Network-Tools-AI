"""Every automatic admission/claim path fails closed; manual jobs stay independent."""
import threading

import pytest

from netagent.services.ai_analysis import AlertAnalysisWorker, alert_fingerprint
from tests.test_ai_analysis import FakeLLM, ai_client, admin_headers
from tests.test_security_ai_controls import ingest, request


def test_missing_and_invalid_policy_cannot_enable_processing(db, settings):
    for value in (None, "", "1", "True", "invalid"):
        with db.transaction():
            db._conn.execute("DELETE FROM meta WHERE key='security_ai_auto_enabled'")
            if value is not None:
                db.set_meta("security_ai_auto_enabled", value)
        aid = ingest(db, n=100 + len(str(value)))
        assert not db.security_ai_auto_enabled()
        worker = AlertAnalysisWorker(db, settings, FakeLLM())
        assert worker.enqueue_missing() == 0
        assert not db.enqueue_alert_analysis(alert_id=aid, fingerprint=alert_fingerprint(db.get_alert(aid)))
        assert not worker.process_one()
        assert db.get_alert_analysis(aid) is None


@pytest.mark.parametrize("promoted", [False, True])
def test_paused_auto_can_be_manually_released_only_for_selected_event(db, settings, promoted):
    db.set_security_ai_auto(True, actor="admin")
    a, b = ingest(db, 1), ingest(db, 2)
    original_id = db.get_alert_analysis(a)["job_id"]
    if promoted:
        db.promote_analysis_intake(200)
    db.set_security_ai_auto(False, actor="admin")
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    assert not worker.process_one()
    row = request(db, a)
    assert row["job_id"] == original_id and row["origin"] == "manual"
    assert worker.process_one()
    assert db.get_alert_analysis(a)["status"] == "COMPLETED"
    assert db.get_alert_analysis(b)["status"] == "PENDING"
    assert not worker.process_one()
    assert request(db, a)["job_id"] == original_id


def test_claim_and_intake_helpers_cannot_bypass_off_setting(db):
    db.set_security_ai_auto(True, actor="admin")
    a, b = ingest(db, 1), ingest(db, 2)
    db.promote_analysis_intake(1)
    db.set_security_ai_auto(False, actor="admin")
    assert db.promote_analysis_intake(200) == 0
    assert db.claim_next_alert_analysis() is None
    assert db.claim_next_alert_analysis_batch(max_batch=5) == []
    db.start_alert_analysis(a)
    assert db.get_alert_analysis(a)["status"] == "PENDING"
    assert db.get_alert_analysis(b)["status"] == "PENDING"


def test_running_job_completes_when_auto_is_disabled(db, settings):
    db.set_security_ai_auto(True, actor="admin")
    a, b = ingest(db, 1), ingest(db, 2)
    started, finish = threading.Event(), threading.Event()
    class Slow(FakeLLM):
        def chat(self, messages):
            started.set()
            assert finish.wait(3)
            return super().chat(messages)
    worker = AlertAnalysisWorker(db, settings, Slow())
    thread = threading.Thread(target=worker.process_one)
    thread.start()
    try:
        assert started.wait(3)
        db.set_security_ai_auto(False, actor="admin")
    finally:
        finish.set()
        thread.join(3)
    assert not thread.is_alive()
    rows = [db.get_alert_analysis(i) for i in (a, b)]
    assert sorted(r["status"] for r in rows) == ["COMPLETED", "PENDING"]
    assert not worker.process_one()


def test_bounded_configurable_backlog_only_admitted_on_enable_transition(db, settings):
    ids = [ingest(db, n) for n in range(1, 8)]
    db.set_security_ai_auto(True, actor="admin", backlog_policy="recent_unprocessed", backlog_limit=2)
    queued = [i for i in ids if db.get_alert_analysis(i)]
    assert queued == sorted(ids)[-2:]
    job_ids = [db.get_alert_analysis(i)["job_id"] for i in queued]
    db.set_security_ai_auto(True, actor="admin", backlog_policy="recent_unprocessed", backlog_limit=2)
    assert [db.get_alert_analysis(i)["job_id"] for i in queued] == job_ids
    assert db.pending_alert_analysis_count() == 2
    assert db.analysis_summary()["backlog_policy"] == "recent_unprocessed"


def test_intake_bound_retains_unadmitted_events_and_manual_budget(db, settings):
    db.analysis_intake_limit = 2
    db.set_security_ai_auto(True, actor="admin")
    ids = [ingest(db, n) for n in range(1, 7)]
    assert db.pending_alert_analysis_count() == 2
    assert db.query_alerts()[1] == 6
    db.set_security_ai_auto(False, actor="admin")
    manual = db.request_alert_analysis(ids[-1], actor="admin", capacity=1)
    assert manual["origin"] == "manual"
    assert AlertAnalysisWorker(db, settings, FakeLLM()).process_one()
    assert db.get_alert_analysis(ids[-1])["status"] == "COMPLETED"
    assert db.analysis_summary()["paused_automatic"] == 2


def test_security_read_endpoints_do_not_create_analysis(ai_client, db):
    ai_client.app.state.llm = None
    aid = ingest(db)
    for path in ("/dashboard/security", "/api/alerts", "/api/admin/v1/security-ai", f"/api/admin/v1/ai-analyses?alert_ids={aid}"):
        assert ai_client.get(path, headers=admin_headers()).status_code == 200
    assert db.get_alert_analysis(aid) is None
    assert not db.security_ai_auto_enabled()


def test_failed_manual_job_is_visible_and_retry_is_selected_and_audited(ai_client, db, settings):
    a, b = ingest(db, 1), ingest(db, 2)
    h = admin_headers()
    ai_client.post(f"/api/admin/v1/ai-analyses/{a}/analyze", headers=h)
    class Bad(FakeLLM):
        def chat(self, messages):
            return "invalid"
    worker = AlertAnalysisWorker(db, settings, Bad())
    for _ in range(settings.ai_analysis_max_attempts):
        worker.process_one()
    old = db.get_alert_analysis(a)
    assert old["status"] == "FAILED" and old["error"]
    retry = ai_client.post(f"/api/admin/v1/ai-analyses/{a}/analyze", headers=h).json()
    assert retry["job_id"] != old["job_id"]
    worker.llm = FakeLLM()
    assert worker.process_one()
    assert db.get_alert_analysis(a)["status"] == "COMPLETED"
    assert db.get_alert_analysis(b) is None
    assert db.alert_analysis_history(a)[0]["error"] == old["error"]
    assert db._conn.execute("SELECT COUNT(*) FROM admin_audit WHERE action='ai_analysis.retry'").fetchone()[0] == 1


def test_backlog_contract_and_validation(ai_client, db):
    ingest(db)
    endpoint = "/api/admin/v1/security-ai/automatic"
    h = admin_headers()
    for body in ({"enabled": True, "backlog_policy": "all"}, {"enabled": True, "backlog_limit": "50"}, {"enabled": True, "backlog_limit": 201}):
        assert ai_client.put(endpoint, json=body, headers=h).status_code == 422
    assert ai_client.put(endpoint, json={"enabled": True, "backlog_policy": "recent_unprocessed", "backlog_limit": 1}, headers=h).status_code == 200
    assert db.pending_alert_analysis_count() == 1


def test_history_pages_are_read_only_and_preserve_selected_event_results(ai_client, db, settings):
    a, b = ingest(db, 1), ingest(db, 2)
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    ids = []
    for _ in range(3):
        ids.append(request(db, a, reanalyze=True)["job_id"])
        assert worker.process_one()
    request(db, a, reanalyze=True)
    h = admin_headers()
    url = f"/api/admin/v1/ai-analyses/{a}/history"
    all_rows = ai_client.get(url, headers=h).json()
    assert all_rows["total"] == 3
    assert {r["job_id"] for r in all_rows["items"]} == set(ids)
    page = ai_client.get(url + "?limit=1&offset=1", headers=h).json()
    assert page["total"] == 3 and page["items"] == all_rows["items"][1:2]
    for query in ("limit=0", "limit=101", "offset=-1"):
        assert ai_client.get(url + "?" + query, headers=h).status_code == 422
    assert ai_client.get(url + "?limit=1&offset=4", headers=h).json()["items"] == []
    assert db.get_alert_analysis(b) is None
    assert not db.security_ai_auto_enabled()
    assert db.get_alert_analysis(a)["status"] == "PENDING"
    assert len(db.alert_analysis_history(a)) == 3


@pytest.mark.parametrize("saved_policy,saved_limit", [(None, None), ("recent_unprocessed", 7)])
def test_backlog_migration_preserves_admin_mode_results_and_optional_settings(tmp_path, monkeypatch, settings, saved_policy, saved_limit):
    from netagent.database import Database
    from netagent.migrations import MIGRATIONS
    path = tmp_path / "before-backlog-policy.sqlite3"
    with monkeypatch.context() as context:
        context.delitem(MIGRATIONS, "004_security_ai_backlog_policy")
        old = Database(path)
        first, second = ingest(old, 1), ingest(old, 2)
        row = request(old, first)
        assert AlertAnalysisWorker(old, settings, FakeLLM()).process_one()
        old.set_security_ai_auto(True, actor="admin")
        if saved_policy is not None:
            old.set_meta("security_ai_backlog_policy", saved_policy)
            old.set_meta("security_ai_backlog_limit", str(saved_limit))
        old.close()
    for _ in range(2):
        upgraded = Database(path)
        try:
            assert upgraded.get_meta("migration:004_security_ai_backlog_policy") == "applied"
            assert upgraded.security_ai_auto_enabled()
            summary = upgraded.analysis_summary()
            assert summary["backlog_policy"] == (saved_policy or "future_only")
            assert summary["backlog_limit"] == (saved_limit or 50)
            result = upgraded.get_alert_analysis(first)
            assert result["job_id"] == row["job_id"] and result["status"] == "COMPLETED"
            assert result["summary"]
            assert upgraded.get_alert_analysis(second) is None
            assert upgraded.query_alerts()[1] == 2
        finally:
            upgraded.close()
