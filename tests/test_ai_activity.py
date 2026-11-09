"""AI Activity Monitor (v8): observable lifecycle of every real LLM request.

Covers: trace persistence, honest (non-synthetic) stage recording, streaming
first-token milestones on the real LLMClient, failure/timeout statuses,
pruning bounds, and the admin API (auth + payloads).
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from netagent.agent.llm_client import (
    LLMClient, LLMStreamEmpty, LLMTruncated, LLMUnavailable,
)
from netagent.services.ai_activity import ActivityTrace, traced_chat
from netagent.services.ai_analysis import AlertAnalysisWorker, PROMPT_VERSION
from tests.test_ai_analysis import _seed_alert, FakeLLM
from tests.conftest import ADMIN_TOKEN


def admin_headers() -> dict:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _FakeLLM(payload_fn=None):
    class _F:
        model = "fake-model"

        def chat(self, messages):
            self.last_messages = messages
            if payload_fn:
                return payload_fn(self, messages)
            return json.dumps({
                "summary": "گزارش آزمایشی فعالیت.",
                "importance": "low", "evidence": [],
                "anomaly_likelihood": "low", "confidence": "medium",
                "recommendation": "-",
            })
    return _F()


def _seed_batch_of_lookalike_alerts(db, count=3, src_ip="12.0.0.1"):
    from netagent.services.ai_analysis import alert_fingerprint, analysis_priority
    for i in range(count):
        ev = {
            "ts": "2026-11-01T10:00:00+00:00", "ts_epoch": 1793594400.0 + i,
            "event_type": "alert", "flow_id": 5525010101 + i,
            "src_ip": src_ip, "src_port": 8443 + i,
            "dest_ip": "10.233.68.48", "dest_port": 52222 + i,
            "proto": "TCP", "app_proto": "tls",
        }
        event_id = db.insert_event(ev, "{}", f"fp-activity-{src_ip}-{i}")
        db.insert_alert(event_id, {
            "signature": "ET ET rule 8001", "signature_id": 8001,
            "rev": 4, "severity": 2, "action": "allowed",
            "category": "scanning",
        })
    alerts, _t = db.query_alerts(limit=20)
    ids = [a["id"] for a in alerts][:count]
    for aid in ids:
        db.enqueue_alert_analysis(
            alert_id=aid,
            fingerprint=alert_fingerprint(db.get_alert(aid)),
            priority=analysis_priority(db.get_alert(aid)),
        )
    return ids


# -- trace lifecycle ----------------------------------------------------------


def test_trace_records_only_real_stages(db):
    trace = ActivityTrace(db, task_type="alert_analysis", model="m",
                          refs=[{"alert_id": 7}])
    assert trace.request_id.startswith("act_")
    row = db.get_ai_activity(trace.request_id)
    assert row["status"] == "RUNNING"
    stages = [e["stage"] for e in row["timeline"]]
    assert stages == ["REQUEST_CREATED"]  # nothing pre-filled
    assert row["sent_at"] is None and row["final_at"] is None

    trace.mark("SENT_TO_LLM")
    row = db.get_ai_activity(trace.request_id)
    assert row["sent_at"] is not None
    trace.mark("RESPONSE_RECEIVED")
    trace.complete(outcome_summary="تحلیل کامل شد.")
    row = db.get_ai_activity(trace.request_id)
    assert row["status"] == "COMPLETED"
    assert row["outcome_summary"] == "تحلیل کامل شد."
    assert row["duration_ms"] is not None and row["duration_ms"] >= 0
    stage_names = [e["stage"] for e in row["timeline"]]
    assert stage_names == [
        "REQUEST_CREATED", "SENT_TO_LLM",
        "RESPONSE_RECEIVED",  # recorded by the trace itself in lifecycle tests
        "PERSISTED",
    ]
    # no fabricated stage ever appears
    assert "FIRST_TOKEN_RECEIVED" not in stage_names


def test_trace_unknown_stage_rejected(db):
    trace = ActivityTrace(db, task_type="alert_analysis", model="m")
    with pytest.raises(ValueError):
        db.stage_ai_activity(trace.request_id, "MADE_UP_STAGE")


def test_trace_failure_and_timeout_status(db):
    trace = ActivityTrace(db, task_type="alert_analysis", model="m")
    trace.sent()
    trace.mark("FIRST_TOKEN_RECEIVED", first_token_ms=100.5, streaming=True)
    trace.fail("boom")
    row = db.get_ai_activity(trace.request_id)
    assert row["status"] == "FAILED"
    assert row["error"] == "boom"
    assert [e["stage"] for e in row["timeline"]].count("RESPONSE_RECEIVED") == 0
    assert row["first_token_ms"] == 100.5 and row["streaming"] == 1

    trace2 = ActivityTrace(db, task_type="alert_analysis", model="m")
    trace2.sent()
    trace2.fail("APITimeoutError: x", timeout=True)
    assert db.get_ai_activity(trace2.request_id)["status"] == "TIMEOUT"


def test_trace_prune_keeps_bounded(db):
    for _ in range(12):
        t = ActivityTrace(db, task_type="x", model=None)
        t.complete()
    db.prune_ai_activity(keep=5)
    assert len(db.list_ai_activity(limit=500)[0]) == 5


# -- traced chat / streaming ---------------------------------------------------


class StreamFakeClient:
    """Stands in for the OpenAI client to exercise LLMClient.chat_stream."""

    def __init__(self, chunks, fail_stream=False):
        self._chunks = chunks
        self.chat = self  # duck-typed namespace: client.chat.completions...

    class _Completions:
        def __init__(self, outer):
            self._outer = outer
        def create(self, **kwargs):
            assert kwargs.get("stream") is True
            return self._outer._chunks

    @property
    def completions(self):
        return self._Completions(self)

    def __iter__(self):
        return iter(self._chunks)


def _chunk(content=None, finish=None):
    class C:
        def __init__(self, content, finish):
            class _D:
                def __init__(self, c):
                    self.content = c
            delta = _D(content)
            finish_reason = finish
            self.choices = [type("S", (), {"delta": delta, "finish_reason": finish_reason})()]
    return C(content, finish)


def test_chat_stream_collections_of_deltas_with_first_token():
    chunks = iter([_chunk(None), _chunk("سلام "), _chunk("دنیا"), _chunk(None, "stop")])
    client = LLMClient.__new__(LLMClient)  # skip __init__ wiring
    from netagent.config import Settings
    s = Settings()
    s.llm_max_output_tokens = 128
    client._settings = s
    client._client = StreamFakeClient(chunks)
    calls = []
    text = client.chat_stream(
        [{"role": "user", "content": "x"}], first_token_cb=lambda: calls.append(1)
    )
    assert text == "سلام دنیا"
    assert client.last_finish_reason == "stop"
    assert calls == [1]
    # an unterminated stream (disconnect) is an error, not a complete answer
    client_broken = LLMClient.__new__(LLMClient)
    client_broken._settings = s
    client_broken._client = StreamFakeClient(iter([_chunk(None), _chunk("نصف")]))
    with pytest.raises(LLMUnavailable):
        client_broken.chat_stream([{"role": "user", "content": "x"}])
    # reasoning-only model → empty stream signals fallback, not success
    client2 = LLMClient.__new__(LLMClient)
    client2._settings = s
    client2._client = StreamFakeClient(iter([_chunk(None), _chunk(None, "stop")]))
    with pytest.raises(LLMStreamEmpty):
        client2.chat_stream([{"role": "user", "content": "x"}])


def test_traced_chat_falls_back_on_empty_stream(db):
    traced = []
    trace = ActivityTrace(db, task_type="t", model="fake")

    class StreamThenPlain:
        model = "fake"
        def chat(self, messages, max_tokens=None):
            traced.append("plain")
            return "fallback"
        def chat_stream(self, messages, max_tokens=None, first_token_cb=None):
            raise LLMStreamEmpty("empty")

    text = traced_chat(StreamThenPlain(), [{"role": "user", "content": "q"}], trace=trace)
    assert text == "fallback"
    row = db.get_ai_activity(trace.request_id)
    stages = [e["stage"] for e in row["timeline"]]
    assert stages == [
        "REQUEST_CREATED", "SENT_TO_LLM", "RESPONSE_RECEIVED",
    ]


def test_traced_chat_plain_client_without_stream(db):
    trace = ActivityTrace(db, task_type="t", model="fake")
    llm = FakeLLM()  # plain chat() contract, no stream support
    out = traced_chat(llm, [{"role": "user", "content": "q"}], trace=trace)
    assert out.startswith("{")
    row = db.get_ai_activity(trace.request_id)
    assert row["status"] == "RUNNING"  # caller still closes it


def test_traced_chat_records_truncated_stream_finish_in_trace(db):
    """A truncated answer (finish_reason=length) can never be used, but its
    *real* termination signal must still appear in the activity trace."""
    trace = ActivityTrace(db, task_type="t", model="fake")
    client = LLMClient.__new__(LLMClient)  # skip __init__ wiring
    from netagent.config import Settings
    s = Settings()
    s.llm_max_output_tokens = 8
    client._settings = s
    client.model = "fake"
    client.last_finish_reason = None
    client.last_usage = None
    client._client = StreamFakeClient(iter([
        _chunk(None), _chunk("نصف "), _chunk("پاسخ"), _chunk(None, "length"),
    ]))
    with pytest.raises(LLMTruncated):
        traced_chat(client, [{"role": "user", "content": "q"}], trace=trace)
    row = db.get_ai_activity(trace.request_id)
    stages = [e["stage"] for e in row["timeline"]]
    assert stages == [
        "REQUEST_CREATED", "SENT_TO_LLM", "FIRST_TOKEN_RECEIVED",
        "STREAM_FINISHED",
    ]
    finish = row["timeline"][-1]
    assert finish["finish_reason"] == "length"  # never synthesized


# -- worker integration --------------------------------------------------------


def test_worker_records_activity_per_request(db, settings):
    _seed_alert(db)
    worker = AlertAnalysisWorker(db, settings, FakeLLM())
    worker.enqueue_missing()
    worker.process_one()
    items, _total = db.list_ai_activity(task_type="alert_analysis")
    assert len(items) == 1
    row = items[0]
    assert row["status"] == "COMPLETED"
    assert row["model"] == "fake-model"
    assert row["prompt_version"] == PROMPT_VERSION
    assert row["outcome_summary"].startswith("low:")
    stages = [e["stage"] for e in row["timeline"]]
    assert "SENT_TO_LLM" in stages and "PERSISTED" in stages
    assert "REQUEST_CREATED" in stages


def test_worker_records_batch_activity(db, settings):
    settings.ai_analysis_batch_size = 5
    ids = _seed_batch_of_lookalike_alerts(db, count=3)
    worker = AlertAnalysisWorker(
        db, settings,
        _FakeLLM(lambda self, messages: json.dumps({
            "results": [
                {"alert_id": aid, "summary": f"گزارش {aid}", "importance": "low",
                 "evidence": [], "anomaly_likelihood": "low",
                 "confidence": "medium", "recommendation": "-"}
                for aid in ids
            ]
        })),
    )
    worker.process_one()
    items, _t = db.list_ai_activity(task_type="alert_analysis_batch")
    assert len(items) == 1
    row = items[0]
    assert row["status"] == "COMPLETED"
    assert [r["alert_id"] for r in row["refs"]] == sorted(ids)


def test_worker_offline_llm_records_failure_not_success(db, settings):
    _seed_alert(db)

    class Offline:
        model = "fake"
        def chat(self, messages):
            raise LLMUnavailable("LLM request failed: APITimeoutError")

    worker = AlertAnalysisWorker(db, settings, Offline())
    worker.enqueue_missing()
    worker.process_one()
    items, _t = db.list_ai_activity()
    row = items[0]
    assert row["status"] == "TIMEOUT"
    assert "APITimeoutError" in row["error"]
    assert "RESPONSE_RECEIVED" not in [e["stage"] for e in row["timeline"]]


# -- admin API ------------------------------------------------------------------


@pytest.fixture()
def activity_client(db, settings, monkeypatch):
    settings.admin_api_token = ADMIN_TOKEN
    settings.ai_analysis_enabled = True
    from fastapi.testclient import TestClient

    from netagent.main import create_app

    app = create_app(settings, start_monitor=False)
    app.state.db = db
    with TestClient(app) as c:
        yield c


def test_ai_activity_api_requires_admin(activity_client, db):
    t = ActivityTrace(db, task_type="x", model=None)
    t.complete()
    r = activity_client.get("/api/admin/v1/ai-activity")
    assert r.status_code == 401
    r = activity_client.get("/api/admin/v1/ai-activity", headers=admin_headers())
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_ai_activity_summary_api(activity_client, db, settings):
    t = ActivityTrace(db, task_type="alert_analysis", model="m")
    t.sent()
    t.complete(outcome_summary="s")
    r = activity_client.get("/api/admin/v1/ai-activity/summary", headers=admin_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["counts"].get("COMPLETED") == 1
    assert "alert_analysis_pending_and_running" in body["queue"]
    assert body["llm_enabled"] == settings.llm_enabled


def test_ai_activity_detail_api(activity_client, db):
    t = ActivityTrace(db, task_type="alert_analysis", model="m")
    t.sent()
    t.complete()
    r = activity_client.get(
        f"/api/admin/v1/ai-activity/{t.request_id}", headers=admin_headers()
    )
    assert r.status_code == 200
    assert r.json()["request_id"] == t.request_id
    r = activity_client.get("/api/admin/v1/ai-activity/act_missing", headers=admin_headers())
    assert r.status_code == 404
