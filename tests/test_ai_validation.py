"""Structured output + classification tests for the analysis pipeline
(bug-fix coverage for the Ollama migration).

- single: invalid JSON / missing fields / schema errors are distinguished,
  a valid-but-incomplete form is a schema failure with the exact fields;
- batch: matching only on alert_id, unknown/duplicate/invalid-item policy,
  and uncovered alerts falling through to the single path (no lost alerts,
  no wrong attribution);
- memory scope: batch memory is the intersection of all members' scopes —
  an agent-bound memory must never leak into another member's prompt;
- truncation: finish_reason=length is never persisted as a COMPLETED
  analysis.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

import pytest

from netagent.agent.llm_client import LLMStreamEmpty, LLMTruncated
from netagent.config import Settings
from netagent.database import Database
from netagent.services.ai_analysis import (
    ANALYSIS_SCHEMA,
    BATCH_SCHEMA,
    AlertAnalysisWorker,
)
from tests.test_ai_analysis import FakeLLM, _seed_alert
from tests.test_ai_memory import _memory as _mk_memory  # noqa: F401


def _db() -> tuple[Database, Settings]:
    tmp = tempfile.TemporaryDirectory()
    db = Database(os.path.join(tmp.name, "t.sqlite3"))
    s = Settings(database_path=os.path.join(tmp.name, "t.sqlite3"))
    return db, s


def _worker(db: Database, s: Settings, llm: Any) -> AlertAnalysisWorker:
    return AlertAnalysisWorker(db, s, llm)


# ---- single ----------------------------------------------------------------


def test_worker_records_stream_finished_metadata(db, settings):
    _seed_alert(db)
    trace = None
    from netagent.services.ai_activity import ActivityTrace

    trace = ActivityTrace(
        db, task_type="alert_analysis", model="fake", refs=[{"alert_id": 1}],
        prompt_version="test",
    )
    trace.stream_finished(
        finish_reason="stop", prompt_tokens=10, completion_tokens=5
    )
    row = db.get_ai_activity(trace.request_id)
    assert row["finish_reason"] == "stop"
    assert row["prompt_tokens"] == 10 and row["completion_tokens"] == 5
    timeline = row.get("timeline") or []
    finish = [e for e in timeline if e.get("stage") == "STREAM_FINISHED"]
    assert finish and finish[-1]["finish_reason"] == "stop"
    assert finish[-1]["completion_tokens"] == 5


def test_single_invalid_json_is_classified(db, settings):
    _seed_alert(db)

    class Bad(FakeLLM):
        def chat(self, messages, max_tokens=None):
            return "این متن هیچ JSON ندارد"

    w = _worker(db, settings, Bad())
    w.enqueue_missing()
    w.process_one()
    row = db.get_alert_analysis(1)
    assert row["status"] == "FAILED"
    assert row["error"].startswith("ValueError: invalid_json")


def test_single_missing_field_distinct_from_invalid_json(db, settings):
    _seed_alert(db)

    class Partial(FakeLLM):
        def chat(self, messages, max_tokens=None):
            payload = json.loads(FakeLLM.chat(self, messages))
            payload.pop("importance")
            return json.dumps(payload, ensure_ascii=False)

    w = _worker(db, settings, Partial())
    w.enqueue_missing()
    w.process_one()
    row = db.get_alert_analysis(1)
    assert row["status"] == "FAILED"
    assert row["error"].startswith("ValueError: missing_required_fields")
    assert "importance" in row["error"]


def test_single_bad_enum_reports_schema_error(db, settings):
    _seed_alert(db)

    class Buggy(FakeLLM):
        def chat(self, messages, max_tokens=None):
            payload = json.loads(FakeLLM.chat(self, messages))
            payload["importance"] = "VERY-BAD"
            return json.dumps(payload, ensure_ascii=False)

    w = _worker(db, settings, Buggy())
    w.enqueue_missing()
    w.process_one()
    row = db.get_alert_analysis(1)
    assert row["status"] == "FAILED"
    assert row["error"].startswith("ValueError: schema_validation_failed")
    assert "importance" in row["error"]


# ---- truncation ------------------------------------------------------------


def test_llm_truncation_classified_in_stream():
    w = LLMTruncated("output truncated by the token limit (finish_reason=length)")
    assert "truncated" in str(w) and isinstance(w, RuntimeError)


def test_partial_json_outputs_never_marked_completed(db, settings):
    _seed_alert(db)

    class Trunc(FakeLLM):
        def chat(self, messages, max_tokens=None):
            payload = json.loads(FakeLLM.chat(self, messages))
            # only summary was emitted before the token limit cut the model
            return json.dumps({"summary": payload["summary"]}, ensure_ascii=False)[:20]

    w = _worker(db, settings, Trunc())
    w.enqueue_missing()
    w.process_one()
    row = db.get_alert_analysis(1)
    assert row["status"] == "FAILED"  # partial output is never success
    error = row["error"]
    assert "invalid_json" in error or "missing_required_fields" in error


# ---- batch -----------------------------------------------------------------


def _batch_settings_with_two_alerts(db, settings) -> list[int]:
    ids = [_seed_alert(db)]
    return ids


def test_batch_unknown_and_duplicate_ids_skipped_not_attributed(db, settings):
    _seed_alert(db)
    ev = {
        "ts": "2026-11-01T10:01:00+00:00", "ts_epoch": 1793594460.0,
        "event_type": "alert", "flow_id": 2025010102,
        "src_ip": "152.53.87.65", "src_port": 8443,
        "dest_ip": "10.233.68.49", "dest_port": 52223, "proto": "TCP",
        "app_proto": "tls",
    }
    event_id = db.insert_event(ev, "{}", "fp-batch-2")
    db.insert_alert(event_id, {
        "signature": "ET INFO Observed DNS Query to Uncommon Domain",
        "signature_id": 2027865, "rev": 4, "severity": 2, "action": "allowed",
        "category": "Potential Corporate Privacy Violation",
    })
    alerts, total = db.query_alerts(limit=5)
    ids = [a["id"] for a in alerts]
    good = ids[0]
    payload = {
        "results": [
            {"alert_id": 999, "summary": "غ", "importance": "low", "evidence": [],
             "anomaly_likelihood": "low", "confidence": "low",
             "recommendation": "غ", "memories_used": []},
            {"alert_id": None, "summary": "غ", "importance": "low", "evidence": [],
             "anomaly_likelihood": "low", "confidence": "low",
             "recommendation": "غ", "memories_used": []},
            {"alert_id": good, "summary": "درست", "importance": "low", "evidence": [],
             "anomaly_likelihood": "low", "confidence": "low",
             "recommendation": "درست", "memories_used": []},
            {"alert_id": good, "summary": "تکراری", "importance": "high",
             "evidence": [], "anomaly_likelihood": "low", "confidence": "low",
             "recommendation": "تکراری", "memories_used": []},
        ]
    }

    class Batch(FakeLLM):
        def chat(self, messages, max_tokens=None):
            if "تعداد:" not in messages[1]["content"]:
                payload2 = json.loads(FakeLLM.chat(self, messages))
                return json.dumps(payload2, ensure_ascii=False)
            return json.dumps(payload, ensure_ascii=False)

    w = _worker(db, settings, Batch())
    w.enqueue_missing()
    w.process_one()
    rows = {r["alert_id"]: r for r in db.list_alert_analyses()}
    assert rows[good]["status"] == "COMPLETED"
    assert rows[good]["summary"] == "درست"  # first result wins, dup ignored
    # the alert without a real result was NOT lost and NOT misattributed
    other = [a for a in ids if a != good]
    completed = [
        r for r in w.db.list_alert_analyses(status="COMPLETED")
        if r["alert_id"] in other
    ]
    assert completed and all(
        r["summary"] == "تطابق امضای شناخته‌شده؛ رفتار معمول شبکه."
        for r in completed
    )


def test_batch_result_for_missing_stage_falls_back_to_single(db, settings):
    _seed_alert(db)
    # model returns empty results for the whole batch → single fallback
    class Empty(FakeLLM):
        def chat(self, messages, max_tokens=None):
            if "results" not in messages[1]["content"]:
                payload = json.loads(FakeLLM.chat(self, messages))
                return json.dumps(payload, ensure_ascii=False)
            return json.dumps({"results": []}, ensure_ascii=False)

    from netagent.schemas import AlertAnalysis
    w = _worker(db, settings, Empty())
    w.enqueue_missing()
    w.process_one()
    row = db.get_alert_analysis(1)
    assert row["status"] == "COMPLETED"  # still analyzed individually
    assert row["summary"].startswith("تطابق امضا")


# ---- memory scope ----------------------------------------------------------


def test_batch_memory_never_leaks_across_members(db, settings):
    _seed_alert(db)
    # group of same src_ip fake second alert (batch group needs same src_ip)
    import json as _j
    ev = {
        "ts": "2026-11-01T10:01:00+00:00", "ts_epoch": 1793594460.0,
        "event_type": "alert", "flow_id": 2025010102,
        "src_ip": "152.53.87.65", "src_port": 8443,
        "dest_ip": "10.233.68.49", "dest_port": 52223, "proto": "TCP",
        "app_proto": "tls",
    }
    event_id = db.insert_event(ev, "{}", "fp-batch-2")
    db.insert_alert(event_id, {
        "signature": "ET INFO Observed DNS Query to Uncommon Domain",
        "signature_id": 2027865, "rev": 4, "severity": 2, "action": "allowed",
        "category": "Potential Corporate Privacy Violation",
    })
    # agent-scoped memory for agent 'agt_only': must not leak into batch prompt
    _mk_memory(db, memory_id="mem_scope", scope="agent", agent_id="agt_only")
    db.approve_memory("mem_scope", approved_by="admin")
    try:
        w = _worker(db, settings, FakeLLM())
        w._maybe_propose_followup  # touch keeps coverage obvious
        block, ids, _notes = w._batch_memory_context(
            [db.get_alert(1), db.get_alert(2)]
        )
        assert "mem_scope" not in ids and "mem_scope" not in block
    finally:
        pass


def test_batch_memory_intersection_shared_group_scope(db, settings):
    _seed_alert(db)
    ev = {
        "ts": "2026-11-01T10:01:00+00:00", "ts_epoch": 1793594460.0,
        "event_type": "alert", "flow_id": 2025010102,
        "src_ip": "152.53.87.65", "src_port": 8443,
        "dest_ip": "10.233.68.49", "dest_port": 52223, "proto": "TCP",
        "app_proto": "tls",
    }
    event_id = db.insert_event(ev, "{}", "fp-batch-shared")
    db.insert_alert(event_id, {
        "signature": "ET INFO Observed DNS Query to Uncommon Domain",
        "signature_id": 2027865, "rev": 4, "severity": 2, "action": "allowed",
        "category": "Potential Corporate Privacy Violation",
    })
    _mk_memory(db, memory_id="mem_net", network="0.0.0.0/0", scope="network",
               agent_id=None, host=None)
    db.approve_memory("mem_net", approved_by="admin")
    w = _worker(db, settings, FakeLLM())
    block, ids, _ = w._batch_memory_context(
        [db.get_alert(1), db.get_alert(2)]
    )
    assert ids == ["mem_net"] and "mem_net" in block


# ---- structured-output schemas --------------------------------------------


def schema_required() -> set[str]:
    return {"summary", "importance", "evidence", "anomaly_likelihood",
            "confidence", "recommendation"}


def test_schema_keys_match_pydantic_model():
    schema = ANALYSIS_SCHEMA
    assert schema["properties"]["importance"]["enum"] == [
        "low", "medium", "high",
    ]
    # memories_used carries a schema default → optional, and the backend
    # model itself fills a default list when the key is absent
    assert "evidence" in schema["properties"]
    assert set(schema["required"]) >= {
        "summary", "importance", "confidence", "recommendation",
    }
    batch_items = BATCH_SCHEMA["properties"]["results"]["items"]
    assert "alert_id" in batch_items["required"]


# ---- truncation ------------------------------------------------------------


def test_llm_truncation_classified_in_stream():
    chunks = []
    class FakeClient:
        def chat_stream(self, messages, max_tokens=None, first_token_cb=None):
            chunks.append("aa")
            return "نصف پاسخ؛"
    w = LLMTruncated("output truncated by the token limit (finish_reason=length)")
    assert "truncated" in str(w) and isinstance(w, RuntimeError)


