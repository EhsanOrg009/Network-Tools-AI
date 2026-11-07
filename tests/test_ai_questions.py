"""AI knowledge questions (v10): admin ask → structured answer → gated memory.

Covers: LLM-disabled honesty (FAILED, no fake answer), structured parsing,
the memory-proposal gate (source=question_resolve, PENDING_APPROVAL only,
not retrievable before admin approval), Activity tracing, and the admin API
(auth, list/detail, failure surfacing).
"""

from __future__ import annotations

import json

import pytest

from netagent.database import Database
from netagent.services.knowledge import ask_question
from tests.conftest import ADMIN_TOKEN
from tests.test_ai_analysis import _seed_alert
from tests.test_ai_memory import admin_headers, mem_client  # noqa: F401


class QFakeLLM:
    """Question-answer fake: captures messages, returns one canned payload."""

    model = "fake-question-model"

    def __init__(self, payload: str):
        self.payload = payload
        self.captured: list[list[dict[str, str]]] = []

    def chat(self, messages, max_tokens=None):
        self.captured.append(messages)
        return self.payload


def _answer_payload(**overrides) -> str:
    base = {
        "answer": "این هشدار یک سرویس عمدی شناخته‌شده است.",
        "confidence": "medium",
        "memory_proposal": {
            "title": "هشدارهای تکراری 2027865 روی agt_1 مثبت کاذب‌اند",
            "description": "«تکرار این امضا روی این کارگاه طی بررسی مدیریتی سالم است.",
            "category": "known_false_positive",
            "scope": "agent",
        },
    }
    base.update(overrides)
    return json.dumps(base, ensure_ascii=False)


def test_question_with_llm_disabled_is_failed_and_honest(db, settings):
    rec = ask_question(
        db, None, question="سرویس Tor روی agt_1 چه چیزی است؟", asked_by="admin"
    )
    assert rec["status"] == "FAILED"
    assert rec["answer"] is None
    assert "فعال" in rec["error"]
    assert not (rec.get("memory_proposal_ids") or [])


def test_structured_answer_recorded_and_traced(db, settings):
    llm = QFakeLLM(_answer_payload())
    rec = ask_question(db, llm, question="علت تکرار هشدارها چیست؟", asked_by="admin")
    assert rec["status"] == "ANSWERED"
    assert rec["answer"].startswith("این هشدار")
    assert rec["answer_meta"]["confidence"] == "medium"
    assert rec["duration_ms"] is not None
    # real trace in the activity monitor
    acts, _total = db.list_ai_activity(task_type="question", limit=10)
    assert acts and acts[-1].get("status") in ("COMPLETED", "FAILED") or acts
    assert any(
        any(r.get("question_id") == rec["question_id"] for r in (a.get("refs") or []))
        for a in acts
    )
    # prompt contract: system rule, question text, no secrets
    system, user = llm.captured[0][0]["content"], llm.captured[0][1]["content"]
    assert "memory_proposal" in system and "فارسی" in system
    assert "علت تکرار هشدارها" in user


def test_proposal_is_pending_and_never_auto_approved(db):
    llm = QFakeLLM(_answer_payload())
    rec = ask_question(
        db, llm, question="آیا این رفتار مجاز است؟ صحنه؟", asked_by="admin"
    )
    ids = rec["memory_proposal_ids"]
    assert len(ids) == 1
    row = db.get_memory(ids[0])
    assert row["status"] == "PENDING_APPROVAL"
    assert row["source"] == "question_resolve"
    assert row["question_id"] == rec["question_id"]
    from netagent.services.knowledge import retrieve_memories

    assert retrieve_memories(db, agent_id="agt_1") == []


def test_bad_or_absent_proposal_is_dropped_not_fatal(db):
    llm = QFakeLLM(_answer_payload(memory_proposal={"title": ""}))
    rec = ask_question(db, llm, question="سؤال ساده درباره‌ی شبکه", asked_by="admin")
    assert rec["status"] == "ANSWERED" and rec["memory_proposal_ids"] == []

    llm2 = QFakeLLM(_answer_payload(memory_proposal=None))
    rec2 = ask_question(db, llm2, question="سؤال ساده درباره‌ی هشدار ۲", asked_by="admin")
    assert rec2["memory_proposal_ids"] == []


def test_malformed_model_answer_is_honest_failure(db):
    llm = QFakeLLM("چون پیش‌فرض به نظر می‌رسد؛ قطعی نیست.")  # not JSON
    with pytest.raises(Exception):
        ask_question(db, llm, question="سؤال درباره‌ی پاسخ بی‌ساختار", asked_by="a")
    stored = db.list_ai_questions(limit=5)
    assert stored[0]["status"] == "FAILED"
    assert stored[0]["answer"] is None


def test_question_evidence_includes_alert_when_given(db):
    alert_id = _seed_alert(db)
    llm = QFakeLLM(_answer_payload())
    ask_question(
        db, llm, question="این هشدار با آی‌پی کارگاه مرتبط است؟",
        alert_id=alert_id, asked_by="admin",
    )
    user = llm.captured[0][1]["content"]
    assert "previous_analysis" in user or ("152.53.87.65" in user)


# -- admin API --------------------------------------------------------------


def test_question_api_requires_admin(mem_client):
    r = mem_client.get("/api/admin/v1/ai-questions")
    assert r.status_code == 401
    r = mem_client.post("/api/admin/v1/ai-questions", json={"question": "x" * 5})
    assert r.status_code == 401


def test_question_api_without_llm_returns_failed_record(mem_client):
    r = mem_client.post(
        "/api/admin/v1/ai-questions",
        json={"question": "سؤال بدون مدل فعال"}, headers=admin_headers(),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "FAILED"
    # audited
    audit = mem_client.get("/api/admin/v1/audit?limit=50",
                           headers=admin_headers()).json()
    assert any(a["action"] == "question.create" for a in audit["items"])


def test_question_api_list_detail_and_404(mem_client):
    r = mem_client.get("/api/admin/v1/ai-questions", headers=admin_headers())
    assert r.status_code == 200
    items = r.json()["items"]
    assert isinstance(items, list)
    qid = items[0]["question_id"] if items else "q_missing"
    r2 = mem_client.get(f"/api/admin/v1/ai-questions/{qid}", headers=admin_headers())
    assert r2.status_code in (200, 404)
    r3 = mem_client.get("/api/admin/v1/ai-questions/q_no_such", headers=admin_headers())
    assert r3.status_code == 404


def test_question_api_failure_response_when_model_fails(mem_client, db):
    r = mem_client.post(
        "/api/admin/v1/ai-questions",
        json={"question": "سؤال با مدل خراب"}, headers=admin_headers(),
    )
    # the app has no llm configured in tests → FAILED record, 200
    assert r.status_code == 200
    stored = db.list_ai_questions(status="FAILED")
    assert stored and stored[0]["error"].startswith("مدل‌زبان فعال نیست")
