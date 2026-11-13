"""Persistent knowledge base (v9): AI memory — poisoning guards + retrieval.

Covers: approval gate, deterministic ids, expiry, scope-bounded retrieval,
revocation, memory-usage recording, analysis-time integration (memories_used
sanitize against provided ids), and the admin API (auth + audit).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from netagent.database import Database
from netagent.services.ai_analysis import AlertAnalysisWorker
from netagent.services.knowledge import (
    memory_context_block,
    retrieve_memories,
    suggest_memory,
)
from tests.test_ai_analysis import _seed_alert, FakeLLM
from tests.conftest import ADMIN_TOKEN


def admin_headers() -> dict:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture()
def mem_client(db, settings):
    settings.admin_api_token = ADMIN_TOKEN
    from fastapi.testclient import TestClient

    from netagent.main import create_app

    app = create_app(settings, start_monitor=False)
    app.state.db = db
    with TestClient(app) as c:
        yield c


def _memory(db: Database, *, memory_id: str = "mem_test", **kw) -> str:
    args = dict(
        memory_id=memory_id, title="سرویس Tor روی این کارگاه عمدی است",
        description="این سرویس طبق دستور IT با توافق مدیر شبکه فعال شده است.",
        category="approved_service", agent_id="agt_1", host=None,
        process="tor", service="tor", network=None, evidence=None,
        source="administrator", created_by="admin", status="PENDING_APPROVAL",
        confidence=None, scope="agent",
    )
    args.update(kw)
    return db.create_memory(**args)


# -- lifecycle ----------------------------------------------------------------


def test_pending_memory_is_never_retrieved(db):
    _memory(db)
    assert retrieve_memories(db, agent_id="agt_1", ip=None) == []


def test_approve_gate_and_retrieval_score(db):
    mid = _memory(db)
    approved = db.approve_memory(mid, approved_by="admin-ops")
    assert approved
    got = retrieve_memories(db, agent_id="agt_1")
    assert [m["memory_id"] for m in got] == [mid]
    assert got[0]["hit_count"] == 1  # real retrieval recorded


def test_memory_scoped_to_agent_does_not_leak(db):
    _memory(db)
    db.approve_memory("mem_test", approved_by="admin")
    got = retrieve_memories(db, agent_id="agt_9")
    assert got == []  # another agent never inherits this approval


def test_expired_memory_excluded_and_marked(db):
    expires = datetime.now(timezone.utc) - timedelta(hours=1)
    _memory(
        db,
        expires_at=expires.isoformat(timespec="seconds"),
        memory_id="mem_exp",
    )
    assert retrieve_memories(db, agent_id="agt_1") == []
    rows = db.list_memories()
    assert rows[0]["status"] == "EXPIRED"


def test_revoked_memory_stops_being_used(db):
    _memory(db)
    db.approve_memory("mem_test", approved_by="admin")
    db.revoke_memory("mem_test", revoked_by="admin", reason="رفتار تغییر کرد")
    assert retrieve_memories(db, agent_id="agt_1") == []
    row = db.get_memory("mem_test")
    assert row["status"] == "REVOKED" and row["revoke_reason"] == "رفتار تغییر کرد"


def test_memory_context_block_lists_scopes(db):
    _memory(db)
    db.approve_memory("mem_test", approved_by="admin")
    mems = retrieve_memories(db, agent_id="agt_1")
    block = memory_context_block(mems)
    assert "mem_test" in block
    assert "agent=agt_1" in block and "scope=agent" in block


def test_suggest_memory_is_pending_and_deterministic(db):
    m1 = suggest_memory(
        db, title="سرویس مقصد برای 8443 چک آنلاین است", description=None,
        category="known_service", agent_id=None, host="203.0.113.9",
        process=None, service=None, network=None, evidence=None,
        alert_id=5, source="analysis",
    )
    m2 = suggest_memory(
        db, title="سرویس مقصد برای 8443 چک آنلاین است", description=None,
        category="known_service", agent_id=None, host="203.0.113.9",
        process=None, service=None, network=None, evidence=None,
        alert_id=5, source="analysis",
    )
    assert m1["status"] == "PENDING_APPROVAL"
    assert m1["memory_id"] == m2["memory_id"]  # replay-safe identity
    assert m1["source"] == "analysis"


def test_suggest_memory_rejects_bad_scope_or_network(db):
    with pytest.raises(ValueError):
        suggest_memory(
            db, title="x" * 10, description=None, category="made_up",
            agent_id=None, host=None, process=None, service=None,
            network=None, evidence=None, alert_id=None, source="analysis",
        )
    with pytest.raises(ValueError):
        suggest_memory(
            db, title="x" * 10, description=None, category="known_service",
            agent_id=None, host=None, process=None, service=None,
            network="not-a-cidr", evidence=None, alert_id=None,
            source="analysis",
        )


# -- analysis integration -------------------------------------------------------


def test_worker_uses_approved_memory_and_sanitize_ids(db, settings):
    _seed_alert(db)
    # alert from the seed helper: src 152.53.87.65 → scope memory to a DIFFERENT
    # agent first to prove no leak, then bind by network
    _memory(db, memory_id="mem_other")  # agent agt_1 only
    db.approve_memory("mem_other", approved_by="admin")
    mems = retrieve_memories(db, agent_id="agt_x", ip="152.53.87.65")
    assert mems == []  # network/host does not match either

    _memory(db, memory_id="mem_net", network="0.0.0.0/0", scope="network",
            agent_id=None, host=None)
    db.approve_memory("mem_net", approved_by="admin")

    captured = {}

    class MemFake(FakeLLM):
        def chat(self, messages, max_tokens=None):
            captured["messages"] = messages
            return super().chat(messages)

    worker = AlertAnalysisWorker(db, settings, MemFake())
    db.set_security_ai_auto(True, actor="test-admin")
    worker.enqueue_missing()
    worker.process_one()
    user_msg = captured["messages"][1]["content"]
    assert "حافظه‌ی تأییدشده" in user_msg and "mem_net" in user_msg

    # model lying about a memory id it was never given must be ignored
    class Lying(FakeLLM):
        def chat(self, messages, max_tokens=None):
            payload = json.loads(FakeLLM.chat(self, messages) or "{}")
            payload["memories_used"] = ["mem_net", "mem_never_given"]
            return json.dumps(payload, ensure_ascii=False)

    worker2 = AlertAnalysisWorker(db, settings, Lying())
    db.set_security_ai_auto(True, actor="test-admin")
    worker2.enqueue_missing()
    alert_ids = [a["id"] for a in db.query_alerts(limit=5)[0]]
    # reanalyze to force another pass
    for aid in alert_ids:
        db.reset_alert_analysis(aid)
    worker2.process_one()
    row = db.get_alert_analysis(alert_ids[0])
    assert row["memories_used"] == ["mem_net"]


def test_worker_no_memories_leaves_block_out(db, settings):
    alert_id = _seed_alert(db)

    class Plain(FakeLLM):
        def chat(self, messages, max_tokens=None):
            Plain.seen = messages
            return super().chat(messages)

    Plain.seen = []
    worker = AlertAnalysisWorker(db, settings, Plain())
    db.set_security_ai_auto(True, actor="test-admin")
    worker.enqueue_missing()
    worker.process_one()
    # the user message must stay free of any memory context; the *system*
    # template may legitimately mention the conditional «حافظه‌ی تأییدشده» rule
    assert "حافظه‌ی تأییدشده" not in Plain.seen[1]["content"]


# -- admin API --------------------------------------------------------------


def test_memory_api_requires_admin(mem_client, db):
    r = mem_client.get("/api/admin/v1/ai-memories")
    assert r.status_code == 401


def test_admin_creates_memory_directly_approved(mem_client, db):
    payload = {
        "title": "سرویس Tor روی همین عامل عمدی است",
        "description": "طبق هماهنگی IT، محدود به همین دستگاه.",
        "category": "approved_service",
        "agent_id": "agt_1",
        "scope": "agent",
        "process": "tor",
    }
    r = mem_client.post("/api/admin/v1/ai-memories",
                        json=payload, headers=admin_headers())
    assert r.status_code in (200, 201)
    body = r.json()
    assert body["status"] == "APPROVED"
    assert body["source"] == "administrator"

    # approved knowledge is usable and idempotent-creation is safe
    r2 = mem_client.post("/api/admin/v1/ai-memories",
                         json=payload, headers=admin_headers())
    assert r2.status_code in (200, 201)

    # audit trail
    audit = mem_client.get("/api/admin/v1/audit?limit=50",
                           headers=admin_headers()).json()
    assert any(a["action"] == "memory.create" for a in audit["items"])


def test_admin_approve_revoke_and_rate_limit_paths(mem_client, db):
    _memory(db)
    r = mem_client.post("/api/admin/v1/ai-memories/mem_test/approve",
                        headers=admin_headers())
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    r = mem_client.post(
        "/api/admin/v1/ai-memories/mem_test/revoke",
        json={"reason": "رفتار سرویس تغییر کرد"}, headers=admin_headers(),
    )
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"
    # invalid category rejected with 422
    r = mem_client.post(
        "/api/admin/v1/ai-memories",
        json={"title": "دسته‌ی نامعتبر", "category": "bogus_cats", "scope": "agent"},
        headers=admin_headers(),
    )
    assert r.status_code == 422
def test_listing_knowledge_does_not_leave_a_transaction_that_blocks_security(db, settings):
    from netagent.services.ai_analysis import AlertAnalysisWorker
    from tests.test_ai_analysis import FakeLLM
    from tests.test_security_ai_controls import ingest, request
    selected = ingest(db)
    assert db.list_memories() == []
    row = request(db, selected)
    assert AlertAnalysisWorker(db, settings, FakeLLM()).process_one()
    assert db.get_alert_analysis(selected)["job_id"] == row["job_id"]
    assert db.get_alert_analysis(selected)["status"] == "COMPLETED"

