"""AI action proposals (v11): observe-first autonomy boundary.

Covers: dedupe, the worker hook (high-importance → proposal, low → none),
the admin API gates (auth, 404/409, approve → real investigation record →
EXECUTED, reject, 404 detail wording), and the hard rule that nothing
executes without an admin decision.
"""

from __future__ import annotations

import pytest

from netagent.database import Database
from netagent.services.ai_analysis import AlertAnalysisWorker
from netagent.services.actions import propose_investigation
from tests.test_ai_analysis import FakeLLM, _seed_alert
from tests.test_ai_memory import admin_headers, mem_client  # noqa: F401


def _propose(db: Database, **kw) -> str:
    return propose_investigation(
        db, alert_id=7, target_ip="10.10.0.4",
        rationale="رفتار مشروع مشکوک توصیف شد", **kw,
    )


def test_propose_creates_observed_and_dedupes(db):
    aid = _propose(db)
    assert aid is not None
    row = db.get_ai_action(aid)
    assert row["status"] == "OBSERVED"
    assert row["kind"] == "run_investigation"
    assert row["target"] == {"alert_id": 7, "target_ip": "10.10.0.4"}
    # same (alert, ip) while OBSERVED → dedupe, no new row
    assert _propose(db) is None
    assert len(db.list_ai_actions()) == 1


def test_decide_transitions_only_from_observed(db):
    aid = _propose(db)
    assert db.decide_ai_action(aid, decided_by="admin", status="REJECTED")
    assert db.get_ai_action(aid)["status"] == "REJECTED"
    assert not db.decide_ai_action(aid, decided_by="admin", status="APPROVED")
    assert db.get_ai_action(aid)["status"] == "REJECTED"


def _high_importance_ending(db, settings, importance: str) -> int:
    """Run one analysis with a forced importance; return the alert id."""

    class Sometimes(FakeLLM):
        def chat(self, messages, max_tokens=None):
            import json as _j
            payload = _j.loads(FakeLLM.chat(self, messages))
            payload["importance"] = importance
            return _j.dumps(payload, ensure_ascii=False)

    alert_id = _seed_alert(db)
    worker = AlertAnalysisWorker(db, settings, Sometimes())
    db.set_security_ai_auto(True, actor="test-admin")
    worker.enqueue_missing()
    worker.process_one()
    return alert_id


def test_worker_high_importance_proposes_investigation(db, settings):
    alert_id = _high_importance_ending(db, settings, "high")
    observed = [a for a in db.list_ai_actions() if a["status"] == "OBSERVED"]
    assert len(observed) == 1
    assert observed[0]["target"]["alert_id"] == alert_id
    # nothing executed by itself — analysis only recorded a suggestion
    assert all(a["kind"] == "run_investigation" for a in db.list_ai_actions())


def test_worker_low_importance_proposes_nothing(db, settings):
    alert_id = _high_importance_ending(db, settings, "low")
    assert alert_id >= 0
    assert db.list_ai_actions() == []


# -- admin API --------------------------------------------------------------


def test_action_api_requires_admin(mem_client):
    r = mem_client.get("/api/admin/v1/ai-actions")
    assert r.status_code == 401
    r = mem_client.post("/api/admin/v1/ai-actions/actn_x/reject")
    assert r.status_code == 401


def test_action_approval_runs_real_investigation(mem_client, db):
    aid = _propose(db)
    r = mem_client.post(f"/api/admin/v1/ai-actions/{aid}/approve",
                        headers=admin_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "EXECUTED"
    assert body["result"].get("investigation_id") is not None
    inv = db.get_investigation(body["result"]["investigation_id"])
    assert inv is not None and inv["status"].startswith("completed")
    # audit trail has the decision
    audit = mem_client.get("/api/admin/v1/audit?limit=50",
                           headers=admin_headers()).json()
    assert any(a["action"] == "action.approve" and a["target"] == aid
               for a in audit["items"])
    # second approve is a conflict
    r2 = mem_client.post(f"/api/admin/v1/ai-actions/{aid}/approve",
                         headers=admin_headers())
    assert r2.status_code == 409


def test_action_reject_and_404(mem_client, db):
    aid = _propose(db)
    r = mem_client.post(f"/api/admin/v1/ai-actions/{aid}/reject",
                        headers=admin_headers())
    assert r.status_code == 200 and r.json()["status"] == "REJECTED"
    audit = mem_client.get("/api/admin/v1/audit?limit=50",
                           headers=admin_headers()).json()
    assert any(a["action"] == "action.reject" and a["target"] == aid
               for a in audit["items"])
    r2 = mem_client.post("/api/admin/v1/ai-actions/actn_missing/reject",
                         headers=admin_headers())
    assert r2.status_code == 404
