import json
import os
import sqlite3
import threading
import time
from unittest.mock import Mock

import pytest

from endpoint_agent import ApiError, EndpointAgent, ResultSpool, State, build_parser
from netagent.database import Database
from tests.conftest import admin_headers, agent_headers, claim_over_http, enroll


def endpoint(tmp_path):
    path = tmp_path / "endpoint.json"
    state = State(path)
    state.data.update(agent_id="agent-test", agent_token="test-credential", server_url="https://core.invalid")
    state.save()
    return EndpointAgent(build_parser().parse_args(["run", "--state-file", str(path)]))


def ack(row):
    return {"ack": {"status": "stored", "result_id": row["result_id"],
                    "task_id": row["task_id"], "agent_id": row["agent_id"]}}


def test_result_persisted_before_delivery_and_survives_restart(tmp_path):
    agent = endpoint(tmp_path)
    transport = Mock()
    transport.request.side_effect = ApiError(0, "offline")
    agent.client = transport
    agent._submit_result("task-a", True, {"output": "valuable result"}, None)
    transport.request.assert_not_called()
    agent.deliver_results()
    row = dict(agent.spool.db.execute("SELECT * FROM results").fetchone())
    assert row["retry_count"] == 1 and row["delivery_status"] == "retry"
    assert row["next_retry_epoch"] > time.time()
    agent.spool.close()
    restored = endpoint(tmp_path)
    spool = restored._ensure_spool()
    with spool.db:
        spool.db.execute("UPDATE results SET next_retry_epoch=0")
    restored.client = Mock()
    restored.client.request.return_value = ack(row)
    restored.deliver_results()
    sent = restored.client.request.call_args.kwargs["payload"]
    assert sent["result"]["output"] == "valuable result"
    assert sent["result_id"] == row["result_id"]
    assert spool.db.execute("SELECT count(*) FROM results").fetchone()[0] == 0
    assert not spool.begin("task-a", "agent-test")
    spool.close()


@pytest.mark.parametrize("response", [{"accepted": True}, {"ack": {"status": "stored"}}, {}])
def test_invalid_ack_does_not_remove_result(tmp_path, response):
    agent = endpoint(tmp_path)
    agent._submit_result("task-a", True, {}, None)
    agent.client = Mock()
    agent.client.request.return_value = response
    agent.deliver_results()
    assert agent.spool.db.execute("SELECT count(*) FROM results").fetchone()[0] == 1
    agent.spool.close()


def test_delivery_failure_never_reexecutes_task(tmp_path, monkeypatch):
    agent = endpoint(tmp_path)
    execute = Mock(return_value=({"output": "done"}, True))
    monkeypatch.setattr(agent, "_dispatch_by_type", execute)
    agent.client = Mock()
    agent.client.request.side_effect = ApiError(0, "offline")
    message = {"task_id": "task-a", "type": "inventory_collection"}
    agent._execute_task_message(message)
    agent.deliver_results()
    agent._execute_task_message(message)
    assert execute.call_count == 1
    agent.spool.close()


def test_interrupted_execution_is_reported_without_rerun(tmp_path):
    path = tmp_path / "state.json"
    spool = ResultSpool(path)
    assert spool.begin("task-a", "agent-a")
    spool.close()
    restored = ResultSpool(path)
    restored.recover_interrupted("agent-a")
    row = restored.due("agent-a")[0]
    assert json.loads(row["payload_json"])["result"]["interrupted"]
    assert not restored.begin("task-a", "agent-a")
    restored.close()


def test_spool_size_permissions_capacity_and_no_pending_retention_deletion(tmp_path):
    spool = ResultSpool(tmp_path / "state.json", max_pending=1)
    spool.put("task-a", "agent-a", {"ok": True, "result": {"output": "x" * 100000}}, max_output_bytes=4096)
    row = spool.due("agent-a")[0]
    assert len(row["payload_json"].encode()) < 4096
    assert json.loads(row["payload_json"])["result"]["truncated"]
    assert not spool.has_capacity()
    with pytest.raises(RuntimeError):
        spool.begin("task-b", "agent-a")
    if os.name == "posix":
        assert spool.path.stat().st_mode & 0o777 == 0o600
        assert spool.directory.stat().st_mode & 0o777 == 0o700
    with spool.db:
        spool.db.execute("UPDATE results SET created_epoch=0")
    assert len(spool.due("agent-a")) == 1
    spool.close()


def test_long_task_keeps_control_heartbeat_and_bounded_worker_count(tmp_path, monkeypatch):
    agent = endpoint(tmp_path)
    started, finish = threading.Event(), threading.Event()
    def long_task(*a):
        started.set()
        assert finish.wait(5)
        return {"output": "done"}, True
    monkeypatch.setattr(agent, "_dispatch_by_type", long_task)
    monkeypatch.setattr(agent, "_quick_ips", lambda: [])
    responses = [{"task": {"task_id": "task-a", "type": "inventory_collection"}},
                 {"accepted": True}, {"task": None}]
    agent.client = Mock()
    agent.client.request.side_effect = lambda *a, **k: responses.pop(0) if responses else {"accepted": False}
    agent._start_workers()
    try:
        agent.poll_and_execute_task()
        assert started.wait(2)
        agent.heartbeat()
        agent.poll_and_execute_task()
        assert agent.last_heartbeat > 0 and not finish.is_set()
        assert agent.client.request.call_args.args[1].endswith("control_only=true")
        assert len(agent._workers) == agent.max_workers + 2
    finally:
        finish.set()
        agent.shutdown(timeout=3)


def new_task(client):
    agent_id, token = enroll(client)
    task = client.post("/api/admin/v1/tasks", headers=admin_headers(),
                       json={"agent_id": agent_id, "type": "inventory_collection"}).json()
    assert claim_over_http(client, token)["task_id"] == task["id"]
    return task["id"], agent_id, token


def test_server_ack_is_idempotent_and_bound_to_content(full_client, db):
    task_id, agent_id, token = new_task(full_client)
    body = {"result_id": "r" * 32, "ok": True, "result": {"output": "done"}}
    path = f"/api/agent/v1/tasks/{task_id}/result"
    first = full_client.post(path, headers=agent_headers(token), json=body)
    assert first.status_code == 200
    assert first.json()["ack"] == {"result_id": "r" * 32, "task_id": task_id, "agent_id": agent_id, "status": "stored"}
    again = full_client.post(path, headers=agent_headers(token), json=body)
    assert again.status_code == 200 and again.json()["duplicate"]
    body["result"]["output"] = "changed"
    assert full_client.post(path, headers=agent_headers(token), json=body).status_code == 409
    assert db.get_task(task_id)["result"]["output"] == "done"


def test_ack_not_issued_if_receipt_persistence_fails(full_client, db, monkeypatch):
    task_id, agent_id, token = new_task(full_client)
    def fail(**kwargs):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(db, "record_result_receipt", fail)
    with pytest.raises(sqlite3.OperationalError):
        full_client.post(f"/api/agent/v1/tasks/{task_id}/result", headers=agent_headers(token),
                         json={"result_id": "r" * 32, "ok": True, "result": {"output": "done"}})
    assert db.get_task(task_id)["status"] == "dispatched"
    assert db.get_result_receipt("r" * 32) is None


@pytest.mark.parametrize("status", ["expired", "cancelled"])
def test_late_results_are_durable_without_changing_task_status(full_client, db, status):
    task_id, agent_id, token = new_task(full_client)
    with db.transaction():
        db._conn.execute("UPDATE agent_tasks SET status=? WHERE id=?", (status, task_id))
    response = full_client.post(f"/api/agent/v1/tasks/{task_id}/result", headers=agent_headers(token),
                               json={"result_id": "r" * 32, "ok": True, "result": {"output": "late"}})
    assert response.status_code == 200 and response.json()["ack"]["status"] == "stored"
    task = db.get_task(task_id)
    assert task["status"] == status and task["late_result"]["result"]["output"] == "late"


def test_receipt_migration_preserves_tasks_and_is_repeatable(full_client, db):
    task_id, _, _ = new_task(full_client)
    other = Database(db.path)
    assert other.get_task(task_id)["status"] == "dispatched"
    assert other.get_meta("migration:001_agent_result_receipts") == "applied"
    other.close()


def test_control_only_poll_does_not_claim_normal_task(full_client):
    agent_id, token = enroll(full_client)
    task = full_client.post("/api/admin/v1/tasks", headers=admin_headers(),
                            json={"agent_id": agent_id, "type": "inventory_collection"}).json()
    response = full_client.get("/api/agent/v1/tasks/next?control_only=true", headers=agent_headers(token))
    assert response.json()["task"] is None
    assert claim_over_http(full_client, token)["task_id"] == task["id"]
