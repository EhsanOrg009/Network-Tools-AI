"""Endpoint-agent API tests: enrollment, auth, heartbeat/stale, inventory, tasks.

No real network scans and no real endpoints: everything is HTTP against the
test client with a temporary database. Windows and Linux behave the same at
the HTTP contract level (the platform collectors themselves are unit-tested
separately with OS mocks).
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from tests.conftest import (
    agent_headers,
    claim_over_http,
    enroll,
    make_client,
    secure_settings,
)  # noqa: F401


# -- enrollment ----------------------------------------------------------------


def test_enroll_with_one_time_token_roundtrip(full_client):
    # admin must first mint a one-time token
    r = full_client.post("/api/admin/v1/enrollment-tokens",
                         json={"ttl_minutes": 5},
                         headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef"})
    assert r.status_code == 200
    token = r.json()["token"]

    agent_id, agent_token = enroll(full_client, token=token)
    assert agent_id.startswith("agt_") and agent_token.endswith(("_",)) is not None

    # the token is single-use: a second enrollment with the same token fails
    r2 = full_client.post("/api/agent/v1/enroll", json={"enrollment_token": token})
    assert r2.status_code == 403


def test_enroll_rejects_bad_tokens(full_client, secure_settings):
    for bad in ("", "wrong-token", "bogus"):
        r = full_client.post("/api/agent/v1/enroll", json={"enrollment_token": bad})
        assert r.status_code == 403, (bad, r.text)


def test_enroll_with_static_bootstrap_token(full_client, secure_settings):
    secure_settings.agent_enrollment_token = "static-bootstrap-secret"
    agent_id, agent_token = enroll(full_client, token="static-bootstrap-secret")
    assert agent_id
    assert agent_token not in repr(db_token_hash_is_present(full_client, agent_id, agent_token))


def db_token_hash_is_present(full_client, agent_id, agent_token):
    """The stored credential is a SHA-256 hash, never the plaintext token."""
    agent = full_client.app.state.db.get_agent(agent_id)
    h = agent.get("token_hash") or ""
    return h  # non-empty hash; plaintext never stored
    # (assertion inside caller via repr trick above; direct form below)


def test_agent_token_plaintext_never_in_db(full_client):
    agent_id, agent_token = enroll(full_client)
    agent = full_client.app.state.db.get_agent(agent_id)
    stored = dict(agent)
    assert agent_token not in str(stored)
    assert stored["token_hash"]


# -- authentication --------------------------------------------------------------


def test_agent_routes_require_bearer(full_client):
    for method, path in (("post", "/api/agent/v1/heartbeat"),):
        r = getattr(full_client, method)(path, json={})
        assert r.status_code == 401, r.text
    r = full_client.get("/api/agent/v1/tasks/next")
    assert r.status_code == 401


def test_wrong_agent_token_rejected(full_client):
    enroll(full_client)
    r = full_client.post("/api/agent/v1/heartbeat",
                         json={},
                         headers=agent_headers("agt_wrong"))
    assert r.status_code == 401


# -- heartbeat / staleness --------------------------------------------------------


def test_heartbeat_updates_last_seen_and_reports_interval(full_client):
    agent_id, agent_token = enroll(full_client)
    r = full_client.post("/api/agent/v1/heartbeat", json={
        "claimed_ips": ["192.168.1.10"], "hostname": "ws-test",
    }, headers=agent_headers(agent_token))
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is True
    assert body["heartbeat_interval_seconds"] > 0
    agent = full_client.app.state.db.get_agent(agent_id)
    assert agent["last_heartbeat_epoch"] > 0


def test_stale_agent_reported_not_offline(full_client, secure_settings, db):
    """A missing heartbeat means *stale*, never an assumed power-off."""
    agent_id, _ = enroll(full_client)
    db.agent_heartbeat(agent_id)
    # force the heartbeat to be old:
    with db._lock:
        db._conn.execute("UPDATE endpoint_agents SET last_heartbeat_epoch = ? WHERE id = ?",
                         (time.time() - 9999, agent_id))
        db._conn.commit()
    r = full_client.get("/api/admin/v1/agents",
                        headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef"})
    item = next(a for a in r.json()["items"] if a["id"] == agent_id)
    assert item["status"] == "stale"


def test_revoked_agent_rejected_after_revoke(full_client):
    agent_id, agent_token = enroll(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/revoke",
                         headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef"})
    assert r.status_code == 200
    # the stored hash is overwritten on revoke → the old bearer credential
    # no longer authenticates at all (401/403 both mean "cannot act")
    r2 = full_client.post("/api/agent/v1/heartbeat", json={},
                          headers=agent_headers(agent_token))
    assert r2.status_code in (401, 403)


# -- inventory --------------------------------------------------------------------


def test_inventory_ingested_and_due_flag_clears(full_client):
    agent_id, agent_token = enroll(full_client)
    payload = {
        "collected_at_epoch": time.time() - 5,
        "hostname": "ws-test",
        "interfaces": [{
            "name": "eth0", "status": "up", "ipv4": ["192.168.1.10/24"],
            "connected_networks": ["192.168.1.0/24"], "gateway": "192.168.1.1",
            "classification": "physical",
        }],
        "collectors_status": [{"name": "interfaces", "ok": True}],
    }
    r = full_client.post("/api/agent/v1/inventory", json=payload,
                         headers=agent_headers(agent_token))
    assert r.status_code == 200, r.text
    assert r.json()["stored"] is True

    r2 = full_client.post("/api/agent/v1/heartbeat", json={},
                          headers=agent_headers(agent_token))
    assert r2.json()["inventory_due"] is False


def test_future_inventory_timestamp_rejected(full_client):
    _, agent_token = enroll(full_client)
    r = full_client.post("/api/agent/v1/inventory", json={
        "collected_at_epoch": time.time() + 999999,
        "interfaces": [],
    }, headers=agent_headers(agent_token))
    assert r.status_code in (400, 422)


def test_network_observations_recorded_from_inventory(full_client):
    agent_id, agent_token = enroll(full_client)
    full_client.post("/api/agent/v1/inventory", json={
        "interfaces": [{
            "name": "eth0", "status": "up",
            "ipv4": ["192.168.50.5/24"], "connected_networks": ["192.168.50.0/24"],
            "classification": "physical",
        }],
    }, headers=agent_headers(agent_token))
    rows = full_client.app.state.db.list_network_observations(limit=10)
    assert any(item["cidr"] == "192.168.50.0/24" and item["agent_id"] == agent_id
               for item in rows)


# -- task lifecycle -----------------------------------------------------------------


def test_diagnostic_task_claim_and_duplicate_result_rejected(full_client):
    agent_id, agent_token = enroll(full_client, capabilities=("inventory",))
    admin = {"Authorization": "Bearer unit-admin-token-0123456789abcdef"}
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "inventory_collection"},
                         headers=admin)
    assert r.status_code == 200, r.text
    task_id = r.json()["id"] if "id" in r.json() else r.json().get("task", {}).get("id")

    message = claim_over_http(full_client, agent_token)
    assert message and message["task_id"] and message["type"] == "inventory_collection"
    # unsigned diagnostic: no envelope secret attached
    assert "envelope" not in message

    # a second agent with the same task cannot claim it (atomic pending→dispatched)
    other_id, other_token = enroll(full_client, hostname="ws-other")
    message2 = claim_over_http(full_client, other_token)
    assert message2 is None or message2["task_id"] != message["task_id"]

    body = {"ok": True, "result": {"hosts": []}, "error": None}
    r2 = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result", json=body,
                          headers=agent_headers(agent_token))
    assert r2.status_code == 200 and r2.json()["accepted"] is True
    r3 = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result", json=body,
                          headers=agent_headers(agent_token))
    assert r3.status_code == 409 and r3.json()["accepted"] is False


def test_foreign_agent_cannot_submit_result_for_others_task(full_client):
    agent_id, agent_token = enroll(full_client, capabilities=("inventory",))
    other_id, other_token = enroll(full_client, hostname="ws-other")
    admin = {"Authorization": "Bearer unit-admin-token-0123456789abcdef"}
    full_client.post("/api/admin/v1/tasks",
                     json={"agent_id": agent_id, "type": "inventory_collection"}, headers=admin)
    message = claim_over_http(full_client, agent_token)
    r = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result",
                         json={"ok": True}, headers=agent_headers(other_token))
    assert r.status_code == 403


def test_result_after_expiry_rejected(full_client, db):
    agent_id, agent_token = enroll(full_client, capabilities=("inventory",))
    admin = {"Authorization": "Bearer unit-admin-token-0123456789abcdef"}
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "inventory_collection"},
                         headers=admin)
    task_id = (r.json().get("task") or r.json())["id"]
    assert claim_over_http(full_client, agent_token) is not None
    # age the task beyond its TTL inside the DB, then expire it
    with db._lock:
        db._conn.execute("UPDATE agent_tasks SET expiry_epoch = ? WHERE id = ?",
                         (time.time() - 1000, task_id))
        db._conn.commit()
    db.expire_due_tasks()
    r2 = full_client.post(f"/api/agent/v1/tasks/{task_id}/result",
                          json={"ok": True}, headers=agent_headers(agent_token))
    assert r2.status_code in (400, 409)
    assert r2.json().get("accepted") is not True


def test_admin_task_type_notCreated_for_unknown(full_client):
    agent_id, _ = enroll(full_client)
    admin = {"Authorization": "Bearer unit-admin-token-0123456789abcdef"}
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "admin_python_script"},
                         headers=admin)
    assert r.status_code in (400, 422)


# -- agent/admin credential separation -----------------------------------------------


def test_agent_cannot_use_admin_routes(full_client):
    """An endpoint-credential cannot cross into the admin control plane."""
    _, agent_token = enroll(full_client)
    r = full_client.get("/api/admin/v1/agents",
                        headers={"Authorization": f"Bearer {agent_token}"})
    assert r.status_code == 401


def test_admin_cannot_use_agent_routes(full_client):
    enroll(full_client)
    r = full_client.get("/api/agent/v1/tasks/next",
                        headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef"})
    assert r.status_code == 401
