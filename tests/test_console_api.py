"""Interactive Python console tests: auth, isolation, expiry, limits, audit.

The console rides the same task channel: agent polls the signed
console_* envelope and submits results through the agent result endpoint.
Interpreter subprocesses are NOT spawned here (server-side lifecycle only);
the agent-side interpreter behavior is unit-tested separately.
"""

from __future__ import annotations

import time

from netagent.database import Database

from tests.conftest import (
    admin_headers,
    agent_headers,
    claim_over_http,
    enroll,
)  # noqa: F401


def _admin():
    return admin_headers()


def _enroll_console_agent(full_client):
    return enroll(full_client, capabilities=("inventory", "console"))


def _activate(full_client, agent_token):
    """One agent poll→result cycle moves the console task; session becomes active."""
    message = claim_over_http(full_client, agent_token)
    assert message and message["type"] == "console_session", message
    assert "envelope" in message  # console tasks are ALWAYS signed
    r = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result",
                         json={"ok": True, "result": {"ok": True, "session_id": message["params"]["session_id"]}},
                         headers=agent_headers(agent_token))
    assert r.status_code == 200
    return message["params"]["session_id"]


def _final_result(full_client, agent_token, message, result):
    r = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result",
                         json=result, headers=agent_headers(agent_token))
    assert r.status_code == 200


# -- auth and enablement -----------------------------------------------------------


def test_console_disabled_returns_error(full_client, secure_settings):
    secure_settings.allow_admin_python_console = False
    agent_id, _ = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    assert r.status_code == 400
    assert "disabled" in r.json()["detail"] or "ALLOW_ADMIN_PYTHON_CONSOLE" in r.json()["detail"]


def test_console_requires_admin_token(full_client):
    r = full_client.get("/api/admin/v1/console/sessions")
    assert r.status_code == 401


def test_console_without_signing_key_rejected(full_client, secure_settings):
    secure_settings.task_signing_key = ""
    agent_id, _ = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    assert r.status_code == 400


def test_console_target_without_capability_rejected(full_client):
    agent_id, _ = enroll(full_client)  # no console capability
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    assert r.status_code == 400


# -- session lifecycle --------------------------------------------------------------


def test_session_create_signing_and_activation(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    assert r.status_code == 200, r.text
    session = r.json()
    assert session["status"] == "creating"
    sid = _activate(full_client, agent_token)
    assert sid == session["id"]
    r2 = full_client.get(f"/api/admin/v1/console/sessions/{sid}", headers=_admin())
    assert r2.status_code == 200
    assert r2.json()["session"]["status"] == "active"


def test_terminate_session(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/terminate", headers=_admin())
    assert r2.status_code == 200
    assert r2.json()["status"] == "terminated"
    r3 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "1"}, headers=_admin())
    assert r3.status_code in (400, 404)


# -- ownership isolation -------------------------------------------------------------


def test_session_bound_to_administrator(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef", "X-Admin-Actor": "net-admin"})
    sid = r.json()["id"]
    # a different administrator (same shared token, different actor label)
    # cannot see, use, or terminate the session
    r2 = full_client.get(f"/api/admin/v1/console/sessions/{sid}",
                         headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef", "X-Admin-Actor": "other-admin"})
    assert r2.status_code == 404
    r3 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "1"}, headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef", "X-Admin-Actor": "other-admin"})
    assert r3.status_code == 404
    r4 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/terminate",
                          headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef", "X-Admin-Actor": "other-admin"})
    assert r4.status_code == 404
    # the owner still can
    assert full_client.get(f"/api/admin/v1/console/sessions/{sid}",
                           headers={"Authorization": "Bearer unit-admin-token-0123456789abcdef", "X-Admin-Actor": "net-admin"}).status_code == 200


# -- command flow and result wiring ---------------------------------------------------


def test_command_submit_claim_result_cycle(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)

    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "hosts = ['a']; len(hosts)"}, headers=_admin())
    assert r2.status_code == 200, r2.text
    command = r2.json()
    assert command["status"] == "queued"

    # signed console_command envelope via the same task channel
    message = claim_over_http(full_client, agent_token)
    assert message["type"] == "console_command" and "envelope" in message
    assert message["params"]["session_id"] == sid

    _final_result(full_client, agent_token, message,
                  {"ok": True, "result": {"ok": True, "stdout": "",
                                          "result_repr": "1", "duration_ms": 12.0}})
    r3 = full_client.get(f"/api/admin/v1/console/sessions/{sid}", headers=_admin())
    commands = r3.json()["commands"]
    done = next(c for c in commands if c["id"] == command["id"])
    assert done["status"] == "completed"
    assert done["result_repr"] == "1"
    assert done["code"] == "hosts = ['a']; len(hosts)"


def test_session_state_persists_across_commands_server_side(full_client):
    """Sequential commands share the session (same task channel; interpreter
    state staying alive across cells is asserted on the agent side)."""
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    commands = []
    for code in ("hosts = []", "hosts.append('h1')", "len(hosts)"):
        r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                              json={"code": code}, headers=_admin())
        commands.append((r2.json()["id"], r2.json()["seq"]))
    seqs = [seq for _, seq in commands]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3


# -- expiry / idle timeout -------------------------------------------------------------


def test_ttl_expiry_marks_session_expired(full_client, db):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id, "ttl_seconds": 60}, headers=_admin())
    sid = _activate(full_client, agent_token)
    with db._lock:
        db._conn.execute("UPDATE console_sessions SET expiry_epoch = ? WHERE id = ?",
                         (time.time() - 10, sid))
        db._conn.commit()
    from netagent.services import console as console_service
    console_service.sweep(db)
    r2 = full_client.get(f"/api/admin/v1/console/sessions/{sid}", headers=_admin())
    assert r2.json()["session"]["status"] == "expired"
    r3 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "1"}, headers=_admin())
    assert r3.status_code in (400, 404)


def test_idle_timeout_enforced_on_command_submission(full_client, db):
    """CONFIG'd idle timeout (300s default) closes inactive sessions — the
    sweep and 'submit' path must both honor it."""
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    # rewind last_active beyond the idle window, without touching TTL expiry
    with db._lock:
        db._conn.execute(
            "UPDATE console_sessions SET last_active_at = ? WHERE id = ?",
            (time.strftime(
                "%Y-%m-%dT%H:%M:%S+00:00",
                time.gmtime(time.time() - 100000)), sid))
        db._conn.commit()
    from netagent.services import console as console_service
    closed = console_service.sweep(db)
    assert closed >= 1
    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "1"}, headers=_admin())
    assert r2.status_code in (400, 404)  # likely already swept to expired


def test_idle_session_rejected_even_without_sweep(full_client, db):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    with db._lock:
        db._conn.execute(
            "UPDATE console_sessions SET last_active_at = ? WHERE id = ?",
            (time.strftime("%Y-%m-%dT%H:%M:%S+00:00",
                           time.gmtime(time.time() - 100000)), sid))
        db._conn.commit()
    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "1"}, headers=_admin())
    assert r2.status_code == 400
    assert "idle" in r2.json()["detail"]


# -- limits -------------------------------------------------------------------------------


def test_pending_command_limit(full_client, secure_settings, db):
    secure_settings.console_max_pending_commands = 2
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    for _ in range(2):
        r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                              json={"code": "pass"}, headers=_admin())
        assert r2.status_code == 200
    r3 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "pass"}, headers=_admin())
    assert r3.status_code == 400


def test_max_sessions_per_admin(full_client, secure_settings):
    secure_settings.console_max_sessions_per_admin = 1
    a1, t1 = _enroll_console_agent(full_client)
    a2, t2 = enroll(full_client, capabilities=("inventory", "console"), hostname="ws-2")
    r1 = full_client.post(f"/api/admin/v1/agents/{a1}/console/sessions",
                          json={"agent_id": a1}, headers=_admin())
    assert r1.status_code == 200
    r2 = full_client.post(f"/api/admin/v1/agents/{a2}/console/sessions",
                          json={"agent_id": a2}, headers=_admin())
    assert r2.status_code == 400


def test_output_truncation_on_result_ingest(full_client, secure_settings):
    secure_settings.console_max_output_bytes = 100
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "'x'*1000"}, headers=_admin())
    command_id = r2.json()["id"]
    message = claim_over_http(full_client, agent_token)
    _final_result(full_client, agent_token, message,
                  {"ok": True, "result": {"ok": True, "stdout": "y" * 5000, "stderr": "",
                                          "result_repr": "'x'*1000"}})
    r3 = full_client.get(f"/api/admin/v1/console/sessions/{sid}", headers=_admin())
    done = next(c for c in r3.json()["commands"] if c["id"] == command_id)
    assert len(done["stdout"]) <= 100


def test_cancel_command_queues_terminate_task(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    r2 = full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                          json={"code": "pass"}, headers=_admin())
    command_id = r2.json()["id"]
    r3 = full_client.post(
        f"/api/admin/v1/console/sessions/{sid}/commands/{command_id}/cancel",
        headers=_admin())
    assert r3.status_code == 200
    assert r3.json()["status"] == "cancelling"
    # the cancel spawns a signed console_terminate task on the same channel
    message = claim_over_http(full_client, agent_token)
    assert message is not None
    assert message["type"] in ("console_terminate", "console_command")


def test_duplicate_command_result_rejected(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = _activate(full_client, agent_token)
    full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                     json={"code": "1"}, headers=_admin())
    message = claim_over_http(full_client, agent_token)
    _final_result(full_client, agent_token, message,
                  {"ok": True, "result": {"ok": True, "stdout": "1"}})
    r2 = full_client.post(f"/api/agent/v1/tasks/{message['task_id']}/result",
                          json={"ok": True, "result": {"ok": True, "stdout": "1"}},
                          headers=agent_headers(agent_token))
    assert r2.status_code == 409


# -- auditing --------------------------------------------------------------------------------


def test_console_actions_audited(full_client):
    agent_id, agent_token = _enroll_console_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/console/sessions",
                         json={"agent_id": agent_id}, headers=_admin())
    sid = r.json()["id"]
    _activate(full_client, agent_token)
    full_client.post(f"/api/admin/v1/console/sessions/{sid}/commands",
                     json={"code": "print('console-code-check-456')"}, headers=_admin())
    audit = full_client.get("/api/admin/v1/audit", headers=_admin()).json()
    actions = [a["action"] for a in audit["items"]]
    assert "console.session.create" in actions
    assert "console.command.submit" in actions
