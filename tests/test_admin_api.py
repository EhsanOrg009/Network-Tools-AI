"""Administrator control-plane tests: auth, script tasks, audit, policy gates.

The LLM/orchestrator side is covered structurally: these tests verify the
admin endpoints are unauthenticated-unfriendly and that task creation and
signing cannot happen without an administrator token and the server-side
feature flags.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from tests.conftest import (
    ADMIN_TOKEN,
    admin_headers,
    agent_headers,
    enroll,
    make_client,
)  # noqa: F401


def _admin():
    return admin_headers()


# -- authentication and fail-closed behavior --------------------------------------


def test_admin_routes_fail_closed_without_token(settings, db):
    """No ADMIN_API_TOKEN configured → the whole family is disabled (503)."""
    settings.admin_api_token = ""
    settings.admin_api_token_sha256 = ""
    c = make_client(db, settings)
    r = c.get("/api/admin/v1/agents")
    assert r.status_code == 503
    assert "ADMIN_API_TOKEN" in r.json()["detail"]
    c.close()
    db.close()


def test_short_token_rejected_as_disabled(settings, db):
    settings.admin_api_token = "short"  # < 16 chars → never valid
    c = make_client(db, settings)
    r = c.get("/api/admin/v1/agents", headers={"Authorization": "Bearer short"})
    assert r.status_code == 503
    c.close()
    db.close()


def test_missing_or_wrong_token_401(full_client):
    for headers in ({}, {"Authorization": ""}, {"Authorization": "Bearer wrong-value"},
                    {"Authorization": "wrong scheme"}):
        r = full_client.get("/api/admin/v1/agents", headers=headers)
        assert r.status_code == 401, headers


def test_agent_credential_rejected_for_admin_routes(full_client):
    _, agent_token = enroll(full_client)
    r = full_client.get("/api/admin/v1/agents",
                        headers={"Authorization": f"Bearer {agent_token}"})
    assert r.status_code == 401


def test_token_sha256_only_configuration(full_client, secure_settings):
    """ADMIN_API_TOKEN_SHA256 works equally (plaintext kept out of config files)."""
    from netagent.security import hash_secret
    secure_settings.admin_api_token = ""
    secure_settings.admin_api_token_sha256 = hash_secret(ADMIN_TOKEN)
    r = full_client.get("/api/admin/v1/agents", headers=_admin())
    assert r.status_code == 200


# -- agent visibility / revocation --------------------------------------------------


def test_list_and_get_agent(full_client):
    agent_id, _ = enroll(full_client, capabilities=("inventory", "console"))
    r = full_client.get("/api/admin/v1/agents", headers=_admin())
    assert any(a["id"] == agent_id for a in r.json()["items"])
    r2 = full_client.get(f"/api/admin/v1/agents/{agent_id}", headers=_admin())
    assert r2.status_code == 200
    detail = r2.json()
    assert (detail.get("agent") or detail)["id"] == agent_id
    r3 = full_client.get("/api/admin/v1/agents/agt_missing9999", headers=_admin())
    assert r3.status_code == 404


def test_revoke_excludes_agent_from_new_tasks(full_client):
    agent_id, agent_token = enroll(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/revoke", headers=_admin())
    assert r.status_code == 200
    r2 = full_client.post("/api/admin/v1/tasks",
                          json={"agent_id": agent_id, "type": "inventory_collection"},
                          headers=_admin())
    assert r2.status_code in (400, 404)


# -- diagnostic task creation --------------------------------------------------------


def test_create_diagnostic_task_records_audit(full_client):
    agent_id, _ = enroll(full_client)
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "inventory_collection"},
                         headers=_admin())
    assert r.status_code == 200, r.text
    task = r.json()
    assert task["status"] == "pending"
    audit = full_client.get("/api/admin/v1/audit", headers=_admin()).json()
    assert any(a["action"] == "task.create" for a in audit["items"])


def test_unknown_task_type_rejected(full_client):
    agent_id, _ = enroll(full_client)
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "not_a_type"},
                         headers=_admin())
    assert r.status_code in (400, 422)


def test_cancel_pending_task(full_client):
    agent_id, _ = enroll(full_client)
    r = full_client.post("/api/admin/v1/tasks",
                         json={"agent_id": agent_id, "type": "inventory_collection"},
                         headers=_admin())
    task_id = (r.json().get("task") or r.json())["id"]
    r2 = full_client.post(f"/api/admin/v1/tasks/{task_id}/cancel", headers=_admin())
    assert r2.status_code == 200
    assert r2.json().get("cancelled") is True
    r3 = full_client.get(f"/api/admin/v1/tasks/{task_id}", headers=_admin())
    final = (r3.json().get("task") or r3.json())
    assert final.get("status") == "cancelled"


# -- remote Python execution policy ---------------------------------------------------


def _enroll_exec_agent(full_client):
    return enroll(full_client, capabilities=("inventory", "admin_exec"))


def test_admin_script_task_is_signed(full_client):
    agent_id, _ = _enroll_exec_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print('hello from admin')", "note": "check sshd"},
                         headers=_admin())
    assert r.status_code == 200, r.text
    body = r.json()
    envelope = body.get("envelope") or body.get("task", {}).get("envelope")
    assert envelope, "admin script task must carry a signed envelope"
    assert envelope.get("signature") and envelope.get("nonce")


def test_admin_script_disabled_when_flag_off(full_client, secure_settings):
    secure_settings.allow_admin_python_exec = False
    agent_id, _ = _enroll_exec_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print(1)"}, headers=_admin())
    assert r.status_code in (400, 403)


def test_admin_script_without_signing_key_rejected(full_client, secure_settings):
    secure_settings.task_signing_key = ""
    agent_id, _ = _enroll_exec_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print(1)"}, headers=_admin())
    assert r.status_code in (400, 403)


def test_admin_script_target_without_capability_rejected(full_client):
    agent_id, agent_token = enroll(full_client, capabilities=("inventory",))
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print(1)"}, headers=_admin())
    assert r.status_code in (400, 404)


def test_admin_script_oversize_rejected(full_client, secure_settings):
    secure_settings.admin_script_max_bytes = 128
    agent_id, _ = _enroll_exec_agent(full_client)
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "x = " + "1" * 500}, headers=_admin())
    assert r.status_code in (400, 413, 422)


def test_admin_script_runtime_clamped(full_client, secure_settings):
    secure_settings.admin_script_max_runtime_seconds = 60
    agent_id, _ = _enroll_exec_agent(full_client)
    huge_timeout = 1000000
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print(1)", "timeout_seconds": 3600},
                         headers=_admin())
    assert r.status_code == 200
    timeout = (r.json().get("task") or r.json()).get("timeout_seconds")
    assert timeout <= 60


def test_admin_script_blocked_for_revoked_agent(full_client):
    agent_id, _ = _enroll_exec_agent(full_client)
    full_client.post(f"/api/admin/v1/agents/{agent_id}/revoke", headers=_admin())
    r = full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                         json={"agent_id": agent_id, "code": "print(1)"}, headers=_admin())
    assert r.status_code in (400, 404)


# -- audit trail -----------------------------------------------------------------------


def test_audit_records_admin_actions_without_secrets(full_client):
    agent_id, _ = _enroll_exec_agent(full_client)
    code = "print('audit-secret-check-123')"
    full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts",
                     json={"agent_id": agent_id, "code": code}, headers=_admin())
    audit = full_client.get("/api/admin/v1/audit", headers=_admin()).json()
    actions = [a["action"] for a in audit["items"]]
    assert "admin_script.submit" in actions
    detail_json = json.dumps(audit["items"], default=str)
    assert code not in detail_json  # the code body is not logged in the audit trail
