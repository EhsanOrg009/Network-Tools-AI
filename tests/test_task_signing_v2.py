import os
import time

import pytest

from endpoint_agent import derive_signing_key, verify_envelope
from netagent.security import sign_task
from netagent.services import signing
from netagent.services.tasks import build_signed_envelope
from tests.conftest import admin_headers, agent_headers, enroll, claim_over_http


def message(settings, agent_id="agent-a", version=2):
    result = {"task_id": "task-a", "type": "admin_python_script", "params": {"code": "print(1)"}, "timeout_seconds": 10}
    result["envelope"] = build_signed_envelope(settings, agent_id=agent_id, task_id=result["task_id"],
        task_type=result["type"], params=result["params"], expires_epoch=time.time() + 60,
        protocol_version=version, timeout_seconds=10)
    return result


def test_per_agent_key_is_independent_of_legacy_master(secure_settings):
    a = signing.agent_key(secure_settings, "agent-a")
    b = signing.agent_key(secure_settings, "agent-b")
    assert a != b
    task = message(secure_settings, "agent-b")
    assert verify_envelope(task, b, "agent-b")[0]
    assert not verify_envelope(task, a, "agent-b")[0]
    assert not verify_envelope(task, derive_signing_key(secure_settings.task_signing_key, "agent-b"), "agent-b")[0]
    secure_settings.task_signing_key = "compromised-old-master-changed"
    assert signing.agent_key(secure_settings, "agent-b") == b


@pytest.mark.parametrize("field", ["agent", "task", "type", "params", "timeout", "protocol", "nonce", "signature"])
def test_tampered_task_is_rejected(secure_settings, field):
    task = message(secure_settings)
    key = signing.agent_key(secure_settings, "agent-a")
    if field == "agent":
        task["envelope"]["agent_id"] = "agent-b"
    elif field == "task":
        task["task_id"] = "task-b"
    elif field == "type":
        task["type"] = "console_command"
    elif field == "params":
        task["params"]["code"] = "print(2)"
    elif field == "timeout":
        task["timeout_seconds"] = 1000
    elif field == "protocol":
        task["envelope"]["protocol_version"] = 3
    else:
        task["envelope"][field] = "changed"
    assert not verify_envelope(task, key, "agent-a")[0]


def test_non_ascii_task_signature_is_rejected_without_crashing(secure_settings):
    task = message(secure_settings)
    task["envelope"]["signature"] = "امضای نامعتبر"
    key = signing.agent_key(secure_settings, "agent-a")
    assert verify_envelope(task, key, "agent-a") == (False, "bad signature")


def test_expiry_replay_and_downgrade(secure_settings):
    task = message(secure_settings)
    key = signing.agent_key(secure_settings, "agent-a")
    nonces = []
    assert verify_envelope(task, key, "agent-a", nonces)[0]
    assert not verify_envelope(task, key, "agent-a", nonces)[0]
    task["envelope"]["expires_epoch"] = time.time() - 1
    payload = {k: v for k, v in task["envelope"].items() if k != "signature"}
    task["envelope"]["signature"] = sign_task(payload, key)
    assert verify_envelope(task, key, "agent-a")[1] == "envelope expired"
    legacy = message(secure_settings, version=1)
    assert not verify_envelope(legacy, secure_settings.task_signing_key, "agent-a")[0]
    assert verify_envelope(legacy, secure_settings.task_signing_key, "agent-a", allow_legacy=True)[0]


def test_key_claim_is_agent_owned_and_revocation_applies(full_client):
    a, token_a = enroll(full_client, capabilities=("admin_exec", "task_signing_v2"))
    b, token_b = enroll(full_client, capabilities=("admin_exec", "task_signing_v2"))
    path = "/api/agent/v1/signing-key"
    assert full_client.get(path).status_code == 401
    assert full_client.get(path, headers=admin_headers()).status_code == 401
    ra = full_client.get(path + f"?agent_id={b}", headers=agent_headers(token_a))
    rb = full_client.get(path, headers=agent_headers(token_b))
    assert ra.json()["agent_id"] == a and rb.json()["agent_id"] == b
    assert ra.json()["key"] != rb.json()["key"] and ra.headers["cache-control"] == "no-store"
    full_client.post(f"/api/admin/v1/agents/{a}/revoke", headers=admin_headers())
    # Revocation invalidates the stored token hash, so it is no longer a
    # recognized credential (401), rather than an authenticated identity.
    assert full_client.get(path, headers=agent_headers(token_a)).status_code == 401


def test_v2_dispatch_and_legacy_deadline_do_not_break_diagnostics(full_client, db, secure_settings):
    legacy, old_token = enroll(full_client, capabilities=("admin_exec", "inventory"))
    new, new_token = enroll(full_client, capabilities=("admin_exec", "task_signing_v2"))
    for agent_id in (legacy, new):
        assert full_client.post(f"/api/admin/v1/agents/{agent_id}/scripts", headers=admin_headers(),
                               json={"agent_id": agent_id, "code": "print(1)"}).status_code == 200
    db.set_meta(signing.DEADLINE_KEY, "0")
    assert claim_over_http(full_client, old_token) is None
    task = claim_over_http(full_client, new_token)
    credential = full_client.get("/api/agent/v1/signing-key", headers=agent_headers(new_token)).json()
    assert verify_envelope(task, credential["key"], new)[0]
    full_client.post("/api/admin/v1/tasks", headers=admin_headers(),
                     json={"agent_id": legacy, "type": "inventory_collection"})
    assert claim_over_http(full_client, old_token)["type"] == "inventory_collection"
    signing.initialize(db, secure_settings)
    assert db.get_meta(signing.DEADLINE_KEY) == "0"


def test_rotation_replaces_only_server_root(secure_settings):
    task = message(secure_settings)
    old = signing.agent_key(secure_settings, "agent-a")
    path = signing.root_path(secure_settings)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    path.write_text("a1" * 32)
    new = signing.agent_key(secure_settings, "agent-a")
    assert new != old
    assert not verify_envelope(task, new, "agent-a")[0]
    assert verify_envelope(message(secure_settings), new, "agent-a")[0]
