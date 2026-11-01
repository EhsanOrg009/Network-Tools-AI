"""Screenshot on demand: policy gates, signed round-trip, PNG retrieval."""

from __future__ import annotations

import base64

import pytest

from tests.conftest import ADMIN_TOKEN, SIGNING_KEY, enroll as enroll_agent

# 1x1 transparent PNG
TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


@pytest.fixture()
def ss_client(settings, db):
    settings.admin_api_token = ADMIN_TOKEN
    settings.task_signing_key = SIGNING_KEY
    settings.allow_admin_python_exec = True
    settings.allow_admin_python_console = True
    settings.allow_admin_screenshot = True
    from fastapi.testclient import TestClient

    from netagent.main import create_app

    settings.enable_monitor = False
    app = create_app(settings, start_monitor=False)
    app.state.db = db
    with TestClient(app) as c:
        yield c


def admin() -> dict:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def test_screenshot_disabled_by_default(client, db):
    settings = client.app.state.settings
    settings.admin_api_token = ADMIN_TOKEN
    settings.task_signing_key = SIGNING_KEY
    settings.allow_admin_screenshot = False
    agent_id, _token = enroll_agent(client, capabilities=("screenshot",))
    r = client.post(f"/api/admin/v1/agents/{agent_id}/screenshot", headers=admin())
    assert r.status_code == 403
    assert "ALLOW_ADMIN_SCREENSHOT" in r.json()["detail"]


def test_requires_agent_capability(ss_client):
    client = ss_client
    agent_id, _token = enroll_agent(client, capabilities=("inventory",))
    r = client.post(f"/api/admin/v1/agents/{agent_id}/screenshot", headers=admin())
    assert r.status_code == 400
    assert "screenshot" in r.json()["detail"]


def test_signed_roundtrip_and_png_retrieval(ss_client):
    client = ss_client
    db = client.app.state.db
    agent_id, token = enroll_agent(client, capabilities=("screenshot",))
    r = client.post(f"/api/admin/v1/agents/{agent_id}/screenshot", headers=admin())
    assert r.status_code == 200
    task_id = r.json()["task_id"]

    # fetch before completion → 409
    early = client.get(f"/api/admin/v1/agents/{agent_id}/screenshot/{task_id}", headers=admin())
    assert early.status_code == 409

    # agent claims (signed envelope), executes, submits a real PNG
    msg = client.get("/api/agent/v1/tasks/next",
                     headers={"Authorization": f"Bearer {token}"}).json()["task"]
    assert msg["type"] == "screen_capture" and "envelope" in msg
    r2 = client.post(f"/api/agent/v1/tasks/{task_id}/result",
                     json={"ok": True, "result": {
                         "ok": True, "format": "png", "size_bytes": len(TINY_PNG),
                         "data_base64": base64.b64encode(TINY_PNG).decode("ascii"),
                         "tool": "test"}},
                     headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200

    img = client.get(f"/api/admin/v1/agents/{agent_id}/screenshot/{task_id}", headers=admin())
    assert img.status_code == 200
    assert img.headers["content-type"].startswith("image/png")
    assert img.content == TINY_PNG
    assert img.headers["cache-control"] == "no-store"

    # audited
    audit = client.get("/api/admin/v1/audit?limit=50", headers=admin()).json()
    assert any(a["action"] == "screenshot.request" for a in audit["items"])


def test_failed_capture_surfaces_error(ss_client):
    client = ss_client
    agent_id, token = enroll_agent(ss_client, capabilities=("screenshot",))
    task_id = ss_client.post(
        f"/api/admin/v1/agents/{agent_id}/screenshot", headers=admin()
    ).json()["task_id"]
    # the agent must claim (dispatched) before its result is accepted
    msg = client.get("/api/agent/v1/tasks/next",
                     headers={"Authorization": f"Bearer {token}"}).json()["task"]
    assert msg["type"] == "screen_capture"
    ss_client.post(f"/api/agent/v1/tasks/{task_id}/result",
                   json={"ok": False, "result": {"ok": False},
                         "error": "no screenshot tool available"},
                   headers={"Authorization": f"Bearer {token}"})
    img = ss_client.get(f"/api/admin/v1/agents/{agent_id}/screenshot/{task_id}",
                        headers=admin())
    assert img.status_code == 409
    assert "no screenshot tool" in img.json()["detail"]


def test_cross_agent_fetch_rejected(ss_client):
    client = ss_client
    a1, _t1 = enroll_agent(client, capabilities=("screenshot",))
    a2, t2 = enroll_agent(client, capabilities=("screenshot",))
    task_id = client.post(f"/api/admin/v1/agents/{a1}/screenshot", headers=admin()).json()["task_id"]
    # agent a2 cannot submit a result for a1's task
    r = client.post(f"/api/agent/v1/tasks/{task_id}/result",
                    json={"ok": True, "result": {"ok": True,
                          "data_base64": base64.b64encode(TINY_PNG).decode()}},
                    headers={"Authorization": f"Bearer {t2}"})
    assert r.status_code == 400 or r.json().get("accepted") is False
    # fetching via the wrong agent path → 404
    img = client.get(f"/api/admin/v1/agents/{a2}/screenshot/{task_id}", headers=admin())
    assert img.status_code == 404
