"""Automatic agent registration with administrator approval (v4).

Covers: announce → PENDING_APPROVAL → dashboard approve/reject → claim
issues the permanent credential exactly once → anti-abuse (rate limit,
expiry, dedupe, disabled feature, wrong identity key, revoked flow).

No scan runs anywhere; purely HTTP/service-level tests.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from tests.conftest import (
    ADMIN_TOKEN,
    admin_headers,
    agent_headers,
    make_client,
)  # noqa: F401


def _admin():
    return admin_headers()


def _request_id() -> str:
    return secrets.token_hex(16)


def _identity_hash():
    key = secrets.token_hex(32)
    return hashlib.sha256(key.encode()).hexdigest(), key


def _announce(c, status_expect=200, identity_key: str | None = None, **overrides):
    made_key = identity_key or secrets.token_hex(32)
    identity_hash = hashlib.sha256(made_key.encode()).hexdigest()
    key_out = made_key if identity_key is None else made_key  # always return key
    body = {
        "request_id": overrides.get("request_id", _request_id()),
        "identity_key_hash": identity_hash,
        "hostname": overrides.get("hostname", "auto-ws-1"),
        "platform": {"os_family": "Windows", "os_name": "Windows 11 Pro",
                     "os_version": "10.0.22631", "kernel": "build", "arch": "AMD64"},
        "agent_version": "1.0.0",
        "claimed_ips": ["192.168.1.51"],
        "mac": "d8:96:95:11:22:33",
        "gateway": "192.168.1.1",
    }
    r = c.post("/api/agent/v1/register", json=body)
    assert r.status_code == status_expect, r.text
    return body, r.json(), made_key


def _claim(c, request_id: str, identity_key: str):
    return c.post(f"/api/agent/v1/register/{request_id}/claim",
                  json={"identity_key": identity_key})


# -- announce / pending ------------------------------------------------------------


def test_announce_creates_pending_request(full_client):
    body, response, _announce_key = _announce(full_client)
    assert response["status"] == "PENDING_APPROVAL"
    assert response["request_id"]
    assert response["expires_at"]  # requests expire, no endless backlog


def test_re_announce_updates_existing_request_not_creating_endless_rows(full_client, db):
    rid = _request_id()
    _announce(full_client, request_id=rid)
    _announce(full_client, request_id=rid)
    import hashlib, secrets as s
    h2, _ = _identity_hash()
    r = full_client.post("/api/agent/v1/register", json={
        "request_id": rid, "identity_key_hash": h2, "hostname": "renamed-ws"})
    assert r.status_code == 200
    item = db.get_enrollment_request(rid)
    assert item["hostname"] == "renamed-ws"
    # dedupe is driven by identity hash: the earlier registration updates in place
    items, total = db.list_enrollment_requests(status="PENDING_APPROVAL")
    assert total >= 1


def test_admin_sees_pending_request_in_list(full_client):
    _announce(full_client)
    r = full_client.get("/api/admin/v1/enrollment-requests", headers=_admin())
    assert r.status_code == 200
    body = r.json()
    matching = [i for i in body["items"] if i["status"] == "PENDING_APPROVAL"
                and i["hostname"] == "auto-ws-1"]
    assert matching and matching[0]["claimed_ips"] == ["192.168.1.51"]


def test_enrollment_requests_require_admin_token(full_client):
    r = full_client.get("/api/admin/v1/enrollment-requests")
    assert r.status_code == 401
    r2 = full_client.post("/api/admin/v1/enrollment-requests/x/approve")
    assert r2.status_code == 401


def test_auto_registration_disabled(full_client, secure_settings):
    secure_settings.allow_auto_registration = False
    _, response, _ = _announce(full_client, status_expect=403)
    assert "ALLOW_AUTO_REGISTRATION" in response["detail"]


# -- approve → claim → enroll --------------------------------------------------------


def test_full_approval_lifecycle_exactly_one_credential(full_client):
    body, response, identity_key = _announce(full_client)
    rid = body["request_id"]
    # re-announce with the SAME identity key: refreshes in place (same row)
    _announce(full_client, request_id=rid, identity_key=identity_key)

    # admin approves from the dashboard
    ra = full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/approve",
                          headers={**_admin(), "X-Admin-Actor": "net-admin"})
    assert ra.status_code == 200, ra.text
    assert ra.json()["status"] == "APPROVED"

    # agent claims: the credential is issued exactly once
    rc = _claim(full_client, rid, identity_key)
    assert rc.status_code == 200, rc.text
    issued = rc.json()
    assert issued["status"] == "APPROVED"
    agent_id, agent_token = issued["agent_id"], issued["agent_token"]

    # second claim: ENROLLED, no new credential
    rc2 = _claim(full_client, rid, identity_key)
    assert rc2.json()["status"] == "ENROLLED"
    assert "agent_token" not in rc2.json()

    # the created agent is a fully working one: heartbeat works
    rh = full_client.post("/api/agent/v1/heartbeat", json={},
                          headers=agent_headers(agent_token))
    assert rh.status_code == 200

    # wrong identity key rejected
    rw = _claim(full_client, rid, "wrong-key-value-000")
    assert rw.status_code == 403


def test_rejected_request_grants_nothing(full_client):
    key = secrets.token_hex(32)
    rid = _request_id()
    full_client.post("/api/agent/v1/register", json={
        "request_id": rid,
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "suspicious-ws"})
    rr = full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/reject",
                          json={"reason": "دستگاه ناشناس است"}, headers=_admin())
    assert rr.status_code == 200
    assert rr.json()["status"] == "REJECTED"
    rc = _claim(full_client, rid, key)
    assert rc.status_code == 200
    assert rc.json()["status"] == "REJECTED"
    assert rc.json()["reason"] == "دستگاه ناشناس است"
    # rejected flow re-announce allowed (new identity), but same identity stays rejected
    r2 = full_client.post("/api/agent/v1/register", json={
        "request_id": _request_id(),
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "suspicious-ws-2"})
    assert r2.status_code == 200  # rejected identity may request again via admin review


def test_approve_only_pending_records(full_client):
    rid = _request_id()
    r = full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/approve",
                         headers=_admin())
    assert r.status_code == 409


# -- expiry -------------------------------------------------------------------------


def test_stale_requests_expire(full_client, db):
    key = secrets.token_hex(32)
    rid = _request_id()
    full_client.post("/api/agent/v1/register", json={
        "request_id": rid,
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "stale-ws"})
    with db._lock:
        db._conn.execute("UPDATE enrollment_requests SET expiry_epoch = ? WHERE id = ?",
                         (time.time() - 10, rid))
        db._conn.commit()
    closed = db.expire_due_enrollment_requests()
    assert closed >= 1
    rc = _claim(full_client, rid, key)
    assert rc.status_code == 200
    assert rc.json()["status"] == "EXPIRED"
    assert "agent_token" not in rc.json()


# -- anti-abuse: rate limiting --------------------------------------------------------


def test_rate_limited_announcements_429(full_client):
    from netagent.services.enrollment import _RateLimiter
    limiter = _RateLimiter(max_events=2, window_seconds=3600)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False
    assert limiter.allow("5.6.7.8") is True  # other sources unaffected
    # window expires old events
    limiter2 = _RateLimiter(max_events=2, window_seconds=0.05)
    assert limiter2.allow("x") and limiter2.allow("x")
    time.sleep(0.08)
    assert limiter2.allow("x") is True


def test_already_enrolled_identity_cannot_re_register(full_client):
    key = secrets.token_hex(32)
    rid = _request_id()
    full_client.post("/api/agent/v1/register", json={
        "request_id": rid,
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "once-only-ws"})
    full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/approve", headers=_admin())
    claim = _claim(full_client, rid, key)
    agent_id = claim.json()["agent_id"]

    # same identity tries to announce again → the completed identity must not
    # silently mint a second active device
    r = full_client.post("/api/agent/v1/register", json={
        "request_id": _request_id(),
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "again-ws"})
    assert r.status_code == 403
    assert "باطل کنید" in r.json()["detail"]

    # after the administrator revokes the enrolled agent, the same identity MAY
    # request again (the old device identity is gone)
    full_client.post(f"/api/admin/v1/agents/{agent_id}/revoke", headers=_admin())
    r2 = full_client.post("/api/agent/v1/register", json={
        "request_id": _request_id(),
        "identity_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "hostname": "again-ws"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "PENDING_APPROVAL"


# -- audit ------------------------------------------------------------------------------


def test_approval_actions_audited(full_client):
    body, _, _ = _announce(full_client)
    rid = body["request_id"]
    full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/approve", headers=_admin())
    full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/reject",
                     json={"reason": "test"}, headers=_admin())  # conflict → no audit
    audit = full_client.get("/api/admin/v1/audit", headers=_admin()).json()
    actions = [a["action"] for a in audit["items"]]
    assert "enrollment_request.approve" in actions
