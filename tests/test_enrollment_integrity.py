"""Identity binding, admission bounds and durable enrollment decisions."""
import hashlib
import time

import pytest

from netagent.services.enrollment import _RateLimiter
from tests.conftest import admin_headers
from tests.test_enrollment_request import _announce, _claim


def test_registration_id_cannot_be_rebound_to_another_identity(full_client, db):
    body, _, key = _announce(full_client)
    before = db.get_enrollment_request(body["request_id"])
    response = full_client.post("/api/agent/v1/register", json={
        **body, "identity_key_hash": hashlib.sha256(b"unrelated-identity").hexdigest(),
        "hostname": "replacement",
    })
    assert response.status_code == 403
    assert db.get_enrollment_request(body["request_id"]) == before
    assert _claim(full_client, body["request_id"], key).json()["status"] == "PENDING_APPROVAL"


def test_conflicting_id_and_existing_identity_cannot_update_either_request(full_client, db):
    first, _, _ = _announce(full_client)
    second, _, _ = _announce(full_client)
    before = [db.get_enrollment_request(b["request_id"]) for b in (first, second)]
    response = full_client.post("/api/agent/v1/register", json={
        **second, "identity_key_hash": first["identity_key_hash"], "hostname": "replacement",
    })
    assert response.status_code == 403
    assert [db.get_enrollment_request(b["request_id"]) for b in (first, second)] == before


def test_claim_observes_expiration_on_its_first_poll(full_client, db):
    body, _, key = _announce(full_client)
    with db.transaction():
        db._conn.execute("UPDATE enrollment_requests SET expiry_epoch=? WHERE id=?",
                         (time.time() - 10, body["request_id"]))
    response = _claim(full_client, body["request_id"], key)
    assert response.status_code == 200
    assert response.json()["status"] == "EXPIRED"


def test_expired_pending_request_cannot_be_approved(full_client, db):
    body, _, _ = _announce(full_client)
    with db.transaction():
        db._conn.execute("UPDATE enrollment_requests SET expiry_epoch=? WHERE id=?",
                         (time.time() - 10, body["request_id"]))
    response = full_client.post(f"/api/admin/v1/enrollment-requests/{body['request_id']}/approve",
                                headers=admin_headers())
    assert response.status_code == 409
    assert db.get_enrollment_request(body["request_id"])["status"] != "APPROVED"


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_review_and_audit_commit_together(full_client, db, monkeypatch, decision):
    body, _, _ = _announce(full_client)
    def fail(**kwargs):
        raise RuntimeError("audit storage unavailable")
    monkeypatch.setattr(db, "record_audit", fail)
    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        full_client.post(f"/api/admin/v1/enrollment-requests/{body['request_id']}/{decision}",
                         json={"reason": "test"}, headers=admin_headers())
    assert db.get_enrollment_request(body["request_id"])["status"] == "PENDING_APPROVAL"


def test_claim_rolls_back_credential_issuance_when_audit_fails(full_client, db, monkeypatch):
    body, _, key = _announce(full_client)
    full_client.post(f"/api/admin/v1/enrollment-requests/{body['request_id']}/approve",
                     headers=admin_headers())
    def fail(**kwargs):
        raise RuntimeError("audit storage unavailable")
    with monkeypatch.context() as context:
        context.setattr(db, "record_audit", fail)
        with pytest.raises(RuntimeError, match="audit storage unavailable"):
            _claim(full_client, body["request_id"], key)
    assert db.list_agents() == []
    assert db.get_enrollment_request(body["request_id"])["status"] == "APPROVED"
    retry = _claim(full_client, body["request_id"], key)
    assert retry.status_code == 200 and retry.json()["agent_token"]


def test_single_use_token_is_not_lost_when_agent_storage_fails(full_client, db, monkeypatch):
    minted = full_client.post("/api/admin/v1/enrollment-tokens", json={"ttl_minutes": 5},
                              headers=admin_headers()).json()
    payload = {"enrollment_token": minted["token"], "hostname": "token-test"}
    def fail(**kwargs):
        raise RuntimeError("agent storage unavailable")
    with monkeypatch.context() as context:
        context.setattr(db, "create_agent", fail)
        with pytest.raises(RuntimeError, match="agent storage unavailable"):
            full_client.post("/api/agent/v1/enroll", json=payload)
    retry = full_client.post("/api/agent/v1/enroll", json=payload)
    assert retry.status_code == 200


def test_rate_limiter_has_a_hard_source_bound_without_evicting_active_buckets(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("netagent.services.enrollment.time.monotonic", lambda: now[0])
    limiter = _RateLimiter(max_events=1, window_seconds=10, max_sources=2)
    assert limiter.allow("first") and limiter.allow("second")
    for n in range(100):
        assert not limiter.allow(f"extra-{n}")
    assert len(limiter._events) == 2
    assert not limiter.allow("first")
    now[0] = 11
    assert limiter.allow("new-source")
    assert len(limiter._events) <= 2
