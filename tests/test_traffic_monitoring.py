"""Endpoint traffic monitoring: ingest auth, rate computation, bounds, retention."""

from __future__ import annotations

import time

import pytest

from tests.conftest import ADMIN_TOKEN


@pytest.fixture()
def enrolled(full_client):
    """Enroll one agent via the real API; return (client, agent_id, token)."""
    from tests.conftest import enroll as enroll_agent

    agent_id, token = enroll_agent(full_client, capabilities=("inventory", "traffic"))
    return full_client, agent_id, token


def _post_traffic(client, token, rx, tx, conns=None):
    return client.post(
        "/api/admin/v1/../agent/v1/traffic" if False else "/api/agent/v1/traffic",
        json={
            "collected_at_epoch": time.time(),
            "interfaces": [{"interface": "eth0", "rx_bytes": rx, "tx_bytes": tx}],
            "connections": conns or [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def test_traffic_requires_agent_credential(enrolled):
    client, agent_id, _token = enrolled
    r = client.post("/api/agent/v1/traffic", json={"interfaces": []})
    assert r.status_code == 401


def test_traffic_ingest_and_rate_computation(enrolled):
    client, agent_id, token = enrolled
    r = _post_traffic(client, token, 1000, 500)
    assert r.status_code == 200 and r.json()["stored"] == 1
    # too soon: no rate yet (dt guard)
    r2 = _post_traffic(client, token, 7000, 2500)
    assert r2.status_code == 200
    time.sleep(0.4)
    r3 = _post_traffic(client, token, 9000, 3200,
                       conns=[{"local": "1.2.3.4:5", "remote": "5.6.7.8:443", "state": "ESTAB"}])
    assert r3.status_code == 200

    got = client.get(f"/api/admin/v1/agents/{agent_id}/traffic?hours=1",
                     headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    assert got.status_code == 200
    body = got.json()
    samples = body["samples"]
    assert len(samples) == 3
    rates = [s["rx_rate"] for s in samples]
    assert rates[0] is None  # first sample: nothing to diff against
    assert any(rt is not None and rt > 0 for rt in rates)
    assert body["latest"]["connections"][0]["remote"] == "5.6.7.8:443"
    assert body["latest"]["active_connections"] == 1


def test_traffic_counter_reset_yields_no_bogus_rate(enrolled):
    client, agent_id, token = enrolled
    _post_traffic(client, token, 5_000_000, 1_000_000)
    time.sleep(0.4)
    # counter reset (reboot): rx < previous → NULL rate, never negative
    _post_traffic(client, token, 10, 5)
    got = client.get(f"/api/admin/v1/agents/{agent_id}/traffic",
                     headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    latest = got.json()["latest"]
    assert latest["rx_rate"] is None and latest["tx_rate"] is None


def test_traffic_bounds_are_enforced(enrolled):
    client, _agent_id, token = enrolled
    r = _post_traffic(client, token, -5, 0)  # negative counter → 422
    assert r.status_code == 422
    # oversized connection list is clipped server-side, not rejected
    conns = [{"local": f"1.2.3.4:{p}", "remote": "5.6.7.8:443", "state": "ESTAB"}
             for p in range(300)]
    r = _post_traffic(client, token, 10, 10, conns=conns)
    assert r.status_code == 200


def test_traffic_of_unknown_agent_404(full_client):
    r = full_client.get("/api/admin/v1/agents/agt_missing/traffic",
                        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    assert r.status_code == 404
