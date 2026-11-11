"""Endpoint connectivity must use the same central scope as local tools."""
import socket
from unittest.mock import Mock

import pytest

import endpoint_agent
from tests.conftest import admin_headers, agent_headers, enroll
from tests.test_scope_enforcement import dns_answers


@pytest.mark.parametrize("target", ["203.0.113.10", "2001:db8::1", "192.168.1.0/24"])
def test_endpoint_task_rejects_outside_scope_or_range(full_client, db, target):
    agent_id, _ = enroll(full_client)
    response = full_client.post("/api/admin/v1/tasks", headers=admin_headers(), json={
        "agent_id": agent_id, "type": "connectivity_diagnostic", "params": {"host": target},
    })
    assert response.status_code == 403
    assert db.pending_task_count(agent_id) == 0


def test_endpoint_dns_checks_all_answers_and_pins_target(full_client, monkeypatch):
    agent_id, token = enroll(full_client, capabilities=("connectivity_diagnostic",))
    resolver = Mock(return_value=dns_answers("192.168.1.8", "203.0.113.10"))
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    body = {"agent_id": agent_id, "type": "connectivity_diagnostic",
            "params": {"host": "router.example", "kind": "tcp", "port": 443}}
    assert full_client.post("/api/admin/v1/tasks", headers=admin_headers(), json=body).status_code == 403
    resolver.return_value = dns_answers("192.168.1.8", "192.168.1.9")
    response = full_client.post("/api/admin/v1/tasks", headers=admin_headers(), json=body)
    assert response.status_code == 200
    assert response.json()["params"]["host"] == "192.168.1.8"
    resolver.side_effect = AssertionError("dispatch must not resolve the original hostname again")
    message = full_client.get("/api/agent/v1/tasks/next", headers=agent_headers(token)).json()["task"]
    assert message["params"]["host"] == "192.168.1.8"


def test_endpoint_pending_task_rechecks_changed_scope(full_client, db, settings):
    agent_id, token = enroll(full_client, capabilities=("connectivity_diagnostic",))
    task = full_client.post("/api/admin/v1/tasks", headers=admin_headers(), json={
        "agent_id": agent_id, "type": "connectivity_diagnostic", "params": {"host": "192.168.1.8"},
    }).json()
    settings.monitor_cidrs = "10.0.0.0/8"
    response = full_client.get("/api/agent/v1/tasks/next", headers=agent_headers(token))
    assert response.status_code == 200
    assert response.json()["task"] is None
    assert db.get_task(task["id"])["status"] == "failed"
    assert "scope" in db.get_task(task["id"])["error"].lower()
    audit = full_client.get("/api/admin/v1/audit", headers=admin_headers()).json()["items"]
    assert any(row["action"] == "task.scope_denied" for row in audit)


@pytest.mark.parametrize("target,expected", [
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1%eth0"),
    ("::ffff:192.168.1.8", "192.168.1.8"),
])
def test_endpoint_ipv6_numeric_execution(target, expected, monkeypatch):
    run = Mock(return_value=(0, "reply time=1ms", ""))
    monkeypatch.setattr(endpoint_agent, "_run_cmd", run)
    assert endpoint_agent.run_connectivity_diagnostic({"host": target})["ok"]
    assert run.call_args.args[0][-1] == expected


@pytest.mark.parametrize("target", ["fe80::1%eth0;id", "2001:db8::1%eth0", "192.168.1.0/24"])
def test_endpoint_invalid_numeric_target_does_not_execute(target, monkeypatch):
    run = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr(endpoint_agent, "_run_cmd", run)
    with pytest.raises(ValueError):
        endpoint_agent.run_connectivity_diagnostic({"host": target})
    run.assert_not_called()
