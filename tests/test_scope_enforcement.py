import json
import socket
from unittest.mock import Mock

import pytest

from netagent.agent.orchestrator import Orchestrator
from netagent.agent.tools import ToolScope, build_registry, execute_tool
from netagent.collectors import connectivity, nmap
from netagent.scope import TargetNotAuthorized
from tests.conftest import admin_headers


@pytest.mark.parametrize("target,expected", [
    ("192.168.1.5", "192.168.1.5"), ("192.168.1.129/25", "192.168.1.128/25"),
    ("192.168.1.0/28", "192.168.1.0/28"), ("2001:db8::1", "2001:db8::1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:db8:0:1::/64", "2001:db8:0:1::/64"), ("2001:db8::/48", "2001:db8::/48"),
    ("::ffff:192.168.1.5", "192.168.1.5"), ("fe80::1%eth0", "fe80::1%eth0"),
])
def test_authorized_address_forms(settings, target, expected):
    settings.monitor_cidrs = "192.168.1.0/24,2001:db8::/48,fe80::/64"
    assert ToolScope(settings, []).authorize(target) == expected


@pytest.mark.parametrize("target", [
    "192.168.2.1", "192.168.0.0/16", "2001:db9::1", "2001:db8::/32",
    "::ffff:8.8.8.8", "fe80::1%eth0;id", "2001:db8::1%eth0", "8.8.8.8%eth0",
])
def test_rejected_addresses_never_execute(settings, monkeypatch, target):
    settings.monitor_cidrs = "192.168.1.0/24,2001:db8::/48,fe80::/64"
    run = Mock(side_effect=AssertionError("network executed"))
    monkeypatch.setattr(connectivity.subprocess, "run", run)
    monkeypatch.setattr(connectivity.socket, "create_connection", run)
    for call in (lambda: connectivity.ping(settings, target),
                 lambda: connectivity.tcp_check(settings, target, 80)):
        with pytest.raises(TargetNotAuthorized):
            call()
    run.assert_not_called()


def dns_answers(*addresses):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 0, "",
             (ip, 0, 0, 0) if ":" in ip else (ip, 0)) for ip in addresses]


def test_dns_multiple_answers_all_must_be_authorized(settings, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: dns_answers("192.168.1.8", "8.8.8.8"))
    with pytest.raises(TargetNotAuthorized):
        ToolScope(settings, []).authorize("router.example", hostname=True, host_only=True)


def test_dns_pinned_before_actual_connect(settings, monkeypatch):
    resolver = Mock(return_value=dns_answers("192.168.1.8", "192.168.1.9"))
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    connection = Mock(side_effect=ConnectionRefusedError())
    monkeypatch.setattr(socket, "create_connection", connection)
    connectivity.tcp_check(settings, "router.example", 80)
    assert connection.call_args.args[0] == ("192.168.1.8", 80)
    assert resolver.call_count == 1


@pytest.mark.parametrize("tool,args", [
    ("ping", {"host": "8.8.8.8"}), ("tcp_check", {"host": "8.8.8.8", "port": 80}),
    ("nmap_discovery", {"target": "8.8.8.8"}), ("nmap_services", {"target": "8.8.8.8"}),
    ("nmap_os", {"target": "8.8.8.8"}), ("arp_scan", {"target": "8.8.8.8"}),
    ("host_fingerprint", {"target": "8.8.8.8"}), ("reverse_dns", {"ip": "8.8.8.8"}),
])
def test_registry_and_direct_api_share_gate(full_client, settings, db, monkeypatch, tool, args):
    monkeypatch.setattr("netagent.agent.tools.binary_available", lambda *a: True)
    run = Mock(side_effect=AssertionError("network executed"))
    monkeypatch.setattr(connectivity.subprocess, "run", run)
    monkeypatch.setattr(socket, "create_connection", run)
    monkeypatch.setattr("netagent.collectors.system_info.reverse_dns", run)
    result = execute_tool(build_registry(settings), db, settings, tool, args)
    assert result["unauthorized"] is True
    response = full_client.post(f"/api/tools/{tool}", headers=admin_headers(), json=args)
    assert response.status_code == 403
    run.assert_not_called()


@pytest.mark.parametrize("tool", ["ping", "tcp_check"])
def test_allowed_ipv6_reaches_collector(settings, db, monkeypatch, tool):
    settings.monitor_cidrs = "2001:db8::/64"
    seen = []
    monkeypatch.setattr(connectivity, tool, lambda s, host, *a, **k: seen.append(host) or {"ok": True})
    result = execute_tool(build_registry(settings), db, settings, tool, {"host": "2001:db8::5", "port": 80})
    assert result["ok"] and seen == ["2001:db8::5"]


def test_observed_alert_target_does_not_authorize_llm_network_access(settings, db, monkeypatch):
    class Model:
        model = "test"
        def chat(self, *a, **k):
            return json.dumps({"thought": "diagnose", "action": {"tool": "ping", "args": {"host": "203.0.113.5"}}})
    execute = Mock(side_effect=AssertionError("observed IP was scanned"))
    monkeypatch.setattr(connectivity, "ping", execute)
    settings.max_tool_calls_per_investigation = 2
    orchestrator = Orchestrator(db, settings, Model())
    orchestrator.run({"target_ip": "203.0.113.5"})
    execute.assert_not_called()


def test_observation_authorizes_discovery_only(settings, db, monkeypatch):
    monkeypatch.setattr("netagent.services.discovery.auto_discovery_eligible_networks",
                        lambda *a: [{"cidr": "172.16.1.0/24"}])
    scope = ToolScope(settings, [], db=db)
    assert scope.authorize("172.16.1.0/24", discovery=True) == "172.16.1.0/24"
    with pytest.raises(TargetNotAuthorized):
        scope.authorize("172.16.1.1")

