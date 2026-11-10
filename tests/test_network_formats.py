"""Platform output and IPv6 execution tests; subprocesses are mocked."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netagent.agent.tools import build_registry, execute_tool
from netagent.collectors import connectivity, nmap, system_info


@pytest.mark.parametrize("platform,target,output,replies,loss", [
    ("Linux", "192.168.1.2", "64 bytes from 192.168.1.2: icmp_seq=1 ttl=64 time=1.2 ms\n64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=2.3 ms\n3 packets transmitted, 2 received, 33.3% packet loss", 2, 33.3),
    ("Windows", "192.168.1.2", "Reply from 192.168.1.2: bytes=32 time<1ms TTL=128\nRequest timed out.\nPackets: Sent = 2, Received = 1, Lost = 1 (50% loss)", 1, 50),
    ("Linux", "fd00::2", "64 bytes from fd00::2: icmp_seq=1 ttl=64 time=0.3 ms\n0% packet loss", 1, 0),
    ("Windows", "fd00::2", "Reply from fd00::2: time=2ms\n0% loss", 1, 0),
    ("Linux", "192.168.1.2", "From 192.168.1.1 icmp_seq=1 Destination Host Unreachable\n100% packet loss", 0, 100),
])
def test_ping_reply_records(settings, monkeypatch, platform, target, output, replies, loss):
    settings.authorized_targets = target
    monkeypatch.setattr(connectivity.platform, "system", lambda: platform)
    run = Mock(return_value=SimpleNamespace(stdout=output.encode(), stderr=b"", returncode=0 if replies else 1))
    monkeypatch.setattr(connectivity.subprocess, "run", run)
    result = connectivity.ping(settings, target)
    assert result["responses"] == replies
    assert result["packet_loss_pct"] == loss
    assert result["ok"] is bool(replies)
    command = run.call_args.args[0]
    assert ("-n" if platform == "Windows" else "-c") in command
    assert ("-6" in command) == (":" in target)


@pytest.mark.parametrize("target", ["192.168.1.0/25", "10.2.0.0/16", "fd00::1", "fd00:0:0:0:0:0:0:1", "fd00::/120", "fd00::/64", "fe80::1%eth0"])
def test_nmap_family(settings, monkeypatch, target):
    settings.monitor_cidrs = "192.168.1.0/24,10.0.0.0/8,fd00::/48,fe80::/64"
    run = Mock(return_value=("<nmaprun/>", "", 0, False))
    monkeypatch.setattr(nmap, "_run_nmap", run)
    for operation in (nmap.host_discovery, nmap.port_service_scan):
        operation(settings, target)
        assert ("-6" in run.call_args.args[0]) == (":" in target)
    assert ("-6" in nmap.build_os_command(target, [80])) == (":" in target)


def test_arp_ipv6_does_not_execute(settings, db, monkeypatch):
    settings.authorized_targets = "fd00::1"
    registry = build_registry(settings)
    registry["arp_scan"].available = lambda _: True
    run = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr("subprocess.run", run)
    result = execute_tool(registry, db, settings, "arp_scan", {"target": "fd00::1"})
    assert not result["ok"] and "IPv4 only" in result["error"]
    run.assert_not_called()


def test_reverse_dns_ipv6(settings, monkeypatch):
    settings.authorized_targets = "fd00::1"
    run = Mock(return_value="Nmap scan report for local (fd00::1)")
    monkeypatch.setattr(system_info, "_run", run)
    assert system_info.reverse_dns("fd00::1", settings=settings)["hostname"] == "local"
    assert "-6" in run.call_args.args[0]
