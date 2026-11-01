"""Tool validation: CIDR checks, argument validation, argument building,
and safe subprocess argument construction (mocked, never executed)."""

from __future__ import annotations

import pytest

from netagent.agent.tools import ToolScope, build_registry, execute_tool
from netagent.collectors import connectivity, nmap
from netagent.collectors.nmap import TargetNotAuthorized, validate_discovery_target


# -- host validation -----------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "-c 1 evil.com", "host; rm -rf /", "a b", "$PATH", "x" * 300])
def test_validate_host_rejects_unsafe_input(bad):
    with pytest.raises(ValueError):
        connectivity.validate_host(bad)


@pytest.mark.parametrize("good", ["192.168.1.10", "example.org", "my-host.local", "10.0.0.1"])
def test_validate_host_accepts_safe_input(good):
    assert connectivity.validate_host(good) == good


# -- nmap target authorization ---------------------------------------------------


def test_nmap_target_inside_authorized_cidr(settings):
    assert validate_discovery_target(settings, "192.168.1.0/24") == "192.168.1.0/24"
    assert validate_discovery_target(settings, "192.168.1.10") == "192.168.1.10"


def test_nmap_target_outside_authorized_cidr_rejected(settings):
    with pytest.raises(TargetNotAuthorized):
        validate_discovery_target(settings, "8.8.8.8")
    with pytest.raises(TargetNotAuthorized):
        validate_discovery_target(settings, "172.16.0.0/16")


@pytest.mark.parametrize("bad", ["", "not-an-ip!", "-oG /tmp/evil", "example.org"])
def test_nmap_target_rejects_invalid_and_hostnames(settings, bad):
    with pytest.raises(TargetNotAuthorized):
        validate_discovery_target(settings, bad)


def test_nmap_no_cidrs_configured_rejects_everything(settings):
    settings.monitor_cidrs = ""
    with pytest.raises(TargetNotAuthorized):
        validate_discovery_target(settings, "192.168.1.0/24")


def test_nmap_command_is_fixed_and_safe(settings):
    cmd = nmap.build_discovery_command("192.168.1.0/24")
    assert cmd[:2] == ["-sn", "-n"]
    assert cmd[-1] == "192.168.1.0/24"
    assert all(isinstance(a, str) for a in cmd)  # argument list, never a shell string


def test_nmap_output_parsing():
    sample = (
        "# Nmap 8.0 scan initiated\n"
        "Host: 192.168.1.10 (laptop)\tStatus: Up\n"
        "Host: 192.168.1.1 ()\tStatus: Up\n"
        "Host: 192.168.1.99 ()\tStatus: Down\n"
        "# Nmap done\n"
    )
    hosts = nmap.parse_grepable(sample)
    assert [h["ip"] for h in hosts] == ["192.168.1.10", "192.168.1.1"]


# -- registry / execute_tool ----------------------------------------------------


def test_out_of_scope_targets_rejected_by_registry(settings, db):
    """No feature flags anymore: the only gate is the authorized scope."""
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "nmap_discovery",
                          {"target": "8.8.8.8"})
    assert result["ok"] is False
    assert "خارج از محدوده" in result["error"]


def test_explicit_investigation_target_is_authorized(settings, db):
    """A user-started investigation target is authorized even outside CIDRs."""
    registry = build_registry(settings)
    scope = ToolScope(settings=settings, extra_targets=["203.0.113.5"])
    # 203.0.113.5 is inside TEST-NET-3; never scanned here — monkeypatch run.
    import netagent.agent.tools as tools_mod

    def fake_run(db, s, args, sc):
        return {"ok": True, "tool": "nmap_discovery", "target": args["target"],
                "hosts": []}

    registry["nmap_discovery"].run = fake_run
    result = execute_tool(registry, db, settings, "nmap_discovery",
                          {"target": "203.0.113.5"}, scope)
    assert result["ok"] is True
    # the (fake) run received the explicitly authorized target
    assert result["target"] == "203.0.113.5"


def test_registry_rejects_unknown_tool(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "rm -rf /", {})
    assert result["ok"] is False

    result = execute_tool(registry, db, settings, "_run_hidden", {})
    assert result["ok"] is False


def test_tcp_check_loopback_safe_port(settings, db):
    """Single TCP connect to loopback (never a remote network operation)."""
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "tcp_check",
                          {"host": "127.0.0.1", "port": 9})
    assert result["tool"] == "tcp_check"
    assert result["port"] == 9
    # connection refused on closed loopback port -> structured, no crash
    assert result["connected"] is False


def test_tcp_check_rejects_out_of_range_port(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "tcp_check",
                          {"host": "127.0.0.1", "port": 70000})
    assert result["ok"] is False


def test_tcp_check_extra_model_fields_are_ignored(settings, db):
    """Model-provided extra keys must not change the executed call."""
    registry = build_registry(settings)
    result = execute_tool(
        registry, db, settings, "tcp_check",
        {"host": "127.0.0.1", "port": 9, "extra": {"cmd": ["sh", "-c", "boom"]}},
    )
    assert result["tool"] == "tcp_check"
    assert "extra" not in result


def test_ping_arguments_validation(settings, db, monkeypatch):
    calls = []

    def fake_ping(s, host, count=None):
        calls.append(host)
        return {"target": host, "ok": True, "responses": 3}

    import netagent.agent.tools as tools_mod

    monkeypatch.setattr(tools_mod.connectivity, "ping", fake_ping)
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "ping", {"host": "192.168.1.10"})
    assert result["ok"] is True
    assert calls == ["192.168.1.10"]


def test_alert_tool_argument_bounds(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "suricata_alerts",
                          {"severity": 99, "limit": 5000})
    assert result["ok"] is False  # out-of-range args rejected


def test_events_tool_rejects_unknown_type(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "suricata_events",
                          {"event_type": "'; DROP TABLE events"})
    assert result["ok"] is False


def test_arp_scan_target_must_be_authorized(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "arp_scan", {"target": "8.8.8.8/32"})
    assert result["ok"] is False


def test_scope_rejection_for_new_tools(settings, db):
    registry = build_registry(settings)
    for tool, args in (
        ("nmap_services", {"target": "9.9.9.9"}),
        ("nmap_os", {"target": "9.9.9.9"}),
        ("host_fingerprint", {"target": "9.9.9.9"}),
    ):
        result = execute_tool(registry, db, settings, tool, args)
        assert result["ok"] is False, tool
        assert "خارج از محدوده" in result["error"], tool


def test_fingerprint_history_requires_no_scan(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "fingerprint_history",
                          {"ip": "192.168.1.10"})
    assert result["ok"] is True
    assert result["latest"] is None
    assert result["changes"]["comparisons_available"] is False


def test_route_info_read_only(settings, db):
    registry = build_registry(settings)
    result = execute_tool(registry, db, settings, "route_info", {})
    assert result["tool"] == "route_info"
    # read-only observation; structured either way
    assert "routes" in result or result.get("error")
