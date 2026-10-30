"""Tests for the expanded nmap operations: argument generation, XML parsing,
scope validation, port bounds, and privilege degradation. All subprocess calls
are mocked — no real scans run from the test suite."""

from __future__ import annotations

import pytest

from netagent.collectors import nmap
from netagent.collectors.nmap import (
    TargetNotAuthorized,
    build_os_command,
    build_service_command,
    os_detect,
    port_service_scan,
    validate_port_list,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="TestCorp"/>
    <hostname name="printer.local" type="PTR"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24" method="probe" conf="10"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh" method="table" conf="3"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="98">
        <osclass vendor="Linux" osfamily="Linux" osgen="5.x" type="general purpose" accuracy="98"/>
      </osmatch>
    </os>
  </host>
</nmaprun>"""


# -- scope validation -----------------------------------------------------------


def test_scope_validation_inside_cidr(settings):
    # host targets normalize to a bare IP (never "x.x.x.x/32")
    assert nmap.validate_discovery_target(settings, "192.168.1.55") == "192.168.1.55"


def test_scope_validation_authorized_individual_target(settings):
    settings.authorized_targets = "172.16.47.2"
    assert nmap.validate_discovery_target(settings, "172.16.47.2") == "172.16.47.2"


def test_scope_validation_rejects_outside(settings):
    with pytest.raises(TargetNotAuthorized):
        nmap.validate_discovery_target(settings, "8.8.8.8")
    with pytest.raises(TargetNotAuthorized):
        nmap.validate_discovery_target(settings, "172.16.0.0/16")


def test_scope_validation_rejects_invalid_and_injection(settings):
    for bad in ["", "-oG /tmp/x", "a b", "example.org", "8.8.8.8;rm"]:
        with pytest.raises(TargetNotAuthorized):
            nmap.validate_discovery_target(settings, bad)


# -- argument building -----------------------------------------------------------


def test_discovery_command_fixed():
    cmd = nmap.build_discovery_command("192.168.1.0/24")
    assert cmd == ["-sn", "-n", "-oG", "-", "192.168.1.0/24"]


def test_service_command_args():
    cmd = build_service_command("192.168.1.10", [80, 443], service_detection=True)
    joined = " ".join(cmd)
    assert "-sT" in cmd and "-sV" in cmd and "--version-light" in cmd
    assert "--reason" in cmd
    assert "-p" in cmd and "80,443" in cmd
    assert cmd[-1] == "192.168.1.10"
    assert "sh" not in joined  # never a shell string


def test_service_command_without_version_detection():
    cmd = build_service_command("192.168.1.10", [80], service_detection=False)
    assert "-sV" not in cmd


def test_os_command_args():
    cmd = build_os_command("192.168.1.10", [22, 80])
    assert "-O" in cmd and "--osscan-guess" in cmd and "--reason" in cmd
    assert cmd[-1] == "192.168.1.10"


# -- port validation ---------------------------------------------------------------


def test_port_validation_bounds_and_dedup(settings):
    assert validate_port_list(settings, None) == settings.nmap_service_port_list
    assert validate_port_list(settings, [80, 80, 443]) == [80, 443]
    with pytest.raises(ValueError):
        validate_port_list(settings, [0])
    with pytest.raises(ValueError):
        validate_port_list(settings, [70000])
    with pytest.raises(ValueError):
        validate_port_list(settings, ["80; rm -rf /"])
    # configured cap
    settings.nmap_max_ports = 2
    with pytest.raises(ValueError):
        validate_port_list(settings, [80, 443, 22])


# -- XML parsing --------------------------------------------------------------------


def test_parse_xml_scan_extracts_structured_data():
    parsed = nmap._parse_xml_scan(SAMPLE_XML)
    host = parsed["hosts"][0]
    assert host["status"] == "up"
    assert {"addr": "192.168.1.10", "type": "ipv4", "vendor": None} in host["addresses"]
    assert host["hostnames"][0]["name"] == "printer.local"
    open_port = next(p for p in host["ports"] if p["port"] == 80)
    assert open_port["state"] == "open"
    assert open_port["service"]["product"] == "nginx"
    assert open_port["service"]["method"] == "probe"
    closed_port = next(p for p in host["ports"] if p["port"] == 22)
    assert closed_port["service"]["method"] == "table"  # table guess, not probe
    assert host["os_matches"][0]["name"] == "Linux 5.x"
    assert host["os_matches"][0]["osclasses"][0]["osfamily"] == "Linux"


def test_parse_xml_invalid_is_reported_not_raised():
    parsed = nmap._parse_xml_scan("not xml at all <")
    assert "parse_error" in parsed


# -- privilege degradation --------------------------------------------------------------


def test_os_detect_reports_missing_privileges(settings, monkeypatch):
    def fake_run(args, timeout):
        return "", "TCP/IP fingerprinting (for OS scan) requires root privileges.\nQUITTING!", 1, False

    monkeypatch.setattr(nmap, "_run_nmap", fake_run)
    result = os_detect(settings, "192.168.1.10")
    assert result["ok"] is False
    assert result["capability_required"]
    assert result["degraded"] is True
    assert result["alternatives"]  # unprivileged alternatives listed
    assert "hint" in result


def test_os_detect_success_path(settings, monkeypatch):
    def fake_run(args, timeout):
        return SAMPLE_XML, "", 0, False

    monkeypatch.setattr(nmap, "_run_nmap", fake_run)
    result = os_detect(settings, "192.168.1.10", ports=[80, 443])
    assert result["ok"] is True
    assert result["os_matches"][0]["osclasses"][0]["osfamily"] == "Linux"
    assert "capability_required" not in result


def test_service_scan_success(settings, monkeypatch):
    def fake_run(args, timeout):
        return SAMPLE_XML, "", 0, False

    monkeypatch.setattr(nmap, "_run_nmap", fake_run)
    result = port_service_scan(settings, "192.168.1.10", ports=[80, 22])
    assert result["ok"] is True
    assert result["ports_requested"] == [22, 80]  # sorted
    open_ports = [p["port"] for h in result["hosts"] for p in h["ports"] if p["state"] == "open"]
    assert open_ports == [80]


def test_service_scan_timeout_reported(settings, monkeypatch):
    def fake_run(args, timeout):
        return "", "", -1, True

    monkeypatch.setattr(nmap, "_run_nmap", fake_run)
    result = port_service_scan(settings, "192.168.1.10")
    assert result["ok"] is False
    assert "timed out" in result["error"]


# -- registry: no feature gates, only prerequisites ---------------------------------------


def test_registry_enabled_without_feature_flags(settings):
    from netagent.agent.tools import build_registry

    registry = build_registry(settings)
    # scope-only policy: tools report availability from prerequisites alone
    assert registry["nmap_discovery"].available(settings) is True  # nmap installed here
    assert registry["arp_scan"].available(settings) is True
    assert registry["ping"].available(settings) is True


def test_registry_reports_missing_binary(settings):
    from netagent.agent.tools import build_registry

    settings.__dict__["_nmap_missing"] = None  # no-op, keep settings intact
    registry = build_registry(settings)
    # simulate missing binary via monkeypatched availability
    import netagent.agent.tools as tools_mod

    monkey_marker = lambda s: False  # noqa: E731
    registry["pcap_summary"].available = monkey_marker
    result = tools_mod.execute_tool(
        registry, None, settings, "pcap_summary", {"path": "/tmp/x.pcap"}
    )
    assert result["ok"] is False
    assert result.get("unavailable") is True
