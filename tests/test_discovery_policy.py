"""Automatic network discovery policy tests: classification, eligibility, scope.

Pure policy tests — no scans are executed anywhere. Subnet observations are
seeded directly in the temporary database through the same helpers the agent
inventory path uses.
"""

from __future__ import annotations

from netagent.config import Settings
from netagent.database import Database
from netagent.services.discovery import (
    auto_discovery_eligible_networks,
    classify_cidr,
    effective_discovery_scope,
    is_auto_discovery_target_authorized,
)

from tests.conftest import make_client, admin_headers  # noqa: F401


def _seed_agent(db: Database, agent_id: str = "agt_disc1") -> None:
    db.create_agent(agent_id=agent_id, token_hash=f"x{agent_id}".ljust(64, "0"),
                    hostname=f"ws-{agent_id[-3:]}", platform="Linux",
                    agent_version="1.0.0", origin="test",
                    heartbeat_interval=30, capabilities=["inventory"])


def _observe(db: Database, agent_id: str, cidr: str, iface: str = "eth0",
             classification: str = "physical", connected: bool = True) -> None:
    inventory = (db.get_latest_inventory(agent_id) or {}).get("inventory") or {"interfaces": []}
    current = next((i for i in inventory["interfaces"] if i["name"] == iface), None)
    if current is None:
        current = {"name": iface, "status": "up" if connected else "down", "classification": classification, "connected_networks": []}
        inventory["interfaces"].append(current)
    current["connected_networks"].append(cidr)
    db.store_inventory(agent_id, inventory)
    db.record_network_observations(agent_id, [{
        "interface": iface, "cidr": cidr,
        "classification": classification, "connected": connected,
    }])


# -- classification -----------------------------------------------------------------


def test_classify_cidr():
    assert classify_cidr("127.0.0.0/8") == "loopback"
    assert classify_cidr("169.254.0.0/16") == "link_local"
    assert classify_cidr("8.8.8.0/24") == "public"
    assert classify_cidr("192.168.1.0/24") == "private"
    assert classify_cidr("10.0.0.0/8") == "private"
    assert classify_cidr("224.0.0.0/4") == "other"
    assert classify_cidr("garbage") == "invalid"


# -- eligibility -----------------------------------------------------------------------


def test_auto_discovery_disabled_means_empty(full_client, settings, db):
    _seed_agent(db)
    _observe(db, "agt_disc1", "192.168.1.0/24")
    assert settings.auto_discovery_enabled is False
    assert auto_discovery_eligible_networks(db, settings) == []


def test_private_directly_connected_subnet_eligible(settings, db):
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    _observe(db, "agt_disc1", "192.168.1.0/24", iface="wlan0", classification="unknown")
    eligible = auto_discovery_eligible_networks(db, settings)
    assert [e["cidr"] for e in eligible] == ["192.168.1.0/24"]
    entry = eligible[0]
    assert entry["classification"] == "private"
    assert "agt_disc1" in entry["reporting_agents"]
    assert entry["origin"] == "auto-discovery"
    assert entry["justification"]  # every decision records why


def test_public_loopback_linklocal_never_eligible(settings, db):
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    for cidr in ("8.8.8.0/24", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"):
        _observe(db, "agt_disc1", cidr)
    assert auto_discovery_eligible_networks(db, settings) == []


def test_virtual_vpn_disconnected_interfaces_not_reporters(settings, db):
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    _observe(db, "agt_disc1", "192.168.1.0/24", iface="docker0", classification="virtual")
    _observe(db, "agt_disc1", "192.168.2.0/24", iface="tun0", classification="vpn")
    _observe(db, "agt_disc1", "192.168.3.0/24", iface="eth1", connected=False)
    assert auto_discovery_eligible_networks(db, settings) == []


def test_min_reporters_required(settings, db):
    settings.auto_discovery_enabled = True
    settings.auto_discovery_min_reporters = 2
    _seed_agent(db, "agt_a")
    _observe(db, "agt_a", "192.168.1.0/24")
    assert auto_discovery_eligible_networks(db, settings) == []
    # a second agent agreeing promotes the subnet
    _seed_agent(db, "agt_b")
    _observe(db, "agt_b", "192.168.1.0/24")
    eligible = auto_discovery_eligible_networks(db, settings)
    assert [e["cidr"] for e in eligible] == ["192.168.1.0/24"]
    assert set(eligible[0]["reporting_agents"]) == {"agt_a", "agt_b"}


def test_subnet_size_cap(settings, db):
    settings.auto_discovery_enabled = True
    settings.auto_discovery_max_addresses = 512
    _seed_agent(db)
    _observe(db, "agt_disc1", "10.0.0.0/16")  # 65536 addresses
    assert auto_discovery_eligible_networks(db, settings) == []


def test_exclusion_cidrs(settings, db):
    settings.auto_discovery_enabled = True
    settings.discovery_excluded_cidrs = "192.168.99.0/24"
    _seed_agent(db)
    _observe(db, "agt_disc1", "192.168.99.0/24")
    _observe(db, "agt_disc1", "192.168.1.0/24")
    eligible = auto_discovery_eligible_networks(db, settings)
    assert [e["cidr"] for e in eligible] == ["192.168.1.0/24"]


def test_excluded_interface_names_do_not_report(settings, db):
    settings.auto_discovery_enabled = True
    settings.discovery_excluded_interfaces = "wlo1"
    _seed_agent(db)
    _observe(db, "agt_disc1", "192.168.1.0/24", iface="wlo1")
    assert auto_discovery_eligible_networks(db, settings) == []


# -- scope semantics -------------------------------------------------------------------


def test_effective_scope_extends_never_replaces(settings, db):
    settings.monitor_cidrs = "192.168.1.0/24"
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    _observe(db, "agt_disc1", "172.16.47.0/24")  # auto-discovered, NOT configured
    scope = effective_discovery_scope(db, settings)
    assert "192.168.1.0/24" in scope["configured_cidrs"]
    assert "172.16.47.0/24" in [e["cidr"] for e in scope["auto_discovered"]]
    assert "172.16.47.0/24" not in scope["configured_cidrs"]
    # the note states that auto-discovery extends, never replaces, MONITOR_CIDRS
    assert "نمی‌گیرد" in scope["note"] and "گسترش" in scope["note"]


def test_authorized_target_question_configured_first(settings, db):
    settings.monitor_cidrs = "192.168.1.0/24"
    settings.auto_discovery_enabled = False
    _seed_agent(db)
    _observe(db, "agt_disc1", "172.16.47.0/24")
    # configured scope answers True even with discovery disabled
    assert is_auto_discovery_target_authorized(db, settings, "192.168.1.10/24") is True
    # auto-discovered-only range is NOT authorized while the feature is off
    assert is_auto_discovery_target_authorized(db, settings, "172.16.47.5/24") is False
    # after enabling, the same range becomes authorized (extends scope)
    settings.auto_discovery_enabled = True
    assert is_auto_discovery_target_authorized(db, settings, "172.16.47.5/24") is True
    # loopback stays forbidden no matter what an agent reported
    assert is_auto_discovery_target_authorized(db, settings, "127.0.0.1/24") is False
    # garbage targets never authorized
    assert is_auto_discovery_target_authorized(db, settings, "not-a-target") is False


def test_public_never_authorized_even_if_reported(settings, db):
    """No single agent can make a public range scannable by reporting it."""
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    _observe(db, "agt_disc1", "8.8.8.0/24")
    assert is_auto_discovery_target_authorized(db, settings, "8.8.8.8/32") is False


# -- end-to-end through the API (scope used by the scan endpoints) ----------------------


def test_scan_endpoint_rejects_public_target(full_client):
    r = full_client.post("/api/scans", json={"tool": "nmap", "target": "8.8.8.0/24"}, headers=admin_headers())
    assert r.status_code == 403


def test_admin_networks_endpoint_exposes_scope(full_client):
    r = full_client.get("/api/admin/v1/networks", headers=admin_headers())
    assert r.status_code == 200
