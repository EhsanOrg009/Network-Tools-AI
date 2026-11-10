import time

import pytest

from netagent.services.discovery import auto_discovery_eligible_networks, effective_discovery_scope
from netagent.services.agents import ingest_inventory
from netagent.schemas import InventoryRequest
from tests.test_discovery_policy import _seed_agent


def inventory(networks, **kwargs):
    return InventoryRequest(interfaces=[{"name": "eth0", "status": "up", "classification": "physical", "connected_networks": networks}], **kwargs)


@pytest.fixture
def fresh(settings, db):
    settings.auto_discovery_enabled = True
    _seed_agent(db)
    ingest_inventory(db, settings, "agt_disc1", inventory(["172.16.3.0/24"]))
    return settings, db


def test_fresh_observation_is_eligible_and_configured_scope_is_preserved(fresh):
    settings, db = fresh
    assert auto_discovery_eligible_networks(db, settings)[0]["cidr"] == "172.16.3.0/24"
    assert effective_discovery_scope(db, settings)["configured_cidrs"] == ["192.168.1.0/24", "10.0.0.0/8"]


@pytest.mark.parametrize("stale_part", ["observation", "heartbeat", "inventory", "collection"])
def test_stale_source_cannot_authorize(fresh, stale_part):
    settings, db = fresh
    with db.transaction():
        if stale_part == "observation":
            db._conn.execute("UPDATE network_observations SET last_epoch=0")
        elif stale_part == "heartbeat":
            db._conn.execute("UPDATE endpoint_agents SET last_heartbeat_epoch=0")
        elif stale_part == "inventory":
            db._conn.execute("UPDATE endpoint_agents SET latest_inventory_at='2000-01-01T00:00:00+00:00'")
        else:
            ingest_inventory(db, settings, "agt_disc1", inventory(["172.16.3.0/24"], collected_at_epoch=time.time() - 2000))
    assert auto_discovery_eligible_networks(db, settings) == []
    assert db.list_network_observations()  # history is not deleted


def test_revoked_agent_excluded_immediately(fresh):
    settings, db = fresh
    db.revoke_agent("agt_disc1")
    assert auto_discovery_eligible_networks(db, settings) == []


def test_inventory_subnet_change_and_removed_interface(fresh):
    settings, db = fresh
    ingest_inventory(db, settings, "agt_disc1", inventory(["172.16.4.0/24"]))
    assert [r["cidr"] for r in auto_discovery_eligible_networks(db, settings)] == ["172.16.4.0/24"]
    ingest_inventory(db, settings, "agt_disc1", InventoryRequest(interfaces=[]))
    assert auto_discovery_eligible_networks(db, settings) == []


def test_ttl_expiry_and_switch_require_fresh_observation(fresh):
    settings, db = fresh
    settings.agent_heartbeat_timeout_seconds = 3600
    assert auto_discovery_eligible_networks(db, settings, now_epoch=time.time() + 901) == []
    settings.auto_discovery_enabled = False
    assert auto_discovery_eligible_networks(db, settings) == []
    settings.auto_discovery_enabled = True
    assert len(auto_discovery_eligible_networks(db, settings)) == 1
