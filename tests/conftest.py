"""Shared fixtures: temp database, settings, and representative EVE lines."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netagent.config import Settings
from netagent.database import Database

# --- Representative Suricata EVE records (fixed, self-contained) ------------

ALERT_LINE = json.dumps({
    "timestamp": "2026-10-28T13:13:49.700023+0330",
    "flow_id": 1599202068114454,
    "in_iface": "wlo1",
    "event_type": "alert",
    "src_ip": "152.53.87.65",
    "src_port": 8443,
    "dest_ip": "10.233.68.48",
    "dest_port": 52222,
    "proto": "TCP",
    "app_proto": "tls",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2027865,
        "rev": 4,
        "signature": "ET INFO Observed DNS Query to Uncommon Domain",
        "category": "Potential Corporate Privacy Violation",
        "severity": 2,
        "metadata": {"created_at": ["2020_07_30"], "updated_at": ["2024_11_08"]},
    },
    "app_proto_tc": "tls",
    "flow": {"pkts_toserver": 5, "pkts_toclient": 4},
}, separators=(",", ":"))

DNS_LINE = json.dumps({
    "timestamp": "2026-10-28T13:13:48.100000+0330",
    "flow_id": 111,
    "event_type": "dns",
    "src_ip": "10.233.68.48",
    "src_port": 53311,
    "dest_ip": "192.168.1.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "type": "query",
        "id": 1234,
        "rrname": "example.example.org",
        "rrtype": "A",
    },
}, separators=(",", ":"))

TLS_LINE = json.dumps({
    "timestamp": "2026-10-28T13:13:49.000000+0330",
    "flow_id": 1599202068114454,
    "event_type": "tls",
    "src_ip": "10.233.68.48",
    "dest_ip": "152.53.87.65",
    "dest_port": 8443,
    "proto": "TCP",
    "tls": {"sni": "uncommon.example.org", "version": "TLS 1.3"},
}, separators=(",", ":"))

FLOW_LINE = json.dumps({
    "timestamp": "2026-10-28T13:14:00.000000+0330",
    "flow_id": 111,
    "event_type": "flow",
    "src_ip": "10.233.68.48",
    "src_port": 53311,
    "dest_ip": "192.168.1.1",
    "dest_port": 53,
    "proto": "UDP",
    "flow": {"pkts_toserver": 2, "pkts_toclient": 2, "bytes_toserver": 120},
}, separators=(",", ":"))

ANOMALY_LINE = json.dumps({
    "timestamp": "2026-10-28T13:14:10.000000+0330",
    "flow_id": 222,
    "event_type": "anomaly",
    "src_ip": "10.0.0.9",
    "dest_ip": "10.233.68.48",
    "proto": "TCP",
    "anomaly": {"type": "decode", "event": "invalid checksum"},
}, separators=(",", ":"))

STATS_LINE = json.dumps({
    "timestamp": "2026-10-28T13:15:00.000000+0330",
    "event_type": "stats",
    "stats": {"capture": {"kernel_packets": 100}, "detector": {"alerts": 1}},
}, separators=(",", ":"))


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "test.sqlite3",
        suricata_eve_path=tmp_path / "eve.json",
        enable_monitor=False,
        monitor_cidrs="192.168.1.0/24,10.0.0.0/8",
        authorized_targets="",
        allowed_tcp_ports="80,443",
        llm_enabled=False,
        _env_file=None,
    )


@pytest.fixture()
def db(settings: Settings) -> Database:
    database = Database(settings.database_path)
    yield database
    database.close()


@pytest.fixture()
def client(settings, db, monkeypatch):
    """TestClient for the real app factory (monitor disabled)."""
    from fastapi.testclient import TestClient

    from netagent.main import create_app

    settings.enable_monitor = False
    app = create_app(settings, start_monitor=False)
    # replace app-owned db with the fixture-owned one (auto-closed by fixture)
    app.state.db = db
    with TestClient(app) as c:
        yield c


# --- agent/admin/console test scaffolding (v3) -------------------------------

ADMIN_TOKEN = "unit-admin-token-0123456789abcdef"
SIGNING_KEY = "unit-task-signing-secret"


@pytest.fixture()
def secure_settings(settings: Settings) -> Settings:
    """Settings with the admin control plane + console enabled for tests."""
    settings.admin_api_token = ADMIN_TOKEN
    settings.task_signing_key = SIGNING_KEY
    settings.allow_admin_python_exec = True
    settings.allow_admin_python_console = True
    settings.agent_enrollment_token = ""
    return settings


def agent_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def make_client(database: Database, app_settings: Settings):
    from fastapi.testclient import TestClient

    from netagent.main import create_app

    app_settings.enable_monitor = False
    app = create_app(app_settings, start_monitor=False)
    app.state.db = database
    return TestClient(app)


def admin_headers(actor: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    if actor:
        h["X-Admin-Actor"] = actor
    return h


@pytest.fixture()
def full_client(secure_settings, db) -> "TestClient":  # type: ignore[name-defined]
    c = make_client(db, secure_settings)
    yield c
    c.close()


def enroll(client, *, capabilities=("inventory",), token: str | None = None,
           hostname: str = "ws-test") -> tuple[str, str]:
    """Enroll via the agent API; returns (agent_id, agent_token).

    Without an explicit ``token`` a real one-time enrollment token is minted
    through the admin API, exercising the full admin→agent identity chain."""
    if token is None:
        r = client.post("/api/admin/v1/enrollment-tokens",
                        json={"ttl_minutes": 5},
                        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        assert r.status_code == 200, r.text
        token = r.json()["token"]
    r = client.post("/api/agent/v1/enroll", json={
        "enrollment_token": token,
        "hostname": hostname,
        "platform": {"os_family": "Linux", "os_name": "Ubuntu", "os_version": "1",
                     "kernel": "#1", "arch": "x86_64"},
        "agent_version": "1.0.0",
        "capabilities": list(capabilities),
        "claimed_ips": ["192.168.1.10"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    return body["agent_id"], body["agent_token"]


def claim_over_http(client, a_token: str, cap="inventory"):
    """Poll via the real HTTP endpoint (capabilities come from the agent row)."""
    r = client.get("/api/agent/v1/tasks/next", headers=agent_headers(a_token))
    assert r.status_code == 200, r.text
    return r.json().get("task")
