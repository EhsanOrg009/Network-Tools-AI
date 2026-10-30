"""API tests using FastAPI TestClient with a temporary database and a fake
LLM. No real network scans and no LLM calls are performed."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netagent.agent.llm_client import LLMUnavailable
from netagent.collectors.suricata import parse_eve_line, store_event
from netagent.main import create_app
from tests.conftest import ALERT_LINE, DNS_LINE, TLS_LINE


@pytest.fixture()
def client(settings, db, monkeypatch):
    settings.enable_monitor = False
    app = create_app(settings, start_monitor=False)
    # replace app-owned db with the fixture-owned one (auto-closed by fixture)
    app.state.db = db
    with TestClient(app) as c:
        yield c


# -- health --------------------------------------------------------------------


def test_health_reports_components(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    comps = body["components"]
    for key in ("database", "suricata", "llm", "monitor_thread", "diagnostics"):
        assert key in comps
    # suricata file in fixture tmp_path does not exist -> explicit status shown
    assert comps["suricata"]["file_exists"] is False
    assert "eve_path" in comps["suricata"]


def test_health_reports_authorized_cidrs(client, settings):
    body = client.get("/health").json()
    diag = body["components"]["diagnostics"]
    assert diag["policy"].startswith("all non-destructive")
    assert "192.168.1.0/24" in str(diag["scope"]["cidrs"])
    assert diag["budget"]["max_tool_calls"] >= 2


# -- events / hosts / alerts ------------------------------------------------------


def _seed(db):
    for line in (ALERT_LINE, DNS_LINE, TLS_LINE):
        ev, _ = parse_eve_line(line)
        store_event(db, ev, line)


def test_list_events_endpoint(client, db):
    _seed(db)
    r = client.get("/api/events")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # raw payload never leaks through the list endpoint
    assert all("raw_json" not in item for item in body["items"])

    r = client.get("/api/events", params={"event_type": "tls"})
    assert r.json()["total"] == 1


def test_list_events_pagination(client, db):
    _seed(db)
    body = client.get("/api/events", params={"limit": 2, "offset": 0}).json()
    assert len(body["items"]) == 2
    body2 = client.get("/api/events", params={"limit": 2, "offset": 2}).json()
    ids1 = {i["id"] for i in body["items"]}
    ids2 = {i["id"] for i in body2["items"]}
    assert ids1.isdisjoint(ids2)


def test_list_alerts_endpoint(client, db):
    _seed(db)
    body = client.get("/api/alerts").json()
    assert body["total"] == 1
    a = body["items"][0]
    assert a["action"] == "allowed"

    body = client.get("/api/alerts", params={"group_by_flow": "true"}).json()
    assert body["grouped_by_flow_and_rule"][0]["hit_count"] == 1

    body = client.get("/api/alerts", params={"severity": 9}).json()
    assert body["total"] == 0


def test_hosts_endpoint(client, db):
    _seed(db)
    body = client.get("/api/hosts").json()
    ips = {h["ip"] for h in body["items"]}
    assert "152.53.87.65" in ips


def test_tools_endpoint_lists_registry(client):
    body = client.get("/api/tools").json()
    names = {t["name"] for t in body["tools"]}
    assert {"ping", "tcp_check", "nmap_discovery", "nmap_services", "nmap_os",
            "suricata_alerts", "suricata_events", "host_history", "host_timeline",
            "host_fingerprint", "fingerprint_history", "arp_info", "route_info",
            "reverse_dns", "pcap_summary", "arp_scan"} <= names
    nmap_tool = next(t for t in body["tools"] if t["name"] == "nmap_discovery")
    assert nmap_tool["available"] is True  # prerequisites satisfied on this machine
    assert body["scope"]["cidrs"]


# -- investigations -----------------------------------------------------------------


def test_create_investigation_without_llm_produces_fallback(client, db):
    _seed(db)
    r = client.post("/api/investigations", json={
        "target_ip": "192.168.1.10",
        "question": "تحلیل کن",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["status"].startswith("completed")
    assert body["report_text"] and "خلاصه" in body["report_text"]
    assert body["report"]["limitations"]


def test_create_investigation_requires_target(client):
    r = client.post("/api/investigations", json={})
    assert r.status_code == 422


def test_investigation_404(client):
    assert client.get("/api/investigations/9999").status_code == 404


def test_investigation_list(client, db):
    _seed(db)
    client.post("/api/investigations", json={"target_ip": "192.168.1.10"})
    body = client.get("/api/investigations").json()
    assert len(body["items"]) >= 1


def test_investigation_with_llm_error_falls_back(client, settings, db):
    class FailingLLM:
        def chat(self, messages, max_tokens=None):
            raise LLMUnavailable("timeout")

    settings.llm_enabled = True
    from netagent.agent.llm_client import LLMClient

    client.app.state.llm = FailingLLM()
    r = client.post("/api/investigations", json={"target_ip": "192.168.1.10"})
    body = r.json()
    assert body["status"] == "completed_fallback"
    assert body["error"]


# -- scans / discovery (scope-gated, no per-tool flags) -----------------------------


def test_scans_out_of_scope_rejected(client, settings):
    r = client.post("/api/scans", json={"tool": "nmap", "target": "8.8.8.8"})
    assert r.status_code == 403
    assert "authorized scope" in r.json()["detail"] or "scope" in r.json()["detail"]


def test_scans_in_scope_authorized_no_feature_flag(client, settings, monkeypatch):
    """With scope configured, no extra feature-flag 403 is returned; the scan
    itself is monkeypatched (tests never run real scans)."""
    from netagent.collectors import nmap as nmap_mod

    def fake_discovery(s, target, extra_networks=None):
        return {"ok": True, "tool": "nmap_discovery", "target": target,
                "hosts": [{"ip": "192.168.1.10", "status": "up"}], "host_count": 1}

    monkeypatch.setattr(nmap_mod, "host_discovery", fake_discovery)
    r = client.post("/api/scans", json={"tool": "nmap", "target": "192.168.1.0/24"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["host_count"] == 1


def test_discover_endpoint_records_hosts(client, db, monkeypatch):
    from netagent.collectors import nmap as nmap_mod

    def fake_discovery(s, target, extra_networks=None):
        return {"ok": True, "tool": "nmap_discovery", "target": target,
                "hosts": [{"ip": "192.168.1.42", "status": "up"}], "host_count": 1}

    monkeypatch.setattr(nmap_mod, "host_discovery", fake_discovery)
    r = client.post("/api/hosts/discover",
                    json={"tool": "nmap", "target": "192.168.1.0/24"})
    assert r.status_code == 200
    assert any(h["ip"] == "192.168.1.42" for h in db.list_hosts())


def test_discover_endpoint_out_of_scope_403(client):
    r = client.post("/api/hosts/discover",
                    json={"tool": "nmap", "target": "203.0.113.0/24"})
    assert r.status_code == 403


def test_direct_tool_invocation_share_validation(client, settings, monkeypatch):
    """POST /api/tools/{name} uses the same validation path as the agent."""
    def fake_discovery(s, target, extra_networks=None):
        return {"ok": True, "tool": "nmap_discovery", "target": target, "hosts": []}

    monkeypatch.setattr("netagent.collectors.nmap.host_discovery", fake_discovery)
    r = client.post("/api/tools/nmap_discovery", json={"target": "192.168.1.0/24"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    r = client.post("/api/tools/nmap_discovery", json={"target": "8.8.8.8"})
    assert r.status_code == 403


# -- fingerprints / timeline ----------------------------------------------------------


def test_fingerprint_endpoint(client, db):
    db.save_fingerprint({
        "ip": "192.168.1.10", "os_family": "Linux", "os_version": None,
        "device_type": None, "hostname": "box.local", "hostname_source": "rdns",
        "mac": "d8:96:95:11:22:33", "mac_vendor": "ASUSTek",
        "open_ports": [80], "services": [{"port": 80, "name": "http"}],
        "protocols": [], "availability": "up", "methods": ["arp_info"],
        "evidence": [{"kind": "arp", "label": "observed", "text": "x"}],
        "confidence": "low", "confidence_explanation": "محدود", "source": "test",
    })
    r = client.get("/api/hosts/192.168.1.10/fingerprint")
    assert r.status_code == 200
    body = r.json()
    assert body["latest"]["os_family"] == "Linux"
    assert body["latest"]["open_ports"] == [80]

    r = client.get("/api/hosts/192.168.1.10/fingerprint", params={"history": "true"})
    assert len(r.json()["history"]) == 1

    assert client.get("/api/hosts/192.168.1.99/fingerprint").status_code == 404


def test_host_timeline_endpoint(client, db):
    _seed(db)
    r = client.get("/api/hosts/152.53.87.65/timeline")
    assert r.status_code == 200
    body = r.json()
    assert body["events"]
    assert client.get("/api/hosts/203.0.113.1/timeline").status_code == 404


def test_host_diagnostics_recorded_by_tools(client, db, monkeypatch):
    """Tool invocations are persisted to diagnostics for later review."""
    def fake_ping(s, host, count=None):
        return {"target": host, "ok": True, "responses": 3}

    monkeypatch.setattr("netagent.collectors.connectivity.ping", fake_ping)
    client.post("/api/tools/ping", json={"host": "127.0.0.1"})
    rows = db.host_diagnostics("127.0.0.1")
    assert any(r["tool"] == "ping" for r in rows)


# -- background jobs ------------------------------------------------------------------


def test_investigation_job_flow(client, db):
    _seed(db)
    r = client.post("/api/jobs/investigation",
                    json={"target_ip": "192.168.1.10", "question": "q"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    # poll until completed (fast: llm disabled -> fallback report)
    import time as _time
    for _ in range(50):
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("completed", "failed"):
            break
        _time.sleep(0.05)
    assert body["status"] == "completed"
    assert body["result"]["status"].startswith("completed")
    assert client.get("/api/jobs/nonexistent").status_code == 404


def test_job_investigation_out_of_scope_403(client):
    r = client.post("/api/jobs/investigation", json={"target_ip": "9.9.9.9"})
    assert r.status_code == 403


def test_ping_endpoint_not_present(client):
    """No arbitrary scan endpoints exist; only the two gated tools."""
    r = client.post("/api/scans", json={"tool": "ping", "target": "8.8.8.8"})
    assert r.status_code == 422  # enum validation rejects unknown tools
