"""Database persistence, filtering, pagination, and grouping tests."""

from __future__ import annotations

import pytest

from netagent.collectors.suricata import parse_eve_line, store_event
from tests.conftest import ALERT_LINE, DNS_LINE, FLOW_LINE, TLS_LINE


def _seed(db):
    for line in (ALERT_LINE, DNS_LINE, TLS_LINE, FLOW_LINE):
        ev, _ = parse_eve_line(line)
        store_event(db, ev, line)


def test_events_persisted_with_normalized_fields(db):
    _seed(db)
    events, total = db.query_events()
    assert total == 4
    types = {e["event_type"] for e in events}
    assert types == {"alert", "dns", "tls", "flow"}


def test_event_filter_by_type_and_ip(db):
    _seed(db)
    events, total = db.query_events(event_type="dns")
    assert total == 1 and events[0]["event_type"] == "dns"

    events, total = db.query_events(ip="10.233.68.48")
    assert total >= 2  # appears as src or dest

    events, total = db.query_events(ip="203.0.113.99")
    assert total == 0


def test_event_pagination(db):
    _seed(db)
    page1, total = db.query_events(limit=2, offset=0)
    page2, _ = db.query_events(limit=2, offset=2)
    assert len(page1) == 2 and len(page2) == 2 and total == 4
    assert {p["id"] for p in page1}.isdisjoint({p["id"] for p in page2})


def test_alert_filters(db):
    _seed(db)
    alerts, total = db.query_alerts(severity=2)
    assert total == 1 and alerts[0]["signature_id"] == 2027865

    alerts, total = db.query_alerts(severity=1)
    assert total == 0

    alerts, total = db.query_alerts(signature_id=2027865)
    assert total == 1

    alerts, total = db.query_alerts(ip="152.53.87.65")
    assert total == 1


def test_alert_flow_summary_groups_duplicates(db):
    """Repeated matches of one rule on one flow count once with hit_count."""
    import json as _json
    rec = _json.loads(ALERT_LINE)
    for i in range(3):
        rec["timestamp"] = f"2026-10-28T13:2{i}:00.000000+0330"
        l2 = _json.dumps(rec, separators=(",", ":"))
        ev, _ = parse_eve_line(l2)
        store_event(db, ev, l2)
    grouped = db.alert_flow_summary()
    assert len(grouped) == 1
    assert grouped[0]["hit_count"] == 3
    assert grouped[0]["flow_id"] == 1599202068114454


def test_hosts_upsert_and_list(db):
    _seed(db)
    hosts = {h["ip"] for h in db.list_hosts()}
    assert "152.53.87.65" in hosts and "10.233.68.48" in hosts
    db.upsert_host("10.233.68.48", hostname="laptop.local")
    host = db.get_host("10.233.68.48")
    assert host["hostname"] == "laptop.local"


def test_observations_and_host_history(db):
    db.record_observation("10.233.68.48", "ping", True, {"latency_ms": 3.2})
    db.record_observation("10.233.68.48", "tcp", False, {"port": 443, "error": "refused"})
    obs = db.host_observations("10.233.68.48")
    assert len(obs) == 2
    assert obs[0]["detail"]["port"] == 443

    _seed(db)
    summary = db.host_event_summary("10.233.68.48")
    assert "event_counts_24h" in summary


def test_investigation_lifecycle(db):
    inv_id = db.create_investigation("host", "10.0.0.5", None, {"k": "v"})
    rec = db.get_investigation(inv_id)
    assert rec["status"] == "running"
    db.finish_investigation(
        inv_id, status="completed", report={"summary": "s"},
        report_text="text", confidence="low", iterations=2,
    )
    rec = db.get_investigation(inv_id)
    assert rec["status"] == "completed"
    assert rec["report"]["summary"] == "s"
    assert len(db.list_investigations()) == 1


def test_meta_roundtrip(db):
    assert db.get_meta("missing") is None
    db.set_meta("eve_tailer_state", '{"inode": 1, "offset": 42}')
    assert db.get_meta("eve_tailer_state") == '{"inode": 1, "offset": 42}'
