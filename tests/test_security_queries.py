"""Security filtering covers persisted events before bounded pagination."""
import pytest

from tests.conftest import admin_headers
from tests.test_security_ai_controls import ingest, request


def test_search_finds_older_events_and_treats_wildcards_literally(full_client, db):
    ids = [ingest(db, n) for n in range(1, 65)]
    with db.transaction():
        db._conn.execute("UPDATE alerts SET signature=?,src_ip=? WHERE id=?",
                         ("Unique TLS 100%_rule", "2001:db8::99", ids[0]))
    for term in ("unique tls", "100%_", "2001:db8::99"):
        data = full_client.get("/api/alerts", params={"q": term, "limit": 50},
                               headers=admin_headers()).json()
        assert data["total"] == 1
        assert [r["id"] for r in data["items"]] == [ids[0]]
    assert db.pending_alert_analysis_count() == 0


def test_status_filters_include_durable_intake_and_count_before_pagination(full_client, db):
    untouched = ingest(db, 1)
    manual = ingest(db, 2)
    request(db, manual)
    db.set_security_ai_auto(True, actor="test")
    intake = ingest(db, 3)
    db.set_security_ai_auto(False, actor="test")
    expected = {"PENDING": {manual, intake}, "none": {untouched}, "FAILED": set()}
    for status, ids in expected.items():
        data = full_client.get("/api/alerts", params={"analysis_status": status, "limit": 1},
                               headers=admin_headers()).json()
        assert data["total"] == len(ids)
        assert {r["id"] for r in data["items"]} <= ids
    assert db.get_alert_analysis(intake)["origin"] == "automatic"
    assert db.pending_alert_analysis_count() == 2


def test_grouped_results_and_severity_summary_respect_all_filters(full_client, db):
    a, b = ingest(db, 1, severity=1), ingest(db, 2, severity=4)
    with db.transaction():
        db._conn.execute("UPDATE alerts SET signature='target rule' WHERE id IN (?,?)", (a, b))
    data = full_client.get("/api/alerts", params={"q": "target", "severity": 1,
                           "group_by_flow": True, "include_summary": True}, headers=admin_headers()).json()
    assert data["total"] == 1
    assert data["grouped_by_flow_and_rule"][0]["severity"] == 1
    assert len(data["grouped_by_flow_and_rule"]) == 1
    assert data["severity_counts"] == [{"severity": 1, "count": 1}]
    assert db.pending_alert_analysis_count() == 0


@pytest.mark.parametrize("params", [{"analysis_status": "invalid"}, {"q": "x" * 201}])
def test_invalid_security_filters_are_rejected(full_client, params):
    assert full_client.get("/api/alerts", params=params, headers=admin_headers()).status_code == 422
