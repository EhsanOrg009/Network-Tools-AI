import json
import sqlite3

import pytest

from netagent.collectors.suricata import EveTailer, parse_eve_line, store_event
from netagent.services.monitoring import META_KEY, Monitor
from tests.conftest import ALERT_LINE, DNS_LINE, TLS_LINE


def append(path, *lines):
    with path.open("a") as stream:
        stream.write("\n".join(lines) + "\n")


def test_events_appended_during_shutdown_are_recovered(settings, db):
    append(settings.suricata_eve_path, DNS_LINE, TLS_LINE)
    first = Monitor(db, settings)
    assert first.poll_once()["ingested"] == 2
    first.stop()
    append(settings.suricata_eve_path, ALERT_LINE, DNS_LINE)
    second = Monitor(db, settings)
    assert second.poll_once()["ingested"] == 1
    assert second.duplicates_skipped == 1
    assert db.query_events()[1] == 3
    assert db.query_alerts()[1] == 1
    second.stop()


@pytest.mark.parametrize("failure", ["event", "alert", "cursor"])
@pytest.mark.parametrize("restart", [False, True])
def test_store_failure_never_advances_cursor(settings, db, monkeypatch, failure, restart):
    append(settings.suricata_eve_path, DNS_LINE)
    monitor = Monitor(db, settings)
    assert monitor.poll_once()["ok"]
    before = db.get_meta(META_KEY)
    append(settings.suricata_eve_path, TLS_LINE, ALERT_LINE)
    name = {"event": "insert_event", "alert": "insert_alert", "cursor": "set_meta"}[failure]
    original = getattr(db, name)
    def fail(*a, **k):
        raise sqlite3.OperationalError("simulated disk full")
    monkeypatch.setattr(db, name, fail)
    assert monitor.poll_once()["ok"] is False
    assert db.get_meta(META_KEY) == before
    assert db.query_events()[1] == 1
    assert db.query_alerts()[1] == 0
    monkeypatch.setattr(db, name, original)
    if restart:
        monitor.stop()
        monitor = Monitor(db, settings)
    assert monitor.poll_once()["ingested"] == 2
    assert db.query_events()[1] == 3
    assert db.query_alerts()[1] == 1
    monitor.stop()


@pytest.mark.parametrize("restart", [False, True])
def test_rotation_drains_old_file_before_new_file(settings, db, restart):
    path = settings.suricata_eve_path
    append(path, DNS_LINE)
    monitor = Monitor(db, settings)
    assert monitor.poll_once()["ingested"] == 1
    if restart:
        monitor.stop()
    rotated = path.with_name("eve.json.1")
    path.rename(rotated)
    append(rotated, TLS_LINE)
    append(path, ALERT_LINE)
    if restart:
        monitor = Monitor(db, settings)
    assert monitor.poll_once()["ingested"] == 1
    assert monitor.poll_once()["ingested"] == 1
    assert db.query_events()[1] == 3
    monitor.stop()


@pytest.mark.parametrize("grow_past_offset", [False, True])
def test_copytruncate_recovers_from_beginning(settings, db, grow_past_offset):
    path = settings.suricata_eve_path
    append(path, DNS_LINE)
    monitor = Monitor(db, settings)
    monitor.poll_once()
    replacement = '{"event_type":"flow","flow_id":77}'
    if grow_past_offset:
        replacement += "\n" + ALERT_LINE
    path.write_text(replacement + "\n")
    assert monitor.poll_once()["ingested"] == (2 if grow_past_offset else 1)
    monitor.stop()


def test_pending_batch_is_replayed_until_acknowledged(tmp_path):
    path = tmp_path / "eve.json"
    append(path, DNS_LINE)
    persisted = []
    tailer = EveTailer(path, state_writer=persisted.append)
    first = tailer.poll()
    assert tailer.poll() is first
    assert persisted == [] and tailer.state() is None
    tailer.acknowledge()
    assert persisted[0]["offset"] == path.stat().st_size
    assert tailer.poll().events == []
    tailer.close()


def test_partial_write_and_malformed_record(settings, db):
    path = settings.suricata_eve_path
    append(path, '{"event_type": []}', "{broken", DNS_LINE)
    with path.open("a") as stream:
        stream.write(ALERT_LINE[:50])
    monitor = Monitor(db, settings)
    result = monitor.poll_once()
    assert result["malformed"] == 2 and result["ingested"] == 1
    cursor = json.loads(db.get_meta(META_KEY))
    assert cursor["offset"] == path.stat().st_size - 50
    with path.open("a") as stream:
        stream.write(ALERT_LINE[50:] + "\n")
    assert monitor.poll_once()["ingested"] == 1
    assert db.query_alerts()[1] == 1
    monitor.stop()


def test_store_event_atomic_outside_monitor(db, monkeypatch):
    def fail(*a, **k):
        raise sqlite3.OperationalError("disk error")
    monkeypatch.setattr(db, "insert_alert", fail)
    event, _ = parse_eve_line(ALERT_LINE)
    with pytest.raises(sqlite3.OperationalError):
        store_event(db, event, ALERT_LINE)
    assert db.query_events()[1] == 0


def test_missing_rotated_inode_is_visible(settings, db):
    path = settings.suricata_eve_path
    append(path, DNS_LINE)
    monitor = Monitor(db, settings)
    monitor.poll_once()
    monitor.stop()
    path.rename(path.with_name("unrecoverable-name"))
    append(path, ALERT_LINE)
    monitor = Monitor(db, settings)
    assert monitor.poll_once()["ingested"] == 1
    assert "cannot be recovered" in monitor.last_error
    monitor.stop()


def test_commit_failure_retains_pending_batch(settings, db, monkeypatch):
    append(settings.suricata_eve_path, ALERT_LINE)
    original = db._conn
    class FailingCommit:
        def __getattr__(self, name):
            return getattr(original, name)
        def commit(self):
            raise sqlite3.OperationalError("simulated commit failure")
    monitor = Monitor(db, settings)
    monkeypatch.setattr(db, "_conn", FailingCommit())
    assert monitor.poll_once()["ok"] is False
    assert db.query_events()[1] == 0 and db.get_meta(META_KEY) is None
    monkeypatch.setattr(db, "_conn", original)
    assert monitor.poll_once()["ingested"] == 1
    monitor.stop()


def test_process_crash_before_commit_recovers(settings, db):
    import subprocess
    append(settings.suricata_eve_path, DNS_LINE)
    monitor = Monitor(db, settings)
    monitor.poll_once()
    monitor.stop()
    before = db.get_meta(META_KEY)
    append(settings.suricata_eve_path, ALERT_LINE)
    program = """
import os, sys
from netagent.database import Database
from netagent.collectors.suricata import parse_eve_line, store_event
db = Database(sys.argv[1])
with db.transaction():
    event, _ = parse_eve_line(sys.argv[2])
    store_event(db, event, sys.argv[2])
    db.set_meta('eve_tailer_state', '{}')
    os._exit(99)
"""
    process = subprocess.run(["uv", "run", "python", "-c", program, str(db.path), ALERT_LINE], timeout=30)
    assert process.returncode == 99
    assert db.get_meta(META_KEY) == before
    assert db.query_events()[1] == 1
    monitor = Monitor(db, settings)
    assert monitor.poll_once()["ingested"] == 1
    monitor.stop()
