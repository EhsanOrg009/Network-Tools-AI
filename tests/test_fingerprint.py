"""Fingerprint subsystem tests: evidence merging, confidence handling,
observed-vs-inferred distinction, and history persistence."""

from __future__ import annotations

from netagent.collectors.system_info import is_randomized_mac, mac_vendor
from netagent.services.fingerprint import (
    build_fingerprint_record,
    _normalize_os_match,
    _service_family_inference,
)


# -- helpers ------------------------------------------------------------------------


def test_mac_randomization_detection():
    assert is_randomized_mac("06:7e:69:26:ee:1a") is True  # locally administered
    assert is_randomized_mac("d8:96:95:11:22:33") is False  # globally unique (ASUSTek)
    assert is_randomized_mac("nonsense") is None
    assert is_randomized_mac(None) is None


def test_mac_vendor_lookup():
    assert mac_vendor("dc:a6:32:11:22:33") == "Raspberry Pi Trading"
    assert mac_vendor("00:50:56:aa:bb:cc") == "VMware"
    assert mac_vendor("aa:bb:cc:dd:ee:ff") is None  # unknown prefix -> explicit None


# -- OS match normalization -------------------------------------------------------------


def test_normalize_os_match_picks_highest_accuracy():
    matches = [
        {"name": "guess1", "accuracy": "30", "osclasses": [{"osfamily": "Other"}]},
        {"name": "best", "accuracy": "98",
         "osclasses": [{"osfamily": "Linux", "osgen": "5.x", "type": "general purpose"}]},
    ]
    m = _normalize_os_match(matches)
    assert m["os_family"] == "Linux"
    assert m["os_version"] == "5.x"
    assert m["device_type"] == "general purpose"
    assert m["provenance"] == "inferred:nmap_os"


def test_normalize_os_match_none_when_no_matches():
    assert _normalize_os_match([]) is None
    assert _normalize_os_match([{"name": "x", "accuracy": "0", "osclasses": []}]) is None


# -- service-based family inference ----------------------------------------------------------


def test_service_family_inference_windows_rdp():
    hosts = [{"ports": [{"port": 3389, "state": "open",
                         "service": {"name": "ms-wbt-server", "method": "probe"}}]}]
    hint = _service_family_inference(hosts)
    assert hint["os_family"] == "Windows"
    assert hint["provenance"] == "inferred:services"


def test_service_family_inference_ssh_is_neutral():
    hosts = [{"ports": [{"port": 22, "state": "open",
                         "service": {"name": "ssh", "method": "probe"}}]}]
    assert _service_family_inference(hosts) is None  # SSH says nothing about OS


def test_service_family_inference_empty():
    assert _service_family_inference([]) is None


# -- record building: observed vs inferred vs unknown -------------------------------------------


def test_record_full_evidence_high_confidence():
    os_result = {
        "ok": True,
        "os_matches": [{"name": "Linux 5.x", "accuracy": "98",
                        "osclasses": [{"osfamily": "Linux", "osgen": "5.x",
                                       "type": "general purpose", "accuracy": "98"}]}],
    }
    service_result = {
        "ok": True,
        "hosts": [{
            "status": "up",
            "addresses": [{"addr": "192.168.1.10", "type": "ipv4"}],
            "ports": [{"port": 80, "state": "open",
                       "service": {"name": "http", "product": "nginx",
                                   "version": "1.24", "method": "probe"}}],
        }],
    }
    arp_result = {"mac": "d8:96:95:11:22:33", "mac_vendor": "ASUSTek",
                  "mac_randomized": False, "state": "REACHABLE"}
    rdns_result = {"hostname": "desktop.local", "hostname_source": "rdns"}

    record = build_fingerprint_record(
        "192.168.1.10", os_result=os_result, service_result=service_result,
        arp_result=arp_result, rdns_result=rdns_result, availability="up",
    )
    assert record["os_family"] == "Linux"
    assert record["confidence"] == "high"
    assert record["mac"] == "d8:96:95:11:22:33"
    assert record["hostname_source"] == "rdns"
    labels = {ev["kind"]: ev["label"] for ev in record["evidence"]}
    assert labels["arp"] == "observed"
    assert labels["service"] == "observed"
    assert labels["os"] == "inferred"
    assert labels["rdns"] == "observed"
    # rdns is a guess: the record must not claim it as verified
    assert any("حدسی" in ev["text"] for ev in record["evidence"] if ev["kind"] == "rdns")


def test_record_partial_evidence_medium_confidence():
    service_result = {
        "ok": True,
        "hosts": [{
            "status": "up",
            "addresses": [{"addr": "192.168.1.10", "type": "ipv4"}],
            "ports": [{"port": 3389, "state": "open",
                       "service": {"name": "ms-wbt-server", "method": "probe"}}],
        }],
    }
    record = build_fingerprint_record("192.168.1.10", service_result=service_result)
    assert record["os_family"] == "Windows"
    assert record["confidence"] == "medium"
    assert record["os_version"] is None  # never invented
    assert any("حدسی" in ev["text"] for ev in record["evidence"] if ev["kind"] == "os")


def test_record_no_evidence_unknown_confidence():
    record = build_fingerprint_record(
        "192.168.1.99",
        arp_result={"cache_entry": False},
    )
    assert record["os_family"] is None
    assert record["confidence"] == "unknown"
    assert "کافی" in record["confidence_explanation"]
    assert any(ev["label"] == "unknown" for ev in record["evidence"])


def test_record_capability_missing_is_explicit():
    os_result = {"capability_required": "root or cap_net_raw (nmap -O)",
                 "degraded": True}
    record = build_fingerprint_record("192.168.1.10", os_result=os_result)
    kinds = [ev["kind"] for ev in record["evidence"]]
    assert "capability" in kinds
    assert "nmap_os_unavailable" in record["methods"]


def test_record_service_version_table_guess_is_labeled():
    service_result = {
        "ok": True,
        "hosts": [{
            "status": "up",
            "addresses": [{"addr": "192.168.1.10", "type": "ipv4"}],
            "ports": [{"port": 25, "state": "open",
                       "service": {"name": "smtp", "method": "table"}}],
        }],
    }
    record = build_fingerprint_record("192.168.1.10", service_result=service_result)
    assert record["services"][0]["version_source"] == "inferred:port_table"


# -- persistence and history ------------------------------------------------------------------


def test_fingerprint_persisted_and_history(db):
    r1 = build_fingerprint_record(
        "192.168.1.10",
        arp_result={"mac": "d8:96:95:11:22:33", "mac_vendor": "ASUSTek",
                    "mac_randomized": False, "state": "REACHABLE"},
        availability="up",
    )
    db.save_fingerprint(r1)
    latest = db.latest_fingerprint("192.168.1.10")
    assert latest["mac"] == "d8:96:95:11:22:33"
    assert latest["mac_vendor"] == "ASUSTek"
    assert latest["os_family"] is None

    # OS appears later -> change detection
    r2 = build_fingerprint_record(
        "192.168.1.10",
        os_result={"ok": True,
                   "os_matches": [{"name": "Linux 5.x", "accuracy": "98",
                                   "osclasses": [{"osfamily": "Linux",
                                                  "osgen": "5.x", "accuracy": "98"}]}]},
        arp_result={"mac": "d8:96:95:11:22:33", "state": "REACHABLE"},
        availability="up",
    )
    db.save_fingerprint(r2)
    history = db.fingerprint_history("192.168.1.10")
    assert len(history) == 2
    changes = db.fingerprint_changes("192.168.1.10")
    fields = [c["field"] for c in changes["changes"]]
    assert "os_family" in fields
    assert changes["comparisons_available"] is True


def test_fingerprint_changes_insufficient_history(db):
    assert db.fingerprint_changes("192.168.1.77")["comparisons_available"] is False
