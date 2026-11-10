"""Offline capture tests, including real TShark execution without network IO."""
import struct
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from netagent.agent.tools import build_registry, execute_tool
from netagent.collectors import tshark


@pytest.fixture
def capture(tmp_path):
    p = tmp_path / "sample.pcap"
    # Ethernet + IPv4 + UDP with no payload, TEST-NET source/destination.
    packet = bytes.fromhex("00112233445566778899aabb08004500001c0000000040110000c0000201c000020204d210e100080000")
    p.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet)
    return p


def test_real_registry_pcap_execution(settings, db, capture):
    if not Path(tshark.TSHARK_BINARY).is_file():
        pytest.skip("TShark executable is unavailable")
    settings.monitor_cidrs = settings.authorized_targets = ""
    settings.pcap_allowed_dirs = str(capture.parent)
    result = execute_tool(build_registry(settings), db, settings, "pcap_summary", {"path": str(capture)})
    assert result["ok"], result
    assert any("udp" in line.lower() for line in result["protocol_hierarchy"]["excerpt"])
    assert any("192.0.2.1" in line for line in result["ip_endpoints"]["excerpt"])
    assert result["size_bytes"] == capture.stat().st_size


@pytest.mark.parametrize("kind", ["unset", "outside", "symlink", "missing", "extension", "directory", "oversize"])
def test_invalid_capture_cannot_execute(capture, tmp_path, monkeypatch, kind):
    run = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr(tshark.subprocess, "run", run)
    roots = [tmp_path]
    path = capture
    if kind == "unset": roots = []
    elif kind == "outside": roots = [tmp_path / "allowed"]
    elif kind == "symlink":
        folder = tmp_path / "allowed"
        folder.mkdir()
        path = folder / "link.pcap"
        path.symlink_to(capture)
        roots = [folder]
    elif kind == "missing": path = tmp_path / "missing.pcap"
    elif kind == "extension": path = tmp_path / "secret.txt"
    elif kind == "directory":
        path = tmp_path / "folder.pcap"
        path.mkdir()
    else: monkeypatch.setattr(tshark, "MAX_PCAP_BYTES", 1)
    with pytest.raises(tshark.PcapInvalid):
        tshark.analyze_pcap(path, allowed_roots=roots)
    run.assert_not_called()


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("tshark", 1), FileNotFoundError(), tshark.PcapInvalid("bad capture")])
def test_tshark_error_is_not_success(capture, monkeypatch, error):
    monkeypatch.setattr(tshark, "_run_tshark", Mock(side_effect=error))
    result = tshark.analyze_pcap(capture, allowed_roots=[capture.parent])
    assert result["ok"] is False
    assert result["error"]
