"""Optional offline PCAP metadata analysis with tshark.

- Only explicitly configured/requested files are analyzed; no live capture.
- Nothing is uploaded anywhere; analysis is local.
- Output is bounded; only metadata (endpoints, protocols, ports) is extracted.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

TSHARK_BINARY = "/usr/bin/tshark"
MAX_PCAP_BYTES = 200 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024
ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}


class PcapInvalid(ValueError):
    pass


def validate_pcap_path(path: str | os.PathLike[str]) -> Path:
    p = Path(path).expanduser()
    if not p.is_absolute() and not p.exists():
        raise PcapInvalid(f"pcap file not found: {p}")
    if p.suffix.lower() not in ALLOWED_SUFFIXES:
        raise PcapInvalid(
            f"unsupported file type {p.suffix!r}; expected {sorted(ALLOWED_SUFFIXES)}"
        )
    if not p.exists():
        raise PcapInvalid(f"pcap file not found: {p}")
    if not p.is_file():
        raise PcapInvalid(f"not a regular file: {p}")
    size = p.stat().st_size
    if size > MAX_PCAP_BYTES:
        raise PcapInvalid(
            f"pcap too large ({size} bytes > {MAX_PCAP_BYTES})"
        )
    return p


def _run_tshark(args: list[str], timeout: int) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed args, validated path, no shell
        [TSHARK_BINARY, *args],
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")[:300]
        raise PcapInvalid(f"tshark failed: {err}")
    return proc.stdout[:MAX_TEXT_BYTES].decode("utf-8", "replace")


def analyze_pcap(path: str | os.PathLike[str], timeout: int = 60) -> dict[str, Any]:
    """Extract bounded metadata: protocol hierarchy, IP endpoints, time range."""
    p = validate_pcap_path(path)
    started = time.monotonic()
    try:
        phs = _run_tshark(["-r", str(p), "-q", "-z", "io,phs"], timeout)
        endpoints = _run_tshark(["-r", str(p), "-q", "-z", "endpoints,ip"], timeout)
        convs = _run_tshark(["-r", str(p), "-q", "-z", "conv,tcp"], timeout)
    except subprocess.TimeoutExpired:
        return {"tool": "tshark", "file": str(p), "ok": False,
                "error": "tshark timed out"}
    except FileNotFoundError:
        return {"tool": "tshark", "file": str(p), "ok": False,
                "error": "tshark binary not available"}

    def _section(text: str) -> dict[str, Any]:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return {"excerpt": lines[:60], "line_count": len(lines)}

    return {
        "tool": "tshark",
        "file": str(p),
        "size_bytes": p.stat().st_size,
        "ok": True,
        "protocol_hierarchy": _section(phs),
        "ip_endpoints": _section(endpoints),
        "tcp_conversations": _section(convs),
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "note": "تحلیل آفلاین و محلی؛ هیچ داده‌ای به سرویس بیرونی ارسال نمی‌شود",
    }
