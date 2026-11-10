"""Optional offline PCAP metadata analysis with tshark.

- Only explicitly configured/requested files are analyzed; no live capture.
- Nothing is uploaded anywhere; analysis is local.
- Output is bounded; only metadata (endpoints, protocols, ports) is extracted.
"""

from __future__ import annotations

import os
import subprocess
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

TSHARK_BINARY = "/usr/bin/tshark"
MAX_PCAP_BYTES = 200 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024
ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}


class PcapInvalid(ValueError):
    pass


def validate_pcap_path(path: str | os.PathLike[str], *, allowed_roots=()) -> Path:
    p = Path(path).expanduser().resolve()
    _authorize_path(p, allowed_roots)
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


def _authorize_path(path: Path, allowed_roots) -> None:
    if not any(path.is_relative_to(Path(root).expanduser().resolve()) for root in allowed_roots):
        raise PcapInvalid("capture path is outside PCAP_ALLOWED_DIRS")


def _run_tshark(args: list[str], timeout: int) -> str:
    from netagent.services.job_control import bounded_timeout
    proc = subprocess.run(  # noqa: S603 - fixed args, validated path, no shell
        [TSHARK_BINARY, *args],
        capture_output=True,
        timeout=bounded_timeout(timeout),
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")[:300]
        raise PcapInvalid(f"tshark failed: {err}")
    return proc.stdout[:MAX_TEXT_BYTES].decode("utf-8", "replace")


def analyze_pcap(path: str | os.PathLike[str], timeout: int = 60, *, allowed_roots=()) -> dict[str, Any]:
    """Extract bounded metadata: protocol hierarchy, IP endpoints, time range."""
    p = validate_pcap_path(path, allowed_roots=allowed_roots)
    started = time.monotonic()
    try:
        # Analyze a private bounded snapshot, so replacement/truncation of the
        # source during the three commands cannot change what is read.
        with tempfile.TemporaryDirectory(prefix="netagent-pcap-") as directory:
            snapshot = Path(directory) / "capture.pcap"
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(p, flags), "rb") as source:
                opened = os.fstat(source.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_PCAP_BYTES:
                    raise PcapInvalid("capture is not a bounded regular file")
                fd_path = Path(f"/proc/self/fd/{source.fileno()}")
                if fd_path.exists():
                    _authorize_path(fd_path.resolve(), allowed_roots)
                elif not os.path.samestat(opened, p.stat()):
                    raise PcapInvalid("capture changed while opening")
                size = 0
                with snapshot.open("wb") as dest:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_PCAP_BYTES:
                            raise PcapInvalid("capture grew beyond size limit")
                        dest.write(chunk)
            phs = _run_tshark(["-n", "-r", str(snapshot), "-q", "-z", "io,phs"], timeout)
            endpoints = _run_tshark(["-n", "-r", str(snapshot), "-q", "-z", "endpoints,ip"], timeout)
            convs = _run_tshark(["-n", "-r", str(snapshot), "-q", "-z", "conv,tcp"], timeout)
    except subprocess.TimeoutExpired:
        return {"tool": "tshark", "file": str(p), "ok": False,
                "error": "tshark timed out"}
    except FileNotFoundError:
        return {"tool": "tshark", "file": str(p), "ok": False,
                "error": "tshark binary not available"}
    except (OSError, PcapInvalid) as exc:
        return {"tool": "tshark", "file": str(p), "ok": False, "error": str(exc)[:300]}

    def _section(text: str) -> dict[str, Any]:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return {"excerpt": lines[:60], "line_count": len(lines)}

    return {
        "tool": "tshark",
        "file": str(p),
        "size_bytes": size,
        "ok": True,
        "protocol_hierarchy": _section(phs),
        "ip_endpoints": _section(endpoints),
        "tcp_conversations": _section(convs),
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "note": "تحلیل آفلاین و محلی؛ هیچ داده‌ای به سرویس بیرونی ارسال نمی‌شود",
    }
