"""Validated subprocess wrappers: ping and TCP connectivity checks."""

from __future__ import annotations

import re
import socket
import subprocess
import time
from typing import Any

from netagent.config import Settings

# Hostnames/IPs only. Rejects anything that could be interpreted as an option
# (leading dash), spaces, shell metacharacters, etc.
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,250}[A-Za-z0-9])?$")


def validate_host(host: str) -> str:
    """Return the validated host, or raise ValueError for unsafe input."""
    host = (host or "").strip()
    if not host or len(host) > 253 or not _HOST_RE.match(host):
        raise ValueError(f"unsafe or invalid host: {host[:64]!r}")
    return host


def ping(
    settings: Settings,
    host: str,
    count: int | None = None,
) -> dict[str, Any]:
    """ICMP reachability check with a small, fixed number of requests.

    A failed ping is NOT proof that a device is offline (ICMP may be dropped
    by firewalls); the caller must treat this as weak evidence.
    """
    host = validate_host(host)
    count = count or settings.ping_count
    count = max(1, min(int(count), settings.ping_count))
    timeout = settings.ping_timeout_seconds
    cmd = [
        "/usr/bin/ping" if _exists("/usr/bin/ping") else "ping",
        "-c", str(count),
        "-W", str(timeout),
        host,
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            cmd,
            capture_output=True,
            timeout=timeout * count + 5,
        )
    except subprocess.TimeoutExpired:
        return {"target": host, "attempts": count, "responses": 0,
                "latency_ms": None, "packet_loss_pct": 100.0,
                "error": "ping timed out"}
    except OSError as exc:
        return {"target": host, "attempts": count, "responses": 0,
                "latency_ms": None, "packet_loss_pct": None,
                "error": f"ping unavailable: {exc}"}

    stdout = proc.stdout.decode("utf-8", "replace")
    responses = stdout.count("ttl=") + stdout.count("time=")
    # "time=12.3 ms" lines carry latency
    latencies = [float(m) for m in re.findall(r"time[=<]\s*([\d.]+)\s*ms", stdout)]
    loss_match = re.search(r"([\d.]+)% packet loss", stdout)
    loss = float(loss_match.group(1)) if loss_match else None
    ok = proc.returncode == 0 and responses > 0
    error = None if ok else _first_error_line(stdout, proc.stderr.decode("utf-8", "replace"))
    return {
        "target": host,
        "attempts": count,
        "responses": responses,
        "latency_ms": round(min(latencies), 2) if latencies else None,
        "latency_samples_ms": latencies[:5],
        "packet_loss_pct": loss,
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "ok": ok,
        "error": error,
        "note": "عدم پاسخ به ICMP لزوماً به معنی خاموش بودن دستگاه نیست",
    }


def tcp_check(settings: Settings, host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """TCP connectivity to ONE host on ONE port. A single connect() is a
    non-destructive diagnostic and is allowed by default; the host must be a
    validated single host (no ranges, no options)."""
    host = validate_host(host)
    if not 1 <= int(port) <= 65535:
        raise ValueError(f"port out of range: {port}")
    timeout = max(0.5, min(float(timeout), 10.0))
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = round((time.monotonic() - started) * 1000, 1)
        return {"target": host, "port": port, "connected": True,
                "elapsed_ms": elapsed, "ok": True}
    except OSError as exc:
        return {"target": host, "port": port, "connected": False,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
                "ok": False,
                "error": f"{exc.__class__.__name__}: {exc}"}


def _first_error_line(stdout: str, stderr: str) -> str | None:
    for text in (stderr, stdout):
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line[:200]
    return None


def _exists(path: str) -> bool:
    try:
        import os
        return os.path.exists(path)
    except OSError:
        return False
