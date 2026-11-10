"""Validated subprocess wrappers: ping and TCP connectivity checks."""

from __future__ import annotations

import re
import platform
import ipaddress
import socket
import subprocess
import time
from typing import Any

from netagent.config import Settings
from netagent.scope import ToolScope
from netagent.services.job_control import bounded_timeout

# Hostnames/IPs only. Rejects anything that could be interpreted as an option
# (leading dash), spaces, shell metacharacters, etc.
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,250}[A-Za-z0-9])?$")


def validate_host(host: str) -> str:
    """Return the validated host, or raise ValueError for unsafe input."""
    host = (host or "").strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not host or len(host) > 253 or not _HOST_RE.match(host):
        raise ValueError(f"unsafe or invalid host: {host[:64]!r}")
    return host


def ping(
    settings: Settings,
    host: str,
    count: int | None = None,
    *, scope: ToolScope | None = None,
) -> dict[str, Any]:
    """ICMP reachability check with a small, fixed number of requests.

    A failed ping is NOT proof that a device is offline (ICMP may be dropped
    by firewalls); the caller must treat this as weak evidence.
    """
    host = (scope or ToolScope(settings, [])).authorize(host, hostname=True, host_only=True)
    count = count or settings.ping_count
    count = max(1, min(int(count), settings.ping_count))
    timeout = settings.ping_timeout_seconds
    ipv6 = ipaddress.ip_address(host).version == 6
    if platform.system() == "Windows":
        cmd = ["ping", "-6" if ipv6 else "-4", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["/usr/bin/ping" if _exists("/usr/bin/ping") else "ping",
               *(["-6"] if ipv6 else []), "-c", str(count), "-W", str(timeout), host]
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            cmd,
            capture_output=True,
            timeout=bounded_timeout(timeout * count + 5),
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
    # One reply record is one response, even if it contains both TTL and time.
    replies = [line for line in stdout.splitlines()
               if re.search(r"(?:bytes from|reply from)\s", line, re.I)
               and re.search(r"time[=<]\s*[\d.]+\s*ms", line, re.I)]
    responses = len(replies)
    latencies = [float(m) for line in replies for m in re.findall(r"time[=<]\s*([\d.]+)\s*ms", line, re.I)]
    loss_match = re.search(r"([\d.]+)%\s*(?:packet loss|loss)", stdout, re.I)
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


def tcp_check(settings: Settings, host: str, port: int, timeout: float = 3.0,
              *, scope: ToolScope | None = None) -> dict[str, Any]:
    """TCP connectivity to ONE host on ONE port. A single connect() is a
    non-destructive diagnostic and is allowed by default; the host must be a
    validated single host (no ranges, no options)."""
    host = (scope or ToolScope(settings, [])).authorize(host, hostname=True, host_only=True)
    if not 1 <= int(port) <= 65535:
        raise ValueError(f"port out of range: {port}")
    timeout = bounded_timeout(max(0.5, min(float(timeout), 10.0)))
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
