"""Unprivileged local system observations used as fingerprint evidence.

- ``ip neigh``  : ARP/NDP cache (MAC, vendor prefix, randomized-MAC detection)
- ``ip route``  : default gateway and directly connected networks
- reverse DNS   : via ``nmap -sL`` (bounded) so no blocking resolver calls

All are read-only, run as the normal user, and never escalate privileges.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from typing import Any

MAX_TEXT_BYTES = 32 * 1024

# Small offline OUI prefix map (manufacturer identification, best effort).
_OUI_PREFIXES: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "f4:f5:d8": "Google",
    "00:1b:63": "Apple",
    "ac:de:48": "Apple",
    "f0:18:98": "Apple",
    "d8:96:95": "ASUSTek",
    "00:1a:2b": "Ayecom",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "00:1d:7e": "Cisco",
    "00:00:0c": "Cisco",
    "3c:37:12": "Huawei",
    "00:18:82": "Huawei",
    "00:1e:10": "D-Link",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "02:42:ac": "Docker/container (locally administered)",
    "06:7e:69": "locally administered (randomized?)",
}


def is_randomized_mac(mac: str | None) -> bool | None:
    """IEEE 802 locally-administered bit set => likely randomized MAC."""
    if not mac or mac.count(":") != 5:
        return None
    try:
        first = int(mac.split(":")[0], 16)
    except ValueError:
        return None
    return bool(first & 0b10)


def mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = ":".join(mac.lower().split(":")[:3])
    return _OUI_PREFIXES.get(prefix)


def _run(args: list[str], timeout: int) -> str | None:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed args, no shell
            args, capture_output=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout[:MAX_TEXT_BYTES].decode("utf-8", "replace")


def arp_info(target_ip: str, timeout: int = 10) -> dict[str, Any]:
    """Read the local ARP/NDP entry for one IP from the kernel cache.

    Note: the cache only contains entries this host recently talked to; an
    empty result is not evidence that the device is absent.
    """
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        return {"tool": "arp_info", "ip": target_ip, "ok": False,
                "error": f"invalid IP: {exc}"}
    out = _run(["ip", "-o", "neigh", "show", target_ip], timeout)
    entry: dict[str, Any] = {
        "tool": "arp_info", "ip": target_ip, "ok": True,
        "mac": None, "mac_vendor": None, "mac_randomized": None,
        "state": None, "dev": None,
        "note": "نتیجه از کش ARP/NDP محلی خوانده شد؛ نبودِ ردیف به معنی نبودِ دستگاه نیست.",
    }
    if out:
        parts = out.split()
        # e.g. "10.233.68.161 dev wlo1 lladdr 06:7e:69:26:ee:1a REACHABLE"
        if len(parts) >= 6 and "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
            entry["mac"] = mac
            entry["mac_vendor"] = mac_vendor(mac)
            entry["mac_randomized"] = is_randomized_mac(mac)
        if "dev" in parts:
            entry["dev"] = parts[parts.index("dev") + 1]
        entry["state"] = parts[-1] if parts else None
    else:
        entry["cache_entry"] = False
    return entry


def route_info(timeout: int = 10) -> dict[str, Any]:
    """Default gateway and directly connected networks (read-only)."""
    out = _run(["ip", "route"], timeout)
    routes: list[dict[str, str]] = []
    default_gw = None
    if out:
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "default":
                route = {"dest": "default"}
                for i, p in enumerate(parts):
                    if p == "via" and i + 1 < len(parts):
                        default_gw = parts[i + 1]
                        route["via"] = parts[i + 1]
                    if p == "dev" and i + 1 < len(parts):
                        route["dev"] = parts[i + 1]
                routes.append(route)
            elif "/" in parts[0] or parts[0].count(".") == 3:
                routes.append({"dest": parts[0]})
    return {
        "tool": "route_info", "ok": default_gw is not None or bool(routes),
        "default_gateway": default_gw, "routes": routes,
        "note": "مشاهده‌ی فقط-خواندنی جدول مسیریابی محلی.",
    }


def reverse_dns(target_ip: str, timeout: int = 20) -> dict[str, Any]:
    """Reverse-DNS lookup via ``nmap -sL`` (bounded, unprivileged).

    A reverse-DNS name is a *guess-grade* hostname: the mapping is configured
    by whoever controls the PTR record, not a verified property of the device.
    """
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        return {"tool": "reverse_dns", "ip": target_ip, "ok": False,
                "error": f"invalid IP: {exc}"}
    started = time.monotonic()
    # NOTE: no "-n" here — -n disables DNS resolution and would make the PTR
    # lookup useless. --system-dns uses the system resolver directly.
    out = _run(["nmap", "-sL", "--system-dns", target_ip], timeout)
    if out is None:
        return {"tool": "reverse_dns", "ip": target_ip, "ok": False,
                "error": "lookup unavailable or timed out"}
    name = None
    for line in out.splitlines():
        if "scan report for" in line:
            candidate = line.split("scan report for", 1)[1].strip()
            # "Nmap scan report for 1.2.3.4" (no PTR) => digit-leading, skip
            if candidate.startswith(tuple("0123456789")):
                continue
            # "Nmap scan report for _gateway (10.233.68.161)" => strip the IP
            candidate = candidate.split("(", 1)[0].strip()
            if candidate:
                name = candidate
                break
    return {
        "tool": "reverse_dns", "ip": target_ip, "ok": True,
        "hostname": name, "hostname_source": "rdns",
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "note": "نام از PTR معکوس آمده است؛ حدسی از طرف مالک رکورد، نه ویژگی تأییدشده.",
    }
