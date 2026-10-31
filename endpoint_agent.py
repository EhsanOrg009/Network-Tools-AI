#!/usr/bin/env python3
"""عامل نقطه‌پایان (Endpoint Agent) — single-file, cross-platform (Linux/Windows).

یک اسکریپت پایتون مستقل (فقط کتابخانه‌ی استاندارد) که:
  1. با توکن ثبت‌نام یک‌بارمصرف به مرکز معرفی می‌شود (enroll).
  2. ضربان (heartbeat) و فهرست‌برداری ساختاریافته (inventory) می‌فرستد.
  3. تسک‌های تشخیصی پیش‌تعریف را اجرا و نتیجه را برمی‌گرداند.
  4. تسک‌های مدیریتی (اسکریپت پایتون / ترمینال تعاملی) را فقط با پاکت
     امضاشده (HMAC-SHA256) و فقط اگر صریحاً با پرچم فعال شده باشد اجرا می‌کند.

محدودیت‌های امنیتی طراحی:
- هیچ مقداری از شبکه به shell نمی‌رود؛ زیرفرآیندها با فهرست آرگومان ثابت.
- اعتبارنامه فقط در فایل وضعیت محلی با دسترسی 0600 ذخیره می‌شود.
- اجرای اسکریپت/ترمینال به‌صورت پیش‌فرض خاموش است (--allow-admin-exec /
  --allow-admin-console) و با دسترسی حساب سرویس عامل اجرا می‌شود، نه root.
- بدون sandbox است؛ هر کدی که مدیر می‌فرستد با دسترسی همین حساب اجرا می‌شود.

مثال‌ها:
  python endpoint_agent.py enroll --server-url https://core.example:8000 \
      --enrollment-token enr_xxx
  python endpoint_agent.py run --server-url https://core.example:8000
  python endpoint_agent.py run --once          # یک دور (برای تست)
  python endpoint_agent.py inventory           # فقط جمع‌آوری محلی و چاپ
  python endpoint_agent.py status

پیکربندی با آرگومان یا متغیر محیطی: NETAGENT_SERVER_URL,
NETAGENT_AGENT_TOKEN, NETAGENT_AGENT_ID, NETAGENT_TASK_SIGNING_KEY.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import random
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

AGENT_VERSION = "1.0.0"
STATE_DEFAULT = Path(os.path.expanduser("~/.netagent_endpoint_state.json"))
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EXECUTED_TASK_MEMORY = 200
IS_WINDOWS = platform.system().lower().startswith("win")

DIAGNOSTIC_CAPABILITIES = [
    "inventory", "connectivity_diagnostic", "service_inventory",
    "network_configuration", "approved_network_diagnostic",
]


# ---------------------------------------------------------------------------
# State file (identity + credential; 0600 on POSIX)
# ---------------------------------------------------------------------------


class State:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {
            "server_url": None,
            "agent_id": None,
            "agent_token": None,
            "enrolled_at": None,
            "executed_task_ids": [],
        }

    def load(self) -> "State":
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
        return self

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.data, ensure_ascii=False, indent=2)
        self.path.write_text(payload, encoding="utf-8")
        if os.name == "posix":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    # convenience accessors ---------------------------------------------------

    @property
    def agent_id(self) -> str | None:
        return self.data.get("agent_id")

    @property
    def agent_token(self) -> str | None:
        return self.data.get("agent_token")

    def remember_task(self, task_id: str) -> bool:
        """Replay guard. Returns False when the task was already executed."""
        done: list[str] = self.data.setdefault("executed_task_ids", [])
        if task_id in done:
            return False
        done.append(task_id)
        if len(done) > MAX_EXECUTED_TASK_MEMORY:
            del done[: len(done) - MAX_EXECUTED_TASK_MEMORY]
        return True


MAX_SEEN_NONCES = 200


# ---------------------------------------------------------------------------
# HTTP client (stdlib urllib; TLS verification never disabled)
# ---------------------------------------------------------------------------


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ApiClient:
    def __init__(self, server_url: str, agent_token: str | None = None,
                 ca_bundle: str | None = None, timeout: float = 30.0):
        self.base = server_url.rstrip("/")
        if not self.base.lower().startswith("https://") and not self.base.lower().startswith("http://"):
            raise ValueError("server URL must start with http:// or https://")
        self.agent_token = agent_token
        self.timeout = timeout
        if ca_bundle:
            self._ctx = ssl.create_default_context(cafile=ca_bundle)
        else:
            self._ctx = ssl.create_default_context()

    def request(self, method: str, path: str, payload: dict | None = None,
                auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json",
                   "User-Agent": f"netagent-endpoint/{AGENT_VERSION}"}
        if auth:
            if not self.agent_token:
                raise ApiError(0, "no agent credential; run enroll first")
            headers["Authorization"] = f"Bearer {self.agent_token}"
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = resp.read(MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(MAX_RESPONSE_BYTES)
                detail = json.loads(body).get("detail", str(exc))
            except Exception:
                detail = str(exc)
            raise ApiError(exc.code, str(detail)[:500]) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ApiError(0, f"connection failed: {exc.__class__.__name__}") from exc
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise ApiError(0, "server returned non-JSON response") from exc


# ---------------------------------------------------------------------------
# Signed-envelope verification (must match central services/tasks.py)
# ---------------------------------------------------------------------------

ENVELOPE_KIND = "netagent.admin-task.v1"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def derive_signing_key(master: str, agent_id: str) -> str:
    """Same derivation as the central server: two sha256 hex digests."""
    first = hashlib.sha256(master.encode("utf-8")).hexdigest()
    second = hashlib.sha256(f"{master}:{agent_id}".encode("utf-8")).hexdigest()
    return f"{first}:{second}"


def verify_envelope(message: dict, master_key: str, agent_id: str,
                    seen_nonces: list[str] | None = None) -> tuple[bool, str]:
    """Verify a signed admin task envelope.

    When ``seen_nonces`` is given it is updated in place (bounded by the
    caller): a nonce that was already accepted yields ``(False, "nonce
    replay")`` — an attacker replaying a captured envelope (even inside its
    validity window) is rejected independently of the task-id dedupe."""
    env = message.get("envelope")
    if not isinstance(env, dict):
        return False, "missing envelope"
    required = ("kind", "task_id", "agent_id", "type", "params_sha256", "expires_epoch", "nonce")
    if any(k not in env for k in required):
        return False, "incomplete envelope"
    payload = {k: env[k] for k in required}
    signature = env.get("signature", "")
    key = derive_signing_key(master_key, agent_id)
    expected = hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, "bad signature"
    if payload["kind"] != ENVELOPE_KIND:
        return False, "unknown envelope kind"
    if payload["agent_id"] != agent_id:
        return False, "envelope addressed to another agent"
    if payload["type"] != message.get("type"):
        return False, "envelope/task type mismatch"
    params_digest = hashlib.sha256(
        json.dumps(message.get("params") or {}, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(params_digest, payload["params_sha256"]):
        return False, "params do not match the signed digest"
    if time.time() > float(payload["expires_epoch"]):
        return False, "envelope expired"
    nonce = str(payload["nonce"])
    if seen_nonces is not None:
        if nonce in seen_nonces:
            return False, "nonce replay (already accepted)"
        seen_nonces.append(nonce)
        if len(seen_nonces) > MAX_SEEN_NONCES:
            del seen_nonces[: len(seen_nonces) - MAX_SEEN_NONCES]
    return True, "ok"


# ---------------------------------------------------------------------------
# Collectors — shared core, platform-specific branches (same file)
# ---------------------------------------------------------------------------


def classify_iface_name(name: str) -> str:
    n = (name or "").lower()
    if n == "lo" or n.startswith("lo0") or "loopback" in n:
        return "loopback"
    if any(m in n for m in ("tun", "tap", "wg", "ppp", "vpn", "tunnel", "zt")):
        return "vpn"
    if any(m in n for m in ("docker", "veth", "br-", "virbr", "vmnet", "vbox",
                            "hyper-v", "virtual", "vmware", "vethernet")):
        return "virtual"
    return "unknown"


def _safe_network(addr: str, prefix: int | None) -> tuple[str, str | None]:
    """Return (ip, cidr_or_None) — never raises on odd input."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return addr, None
    cidr = None
    if prefix is not None:
        try:
            cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            cidr = None
    return str(ip), cidr


def _run_cmd(argv: list[str], timeout: float = 10.0,
             max_bytes: int = 256 * 1024) -> tuple[int, str, str]:
    """Run a fixed-argument command; never shell=True; bounded output."""
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)  # noqa: S603
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 127, "", f"{exc.__class__.__name__}"
    out = proc.stdout.decode("utf-8", "replace")[:max_bytes]
    err = proc.stderr.decode("utf-8", "replace")[:4096]
    return proc.returncode, out, err


def collect_platform() -> dict:
    uname = platform.uname()
    os_name = None
    if not IS_WINDOWS:
        for candidate in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                for line in Path(candidate).read_text(encoding="utf-8").splitlines():
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        break
            except OSError:
                continue
            if os_name:
                break
    return {
        "os_family": uname.system or None,
        "os_name": os_name or (f"{uname.system} {uname.release}" if IS_WINDOWS else None),
        "os_version": uname.release or None,
        "kernel": uname.version or None,
        "arch": uname.machine or None,
    }


def collect_boot_uptime() -> tuple[float | None, float | None]:
    if IS_WINDOWS:
        rc, out, _ = _run_cmd([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')",
        ], timeout=20)
        if rc == 0 and out.strip():
            try:
                from datetime import datetime

                boot = datetime.fromisoformat(out.strip()).timestamp()
                return boot, max(0.0, time.time() - boot)
            except ValueError:
                return None, None
        return None, None
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
        return time.time() - uptime, uptime
    except (OSError, ValueError, IndexError):
        return None, None


def _collect_interfaces_linux() -> tuple[list[dict], str | None]:
    rc, out, err = _run_cmd(["ip", "-j", "addr"], timeout=10)
    ifaces: list[dict] = []
    if rc == 0 and out.strip():
        try:
            for item in json.loads(out):
                ipv4, ipv6, networks_v4 = [], [], []
                for addr in item.get("addr_info", []):
                    local = str(addr.get("local") or "")
                    plen = addr.get("prefixlen")
                    ip = _to_ip(local)
                    if ip is None:
                        continue
                    entry = f"{ip}/{plen}" if plen is not None else str(ip)
                    if ip.version == 4:
                        if str(ip).startswith("169.254."):
                            continue
                        ipv4.append(entry)
                        if plen is not None:
                            try:
                                networks_v4.append(str(ipaddress.ip_network(
                                    f"{ip}/{plen}", strict=False)))
                            except ValueError:
                                pass
                    else:
                        if str(ip).lower().startswith("fe80:"):
                            continue  # link-local
                        ipv6.append(entry)
                ifaces.append({
                    "name": item.get("ifname"),
                    "status": "up" if item.get("operstate") == "UP" else
                              (item.get("operstate") or "unknown").lower(),
                    "mac": item.get("address"),
                    "ipv4": ipv4, "ipv6": ipv6,
                    "connected_networks": networks_v4,
                    "gateway": None,
                    "classification": classify_iface_name(item.get("ifname", "")),
                    "dns_servers": [],
                })
        except (ValueError, KeyError, TypeError):
            ifaces = []
    if ifaces:
        # default gateway (JSON first, text fallback)
        rc2, out2, _ = _run_cmd(["ip", "-j", "route", "show", "default"], timeout=5)
        gateway = None
        if rc2 == 0 and out2.strip():
            try:
                routes = json.loads(out2)
                if routes:
                    gateway = routes[0].get("gateway")
            except ValueError:
                pass
        if gateway is None:
            rc3, out3, _ = _run_cmd(["ip", "route", "show", "default"], timeout=5)
            if rc3 == 0:
                match = re.search(r"default via (\S+)", out3)
                gateway = match.group(1) if match else None
        for iface in ifaces:
            if iface["classification"] != "loopback":
                iface["gateway"] = gateway
        # DNS from resolv.conf
        try:
            dns = [l.split()[1] for l in
                   Path("/etc/resolv.conf").read_text().splitlines()
                   if l.startswith("nameserver") and len(l.split()) >= 2][:5]
            for iface in ifaces:
                iface["dns_servers"] = dns
        except OSError:
            pass
        return ifaces, None
    return [], err or "ip command unavailable"


def _to_ip(value: str):
    try:
        return ipaddress.ip_address(value.split("/")[0].split("%")[0])
    except ValueError:
        return None


_PS_IPCONFIG = (
    "Get-NetIPConfiguration | ForEach-Object { $a = $_; "
    "[pscustomobject]@{ name=$a.InterfaceAlias; "
    "status=$a.NetAdapter.Status; mac=$a.NetAdapter.MacAddress; "
    "ipv4=@($a.IPv4Address | ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }); "
    "ipv6=@($a.IPv6Address | ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }); "
    "gw=@($a.IPv4DefaultGateway | ForEach-Object { $_.NextHop }); "
    "dns=@($a.DNSServer | ForEach-Object { $_.ServerAddresses }) } } | ConvertTo-Json -Depth 3"
)


def _collect_interfaces_windows() -> tuple[list[dict], str | None]:
    rc, out, err = _run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-Command", _PS_IPCONFIG], timeout=30)
    ifaces: list[dict] = []
    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                ipv4, ipv6, nets = [], [], []
                for raw in item.get("ipv4") or []:
                    raw = str(raw)
                    if "/" in raw:
                        addr_s, plen_s = raw.split("/", 1)
                        try:
                            plen = int(plen_s)
                        except ValueError:
                            plen = None
                    else:
                        addr_s, plen = raw, None
                    ip = _to_ip(addr_s)
                    if ip is None or ip.version != 4 or str(ip).startswith("169.254."):
                        continue
                    ipv4.append(f"{ip}/{plen}" if plen is not None else str(ip))
                    if plen is not None:
                        try:
                            nets.append(str(ipaddress.ip_network(f"{ip}/{plen}", strict=False)))
                        except ValueError:
                            pass
                ipv6 = [str(v) for v in (item.get("ipv6") or [])
                        if "fe80::" not in str(v).lower()][:8]
                gw = (item.get("gw") or [None])[0]
                ifaces.append({
                    "name": item.get("name"),
                    "status": str(item.get("status") or "unknown").lower(),
                    "mac": item.get("mac"),
                    "ipv4": ipv4, "ipv6": ipv6,
                    "connected_networks": nets,
                    "gateway": gw,
                    "classification": classify_iface_name(item.get("name", "")),
                    "dns_servers": [str(d) for d in (item.get("dns") or [])][:5],
                })
        except (ValueError, KeyError, TypeError):
            ifaces = []
    if ifaces:
        return ifaces, None
    # honest failure: no fabricated data
    return [], err or "PowerShell interface enumeration failed"


def collect_interfaces() -> tuple[list[dict], str | None]:
    if IS_WINDOWS:
        return _collect_interfaces_windows()
    return _collect_interfaces_linux()


def collect_listening_ports() -> dict:
    """Selected local listening TCP ports (no process cmdlines — privacy)."""
    if IS_WINDOWS:
        ps = ("Get-NetTCPConnection -State Listen | Select-Object -First 50 "
              "-Property LocalAddress,LocalPort | ConvertTo-Json -Compress")
        rc, out, err = _run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                                 "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=30)
        if rc != 0:
            return {"ok": False, "error": err or "Get-NetTCPConnection failed"}
        try:
            data = json.loads(out)
            data = data if isinstance(data, list) else [data]
            ports = sorted({int(d["LocalPort"]) for d in data if d.get("LocalPort")})
            return {"ok": True, "listening_tcp_ports": ports[:50]}
        except (ValueError, KeyError, TypeError) as exc:
            return {"ok": False, "error": f"parse failed: {exc}"}
    rc, out, err = _run_cmd(["ss", "-tln"], timeout=10)
    if rc != 0:
        return {"ok": False, "error": err or "ss unavailable"}
    ports = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "LISTEN":
            addr = parts[3].rsplit(":", 1)
            if len(addr) == 2 and addr[1].isdigit():
                ports.add(int(addr[1]))
    return {"ok": True, "listening_tcp_ports": sorted(ports)[:50]}


def collect_arp_cache() -> dict:
    """Local ARP/neighbor cache — cheap, passive Layer-2 context."""
    if IS_WINDOWS:
        rc, out, err = _run_cmd(["arp", "-a"], timeout=15)
        if rc != 0:
            return {"ok": False, "error": err or "arp failed"}
        entries = []
        for line in out.splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{12,17})\s+(\S+)", line)
            if m:
                entries.append({"ip": m.group(1), "mac": m.group(2).lower().replace("-", ":"),
                                "state": m.group(3)})
        return {"ok": True, "arp": entries[:100]}
    rc, out, err = _run_cmd(["ip", "-j", "neigh"], timeout=10)
    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            entries = [{"ip": d.get("dst"), "mac": d.get("lladdr"),
                        "state": d.get("state") if isinstance(d.get("state"), str)
                        else (d.get("state") or [""])[0]}
                       for d in data if d.get("dst")][:100]
            return {"ok": True, "arp": entries}
        except ValueError:
            pass
    rc, out, err = _run_cmd(["ip", "neigh"], timeout=10)
    if rc != 0:
        return {"ok": False, "error": err or "ip neigh unavailable"}
    entries = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "dev" in parts:
            try:
                idx = parts.index("lladdr")
                mac = parts[idx + 1]
            except ValueError:
                mac = None
            entries.append({"ip": parts[0], "mac": mac, "state": parts[-1]})
    return {"ok": True, "arp": entries[:100]}


def collect_optional_stats() -> dict:
    """Bounded, privacy-conscious optional stats; unavailable is reported."""
    stats: dict = {"cpu_percent": None, "memory": None}
    if not IS_WINDOWS:
        try:
            with open("/proc/stat", "rb") as fh:
                fields = fh.readline().split()[1:9]
                stats["cpu_percent"] = None  # single sample is meaningless; honest None
        except OSError:
            pass
        try:
            meminfo = {}
            with open("/proc/meminfo", encoding="utf-8") as fh:
                for line in fh:
                    key, value = line.split(":", 1)
                    meminfo[key.strip()] = int(value.strip().split()[0])
            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            if total:
                stats["memory"] = {"total_kb": total, "available_kb": available,
                                   "used_percent": round(100 * (total - available) / total, 1)}
        except (OSError, ValueError, IndexError):
            pass
    else:
        ps = ("[pscustomobject]@{t=(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize;"
              "f=(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory} | ConvertTo-Json -Compress")
        rc, out, err = _run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                                 "-Command", ps], timeout=20)
        if rc == 0:
            try:
                d = json.loads(out)
                total, free = int(d["t"]), int(d["f"])
                stats["memory"] = {"total_kb": total, "available_kb": free,
                                   "used_percent": round(100 * (total - free) / total, 1)}
            except (ValueError, KeyError, TypeError):
                pass
    return stats


def collect_inventory(collectors_status: list | None = None) -> dict:
    status: list[dict] = collectors_status or []
    errors: list[str] = []

    ifaces, iface_err = collect_interfaces()
    status.append({"name": "interfaces", "ok": bool(ifaces),
                   "message": iface_err if iface_err and not ifaces else None})
    if iface_err and not ifaces:
        errors.append(f"interfaces: {iface_err}")

    boot, uptime = collect_boot_uptime()
    ports = collect_listening_ports()
    status.append({"name": "listening_ports", "ok": bool(ports.get("ok")),
                   "message": ports.get("error")})
    arp = collect_arp_cache()
    status.append({"name": "arp_cache", "ok": bool(arp.get("ok")),
                   "message": arp.get("error")})

    return {
        "collected_at_epoch": round(time.time(), 3),
        "hostname": platform.node() or None,
        "platform": collect_platform(),
        "boot_time_epoch": round(boot, 3) if boot else None,
        "uptime_seconds": round(uptime, 1) if uptime else None,
        "interfaces": ifaces,
        "collectors_status": status,
        "optional_stats": collect_optional_stats(),
        "errors": errors,
        "listening_tcp_ports": ports.get("listening_tcp_ports"),
        "arp_cache": arp.get("arp"),
    }


# ---------------------------------------------------------------------------
# Diagnostic task executors (validated inputs; fixed argv; bounded output)
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$")


def _validated_host(value) -> str:
    host = str(value or "").strip().rstrip(".")
    if not host or len(host) > 253 or " " in host or host.startswith("-"):
        raise ValueError("invalid host")
    if not _HOSTNAME_RE.match(host):
        raise ValueError("invalid host")
    return host


def run_connectivity_diagnostic(params: dict) -> dict:
    host = _validated_host(params.get("host") or params.get("target"))
    kind = str(params.get("kind") or "ping").lower()
    started = time.monotonic()
    if kind == "tcp":
        try:
            port = int(params.get("port"))
        except (TypeError, ValueError) as exc:
            raise ValueError("port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
        try:
            with socket.create_connection((host, port), timeout=3.0):
                return {"ok": True, "kind": "tcp", "host": host, "port": port,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1)}
        except OSError as exc:
            return {"ok": False, "kind": "tcp", "host": host, "port": port,
                    "error": exc.__class__.__name__,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1)}
    if kind == "ping":
        count = min(max(int(params.get("count") or 2), 1), 3)
        if IS_WINDOWS:
            argv = ["ping", "-n", str(count), "-w", "2000", host]
        else:
            argv = ["ping", "-c", str(count), "-W", "2", host]
        rc, out, err = _run_cmd(argv, timeout=15)
        ok = rc == 0
        latency = None
        if ok:
            m = re.search(r"(?:time[=<]|avg = |Minimum = | متوسط = )(\d+(?:\.\d+)?)", out)
            if m:
                latency = float(m.group(1))
        return {"ok": ok, "kind": "ping", "host": host, "count": count,
                "latency_ms": latency, "error": None if ok else (err or "no reply"),
                "duration_ms": round((time.monotonic() - started) * 1000, 1)}
    raise ValueError(f"unsupported diagnostic kind: {kind!r}")


# ---------------------------------------------------------------------------
# Administrator remote execution (envelope-verified; local flags required)
# ---------------------------------------------------------------------------


def run_admin_script(params: dict, timeout_seconds: int) -> dict:
    """Run the signed admin script in an isolated subprocess (never shell).

    Executed with the agent's service-account privileges; no elevation.
    """
    code = str(params.get("code") or "")
    if not code:
        return {"ok": False, "error": "empty script"}
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed executable, code via stdin
            [sys.executable, "-I", "-"],
            input=code.encode("utf-8"),
            capture_output=True,
            timeout=max(5, int(timeout_seconds or 60)),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "execution timeout",
                "timed_out": True,
                "duration_ms": round((time.monotonic() - started) * 1000, 1)}
    except OSError as exc:
        return {"ok": False, "error": f"spawn failed: {exc.__class__.__name__}"}
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": out[:64 * 1024],
        "stderr": err[:64 * 1024],
        "stdout_truncated": len(out) > 64 * 1024,
        "stderr_truncated": len(err) > 64 * 1024,
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
    }


# ---------------------------------------------------------------------------
# Interactive console: persistent interpreter subprocess per session
# ---------------------------------------------------------------------------

# Bootstrap for the interpreter subprocess. Cells arrive base64-encoded, one
# per line on stdin; results are framed with marker lines so the agent can
# capture stdout/stderr and completion reliably. Marker bytes are chosen so
# user output colliding with them is practically impossible.
_CONSOLE_BOOTSTRAP = r"""
import ast, base64, sys, traceback
G = {"__name__": "__console__"}
def _cell(b64):
    status = "ok"
    try:
        src = base64.b64decode(b64.encode("ascii")).decode("utf-8")
        tree = ast.parse(src, "<console>", "exec")
        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last = tree.body.pop()
            exec(compile(tree, "<console>", "exec"), G)
            val = eval(compile(ast.Expression(last.value), "<console>", "eval"), G)
            sys.stdout.write("\x02CVAL " + base64.b64encode(repr(val).encode("utf-8")).decode("ascii") + "\x02\n")
        else:
            exec(compile(tree, "<console>", "exec"), G)
    except BaseException:
        status = "err"
        traceback.print_exc()
    sys.stdout.write("\x02CDONE " + status + "\x02\n")
    sys.stdout.flush()
print("\x02CREADY\x02")
sys.stdout.flush()
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    if line == "\x02CQUIT\x02":
        break
    _cell(line)
"""


class ConsoleSession:
    """One interpreter subprocess; sequential cells; bounded captures."""

    MARKER_DONE = "\x02CDONE"
    MARKER_VAL = "\x02CVAL"
    MARKER_READY = "\x02CREADY"

    def __init__(self, session_id: str, idle_timeout_seconds: float = 300.0):
        self.id = session_id
        self.idle_timeout = float(idle_timeout_seconds or 300.0)
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.out_lines: list[str] = []
        self.err_text: list[str] = []
        self.val_repr: str | None = None
        self._status = "err"
        self.done = threading.Event()
        self.ready = threading.Event()
        self.alive = False
        self.busy = False
        self.last_active = time.time()

    def start(self) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 - fixed interpreter, no shell
            [sys.executable, "-I", "-u", "-c", _CONSOLE_BOOTSTRAP],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.alive = True
        threading.Thread(target=self._pump, args=(self.proc.stdout, self._on_out),
                         name=f"console-{self.id[:8]}-out", daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, self._on_err),
                         name=f"console-{self.id[:8]}-err", daemon=True).start()

    @staticmethod
    def _pump(stream, handler) -> None:
        for raw in iter(stream.readline, b""):
            handler(raw.decode("utf-8", "replace").rstrip("\r\n"))
        handler(None)  # EOF

    def _on_out(self, line: str | None) -> None:
        if line is None:
            self.alive = False
            self.done.set()
            return
        if line.startswith(self.MARKER_READY):
            self.ready.set()
        elif line.startswith(self.MARKER_VAL):
            try:
                self.val_repr = base64.b64decode(
                    line[len(self.MARKER_VAL) + 1:-1].encode("ascii")
                ).decode("utf-8")
            except Exception:
                self.val_repr = None
        elif line.startswith(self.MARKER_DONE):
            parts = line.split()
            self._status = parts[1].strip("\x02") if len(parts) > 1 else "err"
            self.done.set()
        else:
            self.out_lines.append(line)
            if sum(len(l) for l in self.out_lines) > 96 * 1024:
                del self.out_lines[: len(self.out_lines) // 2]

    def _on_err(self, line: str | None) -> None:
        if line is None:
            return
        self.err_text.append(line)
        if sum(len(l) for l in self.err_text) > 32 * 1024:
            del self.err_text[: len(self.err_text) // 2]

    def execute(self, code: str, timeout_seconds: float) -> dict:
        started = time.monotonic()
        with self.lock:
            self.busy = True
            try:
                return self._execute_locked(code, timeout_seconds, started)
            finally:
                self.busy = False

    def _execute_locked(self, code: str, timeout_seconds: float, started: float) -> dict:
        if not self.alive or self.proc is None:
            return {"ok": False, "session_lost": True,
                    "error": "interpreter is not running"}
        self.out_lines.clear()
        self.err_text.clear()
        self.val_repr = None
        self.done.clear()
        try:
            b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
            assert self.proc.stdin is not None
            self.proc.stdin.write((b64 + "\n").encode("ascii"))
            self.proc.stdin.flush()
        except (OSError, ValueError):
            self.alive = False
            return {"ok": False, "session_lost": True,
                    "error": "interpreter pipe closed"}
        finished = self.done.wait(max(1.0, float(timeout_seconds)))
        duration = round((time.monotonic() - started) * 1000, 1)
        if not finished:
            # kill the whole interpreter: a thread cannot be aborted safely
            self.kill()
            return {"ok": False, "session_lost": True, "timed_out": True,
                    "stdout": "\n".join(self.out_lines)[:64 * 1024],
                    "stderr": "\n".join(self.err_text)[:32 * 1024],
                    "error": "command timeout; interpreter terminated",
                    "duration_ms": duration}
        if not self.alive:
            return {"ok": False, "session_lost": True,
                    "stdout": "\n".join(self.out_lines)[:64 * 1024],
                    "stderr": "\n".join(self.err_text)[:32 * 1024],
                    "error": "interpreter exited during command",
                    "duration_ms": duration}
        status = getattr(self, "_status", "err")
        return {"ok": status == "ok",
                "stdout": "\n".join(self.out_lines)[:64 * 1024],
                "stderr": "\n".join(self.err_text)[:32 * 1024],
                "result_repr": self.val_repr,
                "duration_ms": duration}

    def kill(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin:
                try:
                    self.proc.stdin.write(b"\x02CQUIT\x02\n")
                    self.proc.stdin.flush()
                    self.proc.stdin.close()
                except (OSError, ValueError):
                    pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except OSError:
            pass
        finally:
            self.alive = False
            self.done.set()


class ConsoleManager:
    """Session registry on the endpoint (in-memory; max sessions bounded)."""

    def __init__(self, max_sessions: int = 3):
        self.sessions: dict[str, ConsoleSession] = {}
        self.max_sessions = max_sessions

    def start(self, session_id: str, idle_timeout_seconds: float | None = None) -> dict:
        self.reap()
        existing = self.sessions.get(session_id)
        if existing and existing.alive:
            if idle_timeout_seconds is not None:
                existing.idle_timeout = float(idle_timeout_seconds)
            return {"ok": True, "session_id": session_id, "detail": "already running"}
        if len(self.sessions) >= self.max_sessions:
            return {"ok": False, "error": "local session limit reached"}
        session = ConsoleSession(
            session_id,
            idle_timeout_seconds=float(idle_timeout_seconds or 300.0),
        )
        session.start()
        if not session.ready.wait(10):
            session.kill()
            return {"ok": False, "error": "interpreter failed to start"}
        self.sessions[session_id] = session
        return {"ok": True, "session_id": session_id}

    def execute(self, session_id: str, code: str, timeout_seconds: float) -> dict:
        session = self.sessions.get(session_id)
        if session is None or not session.alive:
            return {"ok": False, "session_lost": True,
                    "error": "session not found on this endpoint"}
        session.last_active = time.time()
        return session.execute(code, timeout_seconds)

    def terminate(self, session_id: str) -> dict:
        session = self.sessions.pop(session_id, None)
        if session is None:
            return {"ok": True, "detail": "session not present"}
        session.kill()
        return {"ok": True, "detail": "terminated"}

    def reap(self) -> None:
        """Drop dead interpreters, plus interpreters idle beyond their window.

        An idle session is killed (not just forgotten): the console interpreter
        must not outlive the server-side idle policy. Busy sessions (a command
        currently executing) are never reaped — the idle clock pauses while a
        long command runs."""
        now = time.time()
        for sid, session in list(self.sessions.items()):
            if not session.alive:
                self.sessions.pop(sid, None)
            elif not session.busy and (now - session.last_active) > session.idle_timeout:
                self.sessions.pop(sid, None)
                session.kill()


# ---------------------------------------------------------------------------
# The agent loop
# ---------------------------------------------------------------------------


class EndpointAgent:
    def __init__(self, args: argparse.Namespace):
        self.state = State(Path(args.state_file or STATE_DEFAULT)).load()
        self.server_url = args.server_url or os.environ.get("NETAGENT_SERVER_URL") \
            or self.state.data.get("server_url")
        token_env = os.environ.get("NETAGENT_AGENT_TOKEN")
        if token_env:
            self.state.data["agent_token"] = token_env
        if args.server_url:
            self.state.data["server_url"] = self.server_url
        self.signing_key = os.environ.get("NETAGENT_TASK_SIGNING_KEY", "")
        # enroll/status subparsers don't carry the run-only flags; default them.
        self.heartbeat_interval = max(5, int(getattr(args, "heartbeat_interval", 30) or 30))
        self.inventory_interval = max(30, int(getattr(args, "inventory_interval", 300) or 300))
        self.poll_interval = max(1.0, float(getattr(args, "poll_interval", 5.0) or 5.0))
        self.allow_admin_exec = bool(getattr(args, "allow_admin_exec", False))
        self.allow_admin_console = bool(getattr(args, "allow_admin_console", False))
        self.allow_insecure_http = bool(getattr(args, "allow_insecure_http", False))
        self.console = ConsoleManager(max_sessions=3)
        self.client: ApiClient | None = None
        self.last_heartbeat = 0.0
        self.last_inventory = 0.0
        self.last_inventory_payload: dict | None = None

    # -- capabilities ----------------------------------------------------------

    def capabilities(self) -> list[str]:
        caps = list(DIAGNOSTIC_CAPABILITIES)
        if self.allow_admin_exec:
            caps.append("admin_exec")
        if self.allow_admin_console:
            caps.append("console")
        return caps

    # -- http ------------------------------------------------------------------

    def api(self) -> ApiClient:
        if self.client is None:
            if self.server_url is None:
                raise SystemExit("server URL unknown; use --server-url or enroll first")
            if self.server_url.lower().startswith("http://") and not self.allow_insecure_http:
                print(
                    "توجه: آدرس سرور http:// است؛ ارتباط رمزنگاری‌شده نیست. برای "
                    "تست محلی --allow-insecure-http را صریحاً بدهید؛ در تولید از "
                    "https با گواهی معتبر استفاده کنید.",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            self.client = ApiClient(self.server_url, self.state.agent_token,
                                    ca_bundle=os.environ.get("NETAGENT_CA_BUNDLE"))
        return self.client

    # -- enrollment ------------------------------------------------------------

    def enroll(self, enrollment_token: str) -> None:
        client = self.api()
        hostname = platform.node() or None
        response = client.request("POST", "/api/agent/v1/enroll", auth=False, payload={
            "enrollment_token": enrollment_token,
            "hostname": hostname,
            "platform": collect_platform(),
            "agent_version": AGENT_VERSION,
            "capabilities": self.capabilities(),
            "claimed_ips": self._quick_ips(),
        })
        self.state.data.update({
            "server_url": self.server_url,
            "agent_id": response["agent_id"],
            "agent_token": response["agent_token"],
            "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "executed_task_ids": [],
            "seen_envelope_nonces": [],
        })
        self.state.save()
        print(f"ثبت‌نام موفق: agent_id={response['agent_id']}")
        print("اعتبارنامه در فایل وضعیت ذخیره شد؛ مقدار توکن دوباره نمایش داده نمی‌شود.")

    def _quick_ips(self) -> list[str]:
        ifaces, _ = collect_interfaces()
        ips = []
        for iface in ifaces:
            ips.extend((iface.get("ipv4") or []) + (iface.get("ipv6") or []))
        return ips[:20]

    # -- automatic registration with administrator approval -------------------

    def self_register(self) -> str:
        """Introduce this endpoint to the core WITHOUT any manual token.

        The server stores the request as PENDING_APPROVAL; an administrator
        must approve it from the dashboard before any credential is issued.
        The local identity key never leaves this file except through the TLS
        channel during claim polls. Returns the request_id."""
        ifaces, _ = collect_interfaces()
        mac = next((i.get("mac") for i in ifaces
                    if i.get("mac") and i.get("classification") != "loopback"), None)
        gateway = next((i.get("gateway") for i in ifaces if i.get("gateway")), None)
        request_id = self.state.data.get("auto_request_id") or uuid.uuid4().hex
        identity_key = self.state.data.get("auto_identity_key")
        if not identity_key:
            identity_key = secrets.token_hex(32)
        identity_key_hash = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
        response = self.api().request("POST", "/api/agent/v1/register", auth=False, payload={
            "request_id": request_id,
            "identity_key_hash": identity_key_hash,
            "hostname": platform.node() or None,
            "platform": collect_platform(),
            "agent_version": AGENT_VERSION,
            "claimed_ips": self._quick_ips(),
            "mac": mac,
            "gateway": gateway,
        })
        self.state.data.update({
            "server_url": self.server_url,
            "auto_request_id": request_id,
            "auto_identity_key": identity_key,
            "auto_registered_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        })
        self.state.save()
        return str(response.get("request_id") or request_id)

    def poll_registration(self) -> int | None:
        """Ask the core for the registration decision.

        Returns None when still pending/unknown (keep the loop running), 0
        when enrollment is complete, 2 when the agent must stop (rejected or
        credential already consumed elsewhere)."""
        request_id = self.state.data.get("auto_request_id")
        identity_key = self.state.data.get("auto_identity_key")
        if not request_id or not identity_key:
            request_id = self.self_register()
        try:
            response = self.api().request(
                "POST", f"/api/agent/v1/register/{request_id}/claim", auth=False,
                payload={"identity_key": identity_key},
            )
        except ApiError as exc:
            if exc.status == 404:
                # request expired server-side → announce again
                self.state.data.pop("auto_request_id", None)
                self.state.save()
                return None
            raise
        status = response.get("status")
        if status == "APPROVED":
            self.state.data.update({
                "agent_id": response["agent_id"],
                "agent_token": response["agent_token"],
                "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "executed_task_ids": [],
                "seen_envelope_nonces": [],
                "auto_pending_notice_shown": None,
            })
            self.state.save()
            print(f"ثبت‌نام تأیید و تکمیل شد: agent_id={response['agent_id']}")
            print("اعتبارنامه در فایل وضعیت ذخیره شد؛ مقدار توکن دوباره نمایش داده نمی‌شود.")
            return 0
        if status == "PENDING_APPROVAL":
            if not self.state.data.get("auto_pending_notice_shown"):
                print("درخواست ثبت‌نام ارسال شد؛ در انتظار تأیید مدیر شبکه از داشبورد…")
                self.state.data["auto_pending_notice_shown"] = True
                self.state.save()
            return None
        if status == "REJECTED":
            print("درخواست ثبت‌نام رد شد؛ دلیل: "
                  f"{response.get('reason') or 'مشخص نشده'}", file=sys.stderr)
            return 2
        if status == "EXPIRED":
            self.state.data.pop("auto_request_id", None)
            self.state.save()
            return None
        if status == "ENROLLED":
            print("این درخواست قبلاً تکمیل شده اما اعتبارنامه محلی موجود نیست؛ ",
                  "برای ثبت‌نام مجدد، عامل قدیمی را در سرور Revoke کنید.",
                  file=sys.stderr)
            return 2
        return None

    # -- loop steps ------------------------------------------------------------

    def heartbeat(self) -> dict:
        body = {
            "claimed_ips": self._quick_ips(),
            "agent_version": AGENT_VERSION,
            "hostname": platform.node() or None,
            "platform": collect_platform(),
            "capabilities": self.capabilities(),
        }
        response = self.api().request("POST", "/api/agent/v1/heartbeat", payload=body)
        self.last_heartbeat = time.time()
        if response.get("agent_status") == "revoked":
            raise SystemExit("اعتبارنامه‌ی این عامل در سرور باطل شده است (403).")
        return response

    def push_inventory(self) -> None:
        payload = collect_inventory()
        self.last_inventory_payload = payload
        self.api().request("POST", "/api/agent/v1/inventory", payload=payload)
        self.last_inventory = time.time()

    def poll_and_execute_task(self) -> None:
        response = self.api().request("GET", "/api/agent/v1/tasks/next")
        message = response.get("task")
        if not message:
            return
        self._execute_task_message(message)

    # -- task execution ---------------------------------------------------------

    def _execute_task_message(self, message: dict) -> None:
        task_id = message.get("task_id") or "unknown"
        ttype = message.get("type", "")
        started_epoch = time.time()
        if not self.state.remember_task(str(task_id)):
            self._submit_result(task_id, False, None,
                                "duplicate task rejected (already executed)")
            return
        if ttype in ("admin_python_script", "console_session",
                     "console_command", "console_terminate"):
            ok, reason = verify_envelope(
                message, self.signing_key, self.state.agent_id or "",
                seen_nonces=self.state.data.setdefault("seen_envelope_nonces", []),
            )
            if not ok:
                self._submit_result(task_id, False, None,
                                    f"signature verification failed: {reason}")
                return
            if ttype == "admin_python_script" and not self.allow_admin_exec:
                self._submit_result(task_id, False, None,
                                    "admin execution disabled locally (--allow-admin-exec)")
                return
            if ttype.startswith("console") and not self.allow_admin_console:
                self._submit_result(task_id, False, None,
                                    "console disabled locally (--allow-admin-console)")
                return

        result, ok = self._dispatch_by_type(ttype, message.get("params") or {},
                                            message.get("timeout_seconds"))
        self._submit_result(task_id, ok, result, None if ok else (result or {}).get("error"),
                            started_epoch=started_epoch)

    def _dispatch_by_type(self, ttype: str, params: dict, timeout_seconds) -> tuple[dict, bool]:
        try:
            if ttype == "inventory_collection":
                return collect_inventory(), True
            if ttype == "network_configuration":
                ifaces, err = collect_interfaces()
                return ({"ok": bool(ifaces), "interfaces": ifaces,
                         "error": err}, bool(ifaces))
            if ttype == "service_inventory":
                result = collect_listening_ports()
                return result, bool(result.get("ok"))
            if ttype == "approved_network_diagnostic":
                result = collect_arp_cache()
                return result, bool(result.get("ok"))
            if ttype == "connectivity_diagnostic":
                result = run_connectivity_diagnostic(params)
                return result, bool(result.get("ok"))
            if ttype == "admin_python_script":
                result = run_admin_script(params, timeout_seconds)
                return result, bool(result.get("ok"))
            if ttype == "console_session":
                try:
                    idle = float(params.get("idle_timeout_seconds") or 300.0)
                except (TypeError, ValueError):
                    idle = 300.0
                result = self.console.start(str(params.get("session_id")), idle)
                return result, bool(result.get("ok"))
            if ttype == "console_command":
                result = self.console.execute(
                    str(params.get("session_id")),
                    str(params.get("code") or ""),
                    float(params.get("timeout_seconds") or 30),
                )
                return result, bool(result.get("ok"))
            if ttype == "console_terminate":
                session_id = str(params.get("session_id"))
                if params.get("mode") == "cancel":
                    result = self.console.terminate(session_id)
                    result["cancelled_command"] = params.get("command_id")
                else:
                    result = self.console.terminate(session_id)
                return result, True
            return {"ok": False, "error": f"unsupported task type: {ttype!r}"}, False
        except Exception as exc:  # a failing task must never kill the loop
            return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"[:300]}, False

    def _submit_result(self, task_id: str, ok: bool, result: dict | None,
                       error: str | None, started_epoch: float | None = None) -> None:
        body = {
            "ok": bool(ok),
            "result": result or {},
            "error": error,
            "duration_ms": round((time.time() - (started_epoch or time.time())) * 1000, 1),
            "started_at_epoch": started_epoch,
            "finished_at_epoch": time.time(),
        }
        try:
            self.api().request("POST", f"/api/agent/v1/tasks/{task_id}/result", payload=body)
        except ApiError as exc:
            # 409 = already recorded centrally: acceptable, keep the state mark
            if exc.status != 409:
                print(f"submit result failed: {exc}", file=sys.stderr)

    # -- main loop ---------------------------------------------------------------

    def run(self, once: bool = False) -> int:
        client = self.api()
        if not self.state.agent_id or not self.state.agent_token:
            # No credential yet: introduce this endpoint automatically and let
            # the run loop poll for the administrator's approval decision.
            print("عامل ثبت‌نام نشده است؛ معرفی خودکار به مرکز انجام می‌شود…")
            try:
                self.self_register()
            except ApiError as exc:
                if exc.status == 403:
                    print("ثبت‌نام خودکار روی سرور غیرفعال است؛ یا توکن یک‌بارمصرف "
                          "به‌صورت دستی با enroll وارد کنید.", file=sys.stderr)
                    return 2
                print(f"ارتباط با مرکز برقرار نشد ({exc})؛ دوباره تلاش کنید.",
                      file=sys.stderr)
                return 2
        attempt = 0
        last_claim_poll = 0.0
        while True:
            try:
                if not self.state.agent_token:
                    # pre-enrollment: poll the registration decision on a slow
                    # cadence; diagnostics stay off until approved
                    claim_cadence = max(10.0, self.poll_interval * 4)
                    if time.time() - last_claim_poll >= claim_cadence:
                        last_claim_poll = time.time()
                        outcome = self.poll_registration()
                        if outcome == 0:
                            continue  # enrolled now: heartbeat on the next pass
                        if outcome == 2:
                            return 2
                if self.state.agent_token:
                    if time.time() - self.last_heartbeat >= self.heartbeat_interval:
                        hb = self.heartbeat()
                        # the server may adjust the cadence centrally (e.g.
                        # probe storms quieted): honor it, never faster than 5s.
                        hb_interval = hb.get("heartbeat_interval_seconds")
                        if isinstance(hb_interval, (int, float)) and hb_interval >= 1:
                            self.heartbeat_interval = min(3600.0, max(5.0, float(hb_interval)))
                        if hb.get("inventory_due") or \
                                time.time() - self.last_inventory >= self.inventory_interval:
                            self.push_inventory()
                    self.poll_and_execute_task()
                attempt = 0
            except ApiError as exc:
                attempt += 1
                delay = min(30.0, 2.0 * (2 ** min(attempt, 5))) + random.uniform(0, 1.5)
                print(f"خطای ارتباط ({exc}); تلاش دوباره در {delay:.1f}s", file=sys.stderr)
                time.sleep(delay)
                continue
            except SystemExit as exc:
                print(str(exc), file=sys.stderr)
                return 2
            if once:
                return 0
            time.sleep(self.poll_interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpoint_agent",
        description="عامل نقطه‌پایان سبک برای پایش و مدیریت مجاز (ویندوز/لینوکس)",
    )
    parser.add_argument("--server-url", default=None,
                        help="آدرس مرکز مثل https://core.example:8000")
    parser.add_argument("--state-file", default=None,
                        help=f"مسیر فایل وضعیت (پیش‌فرض {STATE_DEFAULT})")
    sub = parser.add_subparsers(dest="command")

    enroll = sub.add_parser("enroll", help="ثبت‌نام با توکن یک‌بارمصرف")
    enroll.add_argument("--enrollment-token", default=None)
    enroll.add_argument("--server-url", default=None)
    enroll.add_argument("--state-file", default=None)
    enroll.add_argument("--allow-insecure-http", action="store_true",
                        help="فقط تست محلی: اجازه‌ی http بدون رمزنگاری")

    run = sub.add_parser("run", help="اجرای دوره‌ای: ضربان + inventory + تسک‌ها")
    run.add_argument("--server-url", default=None)
    run.add_argument("--state-file", default=None)
    run.add_argument("--heartbeat-interval", type=int, default=30)
    run.add_argument("--inventory-interval", type=int, default=300)
    run.add_argument("--poll-interval", type=float, default=5.0)
    run.add_argument("--once", action="store_true", help="فقط یک دور اجرا کن")
    run.add_argument("--allow-admin-exec", action="store_true",
                     help="اجازه‌ی اجرای اسکریپت پایتون مدیریتی امضاشده (پیش‌فرض: خاموش)")
    run.add_argument("--allow-admin-console", action="store_true",
                     help="اجازه‌ی ترمینال پایتون تعاملی مدیریتی (پیش‌فرض: خاموش)")
    run.add_argument("--allow-insecure-http", action="store_true",
                     help="فقط تست محلی: اجازه‌ی http بدون رمزنگاری")

    for name, help_text in (
        ("status", "نمایش وضعیت محلی (بدون افشای توکن)"),
        ("inventory", "جمع‌آوری inventory محلی و چاپ آن (بدون ارسال)"),
        ("version", "نمایش نسخه"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--state-file", default=None)

    diag = sub.add_parser(
        "diagnostics",
        help="خودآزمایی محلی: وضعیت جمع‌کننده‌ها، رابط‌های شبکه و (با --ping-server) دسترسی به مرکز",
    )
    diag.add_argument("--state-file", default=None)
    diag.add_argument("--server-url", default=None)
    diag.add_argument("--ping-server", action="store_true",
                      help="همچنین یک درخواست /health به مرکز بفرست")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # --server-url/--state-file are top-level; subcommands may also pass them
    if not args.command:
        parser.print_help()
        return 2
    if args.command == "version":
        print(AGENT_VERSION)
        return 0
    state_path = getattr(args, "state_file", None) or args.state_file
    if args.command == "inventory":
        print(json.dumps(collect_inventory(), ensure_ascii=False, indent=2, default=str))
        return 0
    if args.command == "diagnostics":
        state = State(Path(getattr(args, "state_file", None) or STATE_DEFAULT)).load()
        report: dict[str, object] = {"agent_version": AGENT_VERSION}
        inventory = collect_inventory()
        report["platform"] = inventory.get("platform")
        report["collectors"] = inventory.get("collectors_status")
        ifaces, iface_error = collect_interfaces()
        report["interfaces"] = {
            "count": len(ifaces),
            "names": [i.get("name") for i in ifaces],
            "error": iface_error,
        }
        ports = collect_listening_ports()
        report["listening_ports"] = {
            "ok": bool(ports.get("ok")), "error": ports.get("error")}
        arp = collect_arp_cache()
        report["arp_cache"] = {"ok": bool(arp.get("ok")), "error": arp.get("error")}
        state_file = state.path
        report["state_file"] = {
            "path": str(state_file),
            "exists": state_file.exists(),
            "credential_present": bool(state.agent_token),
        }
        server_url = getattr(args, "server_url", None) or state.data.get("server_url")
        report["server"] = {"url": server_url, "reachable": None}
        if args.ping_server and server_url:
            try:
                client = ApiClient(
                    server_url, None, ca_bundle=os.environ.get("NETAGENT_CA_BUNDLE"))
                client.request("GET", "/health", auth=False)
                report["server"]["reachable"] = True
            except ApiError as exc:
                report["server"] = {"url": server_url, "reachable": False,
                                    "error": str(exc)[:200]}
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 0
    if args.command == "status":
        state = State(Path(state_path or STATE_DEFAULT)).load()
        print(json.dumps({
            "server_url": state.data.get("server_url"),
            "agent_id": state.data.get("agent_id"),
            "enrolled_at": state.data.get("enrolled_at"),
            "state_file": str(state.path),
            "credential_present": bool(state.agent_token),
            "executed_tasks_remembered": len(state.data.get("executed_task_ids", [])),
            "platform": collect_platform(),
        }, ensure_ascii=False, indent=2))
        return 0

    agent = EndpointAgent(args)
    if args.command == "enroll":
        if not args.server_url:
            print("--server-url لازم است.", file=sys.stderr)
            return 2
        if not args.enrollment_token:
            print("برای ثبت‌نام بدون توکن، زیرفرمان run را اجرا کنید؛ عامل خودش را "
                  "معرفی می‌کند و مدیر شبکه از داشبورد تأیید می‌کند.", file=sys.stderr)
            return 2
        try:
            agent.enroll(args.enrollment_token)
        except ApiError as exc:
            print(f"ثبت‌نام رد شد: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "run":
        try:
            return agent.run(once=args.once)
        except KeyboardInterrupt:
            print("\nمتوقف شد.")
            return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
