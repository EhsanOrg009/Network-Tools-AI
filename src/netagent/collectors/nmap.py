"""Nmap diagnostic operations — first-class, non-destructive, scope-limited.

Operations (all enabled by default; the configured scope is the only gate):
- host discovery       (-sn, grepable)
- port/service scan    (-sT -sV --version-light --reason, XML)  [unprivileged]
- OS fingerprinting    (-O --osscan-guess --reason, XML)        [root/cap needed]

Hard rules:
- Targets validated against the authorized scope (CIDRs + explicit targets).
- Fixed argument templates; subprocess invoked with argument lists only.
- Never ``shell=True``; the model can only choose profiles + validated params.
- Timeouts and bounded output; missing privileges are *reported*, not hidden,
  and never silently substituted with results of different semantics.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any

from netagent.config import Settings

NMAP_BINARY = "/usr/bin/nmap"
MAX_OUTPUT_BYTES = 256 * 1024

_ROOT_MARKERS = (
    "requires root privileges",
    "you requested a scan type which requires root",
    "need root privileges",
)


class TargetNotAuthorized(ValueError):
    """Target lies outside the configured authorized scope."""


class NmapUnavailable(RuntimeError):
    """The nmap executable is missing."""


def validate_discovery_target(
    settings: Settings, target: str, extra_networks: list[str] | None = None
) -> str:
    """Validate a target (IP or CIDR) against the authorized scope.

    ``extra_networks`` (auto-discovered eligible networks) EXTENDS the
    configured scope; it never replaces or broadens it silently.
    """
    target = (target or "").strip()
    # Hostnames are not accepted for network scans: only IPs/CIDRs that can
    # be proven inside an authorized range.
    if not target or any(ch.isspace() for ch in target) or target.startswith("-"):
        raise TargetNotAuthorized(f"invalid target: {target[:64]!r}")
    try:
        candidate = ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            candidate = ipaddress.ip_network(f"{target}/32", strict=False)
        except ValueError as exc:
            raise TargetNotAuthorized(
                f"target is not an IP or CIDR: {target[:64]!r}"
            ) from exc
    if not settings.is_target_authorized(str(candidate)):
        authorized = False
        for raw in extra_networks or []:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                continue
            if candidate.version == net.version and candidate.subnet_of(net):
                authorized = True
                break
        if not authorized:
            raise TargetNotAuthorized(
                f"target {candidate} outside authorized scope "
                f"(MONITOR_CIDRS/AUTHORIZED_TARGETS): {settings.scope_description()}"
            )
    # Host-level targets normalize to a bare IP (see ToolScope.authorize).
    if candidate.prefixlen == candidate.max_prefixlen:
        return str(candidate.network_address)
    return str(candidate)


def validate_port_list(settings: Settings, ports: list[int] | None) -> list[int]:
    """Validate and bound a requested port list against configured limits."""
    if not ports:
        return list(settings.nmap_service_port_list)
    seen: set[int] = set()
    out: list[int] = []
    for p in ports:
        try:
            p = int(p)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid port: {p!r}") from exc
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
        if p not in seen:
            seen.add(p)
            out.append(p)
    if len(out) > settings.nmap_max_ports:
        raise ValueError(
            f"too many ports requested ({len(out)} > {settings.nmap_max_ports})"
        )
    return sorted(out)


# -- subprocess plumbing -------------------------------------------------------


def _run_nmap(args: list[str], timeout: int) -> tuple[str, str, int, bool]:
    """Run nmap with a fixed argument list. Returns (stdout, stderr, rc, timed_out)."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed args, validated target, no shell
            [NMAP_BINARY, *args],
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "", "", -1, True
    except FileNotFoundError as exc:
        raise NmapUnavailable(f"nmap binary not available: {exc}") from exc
    stdout = proc.stdout[:MAX_OUTPUT_BYTES]
    stderr = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    return stdout.decode("utf-8", "replace"), stderr, proc.returncode, False


def _needs_root(stderr: str) -> bool:
    low = stderr.lower()
    return any(marker in low for marker in _ROOT_MARKERS)


# -- A. host discovery ----------------------------------------------------------


def build_discovery_command(target: str) -> list[str]:
    """Fixed, allowlisted argument set for host discovery (-sn, no port scan)."""
    return ["-sn", "-n", "-oG", "-", target]


def parse_grepable(output: str) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.startswith("Host:"):
            continue
        head, _, tail = line.partition("\t")
        try:
            ip = head.split(":", 1)[1].split("(", 1)[0].strip()
        except (IndexError, ValueError):
            continue
        status = "Up" if "Status: Up" in tail else ("Down" if "Status: Down" in tail else None)
        if ip and status == "Up":
            hosts.append({"ip": ip, "status": "up"})
    return hosts


def host_discovery(
    settings: Settings, target: str, extra_networks: list[str] | None = None
) -> dict[str, Any]:
    """Host discovery over one authorized CIDR/IP.

    ``extra_networks`` (auto-discovered eligible networks) extends the
    authorized scope for this scan only; see :func:`validate_discovery_target`.
    """
    target = validate_discovery_target(settings, target, extra_networks)
    cmd = build_discovery_command(target)
    started = time.monotonic()
    stdout, stderr, rc, timed_out = _run_nmap(cmd, settings.nmap_discovery_timeout)
    if timed_out:
        return {"tool": "nmap_discovery", "target": target, "ok": False,
                "error": "nmap timed out", "hosts": []}
    hosts = parse_grepable(stdout)
    return {
        "ok": rc == 0,
        "tool": "nmap_discovery",
        "target": target,
        "hosts": hosts,
        "host_count": len(hosts),
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "output_truncated": len(stdout) >= MAX_OUTPUT_BYTES,
        "error": None if rc == 0 else stderr[:300],
        "note": "فقط کشف میزبان (-sn)؛ بدون اسکن پورت.",
    }


# -- B. port / service discovery --------------------------------------------------


def build_service_command(target: str, ports: list[int], service_detection: bool) -> list[str]:
    """Unprivileged TCP connect scan (-sT) with optional version detection."""
    args = ["-sT", "-Pn", "--reason", "-n", "-oX", "-",
            "-p", ",".join(str(p) for p in ports)]
    if service_detection:
        args += ["-sV", "--version-light"]
    args.append(target)
    return args


def _parse_xml_scan(xml_text: str) -> dict[str, Any]:
    """Parse nmap XML output into structured host/port/service/os data."""
    result: dict[str, Any] = {"hosts": [], "os_matches": [], "runstats": {}}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result["parse_error"] = f"xml parse failed: {exc.__class__.__name__}"
        return result

    for host_el in root.iter("host"):
        host: dict[str, Any] = {"addresses": [], "hostnames": [], "ports": []}
        status_el = host_el.find("status")
        if status_el is not None:
            host["status"] = status_el.get("state")
        for addr in host_el.iter("address"):
            host["addresses"].append({
                "addr": addr.get("addr"), "type": addr.get("addrtype"),
                "vendor": addr.get("vendor"),
            })
        for hn in host_el.iter("hostname"):
            host["hostnames"].append({
                "name": hn.get("name"), "type": hn.get("type"),
            })
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.iter("port"):
                pe: dict[str, Any] = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol"),
                }
                state_el = port_el.find("state")
                if state_el is not None:
                    pe["state"] = state_el.get("state")
                    pe["reason"] = state_el.get("reason")
                service_el = port_el.find("service")
                if service_el is not None:
                    pe["service"] = {
                        "name": service_el.get("name"),
                        "product": service_el.get("product"),
                        "version": service_el.get("version"),
                        "method": service_el.get("method"),  # probe|table
                        "conf": service_el.get("conf"),
                    }
                host["ports"].append(pe)
        os_el = host_el.find("os")
        if os_el is not None:
            os_matches = []
            for match in os_el.iter("osmatch"):
                os_matches.append({
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                    "osclasses": [
                        {
                            "vendor": oc.get("vendor"),
                            "osfamily": oc.get("osfamily"),
                            "osgen": oc.get("osgen"),
                            "type": oc.get("type"),
                            "accuracy": oc.get("accuracy"),
                        }
                        for oc in match.iter("osclass")
                    ],
                })
            host["os_matches"] = os_matches
            for fingerprint in os_el.iter("osfinger"):
                host.setdefault("os_fingers", []).append({
                    "fingerprint": fingerprint.get("finger"),
                    "name": fingerprint.get("name"),
                })
        result["hosts"].append(host)

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            result["runstats"] = {
                "elapsed": finished.get("elapsed"),
                "summary": finished.get("summary"),
                "exit": finished.get("exit"),
            }
    return result


def port_service_scan(
    settings: Settings,
    target: str,
    ports: list[int] | None = None,
    service_detection: bool = True,
) -> dict[str, Any]:
    """Bounded TCP connect scan + optional service/version detection."""
    target = validate_discovery_target(settings, target)
    ports = validate_port_list(settings, ports)
    cmd = build_service_command(target, ports, service_detection)
    started = time.monotonic()
    stdout, stderr, rc, timed_out = _run_nmap(cmd, settings.nmap_service_timeout)
    if timed_out:
        return {"tool": "nmap_services", "target": target, "ok": False,
                "error": "nmap timed out", "ports": ports}
    parsed = _parse_xml_scan(stdout)
    return {
        "ok": rc == 0 and not parsed.get("parse_error"),
        "tool": "nmap_services",
        "target": target,
        "ports_requested": ports,
        "service_detection": service_detection,
        "hosts": parsed["hosts"],
        "runstats": parsed["runstats"],
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "error": None if rc == 0 else stderr[:300],
        "note": (
            "اسکن اتصال TCP محدود (-sT) با سرویس/نسخه سبک (-sV --version-light). "
            "بدون اسکن تهاجمی."
        ),
    }


# -- C. OS fingerprinting -----------------------------------------------------------


def build_os_command(target: str, ports: list[int]) -> list[str]:
    """OS detection arguments (requires root / cap_net_raw)."""
    return [
        "-O", "--osscan-guess", "--reason", "-Pn", "-n", "-oX", "-",
        "-p", ",".join(str(p) for p in ports),
        target,
    ]


def os_detect(settings: Settings, target: str, ports: list[int] | None = None) -> dict[str, Any]:
    """TCP/IP stack fingerprinting. Degrades explicitly when privileges are
    missing instead of silently substituting a weaker result."""
    target = validate_discovery_target(settings, target)
    ports = validate_port_list(settings, ports)
    cmd = build_os_command(target, ports)
    started = time.monotonic()
    stdout, stderr, rc, timed_out = _run_nmap(cmd, settings.nmap_os_timeout)
    if timed_out:
        return {"tool": "nmap_os", "target": target, "ok": False,
                "error": "nmap timed out", "ports": ports}
    if _needs_root(stderr):
        return {
            "ok": False,
            "tool": "nmap_os",
            "target": target,
            "capability_required": "root or cap_net_raw (nmap -O)",
            "degraded": True,
            "error": (
                "تشخیص سیستم‌عامل nmap به دسترسی raw-packet نیاز دارد "
                "(root یا cap_net_raw). این آزمایش رد شد و نتیجه‌ی جایگزین "
                "با معنای متفاوت جایگزین نشد."
            ),
            "alternatives": [
                "nmap_services + host_fingerprint (استنتاج خانواده‌ی OS از سرویس‌ها)",
                "arp_info و reverse_dns برای شناسایی دستگاه",
            ],
            "hint": (
                "برای فعال‌سازی اختیاری: sudo setcap cap_net_raw+ep /usr/bin/nmap "
                "(فقط با تصمیم خودتان؛ برنامه هرگز دسترسی را تغییر نمی‌دهد)."
            ),
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
        }
    parsed = _parse_xml_scan(stdout)
    return {
        "ok": rc == 0 and not parsed.get("parse_error"),
        "tool": "nmap_os",
        "target": target,
        "ports": ports,
        "hosts": parsed["hosts"],
        "os_matches": [m for h in parsed["hosts"] for m in h.get("os_matches", [])],
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "error": None if rc == 0 else stderr[:300],
        "note": "پیش‌بینی انگشت‌نگاری TCP/IP؛ همیشه احتمالی است، نه حقیقت تأییدشده.",
    }
