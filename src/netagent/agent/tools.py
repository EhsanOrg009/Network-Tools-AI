"""Validated diagnostic tool registry.

Policy (v2): every non-destructive diagnostic tool is enabled by default.
There are no per-tool feature flags. The single authorization gate is the
configured *scope* (MONITOR_CIDRS ∪ AUTHORIZED_TARGETS), validated inside
each target-taking tool. Observed or model-selected targets never grant
authorization. Only low-impact discovery can use policy-eligible networks.

Hard invariants:
- Model output never reaches a shell; subprocesses use argument lists built
  from fixed templates plus validated parameters.
- Untrusted data (hostnames, banners, DNS names) is regex/structure-checked.
- Missing executables / missing OS capabilities are reported explicitly and
  never silently substituted with results of different semantics.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Callable

from netagent.collectors import connectivity, system_info
from netagent.config import Settings, binary_available
from netagent.database import Database
from netagent.scope import ToolScope, TargetNotAuthorized


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    available: Callable[[Settings], bool]  # prerequisites only (binary exists)
    unavailable_message: str
    run: Callable[..., dict[str, Any]]
    cost: str = "cheap"  # cheap | moderate | expensive — for LLM planning


def _validate_ping_args(args: dict[str, Any]) -> dict[str, Any]:
    host = args.get("host") or args.get("target")
    if not host:
        raise ValueError("host is required")
    return {"host": str(host)}


def _validate_tcp_args(args: dict[str, Any], settings: Settings) -> dict[str, Any]:
    host = args.get("host") or args.get("target")
    port = args.get("port")
    if not host or port is None:
        raise ValueError("host and port are required")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return {"host": str(host), "port": port}


def _validate_target_arg(args: dict[str, Any], scope: ToolScope, *, discovery: bool = False) -> dict[str, Any]:
    target = args.get("target") or args.get("cidr") or args.get("ip")
    if not target:
        raise ValueError("target is required")
    return {"target": scope.authorize(str(target), discovery=discovery)}


def _validate_ports_arg(args: dict[str, Any], settings: Settings) -> list[int] | None:
    ports = args.get("ports")
    if ports is None:
        return None
    if not isinstance(ports, list):
        raise ValueError("ports must be a list of integers")
    from netagent.collectors.nmap import validate_port_list
    return validate_port_list(settings, ports)


def _validate_alert_args(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if args.get("ip"):
        out["ip"] = str(args["ip"])[:64]
    if args.get("severity") is not None:
        sev = int(args["severity"])
        if not 0 <= sev <= 10:
            raise ValueError("severity must be 0-10")
        out["severity"] = sev
    if args.get("signature_id") is not None:
        out["signature_id"] = int(args["signature_id"])
    if args.get("since_minutes") is not None:
        mins = int(args["since_minutes"])
        if not 1 <= mins <= 60 * 24 * 7:
            raise ValueError("since_minutes must be 1..10080")
        out["since_minutes"] = mins
    out["limit"] = min(max(int(args.get("limit", 20)), 1), 50)
    return out


def _validate_history_args(args: dict[str, Any]) -> dict[str, Any]:
    ip = args.get("ip") or args.get("host")
    if not ip:
        raise ValueError("ip is required")
    return {"ip": str(ip)[:64]}


def _validate_pcap_args(args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path")
    if not path:
        raise ValueError("path is required")
    return {"path": str(path)[:512]}


# -- implementations ---------------------------------------------------------


def _run_endpoint_inventory(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    """Read-only endpoint-agent evidence: latest inventory for a host/agent.

    Agent-reported data is untrusted input: it is returned marked with its
    source and collection time; the model must treat OS claims as reported,
    not verified. This tool NEVER exposes admin script/console functions.
    """
    ip = args.get("ip") or args.get("host")
    agent_id = args.get("agent_id")
    if not ip and not agent_id:
        raise ValueError("ip or agent_id is required")
    agents = db.list_agents(limit=500)
    target = None
    if agent_id:
        target = db.get_agent(str(agent_id)[:64])
        if target is None:
            raise ValueError(f"agent not found: {str(agent_id)[:32]}")
    else:
        ip_s = str(ip)[:64]
        for agent in agents:
            claimed = agent.get("claimed_ips") or []
            normalized = {c.split("/")[0] for c in claimed if isinstance(c, str)}
            if ip_s in normalized:
                target = agent
                break
    if target is None:
        return {"ok": True, "tool": "endpoint_inventory", "agent": None,
                "note": "برای این میزبان عامل ثبت‌شده‌ای یافت نشد (unmanaged)."}
    from netagent.services.agents import agent_public_view

    view = agent_public_view(target, settings)
    latest = db.get_latest_inventory(target["id"])
    inventory = (latest or {}).get("inventory") or {}
    return {
        "ok": True,
        "tool": "endpoint_inventory",
        "agent": view,
        "inventory": inventory,
        "trust_note": (
            "این داده توسط عامل نقطه‌پایان گزارش شده است؛ ادعای خود دستگاه است، "
            "نه fingerprint مستقل شبکه. با شواهد شبکه مقایسه کن."
        ),
    }


def _run_endpoint_status(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    """Read-only online/stale overview of enrolled endpoint agents."""
    from netagent.services.agents import agent_public_view

    agents = [
        agent_public_view(a, settings)
        for a in db.list_agents(limit=min(max(int(args.get("limit", 20)), 1), 100))
    ]
    counts = {"active": 0, "stale": 0, "revoked": 0}
    for a in agents:
        counts[a["status"]] = counts.get(a["status"], 0) + 1
    return {"ok": True, "tool": "endpoint_status", "agents": agents,
            "status_counts": counts,
            "note": "stale یعنی ضربان اخیر دریافت نشده؛ اثبات خاموشی نیست."}


def _run_ping(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    v = _validate_ping_args(args)
    v["host"] = scope.authorize(v["host"], hostname=True, host_only=True)
    result = connectivity.ping(settings, v["host"], scope=scope)
    db.record_observation(v["host"], "ping", bool(result.get("ok")), result)
    return result


def _run_tcp(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    v = _validate_tcp_args(args, settings)
    v["host"] = scope.authorize(v["host"], hostname=True, host_only=True)
    result = connectivity.tcp_check(settings, v["host"], v["port"], scope=scope)
    db.record_observation(
        v["host"], "tcp", bool(result.get("ok")),
        {"target": v["host"], "port": v["port"], "ok": result.get("ok"),
         "error": result.get("error")},
    )
    return result


def _run_nmap_discovery(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    from netagent.collectors.nmap import host_discovery
    v = _validate_target_arg(args, scope, discovery=True)
    return host_discovery(settings, v["target"], extra_networks=scope.networks(discovery=True))


def _run_nmap_services(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    from netagent.collectors.nmap import port_service_scan
    v = _validate_target_arg(args, scope)
    ports = _validate_ports_arg(args, settings)
    service_detection = bool(args.get("service_detection", True))
    result = port_service_scan(settings, v["target"], ports, service_detection)
    for host in result.get("hosts", []):
        for addr in host.get("addresses", []):
            if addr.get("type") == "ipv4" and addr.get("addr"):
                db.record_observation(
                    addr["addr"], "nmap_services", bool(result.get("ok")),
                    {"open_ports": [p["port"] for p in host.get("ports", [])
                                    if p.get("state") == "open"]},
                )
    return result


def _run_nmap_os(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    from netagent.collectors.nmap import os_detect
    v = _validate_target_arg(args, scope)
    ports = _validate_ports_arg(args, settings)
    return os_detect(settings, v["target"], ports)


def _run_arp_scan(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    import subprocess

    v = _validate_target_arg(args, scope, discovery=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed args, validated CIDR, no shell
            ["/usr/sbin/arp-scan", v["target"]],
            capture_output=True,
            timeout=settings.arp_scan_timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "tool": "arp_scan", "target": v["target"],
                "error": "arp-scan timed out"}
    except FileNotFoundError:
        return {"ok": False, "tool": "arp_scan", "target": v["target"],
                "error": "arp-scan binary not available"}
    except OSError as exc:
        return {"ok": False, "tool": "arp_scan", "target": v["target"],
                "error": f"arp-scan unavailable: {exc}"}
    stdout = proc.stdout.decode("utf-8", "replace")[: settings.max_tool_output_bytes]
    from netagent.collectors.system_info import mac_vendor, is_randomized_mac
    hosts = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].count(".") == 3:
            mac = parts[1]
            hosts.append({
                "ip": parts[0], "mac": mac,
                "mac_vendor": mac_vendor(mac),
                "mac_randomized": is_randomized_mac(mac),
            })
            db.record_observation(parts[0], "arp", True, {"mac": mac})
    ok = proc.returncode == 0
    error = None
    if not ok:
        stderr = proc.stderr.decode("utf-8", "replace")[:300]
        low = stderr.lower()
        if "permission" in low or "pcap" in low or "root" in low or "libpcap" in low:
            error = (
                "arp-scan به دسترسی raw-socket نیاز دارد (root یا setcap). "
                "اجرای آن مجاز نیست؛ به‌جای ارتقای دسترسی، از nmap_discovery "
                "و arp_info استفاده شد."
            )
            return {"ok": False, "tool": "arp_scan", "target": v["target"],
                    "capability_required": "root or cap_net_raw (arp-scan)",
                    "degraded": True, "error": error, "hosts": []}
        error = stderr or f"arp-scan exited with code {proc.returncode}"
    return {"ok": ok, "tool": "arp_scan", "target": v["target"],
            "hosts": hosts, "host_count": len(hosts),
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
            "error": error}


def _run_alerts(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    v = _validate_alert_args(args)
    since = time.time() - v["since_minutes"] * 60 if "since_minutes" in v else None
    alerts, total = db.query_alerts(
        ip=v.get("ip"),
        severity=v.get("severity"),
        signature_id=v.get("signature_id"),
        since_epoch=since,
        limit=v["limit"],
    )
    keys = ("id", "ts", "flow_id", "src_ip", "src_port", "dest_ip", "dest_port",
            "proto", "app_proto", "signature", "signature_id", "category",
            "severity", "action")
    curated = [{k: a.get(k) for k in keys} for a in alerts]
    flow = db.alert_flow_summary(ip=v.get("ip"), since_epoch=since, limit=20)
    return {"ok": True, "tool": "suricata_alerts", "total": total,
            "alerts": curated, "grouped_by_flow_and_rule": flow,
            "note": (
                "هشدار = تطابق قانون؛ نه اثبات نفوذ. action=allowed یعنی بسته "
                "عبور کرده. تکرار امضا روی یک flow یک رویداد است نه چند حمله."
            )}


def _run_events(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    ip = args.get("ip") or None
    event_type = str(args.get("event_type"))[:32] if args.get("event_type") else None
    if args.get("event_type") and event_type not in (
        "alert", "dns", "tls", "flow", "http", "anomaly", "stats", "dhcp", "ssh",
    ):
        raise ValueError(f"unsupported event_type: {event_type!r}")
    if args.get("since_minutes") is not None:
        mins = int(args["since_minutes"])
        if not 1 <= mins <= 60 * 24 * 7:
            raise ValueError("since_minutes must be 1..10080")
        since_epoch = time.time() - mins * 60
    else:
        since_epoch = None
    items, total = db.query_events(
        event_type=event_type, ip=ip, since_epoch=since_epoch,
        limit=min(max(int(args.get("limit", 20)), 1), 50),
    )
    return {"ok": True, "tool": "suricata_events", "total": total,
            "events": items, "ip": ip, "event_type": event_type}


def _run_history(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    v = _validate_history_args(args)
    host = db.get_host(v["ip"])
    obs = db.host_observations(v["ip"], limit=20)
    summary = db.host_event_summary(v["ip"])
    fp = db.latest_fingerprint(v["ip"])
    return {"ok": True, "tool": "host_history", "ip": v["ip"],
            "host_record": host, "observations": obs,
            "event_summary_24h": summary,
            "latest_fingerprint": fp}


def _run_timeline(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    v = _validate_history_args(args)
    limit = min(max(int(args.get("limit", 50)), 1), 200)
    return {"ok": True, "tool": "host_timeline", "ip": v["ip"],
            "timeline": db.host_timeline(v["ip"], limit=limit)}


def _run_arp_info(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    ip = args.get("ip") or args.get("host") or args.get("target")
    if not ip:
        raise ValueError("ip is required")
    result = system_info.arp_info(str(ip)[:64])
    if result.get("mac"):
        db.record_observation(str(ip)[:64], "arp_info", True,
                              {"mac": result["mac"], "state": result.get("state")})
    return result


def _run_route_info(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    return system_info.route_info()


def _run_reverse_dns(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    ip = args.get("ip") or args.get("host")
    if not ip:
        raise ValueError("ip is required")
    return system_info.reverse_dns(scope.authorize(str(ip), host_only=True))


def _run_fingerprint(db: Database, settings: Settings, args: dict[str, Any], scope: ToolScope) -> dict[str, Any]:
    from netagent.services.fingerprint import fingerprint_host
    v = _validate_target_arg(args, scope)
    include_os = bool(args.get("os_detect", True))
    record = fingerprint_host(
        db, settings, v["target"], include_os_detect=include_os, save=True,
    )
    return {"ok": True, "tool": "host_fingerprint", **record}


def _run_fingerprint_history(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    v = _validate_history_args(args)
    ip = v["ip"]
    history = db.fingerprint_history(ip)
    changes = db.fingerprint_changes(ip)
    return {"ok": True, "tool": "fingerprint_history", "ip": ip,
            "latest": history[0] if history else None,
            "history": history, "changes": changes}


def _run_pcap(db: Database, settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    v = _validate_pcap_args(args)
    result = collectors.tshark.analyze_pcap(
        v["path"], timeout=settings.subprocess_timeout_seconds * 2
    )
    result.setdefault("ok", True)
    return result


def _nmap_available(s: Settings) -> bool:
    return binary_available("/usr/bin/nmap") or binary_available("nmap")


def _arp_available(s: Settings) -> bool:
    return binary_available("/usr/sbin/arp-scan") or binary_available("arp-scan")


def _tshark_available(s: Settings) -> bool:
    return binary_available("/usr/bin/tshark") or binary_available("tshark")


def _iproute2_available(s: Settings) -> bool:
    return binary_available("ip")


def build_registry(settings: Settings) -> dict[str, ToolSpec]:
    """Registry. Every tool is enabled by default; ``available`` only checks
    prerequisites (binary presence). Scope is enforced per call via ToolScope.
    Model-supplied targets outside the scope are rejected with a clear error.
    """
    return {
        "ping": ToolSpec(
            name="ping",
            description="بررسی دسترس‌پذیری ICMP یک میزبان با تعداد محدود",
            parameters={"host": "string (required)", "count": "int optional (<=3)"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_ping(db, s, args, scope),
            cost="cheap",
        ),
        "tcp_check": ToolSpec(
            name="tcp_check",
            description="بررسی اتصال TCP به یک میزبان روی یک پورت مشخص",
            parameters={"host": "string (required)", "port": "int 1-65535 (required)"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_tcp(db, s, args, scope),
            cost="cheap",
        ),
        "nmap_discovery": ToolSpec(
            name="nmap_discovery",
            description="کشف میزبان nmap (-sn) در یک CIDR یا روی یک IP داخل محدوده‌ی مجاز",
            parameters={"target": "string: IP یا CIDR داخل scope (required)"},
            available=_nmap_available,
            unavailable_message="nmap نصب نیست.",
            run=lambda db, s, args, scope: _run_nmap_discovery(db, s, args, scope),
            cost="moderate",
        ),
        "nmap_services": ToolSpec(
            name="nmap_services",
            description=(
                "کشف پورت/سرویس و نسخه (-sT -sV سبک) روی یک میزبان مجاز؛ "
                "فهرست پورت‌ها محدود است"
            ),
            parameters={
                "target": "string: IP میزبان مجاز (required)",
                "ports": "list[int] optional (حداکثر NMAP_MAX_PORTS)",
                "service_detection": "bool optional (default true)",
            },
            available=_nmap_available,
            unavailable_message="nmap نصب نیست.",
            run=lambda db, s, args, scope: _run_nmap_services(db, s, args, scope),
            cost="moderate",
        ),
        "nmap_os": ToolSpec(
            name="nmap_os",
            description=(
                "انگشت‌نگاری سیستم‌عامل (-O --osscan-guess)؛ نیازمند دسترسی "
                "raw-packet — در صورت نبود دسترسی، صریحاً گزارش می‌شود"
            ),
            parameters={
                "target": "string: IP میزبان مجاز (required)",
                "ports": "list[int] optional",
            },
            available=_nmap_available,
            unavailable_message="nmap نصب نیست.",
            run=lambda db, s, args, scope: _run_nmap_os(db, s, args, scope),
            cost="moderate",
        ),
        "arp_scan": ToolSpec(
            name="arp_scan",
            description="کشف دستگاه‌های شبکه‌ی محلی متصل با arp-scan در CIDR مجاز",
            parameters={"target": "string: CIDR محلی مجاز (required)"},
            available=_arp_available,
            unavailable_message="arp-scan نصب نیست.",
            run=lambda db, s, args, scope: _run_arp_scan(db, s, args, scope),
            cost="moderate",
        ),
        "arp_info": ToolSpec(
            name="arp_info",
            description="خواندن MAC/وضعیت یک IP از کش ARP/NDP محلی (بدون ترافیک)",
            parameters={"ip": "string (required)"},
            available=_iproute2_available,
            unavailable_message="دستور ip در دسترس نیست.",
            run=lambda db, s, args, scope: _run_arp_info(db, s, args),
            cost="cheap",
        ),
        "route_info": ToolSpec(
            name="route_info",
            description="مشاهده‌ی گیت‌وی پیش‌فرض و شبکه‌های متصل (فقط خواندنی)",
            parameters={},
            available=_iproute2_available,
            unavailable_message="دستور ip در دسترس نیست.",
            run=lambda db, s, args, scope: _run_route_info(db, s, args),
            cost="cheap",
        ),
        "reverse_dns": ToolSpec(
            name="reverse_dns",
            description="جست‌وجوی نام معکوس (PTR) برای یک IP — نتیجه حدسی است",
            parameters={"ip": "string (required)"},
            available=_nmap_available,
            unavailable_message="nmap نصب نیست.",
            run=lambda db, s, args, scope: _run_reverse_dns(db, s, args, scope),
            cost="cheap",
        ),
        "suricata_alerts": ToolSpec(
            name="suricata_alerts",
            description="واکشی هشدارهای Suricata با فیلتر IP/شدت/امضا/بازه",
            parameters={
                "ip": "string optional", "severity": "int optional (0-10)",
                "signature_id": "int optional", "since_minutes": "int optional",
                "limit": "int optional (<=50)",
            },
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_alerts(db, s, args),
            cost="cheap",
        ),
        "suricata_events": ToolSpec(
            name="suricata_events",
            description="واکشی رویدادهای Suricata (dns/tls/flow/http/anomaly) با فیلتر",
            parameters={
                "ip": "string optional", "event_type": "string optional",
                "since_minutes": "int optional", "limit": "int optional (<=50)",
            },
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_events(db, s, args),
            cost="cheap",
        ),
        "host_history": ToolSpec(
            name="host_history",
            description="تاریخچه‌ی رویدادها، بررسی‌ها و آخرین fingerprint یک میزبان",
            parameters={"ip": "string (required)"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_history(db, s, args),
            cost="cheap",
        ),
        "host_timeline": ToolSpec(
            name="host_timeline",
            description="خط زمانی یکپارچه‌ی میزبان: رویدادها + بررسی‌ها + fingerprint‌ها",
            parameters={"ip": "string (required)", "limit": "int optional"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_timeline(db, s, args),
            cost="cheap",
        ),
        "host_fingerprint": ToolSpec(
            name="host_fingerprint",
            description=(
                "شناسایی کامل میزبان: OS/سرویس/MAC/PTR با ثبت تاریخچه؛ "
                "در نبود دسترسی raw-packet به‌صورت غیرمجاز و شفاف کاهش می‌یابد"
            ),
            parameters={
                "target": "string: IP میزبان مجاز (required)",
                "os_detect": "bool optional (default true)",
            },
            available=_nmap_available,
            unavailable_message="nmap نصب نیست؛ fingerprint محدود می‌شود.",
            run=lambda db, s, args, scope: _run_fingerprint(db, s, args, scope),
            cost="expensive",
        ),
        "fingerprint_history": ToolSpec(
            name="fingerprint_history",
            description="تاریخچه‌ی fingerprint یک میزبان و تغییرات بین دو نمونه‌ی آخر",
            parameters={"ip": "string (required)"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_fingerprint_history(db, s, args),
            cost="cheap",
        ),
        "pcap_summary": ToolSpec(
            name="pcap_summary",
            description="تحلیل آفلاین متادیتای یک فایل PCAP با tshark (بدون ضبط زنده)",
            parameters={"path": "string (required): مسیر فایل .pcap/.pcapng"},
            available=_tshark_available,
            unavailable_message="tshark نصب نیست.",
            run=lambda db, s, args, scope: _run_pcap(db, s, args),
            cost="moderate",
        ),
        "endpoint_inventory": ToolSpec(
            name="endpoint_inventory",
            description=(
                "آخرین inventory گزارش‌شده‌ی عامل نقطه‌پایان برای یک IP یا agent_id "
                "(فقط خواندنی؛ داده‌ی خود-گزارش‌شده است، نه fingerprint شبکه)"
            ),
            parameters={
                "ip": "string optional: IP میزبان برای یافتن عامل آن",
                "agent_id": "string optional: شناسه‌ی مستقیم عامل",
            },
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_endpoint_inventory(db, s, args),
            cost="cheap",
        ),
        "endpoint_status": ToolSpec(
            name="endpoint_status",
            description="وضعیت active/stale عوامل ثبت‌شده‌ی نقطه‌پایان (فقط خواندنی)",
            parameters={"limit": "int optional (<=100)"},
            available=lambda s: True,
            unavailable_message="",
            run=lambda db, s, args, scope: _run_endpoint_status(db, s, args),
            cost="cheap",
        ),
    }


def tool_catalog_docs(registry: dict[str, ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "parameters": t.parameters,
            "cost": t.cost,
        }
        for t in registry.values()
    ]


def execute_tool(
    registry: dict[str, ToolSpec],
    db: Database | None,
    settings: Settings,
    tool_name: str,
    args: dict[str, Any],
    scope: ToolScope | None = None,
) -> dict[str, Any]:
    """Validate and execute one tool request. Never raises; errors come back
    as structured results the model can read."""
    spec = registry.get(tool_name)
    if spec is None or tool_name.startswith("_") or "\x00" in tool_name:
        return {"ok": False, "error": f"ابزار ناشناخته است: {tool_name!r}"}
    if not spec.available(settings):
        result = {"ok": False, "error": spec.unavailable_message,
                  "unavailable": True}
        result["tool"] = tool_name
        return result
    effective_scope = scope or ToolScope(settings=settings, extra_targets=[])
    try:
        result = spec.run(db, settings, args or {}, effective_scope)
    except TargetNotAuthorized as exc:
        result = {"ok": False, "unauthorized": True, "error": str(exc)}
    except (ValueError, TypeError) as exc:
        result = {"ok": False, "error": f"آرگومان نامعتبر: {exc}"}
    except Exception as exc:  # defensive: never leak a crash into the loop
        result = {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"[:300]}
    result.setdefault("tool", tool_name)
    if db is not None:
        db.record_diagnostic(
            tool_name,
            str(args.get("target") or args.get("host") or args.get("ip")
                or args.get("cidr") or ""),
            args, bool(result.get("ok")), result, result.get("error"),
        )
    return result
