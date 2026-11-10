"""Host OS / device fingerprinting.

Aggregates evidence from multiple unprivileged sources and persists a
fingerprint record with an explicit confidence level and provenance labels:

- ``observed``  : directly measured (MAC, open port, banner, PTR name)
- ``inferred``  : tool-generated inference (nmap OS match, service-based OS
                  family guess, vendor from MAC prefix)
- ``unknown``   : not determinable from current evidence

The subsystem never invents OS versions or device types; if evidence only
supports a broad classification, only the broad classification is recorded.
"""

from __future__ import annotations

from typing import Any

from netagent.collectors import system_info
from netagent.config import Settings
from netagent.database import Database

# Service hints for broad OS-family inference. These are *weak* signals and
# always labeled as inferred with low/medium confidence.
_SERVICE_OS_HINTS: dict[str, dict[str, Any]] = {
    "ms-wbt-server": {"os_family": "Windows", "note": "RDP (3389) باز است"},
    "microsoft-ds": {"os_family": "Windows", "note": "SMB (445) باز است"},
    "netbios-ssn": {"os_family": "Windows", "note": "NetBIOS باز است"},
    "windows": {"os_family": "Windows", "note": "سرویس با نام windows"},
    "ssh": {"os_family": None, "note": "SSH مستقل از خانواده‌ی OS است"},
}


def _normalize_os_match(os_matches: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the highest-accuracy nmap OS match, if any."""
    if not os_matches:
        return None

    def _acc(m: dict[str, Any]) -> float:
        try:
            return float(m.get("accuracy") or 0)
        except (TypeError, ValueError):
            return 0.0

    best = max(os_matches, key=_acc)
    if _acc(best) <= 0:
        return None
    osclass = (best.get("osclasses") or [{}])[0]
    return {
        "os_family": osclass.get("osfamily") or None,
        "os_version": osclass.get("osgen") or None,
        "device_type": osclass.get("type") or None,
        "vendor": osclass.get("vendor") or None,
        "accuracy": best.get("accuracy"),
        "match_name": best.get("name"),
        "provenance": "inferred:nmap_os",
    }


def _service_family_inference(hosts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Very broad OS-family hints from detected services (never versions)."""
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            svc = port.get("service") or {}
            name = (svc.get("name") or "").lower()
            product = (svc.get("product") or "").lower()
            for hint_key, hint in _SERVICE_OS_HINTS.items():
                if hint["os_family"] and hint_key in name or hint_key in product:
                    return {
                        "os_family": hint["os_family"],
                        "provenance": "inferred:services",
                        "note": hint["note"],
                        "port": port.get("port"),
                    }
            if "linux" in product or "ubuntu" in product or "debian" in product:
                return {"os_family": "Linux",
                        "provenance": "inferred:services",
                        "note": f"بنر سرویس: {svc.get('product')}",
                        "port": port.get("port")}
            if "bsd" in product:
                return {"os_family": "BSD",
                        "provenance": "inferred:services",
                        "note": f"بنر سرویس: {svc.get('product')}",
                        "port": port.get("port")}
    return None


def build_fingerprint_record(
    ip: str,
    *,
    os_result: dict[str, Any] | None = None,
    service_result: dict[str, Any] | None = None,
    arp_result: dict[str, Any] | None = None,
    rdns_result: dict[str, Any] | None = None,
    availability: str | None = None,
    protocols: list[str] | None = None,
    source: str = "agent",
) -> dict[str, Any]:
    """Merge raw tool results into one labeled fingerprint record."""
    evidence: list[dict[str, Any]] = []
    methods: list[str] = []

    record: dict[str, Any] = {
        "ip": ip,
        "os_family": None,
        "os_version": None,
        "device_type": None,
        "hostname": None,
        "hostname_source": None,
        "mac": None,
        "mac_vendor": None,
        "mac_randomized": None,
        "open_ports": [],
        "services": [],
        "protocols": protocols or [],
        "availability": availability,
        "confidence": "unknown",
        "confidence_explanation": "",
        "source": source,
    }

    # --- OS evidence (nmap -O) — strongest, but needs privileges ------------
    if os_result is not None:
        if os_result.get("capability_required"):
            evidence.append({
                "kind": "capability",
                "label": "observed",
                "text": (
                    f"تشخیص OS با nmap اجرا نشد: {os_result.get('capability_required')} "
                    "نیاز است. آزمایش جایگزین شده است."
                ),
            })
            methods.append("nmap_os_unavailable")
        else:
            match = _normalize_os_match(os_result.get("os_matches") or [])
            if match:
                record["os_family"] = match["os_family"]
                record["os_version"] = match["os_version"]
                record["device_type"] = match["device_type"]
                evidence.append({
                    "kind": "os", "label": "inferred",
                    "text": (
                        f"تطابق انگشت‌نگاری nmap: «{match['match_name']}» "
                        f"(دقت {match['accuracy']}%)، خانواده "
                        f"{match['os_family']} {match['os_version'] or ''}"
                    ),
                })
                methods.append("nmap_os")
            else:
                evidence.append({
                    "kind": "os", "label": "unknown",
                    "text": "nmap -O اجرا شد اما تطابق قابل‌اعتمادی برنگرداند.",
                })
                methods.append("nmap_os_no_match")

    # --- Service evidence (nmap -sV) ----------------------------------------
    if service_result is not None:
        for host in service_result.get("hosts", []):
            for addr in host.get("addresses", []):
                if addr.get("type") == "mac" and addr.get("addr") and not record["mac"]:
                    record["mac"] = addr["addr"]
                    record["mac_vendor"] = addr.get("vendor") or system_info.mac_vendor(addr["addr"])
                    record["mac_randomized"] = system_info.is_randomized_mac(addr["addr"])
                    evidence.append({
                        "kind": "mac", "label": "observed",
                        "text": f"MAC مشاهده شد: {record['mac']}",
                    })
            for hn in host.get("hostnames", []):
                if hn.get("name") and not record["hostname"]:
                    record["hostname"] = hn["name"]
                    record["hostname_source"] = hn.get("type") or "nmap"
                    evidence.append({
                        "kind": "hostname", "label": "observed",
                        "text": f"نام میزبان از nmap: {hn['name']} (نوع: {hn.get('type')})",
                    })
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    record["open_ports"].append(port.get("port"))
                    svc = port.get("service") or {}
                    svc_info = {
                        "port": port.get("port"),
                        "name": svc.get("name"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "method": svc.get("method"),
                        "conf": svc.get("conf"),
                    }
                    # version/method=table is a port-table guess, not observed
                    svc_info["version_source"] = (
                        "inferred:port_table"
                        if svc.get("method") == "table" else "observed:probe"
                    )
                    record["services"].append(svc_info)
                    evidence.append({
                        "kind": "service", "label": "observed",
                        "text": (
                            f"پورت {port.get('port')}/TCP باز؛ سرویس "
                            f"{svc.get('name') or 'نامشخص'} "
                            f"{svc.get('product') or ''} {svc.get('version') or ''}"
                        ),
                    })
            if host.get("status") and not record["availability"]:
                record["availability"] = host["status"]
        if service_result.get("ok"):
            methods.append("nmap_services")
        family_hint = _service_family_inference(service_result.get("hosts", []))
        if family_hint and not record["os_family"]:
            record["os_family"] = family_hint["os_family"]
            evidence.append({
                "kind": "os", "label": "inferred",
                "text": (
                    f"خانواده‌ی OS به‌صورت حدسی از سرویس‌ها: "
                    f"{family_hint['os_family']} ({family_hint.get('note', '')})"
                ),
            })

    # --- ARP evidence --------------------------------------------------------
    if arp_result is not None:
        if arp_result.get("mac"):
            record["mac"] = record["mac"] or arp_result["mac"]
            record["mac_vendor"] = record["mac_vendor"] or arp_result.get("mac_vendor")
            record["mac_randomized"] = (
                record["mac_randomized"]
                if record["mac_randomized"] is not None
                else arp_result.get("mac_randomized")
            )
            evidence.append({
                "kind": "arp", "label": "observed",
                "text": (
                    f"ARP: MAC {arp_result['mac']} "
                    f"(سازنده: {record['mac_vendor'] or 'ناشناخته'}"
                    + ("; احتمالاً MAC تصادفی‌شده" if arp_result.get("mac_randomized") else "")
                    + f"، وضعیت: {arp_result.get('state')})"
                ),
            })
            methods.append("arp_info")
        elif arp_result.get("cache_entry") is False:
            evidence.append({
                "kind": "arp", "label": "unknown",
                "text": "ردیفی در کش ARP برای این IP نبود.",
            })

    # --- Reverse DNS ----------------------------------------------------------
    if rdns_result is not None and rdns_result.get("hostname"):
        if not record["hostname"]:
            record["hostname"] = rdns_result["hostname"]
            record["hostname_source"] = "rdns"
        evidence.append({
            "kind": "rdns", "label": "observed",
            "text": f"نام معکوس (PTR): {rdns_result['hostname']} — حدسی، نه تأییدشده.",
        })
        methods.append("reverse_dns")

    # --- Confidence -------------------------------------------------------------
    nmap_os_ok = "nmap_os" in methods
    services_open = bool(record["services"])
    if nmap_os_ok and record["os_family"]:
        record["confidence"] = "high"
        record["confidence_explanation"] = (
            "تطابق مستقیم انگشت‌نگاری nmap با دقت بالا؛ همچنان پیش‌بینی است نه تأیید."
        )
    elif record["os_family"]:
        record["confidence"] = "medium"
        record["confidence_explanation"] = (
            "خانواده‌ی OS از سرویس‌ها/بنرها حدس زده شد؛ نسخه و توزیع دقیق نامشخص است."
        )
    elif services_open or record["mac"] or record["hostname"]:
        record["confidence"] = "low"
        record["confidence_explanation"] = (
            "شناسایی سرویس/سخت‌افزار انجام شد اما سیستم‌عامل قابل‌تعیین نبود."
        )
    else:
        record["confidence"] = "unknown"
        record["confidence_explanation"] = (
            "شواهد کافی برای شناسایی سیستم‌عامل وجود ندارد."
        )

    record["methods"] = methods
    record["evidence"] = evidence
    return record


def fingerprint_host(
    db: Database,
    settings: Settings,
    ip: str,
    *,
    include_os_detect: bool = True,
    save: bool = True,
) -> dict[str, Any]:
    """Run the full unprivileged fingerprint pipeline for one host."""
    from netagent.collectors import nmap as nmap_collector
    from netagent.scope import ToolScope

    ip = ToolScope(settings, []).authorize(ip, host_only=True)

    arp_result = system_info.arp_info(ip)
    rdns_result = system_info.reverse_dns(ip)
    os_result = None
    service_result = None
    availability = None

    if include_os_detect:
        os_result = nmap_collector.os_detect(settings, ip)
        # OS detection also opens the ports; reuse it as service evidence when
        # it succeeded so we don't scan twice.
        if os_result.get("ok"):
            service_result = {"ok": True, "hosts": os_result.get("hosts", [])}
        else:
            service_result = nmap_collector.port_service_scan(settings, ip)

    if service_result and service_result.get("hosts"):
        for h in service_result["hosts"]:
            if h.get("status") == "up":
                availability = "up"
                break
    if availability is None and arp_result.get("state"):
        availability = "up"

    record = build_fingerprint_record(
        ip,
        os_result=os_result,
        service_result=service_result,
        arp_result=arp_result,
        rdns_result=rdns_result,
        availability=availability,
        source="fingerprint_host",
    )

    # protocols observed from Suricata history
    summary = db.host_event_summary(ip)
    protocols = sorted((summary.get("event_counts_24h") or {}).keys())
    record["protocols"] = protocols

    if save:
        db.save_fingerprint(record)
    record["latest_saved"] = save
    record["os_detect_attempted"] = include_os_detect
    return record
