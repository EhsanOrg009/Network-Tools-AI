"""Local FastAPI routes (v2).

Backward compatible with the MVP endpoints. New capabilities:
- host discovery, fingerprint history, host timeline
- capability report for diagnostic tools
- background investigation jobs (API never blocks on long LLM runs)

Active diagnostics are authorized by the configured scope only; there are no
per-tool feature flags. All endpoints share the same target-validation and
timeout logic as the CLI and the agent tool registry.

Every endpoint carries Persian OpenAPI metadata (summary/description/
examples). Example values below are *illustrative* only — they are not
runtime data of any particular machine.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Body, HTTPException, Path, Query, Request

from netagent.agent.tools import (
    ToolScope,
    build_registry,
    execute_tool,
    tool_catalog_docs,
)
from netagent.collectors import nmap as nmap_collector
from netagent.collectors.nmap import TargetNotAuthorized
from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import InvestigationRequest, ScanRequest
from netagent.services.investigations import run_investigation

router = APIRouter()

# ---------------------------------------------------------------------------
# OpenAPI helpers (Persian docs; examples are illustrative, not runtime data)
# ---------------------------------------------------------------------------

# Persian message raised by ToolScope.authorize (investigations, tool calls).
_ERR_403_OUT_OF_SCOPE = {
    "value": {
        "detail": (
            "target 8.8.8.8/32 خارج از محدوده‌ی مجاز است؛ scope پیکربندی‌شده: "
            "{'cidrs': ['192.168.1.0/24'], 'authorized_targets': []}"
        )
    }
}

# English message raised by the nmap collector's TargetNotAuthorized (scans).
_ERR_403_OUT_OF_SCOPE_EN = {
    "value": {
        "detail": (
            "target 8.8.8.8/32 outside authorized scope (MONITOR_CIDRS/"
            "AUTHORIZED_TARGETS): {'cidrs': ['192.168.1.0/24'], 'authorized_targets': []}"
        )
    }
}

# Realistic FastAPI validation failure as produced by this app's 422s.
_ERR_422_VALIDATION = {
    "summary": "پارامتر یا فیلد نامعتبر",
    "value": {
        "detail": [
            {
                "type": "less_than_equal",
                "loc": ["query", "limit"],
                "msg": "Input should be less than or equal to 500",
                "input": "9999",
                "ctx": {"le": 500},
            }
        ]
    },
}

# Semantic 422 raised explicitly by the investigation endpoints.
_ERR_422_MISSING_TARGET = {
    "summary": "بدون target_ip و alert_id",
    "value": {"detail": "target_ip or alert_id required"},
}


def _responses(
    description: str,
    example: Any,
    *,
    not_found: str | None = None,
    not_found_detail: str = "not found",
    forbidden: bool = False,
    forbidden_example: dict[str, Any] | None = None,
    validation: bool = False,
    extra_422_examples: dict[str, dict[str, Any]] | None = None,
) -> dict[int, Any]:
    """Build the ``responses`` OpenAPI dict: one 200 example plus applicable
    error responses. Keeps documentation next to the real contract."""
    responses: dict[int, Any] = {
        200: {
            "description": description,
            "content": {
                "application/json": {
                    "examples": {"default": {"value": example}},
                }
            },
        }
    }
    if not_found:
        responses[404] = {
            "description": not_found,
            "content": {
                "application/json": {
                    "examples": {"default": {"value": {"detail": not_found_detail}}}
                }
            },
        }
    if forbidden:
        responses[403] = {
            "description": "هدف خارج از محدوده‌ی مجاز (scope) است.",
            "content": {
                "application/json": {
                    "examples": forbidden_example or _ERR_403_OUT_OF_SCOPE
                }
            },
        }
    if validation:
        examples: dict[str, dict[str, Any]] = {"validation": _ERR_422_VALIDATION}
        if extra_422_examples:
            examples.update(extra_422_examples)
        responses[422] = {
            "description": (
                "ورودی نامعتبر است؛ پارامترهای مسیر/کوئری یا فیلدهای بدنه‌ی "
                "درخواست اعتبارسنجی نشده‌اند و `detail` شرح هر خطا را می‌دهد."
            ),
            "content": {"application/json": {"examples": examples}},
        }
    return responses


def _ctx(request: Request) -> tuple[Database, Settings, Any]:
    return request.app.state.db, request.app.state.settings, request.app.state.llm


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    tags=["سلامت سیستم"],
    summary="دریافت وضعیت سلامت برنامه",
    description=(
        "وضعیت کلی برنامه (`ok` یا `degraded`) و جزئیات هر جزء را برمی‌گرداند: "
        "آمار پایگاه داده، خوانایی `eve.json`، دسترسی به LLM محلی، "
        "قابلیت‌های ابزارها (nmap و arp-scan و tshark و …)، محدوده‌ی مجاز "
        "(scope) و بودجه‌ی بررسی. برای چک سریع پیش از هر عملیات دیگر مناسب است."
    ),
    responses=_responses(
        "وضعیت سلامت اجزای برنامه؛ مقدار status یا ok است یا degraded.",
        {
            "status": "ok",
            "components": {
                "database": {
                    "ok": True,
                    "path": "data/netagent.sqlite3",
                    "stats": {"events": 5200, "alerts": 35, "hosts": 160, "investigations": 9},
                },
                "suricata": {
                    "eve_path": "/var/log/suricata/eve.json",
                    "file_readable": True,
                    "consecutive_errors": 0,
                    "ok": True,
                },
                "llm": {
                    "ok": True,
                    "detail": "reachable",
                    "base_url": "http://127.0.0.1:11964/v1",
                    "model": "gemma-4-e2b-it-q4_0--2-:latest",
                },
                "monitor_thread": {"ok": True, "running": True},
                "endpoint_agents": {
                    "ok": True,
                    "active": 3,
                    "stale": 1,
                    "revoked": 0,
                    "total": 4,
                    "heartbeat_timeout_seconds": 180,
                },
                "diagnostics": {
                    "policy": "all non-destructive tools enabled by default; scope-gated",
                    "capabilities": {
                        "nmap": True, "arp_scan": True, "tshark": True,
                        "iproute2": True, "ping": True,
                    },
                    "scope": {
                        "cidrs": ["192.168.1.0/24"],
                        "authorized_targets": [],
                    },
                    "auto_discovery": {
                        "enabled": True,
                        "eligible_networks": [
                            {"cidr": "10.20.0.0/24", "reporting_agents": 2}
                        ],
                    },
                    "budget": {
                        "max_tool_calls": 10,
                        "deadline_seconds": 900.0,
                    },
                },
            },
            "version": "0.2.0",
        },
    ),
)
def health(request: Request) -> dict[str, Any]:
    db, settings, _ = _ctx(request)
    monitor = request.app.state.monitor
    from netagent.api.health import build_health

    running = bool(monitor and monitor._thread and monitor._thread.is_alive())
    return build_health(db, settings, monitor.health() if monitor else {}, running)


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/hosts",
    tags=["میزبان‌ها و شبکه"],
    summary="دریافت فهرست میزبان‌های شناسایی‌شده",
    description=(
        "میزبان‌هایی که در رویدادها یا بررسی‌ها دیده شده‌اند، مرتب‌شده بر اساس "
        "آخرین مشاهده. هر ردیف شامل IP، نام میزبان (در صورت شناخت)، MAC و "
        "زمان اولین/آخرین مشاهده است. این فهرست فقط داده‌ی ذخیره‌شده است و "
        "اسکن جدیدی اجرا نمی‌کند."
    ),
    responses=_responses(
        "فهرست میزبان‌ها با صفحه‌بندی. مقادیر نمونه صرفاً illustrative هستند.",
        {
            "items": [
                {
                    "ip": "192.168.1.10",
                    "hostname": None,
                    "mac": "d8:96:95:11:22:33",
                    "first_seen": "2026-10-28T09:15:00+0330",
                    "last_seen": "2026-10-28T12:40:00+0330",
                }
            ]
        },
        validation=True,
    ),
)
def list_hosts(
    request: Request,
    limit: int = Query(
        100, ge=1, le=500,
        description="حداکثر تعداد ردیف برگشتی (۱ تا ۵۰۰). پیش‌فرض 100.",
    ),
    offset: int = Query(
        0, ge=0,
        description="تعداد ردیف‌های صرف‌نظرشده برای صفحه‌بندی. پیش‌فرض 0.",
    ),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    return {"items": db.list_hosts(limit=limit, offset=offset)}


@router.get(
    "/api/hosts/{ip}/timeline",
    tags=["میزبان‌ها و شبکه"],
    summary="دریافت خط زمانی یکپارچه‌ی یک میزبان",
    description=(
        "سه منبع تاریخچه برای یک IP را یکجا برمی‌گرداند: رویدادهای Suricata، "
        "نتایج بررسی‌های اجراشده (ping و tcp و …) و fingerprint‌های ثبت‌شده. "
        "برای مرور گذشته‌ی یک میزبان قبل از شروع بررسی جدید مناسب است."
    ),
    responses=_responses(
        "خط زمانی میزبان شامل سه آرایه؛ اگر هر سه خالی باشند 404.",
        {
            "ip": "192.168.1.10",
            "events": [
                {
                    "ts": "2026-10-28T12:30:01+0330",
                    "event_type": "flow",
                    "flow_id": 2025010101,
                    "src_ip": "192.168.1.10",
                    "src_port": 52311,
                    "dest_ip": "142.250.185.68",
                    "dest_port": 443,
                    "proto": "TCP",
                    "app_proto": "tls",
                }
            ],
            "observations": [
                {
                    "ts": "2026-10-28T12:35:00+0330",
                    "kind": "ping",
                    "success": 1,
                    "detail": {"target": "192.168.1.10", "ok": True},
                }
            ],
            "fingerprints": [
                {
                    "created_at": "2026-10-28T12:36:00+0330",
                    "os_family": None,
                    "os_version": None,
                    "device_type": None,
                    "hostname": None,
                    "mac": "d8:96:95:11:22:33",
                    "confidence": "low",
                }
            ],
        },
        not_found="هیچ تاریخی برای این میزبان ثبت نشده است.",
        not_found_detail="no history for this host",
        validation=True,
    ),
)
def host_timeline(
    request: Request,
    ip: str = Path(
        description="آدرس IPv4 یا IPv6 میزبان؛ همان شکلی که در رویدادها ثبت شده است.",
        examples=["192.168.1.10"],
    ),
    limit: int = Query(
        100, ge=1, le=500,
        description="حداکثر تعداد آیتم هر بخش از خط زمانی. پیش‌فرض 100.",
    ),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    timeline = db.host_timeline(ip, limit=limit)
    if not any([timeline["events"], timeline["observations"], timeline["fingerprints"]]):
        raise HTTPException(status_code=404, detail="no history for this host")
    return timeline


@router.get(
    "/api/hosts/{ip}/fingerprint",
    tags=["میزبان‌ها و شبکه"],
    summary="دریافت آخرین شناسایی (fingerprint) میزبان",
    description=(
        "آخرین نتیجه‌ی شناسایی میزبان را برمی‌گرداند: خانواده‌ی سیستم‌عامل "
        "(پیش‌بینی، نه تأیید)، نام میزبان و منبع آن، MAC و سازنده، پورت‌های باز، "
        "سرویس‌ها، سطح اطمینان و شواهد. با `history=true` تاریخچه و تغییرات "
        "بین دو نمونه‌ی آخر هم اضافه می‌شود. این نقطه‌پایان فقط داده‌ی "
        "ذخیره‌شده می‌خواند؛ برای شناسایی جدید از `POST /api/tools/host_fingerprint` "
        "استفاده کنید."
    ),
    responses=_responses(
        "آخرین fingerprint؛ با history=true آرایه‌ی history و شیء changes هم می‌آید.",
        {
            "latest": {
                "ip": "192.168.1.10",
                "created_at": "2026-10-28T12:36:00+0330",
                "os_family": None,
                "os_version": None,
                "device_type": None,
                "hostname": "printer.local",
                "hostname_source": "rdns",
                "mac": "d8:96:95:11:22:33",
                "mac_vendor": "ASUSTek",
                "mac_randomized": 0,
                "open_ports": [80],
                "services": [{"port": 80, "name": "http", "version_source": "observed:probe"}],
                "protocols": ["dns", "tls"],
                "availability": "up",
                "methods": ["nmap_services", "arp_info", "reverse_dns"],
                "evidence": [
                    {"kind": "arp", "label": "observed", "text": "ARP: MAC d8:96:95:11:22:33"}
                ],
                "confidence": "low",
                "confidence_explanation": "شناسایی سرویس/سخت‌افزار انجام شد اما سیستم‌عامل قابل‌تعیین نبود.",
                "source": "fingerprint_host",
            },
            "history": ["... فهرست همه‌ی fingerprint‌های قبلی همین میزبان (وقتی history=true)"],
            "changes": {
                "changes": [{"field": "open_ports", "old": [80, 443], "new": [80]}],
                "comparisons_available": True,
            },
        },
        not_found="هیچ fingerprint‌ای برای این میزبان ثبت نشده است.",
        not_found_detail="no fingerprint recorded for this host",
        validation=True,
    ),
)
def host_fingerprint(
    request: Request,
    ip: str = Path(
        description="آدرس IPv4 یا IPv6 میزبان.",
        examples=["192.168.1.10"],
    ),
    history: bool = Query(
        False,
        description="اگر true باشد، تاریخچه‌ی کامل و تغییرات (changes) هم برگردانده می‌شود.",
    ),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    latest = db.latest_fingerprint(ip)
    if latest is None:
        raise HTTPException(status_code=404, detail="no fingerprint recorded for this host")
    body: dict[str, Any] = {"latest": latest}
    if history:
        body["history"] = db.fingerprint_history(ip)
        body["changes"] = db.fingerprint_changes(ip)
    return body


@router.get(
    "/api/events",
    tags=["رخدادها و هشدارهای امنیتی"],
    summary="دریافت رویدادهای Suricata با فیلتر",
    description=(
        "رویدادهای ذخیره‌شده‌ی eve.json (بدون payload خام) را با فیلتر نوع، "
        "IP و بازه‌ی زمانی برمی‌گرداند. `total` تعداد کل ردیف‌های منطبق "
        "با فیلتر است؛ صفحه‌بندی با `limit` و `offset` انجام می‌شود. "
        "این نقطه‌پایان فقط می‌خواند و اسکنی اجرا نمی‌کند."
    ),
    responses=_responses(
        "فهرست رویدادها با تعداد کل و پارامترهای صفحه‌بندی.",
        {
            "items": [
                {
                    "id": 5123,
                    "ts": "2026-10-28T12:30:01+0330",
                    "ts_epoch": 1769646601.2,
                    "event_type": "dns",
                    "flow_id": 2025010101,
                    "src_ip": "192.168.1.10",
                    "src_port": 52311,
                    "dest_ip": "142.250.185.68",
                    "dest_port": 443,
                    "proto": "UDP",
                    "app_proto": "dns",
                    "ingress": "wlo1",
                    "created_at": "2026-10-28T12:30:01+0330",
                }
            ],
            "total": 1,
            "limit": 100,
            "offset": 0,
        },
        validation=True,
    ),
)
def list_events(
    request: Request,
    event_type: str | None = Query(
        None,
        description=(
            "نوع رویداد EVE مثل alert یا dns یا tls یا flow یا http یا "
            "anomaly (اختیاری؛ بدون فیلتر همه‌ی انواع)."
        ),
        examples=["dns"],
    ),
    ip: str | None = Query(
        None,
        description="فیلتر بر اساس IP مبدأ یا مقصد (IPv4/IPv6؛ اختیاری).",
        examples=["192.168.1.10"],
    ),
    since: str | None = Query(
        None,
        description="شروع بازه به فرمت ISO 8601 مثل 2026-10-28T08:00:00 (اختیاری).",
        examples=["2026-10-28T08:00:00"],
    ),
    until: str | None = Query(
        None,
        description="پایان بازه به فرمت ISO 8601 (اختیاری).",
        examples=["2026-10-28T12:00:00"],
    ),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف (۱ تا ۵۰۰). پیش‌فرض 100."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی: تعداد ردیف‌های صرف‌نظرشده. پیش‌فرض 0."),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    from netagent.database import parse_iso_epoch

    items, total = db.query_events(
        event_type=event_type,
        ip=ip,
        since_epoch=parse_iso_epoch(since) if since else None,
        until_epoch=parse_iso_epoch(until) if until else None,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get(
    "/api/alerts",
    tags=["رخدادها و هشدارهای امنیتی"],
    summary="دریافت هشدارهای امنیتی با فیلتر",
    description=(
        "هشدارهای تطبیق قانون Suricata را برمی‌گرداند. هر هشدار فقط یعنی "
        "الگویی مشابه قانون دیده شده — اثبات نفوذ نیست؛ `action=allowed` "
        "یعنی بسته عبور کرده و صرفاً هشدار ثبت شده است. با `group_by_flow=true` "
        "تکرار امضا روی یک flow به‌صورت گروهی خلاصه می‌شود و از شمرده‌شدن "
        "تکرارها به‌عنوان چند حمله‌ی مستقل جلوگیری می‌کند."
    ),
    responses=_responses(
        "فهرست هشدارها؛ با group_by_flow=true کلید grouped_by_flow_and_rule هم اضافه می‌شود.",
        {
            "items": [
                {
                    "id": 34,
                    "ts": "2026-10-28T12:31:00+0330",
                    "ts_epoch": 1769646660.0,
                    "flow_id": 2025010101,
                    "src_ip": "192.168.1.10",
                    "src_port": 52311,
                    "dest_ip": "142.250.185.68",
                    "dest_port": 443,
                    "proto": "TCP",
                    "app_proto": "tls",
                    "signature": "SURICATA TLS Obsolete Version",
                    "signature_id": 22000300,
                    "signature_rev": 2,
                    "category": "Not Suspicious Traffic",
                    "severity": 3,
                    "action": "allowed",
                    "metadata_json": "{... متادیتای خام قانون}",
                }
            ],
            "total": 1,
            "limit": 100,
            "offset": 0,
            "note": "هشدار = تطابق قانون؛ اثبات قطعی حمله نیست. action=allowed یعنی بسته عبور کرده.",
            "grouped_by_flow_and_rule": [
                {
                    "flow_id": 2025010101,
                    "signature_id": 22000300,
                    "signature": "SURICATA TLS Obsolete Version",
                    "category": "Not Suspicious Traffic",
                    "severity": 3,
                    "hit_count": 7,
                    "last_seen": "2026-10-28T12:31:00+0330",
                }
            ],
        },
        validation=True,
    ),
)
def list_alerts(
    request: Request,
    q: str | None = Query(None, max_length=200, description="جست‌وجوی متنی در امضا و IP همهٔ هشدارها، پیش از صفحه‌بندی."),
    analysis_status: Literal["PENDING", "PROCESSING", "COMPLETED", "FAILED", "none"] | None = Query(
        None, description="وضعیت تحلیل؛ PENDING شامل ورودی خودکار متوقف و none یعنی بدون درخواست است."),
    include_summary: bool = Query(False, description="تفکیک شدت تمام هشدارهای مطابق فیلتر را اضافه می‌کند؛ فقط خواندنی."),
    ip: str | None = Query(
        None,
        description="فیلتر بر اساس IP مبدأ یا مقصد (IPv4/IPv6؛ اختیاری).",
        examples=["192.168.1.10"],
    ),
    severity: int | None = Query(
        None, ge=0, le=10,
        description="شدت Suricata (۰ تا ۱۰؛ عدد کوچک‌تر یعنی اولویت بالاتر؛ اختیاری).",
        examples=[2],
    ),
    signature_id: int | None = Query(
        None,
        description="شناسه‌ی عددی امضای Suricata (اختیاری).",
        examples=[22000300],
    ),
    since: str | None = Query(
        None, description="شروع بازه به فرمت ISO 8601 (اختیاری).",
        examples=["2026-10-28T08:00:00"],
    ),
    until: str | None = Query(
        None, description="پایان بازه به فرمت ISO 8601 (اختیاری).",
        examples=["2026-10-28T12:00:00"],
    ),
    group_by_flow: bool = Query(
        False,
        description="اگر true باشد، خلاصه‌ی گروه‌بندی‌شده بر اساس flow و امضا هم برگردانده می‌شود.",
    ),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف (۱ تا ۵۰۰). پیش‌فرض 100."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی: تعداد ردیف‌های صرف‌نظرشده. پیش‌فرض 0."),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    from netagent.database import parse_iso_epoch

    filters = dict(ip=ip, severity=severity, signature_id=signature_id,
                   since_epoch=parse_iso_epoch(since) if since else None,
                   until_epoch=parse_iso_epoch(until) if until else None,
                   q=q, analysis_status=analysis_status)
    items, total = db.query_alerts(**filters, limit=limit, offset=offset)
    response: dict[str, Any] = {
        "items": items, "total": total, "limit": limit, "offset": offset,
        "note": "هشدار = تطابق قانون؛ اثبات قطعی حمله نیست. action=allowed یعنی بسته عبور کرده.",
    }
    if group_by_flow:
        response["grouped_by_flow_and_rule"] = db.alert_flow_summary(
            **filters, limit=min(limit, 100)
        )
    if include_summary:
        response["severity_counts"] = db.filtered_alert_severity_counts(**filters)
    return response


@router.get(
    "/api/tools",
    tags=["ابزارها و قابلیت‌ها"],
    summary="دریافت فهرست ابزارهای تشخیصی و محدوده‌ی مجاز",
    description=(
        "همه‌ی ابزارهای تشخیصی ثبت‌شده را با پارامترهای قابل قبول، سطح هزینه، "
        "موجود بودن پیش‌نیازها (مثل نصب بودن nmap) و محدوده‌ی مجاز "
        "(scope) فعلی برمی‌گرداند. پیش از `POST /api/tools/{tool_name}` "
        "برای دیدن نام و پارامترهای ابزار مناسب است."
    ),
    responses=_responses(
        "سیاست فعلی، scope و فهرست ابزارها.",
        {
            "scope": {"cidrs": ["192.168.1.0/24"], "authorized_targets": []},
            "policy": (
                "همه‌ی ابزارهای تشخیصی غیرمخرب به‌صورت پیش‌فرض فعال‌اند؛ تنها "
                "محدودیت، محدوده‌ی مجاز (scope) و موجود بودن پیش‌نیازهاست."
            ),
            "tools": [
                {
                    "name": "nmap_services",
                    "description": "کشف پورت/سرویس و نسخه (-sT -sV سبک) روی یک میزبان مجاز؛ فهرست پورت‌ها محدود است",
                    "parameters": {
                        "target": "string: IP میزبان مجاز (required)",
                        "ports": "list[int] optional (حداکثر NMAP_MAX_PORTS)",
                        "service_detection": "bool optional (default true)",
                    },
                    "cost": "moderate",
                    "available": True,
                    "prerequisite_message": None,
                }
            ],
        },
    ),
)
def list_tools(request: Request) -> dict[str, Any]:
    _, settings, _ = _ctx(request)
    registry = build_registry(settings)
    from netagent.config import binary_available
    return {
        "scope": settings.scope_description(),
        "policy": (
            "همه‌ی ابزارهای تشخیصی غیرمخرب به‌صورت پیش‌فرض فعال‌اند؛ تنها "
            "محدودیت، محدوده‌ی مجاز (scope) و موجود بودن پیش‌نیازهاست."
        ),
        "tools": [
            {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
                "cost": spec.cost,
                "available": spec.available(settings),
                "prerequisite_message": spec.unavailable_message or None,
            }
            for spec in registry.values()
        ],
    }


# ---------------------------------------------------------------------------
# Investigations (sync + background jobs)
# ---------------------------------------------------------------------------


@router.get(
    "/api/investigations",
    tags=["بررسی‌های هوشمند"],
    summary="دریافت فهرست بررسی‌های انجام‌شده",
    description=(
        "خلاصه‌ی بررسی‌های گذشته را از جدید به قدیمی برمی‌گرداند (وضعیت، هدف، "
        "پرسش، سطح اطمینان، تعداد فراخوانی ابزار). گزارش کامل هر بررسی را "
        "با `GET /api/investigations/{inv_id}` بگیرید."
    ),
    responses=_responses(
        "فهرست خلاصه‌ی بررسی‌ها با صفحه‌بندی.",
        {
            "items": [
                {
                    "id": 9,
                    "created_at": "2026-10-28T12:40:00+0330",
                    "finished_at": "2026-10-28T12:43:12+0330",
                    "trigger": "host",
                    "target_ip": "192.168.1.10",
                    "question": "چرا این میزبان پاسخ نمی‌دهد؟",
                    "status": "completed",
                    "confidence": "low",
                    "iterations": 2,
                    "error": None,
                }
            ]
        },
        validation=True,
    ),
)
def list_investigations(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="حداکثر تعداد ردیف (۱ تا ۲۰۰). پیش‌فرض 50."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی: تعداد ردیف‌های صرف‌نظرشده. پیش‌فرض 0."),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    return {"items": db.list_investigations(limit=limit, offset=offset)}


@router.get(
    "/api/investigations/{inv_id}",
    tags=["بررسی‌های هوشمند"],
    summary="دریافت جزئیات کامل یک بررسی",
    description=(
        "رکورد کامل یک بررسی را برمی‌گرداند: شواهد گردآوری‌شده، گزارش فارسی "
        "۱۲ بخشی به‌صورت متن (`report_text`) و ساختار (`report`) و وضعیت. "
        "شناسه را از `GET /api/investigations` بگیرید."
    ),
    responses=_responses(
        "رکورد کامل بررسی شامل report و report_text و evidence.",
        {
            "id": 9,
            "created_at": "2026-10-28T12:40:00+0330",
            "finished_at": "2026-10-28T12:43:12+0330",
            "trigger": "host",
            "target_ip": "192.168.1.10",
            "question": "چرا این میزبان پاسخ نمی‌دهد؟",
            "status": "completed",
            "confidence": "low",
            "iterations": 2,
            "error": None,
            "evidence": {"target_ip": "192.168.1.10", "database_stats": {"events": 5200}},
            "report": {
                "summary": "خلاصه‌ی گزارش...",
                "host_status": "up",
                "observed_facts": ["ping پاسخ داد"],
                "confidence": {"level": "low", "explanation": "شواهد محدود"},
            },
            "report_text": "## خلاصه مدیریتی\nگزارش فارسی کامل...",
        },
        not_found="بررسی‌ای با این شناسه وجود ندارد.",
        not_found_detail="investigation not found",
        validation=True,
    ),
)
def get_investigation(
    request: Request,
    inv_id: int = Path(description="شناسه‌ی عددی بررسی.", examples=[9]),
) -> dict[str, Any]:
    db, _, _ = _ctx(request)
    record = db.get_investigation(inv_id)
    if record is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return record


def _validated_target_or_none(target_ip: str | None, settings: Settings, db) -> str | None:
    """Validate a user-supplied target against the configured scope (extended
    by policy-eligible auto-discovered networks when db is given).

    User-facing endpoints must not auto-authorize arbitrary targets: only
    MONITOR_CIDRS + AUTHORIZED_TARGETS (+ eligible discovered networks) count
    here. (The orchestrator may additionally authorize the subject of an
    alert-focused investigation, but a direct API target request is rejected
    when outside the scope.)
    """
    if not target_ip:
        return None
    scope = ToolScope(settings=settings, extra_targets=[], db=db)
    try:
        return scope.authorize(target_ip)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post(
    "/api/investigations",
    tags=["بررسی‌های هوشمند"],
    summary="اجرای بررسی هوشمند همگام",
    description=(
        "یک بررسی خودکار چندمرحله‌ای را روی میزبان یا هشدار مشخص اجرا می‌کند "
        "و رکورد کامل آن (شامل گزارش فارسی) را برمی‌گرداند. **توجه:** این "
        "فراخوانی تا پایان بررسی مسدود می‌شود (با LLM محلی ممکن است چند دقیقه "
        "طول بکشد)؛ برای بررسی‌های طولانی از `POST /api/jobs/investigation` "
        "استفاده کنید. حداقل یکی از `target_ip` یا `alert_id` لازم است. هدف "
        "باید داخل محدوده‌ی مجاز باشد."
    ),
    responses=_responses(
        "رکورد کامل بررسی (همان ساختار GET /api/investigations/{inv_id}).",
        {
            "id": 9,
            "created_at": "2026-10-28T12:40:00+0330",
            "finished_at": "2026-10-28T12:43:12+0330",
            "trigger": "host",
            "target_ip": "192.168.1.10",
            "question": "چرا این میزبان پاسخ نمی‌دهد؟",
            "status": "completed",
            "confidence": "low",
            "iterations": 2,
            "error": None,
            "evidence": {"target_ip": "192.168.1.10"},
            "report": {"summary": "خلاصه‌ی گزارش..."},
            "report_text": "## خلاصه مدیریتی\nگزارش فارسی کامل...",
        },
        forbidden=True,
        validation=True,
        extra_422_examples={"missing_target": _ERR_422_MISSING_TARGET},
    ),
    openapi_extra={
        "requestBody": {"content": {"application/json": {"examples": {
            "host_inquiry": {
                "summary": "بررسی یک میزبان با اجرای ping",
                "value": {
                    "target_ip": "192.168.1.10",
                    "question": "چرا این میزبان به ping پاسخ نمی‌دهد؟",
                    "run_ping": True,
                },
            },
            "alert_inquiry": {
                "summary": "بررسی متمرکز روی یک هشدار ثبت‌شده",
                "value": {
                    "alert_id": 12,
                    "question": "این هشدار چه چیزی را نشان می‌دهد؟",
                },
            },
        }}}},
    },
)
def create_investigation(
    request: Request, body: InvestigationRequest
) -> dict[str, Any]:
    """Synchronous investigation (kept for CLI/simple clients). For long runs
    prefer POST /api/jobs/investigation which never blocks the caller."""
    db, settings, llm = _ctx(request)
    if body.alert_id is None and not body.target_ip:
        raise HTTPException(status_code=422, detail="target_ip or alert_id required")
    # explicit user-supplied target => authorized for this investigation
    _validated_target_or_none(body.target_ip, settings, db)
    record = run_investigation(
        db, settings, llm,
        target_ip=body.target_ip,
        alert_id=body.alert_id,
        question=body.question,
        run_ping=body.run_ping,
    )
    return record


@router.post(
    "/api/jobs/investigation",
    tags=["بررسی‌های هوشمند"],
    summary="شروع بررسی هوشمند به‌صورت کار پس‌زمینه",
    description=(
        "بررسی را در یک کار پس‌زمینه شروع می‌کند و بلافاصله `job_id` "
        "برمی‌گرداند؛ فراخوانی‌کننده مسدود نمی‌شود. وضعیت و نتیجه را با "
        "`GET /api/jobs/{job_id}` دنبال کنید. همان بدنه و همان قواعد "
        "بررسی همگام: حداقل یکی از `target_ip` یا `alert_id` و هدف داخل "
        "محدوده‌ی مجاز."
    ),
    responses=_responses(
        "شناسه‌ی کار برای پیگیری وضعیت.",
        {
            "job_id": "28ff9e256927",
            "status": "queued",
            "poll": "GET /api/jobs/28ff9e256927",
        },
        forbidden=True,
        validation=True,
        extra_422_examples={"missing_target": _ERR_422_MISSING_TARGET},
    ),
    openapi_extra={
        "requestBody": {"content": {"application/json": {"examples": {
            "host_inquiry": {
                "summary": "بررسی پس‌زمینه‌ی یک میزبان با اجرای ping",
                "value": {
                    "target_ip": "192.168.1.10",
                    "question": "چرا این میزبان به ping پاسخ نمی‌دهد؟",
                    "run_ping": True,
                },
            },
            "alert_inquiry": {
                "summary": "بررسی پس‌زمینه‌ی متمرکز روی یک هشدار ثبت‌شده",
                "value": {
                    "alert_id": 12,
                    "question": "این هشدار چه چیزی را نشان می‌دهد؟",
                },
            },
        }}}},
    },
)
def submit_investigation_job(
    request: Request, body: InvestigationRequest
) -> dict[str, Any]:
    db, settings, llm = _ctx(request)
    if body.alert_id is None and not body.target_ip:
        raise HTTPException(status_code=422, detail="target_ip or alert_id required")
    _validated_target_or_none(body.target_ip, settings, db)

    def _run() -> dict[str, Any]:
        return run_investigation(
            db, settings, llm,
            target_ip=body.target_ip,
            alert_id=body.alert_id,
            question=body.question,
            run_ping=body.run_ping,
        )

    from netagent.services.jobs import JobQueueFull
    try:
        job_id = request.app.state.jobs.submit("investigation", _run)
    except JobQueueFull as exc:
        raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"}) from exc
    return {"job_id": job_id, "status": "queued",
            "poll": f"GET /api/jobs/{job_id}"}


@router.post(
    "/api/jobs/{job_id}/cancel", tags=["بررسی‌های هوشمند"], summary="لغو کار پس‌زمینه",
    description="مدیر می‌تواند کار صف‌شده یا در حال اجرا را لغو کند؛ اجرای بومی جاری به‌صورت محدود پایان می‌یابد و مرحلهٔ تازه شروع نمی‌شود.",
    responses=_responses("وضعیت واقعی کار پس از درخواست لغو.", {"id": "example", "status": "cancelled"},
                         not_found="کار یافت نشد.", not_found_detail="job not found", validation=True),
)
def cancel_job(request: Request, job_id: str = Path(description="شناسهٔ پایدار کار پس‌زمینه.")):
    job = request.app.state.jobs.cancel(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    request.app.state.db.record_audit(actor=request.headers.get("x-admin-actor", "admin-api"),
                                      action="job.cancel", target=job_id, detail={"status": job["status"]})
    return job


@router.get(
    "/api/jobs/{job_id}",
    tags=["بررسی‌های هوشمند"],
    summary="دریافت وضعیت و نتیجه‌ی یک کار پس‌زمینه",
    description=(
        "وضعیت فعلی کار (`queued` یا `running` یا `completed` یا `failed`) "
        "را برمی‌گرداند؛ پس از پایان، نتیجه‌ی بررسی در کلید `result` قرار "
        "می‌گیرد. کارها در حافظه نگه‌داری می‌شوند و پس از راه‌اندازی مجدد "
        "برنامه در دسترس نیستند."
    ),
    responses=_responses(
        "وضعیت کار؛ result فقط پس از completed/failed پر می‌شود.",
        {
            "id": "28ff9e256927",
            "kind": "investigation",
            "status": "completed",
            "created_at": 1769646600.1,
            "finished_at": 1769646792.5,
            "error": None,
            "result": {
                "id": 9,
                "status": "completed",
                "target_ip": "192.168.1.10",
                "report_text": "## خلاصه مدیریتی\nگزارش فارسی کامل...",
            },
        },
        not_found="کاری با این شناسه وجود ندارد.",
        not_found_detail="job not found",
        validation=True,
    ),
)
def get_job(
    request: Request,
    job_id: str = Path(description="شناسه‌ی کار دریافتی از POST /api/jobs/investigation.",
                       examples=["28ff9e256927"]),
) -> dict[str, Any]:
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


# ---------------------------------------------------------------------------
# Discovery / scans (scope-gated, no per-tool flags)
# ---------------------------------------------------------------------------


@router.post(
    "/api/hosts/discover",
    tags=["عملیات اسکن"],
    summary="کشف میزبان در یک محدوده‌ی مجاز",
    description=(
        "یک بار کشف میزبان (بدون اسکن پورت) روی IP یا CIDR داده‌شده اجرا "
        "می‌کند: با `nmap` به روش `-sn` و با `arp_scan` به روش ARP. میزبان‌های "
        "پیدا‌شده در فهرست میزبان‌ها ثبت می‌شوند. هدف باید داخل محدوده‌ی مجاز "
        "پیکربندی‌شده باشد؛ با nmap هدف خارج از محدوده با کد 403 رد می‌شود و "
        "با arp_scan پاسخ 200 با `ok=false` و پیام خطا برمی‌گردد. arp_scan به "
        "دسترسی raw-socket نیاز دارد و در نبود آن هم پاسخ 200 با `ok=false` "
        "و کلید `unavailable` برمی‌گردد."
    ),
    responses=_responses(
        "نتیجه‌ی کشف؛ فهرست میزبان‌های پاسخ‌دهنده و مدت اجرا.",
        {
            "ok": True,
            "tool": "nmap_discovery",
            "target": "192.168.1.0/24",
            "hosts": [{"ip": "192.168.1.10", "status": "up"}],
            "host_count": 1,
            "duration_ms": 5230.4,
            "output_truncated": False,
            "error": None,
            "note": "فقط کشف میزبان (-sn)؛ بدون اسکن پورت.",
        },
        forbidden=True,
        forbidden_example=_ERR_403_OUT_OF_SCOPE_EN,
        validation=True,
    ),
    openapi_extra={
        "requestBody": {"content": {"application/json": {"examples": {
            "nmap_cidr": {
                "summary": "کشف میزبان با nmap روی یک CIDR مجاز",
                "value": {"tool": "nmap", "target": "192.168.1.0/24"},
            },
            "arp_scan_host": {
                "summary": "کشف با arp-scan روی یک IP (نیازمند دسترسی raw-socket)",
                "value": {"tool": "arp_scan", "target": "192.168.1.10"},
            },
        }}}},
    },
)
def discover_hosts(request: Request, body: ScanRequest) -> dict[str, Any]:
    """Host discovery over one authorized CIDR (nmap -sn; arp-scan fallback)."""
    db, settings, _ = _ctx(request)
    if body.tool != "nmap" and body.tool != "arp_scan":
        raise HTTPException(status_code=422, detail="tool must be nmap or arp_scan")
    try:
        if body.tool == "nmap":
            from netagent.services.discovery import auto_discovery_eligible_networks

            result = nmap_collector.host_discovery(
                settings, body.target,
                extra_networks=[e["cidr"] for e in auto_discovery_eligible_networks(db, settings)],
            )
        else:
            result = execute_tool(
                build_registry(settings), db, settings,
                "arp_scan", {"target": body.target},
                ToolScope(settings=settings, extra_targets=[], db=db),
            )
    except TargetNotAuthorized as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if result.get("unauthorized"):
        raise HTTPException(status_code=403, detail=result["error"])
    for host in result.get("hosts", []):
        db.upsert_host(host["ip"])
    return result


@router.post(
    "/api/tools/{tool_name}",
    tags=["ابزارها و قابلیت‌ها"],
    summary="فراخوانی مستقیم یک ابزار تشخیصی",
    description=(
        "یکی از ابزارهای `GET /api/tools` را با آرگومان‌های دلخواه اجرا "
        "می‌کند؛ همان مسیر اعتبارسنجی عامل (scope و محدودیت‌های آرگومان) "
        "اعمال می‌شود. اگر ابزار یا آرگومان نامعتبر باشد، پاسخ 200 با "
        "`ok=false` و پیام خطا برمی‌گردد؛ هدف خارج از محدوده با 403 رد "
        "می‌شود. هر فراخوانی در جدول diagnostics ثبت می‌شود."
    ),
    responses=_responses(
        "نتیجه‌ی ساختاریافته‌ی ابزار؛ ساختار بر اساس ابزار انتخابی متفاوت است.",
        {
            "ok": True,
            "tool": "nmap_services",
            "target": "192.168.1.10",
            "ports_requested": [22, 80, 443],
            "service_detection": True,
            "hosts": [
                {
                    "status": "up",
                    "addresses": [{"addr": "192.168.1.10", "type": "ipv4", "vendor": None}],
                    "hostnames": [],
                    "ports": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "reason": "syn-ack",
                            "service": {
                                "name": "http", "product": "nginx",
                                "version": "1.24", "method": "probe", "conf": "10",
                            },
                        }
                    ],
                }
            ],
            "duration_ms": 1460.2,
            "error": None,
            "note": "اسکن اتصال TCP محدود (-sT) با سرویس/نسخه سبک (-sV --version-light). بدون اسکن تهاجمی.",
        },
        forbidden=True,
        validation=True,
    ),
    openapi_extra={
        "requestBody": {"content": {"application/json": {"examples": {
            "nmap_services": {
                "summary": "اسکن سرویس روی پورت‌های 80 و 443 یک میزبان مجاز",
                "value": {
                    "target": "192.168.1.10",
                    "ports": [80, 443],
                    "service_detection": True,
                },
            },
            "ping": {
                "summary": "ping محدود یک میزبان مجاز (پارامتر host)",
                "value": {"host": "192.168.1.10"},
            },
        }}}},
    },
)
def invoke_tool(
    request: Request,
    tool_name: str = Path(
        description="نام ابزار از فهرست `GET /api/tools` مثل ping یا nmap_services یا host_fingerprint.",
        examples=["nmap_services"],
    ),
    args: dict[str, Any] | None = Body(
        default=None,
        description=(
            "آرگومان‌های ابزار به‌صورت شیء JSON؛ کلیدهای لازم را از "
            "`GET /api/tools` ببینید. مثلاً برای nmap_services: "
            "‏{\"target\": \"192.168.1.10\", \"ports\": [80, 443]}‏"
        ),
        examples=[
            {"target": "192.168.1.10", "ports": [80, 443], "service_detection": True},
        ],
    ),
) -> dict[str, Any]:
    """Direct, validated tool invocation (same validation path as the agent)."""
    db, settings, _ = _ctx(request)
    registry = build_registry(settings)
    # Same target-validation path as the agent: configured scope (extended by
    # eligible discovered networks); a user-supplied target never self-authorizes.
    scope = ToolScope(settings=settings, extra_targets=[], db=db)
    result = execute_tool(registry, db, settings, tool_name, args or {}, scope)
    error = str(result.get("error", ""))
    if result.get("unauthorized") or (not result.get("ok") and ("خارج از محدوده" in error or "outside authorized scope" in error)):
        raise HTTPException(status_code=403, detail=error)
    return result


@router.post(
    "/api/scans",
    tags=["عملیات اسکن"],
    summary="کشف میزبان (نقطه‌پایان سازگاری قبلی)",
    description=(
        "رفتار همان `POST /api/hosts/discover` است و برای سازگاری با "
        "کلاینت‌های قبلی نگه‌داشته شده؛ به‌علاوه هر اجرا در جدول diagnostics "
        "ثبت می‌شود. اگر ابزار به دسترسی ویژه نیاز داشته باشد و آن دسترسی "
        "نباشد، پاسخ 200 با `ok=false` و کلید `capability_required` "
        "برمی‌گردد (ارزیابی دقیق، نه خطای مبهم). هدف باید داخل محدوده‌ی مجاز "
        "باشد؛ با nmap هدف خارج از محدوده 403 و با arp_scan پاسخ 200 با "
        "`ok=false` برمی‌گردد."
    ),
    responses=_responses(
        "نتیجه‌ی کشف میزبان؛ در خطای دسترسی، ok=false با capability_required.",
        {
            "ok": True,
            "tool": "nmap_discovery",
            "target": "192.168.1.0/24",
            "hosts": [{"ip": "192.168.1.10", "status": "up"}],
            "host_count": 1,
            "duration_ms": 5230.4,
            "output_truncated": False,
            "error": None,
            "note": "فقط کشف میزبان (-sn)؛ بدون اسکن پورت.",
        },
        forbidden=True,
        forbidden_example=_ERR_403_OUT_OF_SCOPE_EN,
        validation=True,
    ),
    openapi_extra={
        "requestBody": {"content": {"application/json": {"examples": {
            "nmap_cidr": {
                "summary": "کشف میزبان با nmap روی یک CIDR مجاز",
                "value": {"tool": "nmap", "target": "192.168.1.0/24"},
            },
            "arp_scan_host": {
                "summary": "کشف با arp-scan روی یک IP (نیازمند دسترسی raw-socket)",
                "value": {"tool": "arp_scan", "target": "192.168.1.10"},
            },
        }}}},
    },
)
def create_scan(request: Request, body: ScanRequest) -> dict[str, Any]:
    """Backward-compatible scan endpoint. Same validation as the agent tools:
    scope-gated, no per-tool flags; unauthorized targets => 403."""
    db, settings, _ = _ctx(request)
    registry = build_registry(settings)

    try:
        if body.tool == "nmap":
            from netagent.services.discovery import auto_discovery_eligible_networks

            result = nmap_collector.host_discovery(
                settings, body.target,
                extra_networks=[e["cidr"] for e in auto_discovery_eligible_networks(db, settings)],
            )
        else:
            result = execute_tool(
                registry, db, settings, "arp_scan", {"target": body.target},
                ToolScope(settings=settings, extra_targets=[], db=db),
            )
    except TargetNotAuthorized as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    db.record_diagnostic(
        body.tool, body.target, {"target": body.target},
        bool(result.get("ok")), result, result.get("error"),
    )
    if not result.get("ok") and result.get("capability_required"):
        # capability problem: report precisely, HTTP 200 with structured error
        return result
    return result
