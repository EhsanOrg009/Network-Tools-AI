"""Dashboard API (v1): aggregate views for the Persian RTL admin dashboard.

Everything here is administrator-only (same ``ADMIN_API_TOKEN`` as the rest
of the admin plane) and read-only — decision-making operations stay in
``/api/admin/v1`` so audit semantics live in one place. The frontend never
touches the database directly; these endpoints exist only because the SPA
needs bundled/aggregated numbers (overview page, trends) that no existing
endpoint returns in one round-trip.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from netagent.api.admin_routes import _ctx, _guard
from netagent.services.agents import agent_public_view

router = APIRouter(prefix="/api/dashboard/v1", tags=["داشبورد مدیریتی"])


def _unauthorized(detail: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})


_ERR_503 = {"value": {"detail": "API مدیر غیرفعال است؛ ADMIN_API_TOKEN تنظیم نشده است."}}
_ERR_401 = {"value": {"detail": "توکن مدیر نامعتبر یا ارسال‌نشده است (Bearer)."}}


def _responses(description: str, example: Any) -> dict[int, Any]:
    return {
        200: {
            "description": description,
            "content": {"application/json": {"examples": {"default": {"value": example}}}},
        },
        422: {
            "description": "ورودی نامعتبر است؛ جلوه‌ها بر شرح خطا در `detail` می‌دهد.",
            "content": {"application/json": {"examples": {"validation": {
                "value": {"detail": [
                    {"type": "string_type", "loc": ["header", "authorization"],
                     "msg": "Input should be a valid string"}
                ]}}}}},
        },
        401: {"description": "توکن مدیر لازم است (Bearer ADMIN_API_TOKEN).",
              "content": {"application/json": {"examples": _ERR_401}}},
        503: {"description": "API مدیر غیرفعال است.",
              "content": {"application/json": {"examples": _ERR_503}}},
    }


@router.get(
    "/overview",
    summary="آمار کلی سامانه برای صفحه‌ی نمای کلی داشبورد",
    description=(
        "همه‌ی شمارنده‌های صفحه‌ی نمای کلی در **یک** پاسخ: وضعیت عوامل "
        "(active/stale/revoked)، درخواست‌های ثبت‌نامِ در انتظار تأیید، میزبان‌های "
        "شناسایی‌شده، رویدادها و هشدارهای Suricata (جمع و تفکیک شدت)، تسک‌های "
        "در صف، نشست‌های فعال کنسول، روند ۷ روزه‌ی فعالیت و آخرین رکوردهای "
        "حسابرسی. همگی مستقیم از پایگاه‌داده — بدون داده‌ی Mock."
    ),
    responses=_responses(
        "آمار تجمیعی سامانه.",
        {
            "agents": {"total": 12, "active": 9, "stale": 2, "revoked": 1,
                       "pending_approval": 3},
            "hosts": 240,
            "events": "۱۲هزار…",
            "alerts": {"total": 37, "last_24h": 5, "by_severity": [
                {"severity": 2, "count": 4}, {"severity": 3, "count": 1}]},
            "tasks": {"pending": 1},
            "investigations": {"total": 8, "running": 1},
            "console_sessions_active": 1,
            "trend_7d": [{"date": "2026-10-30", "events": 1200, "alerts": 3,
                          "audit": 12}],
            "recent_audit": [{"at": "…", "actor": "net-admin",
                              "action": "enrollment_request.approve",
                              "target": "req_…", "outcome": "ok"}],
            "generated_at": "2026-10-31T12:00:00+00:00",
        },
    ),
    )
def overview(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب مدیر در حسابرسی."
        ),
    ),
) -> dict[str, Any]:
    _guard(request, authorization, x_admin_actor)
    db, settings = _ctx(request)

    agents = [
        agent_public_view(a, settings)
        for a in db.list_agents(limit=500, include_revoked=True)
    ]
    by_state = {"total": len(agents), "active": 0, "stale": 0, "revoked": 0}
    for a in agents:
        by_state[a["status"]] = by_state.get(a["status"], 0) + 1

    day_epoch = time.time() - 86400
    _, alerts_total = db.query_alerts(limit=1)
    _, alerts_24h = db.query_alerts(since_epoch=day_epoch, limit=1)
    _, events_total = db.query_events(limit=1)
    _, events_24h = db.query_events(since_epoch=day_epoch, limit=1)
    hosts_total = len(db.list_hosts(limit=1, offset=0))
    stats = db.stats()

    investigations = db.list_investigations(limit=200)
    inv_counts: dict[str, int] = {"total": len(investigations)}
    for inv in investigations:
        s = inv.get("status") or "unknown"
        inv_counts[s] = inv_counts.get(s, 0) + 1

    pending_requests, pending_total = db.list_enrollment_requests(status="PENDING_APPROVAL")
    recent_audit, _ = db.list_audit(limit=12)

    return {
        "agents": {
            **by_state,
            "pending_approval": int(pending_total),
            "pending_requests": pending_requests[:5],
        },
        "hosts": hosts_total,
        "events": {"total": events_total, "last_24h": events_24h},
        "alerts": {
            "total": alerts_total,
            "last_24h": alerts_24h,
            "by_severity": db.alert_severity_counts(),
        },
        "tasks": {"pending": stats.get("pending_tasks")},
        "investigations": inv_counts,
        "console_sessions_active": db.count_active_console_sessions(),
        "trend_7d": db.daily_activity_counts(days=7),
        "recent_audit": [
            {k: r.get(k) for k in ("at", "actor", "action", "target", "outcome")}
            for r in recent_audit
        ],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }


@router.get(
    "/healthz",
    summary="بررسی در دسترس‌بودن مسیر داشبورد (همراه با توکن)",
    description=(
        "پاسخ سبک برای صفحه‌ی داشبورد تا «اتصال زنده» را تشخیص دهد: اگر این "
        "اندپوینت با توکن مدیر پاسخ دهد، بقیه‌ی داده‌ها هم در دسترس‌اند."
    ),
    responses=_responses("در دسترس است.", {"ok": True, "now": "2026-10-31T12:00:00+00:00"}),
    )
def healthz(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`.",
    ),
    x_admin_actor: str | None = Header(default=None, description="برچسب مدیر."),
) -> dict[str, Any]:
    _guard(request, authorization, x_admin_actor)
    return {"ok": True, "now": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}


# Non-secret, non-credential fields exposed for the dashboard Settings page.
# Tokens, keys, hashes and paths that could contain secrets are NEVER listed.
_SETTINGS_WHITELIST = (
    "app_host", "app_port",
    "monitor_cidrs", "authorized_targets", "monitor_interface",
    "enable_monitor", "monitor_interval_seconds",
    "suricata_eve_path",
    "llm_enabled", "llm_base_url", "llm_model", "llm_provider",
    "llm_timeout_seconds", "llm_connect_timeout_seconds", "llm_timeout_cooldown_seconds",
    "llm_max_output_tokens", "llm_max_input_chars", "llm_structured_outputs",
    "ai_analysis_enabled", "ai_analysis_backlog_limit", "ai_analysis_intake_limit", "ai_analysis_batch_size",
    "job_workers", "job_queue_size", "job_timeout_seconds",
    "allow_auto_registration", "enrollment_request_ttl_minutes",
    "max_pending_enrollment_requests", "registration_rate_limit_per_hour",
    "agent_heartbeat_interval_seconds", "agent_heartbeat_timeout_seconds",
    "agent_inventory_interval_seconds", "agent_max_task_result_bytes",
    "allow_admin_python_exec", "allow_admin_python_console",
    "admin_script_max_bytes", "admin_script_max_runtime_seconds",
    "console_session_ttl_seconds", "console_idle_timeout_seconds",
    "console_command_timeout_seconds", "console_max_code_bytes",
    "console_max_output_bytes", "console_max_pending_commands",
    "auto_discovery_enabled", "discovery_excluded_cidrs",
    "discovery_excluded_interfaces", "auto_discovery_max_addresses",
    "auto_discovery_min_reporters",
    "ping_count", "ping_timeout_seconds", "allowed_tcp_ports",
)


@router.get(
    "/settings",
    summary="نمای فقط‌خواندنی تنظیمات غیر‌فاش (برای صفحه‌ی تنظیمات داشبورد)",
    description=(
        "فقط فیلدهای غیر‌حساس پیکربندی را برمی‌گرداند؛ توکن‌ها، کلیدها و مقادیر "
        "فاش هرگز در این پاسخ نمی‌آیند. تغییر پیکربندی از این مسیر هم انجام "
        "نمی‌شود — منبع حقیقت متغیرهای محیطی هسته است."
    ),
    responses=_responses(
        "پیکربندی غیر‌حساس سامانه.",
        {"app_host": "127.0.0.1", "app_port": 8000,
         "allow_auto_registration": True, "registration_rate_limit_per_hour": 30},
    ),
)
def dashboard_settings(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`.",
    ),
    x_admin_actor: str | None = Header(default=None, description="برچسب مدیر."),
) -> dict[str, Any]:
    _guard(request, authorization, x_admin_actor)
    _, settings = _ctx(request)
    out: dict[str, Any] = {}
    for key in _SETTINGS_WHITELIST:
        value = getattr(settings, key, None)
        if value is None:
            continue
        out[key] = str(value) if not isinstance(value, (str, int, float, bool)) else value
    return out
