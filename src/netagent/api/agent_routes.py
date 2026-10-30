"""Agent API (v1): the single communication channel for endpoint agents.

Same FastAPI application and port as the rest of the product — a versioned
route prefix is not a separate listener. Agents authenticate with their
individual bearer credential (issued at enrollment, stored hashed).
Administrator credentials do NOT work here, and agent credentials do NOT
work on /api/admin/v1.

All Persian OpenAPI metadata lives next to the handlers. Example values are
illustrative only — they are not runtime data of any particular machine.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Header, Path, Request
from fastapi.responses import JSONResponse

from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import (
    EnrollRequest,
    HeartbeatRequest,
    InventoryRequest,
    SimpleAck,
    TaskResultRequest,
)
from netagent.security import verify_admin_token  # noqa: F401 (re-exported for tests)
from netagent.services import agents as agent_service
from netagent.services import tasks as task_service
from netagent.services.agents import (
    AgentAuthError,
    EnrollmentError,
    agent_public_view,
    authenticate_agent,
    enroll_agent,
    ingest_inventory,
)

router = APIRouter(prefix="/api/agent/v1")

_ERR_401 = {"value": {"detail": "اعتبارنامه‌ی عامل نامعتبر یا ارسال‌نشده است."}}
_ERR_403_REVOKED = {"value": {"detail": "این عامل باطل (revoked) شده است."}}


def _responses(description: str, example: Any, **errors: Any) -> dict[int, Any]:
    responses: dict[int, Any] = {
        200: {
            "description": description,
            "content": {"application/json": {"examples": {"default": {"value": example}}}},
        },
        422: {
            "description": "ورودی نامعتبر است؛ ساختار detail شرح خطا را می‌دهد.",
            "content": {"application/json": {"examples": {"validation": {
                "value": {"detail": [
                    {"type": "missing", "loc": ["body", "enrollment_token"],
                     "msg": "Field required"}
                ]}}}}},
        },
    }
    if errors.get("auth", True):
        responses[401] = {
            "description": "اعتبارنامه‌ی عامل ارسال نشده یا نامعتبر است (Bearer).",
            "content": {"application/json": {"examples": _ERR_401}},
        }
    if errors.get("revoked"):
        responses[403] = {
            "description": "عامل باطل شده است.",
            "content": {"application/json": {"examples": _ERR_403_REVOKED}},
        }
    if errors.get("not_found"):
        responses[404] = {
            "description": errors["not_found"],
            "content": {"application/json": {"examples": {"default": {
                "value": {"detail": "task not found"}}}}},
        }
    if errors.get("conflict"):
        responses[409] = {
            "description": errors["conflict"],
            "content": {"application/json": {"examples": {"default": {
                "value": {"detail": "task status is 'succeeded'",
                          "rejection_reason": "task status is 'succeeded', not 'dispatched'; result was not stored"}}}}},
        }
    return responses


def _ctx(request: Request) -> tuple[Database, Settings]:
    return request.app.state.db, request.app.state.settings


def _agent_or_error(request: Request, authorization: str | None) -> dict[str, Any]:
    db, settings = _ctx(request)
    try:
        return authenticate_agent(db, authorization)
    except AgentAuthError as exc:
        message = str(exc)
        if "revoked" in message:
            raise HTTPException(status_code=403, detail=message) from exc
        raise HTTPException(status_code=401, detail=message) from exc


# ---------------------------------------------------------------------------
# Enrollment (no agent credential yet)
# ---------------------------------------------------------------------------


@router.post(
    "/enroll",
    tags=["Endpoint Agent"],
    summary="ثبت‌نام عامل نقطه‌پایان و دریافت اعتبارنامه",
    description=(
        "اولین فراخوانی هر عامل: با توکن ثبت‌نام یک‌بارمصرف (صادرشده توسط "
        "مدیر) هویت می‌سازد و اعتبارنامه‌ی اختصاصی می‌گیرد. توکن فقط یک‌بار "
        "قابل استفاده است و پس از انقضا رد می‌شود. `agent_token` فقط در همین "
        "پاسخ نمایش داده می‌شود؛ عامل باید آن را در فایل وضعیت محلی با دسترسی "
        "محدود ذخیره کند. این نقطه‌پایان اعتبارنامه‌ی مدیر را هم قبول نمی‌کند؛ "
        "دو نوع اعتبارنامه کاملاً جداست."
    ),
    responses=_responses(
        "شناسه و اعتبارنامه‌ی عامل به‌همراه تنظیمات دوره‌ای (heartbeat/inventory).",
        {
            "agent_id": "agt_9f2c41ba07c3",
            "agent_token": "agt_xJ9… (نمونه؛ مقدار واقعی در پاسخ می‌آید)",
            "server_time_epoch": 1769646600.5,
            "heartbeat_interval_seconds": 30,
            "inventory_interval_seconds": 300,
            "max_task_result_bytes": 262144,
        },
        auth=False,
    ),
)
def enroll(request: Request, body: EnrollRequest) -> dict[str, Any]:
    db, settings = _ctx(request)
    try:
        agent, token = enroll_agent(db, settings, body, origin="agent-api")
    except EnrollmentError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.record_audit(
        actor="agent-api", action="agent.enroll", target=agent["id"],
        detail={"hostname": body.hostname, "origin_ip": request.client.host if request.client else None},
    )
    return {
        "agent_id": agent["id"],
        "agent_token": token,
        "server_time_epoch": time.time(),
        "heartbeat_interval_seconds": settings.agent_heartbeat_interval_seconds,
        "inventory_interval_seconds": settings.agent_inventory_interval_seconds,
        "max_task_result_bytes": settings.agent_max_task_result_bytes,
    }


# ---------------------------------------------------------------------------
# Authenticated agent endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/heartbeat",
    tags=["Endpoint Agent"],
    summary="ارسال ضربان (heartbeat) عامل",
    description=(
        "ثبت حیات عامل و به‌روزرسانی IPهای اعلامی و نسخه. پاسخ شامل تنظیم "
        "دوره‌ی ضربان و اعلام `inventory_due` است تا عامل بداند چه زمانی "
        "فهرست‌برداری کامل بفرستد. عامل بی‌ضربان، *stale* گزارش می‌شود نه "
        "خاموش؛ مرکز هیچ‌وقت نبودِ ضربان را قطعیتِ خاموشی نمی‌داند."
    ),
    responses=_responses(
        "تأیید ضربان و تنظیمات بعدی.",
        {
            "accepted": True,
            "agent_status": "active",
            "server_time_epoch": 1769646600.5,
            "heartbeat_interval_seconds": 30,
            "inventory_due": False,
            "max_task_result_bytes": 262144,
        },
        revoked=True,
    ),
)
def heartbeat(
    request: Request,
    body: HeartbeatRequest,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <توکن عامل>` صادرشده هنگام ثبت‌نام. "
            "این اعتبارنامه مخصوص Endpoint Agent است و در مسیرهای مدیر پذیرفته نمی‌شود."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    agent = _agent_or_error(request, authorization)
    ok = db.agent_heartbeat(
        agent["id"],
        claimed_ips=body.claimed_ips,
        heartbeat_interval=settings.agent_heartbeat_interval_seconds,
        agent_version=body.agent_version,
        hostname=body.hostname,
        platform=body.platform.os_family if body.platform else None,
    )
    if not ok:
        raise HTTPException(status_code=403, detail="agent credential is revoked")
    latest = db.get_latest_inventory(agent["id"])
    inventory_due = latest is None or (
        time.time() - _iso_to_epoch(latest.get("collected_at")) >
        settings.agent_inventory_interval_seconds
    )
    return {
        "accepted": True,
        "agent_status": agent_public_view(db.get_agent(agent["id"]) or {}, settings)["status"],
        "server_time_epoch": time.time(),
        "heartbeat_interval_seconds": settings.agent_heartbeat_interval_seconds,
        "inventory_due": inventory_due,
        "max_task_result_bytes": settings.agent_max_task_result_bytes,
    }


def _iso_to_epoch(value: str | None) -> float:
    from datetime import datetime

    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


@router.post(
    "/inventory",
    tags=["Endpoint Agent"],
    summary="ارسال فهرست‌برداری کامل نقطه‌پایان",
    description=(
        "بار ساختاریافته‌ی inventory: پلتفرم، رابط‌های شبکه، آدرس‌ها، "
        "شبکه‌های متصل، DNS و وضعیت جمع‌آورنده‌ها. مرکز آن را در تاریخچه‌ی "
        "محدود ذخیره می‌کند و مشاهده‌های شبکه‌ی مستقیماً متصل را در فهرست "
        "شبکه‌ها ثبت می‌کند (بدون مجازسازی خودکار اسکن). هر جمع‌آورنده باید "
        "وضعیت صریح بدهد؛ مقدار ساختگی مجاز نیست."
    ),
    responses=_responses(
        "خلاصه‌ی ذخیره‌سازی: تعداد رابط‌ها و مشاهده‌های شبکه.",
        {
            "stored": True,
            "interfaces": 3,
            "network_observations": 2,
            "server_time_epoch": 1769646600.5,
        },
        revoked=True,
    ),
)
def inventory(
    request: Request,
    body: InventoryRequest,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <توکن عامل>` صادرشده هنگام ثبت‌نام. "
            "این اعتبارنامه مخصوص Endpoint Agent است و در مسیرهای مدیر پذیرفته نمی‌شود."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    agent = _agent_or_error(request, authorization)
    try:
        summary = ingest_inventory(db, settings, agent["id"], body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    summary["server_time_epoch"] = time.time()
    return summary


@router.post(
    "/status",
    tags=["Endpoint Agent"],
    summary="گزارش وضعیت زمان اجرای عامل",
    description=(
        "به‌روزرسانی وضعیت اختیاری عامل: نسخه، قابلیت‌های فعال و پیام کوتاه. "
        "برای اعلام تغییر قابلیت‌ها (مثلاً فعال شدن اجرای اسکریپت مدیریتی) "
        "بدون انتظار برای دوره‌ی inventory مناسب است."
    ),
    responses=_responses(
        "تأیید دریافت وضعیت.",
        {"ok": True, "detail": "status updated", "server_time_epoch": 1769646600.5},
        revoked=True,
    ),
)
def agent_status(
    request: Request,
    body: HeartbeatRequest,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <توکن عامل>` صادرشده هنگام ثبت‌نام. "
            "این اعتبارنامه مخصوص Endpoint Agent است و در مسیرهای مدیر پذیرفته نمی‌شود."
        ),
    ),
) -> SimpleAck:
    db, _ = _ctx(request)
    agent = _agent_or_error(request, authorization)
    ok = db.agent_heartbeat(
        agent["id"],
        claimed_ips=body.claimed_ips,
        heartbeat_interval=None,
        agent_version=body.agent_version,
        hostname=body.hostname,
        platform=body.platform.os_family if body.platform else None,
    )
    if not ok:
        raise HTTPException(status_code=403, detail="agent credential is revoked")
    return SimpleAck(ok=True, detail="status updated", server_time_epoch=time.time())


@router.get(
    "/tasks/next",
    tags=["Endpoint Agent"],
    summary="دریافت تسک بعدی برای اجرا",
    description=(
        "یک تسک در انتظار را اتمی برمی‌دارد (pending → dispatched). تسک‌های "
        "تشخیصی بدون امضا هستند؛ تسک‌های مدیریتی (admin_python_script و "
        "console_*) فقط داخل پاکت امضاشده (HMAC-SHA256) تحویل می‌شوند و عامل "
        "قبل از اجرا امضا، مقصد، انقضا و تکراری‌نبودن را بررسی می‌کند. اگر "
        "تسکی در انتظار نباشد، task برابر null است."
    ),
    responses=_responses(
        "تسک claimed یا null؛ پاکت امضاشده فقط برای انواع مدیریتی.",
        {
            "task": {
                "task_id": "task_5b1e0a9c77d2f103",
                "type": "inventory_collection",
                "created_at": "2026-10-28T12:40:00+00:00",
                "expires_at": "2026-10-28T12:50:00+00:00",
                "timeout_seconds": 120,
                "params": {},
            }
        },
        revoked=True,
    ),
)
def next_task(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <توکن عامل>` صادرشده هنگام ثبت‌نام. "
            "این اعتبارنامه مخصوص Endpoint Agent است و در مسیرهای مدیر پذیرفته نمی‌شود."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    agent = _agent_or_error(request, authorization)
    supported = list(agent.get("capabilities") or [])
    message = task_service.dispatch_task(db, settings, agent, supported_types=supported)
    return {"task": message, "server_time_epoch": time.time()}


@router.post(
    "/tasks/{task_id}/result",
    tags=["Endpoint Agent"],
    summary="ارسال نتیجه‌ی اجرای تسک",
    description=(
        "نتیجه‌ی هر تسک فقط یک‌بار پذیرفته می‌شود: تسک باید در وضعیت "
        "dispatched باشد و متعلق به همین عامل. ارسال دوباره همان نتیجه با 409 "
        "رد می‌شود تا اجرای تکراری یا پخش مجدد، نتیجه را دوباره ثبت نکند. "
        "اندازه‌ی result به سقف پیکربندی بریده می‌شود و برش، علامت‌گذاری می‌شود."
    ),
    responses={
        200: {
            "description": "وضعیت تسک پس از ثبت نتیجه؛ accepted=true یعنی ذخیره شد.",
            "content": {"application/json": {"examples": {"default": {"value": {
                "id": "task_5b1e0a9c77d2f103",
                "agent_id": "agt_9f2c41ba07c3",
                "type": "inventory_collection",
                "status": "succeeded",
                "accepted": True,
            }}}}},
        },
        401: _responses("", {}, revoked=True)[401],
        403: _responses("", {}, revoked=True)[403],
        404: {
            "description": "تسکی با این شناسه وجود ندارد.",
            "content": {"application/json": {"examples": {"default": {
                "value": {"detail": "task not found"}}}}},
        },
        409: {
            "description": "نتیجه قبلاً ثبت شده یا تسک دیگر در وضعیت dispatched نیست.",
            "content": {"application/json": {"examples": {"default": {
                "value": {"id": "task_5b1e0a9c77d2f103", "status": "succeeded",
                          "accepted": False,
                          "rejection_reason": "task status is 'succeeded'"}}}}},
        },
        422: _responses("", {})[422],
    },
)
def task_result(
    request: Request,
    body: TaskResultRequest,
    task_id: str = Path(description="شناسه‌ی تسک دریافتی از GET /tasks/next.",
                        examples=["task_5b1e0a9c77d2f103"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <توکن عامل>` صادرشده هنگام ثبت‌نام. "
            "این اعتبارنامه مخصوص Endpoint Agent است و در مسیرهای مدیر پذیرفته نمی‌شود."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    agent = _agent_or_error(request, authorization)
    try:
        updated = task_service.complete_task_from_agent(
            db, settings,
            agent=agent,
            task_id=task_id,
            ok=body.ok,
            result=body.result,
            error=body.error,
        )
    except task_service.TaskError as exc:
        message = str(exc)
        status = 404 if "not found" in message else 400
        raise HTTPException(status_code=status, detail=message) from exc
    if updated.get("accepted") is False:
        return JSONResponse(status_code=409, content=updated)
    # Console/admin bookkeeping (updates sessions/commands, records audit)
    from netagent.services import console as console_service

    if updated.get("type", "").startswith("console"):
        console_service.apply_agent_result(db, settings, task=updated, result=body.result)
    elif updated.get("type") == "admin_python_script" and updated.get("accepted"):
        db.record_audit(
            actor="agent", action="admin_script.completed",
            target=agent["id"],
            detail={"task_id": task_id, "ok": body.ok,
                    "duration_ms": body.duration_ms},
        )
    return updated
