"""Administrator control plane (v1): agents, tasks, remote Python, console.

Hard separation rules (enforced structurally, not by prompt):
- Every route here requires the administrator bearer token from settings.
  There is no default; an empty/weak token keeps the whole family disabled.
- Endpoint-agent credentials are rejected (different hash namespace).
- The AI tool registry has no reference to any function in this file; the
  LLM has neither the admin token nor the task signing key.
- Every state-changing operation writes an admin_audit row.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Path, Query, Request

from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import (
    AdminScriptCreate,
    ConsoleCommandCreate,
    ConsoleSessionCreate,
    DiagnosticTaskCreate,
    EnrollmentRejectBody,
    EnrollmentTokenCreate,
)
from netagent.security import (
    admin_token_configured,
    generate_token,
    hash_secret,
    verify_admin_token,
)
from netagent.services import console as console_service
from netagent.services import tasks as task_service
from netagent.services.agents import agent_public_view
from netagent.services.discovery import effective_discovery_scope

router = APIRouter(prefix="/api/admin/v1")


class AdminDisabled(Exception):
    pass


class AdminUnauthorized(Exception):
    pass


def _ctx(request: Request) -> tuple[Database, Settings]:
    return request.app.state.db, request.app.state.settings


def require_admin(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> str:
    """Dependency: validate the administrator token and return the actor label.

    The actor label (X-Admin-Actor) is attribution metadata for the audit
    trail only — it is not a second credential. All admins share the single
    configured token; the label is stored unverified by design.
    """
    _, settings = _ctx(request)
    if not admin_token_configured(settings.admin_api_token, settings.admin_api_token_sha256):
        raise AdminDisabled()
    presented = (authorization or "").strip()
    if presented.lower().startswith("bearer "):
        presented = presented[7:].strip()
    if not verify_admin_token(
        presented, settings.admin_api_token, settings.admin_api_token_sha256
    ):
        raise AdminUnauthorized()
    actor = (x_admin_actor or "admin-api").strip()[:64] or "admin-api"
    return actor


def _guard(request: Request, authorization: str | None, x_admin_actor: str | None) -> str:
    """Same check as require_admin but with Persian HTTP errors."""
    try:
        return require_admin(request, authorization, x_admin_actor)
    except AdminDisabled as exc:
        raise HTTPException(
            status_code=503,
            detail="API مدیر غیرفعال است؛ ADMIN_API_TOKEN (یا ADMIN_API_TOKEN_SHA256) تنظیم نشده است.",
        ) from exc
    except AdminUnauthorized as exc:
        raise HTTPException(
            status_code=401,
            detail="توکن مدیر نامعتبر است.",
        ) from exc


_ERR_503 = {"value": {"detail": "API مدیر غیرفعال است؛ ADMIN_API_TOKEN تنظیم نشده است."}}
_ERR_401 = {"value": {"detail": "توکن مدیر نامعتبر یا ارسال‌نشده است (Bearer)."}}
_ERR_404 = {"value": {"detail": "not found"}}
_ERR_409 = {"value": {"detail": {"accepted": False, "rejection_reason": "task already finished"}}}


def _responses(
    description: str,
    example: Any,
    *,
    not_found: str | None = None,
    conflict: bool = False,
) -> dict[int, Any]:
    responses: dict[int, Any] = {
        200: {
            "description": description,
            "content": {"application/json": {"examples": {"default": {"value": example}}}},
        },
        401: {"description": "توکن مدیر لازم است (Bearer ADMIN_API_TOKEN).",
              "content": {"application/json": {"examples": _ERR_401}}},
        422: {"description": "ورودی نامعتبر است؛ ساختار detail شرح خطا را می‌دهد.",
              "content": {"application/json": {"examples": {"validation": {"value": {
                  "detail": [{"type": "missing", "loc": ["body", "agent_id"],
                              "msg": "Field required"}]}}}}}},
    }
    if not_found:
        responses[404] = {
            "description": not_found,
            "content": {"application/json": {"examples": _ERR_404}},
        }
    if conflict:
        responses[409] = {
            "description": "عملیات تکراری یا وضعیت ناسازگار (مثلاً نتیجه‌ای که قبلاً ثبت شده).",
            "content": {"application/json": {"examples": _ERR_409}},
        }
    return responses


# ---------------------------------------------------------------------------
# Enrollment tokens
# ---------------------------------------------------------------------------


@router.post(
    "/enrollment-tokens",
    tags=["مدیریت مدیر شبکه"],
    summary="صدور توکن ثبت‌نام یک‌بارمصرف برای عامل جدید",
    description=(
        "توکنی کوتاه‌عمر می‌سازد که عامل با آن از طریق "
        "`POST /api/agent/v1/enroll` ثبت‌نام می‌کند. مقدار توکن فقط یک‌بار در "
        "پاسخ نمایش داده می‌شود و در پایگاه داده فقط هش آن می‌ماند. هر توکن "
        "فقط یک‌بار قابل مصرف است."
    ),
    responses=_responses(
        "توکن و زمان انقضا؛ توکن را فقط همین‌جا می‌بینید.",
        {
            "token": "enr_xJ9… (نمونه)",
            "expires_at": "2026-10-29T13:40:00+00:00",
            "ttl_minutes": 60,
        },
    ),
)
def create_enrollment_token(
    request: Request,
    body: EnrollmentTokenCreate,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    token = generate_token("enr")
    meta = db.create_enrollment_token(
        token_hash=hash_secret(token), ttl_seconds=body.ttl_minutes * 60, created_by=actor,
    )
    db.record_audit(actor=actor, action="enrollment_token.create",
                    detail={"ttl_minutes": body.ttl_minutes})
    return {"token": token, "expires_at": meta["expires_at"],
            "ttl_minutes": body.ttl_minutes}


@router.get(
    "/enrollment-tokens",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست توکن‌های ثبت‌نام اخیر",
    description=("فقط پیشوند هش نمایش داده می‌شود؛ توکن خام قابل بازیابی نیست."),
    responses=_responses(
        "فهرست توکن‌ها با وضعیت مصرف.",
        {"items": [{"token_hash": "2f3b9c1a8e0d…", "created_at": "2026-10-29T12:40:00+00:00",
                    "created_by": "admin-api", "expires_at": "2026-10-29T13:40:00+00:00",
                    "used_by": None, "used_at": None}]},
    ),
)
def list_enrollment_tokens(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    return {"items": db.list_enrollment_tokens()}


# ---------------------------------------------------------------------------
# Enrollment requests (auto-registration awaiting admin approval)
# ---------------------------------------------------------------------------


@router.get(
    "/enrollment-requests",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست درخواست‌های ثبت‌نام خودکار",
    description=(
        "درخواست‌های معرفی عامل‌ها با فیلتر وضعیت: `PENDING_APPROVAL` (در انتظار "
        "تأیید)، `APPROVED` (تأییدشده تا تکمیل توسط عامل)، `ENROLLED` (تکمیل‌شده)، "
        "`REJECTED` و `EXPIRED`. اطلاعات هر درخواست همان موارد **اعلامی** عامل "
        "است و تا تأیید مدیر هیچ اعتباری ندارد."
    ),
    responses=_responses(
        "فهرست درخواست‌ها با تعداد کل.",
        {"items": [{
            "id": "9f2c41ba07c34d5e8a1b2c3d4e5f6071",
            "hostname": "workstation-15",
            "platform": {"os_family": "Windows", "os_name": "Windows 11 Pro"},
            "agent_version": "1.0.0",
            "claimed_ips": ["192.168.1.51"],
            "mac": "d8:96:95:11:22:33",
            "gateway": "192.168.1.1",
            "status": "PENDING_APPROVAL",
            "requested_at": "2026-10-31T10:00:00+00:00",
            "expires_at": "2026-11-01T10:00:00+00:00",
        }], "total": 1, "limit": 100, "offset": 0},
    ),
)
def list_enrollment_requests(
    request: Request,
    status: str | None = Query(
        None,
        description="فیلتر وضعیت: PENDING_APPROVAL یا APPROVED یا ENROLLED یا REJECTED یا EXPIRED.",
    ),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    db.expire_due_enrollment_requests()
    items, total = db.list_enrollment_requests(status=status, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post(
    "/enrollment-requests/{request_id}/approve",
    tags=["مدیریت مدیر شبکه"],
    summary="تأیید درخواست ثبت‌نام عامل",
    description=(
        "مدیر اطلاعات اعلامی را بازبینی و تأیید می‌کند. پس از اولین claim عامل "
        "(با اثبات کلید هویت)، شناسه‌ی دائمی و اعتبارنامه‌ی اختصاصی صادر می‌شود "
        "و رکورد به `ENROLLED` می‌رود. تأیید به‌تنهایی اعتبارنامه‌ای به مدیر "
        "نمی‌دهد؛ اعتبارنامه فقط در کانال عامل تحویل می‌شود."
    ),
    responses=_responses(
        "رکورد درخواست پس از تأیید.",
        {"id": "9f2c41ba07c34d5e8a1b2c3d4e5f6071", "status": "APPROVED",
         "reviewed_by": "net-admin", "reviewed_at": "2026-10-31T10:05:00+00:00"},
        not_found="درخواست یافت نشد یا در وضعیت قابل بررسی نیست.",
        conflict=True,
    ),
)
def approve_enrollment_request(
    request: Request,
    request_id: str = Path(description="شناسه‌ی درخواست.",
                           examples=["9f2c41ba07c34d5e8a1b2c3d4e5f6071"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    reviewed = db.review_enrollment_request(request_id, approve=True, reviewed_by=actor)
    if reviewed is None:
        raise HTTPException(status_code=409,
                            detail="درخواست یافت نشد یا در وضعیت قابل بررسی نیست.")
    db.record_audit(actor=actor, action="enrollment_request.approve", target=request_id,
                    detail={"hostname": reviewed.get("hostname")})
    return reviewed


@router.post(
    "/enrollment-requests/{request_id}/reject",
    tags=["مدیریت مدیر شبکه"],
    summary="رد درخواست ثبت‌نام عامل",
    description=(
        "درخواست رد می‌شود و دلیل آن برای سابقه ثبت می‌گردد. عاملِ ردشده هرگز "
        "به‌عنوان دستگاه تأییدشده شناخته نمی‌شود، تسکی دریافت نمی‌کند و claim "
        "بعدی فقط وضعیت `REJECTED` با دلیل را می‌بیند."
    ),
    responses=_responses(
        "رکورد درخواست پس از رد.",
        {"id": "9f2c41ba07c34d5e8a1b2c3d4e5f6071", "status": "REJECTED",
         "reviewed_by": "net-admin", "reject_reason": "دستگاه ناشناس است"},
        not_found="درخواست یافت نشد یا در وضعیت قابل بررسی نیست.",
        conflict=True,
    ),
)
def reject_enrollment_request(
    request: Request,
    body: EnrollmentRejectBody,
    request_id: str = Path(description="شناسه‌ی درخواست.",
                           examples=["9f2c41ba07c34d5e8a1b2c3d4e5f6071"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    reviewed = db.review_enrollment_request(request_id, approve=False, reviewed_by=actor,
                                            reason=body.reason)
    if reviewed is None:
        raise HTTPException(status_code=409,
                            detail="درخواست یافت نشد یا در وضعیت قابل بررسی نیست.")
    db.record_audit(actor=actor, action="enrollment_request.reject", target=request_id,
                    detail={"hostname": reviewed.get("hostname"), "reason": body.reason})
    return reviewed


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


@router.get(
    "/agents",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست عوامل ثبت‌شده",
    description=(
        "همه‌ی عوامل با وضعیت محاسبه‌شده: عامل بی‌ضربانِ اخیر *stale* گزارش "
        "می‌شود (نه خاموش). با `include_revoked=true` عوامل باطل‌شده هم می‌آیند."
    ),
    responses=_responses(
        "فهرست عوامل؛ مقادیر نمونه illustrative هستند.",
        {"items": [{
            "id": "agt_9f2c41ba07c3",
            "hostname": "workstation-12",
            "platform": "Windows",
            "agent_version": "1.0.0",
            "status": "active",
            "seconds_since_heartbeat": 12.4,
            "capabilities": ["inventory", "connectivity_diagnostic"],
            "claimed_ips": ["192.168.1.51"],
            "latest_inventory_at": "2026-10-29T12:39:00+00:00",
            "enrolled_at": "2026-10-20T08:00:00+00:00",
        }]},
    ),
)
def list_agents(
    request: Request,
    include_revoked: bool = Query(False, description="نمایش عوامل باطل‌شده هم."),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف (۱ تا ۵۰۰)."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    _, settings2 = _ctx(request)
    items = [
        agent_public_view(a, settings2)
        for a in db.list_agents(limit=limit, offset=offset, include_revoked=include_revoked)
    ]
    return {"items": items}


@router.get(
    "/agents/{agent_id}",
    tags=["مدیریت مدیر شبکه"],
    summary="جزئیات یک عامل و آخرین inventory",
    description=(
        "رکورد عامل به‌همراه آخرین فهرست‌برداری ذخیره‌شده. `inventory=true` "
        "تاریخچه‌ی محدود inventory هم برمی‌گرداند."
    ),
    responses=_responses(
        "رکورد کامل عامل.",
        {
            "agent": {
                "id": "agt_9f2c41ba07c3",
                "hostname": "workstation-12",
                "status": "active",
                "capabilities": ["inventory", "admin_exec"],
            },
            "inventory": {"collected_at": "2026-10-29T12:39:00+00:00", "inventory": {
                "platform": {"os_family": "Windows", "os_name": "Windows 11 Pro"},
                "interfaces": [],
            }},
        },
        not_found="عاملی با این شناسه وجود ندارد.",
    ),
)
def get_agent(
    request: Request,
    agent_id: str = Path(description="شناسه‌ی عامل.", examples=["agt_9f2c41ba07c3"]),
    inventory: bool = Query(False, description="افزودن تاریخچه‌ی inventory (اختیاری)."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    agent = db.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    out: dict[str, Any] = {"agent": agent_public_view(agent, settings)}
    if inventory:
        out["inventory"] = db.get_latest_inventory(agent_id)
        out["inventory_history"] = db.list_inventory_history(agent_id, limit=10)
    return out


@router.post(
    "/agents/{agent_id}/revoke",
    tags=["مدیریت مدیر شبکه"],
    summary="ابطال اعتبارنامه‌ی یک عامل",
    description=(
        "اعتبارنامه‌ی عامل باطل می‌شود؛ هش توکن بازنویسی می‌شود و فراخوانی‌های "
        "بعدی با 403 رد می‌شوند. رکورد عامل برای حسابرسی باقی می‌ماند. برای "
        "ثبت‌نام دوباره، توکن ثبت‌نام جدید صادر کنید."
    ),
    responses=_responses(
        "نتیجه‌ی ابطال.",
        {"revoked": True, "agent_id": "agt_9f2c41ba07c3"},
        not_found="عاملی با این شناسه وجود ندارد.",
        conflict=True,
    ),
)
def revoke_agent(
    request: Request,
    agent_id: str = Path(description="شناسه‌ی عامل.", examples=["agt_9f2c41ba07c3"]),
    reason: str | None = Query(None, description="دلیل اختیاری برای حسابرسی.", max_length=300),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    ok = db.revoke_agent(agent_id, notes=reason)
    if not ok:
        raise HTTPException(status_code=404, detail="agent not found or already revoked")
    db.record_audit(actor=actor, action="agent.revoke", target=agent_id, detail={"reason": reason})
    return {"revoked": True, "agent_id": agent_id}


# ---------------------------------------------------------------------------
# Discovered networks
# ---------------------------------------------------------------------------


@router.get(
    "/networks",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست شبکه‌های کشف‌شده و محدوده‌ی مؤثر اسکن",
    description=(
        "مشاهده‌های شبکه‌ی گزارش‌شده از عوامل + تفکیک صریح «کشف‌شده» و "
        "«مجاز برای کشف فعال». شبکه‌های خصوصیِ مستقیماً متصل فقط در صورت "
        "فعال بودن `AUTO_DISCOVERY_ENABLED` و رعایت سقف‌ها مجاز می‌شوند؛ "
        "شبکه‌ی عمومی/loopback/VPN هرگز مجاز خودکار نمی‌شود."
    ),
    responses=_responses(
        "مشاهده‌ها و محدوده‌ی مؤثر.",
        {
            "observations": [{"agent_id": "agt_9f2c41ba07c3", "interface": "Ethernet",
                              "cidr": "192.168.1.0/24", "classification": "physical",
                              "connected": 1, "last_seen": "2026-10-29T12:39:00+00:00"}],
            "effective_scope": {
                "configured_cidrs": ["192.168.1.0/24"],
                "authorized_targets": [],
                "auto_discovered": [{"cidr": "10.20.0.0/24", "reporting_agents": ["agt_9f2c41ba07c3"],
                                     "justification": "private، مستقیماً متصل، …"}],
                "auto_discovery_enabled": True,
            },
        },
    ),
)
def list_networks(
    request: Request,
    agent_id: str | None = Query(None, description="فیلتر بر اساس عامل گزارش‌دهنده."),
    limit: int = Query(500, ge=1, le=1000, description="حداکثر تعداد مشاهده."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    return {
        "observations": db.list_network_observations(agent_id=agent_id, limit=limit),
        "effective_scope": effective_discovery_scope(db, settings),
    }


# ---------------------------------------------------------------------------
# Diagnostic tasks
# ---------------------------------------------------------------------------


@router.post(
    "/tasks",
    tags=["مدیریت مدیر شبکه"],
    summary="ایجاد تسک تشخیصی برای یک عامل",
    description=(
        "تسک‌های تشخیصی predefined: `inventory_collection` و "
        "`connectivity_diagnostic` و `service_inventory` و "
        "`network_configuration` و `approved_network_diagnostic`. اجرای کد "
        "دلخواه از این مسیر ممنوع است؛ برای آن مسیر جداگانه‌ی اسکریپت وجود "
        "دارد. تسک منقضی‌نشده با اولین GET عامل تحویل می‌شود."
    ),
    responses=_responses(
        "رکورد تسک ایجادشده.",
        {
            "id": "task_5b1e0a9c77d2f103",
            "agent_id": "agt_9f2c41ba07c3",
            "type": "connectivity_diagnostic",
            "status": "pending",
            "params": {"host": "192.168.1.1", "kind": "ping", "count": 3},
            "created_at": "2026-10-29T12:40:00+00:00",
            "expires_at": "2026-10-29T12:50:00+00:00",
        },
    ),
)
def create_task(
    request: Request,
    body: DiagnosticTaskCreate,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    try:
        task = task_service.create_diagnostic_task(
            db, settings,
            agent_id=body.agent_id,
            task_type=body.type,
            params=body.params,
            created_by=actor,
            priority=body.priority,
            timeout_seconds=body.timeout_seconds,
            ttl_seconds=body.ttl_seconds,
        )
    except task_service.TaskError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.record_audit(actor=actor, action="task.create", target=body.agent_id,
                    detail={"task_id": task["id"], "type": body.type})
    return task


@router.get(
    "/tasks",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست تسک‌ها با فیلتر",
    description=("وضعیت‌ها: pending و dispatched و succeeded و failed و timed_out و expired و cancelled."),
    responses=_responses(
        "فهرست تسک‌ها با تعداد کل.",
        {"items": [{"id": "task_5b1e0a9c77d2f103", "agent_id": "agt_9f2c41ba07c3",
                    "type": "inventory_collection", "status": "succeeded",
                    "origin": "admin", "created_by": "admin-api",
                    "created_at": "2026-10-29T12:40:00+00:00"}], "total": 1,
         "limit": 50, "offset": 0},
    ),
)
def list_tasks(
    request: Request,
    agent_id: str | None = Query(None, description="فیلتر عامل."),
    status: str | None = Query(None, description="فیلتر وضعیت."),
    task_type: str | None = Query(None, description="فیلتر نوع تسک."),
    limit: int = Query(50, ge=1, le=200, description="حداکثر تعداد ردیف."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items, total = db.list_tasks(agent_id=agent_id, status=status, task_type=task_type,
                                 limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get(
    "/tasks/{task_id}",
    tags=["مدیریت مدیر شبکه"],
    summary="جزئیات و نتیجه‌ی یک تسک",
    description=("شامل نتیجه‌ی ساختاریافته (برای تسک اسکریپت: stdout/stderr بریده‌شده و exit code)."),
    responses=_responses(
        "رکورد کامل تسک.",
        {
            "id": "task_5b1e0a9c77d2f103",
            "agent_id": "agt_9f2c41ba07c3",
            "type": "admin_python_script",
            "status": "succeeded",
            "result": {"ok": True, "exit_code": 0, "stdout": "workstation-12\n", "stderr": ""},
        },
        not_found="تسکی با این شناسه وجود ندارد.",
    ),
)
def get_task(
    request: Request,
    task_id: str = Path(description="شناسه‌ی تسک.", examples=["task_5b1e0a9c77d2f103"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    task = db.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@router.post(
    "/tasks/{task_id}/cancel",
    tags=["مدیریت مدیر شبکه"],
    summary="لغو تسک در انتظار",
    description=("فقط تسک pending یا dispatched قابل لغو است؛ تسک تمام‌شده تغییر نمی‌کند."),
    responses=_responses(
        "نتیجه‌ی لغو.",
        {"cancelled": True, "task_id": "task_5b1e0a9c77d2f103"},
        not_found="تسکی با این شناسه وجود ندارد.",
        conflict=True,
    ),
)
def cancel_task(
    request: Request,
    task_id: str = Path(description="شناسه‌ی تسک.", examples=["task_5b1e0a9c77d2f103"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    ok = db.cancel_task(task_id)
    if not ok:
        raise HTTPException(status_code=409, detail="task not found or not cancellable")
    db.record_audit(actor=actor, action="task.cancel", target=None, detail={"task_id": task_id})
    return {"cancelled": True, "task_id": task_id}


# ---------------------------------------------------------------------------
# Administrator remote Python execution
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/scripts",
    tags=["مدیریت مدیر شبکه"],
    summary="ارسال اسکریپت پایتون مدیریتی برای اجرا روی عامل",
    description=(
        "**فقط مدیر؛ هرگز از دسترس مدل زبانی خارج نیست.** نیازمند "
        "`ALLOW_ADMIN_PYTHON_EXEC=true` و `TASK_SIGNING_KEY` روی سرور و "
        "قابلیت `admin_exec` روی عامل. تسک با پاکت امضاشده (HMAC-SHA256) "
        "تحویل عامل می‌شود؛ عامل امضا، مقصد، انقضا و تکراری‌نبودن را قبل از "
        "اجرا بررسی می‌کند. خروجی stdout/stderr محدود و ثبت می‌شود. اسکریپت "
        "با دسترسی حساب سرویس عامل اجرا می‌شود — نه root/SYSTEM. نتیجه را با "
        "`GET /api/admin/v1/tasks/{task_id}` دنبال کنید."
    ),
    responses=_responses(
        "تسک اجرای اسکریپت با envelope امضاشده برای نمایش (کلید سرورتان محرمانه است).",
        {
            "id": "task_7c1d2299aa44b801",
            "agent_id": "agt_9f2c41ba07c3",
            "type": "admin_python_script",
            "status": "pending",
            "envelope": {"kind": "netagent.admin-task.v1",
                         "task_id": "task_7c1d2299aa44b801",
                         "agent_id": "agt_9f2c41ba07c3",
                         "type": "admin_python_script",
                         "expires_epoch": 1769647200.0,
                         "nonce": "9db1c0a4f2e3b5a6",
                         "signature": "…hex…"},
            "note": "کلید امضا فقط روی سرور و عامل است؛ LLM به آن دسترسی ندارد.",
        },
        not_found="عاملی با این شناسه وجود ندارد.",
        conflict=True,
    ),
)
def submit_script(
    request: Request,
    body: AdminScriptCreate,
    agent_id: str = Path(description="شناسه‌ی عامل هدف.", examples=["agt_9f2c41ba07c3"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    agent = db.get_agent(agent_id)
    if agent is None or agent.get("status") == "revoked":
        raise HTTPException(status_code=404, detail="agent not found")
    if body.agent_id != agent_id:
        raise HTTPException(status_code=422, detail="body.agent_id must match the path agent_id")
    try:
        task = task_service.create_admin_script_task(
            db, settings, agent=agent, code=body.code, created_by=actor,
            timeout_seconds=body.timeout_seconds, note=body.note,
        )
    except task_service.TaskError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.record_audit(
        actor=actor, action="admin_script.submit", target=agent_id,
        detail={"task_id": task["id"], "code_bytes": len(body.code.encode("utf-8")),
                "timeout_seconds": body.timeout_seconds, "note": body.note},
    )
    return task


# ---------------------------------------------------------------------------
# Interactive Python console (administrator-only)
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/console/sessions",
    tags=["ترمینال پایتون از راه دور"],
    summary="باز کردن نشست ترمینال پایتون روی یک عامل",
    description=(
        "**فقط مدیر؛ LLM هرگز به این مسیر دسترسی ندارد.** نیازمند "
        "`ALLOW_ADMIN_PYTHON_CONSOLE=true` و `TASK_SIGNING_KEY` و قابلیت "
        "`console` روی عامل. نشست به این مدیر و همین عامل گره می‌خورد؛ دستورها "
        "از طریق کانال تسک همان عامل می‌روند و state مفسر بین دستورها حفظ "
        "می‌شود. با `GET /api/admin/v1/console/sessions/{session_id}` وضعیت "
        "را دنبال کنید تا `status=active` شود."
    ),
    responses=_responses(
        "نشست ایجادشده (وضعیت creating تا آماده‌شدن مفسر در عامل).",
        {
            "id": "con_a1b2c3d4e5f6",
            "agent_id": "agt_9f2c41ba07c3",
            "actor": "net-admin",
            "status": "creating",
            "created_at": "2026-10-29T12:40:00+00:00",
            "expires_at": "2026-10-29T13:10:00+00:00",
            "start_task_id": "task_2f88cc11aa55b902",
        },
        not_found="عاملی با این شناسه وجود ندارد.",
    ),
)
def create_console_session(
    request: Request,
    body: ConsoleSessionCreate,
    agent_id: str = Path(description="شناسه‌ی عامل هدف.", examples=["agt_9f2c41ba07c3"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    agent = db.get_agent(agent_id)
    if agent is None or agent.get("status") == "revoked":
        raise HTTPException(status_code=404, detail="agent not found")
    console_service.sweep(db)
    try:
        session = console_service.create_session(
            db, settings, agent=agent, actor=actor, ttl_seconds=body.ttl_seconds,
        )
    except console_service.ConsoleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return session


@router.get(
    "/console/sessions",
    tags=["ترمینال پایتون از راه دور"],
    summary="فهرست نشست‌های ترمینال",
    description=("با فیلتر عامل/وضعیت. وضعیت‌ها: creating و active و terminated و expired و lost."),
    responses=_responses(
        "فهرست نشست‌ها.",
        {"items": [{"id": "con_a1b2c3d4e5f6", "agent_id": "agt_9f2c41ba07c3",
                    "actor": "net-admin", "status": "active",
                    "created_at": "2026-10-29T12:40:00+00:00",
                    "expires_at": "2026-10-29T13:10:00+00:00",
                    "last_active_at": "2026-10-29T12:44:10+00:00"}]},
    ),
)
def list_console_sessions(
    request: Request,
    agent_id: str | None = Query(None, description="فیلتر عامل."),
    status: str | None = Query(None, description="فیلتر وضعیت."),
    limit: int = Query(50, ge=1, le=200, description="حداکثر تعداد ردیف."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    console_service.sweep(db)
    return {"items": db.list_console_sessions(agent_id=agent_id, status=status, limit=limit)}


@router.get(
    "/console/sessions/{session_id}",
    tags=["ترمینال پایتون از راه دور"],
    summary="وضعیت نشست و دستورهای آن",
    description=(
        "شامل خروجی دستورها (stdout/stderr/نتیجه). نشست فقط برای همان مدیری که "
        "ساخته قابل مشاهده است. دستورهای در حال اجرا با `status=running` و "
        "لغوشده با `cancelled` مشخص می‌شوند."
    ),
    responses=_responses(
        "نشست + دستورها.",
        {
            "session": {"id": "con_a1b2c3d4e5f6", "status": "active",
                        "agent_id": "agt_9f2c41ba07c3"},
            "commands": [{"id": "cmd_11aa22bb33cc", "seq": 1, "status": "completed",
                          "code": "import socket; socket.gethostname()",
                          "stdout": "", "result_repr": "'workstation-12'",
                          "duration_ms": 41.2, "error": None}],
        },
        not_found="نشست یافت نشد یا متعلق به مدیر دیگری است.",
    ),
)
def get_console_session(
    request: Request,
    session_id: str = Path(description="شناسه‌ی نشست.", examples=["con_a1b2c3d4e5f6"]),
    commands_limit: int = Query(50, ge=1, le=200, description="حداکثر تعداد دستور برگشتی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    console_service.sweep(db)
    try:
        session = console_service.get_owned_session(db, session_id, actor)
    except console_service.ConsoleError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "session": session,
        "commands": db.list_console_commands(session_id, limit=commands_limit),
    }


@router.post(
    "/console/sessions/{session_id}/commands",
    tags=["ترمینال پایتون از راه دور"],
    summary="اجرای دستور پایتون در نشست",
    description=(
        "کد پایتون را در مفسرِ زنده‌ی نشست اجرا می‌کند؛ state بین دستورها "
        "حفظ می‌شود (متغیرها/importها می‌مانند). هر دستور سقف زمان و اندازه‌ی "
        "خروجی دارد. پاسخ فوری وضعیت queued می‌دهد؛ نتیجه را با GET همین مسیر "
        "دنبال کنید. تلاش برای ارسال دستور تکراری/پس از انقضا رد می‌شود."
    ),
    responses=_responses(
        "دستور ثبت‌شده در صف.",
        {"id": "cmd_44dd55ee66ff", "session_id": "con_a1b2c3d4e5f6", "seq": 2,
         "status": "queued",
         "code": "hosts.append('h1'); len(hosts)",
         "submitted_at": "2026-10-29T12:45:00+00:00",
         "task_id": "task_77ee88ff99aa"},
        not_found="نشست یافت نشد یا متعلق به مدیر دیگری است.",
    ),
)
def submit_console_command(
    request: Request,
    body: ConsoleCommandCreate,
    session_id: str = Path(description="شناسه‌ی نشست.", examples=["con_a1b2c3d4e5f6"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    try:
        session = console_service.get_owned_session(db, session_id, actor)
        command = console_service.submit_command(db, settings, session=session, code=body.code)
    except console_service.ConsoleError as exc:
        message = str(exc)
        status = 404 if "not found" in message or "another administrator" in message else 400
        raise HTTPException(status_code=status, detail=message) from exc
    return command


@router.post(
    "/console/sessions/{session_id}/commands/{command_id}/cancel",
    tags=["ترمینال پایتون از راه دور"],
    summary="لغو دستور در حال اجرا",
    description=(
        "لغو با خاتمه‌دادن زیرفرآیند مفسر انجام می‌شود؛ یعنی state نشست از بین "
        "می‌رود و نشست به وضعیت lost می‌رود (محدودیت طراحیِ امن: نخِ در حال "
        "اجرا قابل کشتن نیست). دستورهای صف‌شده لغو می‌شوند."
    ),
    responses=_responses(
        "وضعیت دستور پس از درخواست لغو.",
        {"id": "cmd_44dd55ee66ff", "status": "cancelling",
         "note": "مفسر نشست خاتمه می‌یابد؛ state حفظ نمی‌شود."},
        not_found="دستور در این نشست یافت نشد.",
    ),
)
def cancel_console_command(
    request: Request,
    command_id: str = Path(description="شناسه‌ی دستور.", examples=["cmd_44dd55ee66ff"]),
    session_id: str = Path(description="شناسه‌ی نشست.", examples=["con_a1b2c3d4e5f6"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    try:
        session = console_service.get_owned_session(db, session_id, actor)
        command = console_service.cancel_command(db, settings, session=session, command_id=command_id)
    except console_service.ConsoleError as exc:
        message = str(exc)
        status = 404 if "not found" in message else 400
        raise HTTPException(status_code=status, detail=message) from exc
    db.record_audit(actor=actor, action="console.command.cancel",
                    target=session["agent_id"],
                    detail={"session_id": session_id, "command_id": command_id})
    return command


@router.post(
    "/console/sessions/{session_id}/terminate",
    tags=["ترمینال پایتون از راه دور"],
    summary="خاتمه‌ی صریح نشست ترمینال",
    description=("مفسر راه‌دور بسته می‌شود و وضعیت نشست terminated می‌شود؛ دستورهای در صف هم لغو می‌شوند."),
    responses=_responses(
        "نشست خاتمه‌یافته.",
        {"id": "con_a1b2c3d4e5f6", "status": "terminated",
         "closed_at": "2026-10-29T12:50:00+00:00"},
        not_found="نشست یافت نشد یا متعلق به مدیر دیگری است.",
    ),
)
def terminate_console_session(
    request: Request,
    session_id: str = Path(description="شناسه‌ی نشست.", examples=["con_a1b2c3d4e5f6"]),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    try:
        session = console_service.get_owned_session(db, session_id, actor)
        closed = console_service.terminate_session(db, settings, session=session)
    except console_service.ConsoleError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return closed


# ---------------------------------------------------------------------------
# Audit history
# ---------------------------------------------------------------------------


@router.get(
    "/audit",
    tags=["مدیریت مدیر شبکه"],
    summary="تاریخچه‌ی حسابرسی عملیات مدیریتی",
    description=(
        "همه‌ی عملیات حساس: صدور توکن، ثبت‌نام/ابطال عامل، ایجاد/لغو تسک، "
        "ارسال اسکریپت، نشست‌ها و دستورهای ترمینال. متن دستورها و اسکریپت‌ها "
        "ذخیره می‌شوند (اندازه محدود) — خروجی حساس به‌صورت پیش‌فرض لاگ نمی‌شود."
    ),
    responses=_responses(
        "فهرست رویدادهای حسابرسی با تعداد کل.",
        {"items": [{"id": 12, "at": "2026-10-29T12:45:00+00:00", "actor": "net-admin",
                    "action": "console.command.submit", "target": "agt_9f2c41ba07c3",
                    "outcome": "ok",
                    "detail": {"session_id": "con_a1b2c3d4e5f6", "seq": 2}}],
         "total": 12, "limit": 100, "offset": 0},
    ),
)
def list_audit(
    request: Request,
    action: str | None = Query(None, description="فیلتر نوع رویداد مثل admin_script.submit."),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض) "
            "و اعتبارنامه‌ی عامل نقطه‌پایان در این مسیرها پذیرفته نمی‌شود."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description=(
            "هدر اختیاری `X-Admin-Actor`: برچسب منتسب به مدیر در گزارش حسابرسی "
            "(اتریبیوشن)، نه اعتبارنامه. مثال: `admin-ops`."
        ),
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items, total = db.list_audit(action=action, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}
