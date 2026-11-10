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

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, StrictBool

import hashlib

from netagent.config import Settings
from netagent.database import AnalysisQueueFull, Database
from netagent.schemas import (
    AdminMemoryCreate,
    AdminMemoryRevokeBody,
    AdminMemoryUpdateBody,
    AdminQuestionCreate,
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
from netagent.services.investigations import run_investigation
from netagent.services.knowledge import ask_question, validate_memory_fields

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
    else:
        raise AdminUnauthorized()
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
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


_admin_bearer = HTTPBearer(auto_error=False, scheme_name="AdministratorBearer")


def admin_access(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_admin_bearer),
) -> str:
    """Router-level gate shared by legacy, dashboard and administrative APIs."""
    authorization = f"Bearer {credentials.credentials}" if credentials else None
    return _guard(request, authorization, request.headers.get("x-admin-actor"))


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
# AI security-alert analyses (background LLM analysis queue)
# ---------------------------------------------------------------------------


@router.get(
    "/ai-analyses",
    tags=["مدیریت مدیر شبکه"],
    summary="فهرست تحلیل‌های هوش مصنوعی هشدارهای امنیتی",
    description=(
        "خروجی کارگر پس‌زمینه‌ی تحلیل: برای هر هشدار، وضعیت (`PENDING` یا "
        "`PROCESSING` یا `COMPLETED` یا `FAILED`) و در صورت آماده بودن، خلاصه، "
        "اهمیت، شواهد، احتمال غیرعادی بودن، اطمینان و پیشنهاد اقدام. تحلیل "
        "**برداشت مدل** است نه واقعیت قطعی؛ هشدار = تطابق قانون، نه اثبات نفوذ. "
        "صفحه‌ی Security داشبورد این داده را با فهرست هشدارها ادغام می‌کند."
    ),
    responses=_responses(
        "فهرست تحلیل‌ها به ترتیب هشدار.",
        {"items": [{
            "alert_id": 34,
            "status": "COMPLETED",
            "summary": "تطابق امضای نسخه‌ی قدیمی TLS؛ رفتار رایج شبکه‌های داخلی است.",
            "importance": "low",
            "evidence": ["signature=SURICATA TLS Obsolete Version", "action=allowed"],
            "anomaly_likelihood": "low",
            "confidence": "medium",
            "recommendation": "بررسی نسخه‌ی TLS سرویس مقصد در فرصت مناسب کافی است.",
            "model": "gemma-4-e2b-it-q4_0--2-:latest",
            "prompt_version": "alert-analysis-v1",
            "analyzed_at": "2026-11-01T10:00:00+00:00",
        }]},
    ),
)
def list_ai_analyses(
    request: Request,
    status: str | None = Query(
        None, description="فیلتر وضعیت: PENDING یا PROCESSING یا COMPLETED یا FAILED."
    ),
    limit: int = Query(300, ge=1, le=1000, description="حداکثر تعداد ردیف."),
    alert_ids: str | None = Query(None, max_length=2400, description="شناسه‌های هشدار جداشده با ویرگول؛ حداکثر ۲۰۰ مورد."),
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
    if alert_ids is not None:
        try:
            ids = [int(part) for part in alert_ids.split(",")]
            if len(ids) > 200 or any(i < 1 for i in ids):
                raise ValueError()
        except ValueError:
            raise HTTPException(422, detail="شناسه‌های هشدار نامعتبر است.")
        return {"items": [row for aid in dict.fromkeys(ids) if (row := db.get_alert_analysis(aid)) is not None]}
    return {"items": db.list_alert_analyses(status=status, limit=limit)}


class SecurityAutoAnalysisBody(BaseModel):
    enabled: StrictBool


@router.get("/security-ai", tags=["مدیریت مدیر شبکه"], summary="وضعیت واقعی صف و کنترل تحلیل امنیت",
            description="تنظیم ماندگار، شمارش کل صف، آخرین پردازش و بررسی اتصال و وجود مدل؛ بدون تولید پاسخ مدل.",
            responses={k: v for k, v in _responses("وضعیت تحلیل امنیت.", {"auto_enabled": False,
                "counts": {"PENDING": 0, "PROCESSING": 0, "COMPLETED": 0, "FAILED": 0},
                "model": "gemma-4-e4b:latest", "connection": {"ok": False, "detail": "disabled"}}).items() if k != 422})
def security_ai_status(request: Request) -> dict[str, Any]:
    db, settings = _ctx(request)
    llm = request.app.state.llm
    connection = llm.connection_status() if llm is not None else {"ok": False, "detail": "disabled"}
    return {**db.analysis_summary(), "model": settings.llm_model,
            "connection": connection, "worker_enabled": settings.ai_analysis_enabled and llm is not None,
            "capacity": settings.ai_analysis_backlog_limit}


@router.put("/security-ai/automatic", tags=["مدیریت مدیر شبکه"], summary="تغییر ماندگار تحلیل خودکار؛ پیش‌فرض خاموش",
            description="فقط مدیر؛ تغییر همراه حسابرسی ذخیره می‌شود. روشن‌کردن شامل تاریخچه نمی‌شود و خاموش‌کردن صف قبلی را حفظ می‌کند.",
            responses=_responses("حالت ذخیره‌شده.", {"auto_enabled": True}))
def set_security_ai_auto(request: Request, body: SecurityAutoAnalysisBody,
                        authorization: str | None = Header(default=None, description="توکن مدیر با پیشوند Bearer."),
                        x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر برای حسابرسی.")) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    return {"auto_enabled": db.set_security_ai_auto(body.enabled, actor=actor)}


@router.post("/ai-analyses/{alert_id}/analyze", tags=["مدیریت مدیر شبکه"], summary="تحلیل فقط یک هشدار با جلوگیری از تکرار",
            description="شناسهٔ پایدار همان هشدار را صف‌بندی می‌کند؛ queued/processing/completed موجود برگردانده می‌شود و شکست اجازهٔ تلاش تازه دارد.",
            responses={**_responses("رکورد فعلی تحلیل.", {"alert_id": 1, "job_id": "example", "status": "PENDING"},
                not_found="هشدار وجود ندارد."), 429: {"description": "صف پر است؛ تلاش بعدی با رعایت Retry-After."}})
def analyze_alert(request: Request, alert_id: int = Path(description="شناسهٔ پایدار هشدار.", ge=1),
                  authorization: str | None = Header(default=None, description="توکن مدیر با پیشوند Bearer."),
                  x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر برای حسابرسی.")) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    return _request_analysis(db, settings, alert_id, actor=actor)


def _request_analysis(db, settings, alert_id, *, actor, reanalyze=False):
    try:
        row = db.request_alert_analysis(alert_id, actor=actor,
            capacity=settings.ai_analysis_backlog_limit, reanalyze=reanalyze)
    except AnalysisQueueFull as exc:
        raise HTTPException(429, detail=str(exc), headers={"Retry-After": "30"}) from exc
    if row is None:
        raise HTTPException(404, detail="هشداری با این شناسه وجود ندارد.")
    return row


@router.get("/ai-analyses/{alert_id}/history", tags=["مدیریت مدیر شبکه"], summary="تاریخچهٔ محفوظ تلاش‌های تحلیل",
            description="نتایج تلاش‌های پیشین که هنگام درخواست صریح retry یا reanalyze بایگانی شدند؛ حذف تاریخچه انجام نمی‌شود.",
            responses=_responses("تاریخچهٔ تحلیل.", {"items": []}, not_found="هشدار وجود ندارد."))
def analysis_history(request: Request, alert_id: int = Path(description="شناسهٔ پایدار هشدار.", ge=1)) -> dict[str, Any]:
    db, _ = _ctx(request)
    if not db.get_alert(alert_id):
        raise HTTPException(404, detail="هشداری با این شناسه وجود ندارد.")
    return {"items": db.alert_analysis_history(alert_id)}


@router.post(
    "/ai-analyses/{alert_id}/reanalyze",
    tags=["مدیریت مدیر شبکه"],
    summary="درخواست تحلیل مجدد یک هشدار",
    description=(
        "رکورد تحلیل به `PENDING` برمی‌گردد و بودجه‌ی تلاش دوباره فعال می‌شود؛ "
        "کارگر پس‌زمینه آن را دوباره به مدل می‌دهد. نتیجه‌ی قبلی تا آماده شدن "
        "نتیجه‌ی جدید باقی می‌ماند."
    ),
    responses=_responses(
        "وضعیت رکورد پس از درخواست.",
        {"alert_id": 34, "status": "PENDING", "queued": True},
        not_found="برای این هشدار تحلیلی ثبت نشده است.",
    ),
)
def reanalyze_alert(
    request: Request,
    alert_id: int = Path(description="شناسه‌ی هشدار.", examples=[34]),
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
    return _request_analysis(db, settings, alert_id, actor=actor, reanalyze=True)


# ---------------------------------------------------------------------------
# AI Activity Monitor (v8): observable lifecycle of every real LLM request
# ---------------------------------------------------------------------------


@router.get(
    "/ai-activity/summary",
    tags=["پایش فعالیت هوش مصنوعی"],
    summary="وضعیت تجمیعی فعالیت مدل محلی",
    description=(
        "آمار واقعی درخواست‌های LLM: تعداد رکوردها بر اساس وضعیت "
        "(`RUNNING`/`COMPLETED`/`FAILED`/`TIMEOUT`)، میانگین زمان پاسخ، آخرین "
        "فعالیت، خطاهای اخیر و وضعیت صف تحلیل. همه‌ی مقادیر از رکوردهای واقعی "
        "می‌آیند؛ هیچ شمارنده‌ی ساختگی و انیمیشن فعال‌کننده وجود ندارد."
    ),
    responses=_responses(
        "خلاصه‌ی فعالیت مدل.",
        {
            "counts": {"COMPLETED": 12, "FAILED": 2},
            "avg_duration_ms": 4120.5,
            "last_final_at": "2026-11-06T09:30:00+00:00",
            "last_created_at": "2026-11-06T09:29:41+00:00",
            "last_error": {"error": "LLMUnavailable: LLM request failed: APITimeoutError", "final_at": "..."},
            "recent_errors": [
                {"error": "LLMUnavailable: ...", "final_at": "2026-11-06T09:10:02+00:00"}
            ],
            "queue": {"alert_analysis_pending_and_running": 3},
            "model": "gemma-4-e2b-it-q4_0--2-:latest",
            "llm_enabled": True,
        },
    ),
)
def ai_activity_summary(
    request: Request,
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض)."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description="برچسب اختیاری مدیر برای حسابرسی، مثال: `admin-ops`.",
    ),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    summary = db.ai_activity_summary()
    summary["queue"] = {
        "alert_analysis_pending_and_running": db.pending_alert_analysis_count(),
    }
    summary["model"] = settings.llm_model if settings.llm_enabled else None
    summary["llm_enabled"] = settings.llm_enabled
    return summary


@router.get(
    "/ai-activity",
    tags=["پایش فعالیت هوش مصنوعی"],
    summary="فهرست رکوردهای فعالیت مدل",
    description=(
        "یک رکورد به‌ازای هر درخواست/کار LLM — تحلیل هشدار (تکی یا گروهی) یا "
        "بررسی هوشمند. برای هر رکورد: شناسه درخواست، نوع کار، ارجاع‌های مرتبط "
        "(`refs`)، مدل، نسخه پرامپت، وضعیت، زمان‌ها (ایجاد، ارسال، اولین توکن، "
        "پاسخ)، مدت، خلاصه‌ی خروجی و خطا. مراحل ساختگی نمایش داده نمی‌شوند؛ "
        "فقط مسیرِ واقعیِ انجام‌شده."
    ),
    responses=_responses(
        "فهرست رکوردهای فعالیت به ترتیب زمان.",
        {
            "items": [{
                "request_id": "act_3f6a9c2b",
                "task_type": "alert_analysis",
                "status": "COMPLETED",
                "duration_ms": 4120.5,
                "model": "gemma-4-e2b-it-q4_0--2-:latest",
                "created_at": "2026-11-06T09:29:41+00:00",
            }],
            "total": 184,
        },
    ),
)
def list_ai_activity(
    request: Request,
    task_type: str | None = Query(
        None, description="فیلتر نوع کار: alert_analysis یا alert_analysis_batch یا investigation."
    ),
    status: str | None = Query(
        None, description="فیلتر وضعیت: RUNNING یا COMPLETED یا FAILED یا TIMEOUT."
    ),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد رکورد."),
    offset: int = Query(0, ge=0, description="شیفت صفحه‌بندی."),
    authorization: str | None = Header(
        default=None,
        description=(
            "هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. "
            "توکن مدیر از متغیر محیطی `ADMIN_API_TOKEN` می‌آید (بدون مقدار پیش‌فرض)."
        ),
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description="برچسب اختیاری مدیر برای حسابرسی، مثال: `admin-ops`.",
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items, total = db.list_ai_activity(
        task_type=task_type, status=status, limit=limit, offset=offset
    )
    return {"items": items, "total": total}


@router.get(
    "/ai-activity/{request_id}",
    tags=["پایش فعالیت هوش مصنوعی"],
    summary="جزئیات و خط زمانی یک درخواست",
    description=(
        "خط زمانی کامل (و فقط خط زمانی واقعی) یک درخواست: مرحله، زمان و "
        "بلوک ابزارها. در صفحه‌ی AI Activity برای باز کردن جزئیات استفاده می‌شود."
    ),
    responses=_responses(
        "رکورد کامل فعالیت.",
        {
            "request_id": "act_3f6a9c2b",
            "task_type": "alert_analysis_batch",
            "status": "COMPLETED",
            "timeline": [
                {"stage": "REQUEST_CREATED", "at": "2026-11-06T09:29:41+00:00"},
                {"stage": "SENT_TO_LLM", "at": "2026-11-06T09:29:41+00:00"},
                {"stage": "FIRST_TOKEN_RECEIVED", "at": "2026-11-06T09:29:52+00:00"},
                {"stage": "RESPONSE_RECEIVED", "at": "2026-11-06T09:29:58+00:00"},
                {"stage": "PERSISTED", "at": "2026-11-06T09:29:58+00:00"},
            ],
        },
        not_found="درخواستی با این شناسه وجود ندارد (ممکن است حذف شده باشد).",
    ),
)
def get_ai_activity(
    request: Request,
    request_id: str = Path(description="شناسه‌ی درخواست.", examples=["act_3f6a9c2b"]),
    authorization: str | None = Header(
        default=None,
        description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`. توکن مدیر اجباری است.",
    ),
    x_admin_actor: str | None = Header(
        default=None,
        description="برچسب اختیاری مدیر برای حسابرسی، مثال: `admin-ops`.",
    ),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    row = db.get_ai_activity(request_id)
    if row is None:
        raise HTTPException(status_code=404, detail="درخواستی با این شناسه یافت نشد.")
    return row


# ---------------------------------------------------------------------------
# Persistent knowledge base (v9): AI memory (admin-owned)
# ---------------------------------------------------------------------------


@router.get(
    "/ai-memories",
    tags=["حافظه‌ی دائمی هوش مصنوعی"],
    summary="فهرست حافظه‌ها (دانش تأییدشده و پیش‌نویس‌ها)",
    description=(
        "همه‌ی رکوردهای حافظه با وضعیت: `APPROVED` (قابل استفاده در تحلیل)، "
        "`PENDING_APPROVAL` (پیشنهاد AI و فقط با تأیید مدیر فعال می‌شود)، "
        "`REVOKED` و `EXPIRED`. رکوردهای منقضی‌شده به‌صورت خودکار علامت‌گذاری "
        "می‌شوند و دیگر در تحلیل استفاده نمی‌شوند."
    ),
    responses=_responses(
        "فهرست حافظه‌ها (جدیدترین اول).",
        {"items": [{
            "memory_id": "mem_9c2b1f",
            "title": "سرویس Tor روی این عامل عمداً فعال است",
            "category": "approved_service",
            "agent_id": "agt_1a2c", "scope": "agent",
            "status": "APPROVED",
            "expires_at": None, "hit_count": 4,
        }]},
    ),
)
def list_ai_memories(
    request: Request,
    category: str | None = Query(None, description="فیلتر دسته‌بندی."),
    status: str | None = Query(None, description="فیلتر وضعیت."),
    agent_id: str | None = Query(None, description="فیلتر عامل."),
    limit: int = Query(200, ge=1, le=1000, description="حداکثر تعداد رکورد."),
    offset: int = Query(0, ge=0, description="شیفت صفحه‌بندی."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items = db.list_memories(
        category=category, status=status, agent_id=agent_id,
        limit=limit, offset=offset,
    )
    return {"items": items}


@router.post(
    "/ai-memories",
    tags=["حافظه‌ی دائمی هوش مصنوعی"],
    summary="ثبت مستقیم حافظه توسط مدیر (بلافاصله APPROVED)",
    description=(
        "دانش مدیریتی را مستقیم ثبت کنید؛ رکورد با `source=administrator` و وضعیت "
        "APPROVED از همان تحلیل بعدی قابل استفاده است. برای جلوگیری از مسمومیت "
        "حافظه، مدل و لاگ به این مسیر دسترسی ندارند؛ پیشنهادهای AI از مسیر "
        "سؤال‌ها (AI Knowledge) می‌آیند و تا تأیید در همان وضعیت می‌مانند."
    ),
    responses=_responses(
        "رکورد حافظه‌ی ثبت‌شده.",
        {"memory_id": "mem_9c2b1f", "status": "APPROVED"},
    ),
    status_code=201,
)
def create_admin_memory(
    request: Request,
    body: AdminMemoryCreate,
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    errors: list[str] = []
    if not validate_memory_fields(
        category=body.category, scope=body.scope, agent_id=body.agent_id,
        host=body.host, process=body.process, service=body.service,
        network=body.network, errors=errors,
    ):
        raise HTTPException(status_code=422, detail="؛ ".join(errors))
    memory_id = (
        "mem_" + hashlib.sha256(
            f"{body.title}|{body.agent_id}|{body.host}".encode()
        ).hexdigest()[:16]
    )
    if db.get_memory(memory_id) is None:
        db.create_memory(
            memory_id=memory_id, title=body.title, description=body.description,
            category=body.category, agent_id=body.agent_id, host=body.host,
            process=body.process, service=body.service, network=body.network,
            evidence=[e for e in body.evidence if isinstance(e, str)],
            source="administrator", created_by=actor,
            status="APPROVED", confidence=body.confidence, scope=body.scope,
            expires_at=body.expires_at or None,
        )
    db.record_audit(actor=actor, action="memory.create", target=memory_id,
                    detail={"category": body.category, "scope": body.scope})
    return db.get_memory(memory_id)  # type: ignore[return-value]


@router.post(
    "/ai-memories/{memory_id}/approve",
    tags=["حافظه‌ی دائمی هوش مصنوعی"],
    summary="تأیید یک حافظه‌ی پیش‌نهادی",
    description=(
        "تنها مسیر PENDING_APPROVAL → APPROVED در کل سامانه همین است و مدل/لاگ "
        "نمی‌توانند از آن عبور کنند؛ عملیات در حسابرسی ثبت می‌شود."
    ),
    responses=_responses(
        "حافظه‌ی تأییدشده.",
        {"memory_id": "memA_11", "status": "APPROVED"},
        not_found="حافظه‌ای با این شناسه نیست.",
    ),
)
def approve_ai_memory(
    request: Request,
    memory_id: str = Path(description="شناسه حافظه."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    if not db.approve_memory(memory_id, approved_by=actor):
        if db.get_memory(memory_id) is None:
            raise HTTPException(status_code=404, detail="حافظه‌ای با این شناسه نیست.")
        raise HTTPException(status_code=409, detail="حافظه در وضعیت تأییدپذیر نیست.")
    db.record_audit(actor=actor, action="memory.approve", target=memory_id)
    return db.get_memory(memory_id)  # type: ignore[return-value]


@router.post(
    "/ai-memories/{memory_id}/revoke",
    tags=["حافظه‌ی دائمی هوش مصنوعی"],
    summary="لغو حافظه",
    description=(
        "وضعیت به REVOKED تغییر می‌کند؛ حافظه از تحلیل‌ها حذف می‌شود ولی برای "
        "حسابرسی باقی می‌ماند. دلیل لغو در سابقه ذخیره می‌شود."
    ),
    responses=_responses(
        "حافظه‌ی لغوشده.",
        {"memory_id": "mem_9c2b1f", "status": "REVOKED"},
        not_found="حافظه‌ای با این شناسه نیست.",
    ),
)
def revoke_ai_memory(
    request: Request,
    memory_id: str = Path(description="شناسه حافظه."),
    body: AdminMemoryRevokeBody | None = None,
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    reason = body.reason if body else None
    if not db.revoke_memory(memory_id, revoked_by=actor, reason=reason):
        if db.get_memory(memory_id) is None:
            raise HTTPException(status_code=404, detail="حافظه‌ای با این شناسه نیست.")
        raise HTTPException(status_code=409, detail="حافظه قابل لغو نیست.")
    db.record_audit(actor=actor, action="memory.revoke", target=memory_id,
                    detail={"reason": reason})
    return db.get_memory(memory_id)  # type: ignore[return-value]


@router.post(
    "/ai-memories/{memory_id}/update",
    tags=["حافظه‌ی دائمی هوش مصنوعی"],
    summary="اصلاح حافظه",
    description=(
        "اصلاح عنوان/توضیح/اطمینان/انقضا. محدوده‌ی اعتبار (agent/host/…) برای "
        "ایمنی از این مسیر قابل تغییر نیست؛ اصلاح محدوده یعنی ثبت حافظه‌ی و لغو قبلی."
    ),
    responses=_responses(
        "حافظه‌ی به‌روزشده.",
        {"memory_id": "mem_9c2b1f"},
        not_found="حافظه‌ای با این شناسه نیست.",
    ),
)
def update_ai_memory(
    request: Request,
    body: AdminMemoryUpdateBody,
    memory_id: str = Path(description="شناسه حافظه."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    changed = db.update_memory(
        memory_id, title=body.title, description=body.description,
        confidence=body.confidence,
        expires_at=body.expires_at if body.expires_at is not None else ...,
    )
    if not changed:
        if db.get_memory(memory_id) is None:
            raise HTTPException(status_code=404, detail="حافظه‌ای با این شناسه نیست.")
        raise HTTPException(status_code=400, detail="ایرادی برای اعمال وجود ندارد.")
    db.record_audit(actor=actor, action="memory.update", target=memory_id)
    return db.get_memory(memory_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# AI knowledge questions (v10): admin asks; answer may propose memory
# ---------------------------------------------------------------------------


@router.post(
    "/ai-questions",
    tags=["پرسش هوشمند از دانش شبکه"],
    summary="پرسیدن یک سؤال از مدل (همگام، بدون اجرای ابزار)",
    description=(
        "یک سؤال کوتاه درباره‌ی شبکه/هشدار از مدل محلی می‌پرسد. هیچ ابزاری اجرا "
        "نمی‌شود؛ پاسخ ساختاریمند (answer + confidence) ذخیره می‌شود و اگر مدل "
        "دانش جدیدی پیشنهاد کند، آن پیشنهاد فقط به‌صورت حافظه‌ی "
        "`PENDING_APPROVAL` (source=question_resolve) ثبت می‌شود و تا تأیید شما "
        "در هیچ تحلیلی استفاده نمی‌شود. فراخوانی تا دریافت پاسخ مکث می‌کند "
        "(با مدل محلی معمولاً چند ثانیه)."
    ),
    responses=_responses(
        "سؤال با پاسخ ذخیره‌شده یا خطای دقیق.",
        {
            "question_id": "q_1c2b3a4d5e6f7788",
            "question": "چرا این هشدار تکرار می‌شود؟",
            "status": "ANSWERED",
            "answer": "…", "answer_meta": {"confidence": "medium"},
            "memory_proposal_ids": [],
        },
    ),
)
def create_ai_question(
    request: Request,
    body: AdminQuestionCreate,
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    if body.alert_id is not None and db.get_alert(body.alert_id) is None:
        raise HTTPException(status_code=404, detail="هشداری با این شناسه نیست.")
    try:
        record = ask_question(
            db, request.app.state.llm,
            question=body.question, agent_id=body.agent_id,
            alert_id=body.alert_id, asked_by=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # model/network failure — the FAILED record stays
        raise HTTPException(
            status_code=502, detail=f"پرسش ناموفق بود: {exc}"[:300]
        ) from exc
    db.record_audit(actor=actor, action="question.create",
                    target=record.get("question_id"))
    return record


@router.get(
    "/ai-questions",
    tags=["پرسش هوشمند از دانش شبکه"],
    summary="فهرست سؤال‌های مدیر و پاسخ‌ها",
    description=(
        "سؤال‌های ثبت‌شده (جدیدترین اول) با وضعیت `PENDING`، `ANSWERED`، `FAILED` "
        "و شناسه‌ی حافظه‌های پیشنهادی. حافظه‌های پیشنهادی از این لیست همیشه "
        "PENDING_APPROVAL‌اند تا مدیر در صفحه‌ی حافظه آن‌ها را تأیید/لغو کند."
    ),
    responses=_responses(
        "فهرست سؤال‌ها.",
        {"items": [{
            "question_id": "q_1c2b3a4d5e6f7788",
            "question": "…",
            "status": "ANSWERED",
            "memory_proposal_ids": ["memq_11ff22"],
        }]},
    ),
)
def list_ai_questions(
    request: Request,
    status: str | None = Query(None, description="فیلتر وضعیت."),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items = db.list_ai_questions(status=status, limit=limit, offset=offset)
    return {"items": items}


@router.get(
    "/ai-questions/{question_id}",
    tags=["پرسش هوشمند از دانش شبکه"],
    summary="جزئیات یک سؤال",
    description=(
        "رکورد کامل سؤال: متن سؤال، زمینه‌ی ارسال‌شده، پاسخ ذخیره‌شده (کوتاه)، "
        "اطمینان، مدت پاسخ و شناسه‌ی حافظه‌های پیشنهادی که هنوز در وضعیت "
        "`PENDING_APPROVAL` منتظر تصمیم مدیرند. پاسخ مدل هرگز مستقیم اجرا "
        "نمی‌شود و در حسابرسی فقط ثبت سؤال/پرسشنگار دیده می‌شود."
    ),
    responses=_responses(
        "رکورد سؤال.",
        {"question_id": "q_1c2b3a4d5e6f7788", "question": "…", "status": "ANSWERED"},
        not_found="سؤالی با این شناسه نیست.",
    ),
)
def get_ai_question(
    request: Request,
    question_id: str = Path(description="شناسه سؤال."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    record = db.get_ai_question(question_id)
    if record is None:
        raise HTTPException(status_code=404, detail="سؤالی با این شناسه نیست.")
    return record


# ---------------------------------------------------------------------------
# AI action proposals (v11): observe-first, admin decides
# ---------------------------------------------------------------------------


@router.get(
    "/ai-actions",
    tags=["پیشنهادهای عملکرد هوشمند"],
    summary="فهرست پیشنهادهای شِیء-را انجام بده (Observe-Only)",
    description=(
        "هر چیزی که موتور هوشمند «انجام بده» می‌خواهد، ابتدا اینجا به‌صورت "
        "`OBSERVED` ثبت می‌شود و هیچ تغییری در شبکه نمی‌دهد؛ فعال‌سازی فقط با "
        "تأیید مدیر. حالت پیش‌فرض برابری با Observe Only است."
    ),
    responses=_responses(
        "فهرست پیشنهادها (جدیدترین اول).",
        {"items": [{
            "action_id": "actn_11aa22bb33",
            "kind": "run_investigation",
            "status": "OBSERVED",
            "target": {"target_ip": "10.10.0.4"},
        }]},
    ),
)
def list_ai_actions(
    request: Request,
    status: str | None = Query(None, description="فیلتر وضعیت."),
    limit: int = Query(100, ge=1, le=500, description="حداکثر تعداد ردیف."),
    offset: int = Query(0, ge=0, description="صفحه‌بندی."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    items = db.list_ai_actions(status=status, limit=limit, offset=offset)
    return {"items": items}


@router.post(
    "/ai-actions/{action_id}/approve",
    tags=["پیشنهادهای عملکرد هوشمند"],
    summary="تأیید و اجرای یک پیشنهاد بررسی",
    description=(
        "تنها مسیر OBSERVED → اجرا. برای اقدام جاری اول بررسی هوشمند روی هدف می‌آید؛ "
        "پیشنهاد با حسابرسی تصمیم مدیر به EXECUTED/FAILED می‌رسد."
    ),
    responses=_responses(
        "پیشنهاد با نتیجه/آی‌دی اجرا.",
        {"action_id": "actn_11aa22bb33", "status": "EXECUTED",
         "result": {"investigation_id": 42}},
        not_found="پیشنهادی با این شناسه نیست.",
    ),
)
def approve_ai_action(
    request: Request,
    action_id: str = Path(description="شناسه پیشنهاد."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, settings = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    action = db.get_ai_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="پیشنهادی با این شناسه نیست.")
    if action["status"] != "OBSERVED":
        raise HTTPException(status_code=409, detail="پیشنهاد در وضعیت تأییدپذیر نیست.")
    if action["kind"] != "run_investigation":
        raise HTTPException(status_code=422, detail="این نوع پیشنهاد فعلاً قابل اجرا نیست.")
    target = action.get("target") or {}
    try:
        record = run_investigation(
            db, settings, request.app.state.llm,
            target_ip=target.get("target_ip"),
            alert_id=target.get("alert_id"),
        )
    except Exception as exc:
        db.decide_ai_action(action_id, decided_by=actor, status="OBSERVED")
        db.finish_ai_action(action_id, status="FAILED", result={"error": str(exc)[:300]})
        db.record_audit(actor=actor, action="action.approve", target=action_id,
                        detail={"outcome": "FAILED", "error": str(exc)[:200]})
        raise HTTPException(status_code=502, detail=f"اجرای بررسی ناموفق: {exc}"[:300]) from exc
    db.decide_ai_action(action_id, decided_by=actor, status="APPROVED")
    db.finish_ai_action(
        action_id, status="EXECUTED",
        result={"investigation_id": record.get("id")},
    )
    db.record_audit(actor=actor, action="action.approve", target=action_id,
                    detail={"outcome": "EXECUTED",
                            "investigation_id": record.get("id")})
    return db.get_ai_action(action_id)  # type: ignore[return-value]


@router.post(
    "/ai-actions/{action_id}/reject",
    tags=["پیشنهادهای عملکرد هوشمند"],
    summary="رد یک پیشنهاد",
    description=(
        "پیشنهاد از `OBSERVED` به `REJECTED` می‌رود و دیگر پیگیری نمی‌شود؛ "
        "در حسابرسی با تصمیم‌گیرنده ثبت می‌ماند. رکورد حذف نمی‌شود تا بتوان "
        "بعداً دید موتور چند پیشنهاد بی‌اثر داده است."
    ),
    responses=_responses(
        "پیشنهاد ردشده.",
        {"action_id": "actn_11aa22bb33", "status": "REJECTED"},
        not_found="پیشنهادی با این شناسه نیست.",
    ),
)
def reject_ai_action(
    request: Request,
    action_id: str = Path(description="شناسه پیشنهاد."),
    authorization: str | None = Header(default=None, description="هدر `Authorization: Bearer <ADMIN_API_TOKEN>`."),
    x_admin_actor: str | None = Header(default=None, description="برچسب اختیاری مدیر."),
) -> dict[str, Any]:
    db, _ = _ctx(request)
    actor = _guard(request, authorization, x_admin_actor)
    if not db.get_ai_action(action_id):
        raise HTTPException(status_code=404, detail="پیشنهادی با این شناسه نیست.")
    if not db.decide_ai_action(action_id, decided_by=actor, status="REJECTED"):
        raise HTTPException(status_code=409, detail="پیشنهاد در وضعیت قابل رد نیست.")
    db.record_audit(actor=actor, action="action.reject", target=action_id)
    return db.get_ai_action(action_id)  # type: ignore[return-value]


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


@router.get(
    "/agents/{agent_id}/traffic",
    tags=["مدیریت مدیر شبکه"],
    summary="نمودار و جریان‌های ترافیک یک عامل",
    description=(
        "سری زمانی شمارنده‌ها با نرخ upload/download (محاسبه‌شده روی سرور از دو "
        "نمونه‌ی متوالی)، آخرین اتصال‌های فعال و زمان آخرین جمع‌آوری. منبع داده "
        "فقط گزارش خود عامل است — متادیتای همان سیستم، بدون payload. اگر عامل "
        "قابلیت traffic را فعال نکرده باشد، خالی برمی‌گردد (Empty State)."
    ),
    responses=_responses(
        "سری زمانی + آخرین وضعیت.",
        {
            "samples": [
                {"ts": "2026-11-01T10:00:00+00:00", "interface": "eth0",
                 "rx_rate": 12400.5, "tx_rate": 3100.2, "rx_bytes": 1823456789,
                 "tx_bytes": 234567890, "active_connections": 31},
            ],
            "latest": {"ts": "2026-11-01T10:00:00+00:00",
                       "connections": [{"local": "192.168.1.51:52311",
                                        "remote": "142.250.185.68:443", "state": "ESTAB"}]},
            "hours": 24,
        },
        not_found="عاملی با این شناسه وجود ندارد.",
    ),
)
def get_agent_traffic(
    request: Request,
    agent_id: str = Path(description="شناسه‌ی عامل.", examples=["agt_9f2c41ba07c3"]),
    hours: float = Query(24, ge=0.25, le=168, description="بازه‌ی زمانی به ساعت."),
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
    agent = db.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    samples = db.list_traffic_samples(agent_id, hours=hours)
    latest = db.latest_traffic_sample(agent_id)
    return {"samples": samples, "latest": latest, "hours": hours}


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
# Remote screen capture (screenshot on demand)
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/screenshot",
    tags=["مدیریت مدیر شبکه"],
    summary="درخواست یک‌باره‌ی تصویر صفحه‌ی عامل",
    description=(
        "**فقط مدیر؛ LLM دسترسی ندارد.** نیازمند `ALLOW_ADMIN_SCREENSHOT=true` و "
        "`TASK_SIGNING_KEY` روی سرور و قابلیت `screenshot` روی عامل (اجرای عامل با "
        "`--allow-screenshot` = فعال‌سازی صریح و آگاهانه در خود دستگاه). تسک "
        "امضاشده‌ی `screen_capture` ایجاد می‌شود؛ عامل با ابزارهای بومی سیستم‌عامل "
        "(بدون ارتقای دسترسی) تصویر می‌گیرد و PNG داخل نتیجه‌ی محدود برمی‌گردد. "
        "در نبود نشست گرافیکی/ابزار، خطای شفاف می‌آید — نه تصویر ساختگی. وضعیت را "
        "با `GET /api/admin/v1/tasks/{task_id}` دنبال کنید و تصویر را با "
        "`GET /api/admin/v1/agents/{agent_id}/screenshot/{task_id}` بگیرید."
    ),
    responses=_responses(
        "شناسه‌ی تسک ایجادشده.",
        {"task_id": "task_88aa11bb22cc", "agent_id": "agt_9f2c41ba07c3",
         "type": "screen_capture", "status": "pending",
         "poll": "GET /api/admin/v1/tasks/task_88aa11bb22cc"},
        not_found="عاملی با این شناسه وجود ندارد.",
    ),
)
def request_screenshot(
    request: Request,
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
    if not settings.allow_admin_screenshot:
        raise HTTPException(
            status_code=403,
            detail="قابلیت تصویر صفحه روی این سرور غیرفعال است (ALLOW_ADMIN_SCREENSHOT).",
        )
    if not (settings.task_signing_key or "").strip():
        raise HTTPException(status_code=403,
                            detail="TASK_SIGNING_KEY تنظیم نشده است؛ تسک امضاشده قابل صدور نیست.")
    agent = db.get_agent(agent_id)
    if agent is None or agent.get("status") == "revoked":
        raise HTTPException(status_code=404, detail="agent not found")
    if "screenshot" not in (agent.get("capabilities") or []):
        raise HTTPException(
            status_code=400,
            detail="عامل مقصد قابلیت screenshot را اعلام نکرده است (اجرای عامل با --allow-screenshot).",
        )
    task_id = task_service.new_task_id()
    db.create_task(
        task_id=task_id,
        agent_id=agent_id,
        type="screen_capture",
        params={"note": "on-demand screenshot by administrator"},
        origin="admin",
        created_by=actor,
        timeout_seconds=60,
        ttl_seconds=300,
        priority=2,
    )
    db.record_audit(actor=actor, action="screenshot.request", target=agent_id,
                    detail={"task_id": task_id})
    return {
        "task_id": task_id,
        "agent_id": agent_id,
        "type": "screen_capture",
        "status": "pending",
        "poll": f"GET /api/admin/v1/tasks/{task_id}",
    }


@router.get(
    "/agents/{agent_id}/screenshot/{task_id}",
    tags=["مدیریت مدیر شبکه"],
    summary="دریافت تصویر PNG ثبت‌شده در نتیجه‌ی تسک",
    description=(
        "تصویر دریافتی از عامل را به‌صورت `image/png` برمی‌گرداند. تصویر فقط در "
        "نتیجه‌ی همان تسک (با نگه‌داری محدود تسک‌ها) زندگی می‌کند — ذخیره‌ی "
        "دائمی ندارد. تسک ناتمام/ناموفق با وضعیت HTTP مناسب و پیام فارسی رد می‌شود."
    ),
    responses={
        200: {
            "description": "تصویر PNG.",
            "content": {"image/png": {"schema": {"type": "string", "format": "binary"}}},
        },
        401: {"description": "توکن مدیر لازم است.",
              "content": {"application/json": {"examples": _ERR_401}}},
        404: {"description": "تسک یافت نشد.",
              "content": {"application/json": {"examples": {"default": {"value": {"detail": "task not found"}}}}}},
        409: {"description": "تسک هنوز تمام نشده یا شکست خورده است.",
              "content": {"application/json": {"examples": {"default": {"value": {
                  "detail": "screenshot task status is 'dispatched'",
                  "task_status": "dispatched"}}}}}},
        422: {"description": "ورودی نامعتبر است؛ ساختار detail شرح خطا را می‌دهد.",
              "content": {"application/json": {"examples": {"validation": {"value": {
                  "detail": [{"type": "int_parsing", "loc": ["path", "alert_id"],
                              "msg": "Input should be a valid integer"}]}}}}}},
    },
)
def fetch_screenshot(
    request: Request,
    agent_id: str = Path(description="شناسه‌ی عامل.", examples=["agt_9f2c41ba07c3"]),
    task_id: str = Path(description="شناسه‌ی تسک تصویر.", examples=["task_88aa11bb22cc"]),
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
) -> Any:
    import base64 as _b64

    from fastapi.responses import Response as _Response

    db, _settings = _ctx(request)
    _guard(request, authorization, x_admin_actor)
    task = db.get_task(task_id)
    if task is None or task.get("agent_id") != agent_id:
        raise HTTPException(status_code=404, detail="task not found")
    if task.get("type") != "screen_capture":
        raise HTTPException(status_code=400, detail="task is not a screen_capture")
    if task.get("status") != "succeeded":
        if task.get("status") == "failed" and task.get("error"):
            raise HTTPException(status_code=409, detail=str(task["error"]))
        raise HTTPException(
            status_code=409,
            detail=f"screenshot task status is '{task.get('status')}'",
        )
    result = task.get("result") or {}
    data = result.get("data_base64")
    if not result.get("ok") or not data:
        raise HTTPException(status_code=409,
                            detail=result.get("error") or "تصویری در نتیجه‌ی تسک نیست.")
    try:
        png = _b64.b64decode(str(data))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="تصویر ذخیره‌شده قابل رمزگشایی نیست.") from exc
    return _Response(content=png, media_type="image/png",
                     headers={"Cache-Control": "no-store"})


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
