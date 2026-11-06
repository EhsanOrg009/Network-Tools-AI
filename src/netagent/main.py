"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from netagent import __version__
from netagent.agent.llm_client import LLMClient
from netagent.api.agent_routes import router as agent_router
from netagent.api.admin_routes import router as admin_router
from netagent.api.dashboard_routes import router as dashboard_router
from netagent.api.docs_ui import rtl_swagger_ui_html
from netagent.api.routes import router
from netagent.config import Settings, load_settings
from netagent.database import Database
from netagent.services.monitoring import Monitor

# Persian tags used by the Swagger UI; keep in sync with the routers.
OPENAPI_TAGS = [
    {
        "name": "سلامت سیستم",
        "description": "وضعیت اجزای برنامه: پایگاه داده، خواننده Suricata، دسترسی LLM، عوامل نقطه‌پایان و محدوده‌ی مجاز اسکن.",
    },
    {
        "name": "میزبان‌ها و شبکه",
        "description": "میزبان‌های شناسایی‌شده، خط زمانی رویدادها و نتایج شناسایی (fingerprint) هر میزبان.",
    },
    {
        "name": "رخدادها و هشدارهای امنیتی",
        "description": "رویدادهای خام Suricata و هشدارهای قانون تطبیق‌یافته، با فیلتر و صفحه‌بندی.",
    },
    {
        "name": "بررسی‌های هوشمند",
        "description": "بررسی خودکار چندمرحله‌ای میزبان/هشدار با مدل زبانی محلی؛ همگام یا به‌صورت کار پس‌زمینه.",
    },
    {
        "name": "عملیات اسکن",
        "description": "کشف میزبان (nmap / arp-scan) فقط روی محدوده‌ی مجاز پیکربندی‌شده؛ هدف خارج از scope با 403 رد می‌شود.",
    },
    {
        "name": "ابزارها و قابلیت‌ها",
        "description": "فهرست ابزارهای تشخیصی موجود و فراخوانی مستقیم و اعتبارسنجی‌شده‌ی آن‌ها (همان مسیر عامل).",
    },
    {
        "name": "Endpoint Agent",
        "description": (
            "کانال ارتباطی عامل‌های نقطه‌پایان (ویندوز/لینوکس): ثبت‌نام با توکن "
            "یک‌بارمصرف، ضربان، ارسال inventory، دریافت و نتیجه‌ی تسک. احراز هویت با "
            "اعتبارنامه‌ی اختصاصی عامل (Bearer)؛ توکن مدیر در این مسیرها کار نمی‌کند."
        ),
    },
    {
        "name": "مدیریت مدیر شبکه",
        "description": (
            "کنترل‌پلن مدیر: صدور توکن ثبت‌نام، مدیریت عوامل، تسک‌های تشخیصی، اسکریپت "
            "پایتون مدیریتی و تاریخچه‌ی حسابرسی. فقط با ADMIN_API_TOKEN؛ مدل زبانی به "
            "این مسیرها و کلیدها دسترسی ندارد."
        ),
    },
    {
        "name": "داشبورد مدیریتی",
        "description": (
            "نمای تجمیعی مخصوص داشبورد وب (`/dashboard`): آمار کلی عوامل، هشدارها، "
            "روند فعالیت و حسابرسی اخیر در یک پاسخ. فقط با ADMIN_API_TOKEN و فقط "
            "خواندنی؛ عملیات مدیریتی همچنان در `/api/admin/v1` انجام می‌شود."
        ),
    },
    {
        "name": "پایش فعالیت هوش مصنوعی",
        "description": (
            "فعالیتِ واقعی مدل محلی: یک رکورد به‌ازای هر درخواست LLM با خط "
            "زمانی واقعی (ایجاد، ارسال به Msty، اولین توکن، پاسخ، ذخیره)، "
            "زمان‌بندی، خروجی فشرده و خطاها. فقط خواندنی و فقط برای مدیر؛ "
            "هیچ مرحله‌ی ساختگی یا زنجیره‌ی تفکر خام ذخیره/نمایش داده نمی‌شود."
        ),
    },
    {
        "name": "ترمینال پایتون از راه دور",
        "description": (
            "نشست تعاملی پایتون فقط برای مدیر شبکه: اجرای ترتیبی دستورها با حفظ state "
            "مفسر روی یک عامل ثبت‌شده، از طریق همان کانال تسک؛ با سقف زمان/خروجی و "
            "حسابرسی کامل. نیازمند ALLOW_ADMIN_PYTHON_CONSOLE و TASK_SIGNING_KEY."
        ),
    },
]


def create_app(settings: Settings | None = None, start_monitor: bool | None = None) -> FastAPI:
    settings = settings or load_settings()
    if start_monitor is None:
        start_monitor = settings.enable_monitor

    db = Database(settings.database_path)
    monitor = Monitor(db, settings)
    llm = LLMClient(settings) if settings.llm_enabled else None
    from netagent.services.ai_analysis import AlertAnalysisWorker
    from netagent.services.jobs import JobManager

    ai_worker = AlertAnalysisWorker(db, settings, llm) if (
        settings.ai_analysis_enabled and llm is not None
    ) else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_monitor:
            monitor.start()
        if ai_worker is not None:
            ai_worker.start()
        try:
            yield
        finally:
            if ai_worker is not None:
                ai_worker.stop()
            monitor.stop()
            db.close()

    app = FastAPI(
        title="عامل هوشمند پایش و عیب‌یابی شبکه",
        description=(
            "پایش و عیب‌یابی خودکار شبکه‌ی محلی با Suricata و مدل زبانی محلی (Msty)، "
            "به‌همراه عوامل نقطه‌پایان (Endpoint Agent) برای ویندوز و لینوکس.\n\n"
            "**نکته:** هشدارهای Suricata شواهد اولیه هستند، نه اثبات قطعی حمله. "
            "عملیات فعال (nmap / arp-scan) فقط روی محدوده‌ی مجاز پیکربندی‌شده "
            "(`MONITOR_CIDRS` + `AUTHORIZED_TARGETS` + شبکه‌های مجازِ کشف خودکار) "
            "اجرا می‌شود؛ هدف خارج از محدوده با کد `403` رد می‌شود.\n\n"
            "**تفکیک دسترسی:** API عامل‌ها (`/api/agent/v1`) و API مدیر "
            "(`/api/admin/v1`) با دو نوع اعتبارنامه‌ی جداست. اجرای اسکریپت پایتون و "
            "ترمینال پایتون تعاملی **فقط** برای مدیر شبکه است و هرگز از طریق مدل "
            "زبانی قابل فراخوانی نیست.\n\n"
            "این برنامه فقط برای پایش و عیب‌یابی دفاعی است و هیچ اقدام "
            "مسدودسازی انجام نمی‌دهد."
        ),
        version=__version__,
        docs_url=None,  # custom RTL-aware Swagger UI below; /openapi.json unchanged
        redoc_url=None,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
    )

    @app.get("/api/docs", include_in_schema=False)
    def rtl_docs() -> HTMLResponse:
        return HTMLResponse(rtl_swagger_ui_html(
            openapi_url="/openapi.json", title=app.title + " — Swagger",
        ))

    # backward compatibility: old Swagger UI address now redirects
    @app.get("/docs", include_in_schema=False)
    def docs_redirect() -> RedirectResponse:
        return RedirectResponse(url="/api/docs")

    app.state.db = db
    app.state.settings = settings
    app.state.monitor = monitor
    app.state.llm = llm
    app.state.jobs = JobManager()
    app.include_router(router)
    app.include_router(agent_router)
    app.include_router(admin_router)
    app.include_router(dashboard_router)

    # -- dashboard SPA (built frontend; optional in dev/test) ------------------
    # /dashboard serves dashboard/dist (Vite build, base="/dashboard/").
    # Missing file paths fall back to index.html so client-side routes
    # (/dashboard/agents/{id}) survive a hard refresh. Swagger at /api/docs
    # and /openapi.json are completely unaffected by this mount.
    dist = Path(__file__).resolve().parents[2] / "dashboard" / "dist"

    class _SPAFallback(StaticFiles):
        async def get_response(self, path: str, scope):  # type: ignore[override]
            try:
                return await super().get_response(path, scope)
            except StarletteHTTPException as exc:
                # SPA route → serve the app shell; missing asset files (which
                # have an extension) still 404 loudly
                if exc.status_code == 404 and "." not in path.split("/")[-1]:
                    return await super().get_response("index.html", scope)
                raise

    if dist.is_dir():
        app.mount("/dashboard", _SPAFallback(directory=dist, html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    def root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    return app


app = create_app()
