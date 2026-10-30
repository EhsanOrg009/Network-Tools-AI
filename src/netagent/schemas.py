"""Pydantic schemas for events, alerts, tool calls, and LLM decisions.

Untrusted network data (hostnames, DNS names, log strings) is always treated
as plain *data*: it is validated as strings, never executed, and extra/unknown
fields coming from the LLM are ignored.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SAFE_HOST_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,250}[A-Za-z0-9])?$"


# ---------------------------------------------------------------------------
# Collector output
# ---------------------------------------------------------------------------


class ParsedEvent(BaseModel):
    """Normalized subset of a Suricata EVE record (plus the raw payload)."""

    ts: str | None = None
    ts_epoch: float | None = None
    event_type: str | None = None
    flow_id: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    ingress: str | None = None
    alert: dict[str, Any] | None = None
    payload: dict[str, Any]

    @field_validator("flow_id", "src_port", "dest_port", mode="before")
    @classmethod
    def _coerce_int(cls, v: Any) -> int | None:
        if v in (None, ""):
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None


# ---------------------------------------------------------------------------
# API request bodies
# ---------------------------------------------------------------------------


class InvestigationRequest(BaseModel):
    """بدنه‌ی درخواست بررسی هوشمند.

    حداقل یکی از ``target_ip`` یا ``alert_id`` لازم است؛ در غیر این صورت
    پاسخ ``422`` برمی‌گردد.
    """

    target_ip: str | None = Field(
        default=None,
        description=(
            "IP میزبان هدف (IPv4 یا IPv6). باید داخل محدوده‌ی مجاز "
            "(MONITOR_CIDRS + AUTHORIZED_TARGETS) باشد؛ در غیر این صورت "
            "پاسخ 403. نمونه: 192.168.1.10"
        ),
        examples=["192.168.1.10"],
    )
    alert_id: int | None = Field(
        default=None,
        description=(
            "شناسه‌ی هشدار Suricata برای تمرکز بررسی روی همان رخداد "
            "(اختیاری؛ جایگزین target_ip)."
        ),
        examples=[12],
    )
    question: str | None = Field(
        default=None,
        max_length=2000,
        description="پرسش فارسی کاربر که به مدل محلی داده می‌شود (اختیاری؛ حداکثر 2000 نویسه).",
        examples=["چرا این میزبان به ping پاسخ نمی‌دهد؟"],
    )
    run_ping: bool = Field(
        default=False,
        description="اگر true باشد، یک ping محدود (تعداد PING_COUNT) روی هدف اجرا می‌شود.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target_ip": "192.168.1.10",
                    "alert_id": None,
                    "question": "چرا این میزبان به ping پاسخ نمی‌دهد؟",
                    "run_ping": True,
                }
            ]
        }
    }


class ScanRequest(BaseModel):
    """بدنه‌ی درخواست کشف میزبان روی یک محدوده‌ی مجاز."""

    tool: Literal["nmap", "arp_scan"] = Field(
        description=(
            "ابزار کشف: ‏nmap‏ (بدون دسترسی ویژه) یا arp_scan‏ "
            "(نیازمند دسترسی raw-socket؛ در نبود آن خطای ساختاریافته برمی‌گردد)."
        ),
        examples=["nmap"],
    )
    target: str = Field(
        description=(
            "هدف اسکن: یک IP یا CIDR. باید داخل محدوده‌ی مجاز پیکربندی‌شده "
            "باشد؛ در غیر این صورت پاسخ 403. نمونه: 192.168.1.0/24"
        ),
        examples=["192.168.1.0/24"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{"tool": "nmap", "target": "192.168.1.0/24"}]
        }
    }


# ---------------------------------------------------------------------------
# LLM decision protocol (JSON-mode; no native tool calling assumed)
# ---------------------------------------------------------------------------


class ToolRequest(BaseModel):
    """A tool invocation requested by the model.

    Unknown fields are ignored, extra keys never reach the subprocess layer.
    """

    model_config = {"extra": "ignore"}

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class AgentDecision(BaseModel):
    """Model asks to run one predefined tool."""

    model_config = {"extra": "ignore"}

    thought: str = ""
    action: ToolRequest


class Confidence(BaseModel):
    model_config = {"extra": "ignore"}

    level: Literal["low", "medium", "high", "unknown"] = "unknown"
    explanation: str = ""


class AgentReport(BaseModel):
    """Final Persian report produced by the model (or the fallback builder).

    Sections follow the admin-report contract; the orchestrator auto-fills
    ``tests_run`` from actually executed tool calls.
    """

    model_config = {"extra": "ignore"}

    summary: str = ""
    host_status: str = ""
    identification: list[str] = Field(default_factory=list)
    os_fingerprint: str = ""
    services: list[str] = Field(default_factory=list)
    observed_facts: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    related_alerts: list[str] = Field(default_factory=list)
    tests_run: list[str] = Field(default_factory=list)
    possible_explanations: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default_factory=Confidence)
    unknowns: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AgentFinal(BaseModel):
    """Model produces the final report and stops."""

    model_config = {"extra": "ignore"}

    final: Literal[True]
    report: AgentReport


# ---------------------------------------------------------------------------
# Tool results
# ---------------------------------------------------------------------------


class ToolResult(BaseModel):
    ok: bool
    tool: str
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Endpoint agent API (v3)
# ---------------------------------------------------------------------------

# Diagnostic task types an agent can execute; the admin-only types
# (admin_python_script / console_*) live in ADMIN_TASK_TYPES and never reach
# the AI tool registry.
DIAGNOSTIC_TASK_TYPES = (
    "inventory_collection",
    "connectivity_diagnostic",
    "service_inventory",
    "network_configuration",
    "approved_network_diagnostic",
)
ADMIN_TASK_TYPES = (
    "admin_python_script",
    "console_session",
    "console_command",
    "console_terminate",
)
KNOWN_TASK_TYPES = DIAGNOSTIC_TASK_TYPES + ADMIN_TASK_TYPES


class EndpointPlatformInfo(BaseModel):
    """اطلاعات پلتفرم گزارش‌شده توسط عامل نقطه‌پایان."""

    model_config = {"extra": "ignore"}

    os_family: str | None = Field(default=None, description="خانواده‌ی سیستم‌عامل (Windows یا Linux).")
    os_name: str | None = Field(default=None, description="نام سیستم‌عامل گزارش‌شده توسط خود دستگاه.")
    os_version: str | None = Field(default=None, description="نسخه‌ی سیستم‌عامل.")
    kernel: str | None = Field(default=None, description="نسخه‌ی کرنل یا build سیستم.")
    arch: str | None = Field(default=None, description="معماری پردازنده مثل x86_64 یا AMD64.")


class InterfaceObservation(BaseModel):
    """مشاهده‌ی یک رابط شبکه از دید خود نقطه‌پایان."""

    model_config = {"extra": "ignore"}

    name: str = Field(description="نام رابط مثل eth0 یا Ethernet 2 (بدون فرض نام خاص).")
    status: str | None = Field(default=None, description="وضعیت رابط: up یا down یا unknown.")
    mac: str | None = Field(default=None, description="آدرس MAC رابط در صورت وجود.")
    ipv4: list[str] = Field(default_factory=list, description="آدرس‌های IPv4 با پیشوند مثل 192.168.1.10/24.")
    ipv6: list[str] = Field(default_factory=list, description="آدرس‌های IPv6 با پیشوند.")
    connected_networks: list[str] = Field(
        default_factory=list,
        description="شبکه‌های مستقیماً متصل به‌صورت CIDR مثل 192.168.1.0/24.",
    )
    gateway: str | None = Field(default=None, description="گیت‌وی پیش‌فرض این رابط در صورت شناخت.")
    classification: str | None = Field(
        default=None,
        description="طبقه‌بندی حدسی: physical یا virtual یا loopback یا vpn یا link_local یا unknown.",
    )
    dns_servers: list[str] = Field(default_factory=list, description="سرورهای DNS مشاهده‌شده روی این رابط.")


class EnrollRequest(BaseModel):
    """درخواست ثبت‌نام (enrollment) عامل نقطه‌پایان."""

    model_config = {"extra": "ignore"}

    enrollment_token: str = Field(description="توکن یک‌بارمصرف صادرشده توسط مدیر شبکه.", examples=["enr_..."])
    hostname: str | None = Field(default=None, max_length=255, description="نام میزبان دستگاه.")
    platform: EndpointPlatformInfo = Field(default_factory=EndpointPlatformInfo)
    agent_version: str | None = Field(default=None, max_length=32, description="نسخه‌ی اسکریپت عامل.")
    capabilities: list[str] = Field(
        default_factory=list,
        description="قابلیت‌های اعلامی مثل inventory یا connectivity_diagnostic یا console.",
    )
    claimed_ips: list[str] = Field(default_factory=list, description="IPهای فعلی دستگاه.")


class EnrollResponse(BaseModel):
    agent_id: str = Field(description="شناسه‌ی پایدار عامل؛ در فایل وضعیت محلی ذخیره شود.")
    agent_token: str = Field(description="اعتبارنامه‌ی اختصاصی عامل؛ فقط یک‌بار نمایش داده می‌شود.")
    server_time_epoch: float
    heartbeat_interval_seconds: int
    inventory_interval_seconds: int
    max_task_result_bytes: int


class HeartbeatRequest(BaseModel):
    model_config = {"extra": "ignore"}

    claimed_ips: list[str] | None = Field(default=None, description="IPهای فعلی؛ تغییرها را به‌روزرسانی می‌کند.")
    agent_version: str | None = Field(default=None, max_length=32)
    hostname: str | None = Field(default=None, max_length=255)
    platform: EndpointPlatformInfo | None = None
    capabilities: list[str] | None = Field(default=None, description="به‌روزرسانی فهرست قابلیت‌ها (اختیاری).")


class HeartbeatResponse(BaseModel):
    accepted: bool
    agent_status: str = Field(description="وضعیت ثبت‌شده: active یا stale یا revoked.")
    server_time_epoch: float
    heartbeat_interval_seconds: int
    inventory_due: bool = Field(description="اگر true باشد عامل باید inventory بفرستد.")
    max_task_result_bytes: int


class InventoryRequest(BaseModel):
    """بار کامل فهرست‌برداری (inventory) نقطه‌پایان."""

    model_config = {"extra": "ignore"}

    collected_at_epoch: float | None = Field(default=None, description="زمان جمع‌آوری در دستگاه (epoch).")
    hostname: str | None = Field(default=None, max_length=255)
    platform: EndpointPlatformInfo = Field(default_factory=EndpointPlatformInfo)
    boot_time_epoch: float | None = Field(default=None, description="زمان بوت دستگاه در صورت دسترس‌پذیری.")
    uptime_seconds: float | None = Field(default=None, description="آپ‌تایم در صورت دسترس‌پذیری.")
    interfaces: list[InterfaceObservation] = Field(default_factory=list)
    collectors_status: list[dict[str, Any]] = Field(
        default_factory=list,
        description="وضعیت هر جمع‌آورنده: نام، وضعیت ok/unavailable و پیام خطا در صورت وجود.",
    )
    optional_stats: dict[str, Any] | None = Field(
        default=None, description="آمار اختیاری (حافظه و …)؛ در نبود دسترسی خالی می‌ماند."
    )
    errors: list[str] = Field(default_factory=list, description="خطاهای غیرمهلک جمع‌آوری.")


class SimpleAck(BaseModel):
    ok: bool
    detail: str | None = None
    server_time_epoch: float


class TaskParams(BaseModel):
    model_config = {"extra": "ignore"}


class TaskResultRequest(BaseModel):
    """نتیجه‌ی اجرای یک تسک از سوی عامل."""

    model_config = {"extra": "ignore"}

    ok: bool = Field(description="موفق بودن اجرا؛ خطاهای ساختاریافته در result هم می‌آیند.")
    result: dict[str, Any] | None = Field(default=None, description="نتیجه‌ی ساختاریافته (محدود به سقف بایت).")
    error: str | None = Field(default=None, max_length=1000)
    duration_ms: float | None = None
    started_at_epoch: float | None = None
    finished_at_epoch: float | None = None


# ---------------------------------------------------------------------------
# Administrator API (v3) — request models
# ---------------------------------------------------------------------------


class EnrollmentTokenCreate(BaseModel):
    ttl_minutes: int = Field(default=60, ge=1, le=1440, description="اعتبار توکن به دقیقه (پیش‌فرض 60).")


class DiagnosticTaskCreate(BaseModel):
    """ایجاد تسک تشخیصی برای یک عامل (بدون اجرای کد دلخواه)."""

    agent_id: str = Field(description="شناسه‌ی عامل هدف.", examples=["agt_..."])
    type: str = Field(
        description="نوع تسک تشخیصی؛ یکی از: " + ", ".join(DIAGNOSTIC_TASK_TYPES),
        examples=["inventory_collection"],
    )
    params: dict[str, Any] = Field(default_factory=dict, description="پارامترهای اعتبارسنجی‌شده در سمت عامل.")
    priority: int = Field(default=5, ge=1, le=9, description="عدد کوچک‌تر = اولویت بالاتر (پیش‌فرض 5).")
    timeout_seconds: int | None = Field(default=None, ge=5, le=3600, description="سقف زمان اجرا؛ پیش‌فرض پیکربندی سرور.")
    ttl_seconds: int | None = Field(default=None, ge=10, le=86400, description="عمر تسک؛ پس از آن expired می‌شود.")


class AdminScriptCreate(BaseModel):
    """ارسال اسکریپت پایتون برای اجرای مدیریتی روی یک عامل ثبت‌شده."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "agent_id": "agt_xxxxxxxxxxxx",
                    "code": "import platform; print(platform.node())",
                    "timeout_seconds": 30,
                }
            ]
        }
    }

    agent_id: str = Field(description="عامل هدف؛ باید فعال و دارای قابلیت admin_exec باشد.")
    code: str = Field(
        min_length=1,
        description="کد پایتون برای اجرای ایزوله در زیرفرآیند عامل؛ نیازمند فعال بودن قابلیت در سرور و عامل.",
    )
    timeout_seconds: int | None = Field(default=None, ge=5, le=3600, description="سقف اجرا؛ پیش‌فرض پیکربندی سرور.")
    note: str | None = Field(default=None, max_length=500, description="یادداشت اختیاری برای حسابرسی.")


class ConsoleSessionCreate(BaseModel):
    agent_id: str = Field(description="عامل هدف نشست ترمینال.")
    ttl_seconds: int | None = Field(
        default=None, ge=60, le=4 * 3600, description="عمر نشست؛ پیش‌فرض پیکربندی سرور."
    )


class ConsoleCommandCreate(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {"code": "import socket; socket.gethostname()"},
            ]
        }
    }

    code: str = Field(min_length=1, description="کد پایتون برای اجرای ترتیبی در نشست؛ state بین دستورها حفظ می‌شود.")
