"""Persian report rendering and normalization."""

from __future__ import annotations

import json
from typing import Any

from netagent.schemas import AgentReport

_SECTION_TITLES = {
    "summary": "خلاصه مدیریتی",
    "host_status": "وضعیت میزبان یا رخداد",
    "identification": "اطلاعات شناسایی‌شده",
    "os_fingerprint": "سیستم‌عامل و انگشت‌نگاری دستگاه",
    "services": "سرویس‌ها و پورت‌های مشاهده‌شده",
    "observed_facts": "واقعیت‌های مشاهده‌شده",
    "evidence": "شواهد و زمان ثبت آن‌ها",
    "related_alerts": "هشدارهای مرتبط Suricata",
    "tests_run": "آزمایش‌های اجراشده و نتایج آن‌ها",
    "possible_explanations": "علت‌های احتمالی و توضیح هر فرضیه",
    "confidence": "سطح اطمینان",
    "unknowns": "اطلاعات هنوز مشخص‌نشده",
    "next_steps": "پیشنهاد برای بررسی‌های بعدی",
    "limitations": "محدودیت‌ها",
}

_CONFIDENCE_FA = {
    "low": "کم",
    "medium": "متوسط",
    "high": "زیاد",
    "unknown": "نامشخص",
}


def _section(lines: list[str], title: str, items: list[str], bullet: str = "-") -> None:
    lines.append(f"## {title}")
    if items:
        lines.extend(f"{bullet} {i}" for i in items)
    else:
        lines.append("- موردی ثبت نشده است.")
    lines.append("")


def render_report_fa(report: AgentReport) -> str:
    """Render an AgentReport as the full Persian admin report (12 sections)."""
    lines: list[str] = []

    lines.append(f"## {_SECTION_TITLES['summary']}")
    lines.append(report.summary or "—")
    lines.append("")

    if report.host_status:
        lines.append(f"## {_SECTION_TITLES['host_status']}")
        lines.append(report.host_status)
        lines.append("")

    _section(lines, _SECTION_TITLES["identification"], report.identification)

    lines.append(f"## {_SECTION_TITLES['os_fingerprint']}")
    if report.os_fingerprint:
        lines.append(report.os_fingerprint)
        lines.append("")
        lines.append(
            "> یادآوری: شناسایی سیستم‌عامل پیش‌بینیِ انگشت‌نگاری است، نه حقیقت "
            "تأییدشده؛ نام PTR و سازنده‌ی MAC با نام تأییدشده‌ی میزبان تفاوت دارند."
        )
    else:
        lines.append("شواهد کافی برای شناسایی سیستم‌عامل وجود ندارد.")
    lines.append("")

    _section(lines, _SECTION_TITLES["services"], report.services)
    _section(lines, _SECTION_TITLES["observed_facts"], report.observed_facts)
    _section(lines, _SECTION_TITLES["evidence"], report.evidence)
    _section(lines, _SECTION_TITLES["related_alerts"], report.related_alerts)
    _section(lines, _SECTION_TITLES["tests_run"], report.tests_run)
    _section(lines, _SECTION_TITLES["possible_explanations"], report.possible_explanations)

    lines.append(f"## {_SECTION_TITLES['confidence']}")
    lines.append(
        f"- سطح: {_CONFIDENCE_FA.get(report.confidence.level, report.confidence.level)}"
    )
    if report.confidence.explanation:
        lines.append(f"- توضیح: {report.confidence.explanation}")
    lines.append("")

    _section(lines, _SECTION_TITLES["unknowns"], report.unknowns)
    _section(lines, _SECTION_TITLES["next_steps"], report.next_steps)
    _section(lines, _SECTION_TITLES["limitations"], report.limitations)

    lines.append("")
    lines.append(
        "> یادآوری: هشدارهای Suricata شواهد اولیه هستند، نه اثبات قطعی حمله؛ "
        "عدم پاسخ به ping به‌تنهایی به معنی خاموش بودن دستگاه نیست؛ و این "
        "ابزار هیچ اقدام مسدودسازی انجام نمی‌دهد."
    )
    return "\n".join(lines)


def normalize_llm_report(data: dict[str, Any] | None) -> AgentReport:
    """Coerce an arbitrary dict into a valid AgentReport (never raises).
    Accepts common alternative/Persian key names used by local models."""
    if not data:
        return AgentReport(summary="گزارشی تولید نشد.")

    _ALIASES = {
        "observed_facts": ("observed_facts", "facts", "findings", "واقعیت‌ها",
                           "واقعیت های مشاهده شده", "observations"),
        "evidence": ("evidence", "شواهد", "proof"),
        "possible_explanations": ("possible_explanations", "explanations",
                                  "hypotheses", "توضیحات محتمل", "فرضیه‌ها",
                                  "فرضیه ها"),
        "next_steps": ("next_steps", "steps", "recommendations", "گام‌ها",
                       "گام های بعدی", "اقدامات"),
        "limitations": ("limitations", "محدودیت‌ها", "محدودیت ها",
                        "unresolved"),
    }

    def _as_list(value: Any) -> list[str] | None:
        if isinstance(value, list):
            return [str(x)[:300] for x in value if x][:20]
        if isinstance(value, str) and value.strip():
            return [value[:300]]
        return None

    # Pre-map aliases onto canonical keys, then validate the canonical copy.
    canonical = dict(data)
    for key, names in _ALIASES.items():
        if key in canonical and isinstance(canonical[key], list):
            continue
        for name in names:
            mapped = _as_list(data.get(name))
            if mapped is not None:
                canonical[key] = mapped
                break

    try:
        return AgentReport.model_validate(canonical)
    except Exception:
        pass
    # last-resort salvage
    def _opt_str(key: str) -> str:
        v = canonical.get(key)
        return str(v)[:1000] if isinstance(v, (str, int, float)) else ""

    summary = str(data.get("summary", ""))[:1000] or "گزارش ناقص بود."
    conf_raw = data.get("confidence") or {}
    level = str(conf_raw.get("level", "unknown")).lower()
    if level not in ("low", "medium", "high"):
        level = "unknown"
    return AgentReport(
        summary=summary,
        host_status=_opt_str("host_status"),
        identification=_as_list(canonical.get("identification")) or [],
        os_fingerprint=_opt_str("os_fingerprint"),
        services=_as_list(canonical.get("services")) or [],
        observed_facts=_as_list(canonical.get("observed_facts")) or [],
        evidence=_as_list(canonical.get("evidence")) or [],
        related_alerts=_as_list(canonical.get("related_alerts")) or [],
        possible_explanations=_as_list(canonical.get("possible_explanations")) or [],
        confidence={
            "level": level,  # type: ignore[dict-item]
            "explanation": str(conf_raw.get("explanation", ""))[:500],
        },
        unknowns=_as_list(canonical.get("unknowns")) or [],
        next_steps=_as_list(canonical.get("next_steps")) or [],
        limitations=_as_list(canonical.get("limitations"))
        or ["گزارش مدل ناقص بود و به‌صورت ایمن نرمال‌سازی شد."],
    )


def fill_missing_sections(report: AgentReport, evidence: dict[str, Any]) -> AgentReport:
    """Backfill empty report sections with data-derived facts so a truncated
    or partial model report still carries usable, clearly-sourced content.
    Backfilled items are always labeled as coming from the database, and the
    limitation list states it explicitly."""
    changed = False
    if not report.observed_facts:
        facts: list[str] = []
        stats = evidence.get("database_stats") or {}
        facts.append(
            f"[از پایگاه داده] تا این لحظه {stats.get('events', 0)} رویداد و "
            f"{stats.get('alerts', 0)} هشدار ثبت شده است."
        )
        grouped = evidence.get("target_alerts_grouped_by_flow_rule") or \
            evidence.get("recent_alerts_global") or []
        for g in grouped[:4]:
            if isinstance(g, dict) and g.get("signature"):
                facts.append(
                    f"[از پایگاه داده] امضای «{g.get('signature')}» (شدت "
                    f"{g.get('severity')}, دسته {g.get('category')}) روی flow "
                    f"{g.get('flow_id')}، {g.get('hit_count')} بار؛ آخرین: "
                    f"{g.get('last_seen')}."
                )
        ping_now = evidence.get("target_ping_now") or evidence.get("gateway_ping")
        if ping_now:
            state = "پاسخ داد" if ping_now.get("ok") else "پاسخ نداد (ICMP ممکن است فیلتر شده باشد)"
            facts.append(
                f"[از پایگاه داده] بررسی ping اخیر {ping_now.get('target', '')} "
                f"{state}."
            )
        if facts:
            report.observed_facts = facts
            changed = True

    if not report.next_steps:
        report.next_steps = [
            "بازبینی هشدارهای مرتبط از طریق GET /api/alerts و مقایسه با تاریخچه میزبان.",
            "در صورت تکرار هشدار، بررسی PCAP اخیر روی همان flow (تحلیل آفلاین).",
        ]
        changed = True

    if changed:
        report.limitations = list(report.limitations) + [
            "بخش‌های خالی گزارش مدل از داده‌های مستقیم پایگاه داده تکمیل شده‌اند."
        ]
    return report


def report_summary_json(report: AgentReport) -> dict[str, Any]:
    """Compact dict for JSON storage / API responses."""
    return json.loads(report.model_dump_json())
