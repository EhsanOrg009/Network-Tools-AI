"""Reporting: fallback reports, normalization, and Persian rendering."""

from __future__ import annotations

from netagent.agent.orchestrator import build_fallback_report
from netagent.services.reporting import normalize_llm_report, render_report_fa
from netagent.schemas import AgentReport

SECTIONS = [
    "خلاصه مدیریتی",
    "اطلاعات شناسایی‌شده",
    "سیستم‌عامل و انگشت‌نگاری دستگاه",
    "سرویس‌ها و پورت‌های مشاهده‌شده",
    "واقعیت‌های مشاهده‌شده",
    "شواهد و زمان ثبت آن‌ها",
    "هشدارهای مرتبط Suricata",
    "آزمایش‌های اجراشده و نتایج آن‌ها",
    "علت‌های احتمالی و توضیح هر فرضیه",
    "سطح اطمینان",
    "اطلاعات هنوز مشخص‌نشده",
    "پیشنهاد برای بررسی‌های بعدی",
]


def test_fallback_report_has_all_required_sections(settings, db):
    evidence = {
        "target_ip": "192.168.1.10",
        "database_stats": {"events": 10, "alerts": 2, "hosts": 3, "investigations": 0},
        "target_alerts_grouped_by_flow_rule": [
            {"signature": "ET INFO Test", "severity": 2, "category": "info",
             "flow_id": 1, "hit_count": 3, "last_seen": "2026-10-28T10:00:00+0330"}
        ],
        "generated_at": "2026-10-28T10:00:00+0330",
    }
    report = build_fallback_report(evidence, "LLM غیرفعال است")
    text = render_report_fa(report)
    for section in SECTIONS:
        assert section in text
    assert "LLM غیرفعال است" in text
    assert "شواهد اولیه" in text  # evidence-not-proof reminder present


def test_fallback_report_ping_failure_not_claimed_offline(settings, db):
    evidence = {
        "target_ip": "192.168.1.10",
        "database_stats": {"events": 0, "alerts": 0},
        "target_ping_now": {"ok": False, "target": "192.168.1.10"},
    }
    report = build_fallback_report(evidence, "تست")
    joined = "\n".join(report.observed_facts)
    assert "اثبات خاموش بودن" in joined  # explicitly not claimed offline


def test_normalize_llm_report_never_raises():
    garbage = {"summary": 42, "observed_facts": "not-a-list", "confidence": {"level": "bogus"}}
    report = normalize_llm_report(garbage)
    assert isinstance(report, AgentReport)
    assert report.confidence.level == "unknown"
    assert report.observed_facts == ["not-a-list"]
    assert "ناقص" in "\n".join(report.limitations)

    none_report = normalize_llm_report(None)
    assert none_report.summary


def test_normalize_report_ignores_extra_fields():
    report = normalize_llm_report({
        "summary": "ok",
        "observed_facts": ["f1"],
        "malicious_key": "rm -rf /",  # unknown fields dropped
    })
    assert report.model_dump().get("malicious_key") is None


def test_normalize_report_accepts_persian_alias_keys():
    report = normalize_llm_report({
        "summary": "ok",
        "facts": ["ف۱"],
        "شواهد": ["ش۱"],
        "فرضیه‌ها": ["ه۱"],
        "گام‌ها": ["گ۱"],
        "محدودیت‌ها": ["ل۱"],
    })
    assert report.observed_facts == ["ف۱"]
    assert report.evidence == ["ش۱"]
    assert report.possible_explanations == ["ه۱"]
    assert report.next_steps == ["گ۱"]
    assert "ل۱" in report.limitations


def test_fill_missing_sections_backfills_from_evidence():
    from netagent.services.reporting import fill_missing_sections

    report = AgentReport(summary="فقط خلاصه")
    evidence = {
        "database_stats": {"events": 5, "alerts": 2},
        "target_alerts_grouped_by_flow_rule": [
            {"signature": "ET TOR Test", "severity": 2, "category": "Misc",
             "flow_id": 1, "hit_count": 2, "last_seen": "2026-10-28T10:00:00"}
        ],
        "target_ping_now": {"target": "1.2.3.4", "ok": True},
    }
    filled = fill_missing_sections(report, evidence)
    assert filled.observed_facts
    assert all(f.startswith("[از پایگاه داده]") for f in filled.observed_facts)
    assert filled.next_steps
    assert any("تکمیل" in l for l in filled.limitations)


def test_render_report_confidence_levels():
    for level, fa in (("low", "کم"), ("medium", "متوسط"), ("high", "زیاد"), ("unknown", "نامشخص")):
        report = AgentReport(summary="s", confidence={"level": level, "explanation": "x"})
        text = render_report_fa(report)
        assert fa in text
