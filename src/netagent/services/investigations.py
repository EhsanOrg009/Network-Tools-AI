"""Investigation service: ties evidence collection, the agent loop, and
report persistence together."""

from __future__ import annotations

import time
from typing import Any

from netagent.agent.llm_client import LLMClient
from netagent.agent.orchestrator import Orchestrator
from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import AgentReport
from netagent.services.reporting import (
    fill_missing_sections,
    normalize_llm_report,
    render_report_fa,
)


def run_investigation(
    db: Database,
    settings: Settings,
    llm: LLMClient | None,
    *,
    target_ip: str | None = None,
    alert_id: int | None = None,
    question: str | None = None,
    run_ping: bool = False,
) -> dict[str, Any]:
    """Create, run, and persist one investigation. Returns the stored record."""
    orch = Orchestrator(db, settings, llm=llm)
    evidence = orch.collect_evidence(target_ip=target_ip, alert_id=alert_id, run_ping=run_ping)
    trigger = "manual"
    if alert_id:
        trigger = f"alert:{alert_id}"
    elif target_ip:
        trigger = "host"

    inv_id = db.create_investigation(trigger, target_ip, question, evidence)
    started = time.monotonic()
    try:
        report_raw, meta = orch.run(evidence, question=question)
        report = (
            report_raw if isinstance(report_raw, AgentReport)
            else normalize_llm_report(report_raw)
        )
        report = fill_missing_sections(report, evidence)
        report_text = render_report_fa(report)
        status = "completed" if meta.get("used_llm") else "completed_fallback"
        error = meta.get("llm_error")
        if error:
            status = "completed_fallback"
        db.finish_investigation(
            inv_id,
            status=status,
            report=report.model_dump(mode="json"),
            report_text=report_text,
            confidence=report.confidence.level,
            iterations=len(meta.get("tool_calls", [])),
            error=error,
        )
    except Exception as exc:  # keep the app alive; record precise failure
        db.finish_investigation(
            inv_id,
            status="failed",
            report=None,
            report_text=None,
            confidence=None,
            iterations=0,
            error=f"{exc.__class__.__name__}: {exc}"[:300],
        )
        raise

    record = db.get_investigation(inv_id) or {}
    record["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
    return record
