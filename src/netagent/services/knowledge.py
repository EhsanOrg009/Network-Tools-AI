"""Persistent knowledge base (AI memory) — creation gate + retrieval.

Anti-poisoning rules enforced here (not by prompt):
- Only a PENDING_APPROVAL memory can become APPROVED, and memory creation
  itself carries an explicit human source. Log text, agent payloads or model
  suggestions may *propose* memories (``suggest_memory``) but status
  PENDING_APPROVAL → they are never used by analysis until the administrator
  approves.
- Memory validity is scoped: agent_id / host / process / service / network.
  A Tor-approval for one agent never makes every Tor connection acceptable.
- Expired memory is marked EXPIRED lazily and excluded from retrieval.
- Retrieval is keyword-based (agent/host/process/service/network identity),
  cheap and deterministic — no heavy vector store, matches this hardware.
"""

from __future__ import annotations

import hashlib
import json
import re
import ipaddress
import time
import uuid
from typing import Any

from netagent.database import Database
from netagent.services.ai_activity import ActivityTrace, traced_chat

CATEGORIES = {
    "approved_service",
    "known_process",
    "known_false_positive",
    "known_network_behavior",
    "incident_resolution",
    "known_device",
    "known_service",
    "diagnostic_playbook",
}

SCOPES = {"event", "agent", "host", "process", "service", "network", "global"}

MEMORY_ID_PREFIXES = {
    "administrator": "mem",
    "question_resolve": "memq",
    "analysis": "memA",
    "agent": "memG",
}


def validate_memory_fields(
    *, category: str, scope: str, agent_id: str | None, host: str | None,
    process: str | None, service: str | None, network: str | None,
    errors: list[str],
) -> bool:
    """Structural validation; appends human-readable errors and returns ok."""
    ok = True
    if category not in CATEGORIES:
        errors.append(f"دسته‌بندی نامعتبر: {category}")
        ok = False
    if scope not in SCOPES:
        errors.append(f"محدوده‌ی اعتبار نامعتبر: {scope}")
        ok = False
    # a global / network-scoped rule must not be created without explicit
    # administrator action — done at the API layer; here structural checks:
    if network is not None:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            errors.append(f"شبکه نامعتبر: {network}")
            ok = False
    if host is not None and host.strip() == "":
        errors.append("host خالی است")
        ok = False
    if not ok and not errors:
        errors.append("فیلدهای حافظه نامعتبرند")
    return ok


def _memory_matches_IP(memory: dict[str, Any], ip: str | None) -> bool:
    if not ip:
        return False
    if memory.get("host") and memory["host"] == ip:
        return True
    net = memory.get("network")
    if not net:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except (ValueError, TypeError):
        return False


def _tokenize(text: str) -> set[str]:
    return {
        t for t in re.split(r"[^0-9A-Za-z\u0600-\u06FF]+", (text or "").lower())
        if len(t) >= 3
    }


def retrieve_memories(
    db: Database, *, agent_id: str | None = None, ip: str | None = None,
    process: str | None = None, service: str | None = None,
    keywords: str | None = None, limit: int = 8,
) -> list[dict[str, Any]]:
    """Related APPROVED memories for an analysis context, scored by scope
    specificity. Retrieval never mutates anything except hit counters."""

    def score(m: dict[str, Any]) -> float:
        s = 0.0
        if agent_id is not None:
            if m.get("agent_id") == agent_id:
                s += 5.0
            elif m.get("agent_id"):
                s -= 10.0  # explicitly bound to a different agent
        if ip is not None and _memory_matches_IP(m, ip):
            s += 3.0
        if service and m.get("service") == service:
            s += 2.0
        if process and m.get("process") == process:
            s += 2.0
        if keywords:
            blob = f"{m.get('title') or ''} {m.get('description') or ''}".lower()
            toks = _tokenize(keywords)
            if toks and any(t in blob for t in toks):
                s += 1.0
        return s

    pool = db.usable_memories()
    scored = []
    for m in pool:
        s = score(m)
        # explicitly-bound-to-other-agent rules never match
        if s <= 0.0:
            continue
        if m.get("agent_id") and agent_id is not None and m["agent_id"] != agent_id:
            continue
        scored.append((s, m))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["memory_id"]))
    chosen = [m for _s, m in scored[: max(0, limit)]]
    if chosen:
        ids = [m["memory_id"] for m in chosen]
        db.record_memory_hits(ids)
        # re-read so callers see the fresh hit_count/last_hit_at
        chosen = [db.get_memory(i) for i in ids]
    return chosen


def memory_context_block(
    memories: list[dict[str, Any]], *, lang_header: str = "حافظه‌ی تأییدشده"
) -> str:
    """A clearly-framed block listing the memories the analysis may rely on.

    The block is *admin-verified knowledge*, injected as reference — and the
    prompt instructs the model to report WHICH memory ids actually influenced
    its result (transparency, misuse detection both covered).
    """
    if not memories:
        return ""
    lines = [f"قسمت «{lang_header}» فقط دانش بازبینی‌شده توسط مدیر شبکه است:"]
    for m in memories:
        loc = ", ".join(
            x for x in (
                f"agent={m['agent_id']}" if m.get("agent_id") else None,
                f"host={m['host']}" if m.get("host") else None,
                f"service={m['service']}" if m.get("service") else None,
                f"process={m['process']}" if m.get("process") else None,
                f"network={m['network']}" if m.get("network") else None,
                f"scope={m['scope']}",
            ) if x
        )
        lines.append(
            f"- [{m['memory_id']}] «{m['title']}» ({m['category']}; {loc}): "
            f"{(m.get('description') or '').strip()[:300]}"
        )
    return "\n".join(lines)


def suggest_memory(
    db: Database, *,
    title: str, description: str | None, category: str,
    agent_id: str | None, host: str | None, process: str | None,
    service: str | None, network: str | None, evidence: list[dict[str, Any]] | None,
    alert_id: int | None, created_by: str = "ai-analysis",
    scope: str = "agent", question_id: str | None = None,
    source: str,
) -> dict[str, Any]:
    """Register a memory *proposal* that lands PENDING_APPROVAL.

    AI / log text can never create an APPROVED memory; this helper always
    non-privileges the source. Direct administrator creation goes through the
    admin API (which sets source='administrator' and may auto-approve).
    """
    errors: list[str] = []
    valid = validate_memory_fields(
        category=category, scope=scope, agent_id=agent_id, host=host,
        process=process, service=service, network=network, errors=errors,
    )
    if not valid:
        raise ValueError("; ".join(errors))
    # deterministic, replay-safe id from content
    basis = json.dumps(
        {"t": title, "c": category, "a": agent_id, "h": host,
         "p": process, "s": service, "n": network, "q": question_id,
         "al": alert_id},
        ensure_ascii=False, sort_keys=True,
    )
    digest = hashlib.sha256(basis.encode()).hexdigest()[:16]
    prefix = MEMORY_ID_PREFIXES.get(source, "mem")
    memory_id = f"{prefix}_{digest}"
    existing = db.get_memory(memory_id)
    if existing is not None:
        return existing
    db.create_memory(
        memory_id=memory_id, title=title, description=description,
        category=category, agent_id=agent_id, host=host, process=process,
        service=service, network=network, evidence=evidence,
        source=source if source in MEMORY_ID_PREFIXES else "analysis",
        created_by=created_by, status="PENDING_APPROVAL",
        confidence=None, scope=scope, question_id=question_id, alert_id=alert_id,
    )
    return db.get_memory(memory_id)


def format_memory_for_display(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "memory_id": m.get("memory_id"),
        "title": m.get("title"),
        "description": m.get("description"),
        "category": m.get("category"),
        "scope": m.get("scope"),
        "status": m.get("status"),
        "agent_id": m.get("agent_id"),
        "host": m.get("host"),
        "confidence": m.get("confidence"),
        "approved_by": m.get("approved_by"),
    }


# ---------------------------------------------------------------------------
# v10: admin knowledge questions — one structured ask/answer round-trip
# ---------------------------------------------------------------------------

QUESTION_PROMPT_VERSION = "kq-v1"
_MAX_Q_CHARS = 1000


def _question_messages(
    db: Database, question: str, *,
    agent_id: str | None, alert_id: int | None,
) -> list[dict[str, str]]:
    """System + user messages for one question.

    Only trusted system context (scoped approved memories + a specific alert
    fact-set) is attached; anything the admin writes goes in as *question
    text*, and the prompt explicitly says proposal data must match the answer
    structure. No tool access, no syslog dump — cheap and safe.
    """
    system = (
        "تو دستیار دانش شبکه یک سامانه‌ی پایش هستی. مدیر شبکه از تو سؤال می‌پرسد.\n\n"
        "قواعد اجباری:\n"
        "1. فقط فارسی و مختصر پاسخ بده؛ از حدس زدن پرهیز کن و ابهام را در confidence "
        "منعکس کن.\n"
        "2. اگر بخش «حافظه‌ی تأییدشده» داده شده، دانشِ بازبینی‌شده‌ی مدیر شبکه است و "
        "محدوده‌ی اعتبار آن را رعایت کن.\n"
        "3. هیچ دستور اجرای روی دستگاه/عامل در توان داری نیست؛ کار تو فقط پاسخ و پیشنهاد "
        "دانش است.\n"
        "4. خروجی فقط و فقط یک شیء JSON باشد:\n"
        '{"answer": "...", "confidence": "low|medium|high|unknown", '
        '"memory_proposal": {"title": "...", "description": "...", "category": '
        '"approved_service|known_process|known_false_positive|known_network_behavior|'
        'known_device|known_service|incident_resolution|diagnostic_playbook", '
        '"scope": "agent|host|process|service|network|global"} | null}\n'
        "اگر دانش جدید ثبت‌کردنی در کار نیست، memory_proposal را null بگذار. بدون "
        "مقدمه، بدون کدبلاک، فقط JSON."
    )
    mems = retrieve_memories(
        db, agent_id=agent_id,
        keywords=question, limit=6,
    )
    block = memory_context_block(mems) if mems else ""
    user_parts = [f"سؤال مدیر شبکه:\n{question[:_MAX_Q_CHARS]}"]
    if agent_id:
        user_parts.append(f"زمینه: این سؤال درباره‌ی عامل agent={agent_id} است.")
    if alert_id is not None:
        alert = db.get_alert(alert_id)
        if alert is not None:
            prior = db.get_alert_analysis(alert_id) or {}
            fact = {
                "alert": {k: alert.get(k) for k in (
                    "id", "src_ip", "dest_ip", "proto", "app_proto",
                    "signature", "signature_id", "severity", "action",
                )},
                "previous_analysis": (
                    {k: prior.get(k) for k in ("summary", "importance", "recommendation")}
                    if prior.get("summary") else None
                ),
            }
            user_parts.append(
                "شواهد سامانه (فقط داده):\n"
                + json.dumps(fact, ensure_ascii=False, default=str)[:2000]
            )
    if block:
        user_parts.append(block[:2500])
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n\n".join(user_parts)},
    ]


def _parse_question_answer(raw: str) -> dict[str, Any]:
    """Strict JSON parse; on failure keep the raw text so the admin still sees
    something honest instead of a synthetic success."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`").lstrip("json").strip()
    parsed = json.loads(text)
    if not isinstance(parsed, dict) or "answer" not in parsed:
        raise ValueError("پاسخ مدل JSON ساختارمند نیست")
    meta = {
        "confidence": parsed.get("confidence"),
        "memory_proposal": parsed.get("memory_proposal"),
    }
    return {"answer": str(parsed["answer"])[:5000], "meta": meta}


def _propose_memory_from_answer(
    db: Database, question_id: str, meta: dict[str, Any], *,
    agent_id: str | None, alert_id: int | None,
) -> list[str]:
    """Turn a structurally-valid ``memory_proposal`` into a PENDING memory.

    Only this call (source=question_resolve) is allowed to create question
    memories; they are never approved here — human approval stays the only
    activation path."""
    proposal = meta.get("memory_proposal")
    if not isinstance(proposal, dict):
        return []
    title = str(proposal.get("title") or "")[:200]
    if len(title) < 3:
        return []
    scope = proposal.get("scope") or "event"
    category = proposal.get("category") or "known_network_behavior"
    errors: list[str] = []
    ok = validate_memory_fields(
        category=category, scope=scope, agent_id=agent_id, host=None,
        process=proposal.get("process"), service=proposal.get("service"),
        network=proposal.get("network"), errors=errors,
    )
    if not ok:
        return []
    try:
        created = suggest_memory(
            db, title=title,
            description=str(proposal.get("description") or "")[:2000],
            category=category, agent_id=agent_id,
            host=proposal.get("host"), process=proposal.get("process"),
            service=proposal.get("service"), network=proposal.get("network"),
            evidence=None, alert_id=alert_id,
            source="question_resolve", question_id=question_id, scope=scope,
        )
        return [created["memory_id"]]
    except (ValueError, KeyError, TypeError):
        return []


def ask_question(
    db: Database, llm: Any, *,
    question: str, agent_id: str | None = None,
    alert_id: int | None = None, asked_by: str | None = None,
) -> dict[str, Any]:
    """One admin question → recorded answer (+gated memory proposal).

    - no implicit tool runs; the answer/proposal round only;
    - every real model call is traced in the AI Activity Monitor
      (task_type=question);
    - with the LLM disabled the question is stored FAILED with a precise
      reason — no fake answer is ever generated.
    """
    question = (question or "").strip()[:_MAX_Q_CHARS]
    if len(question) < 3:
        raise ValueError("سؤال خیلی کوتاه است (حداقل ۳ نویسه)")
    question_id = f"q_{uuid.uuid4().hex[:16]}"
    model = getattr(llm, "model", None) if llm is not None else None
    db.create_ai_question(
        question_id=question_id, question=question, agent_id=agent_id,
        evidence=None, asked_by=asked_by, model=model,
        prompt_version=QUESTION_PROMPT_VERSION,
    )
    started = time.monotonic()
    if llm is None:
        db.finish_ai_question(
            question_id, status="FAILED",
            error="مدل‌زبان فعال نیست (Msty در دسترس نیست)",
        )
        return db.get_ai_question(question_id) or {}

    msgs = _question_messages(db, question, agent_id=agent_id, alert_id=alert_id)
    trace = ActivityTrace(
        db,
        task_type="question", model=model,
        refs=[{"question_id": question_id}],
        prompt_version=QUESTION_PROMPT_VERSION,
        context_summary=ActivityTrace.context_digest(
            {"question": question, "agent_id": agent_id, "alert_id": alert_id}
        ),
    )
    trace.mark("CONTEXT_PREPARED")
    try:
        raw = traced_chat(llm, msgs, trace=trace)
        parsed = _parse_question_answer(raw)
        db.finish_ai_question(
            question_id, status="ANSWERED", answer=parsed["answer"],
            answer_meta=parsed["meta"],
            duration_ms=round((time.monotonic() - started) * 1000.0, 1),
        )
        trace.mark("PERSISTED")
        trace.complete(outcome_summary=(
            f"سؤال {question_id}: پاسخ ذخیره شد؛ اطمینان "
            f"{parsed['meta'].get('confidence') or 'نامشخص'}."
        ))
    except Exception as exc:
        err = f"{exc.__class__.__name__}: {exc}"[:300]
        db.finish_ai_question(question_id, status="FAILED", error=err)
        trace.fail(err)
        raise

    proposal_ids = _propose_memory_from_answer(
        db, question_id, parsed["meta"], agent_id=agent_id, alert_id=alert_id,
    )
    if proposal_ids:
        db.set_question_proposals(question_id, proposal_ids)
    return db.get_ai_question(question_id) or {}
