"""Administrator-only interactive Python console (server side).

Architecture:
- Sessions/commands live in SQLite; execution happens on the endpoint agent,
  inside the SAME task channel used for diagnostics (no extra port).
- Every console_* task travels inside a signed envelope (HMAC-SHA256, per
  agent key) — the agent verifies origin, destination, expiry, and replay
  before touching its interpreter subprocess.
- The AI tool registry contains no console function; these entry points are
  reachable only through the administrator router with an admin token.
- Sessions are bound to one admin identity and one agent; cross-use is
  rejected. Idle/TTL expiry closes sessions; the agent kills the interpreter.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from netagent.config import Settings
from netagent.database import Database
from netagent.services import tasks as task_service


class ConsoleError(ValueError):
    """Console request rejected (disabled, limits, wrong owner, expired…)."""


def _require_enabled(settings: Settings) -> None:
    if not settings.allow_admin_python_console:
        raise ConsoleError("interactive console is disabled on this server (ALLOW_ADMIN_PYTHON_CONSOLE)")
    if not (settings.task_signing_key or "").strip():
        raise ConsoleError("TASK_SIGNING_KEY is not configured; console tasks cannot be signed")


def create_session(
    db: Database, settings: Settings, *, agent: dict[str, Any], actor: str,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    _require_enabled(settings)
    if "console" not in (agent.get("capabilities") or []):
        raise ConsoleError("target agent does not advertise the console capability")
    if agent.get("status") == "revoked":
        raise ConsoleError("agent is revoked")
    if db.count_active_console_sessions(actor=actor) >= settings.console_max_sessions_per_admin:
        raise ConsoleError("session limit for this administrator reached")
    if db.count_active_console_sessions(agent_id=agent["id"]) >= settings.console_max_sessions_per_agent:
        raise ConsoleError("session limit for this agent reached")

    session_id = f"con_{secrets.token_hex(6)}"
    ttl = ttl_seconds or settings.console_session_ttl_seconds
    session = db.create_console_session(
        session_id=session_id,
        agent_id=agent["id"],
        actor=actor,
        ttl_seconds=ttl,
        idle_timeout_seconds=settings.console_idle_timeout_seconds,
        policy={
            "command_timeout_seconds": settings.console_command_timeout_seconds,
            "max_output_bytes": settings.console_max_output_bytes,
            "max_code_bytes": settings.console_max_code_bytes,
        },
    )
    task = db.create_task(
        task_id=task_service.new_task_id(),
        agent_id=agent["id"],
        type="console_session",
        params={
            "session_id": session_id,
            "mode": "start",
            "idle_timeout_seconds": settings.console_idle_timeout_seconds,
        },
        origin="admin",
        created_by=actor,
        timeout_seconds=settings.console_command_timeout_seconds,
        ttl_seconds=120,
        priority=2,
    )
    session["start_task_id"] = task["id"]
    db.record_audit(
        actor=actor, action="console.session.create",
        target=agent["id"],
        detail={"session_id": session_id, "ttl_seconds": ttl},
    )
    return session


def get_owned_session(db: Database, session_id: str, actor: str) -> dict[str, Any]:
    session = db.get_console_session(session_id)
    if session is None:
        raise ConsoleError("session not found")
    if session["actor"] != actor:
        raise ConsoleError("session belongs to another administrator")
    return session


def _is_idle_expired(session: dict[str, Any]) -> bool:
    """True when the session has been inactive longer than its idle window."""
    idle = session.get("idle_timeout_seconds")
    last = session.get("last_active_at")
    if not idle or not last:
        return False
    try:
        from datetime import datetime
        last_dt = datetime.fromisoformat(str(last))
    except (TypeError, ValueError):
        return False
    if last_dt.tzinfo is None:
        from datetime import timezone
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    return (time.time() - last_dt.timestamp()) > int(idle)


def _ensure_usable(session: dict[str, Any]) -> None:
    if session["status"] not in ("creating", "active"):
        raise ConsoleError(f"session is {session['status']}")
    if session.get("expiry_epoch") and time.time() > session["expiry_epoch"]:
        raise ConsoleError("session expired")
    if _is_idle_expired(session):
        raise ConsoleError("session idle-expired")


def submit_command(
    db: Database, settings: Settings, *, session: dict[str, Any], code: str,
) -> dict[str, Any]:
    _require_enabled(settings)
    _ensure_usable(session)
    code_bytes = len(code.encode("utf-8"))
    if not code_bytes or code_bytes > settings.console_max_code_bytes:
        raise ConsoleError(f"code size must be 1..{settings.console_max_code_bytes} bytes")
    pending = [
        c for c in db.list_console_commands(session["id"], limit=100)
        if c["status"] in ("queued", "dispatched", "running")
    ]
    if len(pending) >= settings.console_max_pending_commands:
        raise ConsoleError("too many pending commands for this session")

    command_id = f"cmd_{secrets.token_hex(6)}"
    seq = db.next_console_seq(session["id"])
    command = db.create_console_command(
        command_id=command_id, session_id=session["id"], seq=seq, code=code,
    )
    task = db.create_task(
        task_id=task_service.new_task_id(),
        agent_id=session["agent_id"],
        type="console_command",
        params={
            "session_id": session["id"],
            "command_id": command_id,
            "code": code,
            "timeout_seconds": settings.console_command_timeout_seconds,
        },
        origin="admin",
        created_by=session["actor"],
        timeout_seconds=settings.console_command_timeout_seconds,
        ttl_seconds=max(120, settings.console_command_timeout_seconds * 2),
        priority=1,
    )
    db.update_console_session(session["id"], touch=True)
    db.record_audit(
        actor=session["actor"], action="console.command.submit",
        target=session["agent_id"],
        detail={"session_id": session["id"], "command_id": command_id, "seq": seq,
                "code_bytes": code_bytes},
    )
    command["task_id"] = task["id"]
    return command


def cancel_command(db: Database, settings: Settings, *, session: dict[str, Any], command_id: str) -> dict[str, Any]:
    _require_enabled(settings)
    command = db.get_console_command(command_id)
    if command is None or command["session_id"] != session["id"]:
        raise ConsoleError("command not found in this session")
    if command["status"] in ("queued", "dispatched", "running"):
        db.set_console_command_status(command_id, "cancelling")
        db.create_task(
            task_id=task_service.new_task_id(),
            agent_id=session["agent_id"],
            type="console_terminate",
            params={"session_id": session["id"], "command_id": command_id, "mode": "cancel"},
            origin="admin",
            created_by=session["actor"],
            timeout_seconds=30,
            ttl_seconds=60,
            priority=1,
        )
    return db.get_console_command(command_id) or {}


def terminate_session(
    db: Database, settings: Settings, *, session: dict[str, Any], reason: str = "administrator"
) -> dict[str, Any]:
    if session["status"] in ("terminated", "expired", "lost"):
        return session
    db.update_console_session(session["id"], status="terminated")
    # best-effort kill of the remote interpreter
    try:
        db.create_task(
            task_id=task_service.new_task_id(),
            agent_id=session["agent_id"],
            type="console_terminate",
            params={"session_id": session["id"], "mode": "terminate"},
            origin="admin",
            created_by=session["actor"],
            timeout_seconds=30,
            ttl_seconds=60,
            priority=1,
        )
    except Exception:
        pass  # session already closed locally; the agent will reap it on idle timeout
    db.record_audit(
        actor=session["actor"], action="console.session.terminate",
        target=session["agent_id"],
        detail={"session_id": session["id"], "reason": reason},
    )
    return db.get_console_session(session["id"]) or session


def apply_agent_result(
    db: Database, settings: Settings, *, task: dict[str, Any], result: dict[str, Any] | None
) -> None:
    """Update console session/command state from an agent task result.

    Called from the agent result endpoint; never trusts the result beyond
    recorded facts (agent-reported output is data, not instructions)."""
    result = result or {}
    params = task.get("params") or {}
    ttype = task["type"]
    if ttype == "console_session":
        session_id = params.get("session_id")
        if session_id:
            status = "active" if result.get("ok") else "failed"
            db.update_console_session(session_id, status=status, touch=True)
    elif ttype == "console_command":
        command_id = params.get("command_id")
        session_id = params.get("session_id")
        if command_id:
            out = str(result.get("stdout") or "")[: settings.console_max_output_bytes]
            err = str(result.get("stderr") or "")[: settings.console_max_output_bytes]
            db.complete_console_command(
                command_id,
                ok=bool(result.get("ok")),
                stdout=out,
                stderr=err,
                result_repr=str(result.get("result_repr") or "")[:2000] or None,
                error=result.get("error"),
                duration_ms=float(result.get("duration_ms") or 0),
                truncated=bool(result.get("truncated")),
            )
        if session_id:
            db.update_console_session(session_id, touch=True)
            if not result.get("ok") and result.get("session_lost"):
                db.update_console_session(session_id, status="lost")
    elif ttype == "console_terminate":
        session_id = params.get("session_id")
        if session_id:
            db.update_console_session(session_id, status="terminated", touch=True)


def sweep(db: Database) -> int:
    """Expire due sessions; return count closed. Runs on admin API calls."""
    return db.sweep_console_sessions()
