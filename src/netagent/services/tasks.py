"""Central task queue for endpoint agents.

Two authorization domains share one queue implementation but never one
authorization path:

- Diagnostic tasks (inventory_collection, connectivity_diagnostic, …) may be
  created by administrators through the admin API. They carry no secrets.
- Administrator execution tasks (admin_python_script, console_*) are created
  ONLY through the admin control plane after successful admin-token
  authentication, and are handed to agents inside a signed envelope
  (HMAC-SHA256 over the canonical payload, keyed per-agent).

The AI tool registry has no function that creates tasks; the LLM cannot
reach this module's admin entry points because they exist only on the
administrator router (which the model has no credentials for).
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import ADMIN_TASK_TYPES, DIAGNOSTIC_TASK_TYPES
from netagent.security import sign_task

# Task types the agent may run without signed-envelope verification
# (they are data-collection operations, not code execution).
UNSIGNED_TASK_TYPES = DIAGNOSTIC_TASK_TYPES

ENVELOPE_KIND = "netagent.admin-task.v1"

# Map agent-advertised capabilities to the task types the agent may claim.
# "admin_exec" / "console" map to the signed admin task families.
CAPABILITY_TO_TASK_TYPES: dict[str, tuple[str, ...]] = {
    "inventory": ("inventory_collection",),
    "connectivity_diagnostic": ("connectivity_diagnostic",),
    "service_inventory": ("service_inventory",),
    "network_configuration": ("network_configuration",),
    "approved_network_diagnostic": ("approved_network_diagnostic",),
    "admin_exec": ("admin_python_script",),
    "console": ("console_session", "console_command", "console_terminate"),
    "screenshot": ("screen_capture",),
}
DEFAULT_CAPABILITIES = ("inventory", "connectivity_diagnostic", "service_inventory",
                        "network_configuration", "approved_network_diagnostic")


class TaskError(ValueError):
    """Invalid task request (unknown type, bad target, limits exceeded)."""


def new_task_id() -> str:
    return f"task_{secrets.token_hex(8)}"


def signing_key_for(settings: Settings, agent_id: str) -> str | None:
    """Per-agent envelope signing key derived from the master key.

    The master key lives in configuration only (never in the database, never
    in the LLM process inputs). Returns None when signing is unavailable.
    """
    master = (settings.task_signing_key or "").strip()
    if not master:
        return None
    from netagent.security import hash_secret

    return f"{hash_secret(master)}:{hash_secret(f'{master}:{agent_id}')}"


def build_signed_envelope(
    settings: Settings,
    *,
    agent_id: str,
    task_id: str,
    task_type: str,
    params: dict[str, Any],
    expires_epoch: float,
) -> dict[str, Any]:
    """Build the envelope handed to the agent for admin execution tasks.

    The signature covers the task identity, the destination agent, the
    parameters, and the expiry — so a captured envelope cannot be replayed
    against another agent, with other parameters, or after expiry.
    """
    key = signing_key_for(settings, agent_id)
    if key is None:
        raise TaskError(
            "TASK_SIGNING_KEY is not configured; admin execution tasks cannot be signed"
        )
    payload = {
        "kind": ENVELOPE_KIND,
        "task_id": task_id,
        "agent_id": agent_id,
        "type": task_type,
        "params_sha256": _params_digest(params),
        "expires_epoch": expires_epoch,
        "nonce": secrets.token_hex(8),
    }
    payload["signature"] = sign_task(payload, key)
    return payload


def _params_digest(params: dict[str, Any]) -> str:
    import hashlib
    import json

    blob = json.dumps(params or {}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def create_diagnostic_task(
    db: Database,
    settings: Settings,
    *,
    agent_id: str,
    task_type: str,
    params: dict[str, Any] | None,
    created_by: str,
    priority: int = 5,
    timeout_seconds: int | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    if task_type not in DIAGNOSTIC_TASK_TYPES:
        raise TaskError(f"unknown diagnostic task type: {task_type!r}")
    agent = db.get_agent(agent_id)
    if agent is None or agent.get("status") == "revoked":
        raise TaskError("agent not found or revoked")
    if db.pending_task_count(agent_id) >= 100:
        raise TaskError("too many pending tasks for this agent")
    return db.create_task(
        task_id=new_task_id(),
        agent_id=agent_id,
        type=task_type,
        params=_bound_params(params),
        origin="admin",
        created_by=created_by,
        timeout_seconds=timeout_seconds or settings.agent_task_default_timeout_seconds,
        ttl_seconds=ttl_seconds or settings.agent_task_default_ttl_seconds,
        priority=priority,
    )


def create_admin_script_task(
    db: Database,
    settings: Settings,
    *,
    agent: dict[str, Any],
    code: str,
    created_by: str,
    timeout_seconds: int | None = None,
    note: str | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Create an administrator Python-execution task with a signed envelope.

    Requires: the feature flag on the server, signing key configured, and the
    target agent advertising the `admin_exec` capability. The plain script is
    stored (bounded) for the audit trail; the signature covers its digest.
    """
    if not settings.allow_admin_python_exec:
        raise TaskError("remote python execution is disabled on this server (ALLOW_ADMIN_PYTHON_EXEC)")
    if task_type_disabled(settings, agent, "admin_exec"):
        raise TaskError("target agent does not advertise the admin_exec capability")
    code_bytes = len(code.encode("utf-8"))
    if code_bytes == 0 or code_bytes > settings.admin_script_max_bytes:
        raise TaskError(f"script size must be 1..{settings.admin_script_max_bytes} bytes")
    timeout = min(
        timeout_seconds or settings.admin_script_max_runtime_seconds,
        settings.admin_script_max_runtime_seconds,
    )
    task_id = new_task_id()
    ttl = ttl_seconds or settings.agent_task_default_ttl_seconds
    params: dict[str, Any] = {
        "code": code,
        "timeout_seconds": timeout,
        "note": (note or None),
    }
    task = db.create_task(
        task_id=task_id,
        agent_id=agent["id"],
        type="admin_python_script",
        params=params,
        origin="admin",
        created_by=created_by,
        timeout_seconds=timeout,
        ttl_seconds=ttl,
        priority=3,
    )
    task["envelope"] = build_signed_envelope(
        settings,
        agent_id=agent["id"],
        task_id=task_id,
        task_type="admin_python_script",
        params=params,
        expires_epoch=task["expiry_epoch"] or (time.time() + ttl),
    )
    return task


def task_type_disabled(settings: Settings, agent: dict[str, Any], capability: str) -> bool:
    caps = agent.get("capabilities") or []
    return capability not in caps


def dispatch_task(
    db: Database,
    settings: Settings,
    agent: dict[str, Any],
    *,
    supported_types: list[str] | None = None,
) -> dict[str, Any] | None:
    """Claim the next runnable task for one agent and shape the wire message.

    ``supported_types`` holds agent *capabilities* (inventory, admin_exec,
    console, …) which are mapped to task types. Unsigned diagnostic tasks go
    out as-is. Admin execution tasks go out only inside their signed
    envelope, and only when the server-side policy enables them.
    """
    db.expire_due_tasks()
    caps = set(supported_types or agent.get("capabilities") or DEFAULT_CAPABILITIES)
    allowed: set[str] = set()
    for cap in caps:
        types = CAPABILITY_TO_TASK_TYPES.get(cap, ())
        if not types:
            continue
        if types[0] in ADMIN_TASK_TYPES:
            # Central policy gate: admin task families are claimable only when
            # both the server feature flag and the signing key are present.
            if types[0] == "admin_python_script" and not settings.allow_admin_python_exec:
                continue
            if types[0].startswith("console") and not settings.allow_admin_python_console:
                continue
            if types[0] == "screen_capture" and not settings.allow_admin_screenshot:
                continue
            if not (settings.task_signing_key or "").strip():
                continue
        allowed.update(types)
    task = db.claim_next_task(agent["id"], allowed_types=sorted(allowed))
    if task is None:
        return None

    message: dict[str, Any] = {
        "task_id": task["id"],
        "type": task["type"],
        "created_at": task["created_at"],
        "expires_at": task["expires_at"],
        "timeout_seconds": task["timeout_seconds"],
    }
    if task["type"] in UNSIGNED_TASK_TYPES:
        message["params"] = task.get("params") or {}
        return message

    # Admin execution task: attach the signed envelope with the parameters.
    params = task.get("params") or {}
    message["params"] = params
    message["envelope"] = build_signed_envelope(
        settings,
        agent_id=agent["id"],
        task_id=task["id"],
        task_type=task["type"],
        params=params,
        expires_epoch=task["expiry_epoch"] or time.time() + 60,
    )
    return message


def complete_task_from_agent(
    db: Database,
    settings: Settings,
    *,
    agent: dict[str, Any],
    task_id: str,
    ok: bool,
    result: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    """Store a task result; reject results for foreign agents' tasks or
    tasks that are not in the dispatched state (duplicate submission)."""
    task = db.get_task(task_id)
    if task is None:
        raise TaskError("task not found")
    if task["agent_id"] != agent["id"]:
        raise TaskError("task belongs to another agent")
    if task["status"] == "dispatched":
        return db.complete_task(
            task_id,
            ok=ok,
            result=_bound_result(result, settings.agent_max_task_result_bytes),
            error=(error or None),
            # screenshots ride in the result; their cap is the dedicated one
            max_result_bytes=(
                settings.screenshot_max_bytes
                if task["type"] == "screen_capture"
                else settings.agent_max_task_result_bytes
            ),
        )
    # Already finished/expired/cancelled: report the current state without
    # storing a second result (duplicate-execution protection).
    task["accepted"] = False
    task["rejection_reason"] = f"task status is '{task['status']}'"
    return task


def _bound_params(params: dict[str, Any] | None) -> dict[str, Any]:
    import json

    blob = json.dumps(params or {}, ensure_ascii=False, default=str)
    if len(blob.encode("utf-8")) > 64 * 1024:
        raise TaskError("task params too large")
    return params or {}


def _bound_result(result: dict[str, Any] | None, max_bytes: int) -> dict[str, Any]:
    import json

    if result is None:
        return {}
    blob = json.dumps(result, ensure_ascii=False, default=str)
    if len(blob.encode("utf-8")) <= max_bytes:
        return result
    return {"truncated": True, "excerpt": blob[: max_bytes // 2]}
