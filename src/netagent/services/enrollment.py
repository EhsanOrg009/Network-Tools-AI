"""Automatic agent registration with administrator approval.

Flow (no manual enrollment token required):

1. The un-enrolled agent introduces itself: ``POST /api/agent/v1/register``
   with non-sensitive declared info plus ``identity_key_hash =
   sha256(identity_key)`` (a random client-side secret). The server stores
   the request as ``PENDING_APPROVAL``. A request is *declared* data — the
   server trusts nothing yet.
2. The agent polls ``POST /api/agent/v1/register/{id}/claim`` carrying the
   plain ``identity_key`` (over TLS). The hash proves the claimer is the same
   party that made the original request; the identity key never leaves the
   agent except inside the TLS channel and is never stored server-side.
3. The administrator sees the request in the dashboard and approves or
   rejects it. Only after approval does ``claim`` issue the permanent
   ``agent_id`` + ``agent_token`` (exactly once) and create the agent row.
4. Rejected/expired requests never grant anything and stay in the audit
   history.

Anti-abuse: per-source-IP sliding-window rate limiting, a bounded number of
pending requests, expiry of stale requests, and deduplication through the
unique ``identity_key_hash`` (a re-registering agent updates its existing
request instead of creating endless rows).
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import EndpointPlatformInfo
from netagent.security import hash_secret

STATUS_PENDING = "PENDING_APPROVAL"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"
STATUS_ENROLLED = "ENROLLED"


class RegistrationError(ValueError):
    """Registration request rejected (rate limit, disabled, bounds)."""


class ClaimError(ValueError):
    """Claim rejected (unknown request, wrong identity key)."""


# ---------------------------------------------------------------------------
# Rate limiting (per source IP sliding window, in-memory, bounded)
# ---------------------------------------------------------------------------


class _RateLimiter:
    def __init__(self, max_events: int, window_seconds: float, max_sources: int = 10_000):
        self.max_events = max_events
        self.window = window_seconds
        self.max_sources = max_sources
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if source not in self._events and len(self._events) >= self.max_sources:
                self._events = {
                    k: v for k, v in self._events.items()
                    if v and now - v[-1] < self.window
                }
                # Keep live rate-limit buckets; evicting them would let a
                # source reset its allowance by filling the table.
                if len(self._events) >= self.max_sources:
                    return False
            bucket = [t for t in self._events.get(source, []) if now - t < self.window]
            if len(bucket) >= self.max_events:
                self._events[source] = bucket
                return False
            bucket.append(now)
            self._events[source] = bucket
            return True


# ---------------------------------------------------------------------------


def register_request(db: Database, settings: Settings, **fields) -> dict[str, Any]:
    """Serialize identity lookup, refresh and bounded admission together."""
    with db.transaction():
        return _register_request(db, settings, **fields)


def _register_request(
    db: Database,
    settings: Settings,
    *,
    request_id: str,
    identity_key_hash: str,
    hostname: str | None,
    platform: EndpointPlatformInfo,
    agent_version: str | None,
    claimed_ips: list[str],
    mac: str | None,
    gateway: str | None,
) -> dict[str, Any]:
    """Store/refresh a registration request. Returns the stored view."""
    if not settings.allow_auto_registration:
        raise RegistrationError("ثبت‌نام خودکار روی این سرور غیرفعال است (ALLOW_AUTO_REGISTRATION).")
    if not request_id or len(request_id) > 64 or not identity_key_hash or len(identity_key_hash) != 64:
        raise RegistrationError("درخواست ثبت‌نام نامعتبر است.")
    existing = db.get_enrollment_request_by_identity_hash(identity_key_hash)
    by_request_id = db.get_enrollment_request(request_id)
    if by_request_id is not None and by_request_id["identity_key_hash"] != identity_key_hash:
        raise RegistrationError("شناسهٔ درخواست به هویت دیگری تعلق دارد؛ برای هویت جدید شناسهٔ تازه بسازید.")
    ttl_epoch = time.time() + settings.enrollment_request_ttl_minutes * 60
    if existing and existing["status"] == STATUS_PENDING:
        db.refresh_enrollment_request(
            existing["id"],
            hostname=hostname,
            platform=platform.model_dump(),
            agent_version=agent_version,
            claimed_ips=claimed_ips,
            mac=mac,
            gateway=gateway,
            expiry_epoch=ttl_epoch,
        )
        return db.get_enrollment_request(existing["id"])  # type: ignore[return-value]
    if existing and existing["status"] in (STATUS_ENROLLED, STATUS_APPROVED):
        enrolled_agent = db.get_agent(existing.get("enrolled_agent_id") or "")
        if enrolled_agent is not None and enrolled_agent.get("status") != "revoked":
            # already completed for this endpoint identity: re-registration after
            # enrollment is NOT automatic — revoke the previous agent first
            raise RegistrationError(
                "این هویت قبلاً ثبت‌نام شده است؛ برای ثبت‌نام دوباره ابتدا عامل قبلی را باطل کنید."
            )
        # ENROLLED whose agent was revoked (or a stale APPROVED row): let the
        # endpoint re-apply against the same row — no endless new rows
        db.revive_enrollment_request(
            existing["id"],
            identity_key_hash=identity_key_hash,
            hostname=hostname,
            platform=platform.model_dump(),
            agent_version=agent_version,
            claimed_ips=claimed_ips,
            mac=mac,
            gateway=gateway,
            expiry_epoch=ttl_epoch,
        )
        return db.get_enrollment_request(existing["id"])  # type: ignore[return-value]
    if existing and existing["status"] in (STATUS_REJECTED, STATUS_EXPIRED):
        # a rejected/expired endpoint may ask again; the old decision stays in
        # the audit history and the administrator decides anew
        db.revive_enrollment_request(
            existing["id"],
            identity_key_hash=identity_key_hash,
            hostname=hostname,
            platform=platform.model_dump(),
            agent_version=agent_version,
            claimed_ips=claimed_ips,
            mac=mac,
            gateway=gateway,
            expiry_epoch=ttl_epoch,
        )
        return db.get_enrollment_request(existing["id"])  # type: ignore[return-value]
    db.expire_due_enrollment_requests()
    if db.count_enrollment_requests(status=STATUS_PENDING) >= settings.max_pending_enrollment_requests:
        raise RegistrationError("تعداد درخواست‌های در انتظار تأیید به سقف رسیده است.")
    request = db.create_enrollment_request(
        request_id=request_id,
        identity_key_hash=identity_key_hash,
        hostname=hostname,
        platform=platform.model_dump(),
        agent_version=agent_version,
        claimed_ips=claimed_ips,
        mac=mac,
        gateway=gateway,
        ttl_seconds=settings.enrollment_request_ttl_minutes * 60,
    )
    return request


def claim_request(db: Database, settings: Settings, *, request_id: str, identity_key: str) -> dict[str, Any]:
    """Commit issuance, request state and the enrollment audit atomically."""
    with db.transaction():
        return _claim_request(db, settings, request_id=request_id, identity_key=identity_key)


def _claim_request(
    db: Database,
    settings: Settings,
    *,
    request_id: str,
    identity_key: str,
) -> dict[str, Any]:
    """Agent polls its request status. When APPROVED and the identity key
    matches the registered hash, issue the permanent credential exactly once."""
    request = db.get_enrollment_request(request_id)
    if request is None:
        raise ClaimError("درخواست ثبت‌نام یافت نشد.")
    if not identity_key or not secrets.compare_digest(
        hash_secret(identity_key), request["identity_key_hash"]
    ):
        raise ClaimError("کلید هویت با درخواست مطابقت ندارد.")
    db.expire_due_enrollment_requests()
    request = db.get_enrollment_request(request_id)
    status = request["status"]
    if status == STATUS_PENDING:
        return {"status": STATUS_PENDING,
                "note": "درخواست در انتظار تأیید مدیر شبکه است."}
    if status == STATUS_REJECTED:
        return {"status": STATUS_REJECTED,
                "reason": request.get("reject_reason")}
    if status == STATUS_EXPIRED:
        return {"status": STATUS_EXPIRED,
                "note": "درخواست منقضی شده است؛ ثبت‌نام را دوباره انجام دهید."}
    if status == STATUS_ENROLLED:
        return {"status": STATUS_ENROLLED,
                "agent_id": request.get("enrolled_agent_id"),
                "note": "ثبت‌نام قبلاً تکمیل شده است؛ اعتبارنامه فقط یک‌بار صادر می‌شود."}
    if status == STATUS_APPROVED:
        from netagent.services.agents import generate_agent_id
        from netagent.security import generate_token

        agent_id = generate_agent_id(db)
        token = generate_token("agt")
        caps = ["inventory", "connectivity_diagnostic", "service_inventory",
                "network_configuration", "approved_network_diagnostic"]
        outcome, existing = db.complete_enrollment_request(
            request["id"],
            agent_id=agent_id,
            token_hash=hash_secret(token),
            hostname=request.get("hostname"),
            platform_os_family=(request.get("platform") or {}).get("os_family"),
            agent_version=request.get("agent_version"),
            heartbeat_interval=settings.agent_heartbeat_interval_seconds,
            capabilities=caps,
        )
        if outcome == "already_enrolled":
            return {"status": STATUS_ENROLLED,
                    "agent_id": existing,
                    "note": "ثبت‌نام قبلاً تکمیل شده است؛ اعتبارنامه فقط یک‌بار صادر می‌شود."}
        if outcome != "created":  # reviewed/expired between calls: retry next poll
            raise ClaimError("درخواست در وضعیت قابل صدور نیست؛ بعداً دوباره تلاش کنید.")
        db.record_audit(
            actor="auto-registration", action="agent.enroll", target=agent_id,
            detail={"request_id": request["id"],
                    "hostname": request.get("hostname"),
                    "origin": "auto-registration"},
        )
        return {"status": STATUS_APPROVED, "agent_id": agent_id, "agent_token": token}
    raise ClaimError(f"وضعیت نامشخص: {status}")
