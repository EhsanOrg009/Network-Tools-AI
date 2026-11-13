"""Endpoint agent registry: enrollment, authentication, staleness, inventory.

Security model:
- Agents authenticate with an individual bearer token issued at enrollment.
  Only the SHA-256 hash is stored; verification is constant-time.
- An enrollment token (admin-issued one-time token, or the static bootstrap
  token from settings) is required to enroll; DB tokens are consumed
  atomically (single use, expiry enforced).
- A revoked agent's token hash is overwritten, so old tokens stop working.
- An agent without a recent heartbeat is reported *stale*, never assumed
  powered off.
- All agent-reported data is untrusted input: it is validated (Pydantic),
  stored with its source, and never treated as proof of authenticity.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import time
from typing import Any

from netagent.config import Settings
from netagent.database import Database
from netagent.schemas import EnrollRequest, InterfaceObservation, InventoryRequest
from netagent.security import generate_token, hash_secret, secret_matches


class AgentAuthError(Exception):
    """Invalid or missing agent credential."""


class EnrollmentError(Exception):
    """Enrollment rejected (bad/expired/used token)."""


def _normalize_cidr(value: str) -> str | None:
    value = (value or "").strip()
    if not value or "/" not in value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def agent_public_view(agent: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Agent record safe for API responses + computed staleness state."""
    now_epoch = time.time()
    last = agent.get("last_heartbeat_epoch")
    seconds_since = round(now_epoch - last, 1) if last else None
    if agent.get("status") == "revoked":
        state = "revoked"
    elif seconds_since is None or seconds_since > settings.agent_heartbeat_timeout_seconds:
        state = "stale"
    else:
        state = "active"
    return {
        "id": agent["id"],
        "hostname": agent.get("hostname"),
        "platform": agent.get("platform"),
        "agent_version": agent.get("agent_version"),
        "status": state,
        "enrolled_at": agent.get("enrolled_at"),
        "revoked_at": agent.get("revoked_at"),
        "last_heartbeat_at": agent.get("last_heartbeat_at"),
        "seconds_since_heartbeat": seconds_since,
        "heartbeat_interval_seconds": agent.get("heartbeat_interval"),
        "capabilities": agent.get("capabilities") or [],
        "claimed_ips": agent.get("claimed_ips") or [],
        "latest_inventory_at": agent.get("latest_inventory_at"),
    }


def authenticate_agent(db: Database, authorization: str | None) -> dict[str, Any]:
    """Validate ``Authorization: Bearer <token>`` and return the agent row."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AgentAuthError("Authorization header with Bearer token is required")
    token = authorization[7:].strip()
    if not token:
        raise AgentAuthError("empty bearer token")
    agent_id = db.get_agent_id_by_token_hash(hash_secret(token))
    if agent_id is None:
        raise AgentAuthError("unknown agent credential")
    agent = db.get_agent(agent_id)
    if agent is None or agent.get("status") == "revoked":
        raise AgentAuthError("agent credential is revoked")
    return agent


def generate_agent_id(db: Database) -> str:
    while True:
        candidate = f"agt_{secrets.token_hex(6)}"
        if db.get_agent(candidate) is None:
            return candidate


def enroll_agent(db: Database, settings: Settings, req: EnrollRequest, *, origin: str | None = None) -> tuple[dict[str, Any], str]:
    """Token consumption and permanent identity creation share one commit."""
    with db.transaction():
        return _enroll_agent(db, settings, req, origin=origin)


def _enroll_agent(
    db: Database,
    settings: Settings,
    req: EnrollRequest,
    *,
    origin: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Enroll one agent. Returns (agent_row, agent_token) — the token is
    returned exactly once and only its hash is stored."""
    presented = (req.enrollment_token or "").strip()
    if not presented:
        raise EnrollmentError("enrollment_token is required")

    agent_id = generate_agent_id(db)
    static_token = (settings.agent_enrollment_token or "").strip()
    if static_token and hmac.compare_digest(presented, static_token):
        pass  # static bootstrap token from settings: valid, reusable
    else:
        token_hash = hash_secret(presented)
        # Atomic single-use consumption; expiry checked inside the UPDATE.
        if not db.consume_enrollment_token(token_hash, agent_id):
            raise EnrollmentError("توکن ثبت‌نام نامعتبر، منقضی‌شده یا قبلاً استفاده شده است.")

    token = generate_token("agt")
    capabilities = [c for c in (req.capabilities or []) if isinstance(c, str)][:20]
    agent = db.create_agent(
        agent_id=agent_id,
        token_hash=hash_secret(token),
        hostname=(req.hostname or None),
        platform=req.platform.os_family,
        agent_version=req.agent_version,
        origin=origin,
        heartbeat_interval=settings.agent_heartbeat_interval_seconds,
        capabilities=capabilities,
    )
    return agent, token


def ingest_inventory(
    db: Database,
    settings: Settings,
    agent_id: str,
    payload: InventoryRequest,
) -> dict[str, Any]:
    """Validate + persist one inventory upload; refresh network observations."""
    if payload.collected_at_epoch is not None and payload.collected_at_epoch > time.time() + 300:
        raise ValueError("collected_at_epoch is in the future")

    with db.transaction():
        inventory = payload.model_dump(mode="json", exclude_none=False)
        db.store_inventory(agent_id, inventory, max_history=settings.agent_inventory_history_limit)

        excluded_ifaces = {i.lower() for i in settings.discovery_excluded_interface_list}
        observations = []
        claimed_ips: list[str] = []
        for iface in payload.interfaces:
            claimed_ips.extend(iface.ipv4 or [])
            claimed_ips.extend(iface.ipv6 or [])
            if (iface.name or "").lower() in excluded_ifaces:
                continue
            classification = iface.classification or classify_interface(iface)
            for cidr in iface.connected_networks or []:
                normalized = _normalize_cidr(cidr)
                if normalized is None:
                    continue
                observations.append({
                    "interface": iface.name,
                    "cidr": normalized,
                    "classification": classification,
                    "connected": (iface.status or "up") == "up",
                })
        if observations:
            db.record_network_observations(agent_id, observations)
        if claimed_ips:
            db.agent_heartbeat(agent_id, claimed_ips=claimed_ips)

    return {
        "stored": True,
        "interfaces": len(payload.interfaces),
        "network_observations": len(observations),
    }


def classify_interface(iface: InterfaceObservation) -> str:
    """Best-effort interface classification from its name and addresses."""
    name = (iface.name or "").lower()
    ipv4 = list(iface.ipv4 or [])
    if name == "lo" or name.startswith("lo0") or "loopback" in name:
        return "loopback"
    vpn_markers = ("tun", "tap", "wg", "ppp", "vpn", "tunnel", "zt")
    if any(m in name for m in vpn_markers):
        return "vpn"
    virtual_markers = ("docker", "veth", "br-", "virbr", "vmnet", "vbox",
                       "hyper-v", "virtual", "vmware", "vethernet")
    if any(m in name for m in virtual_markers):
        return "virtual"
    if ipv4 and all(a.startswith("169.254.") for a in ipv4):
        return "link_local"
    return "physical" if iface.gateway else "unknown"


def stale_agents(db: Database, settings: Settings) -> list[dict[str, Any]]:
    threshold = settings.agent_stale_threshold_epoch()
    out = []
    for agent in db.list_agents():
        last = agent.get("last_heartbeat_epoch") or 0
        if last < threshold:
            out.append(agent_public_view(agent, settings))
    return out
