"""Automatic network discovery: observed → classified → policy-checked.

Data model distinction (explicit by design):
- **observed**: a CIDR an enrolled agent reports as directly connected.
  Loopback/link-local are recorded but never candidates for scanning.
- **known**: the observation is stored in the central inventory with source,
  timestamps, and classification.
- **authorized for discovery**: only private, directly-connected, small
  enough subnets reported by enough distinct agents, not excluded by policy,
  and only when AUTO_DISCOVERY_ENABLED=true. Public, VPN, virtual, and
  loopback/link-local ranges are NEVER auto-authorized.

The auto-authorized set extends (never replaces) the explicitly configured
MONITOR_CIDRS scope. Every decision records its origin and justification.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from netagent.config import Settings
from netagent.database import Database


def classify_cidr(cidr: str) -> str:
    """Classify a network range: private | loopback | link_local | public | other."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return "invalid"
    if net.is_loopback:
        return "loopback"
    if net.is_link_local:
        return "link_local"
    if net.is_multicast or net.is_reserved or net.is_unspecified:
        return "other"
    if net.is_private:
        return "private"
    return "public"


def _excluded(settings: Settings, cidr: str) -> str | None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return "invalid-cidr"
    for raw in settings.discovery_excluded_cidr_list:
        try:
            ex = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == ex.version and (net.overlaps(ex) or net.subnet_of(ex) or ex.subnet_of(net)):
            return f"matches exclusion {ex}"
    return None


def auto_discovery_eligible_networks(
    db: Database, settings: Settings, *, now_epoch: float | None = None
) -> list[dict[str, Any]]:
    """Return the discovered networks currently eligible for low-impact host
    discovery, each with the justification for the decision (audit trail)."""
    if not settings.auto_discovery_enabled:
        return []
    rows = db.list_network_observations(limit=1000)
    by_cidr: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_cidr.setdefault(row["cidr"], []).append(row)

    eligible: list[dict[str, Any]] = []
    for cidr, observations in by_cidr.items():
        classification = classify_cidr(cidr)
        if classification != "private":
            continue  # public/loopback/link_local/other are never auto-eligible
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.num_addresses > settings.auto_discovery_max_addresses:
            continue
        excluded = _excluded(settings, cidr)
        if excluded:
            continue
        # Only directly-connected observations from physical/unknown (i.e. not
        # explicitly virtual/vpn/loopback) interfaces count as reporters.
        reporters: dict[str, set[str]] = {}
        for obs in observations:
            if not obs.get("connected"):
                continue
            iface_class = classify_iface_key(obs)
            if iface_class in ("virtual", "vpn", "loopback"):
                continue
            if iface_class == "link_local":
                continue
            reporters.setdefault(obs["agent_id"], set()).add(obs["interface"])
        if len(reporters) < settings.auto_discovery_min_reporters:
            continue
        eligible.append({
            "cidr": cidr,
            "classification": classification,
            "reporting_agents": sorted(reporters.keys()),
            "interfaces": sorted({i for s in reporters.values() for i in s}),
            "origin": "auto-discovery",
            "justification": (
                f"private، مستقیماً متصل، {len(reporters)} عامل گزارش‌ده، "
                f"سایز {net.num_addresses} آدرس، خارج از فهرست استثناها"
            ),
        })
    return eligible


def classify_iface_key(obs: dict[str, Any]) -> str:
    """Interface classification recorded on the observation row."""
    return (obs.get("classification") or "unknown").lower()


def effective_discovery_scope(
    db: Database, settings: Settings, *, now_epoch: float | None = None
) -> dict[str, Any]:
    """The effective scope for low-impact host discovery:
    configured MONITOR_CIDRS ∪ auto-authorized discovered networks.

    Never replaces or broadens the configured scope silently — discovered
    entries are listed separately with their justification."""
    configured = [str(n) for n in settings.monitor_cidr_list]
    auto = auto_discovery_eligible_networks(db, settings, now_epoch=now_epoch)
    return {
        "configured_cidrs": configured,
        "authorized_targets": [str(n) for n in settings.authorized_target_list],
        "auto_discovered": [
            {"cidr": e["cidr"], "reporting_agents": e["reporting_agents"],
             "justification": e["justification"]}
            for e in auto
        ],
        "auto_discovery_enabled": settings.auto_discovery_enabled,
        "note": (
            "اسکن فقط روی configured_cidrs ∪ auto_discovered مجاز است. "
            "این فهرست جای MONITOR_CIDRS را نمی‌گیرد؛ فقط آن را گسترش می‌دهد."
        ),
    }


def is_auto_discovery_target_authorized(
    db: Database, settings: Settings, target: str, *, now_epoch: float | None = None
) -> bool:
    """True when *target* (IP or CIDR) falls inside the effective discovery
    scope (configured ∪ auto-authorized discovered)."""
    try:
        addr = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for entry in auto_discovery_eligible_networks(db, settings, now_epoch=now_epoch):
        try:
            net = ipaddress.ip_network(entry["cidr"], strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr.subnet_of(net):
            return True
    return False
