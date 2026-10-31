"""Health status builder: explicit, precise reporting of component states."""

from __future__ import annotations

import socket
from typing import Any

from netagent import __version__
from netagent.config import Settings
from netagent.database import Database


def _llm_reachable(settings: Settings) -> tuple[bool, str]:
    """TCP-level check of the LLM endpoint; sends no model request."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(settings.msty_base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=2.0):
            return True, "reachable"
    except OSError as exc:
        return False, f"unreachable: {exc.__class__.__name__}"


def build_health(
    db: Database,
    settings: Settings,
    monitor_health: dict[str, Any],
    monitor_running: bool,
) -> dict[str, Any]:
    llm_ok, llm_detail = _llm_reachable(settings)
    suricata = monitor_health.get("suricata", {})
    suricata_ok = bool(suricata.get("file_readable")) and suricata.get("consecutive_errors", 0) < 3

    from netagent.config import binary_available
    capabilities = {
        "nmap": binary_available("nmap") or binary_available("/usr/bin/nmap"),
        "arp_scan": binary_available("arp-scan") or binary_available("/usr/sbin/arp-scan"),
        "tshark": binary_available("tshark") or binary_available("/usr/bin/tshark"),
        "iproute2": binary_available("ip"),
        "ping": binary_available("ping") or binary_available("/usr/bin/ping"),
    }

    # Endpoint agents + discovery policy (read-only, never crashes health).
    agents_summary: dict[str, Any] = {"active": 0, "stale": 0, "revoked": 0, "total": 0}
    auto_networks: list[dict[str, Any]] = []
    try:
        from netagent.services.agents import agent_public_view
        from netagent.services.discovery import auto_discovery_eligible_networks

        agents = [agent_public_view(a, settings) for a in db.list_agents(limit=1000)]
        agents_summary["total"] = len(agents)
        for a in agents:
            agents_summary[a["status"]] = agents_summary.get(a["status"], 0) + 1
        if settings.auto_discovery_enabled:
            auto_networks = [
                {"cidr": e["cidr"], "reporting_agents": len(e["reporting_agents"])}
                for e in auto_discovery_eligible_networks(db, settings)
            ]
    except Exception:  # health must never fail because of a new subsystem
        pass

    components = {
        "database": {"ok": True, "path": str(settings.database_path), "stats": db.stats()},
        "suricata": {**suricata, "ok": suricata_ok},
        "llm": {
            "ok": llm_ok,
            "detail": llm_detail,
            "base_url": settings.msty_base_url,
            "model": settings.msty_model,
        },
        "monitor_thread": {"ok": True, "running": monitor_running},
        "endpoint_agents": {
            "ok": True,
            **agents_summary,
            "heartbeat_timeout_seconds": settings.agent_heartbeat_timeout_seconds,
        },
        "diagnostics": {
            "policy": "all non-destructive tools enabled by default; scope-gated",
            "capabilities": capabilities,
            "scope": settings.scope_description(),
            "nmap_os_privileged": False,  # detected at call time; see /api/tools
            "auto_discovery": {
                "enabled": settings.auto_discovery_enabled,
                "eligible_networks": auto_networks,
            },
            "budget": {
                "max_tool_calls": settings.max_tool_calls_per_investigation,
                "deadline_seconds": settings.investigation_deadline_seconds,
            },
        },
    }
    overall = "ok" if (suricata_ok or not settings.enable_monitor) else "degraded"
    if not llm_ok:
        overall = "degraded" if overall == "ok" else overall
    return {"status": overall, "components": components, "version": __version__}
