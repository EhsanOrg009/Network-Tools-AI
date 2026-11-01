"""SQLite persistence layer.

Uses the standard library ``sqlite3`` with WAL mode. A single connection is
shared and guarded by a re-entrant lock because FastAPI runs sync endpoints
in a thread pool.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    mac TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    ts_epoch REAL,
    event_type TEXT,
    flow_id INTEGER,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    app_proto TEXT,
    ingress TEXT,
    raw_json TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dest ON events(dest_ip);
CREATE INDEX IF NOT EXISTS idx_events_flow ON events(flow_id);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE REFERENCES events(id),
    ts TEXT,
    ts_epoch REAL,
    flow_id INTEGER,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    app_proto TEXT,
    signature TEXT,
    signature_id INTEGER,
    signature_rev INTEGER,
    category TEXT,
    severity INTEGER,
    action TEXT,
    metadata_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_sig ON alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dest ON alerts(dest_ip);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    ts TEXT NOT NULL,
    ts_epoch REAL,
    kind TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_host ON observations(host_ip, ts_epoch);

CREATE TABLE IF NOT EXISTS diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT,
    args_json TEXT,
    ok INTEGER NOT NULL,
    result_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL,
    target_ip TEXT,
    question TEXT,
    status TEXT NOT NULL,
    evidence_json TEXT,
    report_json TEXT,
    report_text TEXT,
    confidence TEXT,
    iterations INTEGER,
    error TEXT
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    created_at TEXT NOT NULL,
    os_family TEXT,
    os_version TEXT,
    device_type TEXT,
    hostname TEXT,
    hostname_source TEXT,
    mac TEXT,
    mac_vendor TEXT,
    mac_randomized INTEGER,
    open_ports_json TEXT,
    services_json TEXT,
    protocols_json TEXT,
    availability TEXT,
    methods_json TEXT,
    evidence_json TEXT,
    confidence TEXT,
    confidence_explanation TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_fp_ip ON fingerprints(ip, id);

-- ---------------------------------------------------------------------------
-- Endpoint agents, network discovery, task queue, admin audit, console (v3)
-- All statements are IF NOT EXISTS: opening an existing v2 database adds the
-- new tables without touching existing rows (additive migration only).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS endpoint_agents (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    platform TEXT,
    agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'enrolled',
    token_hash TEXT NOT NULL UNIQUE,
    enrolled_at TEXT NOT NULL,
    enrolled_origin TEXT,
    revoked_at TEXT,
    last_heartbeat_at TEXT,
    last_heartbeat_epoch REAL,
    heartbeat_interval INTEGER,
    capabilities_json TEXT,
    claimed_ips_json TEXT,
    latest_inventory_json TEXT,
    latest_inventory_at TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_agents_hb ON endpoint_agents(last_heartbeat_epoch);

CREATE TABLE IF NOT EXISTS agent_inventories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_inv ON agent_inventories(agent_id, id);

CREATE TABLE IF NOT EXISTS network_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    interface TEXT NOT NULL,
    cidr TEXT NOT NULL,
    classification TEXT,
    connected INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'agent',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_epoch REAL NOT NULL,
    UNIQUE(agent_id, interface, cidr)
);
CREATE INDEX IF NOT EXISTS idx_netobs_cidr ON network_observations(cidr);
CREATE INDEX IF NOT EXISTS idx_netobs_epoch ON network_observations(last_epoch);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    type TEXT NOT NULL,
    params_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 5,
    origin TEXT NOT NULL DEFAULT 'admin',
    created_by TEXT,
    created_at TEXT NOT NULL,
    created_epoch REAL NOT NULL,
    expires_at TEXT,
    expiry_epoch REAL,
    timeout_seconds INTEGER,
    dispatched_at TEXT,
    finished_at TEXT,
    result_json TEXT,
    result_truncated INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    attempt INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON agent_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON agent_tasks(status, created_epoch);

CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL DEFAULT 'ok',
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON admin_audit(at);

CREATE TABLE IF NOT EXISTS console_sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_epoch REAL NOT NULL,
    expires_at TEXT,
    expiry_epoch REAL,
    idle_timeout_seconds INTEGER,
    status TEXT NOT NULL DEFAULT 'creating',
    policy_json TEXT,
    last_active_at TEXT,
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_consolesess_agent ON console_sessions(agent_id, status);

CREATE TABLE IF NOT EXISTS console_commands (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    code TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    submitted_at TEXT NOT NULL,
    submitted_epoch REAL NOT NULL,
    finished_at TEXT,
    stdout TEXT,
    stderr TEXT,
    result_repr TEXT,
    error TEXT,
    duration_ms REAL,
    truncated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_consolecmd_sess ON console_commands(session_id, seq);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT,
    expires_at TEXT NOT NULL,
    expiry_epoch REAL NOT NULL,
    used_by TEXT,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_enrolltokens_exp ON enrollment_tokens(expiry_epoch);

CREATE TABLE IF NOT EXISTS enrollment_requests (
    id TEXT PRIMARY KEY,
    identity_key_hash TEXT NOT NULL UNIQUE,
    hostname TEXT,
    platform_json TEXT,
    agent_version TEXT,
    claimed_ips_json TEXT,
    mac TEXT,
    gateway TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    requested_at TEXT NOT NULL,
    requested_epoch REAL NOT NULL,
    updated_at TEXT,
    expires_at TEXT,
    expiry_epoch REAL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    reject_reason TEXT,
    enrolled_agent_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_enrollreq_status ON enrollment_requests(status, requested_epoch);

CREATE TABLE IF NOT EXISTS alert_analyses (
    alert_id INTEGER PRIMARY KEY REFERENCES alerts(id),
    fingerprint TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'PENDING',
    summary TEXT,
    importance TEXT,
    evidence_json TEXT,
    anomaly_likelihood TEXT,
    confidence TEXT,
    recommendation TEXT,
    model TEXT,
    prompt_version TEXT,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    analyzed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alertanal_status ON alert_analyses(status, alert_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- meta ---------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    # -- hosts --------------------------------------------------------------

    def upsert_host(self, ip: str, hostname: str | None = None, mac: str | None = None) -> None:
        now = _now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO hosts(ip, hostname, mac, first_seen, last_seen)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    hostname = COALESCE(excluded.hostname, hosts.hostname),
                    mac = COALESCE(excluded.mac, hosts.mac)
                """,
                (ip, hostname, mac, now, now),
            )
            self._conn.commit()

    def list_hosts(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM hosts ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_host(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE ip = ?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    # -- events / alerts ----------------------------------------------------

    def insert_event(self, ev: dict[str, Any], raw_json: str, dedupe_key: str) -> int | None:
        """Insert a normalized event. Returns the row id, or None on duplicate."""
        now = _now_iso()
        try:
            with self._lock:
                cur = self._conn.execute(
                    """
                    INSERT INTO events(
                        ts, ts_epoch, event_type, flow_id,
                        src_ip, src_port, dest_ip, dest_port,
                        proto, app_proto, ingress, raw_json, dedupe_key, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ev.get("ts"),
                        ev.get("ts_epoch"),
                        ev.get("event_type"),
                        ev.get("flow_id"),
                        ev.get("src_ip"),
                        ev.get("src_port"),
                        ev.get("dest_ip"),
                        ev.get("dest_port"),
                        ev.get("proto"),
                        ev.get("app_proto"),
                        ev.get("ingress"),
                        raw_json,
                        dedupe_key,
                        now,
                    ),
                )
                self._conn.commit()
                return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return None  # duplicate dedupe_key

    def insert_alert(self, event_id: int, alert: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alerts(
                    event_id, ts, ts_epoch, flow_id,
                    src_ip, src_port, dest_ip, dest_port, proto, app_proto,
                    signature, signature_id, signature_rev,
                    category, severity, action, metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    alert.get("ts"),
                    alert.get("ts_epoch"),
                    alert.get("flow_id"),
                    alert.get("src_ip"),
                    alert.get("src_port"),
                    alert.get("dest_ip"),
                    alert.get("dest_port"),
                    alert.get("proto"),
                    alert.get("app_proto"),
                    alert.get("signature"),
                    alert.get("signature_id"),
                    alert.get("signature_rev"),
                    alert.get("category"),
                    alert.get("severity"),
                    alert.get("action"),
                    json.dumps(alert.get("metadata"), ensure_ascii=False, default=str)
                    if alert.get("metadata") is not None
                    else None,
                ),
            )
            self._conn.commit()

    def query_events(
        self,
        *,
        event_type: str | None = None,
        ip: str | None = None,
        since_epoch: float | None = None,
        until_epoch: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        params: list[Any] = []
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if ip:
            where.append("(src_ip = ? OR dest_ip = ?)")
            params.extend([ip, ip])
        if since_epoch is not None:
            where.append("ts_epoch >= ?")
            params.append(since_epoch)
        if until_epoch is not None:
            where.append("ts_epoch <= ?")
            params.append(until_epoch)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM events {cond}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"""
                SELECT id, ts, ts_epoch, event_type, flow_id, src_ip, src_port,
                       dest_ip, dest_port, proto, app_proto, ingress, created_at
                FROM events {cond}
                ORDER BY ts_epoch DESC, id DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def query_alerts(
        self,
        *,
        ip: str | None = None,
        severity: int | None = None,
        signature_id: int | None = None,
        since_epoch: float | None = None,
        until_epoch: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        params: list[Any] = []
        if ip:
            where.append("(src_ip = ? OR dest_ip = ?)")
            params.extend([ip, ip])
        if severity is not None:
            where.append("severity = ?")
            params.append(severity)
        if signature_id is not None:
            where.append("signature_id = ?")
            params.append(signature_id)
        if since_epoch is not None:
            where.append("ts_epoch >= ?")
            params.append(since_epoch)
        if until_epoch is not None:
            where.append("ts_epoch <= ?")
            params.append(until_epoch)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM alerts {cond}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"""
                SELECT * FROM alerts {cond}
                ORDER BY ts_epoch DESC, id DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT a.*, e.raw_json
                FROM alerts a JOIN events e ON e.id = a.event_id
                WHERE a.id = ?
                """,
                (alert_id,),
            ).fetchone()
        return dict(row) if row else None

    def alert_flow_summary(
        self,
        *,
        ip: str | None = None,
        since_epoch: float | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Group alerts by (flow_id, signature_id) so repeated rule matches on
        the same flow are reported once with a count, not as separate attacks."""
        where: list[str] = []
        params: list[Any] = []
        if ip:
            where.append("(src_ip = ? OR dest_ip = ?)")
            params.extend([ip, ip])
        if since_epoch is not None:
            where.append("ts_epoch >= ?")
            params.append(since_epoch)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT flow_id, signature_id, signature, category, severity,
                       MAX(action) AS action, COUNT(*) AS hit_count,
                       MIN(ts) AS first_seen, MAX(ts) AS last_seen,
                       src_ip, dest_ip, dest_port
                FROM alerts {cond}
                GROUP BY flow_id, signature_id
                ORDER BY MAX(ts_epoch) DESC LIMIT ?
                """,
                [*params, limit],
            ).fetchall()
        return [dict(r) for r in rows]

    # -- observations / diagnostics ------------------------------------------

    def record_observation(
        self, host_ip: str, kind: str, success: bool, detail: dict[str, Any]
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO observations(host_ip, ts, ts_epoch, kind, success, detail_json)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    host_ip,
                    _now_iso(),
                    datetime.now(timezone.utc).timestamp(),
                    kind,
                    int(success),
                    json.dumps(detail, ensure_ascii=False, default=str),
                ),
            )
            self._conn.commit()

    def host_observations(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, host_ip, ts, ts_epoch, kind, success, detail_json
                FROM observations WHERE host_ip = ?
                ORDER BY ts_epoch DESC LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if d.get("detail_json"):
                try:
                    d["detail"] = json.loads(d["detail_json"])
                except (TypeError, ValueError):
                    d["detail"] = None
                d.pop("detail_json", None)
            out.append(d)
        return out

    def host_event_summary(self, ip: str, limit: int = 500) -> dict[str, Any]:
        since = datetime.now(timezone.utc).timestamp() - 24 * 3600
        with self._lock:
            counts = {
                r["event_type"]: r["c"]
                for r in self._conn.execute(
                    """
                    SELECT event_type, COUNT(*) AS c FROM events
                    WHERE (src_ip = ? OR dest_ip = ?) AND ts_epoch >= ?
                    GROUP BY event_type
                    """,
                    (ip, ip, since),
                ).fetchall()
            }
            recent = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT ts, event_type, flow_id, src_ip, src_port,
                           dest_ip, dest_port, proto, app_proto
                    FROM events
                    WHERE (src_ip = ? OR dest_ip = ?) AND ts_epoch >= ?
                    ORDER BY ts_epoch DESC LIMIT ?
                    """,
                    (ip, ip, since, min(limit, 50)),
                ).fetchall()
            ]
        return {"event_counts_24h": counts, "recent_events": recent}

    def record_diagnostic(
        self, tool: str, target: str | None, args: dict[str, Any],
        ok: bool, result: dict[str, Any], error: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO diagnostics(created_at, tool, target, args_json,
                                        ok, result_json, error)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    _now_iso(), tool, target,
                    json.dumps(args, ensure_ascii=False, default=str),
                    int(ok), json.dumps(result, ensure_ascii=False, default=str), error,
                ),
            )
            self._conn.commit()

    # -- investigations -------------------------------------------------------

    def create_investigation(
        self, trigger: str, target_ip: str | None, question: str | None, evidence: dict[str, Any]
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO investigations(created_at, trigger, target_ip,
                                           question, status, evidence_json)
                VALUES(?,?,?,?, 'running', ?)
                """,
                (
                    _now_iso(), trigger, target_ip, question,
                    json.dumps(evidence, ensure_ascii=False, default=str),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_investigation(
        self,
        inv_id: int,
        *,
        status: str,
        report: dict[str, Any] | None,
        report_text: str | None,
        confidence: str | None,
        iterations: int,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE investigations
                SET status = ?, report_json = ?, report_text = ?,
                    confidence = ?, iterations = ?, error = ?,
                    finished_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    json.dumps(report, ensure_ascii=False, default=str) if report else None,
                    report_text,
                    confidence,
                    iterations,
                    error,
                    _now_iso(),
                    inv_id,
                ),
            )
            self._conn.commit()

    def list_investigations(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, created_at, finished_at, trigger, target_ip, question,
                       status, confidence, iterations, error
                FROM investigations ORDER BY id DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_investigation(self, inv_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM investigations WHERE id = ?", (inv_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        for key in ("evidence_json", "report_json"):
            if d.get(key):
                try:
                    d[key.replace("_json", "")] = json.loads(d[key])
                except (TypeError, ValueError):
                    pass
        return d

    # -- fingerprints ----------------------------------------------------------

    def save_fingerprint(self, fp: dict[str, Any]) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO fingerprints(
                    ip, created_at, os_family, os_version, device_type,
                    hostname, hostname_source, mac, mac_vendor, mac_randomized,
                    open_ports_json, services_json, protocols_json,
                    availability, methods_json, evidence_json,
                    confidence, confidence_explanation, source
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    fp.get("ip"),
                    _now_iso(),
                    fp.get("os_family"),
                    fp.get("os_version"),
                    fp.get("device_type"),
                    fp.get("hostname"),
                    fp.get("hostname_source"),
                    fp.get("mac"),
                    fp.get("mac_vendor"),
                    1 if fp.get("mac_randomized") else 0,
                    json.dumps(fp.get("open_ports") or [], ensure_ascii=False),
                    json.dumps(fp.get("services") or [], ensure_ascii=False, default=str),
                    json.dumps(fp.get("protocols") or [], ensure_ascii=False),
                    fp.get("availability"),
                    json.dumps(fp.get("methods") or [], ensure_ascii=False),
                    json.dumps(fp.get("evidence") or [], ensure_ascii=False, default=str),
                    fp.get("confidence"),
                    fp.get("confidence_explanation"),
                    fp.get("source"),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    @staticmethod
    def _fingerprint_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for col, key in (
            ("open_ports_json", "open_ports"),
            ("services_json", "services"),
            ("protocols_json", "protocols"),
            ("methods_json", "methods"),
            ("evidence_json", "evidence"),
        ):
            if d.get(col):
                try:
                    d[key] = json.loads(d[col])
                except (TypeError, ValueError):
                    d[key] = None
            d.pop(col, None)
        return d

    def latest_fingerprint(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM fingerprints WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
        return self._fingerprint_row_to_dict(row) if row else None

    def fingerprint_history(self, ip: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM fingerprints WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            ).fetchall()
        return [self._fingerprint_row_to_dict(r) for r in rows]

    def fingerprint_changes(self, ip: str) -> dict[str, Any]:
        """Diff between the two most recent fingerprints (changes over time)."""
        history = self.fingerprint_history(ip, limit=2)
        if len(history) < 2:
            return {"changes": [], "comparisons_available": len(history) >= 2}
        older, newer = history[1], history[0]
        tracked = ("os_family", "os_version", "device_type", "hostname",
                   "mac", "mac_vendor", "availability", "confidence")
        changes = []
        for key in tracked:
            if older.get(key) != newer.get(key):
                changes.append({
                    "field": key, "old": older.get(key), "new": newer.get(key),
                })
        old_ports = set(older.get("open_ports") or [])
        new_ports = set(newer.get("open_ports") or [])
        if old_ports != new_ports:
            changes.append({
                "field": "open_ports",
                "old": sorted(old_ports), "new": sorted(new_ports),
            })
        return {"changes": changes, "comparisons_available": True}

    # -- host timeline ---------------------------------------------------------

    def host_timeline(self, ip: str, limit: int = 100) -> dict[str, Any]:
        """Unified timeline: events, observations, and fingerprints."""
        with self._lock:
            events = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT ts, event_type, flow_id, src_ip, src_port,
                           dest_ip, dest_port, proto, app_proto
                    FROM events
                    WHERE src_ip = ? OR dest_ip = ?
                    ORDER BY ts_epoch DESC LIMIT ?
                    """,
                    (ip, ip, limit),
                ).fetchall()
            ]
            observations = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT ts, kind, success, detail_json
                    FROM observations WHERE host_ip = ?
                    ORDER BY ts_epoch DESC LIMIT ?
                    """,
                    (ip, limit),
                ).fetchall()
            ]
            fingerprints = [
                dict(r)
                for r in self._conn.execute(
                    """
                    SELECT created_at, os_family, os_version, device_type,
                           hostname, mac, confidence
                    FROM fingerprints WHERE ip = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (ip, limit),
                ).fetchall()
            ]
        for o in observations:
            if o.get("detail_json"):
                try:
                    o["detail"] = json.loads(o.pop("detail_json"))
                except (TypeError, ValueError):
                    o.pop("detail_json", None)
        return {
            "ip": ip,
            "events": events,
            "observations": observations,
            "fingerprints": fingerprints,
        }

    # -- diagnostics listing ----------------------------------------------------

    def host_diagnostics(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT created_at, tool, target, ok, result_json, error
                FROM diagnostics
                WHERE target = ?
                ORDER BY id DESC LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if d.get("result_json"):
                try:
                    d["result"] = json.loads(d.pop("result_json"))
                except (TypeError, ValueError):
                    d.pop("result_json", None)
            out.append(d)
        return out

    # -- stats ----------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            events = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            alerts = self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            hosts = self._conn.execute("SELECT COUNT(*) AS c FROM hosts").fetchone()["c"]
            invs = self._conn.execute("SELECT COUNT(*) AS c FROM investigations").fetchone()["c"]
            agents = self._conn.execute(
                "SELECT COUNT(*) AS c FROM endpoint_agents WHERE status != 'revoked'"
            ).fetchone()["c"]
            tasks = self._conn.execute(
                "SELECT COUNT(*) AS c FROM agent_tasks WHERE status = 'pending'"
            ).fetchone()["c"]
        return {
            "events": int(events),
            "alerts": int(alerts),
            "hosts": int(hosts),
            "investigations": int(invs),
            "agents": int(agents),
            "pending_tasks": int(tasks),
        }

    # -- dashboard aggregates (read-only) ------------------------------------

    def alert_severity_counts(self, since_epoch: float | None = None) -> list[dict[str, Any]]:
        """Alerts grouped by Suricata severity (1=fundamental … 4=low)."""
        cond, params = "", []
        if since_epoch is not None:
            cond = "WHERE ts_epoch >= ?"
            params = [since_epoch]
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT severity, COUNT(*) AS c FROM alerts {cond}
                GROUP BY severity ORDER BY severity
                """,
                params,
            ).fetchall()
        return [{"severity": int(r["severity"]), "count": int(r["c"])} for r in rows]

    def daily_activity_counts(self, days: int = 7) -> list[dict[str, Any]]:
        """Per-day counts of raw events, alerts and audit actions for the
        last ``days`` days (UTC) — the raw material for dashboard trends."""
        with self._lock:
            epoch_now = datetime.now(timezone.utc).timestamp()
            day_start = int(epoch_now // 86400) * 86400 - (days - 1) * 86400
            merged: dict[str, dict[str, int]] = {}
            for table, column in (("events", "ev"), ("alerts", "al")):
                rows = self._conn.execute(
                    f"""
                    SELECT CAST((ts_epoch / 86400.0) AS INTEGER) * 86400 AS day_epoch,
                           COUNT(*) AS c
                    FROM {table} WHERE ts_epoch >= ?
                    GROUP BY day_epoch
                    """,
                    (day_start,),
                ).fetchall()
                for r in rows:
                    bucket = merged.setdefault(
                        datetime.fromtimestamp(r["day_epoch"], timezone.utc)
                        .date().isoformat(), {"events": 0, "alerts": 0, "audit": 0},
                    )
                    bucket[column] = int(r["c"])
            rows = self._conn.execute(
                """
                SELECT CAST((at_epoch / 86400.0) AS INTEGER) * 86400 AS day_epoch,
                       COUNT(*) AS c FROM (
                    SELECT CAST(strftime('%s', at) AS INTEGER) AS at_epoch
                    FROM admin_audit WHERE at IS NOT NULL AND at != ''
                ) WHERE at_epoch >= ?
                GROUP BY day_epoch
                """,
                (day_start,),
            ).fetchall()
            for r in rows:
                bucket = merged.setdefault(
                    datetime.fromtimestamp(r["day_epoch"], timezone.utc)
                    .date().isoformat(), {"events": 0, "alerts": 0, "audit": 0},
                )
                bucket["audit"] = int(r["c"])
        out = []
        for i in range(days):
            day = datetime.fromtimestamp(day_start + i * 86400, timezone.utc).date().isoformat()
            out.append({"date": day, **merged.get(day, {"events": 0, "alerts": 0, "audit": 0})})
        return out

    # =========================================================================
    # Endpoint agents (v3): identity, heartbeat, inventory
    # =========================================================================

    def create_agent(
        self,
        *,
        agent_id: str,
        token_hash: str,
        hostname: str | None,
        platform: str | None,
        agent_version: str | None,
        origin: str | None,
        heartbeat_interval: int,
        capabilities: list[str],
    ) -> dict[str, Any]:
        now = _now_iso()
        with self._lock:
            self._insert_agent_row(
                agent_id=agent_id, token_hash=token_hash, hostname=hostname,
                platform=platform, agent_version=agent_version, origin=origin,
                heartbeat_interval=heartbeat_interval, capabilities=capabilities,
                now=now,
            )
            self._conn.commit()
        return self.get_agent(agent_id)  # type: ignore[return-value]

    def _insert_agent_row(
        self, *, agent_id: str, token_hash: str, hostname: str | None,
        platform: str | None, agent_version: str | None, origin: str | None,
        heartbeat_interval: int, capabilities: list[str], now: str,
    ) -> None:
        """Plain INSERT (must be called while ``self._lock`` is held)."""
        self._conn.execute(
            """
            INSERT INTO endpoint_agents(
                id, hostname, platform, agent_version, status, token_hash,
                enrolled_at, enrolled_origin, heartbeat_interval,
                capabilities_json, last_heartbeat_at, last_heartbeat_epoch
            ) VALUES(?,?,?,?, 'enrolled', ?,?,?,?,?,?,?)
            """,
            (
                agent_id, hostname, platform, agent_version, token_hash, now,
                origin, heartbeat_interval,
                json.dumps(capabilities, ensure_ascii=False), now,
                datetime.now(timezone.utc).timestamp(),
            ),
        )

    @staticmethod
    def _agent_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for col, key in (
            ("capabilities_json", "capabilities"),
            ("claimed_ips_json", "claimed_ips"),
        ):
            if d.get(col):
                try:
                    d[key] = json.loads(d[col])
                except (TypeError, ValueError):
                    d[key] = None
            d.pop(col, None)
        return d

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM endpoint_agents WHERE id = ?", (agent_id,)
            ).fetchone()
        return self._agent_row_to_dict(row) if row else None

    def get_agent_id_by_token_hash(self, token_hash: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM endpoint_agents WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return row["id"] if row else None

    def list_agents(
        self, *, limit: int = 200, offset: int = 0, include_revoked: bool = False
    ) -> list[dict[str, Any]]:
        cond = "" if include_revoked else "WHERE status != 'revoked'"
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT id, hostname, platform, agent_version, status, enrolled_at,
                       revoked_at, last_heartbeat_at, last_heartbeat_epoch,
                       heartbeat_interval, capabilities_json, claimed_ips_json,
                       latest_inventory_at
                FROM endpoint_agents {cond}
                ORDER BY COALESCE(last_heartbeat_epoch, 0) DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [self._agent_row_to_dict(r) for r in rows]

    def agent_heartbeat(
        self,
        agent_id: str,
        *,
        claimed_ips: list[str] | None = None,
        heartbeat_interval: int | None = None,
        agent_version: str | None = None,
        hostname: str | None = None,
        platform: str | None = None,
        capabilities: list[str] | None = None,
    ) -> bool:
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE endpoint_agents SET
                    last_heartbeat_at = ?, last_heartbeat_epoch = ?,
                    status = CASE WHEN status IN ('enrolled', 'stale', 'active')
                                  THEN 'active' ELSE status END,
                    claimed_ips_json = COALESCE(?, claimed_ips_json),
                    heartbeat_interval = COALESCE(?, heartbeat_interval),
                    agent_version = COALESCE(?, agent_version),
                    hostname = COALESCE(?, hostname),
                    platform = COALESCE(?, platform),
                    capabilities_json = COALESCE(?, capabilities_json)
                WHERE id = ? AND status != 'revoked'
                """,
                (
                    now, now_epoch,
                    json.dumps(claimed_ips, ensure_ascii=False) if claimed_ips is not None else None,
                    heartbeat_interval, agent_version, hostname, platform,
                    json.dumps([c for c in capabilities if isinstance(c, str)][:20],
                               ensure_ascii=False) if capabilities is not None else None,
                    agent_id,
                ),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def revoke_agent(self, agent_id: str, notes: str | None = None) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE endpoint_agents
                SET status = 'revoked', revoked_at = ?,
                    notes = COALESCE(?, notes),
                    token_hash = 'revoked:' || id
                WHERE id = ? AND status != 'revoked'
                """,
                (_now_iso(), notes, agent_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def store_inventory(
        self, agent_id: str, payload: dict[str, Any], max_history: int = 20
    ) -> None:
        now = _now_iso()
        blob = json.dumps(payload, ensure_ascii=False, default=str)
        with self._lock:
            self._conn.execute(
                "INSERT INTO agent_inventories(agent_id, collected_at, payload_json)"
                " VALUES(?,?,?)",
                (agent_id, now, blob),
            )
            self._conn.execute(
                """
                UPDATE endpoint_agents SET
                    latest_inventory_json = ?, latest_inventory_at = ?
                WHERE id = ?
                """,
                (blob, now, agent_id),
            )
            # bounded history per agent
            self._conn.execute(
                """
                DELETE FROM agent_inventories WHERE agent_id = ? AND id NOT IN (
                    SELECT id FROM agent_inventories WHERE agent_id = ?
                    ORDER BY id DESC LIMIT ?
                )
                """,
                (agent_id, agent_id, max_history),
            )
            self._conn.commit()

    def get_latest_inventory(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT latest_inventory_json, latest_inventory_at FROM endpoint_agents"
                " WHERE id = ?",
                (agent_id,),
            ).fetchone()
        if not row or not row["latest_inventory_json"]:
            return None
        try:
            payload = json.loads(row["latest_inventory_json"])
        except (TypeError, ValueError):
            return None
        return {"collected_at": row["latest_inventory_at"], "inventory": payload}

    def list_inventory_history(self, agent_id: str, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, collected_at, payload_json FROM agent_inventories"
                " WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            try:
                payload = json.loads(r["payload_json"])
            except (TypeError, ValueError):
                payload = None
            out.append({"id": r["id"], "collected_at": r["collected_at"], "inventory": payload})
        return out

    # -- network observations ---------------------------------------------------

    def record_network_observations(self, agent_id: str, observations: list[dict[str, Any]]) -> None:
        """Upsert one row per (agent, interface, cidr); refreshes last_seen."""
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            for o in observations:
                cidr = str(o.get("cidr") or "").strip()
                iface = str(o.get("interface") or "").strip()
                if not cidr or not iface:
                    continue
                self._conn.execute(
                    """
                    INSERT INTO network_observations(
                        agent_id, interface, cidr, classification, connected,
                        source, first_seen, last_seen, last_epoch
                    ) VALUES(?,?,?,?,?,?,?, ?, ?)
                    ON CONFLICT(agent_id, interface, cidr) DO UPDATE SET
                        classification = excluded.classification,
                        connected = excluded.connected,
                        last_seen = excluded.last_seen,
                        last_epoch = excluded.last_epoch
                    """,
                    (
                        agent_id, iface, cidr,
                        o.get("classification"),
                        1 if o.get("connected", True) else 0,
                        o.get("source", "agent"),
                        now, now, now_epoch,
                    ),
                )
            self._conn.commit()

    def list_network_observations(
        self, *, agent_id: str | None = None, limit: int = 500, offset: int = 0
    ) -> list[dict[str, Any]]:
        cond, params = "", []
        if agent_id:
            cond = "WHERE agent_id = ?"
            params.append(agent_id)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT id, agent_id, interface, cidr, classification, connected,
                       source, first_seen, last_seen
                FROM network_observations {cond}
                ORDER BY last_epoch DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [dict(r) for r in rows]

    # =========================================================================
    # Task queue (v3): signed administration tasks + diagnostic tasks
    # =========================================================================

    def create_task(
        self,
        *,
        task_id: str,
        agent_id: str,
        type: str,
        params: dict[str, Any] | None = None,
        origin: str = "admin",
        created_by: str | None = None,
        timeout_seconds: int = 60,
        ttl_seconds: int = 300,
        priority: int = 5,
    ) -> dict[str, Any]:
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        expiry_epoch = now_epoch + max(1, int(ttl_seconds))
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agent_tasks(
                    id, agent_id, type, params_json, status, priority, origin,
                    created_by, created_at, created_epoch, expires_at,
                    expiry_epoch, timeout_seconds
                ) VALUES(?,?,?,?, 'pending', ?,?,?,?,?,?,?,?)
                """,
                (
                    task_id, agent_id, type,
                    json.dumps(params or {}, ensure_ascii=False, default=str),
                    priority, origin, created_by, now, now_epoch,
                    expiry_iso, expiry_epoch, timeout_seconds,
                ),
            )
            self._conn.commit()
        return self.get_task(task_id)  # type: ignore[return-value]

    def expire_due_tasks(self, now_epoch: float | None = None) -> int:
        """Move unclaimed/unfinished tasks past their TTL to 'expired'."""
        now_epoch = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE agent_tasks SET status = 'expired', finished_at = ?,
                       error = COALESCE(error, 'task expired before completion')
                WHERE status IN ('pending', 'dispatched') AND expiry_epoch IS NOT NULL
                      AND expiry_epoch < ?
                """,
                (_now_iso(), now_epoch),
            )
            self._conn.commit()
        return cur.rowcount

    def claim_next_task(
        self, agent_id: str, *, allowed_types: list[str], now_epoch: float | None = None
    ) -> dict[str, Any] | None:
        """Atomically move the next due pending task for this agent from
        pending to dispatched. Returns the task or None."""
        now_epoch = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
        placeholders = ",".join("?" for _ in allowed_types)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    f"""
                    SELECT * FROM agent_tasks
                    WHERE agent_id = ? AND status = 'pending'
                          AND type IN ({placeholders})
                          AND (expiry_epoch IS NULL OR expiry_epoch >= ?)
                    ORDER BY priority ASC, created_epoch ASC LIMIT 1
                    """,
                    (agent_id, *allowed_types, now_epoch),
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return None
                cur = self._conn.execute(
                    """
                    UPDATE agent_tasks SET status = 'dispatched', dispatched_at = ?,
                           attempt = attempt + 1
                    WHERE id = ? AND status = 'pending'
                    """,
                    (_now_iso(), row["id"]),
                )
                if cur.rowcount != 1:
                    self._conn.execute("COMMIT")
                    return None
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return self.get_task(row["id"])

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._task_row_to_dict(row) if row else None

    @staticmethod
    def _task_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("params_json"):
            try:
                d["params"] = json.loads(d.pop("params_json"))
            except (TypeError, ValueError):
                d["params"] = None
        else:
            d.pop("params_json", None)
        if d.get("result_json"):
            try:
                d["result"] = json.loads(d.pop("result_json"))
            except (TypeError, ValueError):
                d["result"] = None
        else:
            d.pop("result_json", None)
        return d

    def complete_task(
        self,
        task_id: str,
        *,
        ok: bool,
        result: dict[str, Any] | None,
        error: str | None = None,
        max_result_bytes: int = 256 * 1024,
    ) -> dict[str, Any]:
        """Record a task result exactly once.

        Returns the updated task; the result is stored only when the task was
        in 'dispatched' state (replay/duplicate submissions are rejected by
        the caller via ``task['accepted']``)."""
        blob = json.dumps(result or {}, ensure_ascii=False, default=str)
        truncated = len(blob.encode("utf-8")) > max_result_bytes
        if truncated:
            blob = json.dumps(
                {"truncated": True, "excerpt": blob[: max_result_bytes // 2]},
                ensure_ascii=False,
            )
        now = _now_iso()
        status = "succeeded" if ok else "failed"
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE agent_tasks SET status = ?, finished_at = ?,
                       result_json = ?, result_truncated = ?, error = ?
                WHERE id = ? AND status = 'dispatched'
                """,
                (status, now, blob, int(truncated), error, task_id),
            )
            self._conn.commit()
            accepted = cur.rowcount == 1
        task = self.get_task(task_id) or {}
        task["accepted"] = accepted
        if not accepted:
            task["rejection_reason"] = (
                f"task status is '{task.get('status')}', not 'dispatched'; "
                "result was not stored"
            )
        return task

    def list_tasks(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
        task_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        params: list[Any] = []
        if agent_id:
            where.append("agent_id = ?")
            params.append(agent_id)
        if status:
            where.append("status = ?")
            params.append(status)
        if task_type:
            where.append("type = ?")
            params.append(task_type)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM agent_tasks {cond}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"""
                SELECT * FROM agent_tasks {cond}
                ORDER BY created_epoch DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [self._task_row_to_dict(r) for r in rows], int(total)

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agent_tasks SET status = 'cancelled', finished_at = ?, "
                "error = COALESCE(error, 'cancelled by administrator') "
                "WHERE id = ? AND status IN ('pending', 'dispatched')",
                (_now_iso(), task_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def pending_task_count(self, agent_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM agent_tasks WHERE agent_id = ? AND status = 'pending'",
                (agent_id,),
            ).fetchone()
        return int(row["c"])

    # -- admin audit ---------------------------------------------------------------

    def record_audit(
        self,
        *,
        actor: str,
        action: str,
        target: str | None = None,
        outcome: str = "ok",
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO admin_audit(at, actor, action, target, outcome, detail_json)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    _now_iso(), actor, action, target, outcome,
                    json.dumps(detail, ensure_ascii=False, default=str) if detail else None,
                ),
            )
            self._conn.commit()

    # -- enrollment tokens -----------------------------------------------------

    def create_enrollment_token(
        self, *, token_hash: str, ttl_seconds: int, created_by: str | None
    ) -> dict[str, Any]:
        now_epoch = datetime.now(timezone.utc).timestamp()
        expiry_epoch = now_epoch + max(60, int(ttl_seconds))
        now = _now_iso()
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO enrollment_tokens(
                    token_hash, created_at, created_by, expires_at, expiry_epoch
                ) VALUES(?,?,?,?,?)
                """,
                (token_hash, now, created_by, expiry_iso, expiry_epoch),
            )
            self._conn.commit()
        return {"created_at": now, "expires_at": expiry_iso, "expiry_epoch": expiry_epoch}

    def consume_enrollment_token(self, token_hash: str, agent_id: str) -> bool:
        """Atomically mark a valid, unused, unexpired token as consumed."""
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE enrollment_tokens SET used_by = ?, used_at = ?
                WHERE token_hash = ? AND used_by IS NULL AND expiry_epoch >= ?
                """,
                (agent_id, _now_iso(), token_hash, now_epoch),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def list_enrollment_tokens(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT token_hash, created_at, created_by, expires_at, used_by, used_at
                FROM enrollment_tokens ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {**dict(r), "token_hash": r["token_hash"][:12] + "…"} for r in rows
        ]

    def purge_expired_enrollment_tokens(self) -> int:
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM enrollment_tokens WHERE expiry_epoch < ? - 7 * 86400",
                (now_epoch,),
            )
            self._conn.commit()
        return cur.rowcount

    # -- enrollment requests (auto-registration with admin approval) -----------

    @staticmethod
    def _enrollment_request_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for col, key in (("platform_json", "platform"), ("claimed_ips_json", "claimed_ips")):
            if d.get(col):
                try:
                    d[key] = json.loads(d[col])
                except (TypeError, ValueError):
                    d[key] = None
            d.pop(col, None)
        return d

    def create_enrollment_request(
        self,
        *,
        request_id: str,
        identity_key_hash: str,
        hostname: str | None,
        platform: dict[str, Any],
        agent_version: str | None,
        claimed_ips: list[str],
        mac: str | None,
        gateway: str | None,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        expiry_epoch = now_epoch + max(60, int(ttl_seconds))
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO enrollment_requests(
                    id, identity_key_hash, hostname, platform_json, agent_version,
                    claimed_ips_json, mac, gateway, status,
                    requested_at, requested_epoch, updated_at, expires_at, expiry_epoch
                ) VALUES(?,?,?,?,?,?,?,?, 'PENDING_APPROVAL', ?,?,?,?,?)
                """,
                (
                    request_id, identity_key_hash, hostname,
                    json.dumps(platform, ensure_ascii=False, default=str),
                    agent_version,
                    json.dumps(claimed_ips, ensure_ascii=False) if claimed_ips else None,
                    mac, gateway, now, now_epoch, now, expiry_iso, expiry_epoch,
                ),
            )
            self._conn.commit()
        return self.get_enrollment_request(request_id)  # type: ignore[return-value]

    def get_enrollment_request(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrollment_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return self._enrollment_request_row_to_dict(row) if row else None

    def get_enrollment_request_by_identity_hash(self, identity_key_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrollment_requests WHERE identity_key_hash = ?",
                (identity_key_hash,),
            ).fetchone()
        return self._enrollment_request_row_to_dict(row) if row else None

    def refresh_enrollment_request(
        self,
        request_id: str,
        *,
        hostname: str | None,
        platform: dict[str, Any],
        agent_version: str | None,
        claimed_ips: list[str],
        mac: str | None,
        gateway: str | None,
        expiry_epoch: float,
        identity_key_hash: str | None = None,
    ) -> None:
        """A re-introducing agent refreshes its pending request in place.

        ``identity_key_hash`` re-binds the proof key (used when the agent kept
        its ``request_id`` but regenerated the identity key); it never changes
        the request row's id, so re-announces cannot create extra rows."""
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                UPDATE enrollment_requests SET
                    hostname = ?, platform_json = ?, agent_version = ?,
                    claimed_ips_json = ?, mac = ?, gateway = ?,
                    identity_key_hash = COALESCE(?, identity_key_hash),
                    requested_at = ?, requested_epoch = ?,
                    expires_at = ?, expiry_epoch = ?, updated_at = ?
                WHERE id = ? AND status = 'PENDING_APPROVAL'
                """,
                (
                    hostname, json.dumps(platform, ensure_ascii=False, default=str),
                    agent_version,
                    json.dumps(claimed_ips, ensure_ascii=False) if claimed_ips else None,
                    mac, gateway, identity_key_hash, now, now_epoch,
                    expiry_iso, expiry_epoch, now,
                    request_id,
                ),
            )
            self._conn.commit()

    def review_enrollment_request(
        self, request_id: str, *, approve: bool, reviewed_by: str, reason: str | None = None
    ) -> dict[str, Any] | None:
        now = _now_iso()
        status = "APPROVED" if approve else "REJECTED"
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE enrollment_requests SET status = ?, reviewed_by = ?,
                       reviewed_at = ?, reject_reason = ?, updated_at = ?
                WHERE id = ? AND status = 'PENDING_APPROVAL'
                """,
                (status, reviewed_by, now, None if approve else (reason or None), now, request_id),
            )
            self._conn.commit()
        if cur.rowcount != 1:
            return None
        return self.get_enrollment_request(request_id)

    def mark_enrollment_request_enrolled(self, request_id: str, *, agent_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE enrollment_requests SET status = 'ENROLLED',
                       enrolled_agent_id = ?, updated_at = ?
                WHERE id = ? AND status = 'APPROVED'
                """,
                (agent_id, _now_iso(), request_id),
            )
            self._conn.commit()

    def revive_enrollment_request(
        self, request_id: str, *, identity_key_hash: str, hostname: str | None,
        platform: dict[str, Any],
        agent_version: str | None, claimed_ips: list[str], mac: str | None,
        gateway: str | None, expiry_epoch: float,
    ) -> None:
        """Re-open an existing request row (REJECTED, or ENROLLED whose agent
        was revoked): back to PENDING_APPROVAL with fresh declared data. The
        previous decision/audit rows are preserved in admin_audit."""
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(
            timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                UPDATE enrollment_requests SET
                    status = 'PENDING_APPROVAL', hostname = ?, platform_json = ?,
                    agent_version = ?, claimed_ips_json = ?, mac = ?, gateway = ?,
                    identity_key_hash = ?,
                    requested_at = ?, requested_epoch = ?, updated_at = ?,
                    expires_at = ?, expiry_epoch = ?,
                    reviewed_by = NULL, reviewed_at = NULL,
                    reject_reason = NULL
                WHERE id = ?
                """,
                (
                    hostname,
                    json.dumps(platform, ensure_ascii=False, default=str),
                    agent_version,
                    json.dumps(claimed_ips, ensure_ascii=False) if claimed_ips else None,
                    mac, gateway,
                    identity_key_hash,
                    _now_iso(), datetime.now(timezone.utc).timestamp(), _now_iso(),
                    expiry_iso, expiry_epoch, request_id,
                ),
            )
            self._conn.commit()

    def complete_enrollment_request(
        self,
        request_id: str,
        *,
        agent_id: str,
        token_hash: str,
        hostname: str | None,
        platform_os_family: str | None,
        agent_version: str | None,
        heartbeat_interval: int,
        capabilities: list[str],
    ) -> tuple[str, str | None]:
        """Atomically turn an APPROVED request into a permanent agent.

        The APPROVED→ENROLLED transition, the agent INSERT and the assignment
        happen inside one locked block, so two concurrent claim pollers can
        never produce two agents from one approval. Returns
        (outcome, existing_agent_id): outcome is ``created`` (this call did
        the work), ``already_enrolled`` (another claim got there first —
        existing_agent_id is set), or ``unavailable`` (request no longer
        APPROVED, e.g. reviewed/expired between calls)."""
        now = _now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrollment_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                return ("unavailable", None)
            status = row["status"]
            if status == "ENROLLED":
                return ("already_enrolled", row["enrolled_agent_id"])
            if status != "APPROVED":
                return ("unavailable", None)
            self._insert_agent_row(
                agent_id=agent_id, token_hash=token_hash, hostname=hostname,
                platform=platform_os_family, agent_version=agent_version,
                origin="auto-registration", heartbeat_interval=heartbeat_interval,
                capabilities=capabilities, now=now,
            )
            self._conn.execute(
                """
                UPDATE enrollment_requests SET status = 'ENROLLED',
                       enrolled_agent_id = ?, updated_at = ? WHERE id = ?
                """,
                (agent_id, now, request_id),
            )
            self._conn.commit()
        return ("created", None)

    def expire_due_enrollment_requests(self) -> int:
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE enrollment_requests SET status = 'EXPIRED', updated_at = ?
                WHERE status = 'PENDING_APPROVAL' AND expiry_epoch < ?
                """,
                (_now_iso(), now_epoch),
            )
            self._conn.commit()
        return cur.rowcount

    def count_enrollment_requests(self, *, status: str | None = None) -> int:
        cond, params = "", []
        if status:
            cond = "WHERE status = ?"
            params.append(status)
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM enrollment_requests {cond}", params
            ).fetchone()
        return int(row["c"])

    def list_enrollment_requests(
        self, *, status: str | None = None, limit: int = 100, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM enrollment_requests {cond}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"""
                SELECT * FROM enrollment_requests {cond}
                ORDER BY requested_epoch DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [self._enrollment_request_row_to_dict(r) for r in rows], int(total)

    def prune_enrollment_requests(self, keep: int = 500) -> int:
        """Bounded history: drop oldest terminal requests beyond ``keep``."""
        with self._lock:
            cur = self._conn.execute(
                """
                DELETE FROM enrollment_requests
                WHERE status IN ('REJECTED', 'EXPIRED', 'ENROLLED') AND id NOT IN (
                    SELECT id FROM enrollment_requests
                    WHERE status IN ('REJECTED', 'EXPIRED', 'ENROLLED')
                    ORDER BY requested_epoch DESC LIMIT ?
                )
                """,
                (keep,),
            )
            self._conn.commit()
        return cur.rowcount

    # -- enrollment tokens end ---------------------------------------------------

    # =========================================================================
    # AI alert analyses (v5): background LLM analysis of security alerts
    # =========================================================================

    def enqueue_alert_analysis(self, *, alert_id: int, fingerprint: str) -> bool:
        """Insert a PENDING analysis row; False when it already exists."""
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO alert_analyses(alert_id, fingerprint, status, created_at)
                VALUES(?, ?, 'PENDING', ?)
                """,
                (alert_id, fingerprint, _now_iso()),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def claim_next_alert_analysis(
        self, *, max_attempts: int = 3, now_epoch: float | None = None
    ) -> dict[str, Any] | None:
        """Atomically claim one retryable row (oldest first) as PROCESSING.

        FAILED rows are retryable until ``max_attempts`` is exhausted.
        """
        now_epoch = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    """
                    SELECT a.alert_id FROM alert_analyses a
                    WHERE a.status = 'PENDING'
                       OR (a.status = 'FAILED' AND a.attempts < ?)
                    ORDER BY a.alert_id ASC LIMIT 1
                    """,
                    (max_attempts,),
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return None
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        self.start_alert_analysis(row["alert_id"])
        return self.get_alert_analysis(row["alert_id"])

    def get_alert_analysis(self, alert_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alert_analyses WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        return self._alert_analysis_row_to_dict(row) if row else None

    @staticmethod
    def _alert_analysis_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("evidence_json"):
            try:
                d["evidence"] = json.loads(d.pop("evidence_json"))
            except (TypeError, ValueError):
                d.pop("evidence_json", None)
        else:
            d.pop("evidence_json", None)
        return d

    def start_alert_analysis(self, alert_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alert_analyses SET status = 'PROCESSING' WHERE alert_id = ?",
                (alert_id,),
            )
            self._conn.commit()

    def complete_alert_analysis(
        self, alert_id: int, *, analysis: dict[str, Any], model: str, prompt_version: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE alert_analyses SET status = 'COMPLETED',
                       summary = ?, importance = ?, evidence_json = ?,
                       anomaly_likelihood = ?, confidence = ?, recommendation = ?,
                       model = ?, prompt_version = ?, error = NULL,
                       attempts = attempts + 1, analyzed_at = ?
                WHERE alert_id = ?
                """,
                (
                    analysis.get("summary"),
                    analysis.get("importance"),
                    json.dumps(analysis.get("evidence") or [], ensure_ascii=False),
                    analysis.get("anomaly_likelihood"),
                    analysis.get("confidence"),
                    analysis.get("recommendation"),
                    model, prompt_version, _now_iso(), alert_id,
                ),
            )
            self._conn.commit()

    def fail_alert_analysis(self, alert_id: int, *, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE alert_analyses SET status = 'FAILED', error = ?,
                       attempts = attempts + 1, analyzed_at = ?
                WHERE alert_id = ?
                """,
                (error[:500], _now_iso(), alert_id),
            )
            self._conn.commit()

    def reset_alert_analysis(self, alert_id: int) -> bool:
        """Administrator re-analyze: back to PENDING, retry budget restored."""
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE alert_analyses SET status = 'PENDING', error = NULL, attempts = 0
                WHERE alert_id = ?
                """,
                (alert_id,),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def list_alert_analyses(
        self, *, status: str | None = None, limit: int = 300, offset: int = 0
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM alert_analyses {cond}
                ORDER BY alert_id DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [self._alert_analysis_row_to_dict(r) for r in rows]

    def pending_alert_analysis_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM alert_analyses WHERE status IN ('PENDING', 'PROCESSING')"
            ).fetchone()
        return int(row["c"])

    def list_audit(
        self, *, action: str | None = None, limit: int = 100, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        cond, params = "", []
        if action:
            cond = "WHERE action = ?"
            params.append(action)
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM admin_audit {cond}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"SELECT * FROM admin_audit {cond} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if d.get("detail_json"):
                try:
                    d["detail"] = json.loads(d.pop("detail_json"))
                except (TypeError, ValueError):
                    d.pop("detail_json", None)
            out.append(d)
        return out, int(total)

    # =========================================================================
    # Interactive Python console (v3): sessions and commands
    # =========================================================================

    def create_console_session(
        self,
        *,
        session_id: str,
        agent_id: str,
        actor: str,
        ttl_seconds: int,
        idle_timeout_seconds: int,
        policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        expiry_epoch = now_epoch + max(60, int(ttl_seconds))
        expiry_iso = datetime.fromtimestamp(expiry_epoch, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO console_sessions(
                    id, agent_id, actor, created_at, created_epoch, expires_at,
                    expiry_epoch, idle_timeout_seconds, status, policy_json,
                    last_active_at
                ) VALUES(?,?,?,?,?,?,?,?, 'creating', ?, ?)
                """,
                (
                    session_id, agent_id, actor, now, now_epoch, expiry_iso,
                    expiry_epoch, idle_timeout_seconds,
                    json.dumps(policy or {}, ensure_ascii=False, default=str), now,
                ),
            )
            self._conn.commit()
        return self.get_console_session(session_id)  # type: ignore[return-value]

    @staticmethod
    def _console_session_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("policy_json"):
            try:
                d["policy"] = json.loads(d.pop("policy_json"))
            except (TypeError, ValueError):
                d.pop("policy_json", None)
        return d

    def get_console_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM console_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return self._console_session_row_to_dict(row) if row else None

    def list_console_sessions(
        self,
        *,
        agent_id: str | None = None,
        actor: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if agent_id:
            where.append("agent_id = ?")
            params.append(agent_id)
        if actor:
            where.append("actor = ?")
            params.append(actor)
        if status:
            where.append("status = ?")
            params.append(status)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM console_sessions {cond}
                ORDER BY created_epoch DESC LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
        return [self._console_session_row_to_dict(r) for r in rows]

    def update_console_session(
        self, session_id: str, *, status: str | None = None, touch: bool = False
    ) -> None:
        now = _now_iso()
        with self._lock:
            if status is not None:
                self._conn.execute(
                    "UPDATE console_sessions SET status = ?, closed_at = "
                    "CASE WHEN status IN ('terminated','expired','lost') THEN ? ELSE closed_at END "
                    "WHERE id = ?",
                    (status, now, session_id),
                )
            if touch:
                self._conn.execute(
                    "UPDATE console_sessions SET last_active_at = ? WHERE id = ?",
                    (now, session_id),
                )
            self._conn.commit()

    def count_active_console_sessions(
        self, *, actor: str | None = None, agent_id: str | None = None
    ) -> int:
        where = ["status IN ('creating', 'active')"]
        params: list[Any] = []
        if actor:
            where.append("actor = ?")
            params.append(actor)
        if agent_id:
            where.append("agent_id = ?")
            params.append(agent_id)
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM console_sessions WHERE {' AND '.join(where)}",
                params,
            ).fetchone()
        return int(row["c"])

    def sweep_console_sessions(self, now_epoch: float | None = None) -> int:
        """Mark expired (TTL) and idle console sessions. Returns the number closed."""
        now_epoch = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
        closed = 0
        with self._lock:
            cur1 = self._conn.execute(
                """
                UPDATE console_sessions SET status = 'expired',
                       closed_at = COALESCE(closed_at, ?)
                WHERE status IN ('creating', 'active') AND expiry_epoch < ?
                """,
                (_now_iso(), now_epoch),
            )
            closed += max(cur1.rowcount, 0)
            # idle timeout: no activity for longer than the session's configured
            # idle window. Computed in Python (ISO timestamps, timezone offsets).
            rows = self._conn.execute(
                """
                SELECT id, last_active_at, idle_timeout_seconds
                FROM console_sessions
                WHERE status IN ('creating', 'active')
                  AND idle_timeout_seconds IS NOT NULL
                  AND last_active_at IS NOT NULL
                """
            ).fetchall()
            for row in rows:
                try:
                    last = datetime.fromisoformat(str(row["last_active_at"]))
                    idle_s = int(row["idle_timeout_seconds"])
                except (TypeError, ValueError):
                    continue
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if (now_epoch - last.timestamp()) > idle_s:
                    cur2 = self._conn.execute(
                        "UPDATE console_sessions SET status = 'expired', "
                        "closed_at = COALESCE(closed_at, ?) WHERE id = ? AND status IN ('creating', 'active')",
                        (_now_iso(), row["id"]),
                    )
                    closed += max(cur2.rowcount, 0)
            self._conn.commit()
        return closed

    def next_console_seq(self, session_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS m FROM console_commands WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return int(row["m"]) + 1

    def create_console_command(
        self, *, command_id: str, session_id: str, seq: int, code: str
    ) -> dict[str, Any]:
        now = _now_iso()
        now_epoch = datetime.now(timezone.utc).timestamp()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO console_commands(
                    id, session_id, seq, code, status, submitted_at, submitted_epoch
                ) VALUES(?,?,?,?, 'queued', ?, ?)
                """,
                (command_id, session_id, seq, code, now, now_epoch),
            )
            self._conn.commit()
        return self.get_console_command(command_id)  # type: ignore[return-value]

    def get_console_command(self, command_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM console_commands WHERE id = ?", (command_id,)
            ).fetchone()
        return dict(row) if row else None

    def set_console_command_status(self, command_id: str, status: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE console_commands SET status = ? WHERE id = ?", (status, command_id)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def complete_console_command(
        self,
        command_id: str,
        *,
        ok: bool,
        stdout: str,
        stderr: str,
        result_repr: str | None,
        error: str | None,
        duration_ms: float,
        truncated: bool = False,
    ) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE console_commands SET status = ?, finished_at = ?, stdout = ?,
                       stderr = ?, result_repr = ?, error = ?, duration_ms = ?,
                       truncated = ?
                WHERE id = ? AND status IN ('queued', 'dispatched', 'running', 'cancelling')
                """,
                (
                    "completed" if ok else "failed", _now_iso(), stdout, stderr,
                    result_repr, error, duration_ms, int(truncated), command_id,
                ),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def list_console_commands(
        self, session_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM console_commands WHERE session_id = ?
                ORDER BY seq ASC LIMIT ? OFFSET ?
                """,
                (session_id, limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]


def parse_iso_epoch(value: str | None) -> float | None:
    """Parse Suricata-style ISO timestamps into epoch seconds (best effort)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None
