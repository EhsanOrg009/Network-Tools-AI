"""Dashboard aggregate API (admin-only) + agent enrichment on the SPA shell."""

from __future__ import annotations

from tests.conftest import admin_headers, agent_headers


def test_dashboard_overview_requires_admin_token(full_client):
    assert full_client.get("/api/dashboard/v1/overview").status_code == 401
    assert full_client.get("/api/dashboard/v1/overview",
                           headers=agent_headers("agt_wrong")).status_code in (401,)


def test_dashboard_overview_returns_real_aggregates(full_client):
    r = full_client.get("/api/dashboard/v1/overview", headers=admin_headers())
    assert r.status_code == 200, r.text
    body = r.json()
    # real DB numbers, zero-count consistent with an empty store
    assert body["agents"]["total"] == 0
    assert body["hosts"] == 0
    assert body["trend_7d"] and len(body["trend_7d"]) == 7
    for day in body["trend_7d"]:
        assert set(day) >= {"date", "events", "alerts", "audit"}
    assert body["recent_audit"] == []
    assert body["generated_at"]


def test_dashboard_overview_counts_enrollment_and_agents(full_client):
    import hashlib
    import secrets

    from tests.test_enrollment_request import _announce, _claim

    _, _, key = _announce(full_client)
    admin = admin_headers()
    requests = full_client.get("/api/admin/v1/enrollment-requests", headers=admin).json()
    rid = requests["items"][0]["id"]
    full_client.post(f"/api/admin/v1/enrollment-requests/{rid}/approve", headers=admin)
    claim = _claim(full_client, rid, key)
    agent_id = claim.json()["agent_id"]

    r = full_client.get("/api/dashboard/v1/overview", headers=admin).json()
    # pending went back to zero (it became ENROLLED), one agent is counted
    assert r["agents"]["pending_approval"] == 0
    assert r["agents"]["total"] == 1
    # the issued credential is a real working one (agent plane accepts it)
    hb = full_client.post("/api/agent/v1/heartbeat", json={},
                          headers=agent_headers(claim.json()["agent_token"]))
    assert hb.status_code == 200
    assert agent_id


def test_dashboard_healthz_auth(full_client):
    assert full_client.get("/api/dashboard/v1/healthz").status_code == 401
    r = full_client.get("/api/dashboard/v1/healthz", headers=admin_headers())
    assert r.status_code == 200 and r.json()["ok"] is True


def test_swagger_and_dashboard_are_separate_surfaces(full_client):
    """/api/docs and /openapi.json remain the only documentation surface and
    the dashboard mount doesn't shadow the API."""
    r = full_client.get("/openapi.json")
    assert r.status_code == 200 and "openapi" in r.json()
    # dashboard SPA only mounts when the build exists; API routes stay collide-free
    r2 = full_client.get("/api/dashboard/v1/overview")
    assert r2.status_code == 401  # API auth is intact regardless of the mount


def test_dashboard_spa_serving(full_client):
    """When the Vite build exists, /dashboard serves the shell, deep SPA
    routes fall back to index.html, and missing assets still 404."""
    from pathlib import Path

    dist = Path(__file__).resolve().parents[1] / "dashboard" / "dist"
    r = full_client.get("/dashboard/agents/whatever")
    if dist.is_dir():
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert b'id="root"' in r.content
        assert full_client.get("/dashboard/assets/missing-file.js").status_code == 404
    else:
        assert r.status_code in (404, 200)  # mount absent in dev machines without build
    # swagger untouched either way
    docs = full_client.get("/api/docs")
    assert docs.status_code == 200 and "swagger" in docs.text.lower()


def test_dashboard_resource_settings_are_visible_without_credentials(full_client):
    data = full_client.get("/api/dashboard/v1/settings", headers=admin_headers()).json()
    assert data["ai_analysis_intake_limit"] == 1000
    assert data["ai_analysis_batch_size"] == 1
    assert data["llm_structured_outputs"] is True
    assert "console_session_ttl_seconds" in data
    assert not any("token" in key and key != "llm_max_output_tokens" or "signing" in key or "api_key" in key for key in data)


def test_overview_counts_all_hosts_agents_and_investigations(full_client, db):
    import time

    # Exceed both former list limits. Aggregate counts must cover the store,
    # including a stale and revoked endpoint outside the first page.
    with db.transaction():
        for n in range(503):
            db.create_agent(agent_id=f"overview-{n}", token_hash=f"overview-token-{n}",
                            hostname=f"host-{n}", platform="Linux", agent_version="test",
                            origin="test", heartbeat_interval=30, capabilities=[])
        db._conn.execute("UPDATE endpoint_agents SET last_heartbeat_epoch=? WHERE id=?",
                         (time.time() - 86400, "overview-501"))
        db.revoke_agent("overview-502")
        for n in range(3):
            db.upsert_host(f"192.0.2.{n + 1}")
        db._conn.executemany(
            "INSERT INTO investigations(created_at,trigger,status) VALUES(?,?,?)",
            [("2026-11-12T00:00:00Z", "test", "running" if n == 0 else "completed")
             for n in range(205)],
        )
    data = full_client.get("/api/dashboard/v1/overview", headers=admin_headers()).json()
    assert data["hosts"] == 3
    assert {k: data["agents"][k] for k in ("total", "active", "stale", "revoked")} == {
        "total": 503, "active": 501, "stale": 1, "revoked": 1,
    }
    assert data["investigations"] == {"total": 205, "running": 1, "completed": 204}


def test_daily_trend_counts_events_and_alerts_under_the_api_series_names(full_client, db):
    from datetime import datetime, timezone
    from tests.test_security_ai_controls import ingest
    alert = ingest(db)
    stamp = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp() + 1
    with db.transaction():
        db._conn.execute("UPDATE alerts SET ts_epoch=? WHERE id=?", (stamp, alert))
        db._conn.execute("UPDATE events SET ts_epoch=?", (stamp,))
    data = full_client.get("/api/dashboard/v1/overview", headers=admin_headers()).json()
    today = data["trend_7d"][-1]
    assert today["events"] == 1 and today["alerts"] == 1
    assert set(today) == {"date", "events", "alerts", "audit"}
