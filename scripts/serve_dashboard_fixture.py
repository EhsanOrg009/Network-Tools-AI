"""Isolated browser QA server. All evidence and model responses are synthetic.

Run with uv run python scripts/serve_dashboard_fixture.py. Never uses the
operator's database, credentials, EVE file, or Ollama generation endpoint.
"""
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

state = Path(tempfile.mkdtemp(prefix="netagent-dashboard-qa-"))
# Importing netagent.main also constructs its module-level ASGI app. Use
# an empty private working directory so even that app cannot read .env.
os.chdir(state)
os.environ["DATABASE_PATH"] = str(state / "import.sqlite3")
os.environ["TASK_SIGNING_V2_KEY_PATH"] = str(state / "import-signing.key")

from netagent.main import create_app
from netagent.config import Settings
from netagent.security import hash_secret
from netagent.collectors.suricata import parse_eve_line, store_event
from netagent.services.ai_analysis import AlertAnalysisWorker


class FixtureLLM:
    model = "synthetic-browser-test"

    def connection_status(self):
        return {"ok": True, "detail": "synthetic_fixture"}

    def chat(self, messages, **kwargs):
        return json.dumps({"summary": "تحلیل آزمایشی: تطابق قانون در شواهد این رویداد دیده شد.",
                           "importance": "medium", "evidence": ["دادهٔ ساختگی آزمون مرورگر"],
                           "anomaly_likelihood": "low", "confidence": "medium",
                           "recommendation": "بازبینی زمینهٔ سرویس و ادامهٔ پایش."})


token = secrets.token_urlsafe(32)
settings = Settings(_env_file=None, database_path=state / "fixture.sqlite3",
                    task_signing_v2_key_path=state / "signing.key", admin_api_token=token,
                    suricata_eve_path=state / "eve.json", llm_enabled=False, enable_monitor=False,
                    monitor_cidrs="192.0.2.0/24", llm_model=FixtureLLM.model,
                    ai_analysis_poll_seconds=1, task_signing_allow_legacy=False)
app = create_app(settings, start_monitor=False)
db = app.state.db
now = datetime.now(timezone.utc)
for i in range(1, 126):
    stamp = now - timedelta(minutes=126 - i)
    payload = {"timestamp": stamp.isoformat(), "event_type": "alert", "flow_id": i,
               "src_ip": f"192.0.2.{i % 40 + 1}", "dest_ip": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
               "src_port": 51000 + i, "dest_port": 443, "proto": "TCP", "app_proto": "tls",
               "alert": {"signature": ["ET POLICY Unusual TLS Client Handshake", "ET SCAN Potential Network Scan", "SURICATA TLS Certificate Validation", "DNS Query to Uncommon Domain"][i % 4],
                         "signature_id": 2100000 + i % 4, "severity": i % 4 + 1, "action": "allowed"}}
    raw = json.dumps(payload)
    if i == 1:
        payload["alert"]["signature"] = "QA archived event 100%_rule"
        raw = json.dumps(payload)
    event, error = parse_eve_line(raw)
    assert error is None
    store_event(db, event, raw)

for i, platform in enumerate(["Windows", "Linux", "Linux", "macOS"], 1):
    aid = f"agt_qa_{i}"
    hostname = ["workstation-finance-01", "gateway-observability-01", "very-long-endpoint-hostname-in-network-operations.example.test", "design-station-04"][i - 1]
    db.create_agent(agent_id=aid, token_hash=hash_secret(secrets.token_urlsafe(32)), hostname=hostname,
                    platform=platform, agent_version="qa-fixture", origin="browser-test", heartbeat_interval=30,
                    capabilities=["inventory_collection", "connectivity_diagnostic"])
    db.agent_heartbeat(aid, claimed_ips=[f"192.0.2.{i + 10}"])
    db.store_inventory(aid, {"hostname": hostname, "os_name": platform, "os_version": "test", "arch": "x86_64",
                            "interfaces": [{"name": "eth0", "ipv4": [f"192.0.2.{i + 10}"], "ipv6": [], "mac": "02:00:00:00:00:01", "up": True, "prefixlen": 24}],
                            "routes": [], "dns_servers": ["192.0.2.1"], "services": []})
    db.record_network_observations(aid, [{"interface": "eth0", "cidr": "192.0.2.0/24", "classification": "private", "connected": True}])
    if i == 3:
        with db.transaction():
            db._conn.execute("UPDATE endpoint_agents SET last_heartbeat_epoch=? WHERE id=?", ((now - timedelta(hours=2)).timestamp(), aid))
    db.upsert_host(f"192.0.2.{i + 10}", hostname=hostname)

db.create_enrollment_request(request_id="enr_qa", identity_key_hash=hash_secret(secrets.token_urlsafe(32)),
                             hostname="new-office-endpoint", platform={"os_family": "Windows", "arch": "x86_64"},
                             agent_version="qa", claimed_ips=["192.0.2.90"], mac="02:00:00:00:00:90", gateway="192.0.2.1", ttl_seconds=3600)
db.record_audit(actor="browser-qa", action="qa.fixture_created", target="isolated-test-store")
model = FixtureLLM()
worker = AlertAnalysisWorker(db, settings, model)
app.state.llm = model
app.state.ai_worker = worker
lifespan = app.router.lifespan_context


@asynccontextmanager
async def qa_lifespan(application):
    async with lifespan(application):
        worker.start()
        try:
            yield
        finally:
            assert worker.stop()


app.router.lifespan_context = qa_lifespan

# Fixture-only ingestion endpoint for checking ON/OFF against a running worker.
from fastapi import Depends
from netagent.api.admin_routes import admin_access


@app.post("/__qa__/event", dependencies=[Depends(admin_access)])
def qa_event():
    current = datetime.now(timezone.utc).isoformat()
    raw = json.dumps({"timestamp": current, "event_type": "alert", "flow_id": secrets.randbits(48),
                      "src_ip": "192.0.2.42", "dest_ip": "192.0.2.1", "proto": "TCP",
                      "alert": {"signature": "Synthetic QA event", "signature_id": 2999999,
                                "severity": 2, "action": "allowed"}})
    event, error = parse_eve_line(raw)
    assert not error
    store_event(db, event, raw)
    return {"alert_id": db.query_alerts(limit=1)[0][0]["id"]}

(state / "token").write_text(token)
(state / "token").chmod(0o600)
Path("/tmp/netagent-dashboard-qa-state").write_text(str(state))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
