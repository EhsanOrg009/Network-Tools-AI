"""Real integration tests against a live Ollama server.

These exercise the actual provider contract (v1 API on 127.0.0.1:11434):
a plain completion, the structured-outputs schema, and truncation
classification — with the real local model, not fakes. They are skipped
automatically whenever the server is not reachable, so the regular test
suite stays hermetic and fast on machines without Ollama.

Run explicitly with:
    NETAGENT_OLLAMA_IT=1 uv run pytest tests/test_ollama_integration.py -v

Both gates must open: the server must be reachable AND the module opted in
via NETAGENT_OLLAMA_IT=1, so the default suite stays hermetic and fast.
"""

from __future__ import annotations

import os
import urllib.request
import urllib.error

import pytest

from netagent.agent.llm_client import LLMClient, LLMTruncated, LLMUnavailable
from netagent.config import Settings

OLLAMA_URL = "http://127.0.0.1:11434/v1"


def _ollama_up() -> bool:
    try:
        with urllib.request.urlopen(
            f"{OLLAMA_URL}/models", timeout=2
        ) as resp:  # nosec - local fixed URL
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


requires_ollama = pytest.mark.skipif(
    not _ollama_up(),
    reason="live Ollama not reachable on 127.0.0.1:11434",
)
requires_ollama_opt_in = pytest.mark.skipif(
    os.getenv("NETAGENT_OLLAMA_IT") != "1",
    reason="opt into real-local-model tests with NETAGENT_OLLAMA_IT=1",
)


@requires_ollama
@requires_ollama_opt_in
def test_real_chat_completes_with_stop():
    # gemma4-local is a thinking model: its reasoning precedes the visible
    # answer, so the budget must cover both (a tiny budget is truncation,
    # tested separately below).
    s = Settings(llm_timeout_seconds=180, llm_max_output_tokens=512,
                 enable_monitor=False)
    c = LLMClient(s)
    text = c.chat([{"role": "user", "content": "فقط یک کلمه پاسخ بده: سلام"}])
    assert isinstance(text, str) and text.strip()
    assert c.last_finish_reason == "stop"


@requires_ollama
@requires_ollama_opt_in
def test_real_structured_outputs_accepted():
    """response_format=json_schema is accepted by Ollama (never misclassified
    as unsupported) and the answer stays inside the schema's legal values.
    The schema follows the OpenAI wire format, as the worker sends it."""
    import json

    from netagent.services.ai_analysis import ANALYSIS_SCHEMA

    s = Settings(llm_timeout_seconds=300, llm_max_output_tokens=900,
                 enable_monitor=False)
    c = LLMClient(s)
    response_format = {
        "type": "json_schema", "json_schema": {
            "name": "alert_analysis", "strict": True, "schema": ANALYSIS_SCHEMA,
        }
    }
    text = c.chat(
        [
            {"role": "system", "content": "تو یک تحلیل‌گر هشدار شبکه هستی."},
            {"role": "user", "content": "خلاصه یک‌جمله‌ای برای یک هشدار DNS معمولی بنویس."},
        ],
        response_format=response_format,
    )
    data = json.loads(text)  # valid JSON inside the enforced schema
    assert data["importance"] in {"low", "medium", "high"}
    assert data["anomaly_likelihood"] in {"low", "medium", "high", "unknown"}
    assert c.last_finish_reason == "stop"


@requires_ollama
@requires_ollama_opt_in
def test_real_truncation_is_classified_not_completed():
    s = Settings(llm_timeout_seconds=180, llm_max_output_tokens=12,
                 enable_monitor=False)
    c = LLMClient(s)
    with pytest.raises(LLMTruncated):
        c.chat([{"role": "user", "content": "فهرست بلندی از IPها برگردان"}])
    assert c.last_finish_reason == "length"


@pytest.mark.skipif(
    not _ollama_up(), reason="live Ollama not reachable",
)
def test_real_offline_endpoint_is_unavailable():
    """A dead port yields a clean LLMUnavailable, never a raw openai error.
    (No opt-in needed: it never contacts the model.)"""
    s = Settings(llm_base_url="http://127.0.0.1:9/v1", llm_timeout_seconds=5,
                 enable_monitor=False)
    c = LLMClient(s)
    with pytest.raises(LLMUnavailable):
        c.chat([{"role": "user", "content": "سلام"}])


@requires_ollama
@requires_ollama_opt_in
def test_real_manual_security_analysis_persists_only_selected_event(db, settings):
    from netagent.services.ai_analysis import AlertAnalysisWorker
    from tests.test_security_ai_controls import ingest, request

    # Only fixture data enters this live test; the operator's database and
    # enrollment credentials are never read or sent to the model.
    settings.llm_base_url = OLLAMA_URL
    settings.llm_model = "gemma-4-e4b:latest"
    settings.llm_timeout_seconds = 600
    settings.llm_max_output_tokens = 4096
    settings.ai_analysis_batch_size = 3
    first, other = ingest(db, 1), ingest(db, 2)
    job = request(db, first)
    client = LLMClient(settings)
    try:
        worker = AlertAnalysisWorker(db, settings, client)
        assert worker.process_one()
        row = db.get_alert_analysis(first)
        assert row["status"] == "COMPLETED", row.get("error")
        assert row["job_id"] == job["job_id"] and row["summary"]
        assert client.last_finish_reason == "stop"
        assert db.get_alert_analysis(other) is None
        assert not db.security_ai_auto_enabled()
        assert request(db, first)["job_id"] == job["job_id"]
        assert not worker.process_one()
    finally:
        client._client.close()
