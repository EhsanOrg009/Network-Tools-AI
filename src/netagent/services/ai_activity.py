"""Observable trace of every real LLM activity (AI Activity Monitor).

Goal: the operator must be able to see *exactly* what the local model is
doing — when a request was created, when it reached Msty, whether the model
produced a first token, which tools ran, and how long everything took.

Design rules:
- **No synthetic stages.** The timeline contains only milestones that really
  happened; a stage that never occurred is never displayed or pre-filled.
- No raw chain-of-thought is stored or shown. The trace stores the *request
  context summary*, tool calls, an outcome summary and timings — genuine
  observability, not private-reasoning exposure.
- Storage is bounded (oldest rows pruned) so the database cannot grow forever.
- Tracing is best-effort: a failure inside the tracer must never break the
  analysis task it observes.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from netagent.agent.llm_client import LLMClient, LLMStreamEmpty, LLMTruncated
from netagent.database import Database

log = logging.getLogger("netagent.ai_activity")

# Bounded context digest stored per request (chars) — enough to see *what*
# was analyzed, never the full untrusted evidence blob.
_MAX_CONTEXT_CHARS = 600


class ActivityTrace:
    """Lifecycle handle for one LLM-backed task. State lives in the Database
    (so it survives restarts); the handle itself only holds IDs."""

    def __init__(self, db: Database, *, task_type: str, model: str | None,
                 refs: list[dict[str, Any]] | None = None,
                 prompt_version: str | None = None,
                 context_summary: str | None = None):
        self.db = db
        try:
            self.request_id = db.create_ai_activity(
                request_id=f"act_{uuid.uuid4().hex[:24]}",
                task_type=task_type, refs=refs, model=model,
                prompt_version=prompt_version,
                context_summary=context_summary[:_MAX_CONTEXT_CHARS]
                if context_summary else None,
            )
        except Exception:  # tracing must never break the task itself
            log.exception("failed to create an activity trace")
            self.request_id = ""

    def mark(self, stage: str, **kwargs: Any) -> None:
        """Append a *real* milestone to the timeline (fails silently)."""
        if not self.request_id:
            return
        try:
            self.db.stage_ai_activity(self.request_id, stage, **kwargs)
        except Exception:  # pragma: no cover - observability must not hurt
            log.exception("failed to record activity stage")

    def sent(self, *, provider: str | None = None, model: str | None = None) -> None:
        """Recorded immediately before the request is handed over."""
        self.mark("SENT_TO_LLM", provider=provider, model=model)

    def stream_finished(
        self, *, finish_reason: str | None = None,
        prompt_tokens: int | None = None, completion_tokens: int | None = None,
    ) -> None:
        """Real stream termination info (finish_reason / token usage) as
        provided by the provider; never synthesized."""
        self.mark(
            "STREAM_FINISHED",
            finish_reason=finish_reason,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def first_token(self, first_token_ms: float, streaming: bool) -> None:
        self.mark(
            "FIRST_TOKEN_RECEIVED",
            first_token_ms=round(first_token_ms, 1), streaming=streaming,
        )

    def complete(self, *, outcome_summary: str | None = None) -> None:
        if not self.request_id:
            return
        try:
            self.db.finish_ai_activity(
                self.request_id, outcome_summary=outcome_summary,
                status="COMPLETED",
            )
        except Exception:  # pragma: no cover
            log.exception("failed to close an activity trace")

    def fail(self, error: str, *, timeout: bool = False) -> None:
        if not self.request_id:
            return
        try:
            self.db.finish_ai_activity(
                self.request_id, error=error,
                status="TIMEOUT" if timeout else "FAILED",
            )
        except Exception:  # pragma: no cover
            log.exception("failed to close an activity trace")

    @staticmethod
    def context_digest(payload: Any, max_chars: int = _MAX_CONTEXT_CHARS) -> str:
        try:
            blob = json.dumps(payload, ensure_ascii=False, default=str, sort_keys=True)
        except (TypeError, ValueError):
            blob = str(payload)
        return blob[:max_chars]


def traced_chat(
    llm: Any,
    messages: list[dict[str, str]],
    *,
    trace: ActivityTrace | None = None,
    max_tokens: int | None = None,
    response_format: dict | None = None,
) -> str:
    """Chat call used by background workers and the orchestrator.

    - ``LLMClient`` + trace → streaming path (real first-token milestone when
      the model actually produces content; falls back to the plain call when
      a model emits nothing over the stream, e.g. reasoning-only models).
    - ``LLMClient`` without trace → plain non-streaming call (unchanged).
    - Any user-provided client (tests/fakes) → call its ``chat`` directly.
    ``response_format`` (Structured Outputs) is passed through to LLMClient
    and ignored by plain fakes.
    """
    if trace is None:
        if isinstance(llm, LLMClient):
            return llm.chat(messages, max_tokens=max_tokens,
                            response_format=response_format)
        return llm.chat(messages)

    trace.sent(provider=_provider(llm), model=_model_name(llm))
    started = time.monotonic()
    first_token_logged = False
    finish_captured: dict = {}

    def _hook() -> None:
        nonlocal first_token_logged
        if not first_token_logged:
            first_token_logged = True
            trace.first_token((time.monotonic() - started) * 1000.0, streaming=True)

    if isinstance(llm, LLMClient):
        try:
            text = llm.chat_stream(
                messages, max_tokens=max_tokens, first_token_cb=_hook,
                response_format=response_format,
            )
        except LLMStreamEmpty:
            log.info("model produced no stream content; falling back")
        except LLMTruncated:
            # the *real* termination signal still belongs in the trace even
            # though the answer cannot be used
            _record_stream_meta(llm, trace)
            raise
        else:
            finish_captured = {
                "finish_reason": llm.last_finish_reason,
                "prompt_tokens": _token_count(llm.last_usage, "prompt_tokens"),
                "completion_tokens": _token_count(llm.last_usage, "completion_tokens"),
            }
            trace.stream_finished(**finish_captured)
            trace.mark("RESPONSE_RECEIVED")
            return text
        try:
            text = llm.chat(messages, max_tokens=max_tokens, response_format=response_format)
            _record_stream_meta(llm, trace)
        except LLMTruncated:
            _record_stream_meta(llm, trace)
            raise
    else:
        text = llm.chat(messages)
    trace.mark("RESPONSE_RECEIVED")
    return text


def _record_stream_meta(llm: Any, trace: ActivityTrace) -> None:
    """Store the provider's real termination info (finish_reason/usage) once."""
    trace.stream_finished(
        finish_reason=getattr(llm, "last_finish_reason", None),
        prompt_tokens=_token_count(getattr(llm, "last_usage", None), "prompt_tokens"),
        completion_tokens=_token_count(getattr(llm, "last_usage", None), "completion_tokens"),
    )


def _provider(llm: Any) -> str | None:
    provider = getattr(getattr(llm, "settings", None), "llm_provider", None)
    return str(provider) if provider else None


def _model_name(llm: Any) -> str | None:
    model = getattr(llm, "model", None)
    return str(model) if model else None


def _token_count(usage: Any, field: str) -> int | None:
    value = getattr(usage, field, None) if usage is not None else None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
