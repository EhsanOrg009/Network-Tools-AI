"""Thin wrapper around the OpenAI-compatible local LLM (Ollama / Msty).

- Base URL / API key / model come from configuration only (MSTY_* env names
  remain accepted as aliases, so Msty setups keep working unchanged).
- Bounded timeouts, input sizes, and output tokens.
- Distinguishes timeouts / unavailability from context-length failures so the
  orchestrator can trim evidence and retry, and *detects truncated output*
  (finish_reason=length) instead of presenting a cut-off answer as complete.
- Structured Outputs (``response_format`` json_schema) are available to
  callers via ``response_format=...``; unsupported providers are classified
  with :class:`LLMStructuredUnsupported` so callers can fall back safely.
"""

from __future__ import annotations

import json
import re
import threading
import time
from functools import wraps

import httpx

from openai import APIConnectionError, APITimeoutError, OpenAI

from netagent.config import Settings


class LLMUnavailable(RuntimeError):
    """The LLM endpoint is unreachable, timed out, or answered unusably."""


class LLMTimeout(LLMUnavailable):
    """Generation timed out; the server may still be finishing it."""


class LLMBusy(LLMUnavailable):
    """No request was sent: another generation or timeout cooldown is active."""


def _serialized(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        self._ensure_runtime()
        if not self._generation_lock.acquire(blocking=False):
            raise LLMBusy("model generation already in progress")
        try:
            if time.monotonic() < self._cooldown_until:
                raise LLMBusy("model is cooling down after a timed-out request")
            return method(self, *args, **kwargs)
        except LLMTimeout:
            self._cooldown_until = time.monotonic() + self.settings.llm_timeout_cooldown_seconds
            raise
        finally:
            self._generation_lock.release()
    return run


class LLMContextTooLong(RuntimeError):
    """The prompt exceeded the model context; caller should trim and retry."""


class LLMStreamEmpty(RuntimeError):
    """The stream completed without any content delta (e.g. a reasoning-only
    model emitting nothing in ``delta.content``); callers may fall back to the
    non-streaming call."""


class LLMTruncated(LLMUnavailable):
    """Output was cut off by the token limit (finish_reason=length).

    A truncated response is NOT a complete answer: callers must not persist
    it as a successful analysis.
    """


class LLMStructuredUnsupported(LLMUnavailable):
    """The provider rejected response_format; security analysis fails closed
    rather than disabling its schema constraints."""


_CONTEXT_MARKERS = (
    "context length",
    "maximum context",
    "context_length_exceeded",
    "reduce the length",
    "too many tokens",
    "input length exceeds",
)

_STRUCTURED_MARKERS = (
    "response_format",
    "json_schema",
    "structured",
    "not supported",
    "invalid option",
)


def _classify_provider_error(exc: Exception) -> RuntimeError:
    message = str(exc).lower()
    if any(marker in message for marker in _CONTEXT_MARKERS):
        return LLMContextTooLong(str(exc)[:300])
    if "response_format" in message or "json_schema" in message or (
        "structured" in message and "not supported" in message
    ):
        return LLMStructuredUnsupported(
            f"structured output unsupported: {str(exc)[:250]}"
        )
    if "connection" in message or "timeout" in message or "timed out" in message:
        return LLMUnavailable(f"LLM request failed: {exc.__class__.__name__}")
    return LLMUnavailable(
        f"LLM error: {exc.__class__.__name__}: {str(exc)[:200]}"
    )


class LLMClient:
    _runtime_init_lock = threading.Lock()

    def _ensure_runtime(self):
        with self._runtime_init_lock:
            if not hasattr(self, "_metadata"):
                self._metadata = threading.local()
                self._generation_lock = threading.Lock()
                self._cooldown_until = 0.0

    @property
    def last_finish_reason(self):
        self._ensure_runtime()
        return getattr(self._metadata, "finish_reason", None)

    @last_finish_reason.setter
    def last_finish_reason(self, value):
        self._ensure_runtime()
        self._metadata.finish_reason = value

    @property
    def last_usage(self):
        self._ensure_runtime()
        return getattr(self._metadata, "usage", None)

    @last_usage.setter
    def last_usage(self, value):
        self._ensure_runtime()
        self._metadata.usage = value

    def _request_timeout(self):
        from netagent.services.job_control import bounded_timeout
        return httpx.Timeout(bounded_timeout(self.settings.llm_timeout_seconds),
                             connect=bounded_timeout(self.settings.llm_connect_timeout_seconds))

    def connection_status(self) -> dict:
        """Read the provider model list without starting a generation."""
        try:
            models = self._client.with_options(timeout=self.settings.llm_connect_timeout_seconds).models.list()
            present = any(item.id == self.model for item in models.data)
            return {"ok": present, "detail": "ready" if present else "model_not_found"}
        except Exception as exc:
            return {"ok": False, "detail": type(exc).__name__}

    def __init__(self, settings: Settings):
        self._settings = settings
        self._client = OpenAI(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            timeout=self._request_timeout(),
            max_retries=0,
        )
        self.model = settings.llm_model
        # observability of the *last* real completion (single-writer worker);
        # read right after a call — e.g. by traced_chat → Activity Monitor.
        self.last_finish_reason: str | None = None
        self.last_usage: object | None = None

    @property
    def settings(self) -> Settings:
        return self._settings

    def close(self) -> None:
        self._client.close()

    @_serialized
    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        *,
        response_format: dict | None = None,
    ) -> str:
        """Send a chat completion and return assistant text content.

        Raises LLMUnavailable on connection/timeout problems,
        LLMContextTooLong when the prompt does not fit the context window,
        and :class:`LLMTruncated` when the answer was cut off by the token
        limit (never a complete answer).
        """
        s = self._settings
        self.last_finish_reason = None
        self.last_usage = None
        try:
            kwargs: dict = dict(
                model=s.llm_model,
                messages=messages,
                temperature=s.llm_temperature,
                max_tokens=max_tokens or s.llm_max_output_tokens,
                stream=False,
            )
            kwargs["timeout"] = self._request_timeout()
            if response_format is not None:
                kwargs["response_format"] = response_format
            response = self._client.chat.completions.create(**kwargs)
        except APITimeoutError as exc:
            raise LLMTimeout("LLM request failed: APITimeoutError") from exc
        except APIConnectionError as exc:
            raise LLMUnavailable(f"LLM request failed: {exc.__class__.__name__}") from exc
        except Exception as exc:  # openai raises several internals types
            raise _classify_provider_error(exc) from exc

        self._record_completion_meta(response)
        finish = self.last_finish_reason
        try:
            message = response.choices[0].message
            content = message.content
        except (AttributeError, IndexError) as exc:
            raise LLMUnavailable("LLM returned an unexpected response shape") from exc
        if not content:
            # Some local reasoning models emit their visible answer in a
            # separate "reasoning" field; use it as a bounded fallback so
            # JSON extraction still works for models that stopped normally.
            reasoning = getattr(message, "reasoning", None) or getattr(
                message, "reasoning_content", None
            )
            if reasoning and isinstance(reasoning, str) and finish != "length":
                content = reasoning[-(s.llm_max_input_chars // 2):]
        if finish == "length":
            raise LLMTruncated(
                "output truncated by the token limit (finish_reason=length)"
            )
        if finish is None:
            raise LLMUnavailable("LLM response has no finish signal")
        if not content:
            raise LLMUnavailable("LLM returned an empty response")
        return content

    # -- streaming ------------------------------------------------------------

    @_serialized
    def chat_stream(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        *,
        first_token_cb=None,
        response_format: dict | None = None,
    ) -> str:
        """Chat completion with real streaming; the full text is returned so
        callers keep the same contract as :meth:`chat`, but timing milestones
        become observable (first token, in-flight generation; finish reason
        and token usage recorded on ``self`` afterwards).

        ``first_token_cb`` is invoked exactly once, when the first *actual
        content* delta arrives. Raises :class:`LLMStreamEmpty` when the stream
        finished without any content delta, :class:`LLMTruncated` when the
        provider stopped for the token limit, and :class:`LLMUnavailable`
        when the stream ended without a terminate signal (disconnect).
        """
        s = self._settings
        self.last_finish_reason = None
        self.last_usage = None
        try:
            kwargs: dict = dict(
                model=s.llm_model,
                messages=messages,
                temperature=s.llm_temperature,
                max_tokens=max_tokens or s.llm_max_output_tokens,
                stream=True,
                stream_options={"include_usage": True},
            )
            from netagent.services.job_control import bounded_timeout, checkpoint
            deadline = time.monotonic() + bounded_timeout(s.llm_timeout_seconds)
            kwargs["timeout"] = self._request_timeout()
            if response_format is not None:
                kwargs["response_format"] = response_format
            stream = self._client.chat.completions.create(**kwargs)
        except APITimeoutError as exc:
            raise LLMTimeout("LLM request failed: APITimeoutError") from exc
        except APIConnectionError as exc:
            raise LLMUnavailable(f"LLM request failed: {exc.__class__.__name__}") from exc
        except Exception as exc:
            raise _classify_provider_error(exc) from exc

        parts: list[str] = []
        first_token_logged = False
        finish: str | None = None
        usage: object | None = None
        try:
            for chunk in stream:
                if time.monotonic() >= deadline:
                    raise LLMTimeout("LLM stream exceeded generation deadline")
                checkpoint()
                chunk_usage = getattr(chunk, "usage", None)
                if chunk_usage is not None:
                    usage = chunk_usage
                choices = getattr(chunk, "choices", None)
                if not choices:
                    continue
                choice = choices[0]
                chunk_finish = getattr(choice, "finish_reason", None)
                if chunk_finish:
                    finish = chunk_finish
                delta = getattr(choice, "delta", None)
                content = getattr(delta, "content", None)
                if isinstance(content, str) and content:
                    if first_token_cb is not None and not first_token_logged:
                        first_token_logged = True
                        first_token_cb()
                    parts.append(content)
        except (APITimeoutError, httpx.TimeoutException) as exc:
            # The SDK wraps errors opening a stream, but HTTPX can raise
            # directly while consuming it. Apply the same retry quarantine.
            raise LLMTimeout(f"LLM stream failed: {type(exc).__name__}") from exc
        except APIConnectionError as exc:
            raise LLMUnavailable(f"LLM stream failed: {exc.__class__.__name__}") from exc
        finally:
            close = getattr(stream, "close", None)
            if close is not None:
                close()

        self.last_finish_reason = finish
        self.last_usage = usage
        text = "".join(parts)
        if finish == "length":
            raise LLMTruncated(
                "output truncated by the token limit (finish_reason=length)"
            )
        if finish is None:
            # the stream ended without a terminate chunk: a disconnect, not a
            # complete answer — never return a half-received JSON as success
            raise LLMUnavailable("LLM stream ended without a finish signal")
        if not text.strip():
            raise LLMStreamEmpty("stream completed without content deltas")
        return text

    def _record_completion_meta(self, response: object) -> None:
        try:
            self.last_finish_reason = response.choices[0].finish_reason  # type: ignore[attr-defined]
            self.last_usage = getattr(response, "usage", None)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            self.last_finish_reason = None
            self.last_usage = None

    # -- JSON extraction ------------------------------------------------------

    @staticmethod
    def extract_complete_json(text: str) -> dict | None:
        """Decode an intact object for analysis; never repair incomplete JSON."""
        start = text.find("{")
        if start < 0:
            return None
        try:
            value, _ = json.JSONDecoder().raw_decode(text[start:])
        except (ValueError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def extract_json(text: str) -> dict | None:
        """Best-effort extraction of the first JSON object from model output.

        Local models often wrap JSON in prose or code fences; this tolerates
        that without ever executing model output.

        Repair of *truncated* output is limited to the legacy orchestrator
        path; the analysis pipeline detects truncation upstream
        (:class:`LLMTruncated`) and never stores a repaired JSON as a
        complete analysis.
        """
        if not text:
            return None
        text = text.strip()
        # strip code fences
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        start = text.find("{")
        if start == -1:
            return None
        # balanced-brace scan (ignoring braces inside strings)
        depth = 0
        in_str = False
        escape = False
        stack: list[str] = []
        string_start = start
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                string_start = i
            elif ch == "{":
                depth += 1
                stack.append("}")
            elif ch == "[":
                stack.append("]")
            elif ch == "]":
                if stack and stack[-1] == "]":
                    stack.pop()
            elif ch == "}":
                depth -= 1
                if stack and stack[-1] == "}":
                    stack.pop()
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        parsed = json.loads(candidate)
                    except (json.JSONDecodeError, ValueError):
                        return None
                    return parsed if isinstance(parsed, dict) else None
        # Unbalanced (typically truncated by max_tokens): attempt a safe
        # repair — drop a dangling partial string / "key": prefix and any
        # trailing comma, then close open containers in reverse order.
        # Missing keys are filled by schema defaults.
        body = text[start:]
        if in_str:
            body = body[:string_start]
        body = body.rstrip()
        # Drop a dangling "key": (its value was cut off).
        while body.endswith(":"):
            body = body[:-1].rstrip()
            if body.endswith('"'):
                j = len(body) - 2
                while j >= 0:
                    if body[j] == '"' and body[j - 1: j] != "\\":
                        # skip escaped quotes
                        backslashes = 0
                        k = j - 1
                        while k >= 0 and body[k] == "\\":
                            backslashes += 1
                            k -= 1
                        if backslashes % 2 == 0:
                            break
                    j -= 1
                if j >= 0:
                    body = body[:j]
            body = body.rstrip().rstrip(",").rstrip()
        body = body.rstrip().rstrip(",")
        body += "".join(reversed(stack))
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None
