"""Thin wrapper around the OpenAI-compatible local LLM (Msty Studio).

- Base URL / API key / model come from configuration only.
- Bounded timeouts, input sizes, and output tokens.
- Distinguishes timeouts / unavailability from context-length failures so the
  orchestrator can trim evidence and retry.
"""

from __future__ import annotations

import json
import re

from openai import APIConnectionError, APITimeoutError, OpenAI

from netagent.config import Settings


class LLMUnavailable(RuntimeError):
    """The LLM endpoint is unreachable or timed out."""


class LLMContextTooLong(RuntimeError):
    """The prompt exceeded the model context; caller should trim and retry."""


class LLMStreamEmpty(RuntimeError):
    """The stream completed without any content delta (e.g. a reasoning-only
    model emitting nothing in ``delta.content``); callers may fall back to the
    non-streaming call."""


_CONTEXT_MARKERS = (
    "context length",
    "maximum context",
    "context_length_exceeded",
    "reduce the length",
    "too many tokens",
    "input length exceeds",
)


class LLMClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._client = OpenAI(
            base_url=settings.msty_base_url,
            api_key=settings.msty_api_key,
            timeout=settings.llm_timeout_seconds,
            max_retries=1,
        )
        self.model = settings.msty_model

    @property
    def settings(self) -> Settings:
        return self._settings

    def chat(self, messages: list[dict[str, str]], max_tokens: int | None = None) -> str:
        """Send a chat completion and return assistant text content.

        Raises LLMUnavailable on connection/timeout problems and
        LLMContextTooLong when the prompt does not fit the context window.
        """
        s = self._settings
        try:
            response = self._client.chat.completions.create(
                model=s.msty_model,
                messages=messages,
                temperature=s.llm_temperature,
                max_tokens=max_tokens or s.llm_max_output_tokens,
                stream=False,
            )
        except (APITimeoutError, APIConnectionError) as exc:
            raise LLMUnavailable(f"LLM request failed: {exc.__class__.__name__}") from exc
        except Exception as exc:  # openai raises several internals types
            message = str(exc).lower()
            if any(marker in message for marker in _CONTEXT_MARKERS):
                raise LLMContextTooLong(str(exc)[:300]) from exc
            raise LLMUnavailable(f"LLM error: {exc.__class__.__name__}: {str(exc)[:200]}") from exc

        try:
            message = response.choices[0].message
            content = message.content
        except (AttributeError, IndexError) as exc:
            raise LLMUnavailable("LLM returned an unexpected response shape") from exc
        if not content:
            # Some local reasoning models (e.g. Gemma via Msty) emit their
            # visible answer in a separate "reasoning" field; use it as a
            # bounded fallback so JSON extraction still works.
            reasoning = getattr(message, "reasoning", None) or getattr(
                message, "reasoning_content", None
            )
            if reasoning and isinstance(reasoning, str):
                content = reasoning[-(s.llm_max_input_chars // 2):]
        if not content:
            raise LLMUnavailable("LLM returned an empty response")
        return content

    # -- streaming ------------------------------------------------------------

    def chat_stream(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        *,
        first_token_cb=None,
    ) -> str:
        """Chat completion with real streaming; the full text is returned so
        callers keep the same contract as :meth:`chat`, but timing milestones
        become observable (first token, in-flight generation).

        ``first_token_cb`` is invoked exactly once, when the first *actual
        content* delta arrives. Raises :class:`LLMStreamEmpty` when the stream
        finished without any content delta, so callers can fall back to the
        plain non-streaming path (e.g. reasoning-only models).
        """
        s = self._settings
        try:
            stream = self._client.chat.completions.create(
                model=s.msty_model,
                messages=messages,
                temperature=s.llm_temperature,
                max_tokens=max_tokens or s.llm_max_output_tokens,
                stream=True,
            )
        except (APITimeoutError, APIConnectionError) as exc:
            raise LLMUnavailable(f"LLM request failed: {exc.__class__.__name__}") from exc
        except Exception as exc:
            message = str(exc).lower()
            if any(marker in message for marker in _CONTEXT_MARKERS):
                raise LLMContextTooLong(str(exc)[:300]) from exc
            raise LLMUnavailable(f"LLM error: {exc.__class__.__name__}: {str(exc)[:200]}") from exc

        parts: list[str] = []
        first_token_logged = False
        try:
            for chunk in stream:
                choices = getattr(chunk, "choices", None)
                if not choices:
                    continue
                delta = getattr(choices[0], "delta", None)
                content = getattr(delta, "content", None)
                if isinstance(content, str) and content:
                    if first_token_cb is not None and not first_token_logged:
                        first_token_logged = True
                        first_token_cb()
                    parts.append(content)
        except (APITimeoutError, APIConnectionError) as exc:
            raise LLMUnavailable(f"LLM stream failed: {exc.__class__.__name__}") from exc

        text = "".join(parts)
        if not text.strip():
            raise LLMStreamEmpty("stream completed without content deltas")
        return text

    # -- JSON extraction ------------------------------------------------------

    @staticmethod
    def extract_json(text: str) -> dict | None:
        """Best-effort extraction of the first JSON object from model output.

        Local models often wrap JSON in prose or code fences; this tolerates
        that without ever executing model output.
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
