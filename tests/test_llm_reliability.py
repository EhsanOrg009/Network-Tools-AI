import threading
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from openai import APITimeoutError

from netagent.agent.llm_client import LLMClient, LLMBusy, LLMTimeout, LLMStructuredUnsupported
from netagent.services.ai_analysis import AlertAnalysisWorker, ANALYSIS_SCHEMA


def completion(text='ok', tokens=3):
    return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=text))], usage=SimpleNamespace(completion_tokens=tokens))


def test_no_hidden_retry_and_separate_connect_timeout(settings):
    client = LLMClient(settings)
    assert client._client.max_retries == 0
    assert client._client.timeout.connect == settings.llm_connect_timeout_seconds
    assert client._client.timeout.read == settings.llm_timeout_seconds
    client._client.close()


def test_timeout_cooldown_does_not_send_duplicate(settings):
    client = LLMClient(settings)
    create = Mock(side_effect=APITimeoutError(request=httpx.Request('POST', 'http://localhost')))
    client._client.chat.completions.create = create
    with pytest.raises(LLMTimeout): client.chat([])
    with pytest.raises(LLMBusy): client.chat([])
    assert create.call_count == 1
    client._cooldown_until = 0
    create.side_effect = None
    create.return_value = completion()
    assert client.chat([]) == 'ok'


def test_generation_is_serial_and_metadata_is_thread_local(settings):
    client = LLMClient(settings)
    entered, release = threading.Event(), threading.Event()
    def generate(**kwargs):
        entered.set()
        assert release.wait(3)
        return completion(tokens=7)
    client._client.chat.completions.create = Mock(side_effect=generate)
    observed = []
    def first():
        client.chat([])
        observed.append(client.last_usage.completion_tokens)
    thread = threading.Thread(target=first)
    thread.start()
    assert entered.wait(2)
    try:
        with pytest.raises(LLMBusy): client.chat([])
        assert client.last_usage is None
    finally:
        release.set()
        thread.join(3)
    assert observed == [7]
    assert client._client.chat.completions.create.call_count == 1


def test_stream_has_wall_deadline_and_is_closed(settings, monkeypatch):
    settings.llm_timeout_seconds = 1
    client = LLMClient(settings)
    clock = [0.0]
    monkeypatch.setattr('netagent.agent.llm_client.time.monotonic', lambda: clock[0])
    class Stream:
        closed = False
        def __iter__(self):
            clock[0] = 2
            yield SimpleNamespace(choices=[])
        def close(self): self.closed = True
    stream = Stream()
    client._client.chat.completions.create = Mock(return_value=stream)
    with pytest.raises(LLMTimeout): client.chat_stream([])
    assert stream.closed


def test_structured_rejection_does_not_disable_schema(settings, db):
    worker = AlertAnalysisWorker(db, settings, None)
    call = Mock(side_effect=LLMStructuredUnsupported('unsupported'))
    with pytest.raises(LLMStructuredUnsupported):
        worker._chat_with_structured_fallback(call, ANALYSIS_SCHEMA, 'analysis')
    assert call.call_count == 1
    assert call.call_args.args[0]['type'] == 'json_schema'
