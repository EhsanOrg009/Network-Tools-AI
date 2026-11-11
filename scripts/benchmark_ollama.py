"""بنچمارک محلی با شواهد ساختگی؛ هیچ دادهٔ واقعی شبکه ارسال نمی‌شود."""
import argparse
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from netagent.schemas import AlertAnalysis
from netagent.services.ai_analysis import ANALYSIS_SCHEMA, BATCH_SCHEMA, build_analysis_messages, build_batch_analysis_messages

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--case', required=True)
p.add_argument('--api', choices=['native', 'openai'], default='native')
p.add_argument('--context', type=int, default=4096)
p.add_argument('--batch', type=int, default=1)
p.add_argument('--budget', type=int, default=4096)
p.add_argument('--timeout', type=float, default=600)
p.add_argument('--think', choices=['default', 'false'], default='default')
p.add_argument('--large', action='store_true')
p.add_argument('--long', action='store_true')
p.add_argument('--input-chars', type=int, default=0)
p.add_argument('--output', default='docs/benchmarks/ollama-runtime.jsonl')
a = p.parse_args()
base = 'http://127.0.0.1:11434'
model = 'gemma-4-e4b:latest'
alerts = [dict(id=i + 1, src_ip='192.0.2.10', dest_ip='192.0.2.53', src_port=53000+i, dest_port=53, proto='UDP', app_proto='dns', severity=3, signature_id=123, signature='Synthetic DNS policy alert' + (' unknown-domain.example' * 150 if a.large else ''), category='Potential policy violation', action='allowed') for i in range(a.batch)]
messages = build_analysis_messages(alerts[0]) if a.batch == 1 else build_batch_analysis_messages(alerts)
if a.long:
    messages[0]['content'] += '\nتحلیل و توصیه را مفصل با چندین جمله توضیح بده.'
if a.input_chars:
    messages[1]['content'] += '\nشواهد ساختگی افزوده: ' + ('synthetic-flow-metadata ' * (a.input_chars // 24))
schema = ANALYSIS_SCHEMA if a.batch == 1 else BATCH_SCHEMA
record = dict(case=a.case, api=a.api, model=model, requested_context=a.context if a.api == 'native' else None, batch=a.batch, budget=a.budget, think=a.think, timeout=a.timeout)
record.update(started_at=datetime.now(timezone.utc).isoformat(), input_chars=sum(len(m['content']) for m in messages), thinking_chars=0)
record.update(large_evidence_requested=a.large, long_response_requested=a.long,
              extra_input_chars=a.input_chars)
stop = threading.Event()
samples = []
def memory():
    while not stop.is_set():
        fields = {ln.split(':')[0]: int(ln.split()[1]) for ln in Path('/proc/meminfo').read_text().splitlines() if ln.startswith(('MemAvailable:', 'SwapFree:'))}
        samples.append(fields)
        stop.wait(1)
thread = threading.Thread(target=memory, daemon=True)
thread.start()
text = ''
started = time.monotonic()
try:
    with httpx.Client(timeout=httpx.Timeout(a.timeout, connect=5), trust_env=False) as client:
        record['models'] = [m['name'] for m in client.get(base+'/api/tags').json()['models']]
        record['ollama_version'] = client.get(base+'/api/version').json().get('version')
        record['initial_runtime'] = client.get(base+'/api/ps').json()
        assert model in record['models'], 'requested model is not installed'
        if a.api == 'native':
            payload = dict(model=model, messages=messages, format=schema, stream=True, options=dict(num_ctx=a.context, num_predict=a.budget, temperature=0.2), keep_alive='15m')
            if a.think == 'false': payload['think'] = False
            endpoint = '/api/chat'
        else:
            payload = dict(model=model, messages=messages, response_format=dict(type='json_schema', json_schema=dict(name='analysis', strict=True, schema=schema)), max_tokens=a.budget, temperature=0.2, stream=True, stream_options=dict(include_usage=True))
            if a.think == 'false': payload['reasoning_effort'] = 'none'
            endpoint = '/v1/chat/completions'
        with client.stream('POST', base+endpoint, json=payload) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if time.monotonic() - started > a.timeout:
                    raise TimeoutError('wall-clock generation deadline exceeded')
                if not line or line == 'data: [DONE]': continue
                chunk = json.loads(line.removeprefix('data: '))
                if a.api == 'native':
                    text += chunk.get('message', {}).get('content', '')
                    record['thinking_chars'] += len(chunk.get('message', {}).get('thinking') or '')
                    if chunk.get('done'):
                        record.update({k: chunk.get(k) for k in ('prompt_eval_count', 'eval_count', 'done_reason', 'load_duration', 'prompt_eval_duration', 'eval_duration')})
                else:
                    for choice in chunk.get('choices', []):
                        text += choice.get('delta', {}).get('content') or ''
                        delta = choice.get('delta', {})
                        record['thinking_chars'] += len(delta.get('reasoning') or delta.get('reasoning_content') or '')
                        if choice.get('finish_reason'): record['done_reason'] = choice['finish_reason']
                    if chunk.get('usage'): record['usage'] = chunk['usage']
        record['runtime'] = client.get(base+'/api/ps').json()
        if record.get('done_reason') == 'length':
            raise ValueError('LLMTruncated: finish_reason=length')
        if record.get('done_reason') != 'stop':
            raise ValueError('stream did not terminate normally')
        parsed = json.loads(text)
        results = [parsed] if a.batch == 1 else parsed['results']
        for item in results: AlertAnalysis.model_validate(item)
        if a.batch > 1:
            assert len(results) == len(alerts)
            assert {v['alert_id'] for v in results} == {v['id'] for v in alerts}
        record['valid'] = True
except Exception as exc:
    record['valid'] = False
    record['error'] = f'{type(exc).__name__}: {exc}'[:500]
finally:
    stop.set()
    thread.join(2)
    record['duration_seconds'] = round(time.monotonic()-started, 2)
    record['response_chars'] = len(text)
    if samples:
        record['initial_available_kib'] = samples[0]['MemAvailable']
        record['initial_swap_free_kib'] = samples[0]['SwapFree']
        record['minimum_available_kib'] = min(v['MemAvailable'] for v in samples)
        record['minimum_swap_free_kib'] = min(v['SwapFree'] for v in samples)
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    with Path(a.output).open('a') as f: f.write(json.dumps(record, ensure_ascii=False)+'\n')
    print(json.dumps(record, ensure_ascii=False), flush=True)
