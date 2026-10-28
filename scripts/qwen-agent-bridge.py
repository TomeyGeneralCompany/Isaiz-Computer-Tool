#!/usr/bin/env python3
"""One local model request through Qwen-Agent; no agent executor or built-in tools."""
import json
import sys
import urllib.request
from urllib.parse import urlsplit


def respond(request):
    endpoint = request['url']
    parsed = urlsplit(endpoint)
    if (parsed.scheme != 'http' or parsed.hostname not in ('localhost', '127.0.0.1', '::1')
            or parsed.username or parsed.password or parsed.path != '/api/chat' or parsed.query):
        raise ValueError('Qwen-Agent bridge only supports a local Ollama /api/chat endpoint')
    from qwen_agent.llm.function_calling import BaseFnCallModel
    from qwen_agent.llm.schema import Message
    from qwen_agent.utils.utils import format_as_text_message

    payload = request['payload']
    stats = {}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('Model endpoint redirects are disabled')

    class LocalQwen(BaseFnCallModel):
        def _chat_no_stream(self, messages, generate_cfg):
            wire = {k: payload[k] for k in ('model', 'options', 'keep_alive') if k in payload}
            wire.update(stream=True, think=bool(payload.get('think', False)), messages=[
                {'role': msg.role, 'content': format_as_text_message(msg, add_upload_info=False).content}
                for msg in messages])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            req = urllib.request.Request(endpoint, data=json.dumps(wire).encode(),
                                         headers={'Content-Type': 'application/json'})
            with opener.open(req, timeout=900) as response:
                if 'ndjson' not in response.headers.get('Content-Type', ''):
                    raw = response.read(1048577)
                    if len(raw) > 1048576:
                        raise ValueError('Model response exceeds 1 MiB')
                    result = json.loads(raw)
                else:
                    size, content, thinking = 0, '', ''
                    result = None
                    while True:
                        raw = response.readline(1048577)
                        if not raw:
                            break
                        size += len(raw)
                        if size > 1048576:
                            raise ValueError('Model response exceeds 1 MiB')
                        if not raw.strip():
                            continue
                        frame = json.loads(raw)
                        if frame.get('error') or result is not None:
                            raise ValueError('Invalid model stream')
                        message = frame.get('message', {})
                        content += message.get('content', '')
                        thinking += message.get('thinking', '')
                        if message.get('content') or message.get('thinking'):
                            print('[MODEL_PROGRESS] ' + json.dumps({
                                'contentCharacters': len(content),
                                'thinkingCharacters': len(thinking), 'toolCalls': 0,
                            }), file=sys.stderr, flush=True)
                        if frame.get('done') is True:
                            result = frame
                    if result is None:
                        raise ValueError('Model stream ended before completion')
                    result['message'] = {'role': 'assistant', 'content': content}
            stats.update({k: v for k, v in result.items() if k != 'message'})
            return [Message(role='assistant', content=result['message'].get('content', ''))]

        def _chat_stream(self, *args, **kwargs):
            raise ValueError('Only bounded non-streaming requests are supported')

    model = LocalQwen({'model': payload['model'], 'generate_cfg': {
        'max_retries': 0, 'fncall_prompt_type': 'nous',
        # The TypeScript controller owns compaction; never silently discard evidence here.
        'max_input_tokens': 0,
    }})
    messages = [dict(role=m['role'], content=m['content']) for m in payload['messages']]
    messages.append({'role': 'user', 'content': 'Call audit_action exactly once with the next permitted action. Do not execute any tools yourself.' + ('' if payload.get('think') else ' /no_think')})
    result = model.chat(messages=messages, functions=[{
        'name': 'audit_action', 'description': 'Choose the next controller-validated investigation action.',
        'parameters': payload['format'],
    }], stream=False)
    calls = [m.get('function_call') for m in result if m.get('function_call')]
    if len(calls) != 1 or calls[0]['name'] != 'audit_action':
        raise ValueError('Qwen-Agent did not return exactly one audit_action call')
    action = calls[0]['arguments']
    if not isinstance(action, str):
        action = json.dumps(action)
    json.loads(action)
    return {**stats, 'message': {'role': 'assistant', 'content': action}}


if __name__ == '__main__':
    try:
        incoming = sys.stdin.buffer.read(1048577)
        if len(incoming) > 1048576:
            raise ValueError('Request exceeds 1 MiB')
        print(json.dumps(respond(json.loads(incoming))))
    except Exception as exc:
        print(f'Qwen-Agent bridge failed: {type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(1)
