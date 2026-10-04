#!/usr/bin/env python3
"""Mock OpenAI-compatible LLM server (SSE streaming), scenario-driven.

Generic adapter for ai-agent target labs: stands in for the real provider so the
victim agent runs with all model traffic on loopback, fully deterministic.

Scenario file: JSON list of responses. Each response is either
  {"text": "..."}                                     -> assistant text, finish_reason stop
  {"tool_calls": [{"name": "...", "arguments": "{}"}]} -> tool calls, finish_reason tool_calls

Response selection is CONTENT-KEYED, not stateful: a request carrying a tool
result (role=tool or tool_call_id in messages) is the post-tool-call turn and is
served the LAST scenario step; a fresh conversation gets the FIRST. Deterministic
across repeated runs against the same port, which is what makes attack-run-2 a
meaningful replayability control.

Handles POST */chat/completions (stream and non-stream) and GET */models.

Env:
  MOCK_SCENARIO  (required) path to the scenario JSON
  MOCK_PORT      (default 8799)
  MOCK_MODEL     (default "mock-model") model id reported in responses
  MOCK_LOG       (optional) NDJSON request log: one line per request with
                 {"tool_result_seen": bool, "tools": bool}
"""
import json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCENARIO_PATH = os.environ.get('MOCK_SCENARIO')
if not SCENARIO_PATH:
    sys.exit('MOCK_SCENARIO is required (path to scenario JSON)')
PORT = int(os.environ.get('MOCK_PORT', '8799'))
MODEL = os.environ.get('MOCK_MODEL', 'mock-model')
LOG = os.environ.get('MOCK_LOG')

scenario = json.load(open(SCENARIO_PATH))


def log(ev):
    if LOG:
        with open(LOG, 'a') as f:
            f.write(json.dumps(ev) + '\n')


def next_response(body):
    msgs = body.get('messages', [])
    has_tool_result = any(isinstance(m, dict) and (m.get('role') == 'tool' or 'tool_call_id' in m) for m in msgs)
    resp = scenario[-1] if (has_tool_result and len(scenario) > 1) else scenario[0]
    log({'tool_result_seen': has_tool_result, 'tools': bool(body.get('tools'))})
    return resp


def chunks_for(resp):
    base = {'id': 'chatcmpl-mock', 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': MODEL}
    out = []
    if 'tool_calls' in resp:
        tcs = [{'index': n, 'id': f'call_{n}', 'type': 'function',
                'function': {'name': t['name'], 'arguments': t.get('arguments', '{}')}}
               for n, t in enumerate(resp['tool_calls'])]
        c = dict(base); c['choices'] = [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': tcs}, 'finish_reason': None}]
        out.append(c)
        c = dict(base); c['choices'] = [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]
        out.append(c)
    else:
        c = dict(base); c['choices'] = [{'index': 0, 'delta': {'role': 'assistant', 'content': resp.get('text', 'ok')}, 'finish_reason': None}]
        out.append(c)
        c = dict(base); c['choices'] = [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]
        out.append(c)
    return out


def full_for(resp):
    ch = chunks_for(resp)
    msg = {}
    for c in ch:
        d = c['choices'][0]['delta']
        if 'tool_calls' in d: msg['tool_calls'] = d['tool_calls']
        if 'content' in d: msg['content'] = d['content']
    msg.setdefault('content', None)
    msg['role'] = 'assistant'
    return {'id': 'chatcmpl-mock', 'object': 'chat.completion', 'created': int(time.time()), 'model': MODEL,
            'choices': [{'index': 0, 'message': msg, 'finish_reason': ch[-1]['choices'][0]['finish_reason']}],
            'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.endswith('/models'):
            self._json(200, {'object': 'list', 'data': [{'id': MODEL, 'object': 'model'}]})
        else:
            self._json(404, {'error': 'not found'})
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n) or b'{}')
        resp = next_response(body)
        if body.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            for c in chunks_for(resp):
                self.wfile.write(b'data: ' + json.dumps(c).encode() + b'\n\n')
                self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n'); self.wfile.flush()
        else:
            self._json(200, full_for(resp))


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
