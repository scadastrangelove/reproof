#!/usr/bin/env python3
"""Generic MCP streamable-HTTP client (JSON-RPC over HTTP, SSE or JSON replies).

Distilled pattern for HTTP-transport MCP targets: initialize -> capture the
`mcp-session-id` response header -> send `notifications/initialized` -> issue
`tools/call`. Response bodies may be SSE frames (`data: {...}` lines) or plain
JSON; both are parsed. Pure stdlib (urllib), no dependencies.

Follows the profile's entry-adapter protocol: ONE JSON request on stdin, ONE
JSON observation on stdout. All diagnostics go to $MCP_HTTP_LOG (NDJSON),
stdout carries only the final observation.

stdin request:
  {
    "url": "http://127.0.0.1:PORT/api/mcp/stream",     # required
    "auth_headers": {"authorization": "Bearer ..."},    # optional, merged as-is
    "tool": "some_tool",                                # required
    "arguments": {...},                                 # optional
    "protocol_version": "2025-03-26",                   # optional
    "client_info": {"name": "reproof-lab", "version": "1"},  # optional
    "timeout_s": 30                                     # optional
  }

stdout observation:
  {"ok", "init_status", "session_id", "call_status",
   "tool_is_error", "tool_text"}
"""
import json, os, sys
import urllib.request, urllib.error

LOG = os.environ.get('MCP_HTTP_LOG')


def log(ev):
    if LOG:
        with open(LOG, 'a') as f:
            f.write(json.dumps(ev, default=str) + '\n')


def post(url, payload, headers, timeout):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method='POST',
        headers={'content-type': 'application/json',
                 'accept': 'application/json, text/event-stream', **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, dict(res.headers), res.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode('utf-8', 'replace')


def parse_body(text):
    """Return the list of JSON-RPC messages from an SSE or plain-JSON body."""
    events = []
    for line in text.split('\n'):
        if line.startswith('data:'):
            try:
                events.append(json.loads(line[5:].strip()))
            except json.JSONDecodeError:
                pass  # partial frame
    if events:
        return events
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        return []


def main():
    inp = json.load(sys.stdin)
    url = inp['url']
    auth = inp.get('auth_headers', {})
    timeout = inp.get('timeout_s', 30)

    init_status, init_headers, init_body = post(url, {
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {'protocolVersion': inp.get('protocol_version', '2025-03-26'),
                   'capabilities': {},
                   'clientInfo': inp.get('client_info', {'name': 'reproof-lab', 'version': '1'})}},
        auth, timeout)
    session_id = init_headers.get('mcp-session-id') or init_headers.get('Mcp-Session-Id')
    log({'step': 'initialize', 'status': init_status, 'session_id': session_id})

    call_status, tool_is_error, tool_text = 0, None, None
    if init_status == 200:
        headers = dict(auth)
        if session_id:
            post(url, {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                 {**headers, 'mcp-session-id': session_id}, timeout)
            headers['mcp-session-id'] = session_id
        call_status, _, call_body = post(url, {
            'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
            'params': {'name': inp['tool'], 'arguments': inp.get('arguments', {})}},
            headers, timeout)
        for event in parse_body(call_body):
            result = event.get('result') if isinstance(event, dict) and event.get('id') == 2 else None
            if not result:
                continue
            if 'isError' in result:
                tool_is_error = result['isError'] is True
            content = result.get('content') if isinstance(result.get('content'), list) else []
            text_part = next((c for c in content if isinstance(c, dict) and c.get('type') == 'text'), None)
            if text_part:
                tool_text = str(text_part.get('text'))[:4000]
            if event.get('error'):
                tool_text = f"JSONRPC error: {json.dumps(event['error'])}"[:4000]
        log({'step': 'tools/call', 'status': call_status, 'tool_is_error': tool_is_error})

    sys.stdout.write(json.dumps({
        'ok': True, 'init_status': init_status, 'session_id': session_id,
        'call_status': call_status, 'tool_is_error': tool_is_error,
        'tool_text': tool_text}) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        log({'fatal': repr(e)})
        sys.stdout.write(json.dumps({'ok': False, 'error': str(e)}) + '\n')
        sys.exit(1)
