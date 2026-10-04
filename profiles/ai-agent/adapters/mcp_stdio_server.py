#!/usr/bin/env python3
"""Mock MCP server (stdio, newline-delimited JSON-RPC), spec-driven.

Generic adapter: the tool surface comes from a spec file, so the same server
plays both attack and negative-control roles without code edits.

Spec file (env MCP_SPEC, required): JSON object
  {
    "server": {"name": "mockmcp", "version": "0.0.1"},     # optional
    "tools": [
      {"name": "delete_everything",
       "description": "...",                                # may carry any payload, e.g. unicode TAG blocks
       "inputSchema": {"type": "object", "properties": {}},
       "annotations": {"readOnlyHint": true} | null,        # null/omitted = no annotations (control role)
       "marker": "/work/evidence/<marker>",                 # optional: touched on tools/call
       "marker_text": "...",                                # optional marker content
       "result_text": "..."}                                # optional tool result text
    ]
  }

Handshake notes that matter for real agents:
  - Some agents probe with `server/discover` BEFORE `initialize`; answering
    JSON-RPC error -32602 makes them fall back to a classic initialize.
  - Agents typically expose tools to the model under prefixed names
    (`<extension>__<tool>`); the scenario served by mock_llm must use the
    prefixed name if the victim does that.

Everything is logged to $MCP_LOG (default /work/evidence/mcp_server.log) as
NDJSON so the verifier can prove what happened: server start, every rpc,
tool executions.
"""
import json, os, sys

SPEC_PATH = os.environ.get('MCP_SPEC')
if not SPEC_PATH:
    sys.exit('MCP_SPEC is required (path to tool-spec JSON)')
LOG = os.environ.get('MCP_LOG', '/work/evidence/mcp_server.log')

spec = json.load(open(SPEC_PATH))
TOOLS = {t['name']: t for t in spec.get('tools', [])}
SERVER = spec.get('server', {'name': 'mockmcp', 'version': '0.0.1'})


def log(ev):
    with open(LOG, 'a') as f:
        f.write(json.dumps(ev) + '\n')


def send(obj):
    sys.stdout.write(json.dumps(obj) + '\n')
    sys.stdout.flush()


def public_tool(t):
    out = {'name': t['name'],
           'description': t.get('description', ''),
           'inputSchema': t.get('inputSchema', {'type': 'object', 'properties': {}})}
    if t.get('annotations'):
        out['annotations'] = t['annotations']
    return out


def main():
    log({'event': 'mcp_server_start', 'spec': SPEC_PATH, 'tools': sorted(TOOLS)})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get('method', '')
        log({'event': 'rpc', 'method': method, 'id': req.get('id')})
        if method == 'server/discover':
            send({'jsonrpc': '2.0', 'id': req['id'],
                  'error': {'code': -32602, 'message': 'Invalid request parameters', 'data': ''}})
        elif method == 'initialize':
            send({'jsonrpc': '2.0', 'id': req['id'], 'result': {
                'protocolVersion': req.get('params', {}).get('protocolVersion', '2024-11-26'),
                'capabilities': {'tools': {}},
                'serverInfo': SERVER}})
        elif method == 'notifications/initialized':
            pass
        elif method == 'tools/list':
            send({'jsonrpc': '2.0', 'id': req['id'],
                  'result': {'tools': [public_tool(t) for t in TOOLS.values()]}})
        elif method == 'tools/call':
            name = req.get('params', {}).get('name', '')
            tool = TOOLS.get(name.split('__')[-1], TOOLS.get(name, {}))
            marker = tool.get('marker')
            if marker:
                with open(marker, 'w') as f:
                    f.write(tool.get('marker_text', f'tool executed: {name}\n'))
            log({'event': 'tool_executed', 'tool': name, 'marker': marker})
            send({'jsonrpc': '2.0', 'id': req['id'], 'result': {
                'content': [{'type': 'text', 'text': tool.get('result_text', 'ok')}],
                'isError': False}})
        elif req.get('id') is not None:
            send({'jsonrpc': '2.0', 'id': req['id'], 'result': {}})


if __name__ == '__main__':
    main()
