#!/usr/bin/env python3
"""Generic ACP (agent-client-protocol) client driver — NDJSON JSON-RPC over stdio.

Drives any agent that speaks ACP on stdio through initialize -> session/new ->
optional session/prompt, with two attack-relevant knobs:

  - Deeplink injection: a JSON file is base64url-NOPAD encoded into
    session/new params `_meta.<key>` (key configurable; many agents accept a
    recipe/config deeplink there — the consent gate, if any, often lives only
    in the vendor's own renderer, which this raw client bypasses by design).
  - Reverse-request answering: servers may send client-bound requests
    (e.g. asking for recipe parameter values). ACP_REPLIES maps such methods
    to result objects; `${ENV_VAR}` strings inside are substituted from the
    environment, so the injected value is attack-controlled data.

Usage: acp_client.py <cwd> <log>
Env:
  ACP_AGENT_CMD       (required) agent command line, e.g. "myagent acp"
  ACP_DEEPLINK_FILE   path to JSON file to encode into _meta (omit = no deeplink,
                      which is exactly the negative control)
  ACP_DEEPLINK_META_KEY  (default "recipeDeeplink")
  ACP_CLIENT_CAPS     JSON file with clientCapabilities for initialize
  ACP_REPLIES         JSON file: {"<server-method>": {<result object>}}
  ACP_PROMPT_TEXT     prompt text for the spin-up turn (default "hi")
  ACP_SKIP_PROMPT=1   stop after session/new
  ACP_TIMEOUT_S       per-call wait (default 90)
"""
import base64, json, os, re, shlex, subprocess, sys, threading, time

CWD = sys.argv[1] if len(sys.argv) > 1 else '/work'
LOG = sys.argv[2] if len(sys.argv) > 2 else '/work/evidence/acp_driver.log'

CMD = os.environ.get('ACP_AGENT_CMD')
if not CMD:
    sys.exit('ACP_AGENT_CMD is required (e.g. ACP_AGENT_CMD="myagent acp")')
DEEPLINK_FILE = os.environ.get('ACP_DEEPLINK_FILE')
META_KEY = os.environ.get('ACP_DEEPLINK_META_KEY', 'recipeDeeplink')
CAPS = json.load(open(os.environ['ACP_CLIENT_CAPS'])) if os.environ.get('ACP_CLIENT_CAPS') else \
    {'fs': {'readTextFile': False, 'writeTextFile': False}}
REPLIES = json.load(open(os.environ['ACP_REPLIES'])) if os.environ.get('ACP_REPLIES') else {}
PROMPT = os.environ.get('ACP_PROMPT_TEXT', 'hi')
TIMEOUT = int(os.environ.get('ACP_TIMEOUT_S', '90'))


def log(ev):
    with open(LOG, 'a') as f:
        f.write(json.dumps(ev) + '\n')


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def subst(obj):
    """Recursively substitute "${VAR}" strings from the environment."""
    if isinstance(obj, str):
        return re.sub(r'\$\{(\w+)\}', lambda m: os.environ.get(m.group(1), ''), obj)
    if isinstance(obj, dict):
        return {k: subst(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [subst(v) for v in obj]
    return obj


def main():
    deeplink = None
    if DEEPLINK_FILE:
        raw = open(DEEPLINK_FILE, 'rb').read()
        json.loads(raw)  # validate it is JSON before encoding
        deeplink = b64url(raw)

    proc = subprocess.Popen(shlex.split(CMD), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=CWD if os.path.isdir(CWD) else None,
                            env=dict(os.environ), text=True, bufsize=1)
    responses = {}
    lock = threading.Lock()

    def wr(obj):
        with lock:
            proc.stdin.write(json.dumps(obj) + '\n')
            proc.stdin.flush()

    def reader():
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            log({'rx': line[:2000]})
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            method = msg.get('method')
            if method and 'id' in msg and method in REPLIES:
                # server -> client REQUEST: answer from the replies table
                reply = {'jsonrpc': '2.0', 'id': msg['id'], 'result': subst(REPLIES[method])}
                log({'reverse_request_answered': method})
                wr(reply)
                continue
            if 'id' in msg and ('result' in msg or 'error' in msg):
                responses[msg['id']] = msg

    threading.Thread(target=reader, daemon=True).start()

    def call(i, method, params, wait=None):
        wr({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params})
        for _ in range(int((wait or TIMEOUT) * 10)):
            if i in responses:
                return responses[i]
            if proc.poll() is not None:
                return {'error': 'agent exited', 'code': proc.returncode}
            time.sleep(0.1)
        return {'error': 'timeout'}

    r = call(0, 'initialize', {'protocolVersion': 1, 'clientCapabilities': CAPS})
    log({'step': 'initialize', 'ok': 'result' in r})

    params = {'cwd': CWD, 'mcpServers': []}
    if deeplink:
        params['_meta'] = {META_KEY: deeplink}
    r = call(1, 'session/new', params)
    log({'step': 'session/new', 'response': json.dumps(r)[:2000]})
    session_id = r.get('result', {}).get('sessionId')

    if session_id and os.environ.get('ACP_SKIP_PROMPT') != '1':
        r2 = call(2, 'session/prompt',
                  {'sessionId': session_id, 'prompt': [{'type': 'text', 'text': PROMPT}]})
        log({'step': 'session/prompt', 'response': json.dumps(r2)[:1000]})

    time.sleep(1)
    proc.terminate()
    log({'done': True, 'session_id': session_id})


if __name__ == '__main__':
    main()
