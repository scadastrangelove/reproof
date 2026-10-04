#!/usr/bin/env python3
"""Fixture victim for the SSRF template (W57) — NOT a reusable adapter.

Server-side fetch of ?url= with a first-URL filter that blocks the internal
canary path but blindly follows redirects: the classic shape an open redirect
bypasses. Stands in for a target whose validate_url checks only the URL the
caller supplied.

Env:
  VICTIM_PORT           (default 8802)
  VICTIM_BLOCKED_SUBSTR (default "/canary/") first-URL filter
"""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen

PORT = int(os.environ.get('VICTIM_PORT', '8802'))
BLOCKED = os.environ.get('VICTIM_BLOCKED_SUBSTR', '/canary/')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/healthz':
            return self._json({'ok': True})
        if url.path != '/fetch':
            return self._json({'error': 'unknown route'}, 404)
        target = (parse_qs(url.query).get('url') or [''])[0]
        if not target.startswith(('http://', 'https://')):
            return self._json({'error': 'scheme not allowed'}, 403)
        if BLOCKED in urlparse(target).path:
            return self._json({'error': 'blocked by the url filter'}, 403)
        try:
            body = urlopen(target, timeout=5).read()[:4096].decode('utf-8', 'replace')
        except Exception as e:
            return self._json({'error': f'fetch failed: {type(e).__name__}'}, 502)
        self._json({'fetched': body})


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
