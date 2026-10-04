#!/usr/bin/env python3
"""SSRF egress-reachability primitive: redirect -> internal canary (W57).

Generic adapter for ai-agent target labs. SSRF-class findings repeatedly need a
public-looking first hop that passes the target's URL validation, while the lab
has no egress. This adapter supplies both ends:

  /redirect?to=<url>   302 to <url>; the target must be <SSRF_REDIRECT_PREFIX>*
                       (default: this adapter's own /canary/ space), so the
                       primitive can never act as an open relay.
  /canary/<token>      records the hit (token, peer, UA, path) and returns a
                       marker body "SSRF-CANARY:<token>" — proof the victim's
                       server-side fetcher followed the chain.
  /hits                JSON observation channel: every recorded hit.
  /healthz             boot probe (poll this, never sleep — L63).

The pattern under test: the victim validates the FIRST url (public-looking,
passes validate_url/SSRF guards), the fetcher follows the redirect, and the
hit lands on the INTERNAL canary — reachability proven without real egress.

Env:
  SSRF_BIND            (default 127.0.0.1; use 0.0.0.0 inside an internal-lan
                       lab so the victim sees an RFC1918 peer)
  SSRF_PORT            (default 8801)
  SSRF_LOG             (optional) NDJSON hit log
  SSRF_REDIRECT_PREFIX (optional) allowed redirect-target prefix; default is
                       http://<SSRF_BIND>:<SSRF_PORT>/canary/
"""
import json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BIND = os.environ.get('SSRF_BIND', '127.0.0.1')
PORT = int(os.environ.get('SSRF_PORT', '8801'))
LOG = os.environ.get('SSRF_LOG')
PREFIX = os.environ.get('SSRF_REDIRECT_PREFIX', f'http://{BIND}:{PORT}/canary/')

hits = []


def record(ev):
    hits.append(ev)
    if LOG:
        with open(LOG, 'a') as f:
            f.write(json.dumps(ev) + '\n')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # stdout stays clean for the observation channel

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
            return self._json({'ok': True, 'hits': len(hits)})
        if url.path == '/hits':
            return self._json({'hits': hits})
        if url.path == '/redirect':
            to = (parse_qs(url.query).get('to') or [''])[0]
            if not to.startswith(PREFIX):
                record({'kind': 'redirect_refused', 'to': to, 'ts': time.time()})
                return self._json({'error': 'redirect target outside the allowed prefix'}, 403)
            self.send_response(302)
            self.send_header('Location', to)
            self.end_headers()
            return
        if url.path.startswith('/canary/'):
            token = url.path[len('/canary/'):][:128]
            record({'kind': 'canary', 'token': token, 'peer': self.client_address[0],
                    'ua': self.headers.get('User-Agent', ''), 'ts': time.time()})
            body = f'SSRF-CANARY:{token}'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({'error': 'unknown route'}, 404)


if __name__ == '__main__':
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
