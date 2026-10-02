#!/usr/bin/env python3
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Allowlist CONNECT proxy for the agent sandbox.

Agent containers sit on the docker --internal reproof-internal network with
no default route; this proxy is their only path out. Only CONNECT to
allowlisted host:port tuples is honoured, so the agent (and anything it
spawns) can reach the model API and nothing else. Denied attempts are
logged — useful signal if an agent tries to phone home. The orchestrator
stays on the trusted host.

Run as a sidecar container dual-homed on reproof-internal and the default
bridge.
"""

from __future__ import annotations

import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALLOW = {
    h.strip().lower()
    for h in (os.environ.get("REPROOF_EGRESS_ALLOW") or "agent-gw.kimi.com:443").split(",")
    if h.strip()
}
PORT = int(os.environ.get("REPROOF_EGRESS_PORT") or 3128)
# Idle-tunnel timeout. Streaming model APIs can pause between chunks far
# longer than 60s (thinking phases); too small a value kills long-lived
# agent streams mid-run (seen live: 2/3 parallel find agents died with
# provider.connection_error while the third streamed on).
IDLE_TIMEOUT_S = int(os.environ.get("REPROOF_EGRESS_IDLE_TIMEOUT") or 600)

_HOST_RE = re.compile(r"^[a-z0-9.-]+:\d+$")


def _allowed(target: str, allow: set[str] = ALLOW) -> bool:
    # Keep in sync with reproof/auth.py:_host_allowed
    t = target.lower()
    if not _HOST_RE.match(t):
        return False
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):  # noqa: N802 — http.server dispatch convention
        target = self.path
        if not _allowed(target):
            sys.stderr.write(f"[egress DENY] {self.client_address[0]} → {target}\n")
            self.send_error(403, f"egress denied: {target}")
            return
        host, _, port = target.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError as e:
            self.send_error(502, f"upstream connect failed: {e}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        client = self.connection
        sys.stderr.write(f"[egress ok]   {self.client_address[0]} → {target}\n")
        self._pump(client, upstream)

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        # Two blocking forwarder threads. The previous single-loop
        # non-blocking version called sendall() on non-blocking sockets:
        # a large request body (fat agent context) overflowed the upstream
        # send buffer, sendall raised EAGAIN (an OSError), the handler
        # swallowed it and tore down the tunnel — the client saw
        # "Connection reset by peer" on any request above ~100 KB.
        # Blocking sendall applies backpressure correctly; the per-socket
        # timeout still reaps tunnels idle past IDLE_TIMEOUT_S.
        import threading
        a.settimeout(IDLE_TIMEOUT_S)
        b.settimeout(IDLE_TIMEOUT_S)

        def forward(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=forward, args=(a, b), daemon=True)
        t2 = threading.Thread(target=forward, args=(b, a), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def log_message(self, format, *args):  # noqa: A002 — base sig
        pass


def main() -> None:
    sys.stderr.write(f"[egress] listening on :{PORT}, allow={sorted(ALLOW)}\n")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
