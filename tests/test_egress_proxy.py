# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""scripts/egress_proxy.py:_allowed — wildcard semantics + parity with
reproof.auth._host_allowed (the two must agree or reproof-sandboxed's preflight
diverges from what the proxy actually enforces)."""
import importlib.util
from pathlib import Path

import pytest

from reproof.auth import _host_allowed

_SCRIPT = Path(__file__).parent.parent / "scripts" / "egress_proxy.py"
_spec = importlib.util.spec_from_file_location("egress_proxy", _SCRIPT)
assert _spec and _spec.loader
egress_proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress_proxy)


def test_exact_match():
    assert egress_proxy._allowed("api.anthropic.com:443", {"api.anthropic.com:443"})


def test_wildcard_matches_subdomain():
    assert egress_proxy._allowed(
        "bedrock-runtime.us-east-1.amazonaws.com:443", {"*.amazonaws.com:443"}
    )


def test_wildcard_rejects_suffix_squatter():
    assert not egress_proxy._allowed("evilamazonaws.com:443", {"*.amazonaws.com:443"})


def test_wildcard_rejects_apex():
    assert not egress_proxy._allowed("amazonaws.com:443", {"*.amazonaws.com:443"})


def test_case_insensitive():
    assert egress_proxy._allowed(
        "BEDROCK-RUNTIME.US-EAST-1.AMAZONAWS.COM:443", {"*.amazonaws.com:443"}
    )


def test_charset_reject():
    assert not egress_proxy._allowed(
        "evil.com#.amazonaws.com:443", {"*.amazonaws.com:443"}
    )


@pytest.mark.parametrize(
    "target,allow",
    [
        ("api.anthropic.com:443", {"api.anthropic.com:443"}),
        ("bedrock-runtime.us-east-1.amazonaws.com:443", {"*.amazonaws.com:443"}),
        ("evilamazonaws.com:443", {"*.amazonaws.com:443"}),
        ("amazonaws.com:443", {"*.amazonaws.com:443"}),
        ("foo.bar.googleapis.com:443", {"*.googleapis.com:443"}),
        ("api.anthropic.com:443", {"*.amazonaws.com:443"}),
    ],
)
def test_parity_with_harness_auth(target, allow):
    """Proxy enforcement and the reproof-sandboxed preflight share semantics."""
    assert egress_proxy._allowed(target, allow) == _host_allowed(target, allow)


def test_pump_preserves_large_payload_both_ways():
    """EAGAIN regression: >100KB through the tunnel must arrive intact.

    The non-blocking sendall pump used to drop the tunnel on EAGAIN;
    clients saw 'Connection reset by peer' on fat agent requests.
    """
    import socket as _socket
    import threading

    payload = b"x" * 400_000
    reply = b"y" * 200_000
    client_a, proxy_a = _socket.socketpair()
    proxy_b, upstream = _socket.socketpair()

    # upstream echo-end: read all payload, send reply, half-close
    received = bytearray()
    def upstream_end():
        while True:
            d = upstream.recv(65536)
            if not d:
                break
            received.extend(d)
        upstream.sendall(reply)
        upstream.shutdown(_socket.SHUT_WR)
    ut = threading.Thread(target=upstream_end, daemon=True)
    ut.start()

    pt = threading.Thread(
        target=egress_proxy.Handler._pump, args=(proxy_a, proxy_b), daemon=True)
    pt.start()

    client_a.sendall(payload)
    client_a.shutdown(_socket.SHUT_WR)
    got = bytearray()
    while True:
        d = client_a.recv(65536)
        if not d:
            break
        got.extend(d)
    client_a.close()
    ut.join(timeout=10)
    pt.join(timeout=10)

    assert bytes(received) == payload
    assert bytes(got) == reply
