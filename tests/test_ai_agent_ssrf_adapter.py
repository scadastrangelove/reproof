# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""End-to-end template test for the SSRF egress-reachability primitive (W57).

Drives the real adapter (ssrf_canary.py) and the fixture victim
(ssrf_victim.py) as subprocesses over loopback — no Docker needed:
  attack:  victim.fetch(redirect -> canary) must record the canary hit
  control: victim.fetch(canary direct) must be refused by the victim's filter
  relay:   redirect to a non-canary target must be refused (no open relay)
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "profiles" / "ai-agent" / "adapters" / "ssrf_canary.py"
VICTIM = ROOT / "tests" / "fixtures" / "ssrf_victim.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _wait_ready(url: str, proc: subprocess.Popen) -> None:
    for _ in range(100):  # poll, never sleep-and-hope (L63)
        if proc.poll() is not None:
            raise RuntimeError(f"process died: {proc.args}")
        try:
            code, body = _get(url)
            if code == 200:
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"not ready: {url}")


@pytest.fixture
def lab():
    aport, vport = _free_port(), _free_port()
    adapter = subprocess.Popen([sys.executable, str(ADAPTER)],
                               env={**os.environ, "SSRF_PORT": str(aport)})
    victim = subprocess.Popen([sys.executable, str(VICTIM)],
                              env={**os.environ, "VICTIM_PORT": str(vport)})
    try:
        _wait_ready(f"http://127.0.0.1:{aport}/healthz", adapter)
        _wait_ready(f"http://127.0.0.1:{vport}/healthz", victim)
        yield aport, vport
    finally:
        adapter.kill()
        victim.kill()


def test_redirect_chain_reaches_the_internal_canary(lab):
    aport, vport = lab
    attack = (f"http://127.0.0.1:{vport}/fetch?url="
              f"http://127.0.0.1:{aport}/redirect?to="
              f"http://127.0.0.1:{aport}/canary/PIVOT")
    code, body = _get(attack)
    assert code == 200 and body["fetched"] == "SSRF-CANARY:PIVOT"
    _, hits = _get(f"http://127.0.0.1:{aport}/hits")
    assert [h["token"] for h in hits["hits"] if h["kind"] == "canary"] == ["PIVOT"]


def test_direct_fetch_is_blocked_by_the_victims_filter(lab):
    aport, vport = lab
    code, body = _get(f"http://127.0.0.1:{vport}/fetch?url="
                      f"http://127.0.0.1:{aport}/canary/DIRECT")
    assert code == 403 and "filter" in body["error"]
    _, hits = _get(f"http://127.0.0.1:{aport}/hits")
    assert not [h for h in hits["hits"] if h.get("token") == "DIRECT"]


def test_redirect_is_not_an_open_relay(lab):
    aport, _ = lab
    code, body = _get(f"http://127.0.0.1:{aport}/redirect?to=http://198.51.100.9/canary/X")
    assert code == 403
    _, hits = _get(f"http://127.0.0.1:{aport}/hits")
    assert hits["hits"][-1]["kind"] == "redirect_refused"
