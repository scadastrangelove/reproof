# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/hygiene_lint.py — the fail-closed output-path gate (L69/W55)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "hygiene_lint", Path(__file__).resolve().parents[1] / "scripts" / "hygiene_lint.py")
lint = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lint)


@pytest.mark.parametrize("line,rule", [
    ('ssh ops@85.10.20.30 and done', "user@IP identifier"),
    ('host = "85.10.20.30"  # exec box', "routable IP"),
    ('config: /Users/alice/secret-target/lab', "local absolute path (/Users/...)"),
    ('clone into /home/bob/work', "local absolute path (/home/bob)"),
    ("API_KEY = " + '"sk-live-' + "Zm9v" * 8 + '"', "credential-shaped"),
    ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "credential-shaped"),
    ("ghp_" + "a" * 36, "credential-shaped"),
    ('token: "' + "abcd1234" * 3 + '"', "credential-shaped"),
])
def test_leaks_are_flagged(line, rule):
    hits = lint.scan_line(line)
    assert any(rule in h for h in hits), hits


@pytest.mark.parametrize("line", [
    "listen on 127.0.0.1:8080",
    "docker network: 10.11.0.0/16 and 192.168.1.5",
    "example: 192.0.2.10 (TEST-NET-1, RFC 5737)",
    "contact security@example.com",          # plain email, not user@IP
    "sandbox home is /home/oai/share",       # sandbox convention
    "version 1.2.3.400 is fine",             # not an IP
    "no secrets here at all",
])
def test_benign_lines_pass(line):
    assert lint.scan_line(line) == []


def test_allowlist_skips_matching_lines():
    import re
    allow = [re.compile(r"DOCUMENTED-LAB-HOST")]
    text = "host 85.10.20.30 is the DOCUMENTED-LAB-HOST placeholder\nhost 85.10.20.30 real"
    findings = lint.scan_text(text, allow)
    assert list(findings) == [2]


def test_cli_blocks_a_seeded_leak(tmp_path, capsys):
    bad = tmp_path / "run-log.txt"
    bad.write_text("deployed via ops@" + "91.198." + "10.20" + "\n")
    good = tmp_path / "clean.txt"
    good.write_text("all loopback 127.0.0.1\n")
    assert lint.main([str(bad), str(good)]) == 1
    assert "user@IP" in capsys.readouterr().out
    assert lint.main([str(good)]) == 0


def test_binary_files_are_skipped(tmp_path):
    blob = tmp_path / "artifact.bin"
    blob.write_bytes(b"\x00\x01\x02" + b"85.10.20.30")
    assert lint.main([str(blob)]) == 0
