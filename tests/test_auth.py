# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""Tests for reproof.auth — env resolution and egress derivation."""
from __future__ import annotations

import pytest

from reproof import auth

KEYS = ("KIMI_MODEL_NAME", "KIMI_MODEL_API_KEY", "KIMI_MODEL_BASE_URL")
GOOD = {
    "KIMI_MODEL_NAME": "kimi-for-coding",
    "KIMI_MODEL_API_KEY": "sk-test-" + "x" * 32,
    "KIMI_MODEL_BASE_URL": "https://agent-gw.example.com/coding/v1",
}


@pytest.fixture
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_no_env_returns_none(clean_env):
    assert auth.resolve_auth_env() is None


def test_full_env_returns_dict(clean_env):
    for k, v in GOOD.items():
        clean_env.setenv(k, v)
    assert auth.resolve_auth_env() == GOOD


def test_partial_env_rejected(clean_env, capsys):
    clean_env.setenv("KIMI_MODEL_API_KEY", GOOD["KIMI_MODEL_API_KEY"])
    assert auth.resolve_auth_env() is None
    assert "partial Kimi auth" in capsys.readouterr().err


def test_non_https_base_rejected(clean_env, capsys):
    for k, v in {**GOOD, "KIMI_MODEL_BASE_URL": "http://insecure/v1"}.items():
        clean_env.setenv(k, v)
    assert auth.resolve_auth_env() is None
    assert "https" in capsys.readouterr().err


def test_egress_host_derived_from_base_url(clean_env):
    clean_env.setenv("KIMI_MODEL_BASE_URL", GOOD["KIMI_MODEL_BASE_URL"])
    assert auth.required_egress_hosts() == ["agent-gw.example.com:443"]


def test_egress_host_explicit_port(clean_env):
    clean_env.setenv("KIMI_MODEL_BASE_URL", "https://gw.internal:8443/v1")
    assert auth.required_egress_hosts() == ["gw.internal:8443"]


def test_egress_preflight_pass_and_fail(clean_env):
    clean_env.setenv("KIMI_MODEL_BASE_URL", GOOD["KIMI_MODEL_BASE_URL"])
    auth.check_egress_satisfied("agent-gw.example.com:443,other:443")
    with pytest.raises(SystemExit):
        auth.check_egress_satisfied("unrelated.example.com:443")
