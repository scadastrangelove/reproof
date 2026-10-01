# SPDX-License-Identifier: Apache-2.0
"""Tests for reproof.sandbox + reproof.agent_image (no docker daemon needed)."""
from __future__ import annotations

import pytest

from reproof import agent_image, sandbox


@pytest.fixture
def clean_env(monkeypatch):
    for k in (sandbox.RUNTIME_ENV, sandbox.PROXY_ENV, sandbox.NETWORK_ENV,
              "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
              "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


# ── sandbox env plumbing ─────────────────────────────────────────────────────

def test_no_runtime_means_no_sandbox_network(clean_env):
    assert sandbox.runtime() is None
    assert sandbox.network() == "bridge"


def test_runtime_selects_internal_network(clean_env):
    clean_env.setenv(sandbox.RUNTIME_ENV, "runsc")
    assert sandbox.network() == "reproof-internal"
    clean_env.setenv(sandbox.NETWORK_ENV, "custom-net")
    assert sandbox.network() == "custom-net"


def test_container_env_injects_proxy_when_sandboxed(clean_env):
    clean_env.setenv(sandbox.PROXY_ENV, "http://proxy:3128")
    env = sandbox.container_env({"KIMI_MODEL_API_KEY": "k"})
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://proxy:3128"
    assert env["KIMI_MODEL_API_KEY"] == "k"  # auth passes straight through


def test_container_env_forwards_host_proxy_unsandboxed(clean_env):
    clean_env.setenv("HTTPS_PROXY", "http://host-proxy:8080")
    env = sandbox.container_env(None)
    assert env["HTTPS_PROXY"] == "http://host-proxy:8080"


def test_require_refuses_outside_sandbox(clean_env):
    assert "refusing to spawn agents" in sandbox.require(override=False)
    assert sandbox.require(override=True) is None


# ── agent_image ──────────────────────────────────────────────────────────────

def test_agent_tag_format():
    tag = agent_image.agent_tag("reproof-canary:v1")
    assert tag == f"reproof-canary-v1-agent:{agent_image.KIMI_CODE_VERSION}"


def test_invalid_target_tag_rejected():
    with pytest.raises(ValueError):
        agent_image.ensure("bad tag with spaces")


def test_base_image_pins_verified_cli():
    assert agent_image.KIMI_CODE_VERSION == "2.1.1"  # Phase-0-verified (ADR-001)
    assert agent_image.KIMI_CODE_VERSION in agent_image.BASE_TAG
