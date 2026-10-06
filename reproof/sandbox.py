# SPDX-License-Identifier: Apache-2.0
# Ported from rust-in-peace harness/sandbox.py (Copyright 2026 Anthropic PBC),
# with env vars renamed VULN_PIPELINE_* -> REPROOF_* and the Claude-specific
# permission-mode function removed (ADR-001: kimi -p auto-approves routine
# calls; --auto is rejected in prompt mode; static deny lives in config.toml
# [[permission.rules]]).
"""Agent-sandbox configuration.

The pipeline spawns each find/grade/report/recon agent inside a gVisor
container on an `--internal` docker network whose only egress is the
allowlist proxy (derived from KIMI_MODEL_BASE_URL — see ``reproof.auth``).
The sandbox entrypoint (bin/reproof-sandboxed, Phase 2) sets the env vars
below after verifying the runtime and proxy are up; the per-phase modules
read them via this module rather than threading them through the CLI.

Permission model difference from upstream: Claude Code needed
``--permission-mode bypassPermissions`` inside the sandbox. Kimi Code CLI in
``-p`` mode already runs non-interactively (routine tool calls auto-approved,
static deny rules still enforced), so there is no flag to forward — the
container boundary is the only boundary, as before.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from typing import Iterator

from . import agent_backend, agent_image, agent_zcode, agent_zcode_image, docker_ops

RUNTIME_ENV = "REPROOF_AGENT_RUNTIME"
PROXY_ENV = "REPROOF_EGRESS_PROXY"
NETWORK_ENV = "REPROOF_AGENT_NETWORK"
NETWORK_DEFAULT = "reproof-internal"


def runtime() -> str | None:
    return os.environ.get(RUNTIME_ENV) or None


def proxy() -> str | None:
    return os.environ.get(PROXY_ENV) or None


def network() -> str:
    if not runtime():
        return "bridge"
    return os.environ.get(NETWORK_ENV) or NETWORK_DEFAULT


# Alias so ``agent_container``'s ``network`` parameter can shadow the function
# name without losing access to the default-resolution logic.
_default_network = network


@contextlib.contextmanager
def agent_container(
    target_tag: str,
    name: str,
    auth: dict[str, str] | None,
    memory: str = "4g",
    shm_size: str | None = None,
    mounts: list[tuple[str, str]] | None = None,
    network: str | None = None,
) -> Iterator[str]:
    """Spawn the per-phase agent container and tear it down on exit.

    All find/grade/report/recon/judge agents go through this so the
    "every agent runs in the sandbox" invariant lives in one place.

    ``network`` overrides the sandbox default. Pass ``"none"`` for containers
    that never run ``kimi -p`` (e.g. the T0–T2 patch grader): they only run
    target code via ``exec_sh`` and don't need any egress, so don't give them
    any — under ``--dangerously-no-sandbox`` the default falls back to
    ``bridge``, and a binary fed an attacker-crafted PoC shouldn't get that."""
    if agent_backend.current_backend() == "zcode":
        img = agent_zcode_image.ensure(target_tag)
    else:
        img = agent_image.ensure(target_tag)
    container = docker_ops.run(
        img,
        name=name,
        runtime=runtime(),
        network=network if network is not None else _default_network(),
        memory=memory,
        shm_size=shm_size,
        env=container_env(auth),
        mounts=list(mounts or []),
    )
    try:
        yield container
    finally:
        docker_ops.rm(container)


def container_env(auth: dict[str, str] | None) -> dict[str, str]:
    """Env to set on the agent container at ``docker run`` time.

    Auth env from ``reproof.auth.resolve_auth_env`` passes straight through;
    the egress proxy is injected (both upper- and lower-case forms) when the
    sandbox is active so the in-container CLI can reach the model API."""
    e = dict(auth or {})
    if agent_backend.current_backend() == "zcode":
        # ADR-002 R4/R5: the paired provider-config envs (mandatory together
        # or the CLI registry refuses to start) — builtin catalog baked into
        # the image, personal overlay written per-run by agent_zcode.
        e["ZCODE_BUILTIN_PROVIDER_CONFIG_FILE"] = (
            agent_zcode_image.BUILTIN_IN_IMAGE)
        e["ZCODE_PERSONAL_PROVIDER_CONFIG_FILE"] = (
            agent_zcode.PROVIDER_CONFIG_PATH)
    if p := proxy():
        e["HTTPS_PROXY"] = p
        e["https_proxy"] = p
        if agent_backend.current_backend() == "zcode":
            # The zcode CLI strips classic HTTP(S)_PROXY at startup and
            # honors only ZCODE_HTTP_PROXY — without it the model fetch goes
            # direct and dies in the egress-only sandbox network (EAI_AGAIN).
            e["ZCODE_HTTP_PROXY"] = p
    else:
        # No sandbox egress proxy (e.g. --dangerously-no-sandbox). Forward an
        # outbound HTTP(S) proxy from the host env into the agent container so
        # the in-container `kimi -p` can reach the model API from a
        # geo-restricted host. Both cases — some HTTP stacks read only the
        # lower-case.
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
                    "https_proxy", "http_proxy", "no_proxy"):
            if v := os.environ.get(var):
                e[var] = v
    return e


def require(override: bool) -> str | None:
    """Return an error message if the sandbox isn't configured; else None."""
    if override:
        return None
    rt = runtime()
    if not rt:
        return (
            "error: refusing to spawn agents outside the sandbox.\n"
            "  Run via the sandboxed entrypoint (bin/reproof-sandboxed), or pass\n"
            "  --dangerously-no-sandbox to run without gVisor isolation\n"
            "  (development use only — the container boundary is the boundary)."
        )
    runtimes = subprocess.run(
        ["docker", "info", "--format", "{{range $k,$v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True,
        text=True,
    ).stdout.split()
    if rt not in runtimes:
        return (
            f"error: {RUNTIME_ENV}={rt!r} but docker has no such runtime ({runtimes})"
        )
    return None
