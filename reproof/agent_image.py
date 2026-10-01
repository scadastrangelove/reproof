# SPDX-License-Identifier: Apache-2.0
# Ported from rust-in-peace harness/agent_image.py
# (Copyright 2026 Anthropic PBC); the base layer carries the Kimi Code CLI
# instead of Claude Code, plus a pre-seeded $KIMI_CODE_HOME (ADR-001 R4).
"""Build the per-target agent image: target binary + kimi CLI.

The agent runs *inside* its container, so the container needs the CLI. To
avoid one node+npm install per target, ``ensure()`` builds a shared
``reproof-agent-base:<cli-version>`` once (gcc:14 + node + pinned CLI +
a $KIMI_CODE_HOME with loop_control) and then layers each target's ``/work``
on top via ``COPY --from``. Target Dockerfiles stay unchanged (single source
of truth for the binary build).

The baked-in config.toml exists so ``loop_control.max_steps_per_turn`` (the
Kimi equivalent of --max-turns, ADR-001 R4) has a sane default; the run
entrypoint rewrites it per attempt from the run's --max-turns value.
"""
from __future__ import annotations

import functools
import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

KIMI_CODE_VERSION = "2.1.1"  # pinned to the Phase-0-verified CLI
BASE_TAG = f"reproof-agent-base:{KIMI_CODE_VERSION}"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")

# Default step budget inside the container; the run entrypoint overrides it
# per-attempt. Matches the upstream default --max-turns ballpark.
DEFAULT_MAX_STEPS = 200


def agent_tag(target_tag: str) -> str:
    """Distinct agent-image tag per *full* target tag, so a committed
    ``<name>:patched-<uuid>`` snapshot doesn't collide with ``<name>:v1``."""
    return f"{target_tag.replace(':', '-')}-agent:{KIMI_CODE_VERSION}"


def _build(dockerfile: str, tag: str) -> None:
    with tempfile.TemporaryDirectory() as ctx:
        with open(f"{ctx}/Dockerfile", "w") as f:
            f.write(dockerfile)
        subprocess.run(
            ["docker", "build", "-q", "-t", tag, ctx],
            check=True,
            capture_output=True,
            text=True,
        )


def _ensure_base() -> str:
    if docker_ops.image_exists(BASE_TAG):
        return BASE_TAG
    # xxd + gdb: the find/patch prompts list these as available. Target
    # Dockerfiles install them too, but ``ensure()`` only copies /work from the
    # target image — apt packages outside /work don't survive the COPY --from.
    # Anything the prompts promise has to live in this base layer.
    _build(
        textwrap.dedent(f"""\
            FROM gcc:14
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g @moonshot-ai/kimi-code@{KIMI_CODE_VERSION}
            ENV KIMI_CODE_HOME=/opt/reproof/kimi-home
            RUN mkdir -p "$KIMI_CODE_HOME" && \\
                printf '[loop_control]\\nmax_steps_per_turn = {DEFAULT_MAX_STEPS}\\n' \\
                    > "$KIMI_CODE_HOME/config.toml"
            WORKDIR /work
        """),
        BASE_TAG,
    )
    return BASE_TAG


@functools.lru_cache(maxsize=None)
def ensure(target_tag: str) -> str:
    """Build (if missing) and return the agent-image tag for ``target_tag``."""
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    tag = agent_tag(target_tag)
    if docker_ops.image_exists(tag):
        return tag
    _ensure_base()
    _build(
        f"FROM {BASE_TAG}\nCOPY --from={target_tag} /work /work\n",
        tag,
    )
    subprocess.run(
        ["docker", "tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"],
        check=True,
    )
    return tag
