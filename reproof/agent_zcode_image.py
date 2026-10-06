# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""Build the per-target agent image for the zcode backend (ADR-002).

Mirrors ``agent_image.py`` (kimi): a shared base layer once — node 24 + the
from-source zcode CLI bundle + the reproof shim — then each target's ``/work``
layered on top via ``COPY --from``. Target Dockerfiles stay unchanged.

Differences from the kimi base (ADR-002):
  * CLI = ``zcode.cjs`` built from the PINNED open-source commit
    (zai-org/ZCode @ 29628c9, CLI 0.16.9) — not an npm install.
  * No loop_control config: zcode has no budget analog (R6); the shim's
    wall-clock/quiet watchdog is the budget.
  * ``HOME`` is redirected to an empty dir inside the image (R5): the session
    db is hardwired to ``os.homedir()/.zcode``.
  * Provider auth = the personal-overlay file pair, injected at RUN time
    (``ZCODE_BUILTIN_PROVIDER_CONFIG_FILE`` +
    ``ZCODE_PERSONAL_PROVIDER_CONFIG_FILE`` must be set together, R4) — the
    image carries no credentials.
"""
from __future__ import annotations

import functools
import os
import re
import subprocess
import tempfile

from . import docker_ops

# Pinned to the ADR-002 Phase-0-verified from-source build.
ZCODE_VERSION = "0.16.9"
ZCODE_SOURCE_COMMIT = "29628c9"  # zai-org/ZCode v3.14.3 snapshot
BASE_LAYER_REV = "node24"
BASE_TAG = f"reproof-zcode-agent-base:{ZCODE_VERSION}-{BASE_LAYER_REV}"
# Pinned builtin provider catalog (public, no secrets — verified: only
# apiKeyManagementUrl links): zai-org/ZCode runtime catalog schemaVersion 1
# revision 30, captured from the 0.16.9 desktop runtime. The registry
# requires a builtin source alongside the personal overlay.
BUILTIN_IN_IMAGE = "/opt/reproof/conf/zcode-builtin.json"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    return f"{target_tag.replace(':', '-')}-agent:zcode-{ZCODE_VERSION}"


def _build(ctx_dir: str, dockerfile: str, tag: str) -> None:
    with open(f"{ctx_dir}/Dockerfile", "w") as f:
        f.write(dockerfile)
    subprocess.run(
        ["docker", "build", "-q", "-t", tag, ctx_dir],
        check=True,
        capture_output=True,
        text=True,
    )


def _dist_dir() -> str:
    """Directory containing the pinned build artifacts (zcode.cjs[, provider/])."""
    d = os.environ.get("ZCODE_AGENT_DIST")
    if d and os.path.isfile(os.path.join(d, "zcode.cjs")):
        return d
    raise RuntimeError(
        "ZCODE_AGENT_DIST must point at the from-source CLI dist directory "
        "(zcode.cjs) — build it per ADR-002: pnpm install --filter @zcode/cli... "
        "&& pnpm --filter @zcode/cli... build, then set ZCODE_AGENT_DIST=<repo>/"
        "apps/zcode-cli/packages/cli/dist"
    )


def _shim_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "agent_zcode_shim.mjs")
    if not os.path.isfile(p):
        raise RuntimeError(f"shim missing next to the package: {p}")
    return p


def _ensure_base() -> str:
    if docker_ops.image_exists(BASE_TAG):
        return BASE_TAG
    dist = _dist_dir()
    with tempfile.TemporaryDirectory() as ctx:
        # copy artifacts into the build context
        subprocess.run(["cp", "-R", dist, f"{ctx}/dist"], check=True)
        subprocess.run(
            ["cp", _shim_path(), f"{ctx}/dist/zcode-shim.mjs"], check=True)
        builtin = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "zcode_builtin_providers.json")
        subprocess.run(["cp", builtin, f"{ctx}/dist/zcode-builtin.json"],
                       check=True)
        # Model-traffic capture (R4b): to route provider traffic through a mitm
        # recorder, set host env ZCODE_HTTP_PROXY + ZCODE_AGENT_CA_CERT (forwarded
        # by agent_zcode.run_agent). ZCODE_AGENT_CA_CERT is a path INSIDE the
        # container and node's `ca` REPLACES the trust store, so the recorder CA
        # must be reachable there — either bind-mount it at run time, or bake it:
        #   COPY recorder-ca.pem /opt/reproof/conf/recorder-ca.pem
        # (left out by default so the base image stays credential/CA-free).
        _build(
            ctx,
            "FROM node:24-bookworm\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends"
            " ca-certificates curl xxd gdb git python3 &&"
            " rm -rf /var/lib/apt/lists/*\n"
            "COPY dist/ /opt/reproof/\n"
            "RUN chmod +x /opt/reproof/zcode-shim.mjs"
            " && mkdir -p /opt/reproof/home /opt/reproof/conf"
            " && mv /opt/reproof/zcode-builtin.json /opt/reproof/conf/\n"
            "ENV HOME=/opt/reproof/home\n"
            "WORKDIR /work\n",
            BASE_TAG,
        )
    return BASE_TAG


@functools.lru_cache(maxsize=None)
def ensure(target_tag: str) -> str:
    """Build (if missing) and return the zcode agent-image tag for ``target_tag``."""
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    tag = agent_tag(target_tag)
    if docker_ops.image_exists(tag):
        return tag
    _ensure_base()
    with tempfile.TemporaryDirectory() as ctx:
        _build(
            ctx,
            f"FROM {BASE_TAG}\nCOPY --from={target_tag} /work /work\n",
            tag,
        )
    subprocess.run(
        ["docker", "tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"],
        check=True,
    )
    return tag
