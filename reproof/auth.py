# SPDX-License-Identifier: Apache-2.0
# Ported from rust-in-peace harness/auth.py (Copyright 2026 Anthropic PBC),
# retargeted from Claude Code auth to the Kimi Code CLI contract verified in
# docs/adr/ADR-001-agent-backend-kimi.md (Phase 0, R5).
"""Provider/auth resolution — single source of truth for the CLI and the
sandbox shell scripts.

Upstream supported four Anthropic paths (1P key, OAuth, Bedrock, Vertex).
Reproof's first backend is Kimi Code CLI, whose verified non-interactive
auth is env-only: KIMI_MODEL_NAME / KIMI_MODEL_API_KEY / KIMI_MODEL_BASE_URL
synthesize an in-memory provider+model, nothing lands on disk — exactly what
a container wants.

Deliberately dropped vs upstream:
  * the anthropic-cyber-runbook usage marker (Anthropic-only telemetry)
  * OAuth device flow (`kimi login` is interactive; usable on the host for
    development, never inside the agent container)
"""
from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

NO_AUTH_MSG = (
    "error: no model-API auth found. Set all three:\n"
    "  KIMI_MODEL_NAME       (model id, e.g. kimi-for-coding)\n"
    "  KIMI_MODEL_API_KEY    (API key)\n"
    "  KIMI_MODEL_BASE_URL   (OpenAI-compatible base, e.g. https://api.moonshot.ai/v1)\n"
    "For host-side development, `kimi login` (device flow) also works, but\n"
    "agent containers must use the env path — nothing is written to disk."
)

_ENV_KEYS = ("KIMI_MODEL_NAME", "KIMI_MODEL_API_KEY", "KIMI_MODEL_BASE_URL")

# zcode backend (ADR-002): same trio under ZCODE_MODEL_*; the key lands in the
# per-run personal-overlay file inside the ephemeral container (accepted
# deviation from kimi's env-only indirection — see ADR-002 "Adapter
# implications").
_ENV_KEYS_BY_BACKEND = {
    "kimi": _ENV_KEYS,
    "zcode": ("ZCODE_MODEL_NAME", "ZCODE_MODEL_API_KEY", "ZCODE_MODEL_BASE_URL"),
}


_FRIENDLY = {"kimi": "Kimi", "zcode": "Zcode"}


def _backend_auth() -> tuple[tuple[str, ...], str]:
    """(env keys, friendly name) for the current backend."""
    from .agent_backend import current_backend  # local import: avoid cycles
    backend = current_backend()
    if backend not in _ENV_KEYS_BY_BACKEND:
        backend = "kimi"
    return _ENV_KEYS_BY_BACKEND[backend], _FRIENDLY[backend]


def resolve_auth_env() -> dict[str, str] | None:
    """Resolve auth for the in-container agent process (backend-aware).

    Returns the env dict to set on the agent container, or None with a
    specific diagnostic on stderr. All three <KIMI|ZCODE>_MODEL_* vars are
    required: a key without a base URL (or vice versa) is a misconfiguration
    the CLI would otherwise report only after the container is already up.
    """
    keys, name = _backend_auth()
    prefix = keys[0].split("_MODEL_")[0]
    vals = {k: os.environ.get(k) for k in keys}
    present = {k: v for k, v in vals.items() if v}
    if not present:
        return None
    missing = [k for k in keys if k not in present]
    if missing:
        print(f"error: partial {name} auth — set but missing: "
              f"{', '.join(missing)}", file=sys.stderr)
        return None
    base = present[f"{prefix}_MODEL_BASE_URL"]
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname:
        print(f"error: {prefix}_MODEL_BASE_URL must be an https URL, got "
              f"{base!r}", file=sys.stderr)
        return None
    return dict(present)


def required_egress_hosts() -> list[str]:
    """host:port entries the current provider needs on the proxy allowlist.

    Derived from <KIMI|ZCODE>_MODEL_BASE_URL so the egress preflight follows
    the configured endpoint (managed service, model platform, or an
    OpenAI-compatible gateway) instead of hardcoding a vendor host.
    """
    keys, _name = _backend_auth()
    prefix = keys[0].split("_MODEL_")[0]
    base = os.environ.get(f"{prefix}_MODEL_BASE_URL")
    if not base:
        sys.exit(f"error: {prefix}_MODEL_BASE_URL unset — cannot derive egress host")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname:
        sys.exit(f"error: {prefix}_MODEL_BASE_URL must be an https URL, got {base!r}")
    return [f"{parsed.hostname}:{parsed.port or 443}"]


def _host_allowed(target: str, allow: set[str]) -> bool:
    """Mirror of the egress proxy's matcher — keep in sync with it."""
    t = target.lower()
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


def check_egress_satisfied(proxy_allow_csv: str) -> None:
    """Preflight: exit non-zero if any required host is not covered by the
    running proxy's allowlist."""
    allow = {h.strip().lower() for h in proxy_allow_csv.split(",") if h.strip()}
    missing = [h for h in required_egress_hosts() if not _host_allowed(h, allow)]
    if missing:
        sys.exit(
            f"error: egress proxy allowlist ({proxy_allow_csv}) does not cover "
            f"required host(s): {', '.join(missing)}"
        )
