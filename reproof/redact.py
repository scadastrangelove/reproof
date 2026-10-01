# SPDX-License-Identifier: Apache-2.0
# Ported from rust-in-peace harness/redact.py (Copyright 2026 Anthropic PBC),
# with the credential key set retargeted to the Kimi auth surface (ADR-001 R5).
"""Secret redaction for anything written to disk.

The agents run inside a sandbox that carries the model-API credential in its
env (so the in-container ``kimi -p`` can authenticate). A prompt-injected
agent — or a benign ``env`` / build dump — can echo that credential into a
tool result or assistant message, which the transcript writer otherwise
persists verbatim to results/.

This module scrubs the *live secret values* (read from the harness process
env, the same source ``reproof.auth.resolve_auth_env`` uses) out of any
string before it is written to disk. It targets values, not keys, so it
catches the secret no matter which field it lands in. Cheap: a handful of
`str.replace` over the already-serialized line.

Note: this mitigates leakage into transcripts. It does NOT solve the
architectural issue inherited from upstream (credential lives in the env of
the container running untrusted target code) — that fix is the
credential-injecting proxy, tracked on the security roadmap.
"""
from __future__ import annotations

import functools
import os

# The env vars whose *values* are credentials. Mirrors auth.resolve_auth_env
# plus the Kimi Code CLI's other credential-bearing variables (registry /
# web services).
_SECRET_ENV_KEYS = (
    "KIMI_MODEL_API_KEY",
    "KIMI_API_KEY",
    "KIMI_REGISTRY_API_KEY",
    "KIMI_WEB_SEARCH_API_KEY",
    "KIMI_WEB_FETCH_API_KEY",
)
PLACEHOLDER = "***REDACTED-SECRET***"

# Don't redact trivially short values (avoids nuking e.g. an empty/placeholder
# env into every line). Real tokens are long.
_MIN_SECRET_LEN = 12


@functools.lru_cache(maxsize=1)
def _secret_values() -> tuple[str, ...]:
    """Distinct credential values present in this process's env, longest first
    (so a token that contains a shorter one is replaced whole). Cached: auth is
    resolved once at startup and the env is stable for the run."""
    vals = {
        v for k in _SECRET_ENV_KEYS
        if (v := os.environ.get(k)) and len(v) >= _MIN_SECRET_LEN
    }
    return tuple(sorted(vals, key=len, reverse=True))


def scrub(text: str) -> str:
    """Replace every live credential value in ``text`` with a placeholder. A
    no-op when no secrets are in the env (or none appear in the text)."""
    for v in _secret_values():
        if v in text:
            text = text.replace(v, PLACEHOLDER)
    return text


def reset_cache() -> None:
    """Test hook — re-read the env after a test mutates it."""
    _secret_values.cache_clear()
