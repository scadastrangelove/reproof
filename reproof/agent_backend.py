# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""Backend router: stages import run_agent from here, not from a backend.

``REPROOF_AGENT_BACKEND=kimi`` (default) | ``zcode`` selects the agent
backend per ADR-001/ADR-002. Both share ``AgentResult``/``parse_xml_tag``
(and text normalization) from ``agent_kimi`` — the zcode adapter emits
canonical ``{role: "assistant", content}`` events at its boundary so the
shared result type and all stage code work unchanged.
"""
from __future__ import annotations

import os

from .agent_kimi import (  # shared, backend-neutral (re-exported API)
    AgentResult,
    color,
    normalize_message_text,
    parse_xml_tag,
)
__all__ = ["run_agent", "AgentResult", "parse_xml_tag", "normalize_message_text", "color", "current_backend"]
from . import agent_kimi, agent_zcode


def current_backend() -> str:
    return os.environ.get("REPROOF_AGENT_BACKEND", "kimi").strip().lower()


def run_agent(prompt: str, **kwargs):
    """Dispatch to the selected backend's run_agent.

    Kwargs are the union of both signatures; each backend ignores what does
    not apply (agent_zcode: max_turns/agent_file/max_resume_attempts are
    accepted no-ops per ADR-002 R6/R7; kimi: reasoning_level is unused).
    """
    backend = current_backend()
    if backend == "zcode":
        return agent_zcode.run_agent(prompt, **kwargs)
    if backend == "kimi":
        return agent_kimi.run_agent(prompt, **kwargs)
    raise ValueError(
        f"unknown REPROOF_AGENT_BACKEND {backend!r} (want 'kimi' or 'zcode')")
