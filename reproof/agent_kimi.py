# SPDX-License-Identifier: Apache-2.0
"""Kimi Code CLI headless backend — adapter skeleton.

Mirrors the upstream `harness/agent.py:run_agent()` contract so all stage
code (find / grade / judge / report / patch) stays backend-agnostic:

    docker exec <container> kimi -p --output-format stream-json ...

Upstream responsibilities this module must reproduce:
  1. argv construction per attempt (prompt in argv, not stdin — ARG_MAX is
     fine, stdin delivery raced under high-parallel launch upstream)
  2. stream-json parsing -> normalized AgentResult
  3. session resume with exponential backoff (cap 300s, <=20 resumes)
  4. per-message transcript streaming with fsync + credential scrubbing
  5. heartbeat / progress lines on stderr

Phase-0 risks tracked in docs/adr/ADR-001-agent-backend-kimi.md are marked
TODO(Rn) at the exact code sites they block.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TOOLS = ["Read", "Write", "Bash"]

# Kimi Code CLI stream-json event shapes (verify against a live capture — R6).
# Expected coarse shape differs from Claude's content-block stream:
#   {"role": "assistant", "content": ..., "tool_calls": [...]}
#   {"role": "tool", ...}
# A capture fixture from a real `kimi -p --output-format stream-json` run
# belongs in tests/fixtures/ before the normalizer is trusted.


@dataclass
class AgentResult:
    """Backend-neutral collected output of one agent run.

    Field-for-field compatible with the upstream AgentResult so judge /
    grade / report code consumes either backend unchanged.
    """
    messages: list[dict] = field(default_factory=list)
    result_message: dict | None = None
    session_id: str | None = None
    error: str | None = None
    resume_count: int = 0

    def find_tagged_message(self, tag: str) -> str:
        """Most-recent assistant text containing <tag>, else last assistant text.

        The XML-tag contract (<poc_path>, <dup_check>, ...) is the pipeline's
        lingua franca and is backend-agnostic by design.
        """
        needle = f"<{tag}>"
        last_assistant = ""
        for msg in reversed(self.messages):
            text = normalize_message_text(msg)
            if text is None:
                continue
            if not last_assistant:
                last_assistant = text
            if needle in text:
                return text
        return last_assistant


def normalize_message_text(raw: dict) -> str | None:
    """Map one Kimi stream-json event to plain assistant text, or None.

    TODO(R6): implement against a captured fixture. Claude's stream uses
    {"type":"assistant","message":{"content":[{"type":"text",...}]}};
    Kimi emits role-based events with tool_calls. Only assistant text
    should survive normalization — tool calls and thinking are not tags.
    """
    if raw.get("role") == "assistant":
        content = raw.get("content")
        return content if isinstance(content, str) else None
    return None


def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract <tag>...</tag> content. Tags are markers in prose, not XML."""
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


def build_argv(container: str, prompt: str, *, model: str, max_turns: int,
               tools: list[str] | None, system_prompt: str | None,
               session_id: str | None) -> list[str]:
    """Construct the `docker exec ... kimi` argv for one attempt.

    TODO(R2): system_prompt — Claude takes --system-prompt; Kimi exposes
    agent YAML specs (system_prompt + tools). Pick the mechanism and record
    it in ADR-001.
    TODO(R3): tool restriction to Read/Write/Bash (none for judge agents).
    TODO(R4): max-turns equivalent (agent-spec max_steps?) and its
    exhaustion semantics.
    """
    argv = ["docker", "exec", "-i", "-w", "/work", "--", container, "kimi",
            "-p", prompt,
            "--output-format", "stream-json",
            "--auto",  # non-interactive approvals; gVisor is the boundary
            "--model", model]
    # TODO(R1): resume — Claude: --resume <session_id> "continue" yields only
    # NEW messages. Kimi: --session <id> / --continue. Verify new-only yield
    # before wiring, else dedupe by event id here.
    if session_id:
        argv += ["--session", session_id]
    return argv


async def run_agent(
    prompt: str,
    *,
    container: str,
    max_turns: int,
    model: str,
    max_resume_attempts: int = 20,
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,
    system_prompt: str | None = None,
) -> AgentResult:
    """Run one Kimi agent session inside ``container``.

    Contract copied from upstream run_agent(): stream events, persist a
    scrubbed fsync'd transcript, break on the FIRST terminal result, resume
    with capped exponential backoff on transient failure, never lose a
    partial AgentResult to an exception.
    """
    result = AgentResult()
    attempt = 0

    transcript_file = open(transcript_path, "w") if transcript_path else None
    try:
        while True:
            argv = build_argv(container, prompt, model=model,
                              max_turns=max_turns, tools=tools,
                              system_prompt=system_prompt,
                              session_id=result.session_id if attempt else None)
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=16 * 1024 * 1024,  # large tool results; upstream value
            )
            assert proc.stdout

            try:
                async for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    result.messages.append(event)
                    if transcript_file:
                        # TODO: redact.scrub() once the auth module lands —
                        # Moonshot credential patterns (R5).
                        transcript_file.write(json.dumps(event) + "\n")
                        transcript_file.flush()

                    # TODO(R6): terminal-result detection. Claude emits
                    # {"type":"result", "is_error":...} — break on the FIRST
                    # one. Kimi's terminal event shape is unverified; do not
                    # wait for stream exhaustion (background tasks keep the
                    # stream alive).
                    # TODO(R6): session_id capture from the init event.
            except Exception as e:  # noqa: BLE001 — upstream resume discipline
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                attempt += 1
                if result.session_id is None or attempt > max_resume_attempts:
                    result.error = f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    return result
                backoff = min(2 ** attempt, 300)
                print(f"[agent] {type(e).__name__} on attempt {attempt}, "
                      f"resuming in {backoff}s: {e}", file=sys.stderr)
                result.resume_count = attempt
                await asyncio.sleep(backoff)
                continue

            # Stream ended without a terminal event.
            rc = await proc.wait()
            result.error = f"kimi exited rc={rc} without terminal result"
            return result
    finally:
        if transcript_file:
            transcript_file.close()
