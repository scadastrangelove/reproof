# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""Kimi Code CLI headless backend — contract verified against CLI 2.1.1.

Mirrors the upstream `harness/agent.py:run_agent()` contract so all stage
code (find / grade / judge / report / patch) stays backend-agnostic:

    docker exec <container> kimi -p <prompt> --output-format stream-json

Verified contract (docs/adr/ADR-001-agent-backend-kimi.md, Phase 0):
  * events: meta/system.version → assistant(content|tool_calls[]) → tool →
    final assistant → meta/session.resume_hint; NO result sentinel —
    process exit terminates the stream
  * resume: `--session <id>` yields ONLY new events; --agent-file is
    first-attempt-only (incompatible with --session)
  * system prompt + tools: generated agent Markdown (--agent-file);
    `tools: []` disables all tools
  * budget: $KIMI_CODE_HOME/config.toml [loop_control] max_steps_per_turn;
    exhaustion = rc 1 + stderr message, stream ends silently
  * auth: KIMI_MODEL_NAME / KIMI_MODEL_API_KEY / KIMI_MODEL_BASE_URL env —
    nothing on disk
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from . import redact

DEFAULT_TOOLS = ["Read", "Write", "Bash"]

_ANSI = {
    # signal level
    "dim": "2;90",   # low-signal progress (tool calls) — dim + bright-black = faintest grey
    "red": "91",     # crash landed
    "bold": "1",     # verified / important finding
    # phase (start-of-phase lines so interleaved agents are scannable)
    "recon": "96",   # cyan
    "find": "94",    # blue
    "grade": "93",   # yellow
    "judge": "95",   # magenta
    "report": "92",  # green
    "patch": "92",   # green (never interleaves with report)
}


def color(text: str, name: str, stream=sys.stdout) -> str:
    """Wrap ``text`` in ANSI color ``name`` if ``stream`` is a TTY.

    dim  — low-signal progress lines (tool calls)
    red  — a crash landed
    bold — verified / important findings

    No-op when piped or redirected so grep/tee/log files stay clean.
    """
    if not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{_ANSI[name]}m{text}\033[0m"


@dataclass
class AgentResult:
    """Backend-neutral collected output of one agent run.

    Field-for-field compatible with the upstream AgentResult so judge /
    grade / report code consumes either backend unchanged. ``messages``
    holds raw Kimi stream-json events.
    """
    messages: list[dict] = field(default_factory=list)
    result_message: dict | None = None      # unused on Kimi (no sentinel)
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

    def last_assistant_message(self) -> str:
        """Last assistant text in the run ("" if none). Upstream parity."""
        for msg in reversed(self.messages):
            text = normalize_message_text(msg)
            if text is not None:
                return text
        return ""

    def transcript(self) -> list[dict]:
        """JSON-serializable transcript for persistence (tool output clipped)."""
        return [_truncate_tool_results(m) for m in self.messages]


def _truncate_tool_results(msg: dict) -> dict:
    """Clip large tool output (ASAN traces) for transcript persistence.

    Handles both event shapes: Kimi stream-json (``role: tool`` with string
    or block-list ``content``) and the upstream Anthropic shape (``type:
    user`` with ``tool_result`` blocks inside ``message.content``).
    """
    if msg.get("role") == "tool":
        content = msg.get("content")
        if isinstance(content, str) and len(content) > 5000:
            return {**msg, "content": content[:5000]}
        if isinstance(content, list):
            return {**msg, "content": [
                ({**x, "text": x.get("text", "")[:5000]}
                 if isinstance(x, dict) and len(x.get("text", "")) > 5000 else x)
                for x in content[:10]
            ]}
        return msg
    if msg.get("type") != "user":
        return msg
    inner = msg.get("message", {})
    content = inner.get("content")
    if not isinstance(content, list):
        return msg
    clipped = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result":
            c = b.get("content")
            if isinstance(c, str):
                b = {**b, "content": c[:5000]}
            elif isinstance(c, list):
                b = {**b, "content": [
                    ({**x, "text": x.get("text", "")[:5000]} if isinstance(x, dict) else x)
                    for x in c[:10]
                ]}
        clipped.append(b)
    return {**msg, "message": {**inner, "content": clipped}}


def normalize_message_text(raw: dict) -> str | None:
    """Plain assistant text from one event, or None for non-text events.

    Accepts the Kimi stream-json shape (``role: assistant`` + string
    ``content``) and the upstream Anthropic shape (``type: assistant`` +
    ``message.content`` block list) so AgentResult stays consumable by
    backend-agnostic stage code and upstream fixtures alike.
    """
    if raw.get("role") == "assistant":
        content = raw.get("content")
        if isinstance(content, str) and content:
            return content
    if raw.get("type") == "assistant":
        message = raw.get("message") or {}
        blocks = message.get("content")
        if isinstance(blocks, list):
            texts = [b.get("text", "") for b in blocks
                     if isinstance(b, dict) and b.get("type") == "text"]
            joined = "".join(texts)
            if joined:
                return joined
    return None


def iter_tool_calls(raw: dict) -> list[tuple[str, str]]:
    """(tool_name, key_arg) pairs from an assistant event; may be a batch."""
    if raw.get("role") != "assistant":
        return []
    out = []
    for tc in raw.get("tool_calls") or []:
        fn = tc.get("function") or {}
        args = fn.get("arguments") or ""
        key_arg = ""
        try:
            parsed = json.loads(args)
            key_arg = str(parsed.get("command") or parsed.get("file_path")
                          or parsed.get("path") or parsed.get("pattern") or "")
        except (json.JSONDecodeError, AttributeError):
            pass
        out.append((fn.get("name", "?"), key_arg.replace("\n", " ")[:120]))
    return out


def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract <tag>...</tag> content. Tags are markers in prose, not XML."""
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


def write_agent_file(path: str, *, name: str, description: str,
                     tools: list[str] | None, system_prompt: str) -> None:
    """Materialize a Kimi agent Markdown file for one pipeline stage.

    tools=None -> allowlist omitted (all tools); tools=[] -> no tools
    (judge/compare/report-grader agents upstream get no tools).
    """
    if tools is None:
        tools_yaml = ""
    else:
        tools_yaml = "tools: [" + ", ".join(tools) + "]\n"
    with open(path, "w") as f:
        f.write(f"---\nname: {name}\ndescription: {description}\n"
                f"{tools_yaml}---\n\n{system_prompt}\n")


def build_argv(container: str, prompt: str, *, model: str,
               agent_file: str | None, session_id: str | None) -> list[str]:
    """`docker exec ... kimi` argv for one attempt.

    -p mode auto-approves routine calls (--auto is rejected with -p); static
    deny rules from config.toml still apply. agent_file is first-attempt
    only: --session already restores the session's agent.
    """
    argv = ["docker", "exec", "-i", "-w", "/work", "--", container, "kimi",
            "-p", prompt, "--output-format", "stream-json",
            "--model", model]
    if session_id:
        argv += ["--session", session_id]
    elif agent_file:
        argv += ["--agent-file", agent_file]
    return argv


# Where agent_image bakes $KIMI_CODE_HOME (ENV in the base Dockerfile).
KIMI_CODE_HOME = "/opt/reproof/kimi-home"


def kimi_config_toml(model: str, *, max_steps: int,
                     base_url: str | None = None,
                     provider_type: str | None = None) -> str:
    """Render the agent container's config.toml.

    Defines the model alias the pipeline passes via ``--model``: the
    env-synthesized ``__kimi_env_model__`` is invisible to ``-m`` (highest
    priority, alias must exist — verified live), so a real
    ``[providers]/[models]`` pair is required. The API key is referenced
    with ``api_key_env`` — it stays in the container env (forwarded by
    ``sandbox.agent_env``) and never touches disk.
    """
    import json as _json
    import os as _os
    q = lambda s: _json.dumps(s)  # JSON string escaping is TOML-compatible
    base_url = base_url if base_url is not None \
        else _os.environ.get("KIMI_MODEL_BASE_URL")
    provider_type = provider_type or \
        _os.environ.get("KIMI_MODEL_PROVIDER_TYPE") or "kimi"
    lines = [
        f"default_model = {q(model)}",
        "",
        "[providers.reproof]",
        f"type = {q(provider_type)}",
    ]
    if base_url:
        lines.append(f"base_url = {q(base_url)}")
    lines += [
        'api_key_env = "KIMI_MODEL_API_KEY"',
        "",
        f"[models.{q(model)}]",
        'provider = "reproof"',
        f"model = {q(model)}",
        "max_context_size = 262144",
        "",
        "[loop_control]",
        f"max_steps_per_turn = {int(max_steps)}",
        "",
    ]
    return "\n".join(lines)


def write_kimi_config(container: str, *, model: str, max_steps: int) -> None:
    """Write config.toml into the agent container (ADR-001 R4 budget home).

    Idempotent per container; called once per run_agent before the first
    attempt so both the model alias and the step budget match this run.
    """
    from . import docker_ops  # local import: agent layer must not hard-depend on docker
    toml = kimi_config_toml(model, max_steps=max_steps)
    docker_ops.write_file(container, f"{KIMI_CODE_HOME}/config.toml",
                          toml.encode())


def discover_session_id(container: str) -> str | None:
    """Newest on-disk session id inside the agent container, or None.

    Kimi's ``meta/session.resume_hint`` (the pipeline's usual session-id
    source) only arrives at a CLEAN stream end — a mid-stream connection
    drop never emits it, leaving nothing to resume. The CLI persists every
    session at ``$KIMI_CODE_HOME/sessions/wd_*/session_<uuid>/`` as it
    goes, so the newest directory is this agent's resumable state
    (containers are one-agent-per-run, so recency is unambiguous).
    """
    from . import docker_ops
    rc, out, _ = docker_ops.exec_sh(
        container,
        f"ls -td {KIMI_CODE_HOME}/sessions/*/session_* 2>/dev/null | head -1",
        timeout=15,
    )
    if rc != 0 or not out.strip():
        return None
    name = out.strip().rsplit("/", 1)[-1]
    return name if name.startswith("session_") else None


async def run_agent(
    prompt: str,
    *,
    container: str,
    max_turns: int,       # mapped to loop_control.max_steps_per_turn in the
                          # container's $KIMI_CODE_HOME/config.toml (ADR-001 §R4)
    model: str,
    agent_file: str | None = None,
    max_resume_attempts: int = 20,
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,       # baked into agent_file
    system_prompt: str | None = None,     # baked into agent_file
) -> AgentResult:
    """Run one Kimi agent session inside ``container``.

    Upstream discipline preserved: stream events, persist an fsync'd
    transcript, resume with capped exponential backoff on transient failure
    (incl. rc!=0 such as loop.max_steps_exceeded), never lose a partial
    AgentResult to an exception. Termination is process exit — Kimi's
    stream has no result sentinel.
    """
    result = AgentResult()
    attempt = 0
    assistant_count = 0

    # Model alias + step budget live in the container's config.toml: the
    # env-synthesized model is invisible to `-m`, so the alias must exist
    # (verified live: first canary run failed without this).
    write_kimi_config(container, model=model, max_steps=max_turns)

    # Stage callers pass system_prompt/tools the way upstream passed them to
    # `claude --system-prompt --tools`. Kimi takes both via an agent Markdown
    # file (ADR-001 R2/R3), so materialize one inside the container.
    # Written once per container — it is the session's agent on resume too.
    if agent_file is None and (system_prompt is not None or tools is not None):
        from . import docker_ops  # local import: agent layer must not hard-depend on docker
        agent_file = "/work/.reproof-agent.md"
        import io
        buf = io.StringIO()
        buf.write("---\nname: reproof-stage\ndescription: Pipeline stage agent\n")
        if tools is not None:
            buf.write("tools: [" + ", ".join(tools) + "]\n")
        buf.write("---\n\n")
        buf.write(system_prompt or "You are a pipeline stage agent.")
        buf.write("\n")
        docker_ops.write_file(container, agent_file, buf.getvalue().encode())

    transcript_file = open(transcript_path, "w") if transcript_path else None
    try:
        while True:
            argv = build_argv(
                container, prompt, model=model,
                agent_file=agent_file,
                session_id=result.session_id if attempt else None,
            )
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
                        transcript_file.write(
                            redact.scrub(json.dumps(event)) + "\n")
                        transcript_file.flush()

                    if event.get("role") == "assistant":
                        assistant_count += 1
                        if progress_prefix:
                            for name, arg in iter_tool_calls(event):
                                print(f"{progress_prefix}   → {name}: {arg}",
                                      file=sys.stderr, flush=True)
                        if assistant_count % heartbeat_every == 0:
                            print(f"  [agent] {assistant_count} msgs")
                    elif (event.get("role") == "meta"
                          and event.get("type") == "session.resume_hint"):
                        if result.session_id is None:
                            result.session_id = event.get("session_id")
            except Exception as e:  # noqa: BLE001 — upstream resume discipline
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                attempt += 1
                if result.session_id is None:
                    # Mid-stream drop: no resume_hint ever arrived — fall
                    # back to the CLI's on-disk session state.
                    result.session_id = discover_session_id(container)
                if result.session_id is None or attempt > max_resume_attempts:
                    result.error = f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    return result
                backoff = min(2 ** attempt, 300)
                print(f"[agent] {type(e).__name__} on attempt {attempt}, "
                      f"resuming in {backoff}s: {e}", file=sys.stderr)
                result.resume_count = attempt
                await asyncio.sleep(backoff)
                continue

            # Process exit terminates the stream (no result sentinel).
            rc = await proc.wait()
            stderr = b""
            if proc.stderr:
                stderr = await proc.stderr.read()
            if rc != 0:
                # e.g. loop.max_steps_exceeded — resumable with a fresh
                # budget if the caller chooses; here: record and resume
                # like a transient failure.
                attempt += 1
                if result.session_id is None:
                    result.session_id = discover_session_id(container)
                if result.session_id and attempt <= max_resume_attempts:
                    result.resume_count = attempt
                    backoff = min(2 ** attempt, 300)
                    print(f"[agent] kimi rc={rc} on attempt {attempt}, "
                          f"resuming in {backoff}s", file=sys.stderr)
                    continue
                result.error = (f"kimi rc={rc}: "
                                f"{stderr.decode(errors='replace')[:2000]}")
            return result
    finally:
        if transcript_file:
            transcript_file.close()
