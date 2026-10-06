# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""ZCode app-server backend — contract per docs/adr/ADR-002-agent-backend-zcode.md.

Unlike the kimi backend (`docker exec kimi -p`), ZCode's one-shot `-p` has no
model-selection source; the sanctioned headless surface is the app-server
protocol (`zcode app-server`, NDJSON "ZCode Protocol v4"). Reproof drives it
through a thin node shim (`agent_zcode_shim.mjs`, seeded by the Phase-0
harness on the Tamm runner) that speaks v4 and emits simplified JSONL:

    {"type":"session","sessionId":...}
    {"type":"turn","kind":"started|completed|failed","turnId":...}
    {"type":"row","kind":"assistantText|userInput|turnHeader|toolCall|...",
     "rowId":...,"turnId":...,"state":...,"text":...}
    {"type":"done",...} | {"type":"error","message":...}

This module spawns the shim inside the agent container, feeds it the prompt
on stdin, and maps its stream into the shared AgentResult: every completed
assistantText row is ALSO appended as a canonical ``{role: "assistant",
content}`` event, so ``AgentResult.find_tagged_message`` and all downstream
stage code (find/grade/judge/report) work unchanged — the third stream
dialect is normalized at the boundary.

Verified contract (ADR-002, 2026-10-05, from-source build pinned at zai-org/
ZCode 29628c9): custom api-key provider via the personal overlay file
(ZCODE_BUILTIN_PROVIDER_CONFIG_FILE + ZCODE_PERSONAL_PROVIDER_CONFIG_FILE env
pair, HOME-redirected state), v4 createSession with config+firstInput
modelSelection carrying options.reasoningLevel (REQUIRED by the model
factory), conversation frames via v4/conversation/subscribe, multi-turn
tool loop observed end-to-end.

Not yet implemented (ADR-002 adapter milestones): per-stage tool allowlist
(the v4 session/permission surface; default surface is 20 tools — see R7),
turn budget (no max-turns analog exists; wall-clock watchdog only), resume
across shim restarts (v4 base resync).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from . import redact
from .agent_kimi import AgentResult, color

# Baked into the agent image next to the CLI (agent_image analog of
# KIMI_CODE_HOME); the shim + CLI live in /opt/reproof.
SHIM_PATH = "/opt/reproof/zcode-shim.mjs"
# Pipeline provider id in the personal overlay; run_agent writes
# /work/.reproof-provider.json per attempt from ZCODE_MODEL_* env (the analog
# of kimi's write_kimi_config — ADR-002 R4).
PROVIDER_ID = "reproof"
PROVIDER_CONFIG_PATH = "/work/.reproof-provider.json"
BUILTIN_CONFIG_PATH = "/opt/reproof/conf/zcode-builtin.json"
# app-server --cwd / docker exec -w and the shim's ZCODE_WORKSPACE agree on this.
WORKSPACE = "/work"
# ZCode ignores classic HTTP(S)_PROXY for provider traffic; only these ZCODE_*
# knobs reach model egress (parsed into config.network by env-config.adapter and
# kept by SANITIZED_RUNTIME_ENV_KEYS). Forwarded from host env when set (R4b).
PROXY_FORWARD_KEYS = ("ZCODE_HTTP_PROXY", "ZCODE_NO_PROXY", "ZCODE_AGENT_CA_CERT")


def api_type_for(base_url: str) -> str:
    """Protocol type for the personal overlay's api block.

    ZCODE_MODEL_API_TYPE overrides; otherwise derived from the endpoint: the
    GLM Coding Plan key (subscription billing) is anthropic-messages at
    https://api.z.ai/api/anthropic — see the zai-api template in the pinned
    builtin catalog — while standard OpenAI-compatible bases stay
    openai-chat-completions.
    """
    explicit = os.environ.get("ZCODE_MODEL_API_TYPE")
    if explicit:
        return explicit
    if "/api/anthropic" in base_url:
        return "anthropic-messages"
    return "openai-chat-completions"


def provider_config_json(model_id: str, base_url: str, api_key: str) -> str:
    """Render the personal-overlay file (STRICT schema — ADR-002 R4).

    The manual model config is the validated Phase-0 recipe: missing
    optionSpecs/properties keys make the registry drop the whole file
    SILENTLY (providerCount stays 0).
    """
    cfg = {
        "schemaVersion": 1,
        "config": {
            "providerConfigRules": {"providerRules": [{
                "providerId": PROVIDER_ID, "providerName": "reproof",
                "enabled": True,
                "config": {
                    "group": "standard-personal",
                    "access": {"type": "api-key", "apiKey": api_key},
                    "api": {"type": api_type_for(base_url),
                            "baseUrl": base_url},
                    "personalModelIds": [model_id],
                },
            }]},
            "modelConfigRules": {
                "providerModelRules": [],
                "manualProviderModelRules": [{
                    "providerId": PROVIDER_ID, "modelId": model_id,
                    "config": {
                        "enabled": True,
                        "properties": {
                            "contextWindow": 131072,
                            "supportsJsonSchemaOutput": True,
                            "inputFormat": {"supportsImage": False,
                                            "supportsVideo": False,
                                            "supportsPdf": False},
                            "supportsMidConversationSystem": True,
                            "supportsNativeWebSearch": False,
                        },
                        "optionSpecs": {
                            # Official glm-5 rule from the pinned builtin
                            # catalog: values disabled/enabled, map "{}" (the
                            # CLI translates the level itself; a custom map
                            # injected a string `thinking` param the z.ai
                            # anthropic endpoint rejects with 400).
                            "reasoningLevel": {
                                "values": ["disabled", "enabled"],
                                "map": "{}",
                            },
                            "maxOutputTokens": {"max": 64000},
                        },
                    },
                }],
            },
            "defaultModelSelection": {"providerId": PROVIDER_ID,
                                      "modelId": model_id},
        },
    }
    return json.dumps(cfg, indent=1)


def write_provider_config(container: str, model_id: str) -> None:
    """Write /work/.reproof-provider.json from ZCODE_MODEL_* host env.

    Skipped when the env pair is unset (dev smokes seed the files by hand);
    mirrors kimi's write_kimi_config call site inside run_agent.
    """
    base_url = os.environ.get("ZCODE_MODEL_BASE_URL")
    api_key = os.environ.get("ZCODE_MODEL_API_KEY")
    if not (base_url and api_key):
        return
    from . import docker_ops  # local import: agent layer stays docker-free
    docker_ops.write_file(
        container, PROVIDER_CONFIG_PATH,
        provider_config_json(model_id, base_url, api_key).encode())


def shim_env(provider: str, model: str, reasoning: str = "enabled") -> dict[str, str]:
    """Env for the shim inside the container (beyond the sandbox-forwarded
    ZCODE_BUILTIN_PROVIDER_CONFIG_FILE / ZCODE_PERSONAL_PROVIDER_CONFIG_FILE
    pair and HOME override, which agent_env / run_agent set up)."""
    return {
        "ZCODE_CLI": "/opt/reproof/zcode.cjs",
        "ZCODE_WORKSPACE": WORKSPACE,
        "ZCODE_PROVIDER": provider,
        "ZCODE_MODEL": model,
        "ZCODE_REASONING": reasoning,
    }


async def run_agent(
    prompt: str,
    *,
    container: str,
    max_turns: int,  # unused: no loop_control analog (ADR-002 R6) — wall-clock only
    model: str,      # "provider/model" (e.g. "stub/glm-test"); provider defaults to "stub"
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,       # no-op by decision (ADR-002 R7): all default
                                          # tools stay enabled; gVisor is the only boundary.
                                          # Kept for call-site contract parity with kimi.
    system_prompt: str | None = None,     # carried by the stage workspace AGENTS.md (R7)
    agent_file: str | None = None,        # compat no-op: kimi API; zcode uses workspace
                                          # AGENTS.md (R7), not an agent file
    max_resume_attempts: int = 20,        # compat no-op: shim crash = run failure (v1);
                                          # cross-process resume is ADR-002 milestone 3
    reasoning_level: str = "enabled",
    timeout_s: int = 1800,
) -> AgentResult:
    """Run one ZCode agent session inside ``container`` via the shim.

    Upstream discipline preserved: stream events, persist an fsync'd
    transcript, never lose a partial AgentResult. Termination is the shim's
    ``done`` frame (quiet-watchdog after a completed turnHeader) or the
    wall-clock timeout — the documented budget deviation.
    """
    result = AgentResult()
    if "/" in model:
        provider, model_id = model.split("/", 1)
    else:
        provider, model_id = PROVIDER_ID, model
    # Per-attempt provider config from ZCODE_MODEL_* env (ADR-002 R4); no-op
    # when unset (hand-seeded dev containers).
    write_provider_config(container, model_id)
    assistant_count = 0

    env = shim_env(provider, model_id, reasoning_level)
    env["ZCODE_SHIM_TIMEOUT_MS"] = str(timeout_s * 1000)
    # Model-traffic egress (ADR-002 R4b): forward the ZCODE_* proxy/CA knobs from
    # the host so a mitm recorder / corporate proxy applies to the provider API.
    # NOTE: ZCODE_AGENT_CA_CERT is a path INSIDE the container (node's `ca`
    # REPLACES the default trust store — the PEM must carry the recorder CA).
    for _k in PROXY_FORWARD_KEYS:
        _v = os.environ.get(_k)
        if _v:
            env[_k] = _v
    # docker exec env flags must precede "--" or they become argv to the shim
    argv = ["docker", "exec", "-i", "-w", "/work"]
    for k, v in env.items():
        argv += ["-e", f"{k}={v}"]
    argv += ["--", container, "node", SHIM_PATH]

    transcript_file = open(transcript_path, "w") if transcript_path else None
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=16 * 1024 * 1024,
        )
        assert proc.stdin and proc.stdout
        proc.stdin.write(json.dumps({"prompt": prompt}).encode() + b"\n")
        await proc.stdin.drain()

        async def read_stderr() -> None:
            assert proc.stderr
            async for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").strip()
                if line and progress_prefix:
                    print(f"{progress_prefix}   [shim] {line[:160]}",
                          file=sys.stderr, flush=True)

        stderr_task = asyncio.create_task(read_stderr())
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

                etype = event.get("type")
                if etype == "session":
                    result.session_id = event.get("sessionId")
                elif etype == "row":
                    kind = event.get("kind")
                    if kind == "assistantText" and event.get("state") == "complete":
                        text = event.get("text") or ""
                        # Canonical assistant event: downstream stage code
                        # (find_tagged_message et al.) consumes this unchanged.
                        result.messages.append({"role": "assistant", "content": text})
                        assistant_count += 1
                        if progress_prefix:
                            print(f"{progress_prefix}   · {text[:140]!r}",
                                  file=sys.stderr, flush=True)
                        if assistant_count % heartbeat_every == 0:
                            print(f"  [agent] {assistant_count} assistant rows")
                    elif kind == "toolCall" and progress_prefix:
                        print(color(f"{progress_prefix}   → tool call (row {event.get('rowId')})",
                                    "dim", sys.stderr), file=sys.stderr, flush=True)
                elif etype == "turn" and event.get("kind") == "turn-failed":
                    result.error = result.error or f"turn failed: {event.get('turnId')}"
                elif etype == "error":
                    result.error = event.get("message")
                elif etype == "done":
                    break
        finally:
            stderr_task.cancel()
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()
        return result
    except Exception as e:  # noqa: BLE001 — upstream resume discipline
        result.error = result.error or f"{type(e).__name__}: {e}"
        return result
    finally:
        if transcript_file:
            transcript_file.close()


def parse_shim_transcript(lines: list[str]) -> list[dict[str, Any]]:
    """Shim JSONL → event list (assistant rows canonicalized). Unit-testable
    against tests/fixtures/zcode_shim_e2e.jsonl (captured from the verified
    Phase-0 E2E run, tool round-trip included)."""
    events: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.append(event)
        if (event.get("type") == "row" and event.get("kind") == "assistantText"
                and event.get("state") == "complete"):
            events.append({"role": "assistant", "content": event.get("text") or ""})
    return events
