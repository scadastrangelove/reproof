# ADR-001 — Kimi Code CLI as the first agent backend

**Status:** accepted — Phase 0 verified live on Kimi Code CLI 2.1.1 (2026-10-01)
**Date:** 2026-10-01

## Context

Reproof descends from rust-in-peace / Anthropic's defending-code-reference-harness,
whose autonomous harness drives agents through Claude Code's headless CLI
(`claude -p --output-format stream-json`). The upstream coupling is narrow and
concentrated in four places:

| Coupling point | Role |
|---|---|
| `agent.py` (~370 LoC) | argv construction, stream-json parsing, session resume with exponential backoff (≤20 resumes), heartbeat/progress, transcript fsync |
| `agent_image.py` | `npm install -g @anthropic-ai/claude-code` inside the agent container image |
| `auth.py` | `ANTHROPIC_API_KEY` / OAuth / Bedrock / Vertex resolution |
| `redact.py` + egress proxy | credential scrubbing in transcripts; egress allowlist `api.anthropic.com:443` |

Everything downstream (XML-tag contract with agents, honesty gates, judge,
report grading, patch ladder) is model-agnostic by design. The upstream README
states a second backend "requires an adapter"; none exists.

## Decision

The first Reproof backend is **Kimi Code CLI** (`@moonshot-ai/kimi-code`,
MIT), driven headlessly inside the same gVisor container boundary:

```
docker exec <container> kimi -p "<prompt>" --output-format stream-json --auto
```

Rationale: the CLI exposes the full headless contract we need (single-prompt
mode, JSONL event stream, model selection, session resume, non-interactive
permission modes), it is cheap enough to make 12B-token research campaigns
economical, and it is model-pluggable itself (OpenAI-compatible endpoints), so
the adapter potentially unlocks other backends later.

## Risks to verify in Phase 0 (before writing the real adapter)

| # | Risk | Why it matters | Verification |
|---|---|---|---|
| R1 | **Resume semantics** | The pipeline resumes crashed sessions up to 20× and relies on `--resume` yielding *only new* messages. Kimi has `--session <id>` / `--continue`; whether `-p` + resumed session emits only new events in stream-json is unverified | Kill a session mid-run, resume, diff event streams |
| R2 | **Custom system prompt** | Every pipeline agent (find/grade/report/judge) carries a constructed system prompt. Claude has `--system-prompt`; Kimi exposes agent YAML specs (`system_prompt`, `tools`) — flag support in `-p` mode unverified | Run `kimi -p` with a canary system prompt, check obedience |
| R3 | **Tool restriction** | find/grade/report agents get exactly `Read, Write, Bash`; judge gets no tools. Equivalent mechanism (YAML spec or flag) unverified | Attempt a tool call outside the allowlist |
| R4 | **Turn budget** | `--max-turns` is the per-agent budget valve; Kimi's `max_steps` mapping and its exhaustion behavior unverified | Force exhaustion, observe exit semantics |
| R5 | **Auth in-container** | `kimi login` is interactive OAuth; containers need a non-interactive API-key path, and the egress proxy allowlist must switch to the Moonshot API host | Headless container login via env/config |
| R6 | **stream-json schema** | Kimi's event shapes (Assistant/Tool messages) differ from Claude's content-block stream; a normalizer into `AgentResult` is required | Capture and diff both schemas |

## Phase 0 verification results (2026-10-01, Kimi Code CLI 2.1.1)

All six risks verified live against `kimi -p --output-format stream-json`;
fixtures in `tests/fixtures/kimi_streamjson_*.jsonl`.

| # | Verdict | Evidence |
|---|---|---|
| R1 resume | **PASS** | `kimi -p ... --session <id>` yields ONLY new events; context preserved (resumed session recalled facts from the earlier turn); session id arrives in the terminal `meta/session.resume_hint` event (`kimi -r <id>` alias exists). Constraint: `--agent-file` cannot combine with `--session` — pass the agent file on the first attempt only |
| R2 system prompt | **PASS** | `--agent-file <md>`: YAML frontmatter + body IS the system prompt. Canary persona obeyed verbatim in `-p` mode. (`$KIMI_CODE_HOME/SYSTEM.md` is the permanent-override alternative) |
| R3 tool restriction | **PASS** | Frontmatter `tools: [Read, Bash]` allowlist; `tools: []` disables all tools (verified: agent asked to write a file produced text only, no file, no tool events). `disallowedTools` denylist also available; config.toml `[[permission.rules]]` adds static deny rules that apply even in `-p` |
| R4 turn budget | **PASS, config-only** | `[loop_control] max_steps_per_turn` in `$KIMI_CODE_HOME/config.toml`. On exhaustion: exit code 1, `loop.max_steps_exceeded` on stderr, stream ends WITHOUT a terminal error event — adapter must treat rc!=0 as resumable failure. Steps count LLM turns, not tool calls (parallel tool batches count once) |
| R5 auth | **PASS, env-only** | `KIMI_MODEL_NAME` + `KIMI_MODEL_API_KEY` + `KIMI_MODEL_BASE_URL` synthesize an in-memory provider/model — nothing written to disk, ideal for containers. `config.toml` providers with `api_key_env` is the persistent alternative. OAuth device flow exists (`kimi login`) but is not needed |
| R6 schema | **PASS** | Event kinds: `meta/system.version` (init) → `assistant` (with `content` and/or OpenAI-style `tool_calls[]`, possibly batched parallel calls) → `tool` (result, keyed by `tool_call_id`) → final `assistant` → `meta/session.resume_hint`. NO `{"type":"result"}` terminator: process exit closes the stream (background-task keep-alive defaults off). `--auto` is rejected with `-p` — prompt mode already auto-approves |

### Adapter decisions flowing from Phase 0

1. **Termination = process exit**, not a result sentinel (upstream broke on the
   first `result` message; Kimi has none). Partial-transcript preservation is
   unchanged.
2. **Resume**: `--session <id>` on attempts > 0, never `--agent-file` there.
3. **System prompt + tools**: one generated agent Markdown file per stage
   (find/grade/report/judge), written into the container's work dir.
4. **Budget**: ship a `$KIMI_CODE_HOME/config.toml` in the agent image with
   `loop_control.max_steps_per_turn` mapped from `--max-turns`.
5. **Auth**: `KIMI_MODEL_*` env into `docker run -e`; egress allowlist gains
   the configured base-URL host instead of `api.anthropic.com`.
6. **Normalizer**: `assistant.content` → text; `assistant.tool_calls` →
   progress lines; `tool` → transcript; both `meta` types → session
   bookkeeping.

## Consequences

- `reproof/agent_kimi.py` mirrors the `run_agent()` signature so stage code
  stays backend-agnostic.
- `redact` gains Moonshot credential patterns; the egress allowlist gains the
  Moonshot API host. The known upstream limitation (credential lives in the
  target-code container's env) is inherited unchanged and remains on the
  security roadmap — credential-injecting proxy.
- The Anthropic-specific usage marker (`anthropic-cyber-runbook`) is dropped.
