# ADR-001 — Kimi Code CLI as the first agent backend

**Status:** proposed (Phase 0 verification pending)
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

## Consequences

- `reproof/agent_kimi.py` mirrors the `run_agent()` signature so stage code
  stays backend-agnostic.
- `redact` gains Moonshot credential patterns; the egress allowlist gains the
  Moonshot API host. The known upstream limitation (credential lives in the
  target-code container's env) is inherited unchanged and remains on the
  security roadmap — credential-injecting proxy.
- The Anthropic-specific usage marker (`anthropic-cyber-runbook`) is dropped.
