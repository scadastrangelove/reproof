---
name: verify
description: Verify pipeline changes end-to-end without docker — drive the real pinned Kimi CLI against a header-capturing stub server with the exact env resolve_auth_env() produces.
---

# Verifying pipeline changes on a docker-less host

The pipeline's real surface is the in-container `kimi -p` process and its
outbound API requests. Without docker, drive the same pinned CLI binary
directly with the env dict the pipeline would inject via `docker -e`.

## Recipe

1. **Get the pinned CLI** (version from `reproof/agent_image.py:KIMI_CODE_VERSION`):
   `npm install --no-save @moonshot-ai/kimi-code@<pin>` in a temp dir →
   binary at `node_modules/.bin/kimi`.
2. **Stub API server**: a tiny HTTP server that appends each request's
   headers to a JSONL file and returns a 400 (non-retryable, so the CLI
   exits fast; exit=1 is expected). Point the CLI at it via
   `KIMI_MODEL_BASE_URL=http://127.0.0.1:<port>/v1`.
3. **Build the agent env exactly as the pipeline does**:
   `python3 -c "from reproof.auth import resolve_auth_env; ..."` and dump to
   an `export`-lines file with `shlex.quote` (NEVER pass via `env $(...)`,
   word-splitting mangles values; `source` the file). Auth is env-only:
   `KIMI_MODEL_NAME` / `KIMI_MODEL_API_KEY` / `KIMI_MODEL_BASE_URL` — nothing
   is read from disk (ADR-001 R1).
4. **Emulate the container env**: `unset` any ambient `KIMI_*` var not in the
   resolved dict before sourcing — containers only ever see what
   `sandbox.agent_env()` forwards.
5. **Run**: `timeout 30 <cli> -p hi --model "$KIMI_MODEL_NAME"`, then read
   the captured JSONL. For stream-contract checks use
   `--output-format stream-json`; the fixtures from ADR-001
   (`tests/fixtures/kimi_streamjson_*.jsonl`) show the expected event shapes.

## Gotchas

- The docker `-e` injection leg itself can't be exercised without docker;
  it's the same mechanism that carries `KIMI_MODEL_API_KEY` in production.
- `--agent-file` is first-attempt-only (incompatible with `--session`
  resume) — a resumed agent keeps its original system prompt (ADR-001 R3).
- Budget is `[loop_control] max_steps_per_turn` in `$KIMI_CODE_HOME/config.toml`;
  exhaustion = rc 1 + a stderr message, and the stream ends silently with no
  sentinel (ADR-001 R5).
