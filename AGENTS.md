# Reproof — operator guide for agent CLIs

This repo has two halves:

- **Interactive skills** (`.agents/skills/`) — auto-discovered by the Kimi
  Code CLI from the repo root. Read and write files in the repo (no
  target-code execution): `/quickstart` (front door / Q&A), `/threat-model`
  (bootstrap, interview, or bootstrap-then-interview → `THREAT_MODEL.md`),
  `/vuln-scan` (static review → `VULN-FINDINGS.json`), `/variant-scan`
  (three-pass seed-diverse find), `/sast-driven`, `/sast-prioritise`,
  `/triage` (verify + dedupe + rank a findings pile), `/patch` (generate
  candidate fixes → `PATCHES/`), `/customize` (port the pipeline to another
  stack). (`/verify` is contributor tooling for validating pipeline changes
  on docker-less hosts, not part of the user flow.)
- **The pipeline** (`reproof/`) — the autonomous part. Docker +
  capability-routed detectors (rust: Miri/ASan/panic/hang + cargo-fuzz;
  cpp: ASan), executes target code, needs the sandbox (see
  `docs/security.md` and `docs/agent-sandbox.md`). Agents run as `kimi -p`
  processes inside per-target gVisor containers; the backend contract is
  pinned in `docs/adr/ADR-001-agent-backend-kimi.md`.

Docs for each topic are in `docs/`; targets are in `targets/` (`canary` is
the fast cpp smoke test, `rust-canary` the rust one). The pipeline is
profile-driven (`profiles/`): `rust` is the primary profile, `cpp` the
retained base.

## Running the pipeline

On a Linux host with Docker:

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
export KIMI_MODEL_NAME=... KIMI_MODEL_API_KEY=... KIMI_MODEL_BASE_URL=...
./scripts/setup_sandbox.sh                 # one-time: gVisor, egress proxy, images
bin/reproof-sandboxed run rust-canary --model "$KIMI_MODEL_NAME" --runs 3 --parallel --stream
```

gVisor is Linux-only. On macOS/Windows use a Linux VM, or
`--dangerously-no-sandbox` (development only — see `docs/agent-sandbox.md`
for what you lose).

Model is a runtime arg, not config: always `--model` or `REPROOF_MODEL`.
Each subcommand's flags: `reproof <cmd> --help`. Watching a run, resume-on-error,
rate limits, dedup, reports, patches: `docs/pipeline.md`,
`docs/troubleshooting.md`.

## Tests

`.venv/bin/python -m pytest tests/ -q` — unit coverage over the ported
upstream suite (`tests/test_upstream_*.py`, 380+ tests) plus the Kimi
backend contract tests (`tests/test_agent_kimi.py`, fixtures in
`tests/fixtures/kimi_streamjson_*.jsonl`). No integration tests that need
Docker in the default suite; `canary` / `rust-canary` are the live
integration paths on a Linux host.

## Gotchas

- **The agent backend is Kimi Code CLI 2.1.1** (`reproof/agent_image.py:KIMI_CODE_VERSION`),
  driven headless as `kimi -p <prompt> --output-format stream-json` with a
  generated agent Markdown file (`--agent-file` carries the system prompt
  and tool allowlist; first attempt only — resumes use `--session <id>`).
- **No stream sentinel.** The Kimi stream ends when the process exits;
  `meta/session.resume_hint` carries the session id. See ADR-001 for the
  full verified contract before touching `reproof/agent_kimi.py`.
- **Budget** is `[loop_control] max_steps_per_turn` in the container's
  `$KIMI_CODE_HOME/config.toml`; exhaustion = rc 1 + stderr, silent stream
  end. `reproof/agent_image.py` seeds the default; the run entrypoint
  rewrites it per attempt.
- **Auth is env-only** (`KIMI_MODEL_*`); never read credential files, never
  write keys to disk. Transcripts are scrubbed through `reproof/redact.py`.
- **`image_tag` in every `targets/*/config.yaml` is `reproof-<name>:latest`** —
  the agent image derives from it (`<tag>-agent:<cli-version>`); don't
  hand-edit tags without updating dependent fixtures.
