# Reproof

**Reproduction + proof. PoC or it didn't happen.**

Reproof is an agentic security-research pipeline: autonomous agents hunt for
vulnerabilities, but no claim counts until it survives refutation — replayed
in a fresh container, gated on declared premises, judged against known bugs,
and attacked once more after patching.

The name is the method: **repro**duction + **proof**. A secondary reading is
intentional — the pipeline issues *reproofs* to unproven agent claims.

- Multi-language from day one (Rust, C/C++, kernel, mobile, ai-agent profiles) —
  not a Rust-only tool.
- Model-backend-pluggable; the reference backend is
  [Kimi Code CLI](https://github.com/MoonshotAI/kimi-code) (`kimi -p
  --output-format stream-json`).
- **Reproof is the Kimi port of
  [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace)**: the same
  find → grade → judge → reattack pipeline discipline, ported from the
  Claude/Codex agent runtime to the Kimi Code CLI, with the interactive skills
  auto-discovered from `.agents/skills/`. rust-in-peace itself builds on
  Anthropic's
  [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness).

## Using this repo

Two ways in: **interactive skills** (no setup, safe, start here) and the
**autonomous pipeline** (Docker + gVisor on a Linux host, scales to many
parallel agents).

- **Step 1 — Interactive skills.** Open a Kimi Code session in this repo;
  the skills in `.agents/skills/` are auto-discovered. Say `quickstart` for
  a 30-second orientation, then `/threat-model`, `/vuln-scan`, `/triage`
  against `targets/rust-canary` (read-only, repo-local).
- **Step 2 — The pipeline.** On a Linux host: `scripts/setup_sandbox.sh`
  once, then `bin/reproof-sandboxed run rust-canary --model "$KIMI_MODEL_NAME"
  --runs 3 --parallel --stream`. See `docs/pipeline.md`.
- **Step 3 — Make it yours.** Port the pipeline to another stack with
  `/customize`; adding a target is a directory under `targets/` — see
  `targets/README.md` and `docs/customizing.md`.
- **Step 4 — Fix what you find.** `reproof patch results/<target>/<ts>/`
  generates candidate fixes verified on the T0→T2 + re-attack ladder —
  see `docs/patching.md`.

## Status

The original port roadmap (phases 0–4) is complete, including live runs on a
Linux runner and **DVRA-3 benchmark parity** with the Claude baseline (2/3 find,
gold-seed PoC, 10/10 MEDIUM, reattack reproduced, scorecard exit 0 —
`targets/dvra3-parser/README.md`). Since then:

- **ai-agent profile** shipped: contracts/evidence/runtime package, reusable
  lab-adapter pack (mock LLM, MCP stdio/HTTP, ACP, PTY), `internal-lan` runtime
  mode, first wired end-to-end runs (471 tests green) — see
  `docs/extending-ai-agents.md`.
- **3-lens campaign benchmarks** (blind / threat-model / cve-seeded) ran against
  real targets — h2, rustls, rustdesk (hbb_common), x509-parser and more; the
  campaign findings are all fixed upstream (`targets/*/README.md` carry the
  remediation status).
- **Port-fidelity audit** against the upstream harness:
  `docs/port-fidelity-audit.md` (pipeline verbatim, prompts untouched; the two
  contamination bugs it found — `.git` history in target images and the
  reattack-template leak — are fixed with regression tests).
- Work backlog: `docs/IMPROVEMENTS.md` (W49–W65 shipped, incl. the
  multi-candidate find loop and guard-inventory prompt discipline).

## Running (Linux host)

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
export KIMI_MODEL_NAME=... KIMI_MODEL_API_KEY=... KIMI_MODEL_BASE_URL=https://...
scripts/setup_sandbox.sh                      # one-time: runsc, egress proxy, images
bin/reproof-sandboxed run canary --model "$KIMI_MODEL_NAME" --runs 3 --parallel --stream
```

## Roadmap

| Phase | Goal | Done when |
|---|---|---|
| 0 | Verify Kimi headless contract | resume / stream-json / system-prompt / tool-restriction / max-turns behavior measured and recorded in ADR-001 ✅ |
| 1 | Agent adapter + harness port | all stages ported; upstream test parity (392 passed) ✅ |
| 2 | Sandbox entrypoint | `bin/reproof-sandboxed` + setup script; live canary run on a Linux host under gVisor with Kimi-only egress ✅ |
| 3 | Skills port | all 10 skills auto-discovered from `.agents/skills/` by the Kimi CLI; docs ported; quickstart verified live ✅ |
| 4 | Benchmark parity | ✅ DVRA-3 on Kimi == Claude baseline: 2/3 find, gold-seed PoC, 10/10 MEDIUM, reattack reproduced, scorecard exit 0 (`targets/dvra3-parser/README.md`) |
| 5 | AI-agent profile | contracts/evidence/runtime + lab-adapter pack; wired e2e + tool-level mechanism replay 3/3 (W63); 471 tests ✅ |
| 6 | Recall engineering | W64 multi-candidate find loop shipped (per-candidate grading/dedup/judge); W65 guard-inventory prompt discipline; effectiveness measured by the 3-lens × 2-model kimi-code campaign — pending |

## License and attribution

Apache-2.0. Upstream copyright (Anthropic PBC) and the rust-in-peace lineage
are retained where code is carried over.
