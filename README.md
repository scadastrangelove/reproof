# Reproof

**Reproduction + proof. PoC or it didn't happen.**

Reproof is an agentic security-research pipeline: autonomous agents hunt for
vulnerabilities, but no claim counts until it survives refutation — replayed
in a fresh container, gated on declared premises, judged against known bugs,
and attacked once more after patching.

The name is the method: **repro**duction + **proof**. A secondary reading is
intentional — the pipeline issues *reproofs* to unproven agent claims.

- Multi-language from day one (Rust, C/C++, kernel, mobile profiles) — not a
  Rust-only tool.
- Model-backend-pluggable; the first backend is
  [Kimi Code CLI](https://github.com/MoonshotAI/kimi-code) (`kimi -p
  --output-format stream-json`).
- Descended from
  [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) and,
  upstream of it, Anthropic's
  [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness).

## Status

Phase 1 complete: the full pipeline core (find / grade / judge / report /
recon / patch / predisclose / reattack) runs on the Kimi Code CLI backend
(`reproof/agent_kimi.py`), with the upstream test suite green against the
port (392 passed, 4 skipped). Phase 2 adds the sandbox entrypoint
(`bin/reproof-sandboxed`, `scripts/setup_sandbox.sh`); an end-to-end live run
requires a Linux host with Docker (gVisor is Linux-only).

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
| 2 | Sandbox entrypoint | `bin/reproof-sandboxed` + setup script; live canary run on a Linux host under gVisor with Kimi-only egress |
| 3 | Skills port | `/threat-model`, `/variant-scan`, `/triage` etc. load via `--skills-dir` and produce identical artifact schemas |
| 4 | Benchmark parity | DVRA-3 recall on the Kimi backend measured against the recorded Claude baseline |

## License and attribution

Apache-2.0. Upstream copyright (Anthropic PBC) and the rust-in-peace lineage
are retained where code is carried over.
