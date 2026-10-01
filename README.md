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

Early bootstrap. Phase 0 is risk verification of the Kimi CLI headless
contract (see [ADR-001](docs/adr/ADR-001-agent-backend-kimi.md)); the adapter
skeleton lives at `reproof/agent_kimi.py`.

## Roadmap

| Phase | Goal | Done when |
|---|---|---|
| 0 | Verify Kimi headless contract | resume / stream-json / system-prompt / tool-restriction / max-turns behavior measured and recorded in ADR-001 |
| 1 | Agent adapter | `agent_kimi.py` passes the `agent.py` contract tests against a stub CLI, then live against `kimi` |
| 2 | Harness port | find → grade → judge → report runs end-to-end on a canary target under gVisor with Moonshot-only egress |
| 3 | Skills port | `/threat-model`, `/variant-scan`, `/triage` etc. load via `--skills-dir` and produce identical artifact schemas |
| 4 | Benchmark parity | DVRA-3 recall on the Kimi backend measured against the recorded Claude baseline |

## License and attribution

Apache-2.0. Upstream copyright (Anthropic PBC) and the rust-in-peace lineage
are retained where code is carried over.
