# Improvements backlog

Reproof's own work backlog. Numbering continues the rust-in-peace (RIP)
backlog (which ended at W48) so cross-references stay unambiguous.
Format: `- **W<n> — title** \`[L<n>][domain]\`. … **Done-when:** …`.
Lessons live in [`LESSONS.md`](LESSONS.md).

## Backlog refresh (2026-10-04) — post ai-agent dynamic wave (trusted replay: OmniRoute / goose / Open WebUI)

Sources: retrospective of the first full dynamic wave of the ai-agent profile (L61–L70) plus a parallel
session's notes from the same wave. Already shipped, not re-listed: the reusable lab-adapter pack (mock
LLM, MCP stdio/HTTP, ACP client, PTY driver, boot discipline, evidence emitter) lives under
`profiles/ai-agent/adapters/`; the `internal-lan` runtime mode for LAN-scope findings is shipped and
tested.

- **W49 [SHIPPED 2026-10-05] — scope controls to scenarios in trusted replay** `[L62][runtime]`. Controls currently run
  contract-wide inside every trial of every scenario, so one finding's broken fixture vetoes another
  finding's evidence, and control cost multiplies across unrelated scenarios. Add an optional `scenarios:`
  field to controls (absent = all, current behavior) and filter before the trial loop. **Done-when:**
  runtime + contract schema + tests land it, and a failing control of finding X can no longer error the
  trials of scenario Y.
- **W50 [SHIPPED 2026-10-05] — oracle pre-flight lint against the negative fixture** `[L61][replay]`. Contract validation (or a
  `replay --check` mode) resolves every oracle pointer against the negative-control fixture before a
  batch: unresolvable pointer on the negative = hard warning. Companion ritual in the runbook: one control
  run by hand in a debug container before any batch launch. **Done-when:** the two wave failures (absent
  optional header key; predicate written against the input layer instead of the observed layer) are both
  caught by the lint on a fixture contract, and the ritual is one line in the profile README.
- **W51 [SHIPPED 2026-10-05] — reachability control + refuted/inconclusive verdict split** `[L66][evidence]`. Every replay
  scenario gains an explicit positive reachability control ("did the attack input reach the sink?"),
  independent of the vulnerability oracle; `not_confirmed` splits into `refuted` (reachability passed,
  oracle false) vs `inconclusive_setup` (reachability failed). **Done-when:** the evidence schema and the
  runtime emit the split verdict, evidence.py renders it, and no ledger row carries a refuted whose
  reachability control did not pass.
- **W52 [SHIPPED 2026-10-05] — per-sub-claim verdicts** `[L68][evidence]`. Findings carry `subclaims[]`; each sub-claim is
  modeled as its own control with its own verdict; the finding verdict is a roll-up naming which
  sub-claims stand. **Done-when:** the scheduled-recipe shape (core confirmed + escalation refuted)
  serializes as exactly that, not a flat `not_confirmed`.
- **W53 [SHIPPED 2026-10-05] — refute requires a quoted source line in the judge** `[L67][verification]`. Judge prompt rejects
  REFUTE without a verbatim source citation (the guard that stops the vector / the gate that
  config-closes it); non-compliant refutes land as `unverified_refute` and are down-weighted in
  aggregation. **Done-when:** judge prompt + disposition vocab updated, and a regression fixture shows a
  source-less refute being reclassified.
- **W54 [SHIPPED 2026-10-05] — provenance gate in grade/replay** `[L70][measurement]`. Given candidate (path/symbol) + running
  artifact, assert byte-identity of the implicated file against the analyzed commit (or flag drift) before
  measuring; evidence carries `provenance:{analyzed_commit, tested_artifact, identical|drift}`.
  **Done-when:** a replay against a deliberately drifted artifact flags drift instead of producing a
  verdict, and the evidence schema carries the block.
- **W55 [SHIPPED 2026-10-05] — fail-closed hygiene linter on the output path** `[L69][disclosure]`. Pre-commit/pre-package
  redaction gate blocking `user@host` patterns, server IPs, local absolute paths (`/Users/...`), and
  credential-shaped strings; host configuration stays untracked. **Done-when:** a seeded leak is blocked
  locally and in CI, and profile docs reference hosts only through placeholders.
- **W56 [SHIPPED 2026-10-05] — sibling-breadth authz scan rule** `[L65][detection]`. New rule in the ai-agent scan-extras:
  enumerate list/read endpoints, compare response-schema breadth against sibling endpoints' gates, flag
  weaker-gate/broader-schema pairs (especially when a narrow safe schema exists unused in the same
  module). **Done-when:** the rule fires on a fixture repo carrying the wave pattern and stays quiet on
  properly gated siblings.
- **W57 [SHIPPED 2026-10-05] — SSRF egress-reachability primitive** `[lab]`. SSRF-class scenarios repeatedly need a
  public-looking host to pass URL validation while the lab is private. Ship a standard primitive:
  controlled redirector / egress-proxy + the "redirect → internal canary" pattern + an SSRF scenario
  template in the profile. **Done-when:** the template replays end-to-end against a fixture victim with no
  per-target improvisation.
- **W58 [SHIPPED 2026-10-05] — mount, don't bake: lab and adapters ride a volume** `[lab-discipline]`. Targets that mounted
  the lab dir iterated mocks in seconds; targets that baked adapters into the image paid a rebuild per
  edit. Make `-v lab:/work/lab` (and the adapter pack) the default in target runbooks; images rebuild only
  on dependency changes. **Done-when:** target READMEs/run scripts mount by default and the adapters
  README says so.
- **W59 — one full wired e2e run on an ai-agent canary** `[pipeline]`. This wave's confirmations ran
  largely through scripts around the harness; only single legs (grade → replay) are proven end-to-end.
  Run one ai-agent canary target through the complete find → grade → aggregate → scorecard path.
  **Done-when:** a scorecard artifact exists from a from-scratch pipeline run, with no out-of-band steps.
- **W60 — status lines generated from artifacts, not hand-maintained** `[docs]`. Profile/repo status
  strings drifted against reality twice this wave (verifier-only vs grade-leg-proven). Generate the status
  line from artifact presence (e.g. a pipeline-confirmed evidence file flips the claim). **Done-when:**
  the status line regenerates from the results tree and goes stale-red when artifacts are missing.
