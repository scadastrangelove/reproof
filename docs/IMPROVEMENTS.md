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
- **W59 [SHIPPED 2026-10-05] — one full wired e2e run on an ai-agent canary** `[pipeline]`. This wave's confirmations ran
  largely through scripts around the harness; only single legs (grade → replay) are proven end-to-end.
  Run one ai-agent canary target through the complete find → grade → aggregate → scorecard path.
  **Done 2026-10-05:** three-lens run (blind / threat-model / history) on `ai-agent-canary` with
  `kimi-for-coding` went find → tag-parse → schema-validation → replay-grade → judge → report → aggregate
  with zero out-of-band steps: 3/3 runs `crash_found`, all grades replay-confirmed (score 1.0), both
  planted invariants confirmed (`vault-authorization` ×2 lenses, `export-authorization` ×1), 3 reports
  (rubric 6–8/10, sev HIGH). Bring-up took five runs; each exposed exactly one seam, all fixed and
  pinned by tests (L71). Run log: `results/ai-agent-canary/20261004T223505Z/` on the runner host.
- **W61 — judge dedup across lens runs is too lenient on component naming** `[judge]`. Two runs found
  the SAME vault-read authz bypass (same invariant, same root cause, same lines) but named the component
  differently ("assistant-service.dispatch" vs "request-dispatch"); the judge marked both NEW and two
  reports were written. Tighten the judge prompt: dedup key is invariant + ROOT CAUSE, component strings
  are agent-invented and vary. **Done-when:** the canary three-lens run yields 2 bugs, not 3.
- **W62 — report agents try to run the replay inside the container** `[prompts]`. Report agents on the
  canary burned turns attempting `python -m reproof.ai_agent.runtime /tmp/poc.bin` inside the target
  container, where the harness does not exist. State in the ai-agent report prompt that replay is
  orchestrator-side and the container has no reproof install. **Done-when:** report transcripts show no
  replay attempts.
- **W60 — status lines generated from artifacts, not hand-maintained** `[docs]`. Profile/repo status
  strings drifted against reality twice this wave (verifier-only vs grade-leg-proven). Generate the status
  line from artifact presence (e.g. a pipeline-confirmed evidence file flips the claim). **Done-when:**
  the status line regenerates from the results tree and goes stale-red when artifacts are missing.
- **W63 [SHIPPED 2026-10-05] — tool-level mechanism replay for agent-CLI targets** `[pipeline]`. Findings whose violation
  lives in tool executors (path checks, permission chain, arg parsing) can be confirmed without a
  model: a node/python runner that calls the target's tool entrypoints in a fixture workspace, wired
  as a runtime adapter under `mode: mechanism`. **Done 2026-10-05:** kimi-code target: `lab/tool_probe.mjs`
  (importing the target's real `path-access` + permission-policy modules, esbuild-bundled at image
  build) + contract v2 (provenance-pinned implicated files) + two operator scenarios replayed 3/3
  with positive/negative controls green; verdict scope honestly `component`. Reuse note: the probe
  shape (stdin spec -> drive real module -> stdout observation JSON) ports to any JS/TS agent CLI;
  the `#/`-import + decorator gotchas are documented in the Dockerfile comment.
- **W64 [SHIPPED 2026-10-05] — multi-candidate find loop** `[pipeline]`. The find loop returned only the
  last submitted candidate per run; a find-agent that submits and stops capped recall at 1/run (the
  first kimi-code three-lens batch yielded 3 candidates at 3-4% of the turn budget, vs 19 in a
  parallel same-target campaign). `run_find` now extracts every complete `<poc_path>` submission
  (last tag block per path wins), `_run_once` grades each candidate in its own container and writes
  per-candidate result files (`result.json`, `result_2.json`, ...); dedup/aggregate read `result*.json`;
  the dup_check gate drops only the offending candidate; judge dispatch is per-candidate. Recall
  numbers (3-lens × 2-model kimi-code campaign, 2026-10-05): 2.33 candidates/run vs the 1.0 ceiling;
  3 unique classes vs 2 in the single-model batch. Follow-up fix same day (0405330): both models pack
  several submissions into ONE assistant message — extraction now splits per block; without it 6/14
  candidates (43%) were dropped pipeline-side and recovered post-hoc from transcripts.
- **W65 [SHIPPED 2026-10-05] — guard inventory before claims** `[prompts]`. Candidates clustered on the
  first hypothesis instead of systematically uncovered guard residue. The find prompt now makes a guard
  inventory load-bearing (auto-approve policies incl. non-interactive defaults, trust gates, denylists,
  egress, config→hot-reload — coverage AND uncovered residue per guard), and scan-extras gains AI10.
  Effectiveness (same campaign): finders opened with a real permission-policy inventory and covered
  secret-containment + confinement classes (K1/K2 analogs), but never walked the config lifecycle —
  K3/K4/K7 (config write→hot-reload, rules loading, instruction trust) stayed unreached. Inventory
  happened, lifecycle surfaces were under-weighted → W67.
- **W66 — profile-aware vocabulary in user-facing output** `[ux]`. The pipeline's lingua franca is
  memory-corruption (`Crash claimed`, `crash_found`, `found_bugs.jsonl`); for the ai-agent profile the
  artifact is a scenario candidate, not a crash — the log lines mislead. Keep the internal contract
  names (load-bearing: resume, aggregate, status enums) but print profile-aware lines
  ("Candidate claimed", "No candidate emitted"). **Done-when:** an ai-agent run's stdout contains no
  "crash" outside detector excerpts.
- **W67 [SHIPPED 2026-10-05] — config-lifecycle surfaces under-weighted by finders** `[prompts]`. The
  two-model campaign covered permission-policy guard gaps but missed all three config-trust classes the
  parallel campaign found, despite AI10 naming them. Shipped as BOTH mechanisms: a lifecycle checkpoint
  in the find prompt (per-artifact write → validate → load → reload → execute table with the gate at
  each stage) + AI11 in scan-extras + a 4th config-lifecycle focus lens. **Validated:** the 4-lens ×
  2-model rerun surfaced permission-deny-fail-open (config rules parsed but never loaded — confirmed
  by code: zero addRules callers) and a local.toml boundary-extension candidate — from the BLIND lens,
  driven by the checkpoint, while the dedicated lens added nothing new (L74).
- **W68 — stakes-calibrated verify over ALL candidates (drop the severity bar)** `[L79][pipeline]`.
  The ZCode dual campaign: our variant-scan panel-verified only high-or-≥2-vote candidates
  (23/44) and the workflow-draft symlink write — confirmed HIGH 3/3 by the parallel campaign's triage —
  sat in our unverified raw pool. Finder severity is a prior; gating verification on it strands exactly
  the under-rated findings. Change the skill/panel protocol: every deduped candidate gets verified;
  skeptic count allocated by claimed stakes (3 for HIGH/disputed, 2 MED, 1 LOW) instead of a severity
  filter. **Done-when:** the variant-scan skill text and any panel orchestration code express
  votes-by-stakes over the full deduped set, no "below-bar raw pool" tier remains, and a re-run of the
  ZCode register through the updated flow verifies ≥40 of its candidates.
- **W69 — refutations must record tested forms (scoped, never class-level)** `[L76][prompts]`.
  The parallel campaign's CVE lenses wrote "bash parser fails closed on obfuscation" off a
  sample of forms; the backslash-escaped-flag desync in that same parser is live and PoC-verified.
  A class-level refutation closes the class for every later lens. Change the CVE-pass seed handling
  and verifier output format: a refutation entry carries `tested_forms[]` + `untested_forms[]` (or an
  explicit coverage argument), and "class X absent" without enumeration is a format error. **Done-when:**
  the variant-scan/cve-pass prompt + FIND/refute schemas require the split, and at least one campaign
  artifact shows a scoped refutation with a reopened untested form.
- **W70 — env-provenance rule for env-key findings** `[L77][detection]`. The repo-`.env`
  escalation family (proxy/CA MITM, login OAuth redirect, binary hijack) turns entirely on WHO can set
  the variable — a property of the loader chain (`loadCliDotenv` walk-up), invisible from the sink;
  without a loader read the family dies as "operator-trusted env" FPs. Add to the ai-agent FP-rules
  (AIF set): an env-key candidate is not triage-ready until provenance vs the loader chain (dotenv
  walk-up / config file / shell) is cited; symmetrically, "trusted operator config" exclusions demand
  the loader citation. **Done-when:** the rule is in `profiles/ai-agent/fp-rules.txt` (or the triage
  skill's exclusion list) with the ZCode V4/V5/V6 loader example, and the triage checklist prompts for
  loader provenance on env-key candidates.
