# Lessons

Reproof's own lessons ledger. Numbering continues the rust-in-peace (RIP)
ledger (which ended at L60) so cross-references stay unambiguous; entries
marked `RIP L<n>` point at the parent project's `LESSONS.md`.

Format: `## L<n> — title [STATUS] · domain · relation`, then Evidence / Why /
Change. Actionable follow-ups live in [`IMPROVEMENTS.md`](IMPROVEMENTS.md).

## L61 — An oracle must resolve on the negative control; "nothing happened" is an observation, not an absence `[PROVEN]` · replay-design · ai-agent wave

- **Evidence:** OmniRoute trusted replay. The emergency-fallback oracle observed a response-header JSON
  pointer; on the negative control that header is legitimately ABSENT, the pointer resolver raised, and the
  trial died as `infrastructure_error` — indistinguishable from broken lab plumbing, though the control had
  in fact run correctly. Same wave, second form: the first oracle predicate expected the front-end's
  provider-prefixed model id, but the observed upstream layer sees the name with the prefix stripped at
  dispatch; caught only because one control was run by hand in a debug container before re-launching the
  batch.
- **Why:** An oracle written against the input layer, or against optional output fields, confuses "the
  mechanism did not fire" with "the observation channel broke". The negative control is exactly where
  optional fields are absent — so the negative is where an untested oracle fails first, and the failure is
  mislabeled as infrastructure.
- **Change:** Adapters emit TOTAL output (every observed key always present, empty/null when absent).
  Oracles are written at the layer the observer actually sees, not the layer the attacker types into.
  Before any batch: smoke-run ONE control by hand in a debug container — the negative must produce a clean
  `observed=false`, never an error. Lint support is W50.

## L62 — Controls are contract-wide; findings are not — an unscoped control couples unrelated scenarios `[PROVEN]` · runtime · replay

- **Evidence:** trusted replay runs every control in the contract inside every trial of every scenario
  (`for control in contract["controls"]`). A control belonging to finding X (its fixture hit an ENOENT in
  the victim image) errored the trials of unrelated scenario Y; and each control costs a fresh container
  per trial regardless of relevance.
- **Why:** Controls exist to validate the marker path of THEIR finding. Running them globally multiplies
  cost linearly and, worse, lets one finding's broken fixture veto another finding's evidence.
- **Change:** optional `scenarios:` field on controls (absent = all, current behavior); the runtime filters
  before the trial loop. Tracked as W49.

## L63 — Fixtures fail at the identity and boot boundary, not in the target `[PROVEN]` · lab-discipline · extends RIP L59

- **Evidence:** two independent OmniRoute failures: (1) a fixed `sleep` after spawning a mock upstream lost
  the race — the first request arrived before `listen()`; fixed by port-polling readiness. (2) file-planting
  via `~` died ENOENT because the victim runs as a bare uid on a read-only root where the home directory
  resolves to `/`; fixed by explicit `HOME=/tmp` and planting via `/tmp`.
- **Why:** readiness-by-sleep is a bet on timing, and the harness user is rarely the image user — anything
  home-relative, PATH-relative, or cwd-relative must be proven under the uid the contract declares, on the
  mounts the runtime grants.
- **Change:** every spawned sidecar is waited on by a readiness probe (port/health/file), never a sleep;
  anything home-dependent sets HOME explicitly. Both are standing rules in the ai-agent adapters README.

## L64 — When a vector doesn't fire, suspect the fixture before the target `[PROVEN]` · lab-discipline

- **Evidence:** goose wave. An invalid `"matcher":"*"` in a hooks fixture was silently skipped by the
  target's rule parser (regex compile error → warn → rule dropped): "the attack doesn't fire" meant a
  broken fixture, not an absent bug. Same wave: session-start hooks exist only on the interactive path — a
  headless driver can never reach them, however perfect the payload.
- **Why:** a negative result has two parents — the target and the harness around it. Debugging the target
  when the fixture is silently inert burns hours and can produce a false "refuted".
- **Change:** fixture configs are validated as strictly as the target allows (a rule that doesn't parse
  must fail the lab build, not warn); trigger paths gated on interactivity are driven under a PTY.
  Recorded in the adapters README gotchas; the verdict-level fix (inconclusive vs refuted) is L66.

## L65 — The authz gap static lenses miss is sibling-relative `[PROVEN]` · detection · extends RIP L54/L55

- **Evidence:** Open WebUI wave. Three lenses (blind / threat-model / CVE-seeded) all missed a plain CRUD
  authz leak: a list endpoint whose response schema is broader than its admin-gated siblings, while a
  narrow safe schema existed in the same module, unused. Found only by a separate live campaign.
- **Why:** lens prompts look for exotic mechanism (injections, deserialization, memory); "returns more
  fields than the sibling endpoint that required admin" has no dangerous shape to enumerate — the signal is
  RELATIVE: breadth of a response model compared against the gates of its siblings.
- **Change:** detection rule in the ai-agent scan-extras: enumerate list/read endpoints, compare
  response-schema breadth against sibling endpoints' gates, flag pairs where a weaker gate returns a
  strictly broader schema. Rule work is W56.

## L66 — "Not confirmed" must split into refuted vs inconclusive; every scenario needs a positive reachability control `[PROVEN]` · evidence-discipline

- **Evidence:** across all three wave targets, first-pass "not confirmed" verdicts repeatedly traced to
  the SETUP, not the target: payload delivered through a channel the CLI parses earlier than expected, a
  config file not wrapped the way the target reads it, a path-convention mismatch, hooks reachable only
  under a TTY. A naive run would have recorded refuted.
- **Why:** refuted is a claim about the target; a setup failure is a claim about the lab. Conflating them
  poisons the ledger both ways — false refutes kill real findings, and retroactively reclassifying them
  erodes trust in the ones that stand.
- **Change:** every replay scenario carries an explicit positive reachability control ("did the attack
  input reach the sink?" — marker/log/observation at the sink boundary, independent of the vulnerability
  oracle). `not_confirmed` + failed reachability = `inconclusive_setup`, never `refuted`. Runtime/evidence
  work is W51.

## L67 — Refute needs source adjudication too `[PROVEN]` · verification-hygiene · extends RIP L51

- **Evidence:** historical: two lenses of the same model once agreed on a wrong refute; a different model
  caught it by reading the code — the refuted finding later became an advisory. This wave, repeatedly:
  "read the code" beat "assume from shape" (config-gated behavior mistaken for absent behavior;
  serialization quoting mistaken for escaping).
- **Why:** a confirm without evidence fails review; a refute without evidence sails through, because "I
  couldn't make it fire" feels like a result. Agreement between lenses that share a model is not
  independent confirmation — for refutes it is a shared blind spot.
- **Change:** the judge requires a QUOTED SOURCE LINE for REFUTE exactly as for CONFIRM (the guard that
  stops the vector, the gate that config-closes it). A refute without one lands as `unverified_refute`,
  down-weighted in aggregation. Judge-prompt work is W53.

## L68 — Verdicts are per-sub-claim; a finding is not one boolean `[PROVEN]` · evidence-discipline

- **Evidence:** goose scheduled-recipe case: the core mechanism confirmed while an escalation sub-claim
  was honestly refuted — but the flat verdict string read `not_confirmed`, misreporting a confirmed core.
  Same wave, another finding: the reachability claim held with different constraints than the write-up
  assumed.
- **Why:** agent-era findings are compound: core mechanism, escalation path, constraint set. One boolean
  forces the most interesting part of the result (which sub-claim failed) into prose nobody aggregates.
- **Change:** findings carry `subclaims[]`; each sub-claim is modeled as its own control with its own
  verdict; the finding verdict is a roll-up that names which sub-claims stand. Evidence work is W52.

## L69 — Hygiene gates belong on the output path, fail-closed `[PROVEN]` · disclosure-hygiene · extends RIP L28

- **Evidence:** an operator identifier (user@host of the execution box) leaked into a PUBLIC profile repo
  through generated artifacts; remediation required a history rewrite and force-push.
- **Why:** scrubbing by review is probabilistic; the artifacts that leak are exactly the ones generated
  automatically (logs, evidence, run metadata), where nobody re-reads the diff. Once pushed, the fix is a
  history rewrite — the most expensive possible moment, again.
- **Change:** fail-closed redaction linter on commit/package: blocks `user@host` patterns, server IPs,
  local absolute paths (`/Users/...`), credential-shaped strings; host configuration lives untracked. W55.

## L70 — Measurement is invalid until provenance is asserted: analyzed commit vs tested artifact `[PROVEN]` · measurement

- **Evidence:** dynamic confirmation repeatedly ran against artifacts that were not the analyzed tree (a
  published RC vs analyzed HEAD; pinned clones). A manual grep-gate — diffing the finding's file between
  the tested image and the analyzed commit — caught real drift (one finding's file had moved between
  versions) and confirmed identity elsewhere; without it, a "confirmed" would have measured the wrong code.
- **Why:** replay evidence binds a verdict to bytes. If the bytes silently differ from what static
  analysis saw, the evidence is about a different program and every downstream number drifts.
- **Change:** provenance gate in grade/replay: given candidate (path/symbol) + running artifact, assert
  byte-identity of the implicated file (or flag drift) BEFORE measuring; evidence carries
  `provenance:{analyzed_commit, tested_artifact, identical|drift}`. W54.

## L71 — A wired path is proven only by a live run; each first run exposes exactly one seam `[PROVEN]` · process

- **Evidence:** the first ai-agent canary e2e (three-lens, Kimi) needed five attempts, and each failed
  at a different seam that unit tests with mocked replay could not see: (1) `build_find_prompt` rejected
  the `patched` kwarg the generic find stage passes every profile; (2) the finder wrote a scenario in an
  invented JSON shape because the prompt never pinned the schema, and grade discarded it as UNVERIFIED;
  (3) all three finders emitted `<tag>:` prose bullets which the strict `<tag>...</tag>` parser silently
  dropped — zero artifacts from three correct findings; (4) the assessor requires
  `finding.invariant == oracle.invariant` verbatim, but the catalog showed oracle descriptions, not
  invariant ids — every candidate assessed UNRESOLVED; (5) replay trials died with
  `infrastructure_error`: gVisor sentry threads count against the victim's cgroup pids limit, so the
  contract's `pids_limit: 32` intermittently killed runsc itself (urpc EOF), only under the sandboxed
  pipeline, never in unsandboxed manual replays.
- **Why:** every seam sat at a boundary between a generic stage and profile-specific data (kwargs,
  schema, tag syntax, identifier identity, runtime resources). Mocks per side agree with themselves;
  only the live wire-up exercises the actual contract both sides must meet.
- **Change:** profile builders' signatures are pinned to the cpp reference offline; the find prompt
  carries the distilled contract catalog (entries/oracles/mode/invariant ids) plus the strict scenario
  format and tag syntax; victim labs floor pids-limit at 256 under a sandbox runtime. All five fixes
  ship with regression tests. W59 shipped; follow-ups W61 (judge dedup on root cause, not component
  string) and W62 (report prompt: replay is orchestrator-side).

## L72 — Agent-CLI findings decompose to tool-level mechanism checks; a model is not always needed `[PROVEN]` · method

- **Evidence:** the first real-target three-lens run (a coding-agent CLI, --find-only) produced three
  candidates; triage confirmed two tracks statically, and BOTH are dynamically confirmable by driving
  the tool executors directly in a fixture workspace (path-confusion write, guard-presence check) —
  no live model, no agent_behavior adapter. The finders also self-separated intended behavior from
  bugs: one candidate was merged as documented design after the doc lines were checked, zero false
  code claims survived triage.
- **Why:** an agent system's authority boundaries live in deterministic code (path canonicalization,
  policy-chain ordering, tool argument handling). The model is the *steering* uncertainty, but the
  *guard* either holds for all inputs or it doesn't — and that question is mechanism, not behavior.
- **Change:** when a finding's violation lives in tool-execution code, prefer a tool-level mechanism
  replay (fixture workspace + direct executor calls) over waiting for an agent_behavior adapter.
  Contract entries should name the tool executor, not only the user-facing CLI. W63.
