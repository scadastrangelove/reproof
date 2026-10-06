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

## L73 — Agents pack multiple submissions into ONE message; parse per-block, never per-message `[PROVEN]` · pipeline

- **What happened:** W64 taught the find loop to accept several candidates per run. Both kimi
  models then packed 2–3 complete `<poc_path>` submissions into a single assistant message
  (one message at the end of the hunt). The extractor ran `re.search` per message and kept
  only the first block — silently dropping 6 of 14 candidates (43%) in the two-model
  kimi-code campaign, including the entire symlink-escape class from three runs.
- **Why:** "one message = one submission" felt like a safe structural assumption — it holds
  when agents submit incrementally, but "submit each, keep hunting" also reads as "collect,
  then dump". Models choose. Any tag-protocol parser must assume N blocks per message.
- **Change:** `extract_crashes` splits every assistant message at each `<poc_path>` opener
  and parses segments independently (0405330, pinned by test_find_multi). Lost candidates
  were recoverable because Write tool-call contents persist in transcripts — a second
  argument for fsync'd transcripts. When a count looks suspiciously low, diff the number of
  `<poc_path>` openers in the transcript against parsed artifacts before blaming the model.

## L74 — A shared prompt checkpoint beat a dedicated focus lens `[PROVEN]` · method

- **What happened:** W67 shipped two mechanisms for the same gap: a config-lifecycle
  checkpoint in the shared find prompt (all lenses) and a dedicated config-lifecycle
  focus lens. In the validation campaign the config-trust classes (permission rules
  never loaded; local.toml boundary extension) came from the BLIND lens — via the
  checkpoint — while both models' dedicated-lens runs produced only the classes the
  earlier campaign already had.
- **Why:** a focus seed constrains WHERE to look but the model still free-styles HOW;
  a checkpoint constrains the PROCESS (enumerate five lifecycle stages per artifact
  before claiming), which forces the walk regardless of focus. Possibly the example-
  heavy lens text also anchored the dedicated runs on the named artifacts.
- **Change:** prefer process checkpoints in the shared prompt over additional focus
  lenses when the gap is "a surface type nobody walks". Also: a checkpoint that NAMES
  the defect shapes validates guided recall, not discovery — read done-when results
  accordingly and keep a blind pass without the seed when measuring true recall.

## L75 — Two independent pipelines converge on the headliners and diverge on the tail; the tail is the yield `[PROVEN]` · campaign-design · extends RIP L21/L25

- **Evidence:** ZCode v3.14.3 (commit 29628c9) scanned twice in parallel by independent
  stacks: a GLM variant-scan (15 lenses, 3-skeptic panel) and a Claude campaign
  (6 lenses: TM/Blind/CVE × opus/sonnet, stakes-calibrated triage). The headliners are
  identical — project-config MCP auto-spawn (found by 5/15 lenses resp. 6/6), repo
  config `permission.mode=yolo`, plugin-hook trust bypass, plan-mode MCP annotations,
  WebFetch SSRF dead guard, sed `w`-flag write, unauth self-host server, Explore
  subagent yolo. The tails are disjoint: GLM-only found the backslash parser desync
  (V18, PoC-verified), marketplace `ext::` pre-approval RCE (V7), the repo-`.env`
  escalation family (V4/V5/V6), Edit/Write rule asymmetry, credential-cipher key;
  Claude-only found the dynamic-workflow `vm` `__send` escape (Z9), `uniq` output
  operand (Z10), workflow-draft symlink write confirmed HIGH (Z5), NTLM leak (Z21).
- **Why:** convergence certifies the target's structural holes — any reasonable method
  finds those; it measures the target, not the method. Recall lives in the tail, and
  the tail is specific to model, seed family, and lens framing. A second stack is a
  recall multiplier, not a redundancy check.
- **Change:** for campaign-grade targets run at least two model stacks (or two
  disjoint seed families) and budget triage for the UNION of tails, never the
  intersection. Report convergence separately from novelty.

## L76 — A seed refutation is scoped to the forms actually tested; a class-level "absent" hides live bypasses `[PROVEN]` · cve-seeding

- **Evidence:** the Claude CVE lenses ported the kimi obfuscation seed to ZCode, tested
  forms, and recorded "bash parser fails closed on obfuscation". Yet the backslash-
  escaped-flag desync (V18) — an obfuscation-class bypass in exactly that parser — is
  real and PoC-verified through the real classifier (`rg \-\-pre=…` readonly=true,
  unescaped control correctly false). Their own blind lens independently found adjacent
  write/exec vectors in the same allowlist family (`uniq` operand, sed `s///e`, `w`).
- **Why:** a refutation generalizes from sampled instances to a written verdict;
  recording the class as absent closes it for every later lens and campaign, and the
  next reader treats the closed class as ground truth.
- **Change:** refutations must name the exact forms tested ("escaped-flag desync NOT
  tested" vs "obfuscation absent"); a class-level refutation requires an enumeration
  of the class or an argument covering it, never a sample.

## L77 — Env-var findings live or die on WHO can set the variable; that fact lives in the loader, not the sink `[PROVEN]` · reachability · trust-boundary

- **Evidence:** the repo-`.env` escalation family (proxy/CA MITM of model traffic,
  `zcode login` OAuth redirect, `ZCODE_GIT_BINARY` hijack) would have been dropped as
  operator-trusted-env false positives under the campaign's exclusion rule; reading
  the loader (`cli/src/env.ts` `loadCliDotenv` → `findDotenv` walking up from the
  workspace cwd, `override:false`) proved repo-reachable and made them genuine
  untrusted-repo vectors. The inverse held too: the CLI-login `cmd /c start` candidate
  was correctly refuted because the URL was vendor/user-sourced — no crossing.
- **Why:** "is this env operator-controlled or repo-controlled?" is a property of the
  loading path; it is invisible from the sink, and both the FP and the HIGH verdicts
  in this family turned on the same one function.
- **Change:** every env-key finding carries a provenance check against the loader chain
  (dotenv walk-up / config file / shell) before triage; "trusted operator config"
  exclusions demand the loader citation, symmetrically with reachability citations.

## L78 — A severity dispute between independent readers points at an unread guard, not at a difference of opinion `[PROVEN]` · verification-hygiene · extends L67

- **Evidence:** both campaigns' panels independently downgraded the WebFetch SSRF
  HIGH→MED for identical reasons (unconditional https-upgrade, TLS cert validation,
  build-mode approval) and both re-rated the unauth server conditional (opt-in
  launcher, loopback-by-default daemon). The one genuine dispute (workflow-draft
  symlink write) was resolved not by averaging but by guard analysis: `O_NOFOLLOW`/
  `lstat` protect only the final path component, `mkdir -p` follows the intermediate
  symlink — the refutation itself was refuted and HIGH restored.
- **Why:** severity is derived from gating conditions. Two adversarial readers of the
  same gates converge; disagreement is evidence that SOME gate on the path has not
  been read by one side.
- **Change:** treat cross-panel severity disagreement as a pointer to an unread guard:
  enumerate the gates in the disputed chain before any compromise. Never settle a
  dispute by averaging votes.

## L79 — A verify bar selected by claimed severity strands real findings in the raw pool; spend skeptic votes by stakes over ALL candidates instead `[PROVEN]` · triage-design

- **Evidence:** the GLM variant-scan panel-verified only candidates that were
  high-severity or ≥2-lens-vote (23 of 44); the workflow-draft symlink write sat in
  the unverified raw pool and was confirmed HIGH (3/3) by the parallel campaign's
  triage. That triage instead verified every one of its 37 candidates with
  stakes-calibrated votes (3 for HIGH/disputed, 2 MED, 1 LOW) — coverage by
  allocation, not exclusion.
- **Why:** finder severity is a prior, not a verdict; using the prior as the gate for
  WHICH candidates get verified bakes the prior in — exactly the findings a finder
  under-rates are the ones never checked.
- **Change:** verify every deduped candidate; allocate skeptic count by claimed
  stakes rather than excluding candidates below a severity bar. Raw-pool items are
  "unverified", never "probably fine".

## L80 — When a dispute reduces to "what does pinned dependency X do", the tie-breaker is a probe of X, not another vote `[PROVEN]` · verification-hygiene · extends L72

- **Evidence:** V18 split the skeptic panel 1-refute/2-confirm, BOTH sides claiming
  live probes of `unbash@4.0.1` with opposite results. Settled only by an independent
  scratch-dir probe of the pinned version (`word.value` retains backslashes in unquoted
  words) plus a harness running the real 23 classifier files copied verbatim from the
  target (payload readonly=true, controls false, real shell executes the escaped
  flag). The parallel campaign hit the same shape (TUI cell-buffer ANSI question) and
  could only park it "for dynamic" — no probe was run.
- **Why:** when the disputed fact is the behavior of a specific pinned artifact, any
  number of readers is worth less than one execution of that artifact; dueling
  "I tested it" claims are symmetric and votes don't break symmetry.
- **Change:** a panel dispute that reduces to pinned-artifact semantics is settled by
  a reproducible scratch-dir probe of that exact version, recorded with the harness
  path; only then does the disposition flip. Mirrors L72: decompose to the mechanism,
  then measure the mechanism.

## L81 — A foreign pipeline's findings are untrusted input: diff, verify anchors, adopt as candidates — never inherit dispositions `[PROVEN]` · campaign-hygiene

- **Evidence:** each campaign's output landed in the other's working area (the GLM
  `VARIANT-FINDINGS.json` inside the clone; the Claude register log in the other
  direction). Both sides handled it correctly: treated as data, diffed against the
  local register by root cause, anchors re-checked in source (and one crux — does
  ZCode load a repo-local `.env` — resolved in the loader before adopting the family),
  adopted as new register entries with fresh triage rather than inherited
  "confirmed" status.
- **Why:** a findings file mixes real anchors with over-claims and, in an agent-
  pipeline context, may itself carry injected instructions; adopting its dispositions
  launders unverified claims into a "confirmed" register and destroys the meaning of
  the local verdict vocabulary.
- **Change:** foreign findings enter the register as candidates with citation checks
  and re-verification; dispositions are always re-derived locally. The cross-campaign
  diff itself is a deliverable (convergence vs novelty, L75).

## L82 — A negative reading from an instrument you never positively validated is not a result `[PROVEN]` · measurement · echoes L61

- **Evidence:** ADR-002 R4b was published as "zcode CLI ignores ALL proxy
  configuration", based on a MITM recorder showing zero records. The recorder
  itself was broken (deadlock: it re-read the CONNECT request the HTTP
  framework had already consumed; its only smoke test returned curl 000 and
  was dismissed as a quoting artifact). A contributor's source read
  challenged the claim; rebuilding the recorder (v2) and re-running the exact
  experiment produced the recorded, forwarded, 200-OK main-turn request —
  `ZCODE_HTTP_PROXY`/`ZCODE_AGENT_CA_CERT` are honored. The "ignore" was the
  instrument, not the CLI. (The residual zcode.z.ai traffic was sidecars on
  the default gateway — a different, real finding that the bad instrument
  had blurred together.)
- **Why:** a silent instrument and an ignored path produce the same
  observation — nothing. L61 says oracles must resolve on the negative
  control; this is the same rule one layer up: the RECORDER must first
  positively capture a known-good request before its silence is evidence of
  anything. One positive control (curl through the recorder) would have cost
  30 seconds and prevented a wrong ADR section plus a day of workaround
  design.
- **Change:** every capture/recorder harness gets a positive-control step in
  its recipe (a known-good request MUST appear in the log before the
  experiment starts); "the proxy/CLI/X ignored the config" is not claimable
  from recorder silence alone. Counter-analysis from source beats black-box
  inference — invite it earlier.

## L83 — A published narrow trust boundary calibrates disposition, not discovery; own-code enablers flip accepted-risk classes back in scope `[PROVEN]` · scope · triage

- **Evidence:** the Pi campaign hit a target whose SECURITY.md/threat model
  declares whole classes accepted-risk (untrusted-repo config, prompt
  injection, no-sandbox). Treating the document as a filter would have
  dropped real defects; treating it as noise would have overclaimed. The
  productive split was bucket-A (bypass of the target's OWN control or an
  OS/network boundary — disclosable) vs bucket-B (vendor-declared
  accepted-risk — recorded, not reported). One class flipped from B to A
  when the target's own shipped artifact granted the enabler the "accepted
  risk" had assumed only the user could set.
- **Why:** scope documents describe intent, not mechanism. The mechanism
  question — does the target's own code or packaging hand the attacker the
  prerequisite? — is answerable from source and packaging, and it is what
  separates "by design" from "the design is undercut by the artifact".
  Bucket-B findings also keep value for DERIVED products that drop the
  caveats, so they must be recorded with the same rigor, not discarded.
- **Change:** scan-extras AI12 (declared-scope calibration) + one sentence
  in fp-rules AIF2: read the published trust boundary first, classify every
  candidate bucket-A/bucket-B explicitly, and name the control bypassed and
  the line where the target grants the access when a class flips.

## L84 — Ambient config is attacker surface when untrusted content can set it, and the shipped artifact — not the dev run — is the unit under test `[PROVEN]` · reachability · config

- **Evidence:** Pi P3 and the ZCode campaign (Z40/Z41/Z47) clustered on the
  same shape: a tool resolving a security-relevant config dir, trust store,
  provider endpoint, proxy or CA from an env var or an autoloaded dotfile
  (.env, bunfig, rc) that untrusted content can write before the tool reads
  it. Two findings were nearly misjudged from dev behavior: a compiled
  binary autoloaded a cwd `.env` that a dev run would not — one build flag
  toggled it. A sibling tool on the same stack made the safe choice, which
  both proved avoidability and gave the reference fix.
- **Why:** the env var's documented existence is not the finding; the
  REDIRECT of authority (who can set the source before the read) is. And
  the authority question is answered by the loader and the packaging, not
  the sink (echoes L77). Shipped ≠ dev: build/package flags can change
  which ambient sources are autoloaded.
- **Change:** scan-extras AI13 (ambient config authority): trace each
  config/trust-store/endpoint/proxy/CA/flag source, ask who can write it
  before the tool reads it, read the exact build flags of the shipped
  artifact, and cite the safe sibling when one exists.

## L85 — Every disposition carries a verification tier, and a chain control must isolate the load-bearing link `[PROVEN]` · verification-hygiene · extends L67/L82

- **Evidence:** the Pi campaign's controls showed a recurring overclaim
  pattern: a source-only candidate read as dynamically confirmed, and a
  multi-step chain "verified" by attack-vs-nothing — where removing the
  payload also removed steps the chain needed anyway, so the control proved
  nothing about the specific link claimed. Separately, dynamic checks that
  failed oddly were nearly recorded as refuted when the true mechanism was
  in the runtime's semantics (a tool naming the wrong cause; an
  exists-check that already proved a path; a geo-blocked dependency) — i.e.
  lab-misconfiguration, not absence.
- **Why:** disposition strength is a property of the evidence tier
  (source-only / component-dynamic / end-to-end-live), and a chain is only
  as verified as its weakest isolated link. The control that matters runs
  the same payload with the load-bearing link removed and shows the outcome
  stops. Surface error strings are the runtime's guess, not ground truth.
- **Change:** fp-rules AIF13 (verification tiers): state the tier of every
  disposition, isolate the load-bearing link in chain controls, and derive
  the true failing mechanism from runtime semantics before recording
  refuted vs lab-misconfiguration.

## L86 — A version-applicability boundary is a hypothesis until you locate the file per-tag AND confirm it dynamically `[PROVEN]` · version-triage · extends L84/L85

- **Evidence:** fix-verifying four Rocket.Chat CVEs, the static pass set the
  CVE-2026-56845 boundary by grepping one develop path for the fix token
  (`sanitizeFileName`) across tags — and concluded "contained since 8.0.7,
  NVD under-lists it." Wrong. The feature had been relocated
  (`apps/meteor/app/file/server/file.server.ts` on 8.0.x/8.5.x →
  `apps/meteor/server/lib/media/file/` on develop), so the develop path 404s
  on old tags and the grep read the 404 as "token absent." Re-probing the
  correct per-tag path put `sanitizeFileName` first at **8.0.2** (absent in
  8.0.1) — exactly NVD's list. A live replay clinched it: RC 8.0.1 served
  `/custom-sounds/..%2f..%2f..%2f..%2fetc%2fpasswd` → `root:x:0:0:` (200),
  8.0.2 blocks it. Same relocation trap was waiting on the SAML parser
  (`app/meteor-accounts-saml/…` vs develop's `server/lib/saml/…`), avoided by
  per-tag locate: 58066 fixed 8.6.1/8.5.2/7.10.14, vuln one patch below each.
- **Why:** signature-grep over versions is correct (L84/"grep diffs not
  messages"), but it silently fails across a refactor boundary, and a 404 is
  not a negative. "NVD is a disclosure artifact, not containment history" is
  a real pattern — but it must be *proven* per-case, not assumed; here NVD was
  right and the clever-sounding "NVD under-lists" claim was the error. A
  static boundary is a hypothesis; the file's real location at each tag and a
  dynamic (or correct-path) check are what make it a conclusion.
- **Change:** scan-extras/version-triage: locate the file at each tag via
  `gh api repos/<o>/<r>/git/trees/<tag>?recursive=1` then grep; treat HTTP
  404 as "unknown, re-locate" never "absent"; state the boundary as a
  hypothesis and confirm the load-bearing tag dynamically when a lab exists.
  Replay gotchas to encode: vendors ship deliberately-bricked releases
  (RC `shouldBreakInVersion` throws in 8.0.0) and runtime-version floors
  (RC 8.x needs MongoDB ≥ 7.0) — a non-booting tag is lab state, not a verdict.

## L87 — Dynamic verification has a ladder of tiers; pick the highest the bug allows, and never conflate "vuln confirmed" with "RCE on today's runtime" `[PROVEN]` · verification-hygiene · extends L85/L86

- **Evidence:** reproducing four RC CVEs dynamically landed each at a
  *different* faithful tier, and forcing them all to "end-to-end RCE" would
  have meant overclaiming. (1) **56845** — unauth HTTP: a single curl on a
  running 8.0.1 = full end-to-end. (2) **H1 1049367** — real `path.join`+
  `filenamify`, a canary escaping the export base pre-fix / contained
  post-fix: complete behavioral delta at component level. (3) **58066** —
  the full multi-element SAML auth-bypass must thread `getAssertion`'s
  single-assertion + single-direct-child-signature checks; instead the
  harness exercised the fix's *load-bearing predicate* on REAL signed XML
  (real `xml-crypto`): pre-fix `checkSignature` accepts the signature no
  matter which element identity is consumed; verbatim post-fix
  `signatureCoversElement(sig, expectedId)` rejects the mismatch and accepts
  the legit case. (4) **23917** — the verbatim pre-fix LDAP walk pollutes
  `Object.prototype`, the 5.2.0 immutable rebuild does not; but the era RCE
  gadget (`Object.prototype.env.NODE_OPTIONS` → child `--require`) did NOT
  fire on Node 24, and probing showed Node 24 no longer inherits
  `options.env` from the prototype. The pollution is real; the RCE gadget is
  runtime-version-specific and hardened on current Node.
- **Why:** a "vuln" is the attacker-reachable defect; an "RCE" also needs a
  live gadget in the *deployed runtime*, which the runtime can close
  independently of the app fix. Reporting "proto-pollution → RCE reproduced"
  on Node 24 would be false even though the pollution reproduces perfectly.
  For validate≠bind / crypto-wrapping classes, the fix's predicate on a real
  signed artifact is the faithful, assemblable unit when full protocol
  assembly is impractical — and it isolates exactly the load-bearing link.
- **Change:** verification tiers (sharpens L85/AIF13): pick the highest tier
  the bug economically allows — end-to-end > component-behavioral >
  fix-predicate-on-real-inputs > pollution/delta — and *label which one*.
  Separate "vulnerability confirmed" from "RCE on runtime X"; when a gadget
  fails, probe whether the runtime hardened it (a closed gadget is a runtime
  defense finding, not a refutation of the vuln). Reusable primitive: for
  signature/assertion-wrapping bugs, drive the real crypto lib and assert the
  fix predicate accepts legit / rejects the unbound case.
