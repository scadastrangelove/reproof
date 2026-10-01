# x509-parser campaign — lessons for rust-in-peace

Draft for review. Lessons distilled from the x509-parser 2×2 study
({Track A autonomous crash pipeline, Track B curated static review} × {Opus 4.8, Sonnet 5}).
Each item: **what happened → implication for the project → concrete change**, tagged
`[PROVEN]` (the campaign demonstrated it) or `[PROPOSED]` (a reasonable inference), with a
rough effort estimate. Full evidence: [`JOURNAL.md`](JOURNAL.md), [`CONSOLIDATION.md`](CONSOLIDATION.md).

TL;DR: the campaign found **0 attacker-reachable memory/panic-DoS bugs** and **2 genuine
low-severity defects** (`ASN1Time::add` contract-violating panic; duplicate-CRL-extension
accessor divergence). The *methodological* result is more valuable than the findings: the same
reachability over-claim occurred at three layers and was caught only by cheap execution + outside
pressure — so the fix is to make "verify, don't assert" **structural**, not a matter of diligence.

---

## High-value (proven by the campaign)

### L1 — Enforce evidence for *dependency-behaviour* claims  `[PROVEN]` · cheap-win · low effort
The headline RSA finding (`validate/structure.rs:169`, empty-modulus `[0]` index panic) survived
a recall-first find **and** a full R1–R11 triage as `real` — and was **wrong**. Its load-bearing
premise was "asn1-rs does not reject a zero-length DER INTEGER (`02 00`)": asserted twice, uncited,
and false. R1–R11 reason about *this crate's* invariants, so an unverified claim about an
**upstream dependency's** accept/reject behaviour slides straight through.
- **Change:** any claim about a dependency's parse / accept / reject behaviour must cite that
  dependency's source (`file:line`). An uncited dependency-behaviour claim is **inadmissible as
  the load-bearing premise of a `real` OR a `false_positive`.** Add as an R-rule / triage gate.
- Sonnet reached the correct verdict precisely by doing this (opened
  `asn1-rs-0.8.0-beta.1/src/asn1_types/integer.rs:622` → `[] => Err(DerConstraint::IntegerEmpty)`).
  Static, no quota — would have killed the FP at triage.

### L2 — The lever is "open the dependency," not "run it dynamically"  `[PROVEN]` · prompt-only
Sonnet derived the correct verdict *statically* from the dependency source; the `cargo run`
confirmation came later and cost more. Static-vs-dynamic was **not** the differentiator —
**whether the agent opened the dependency** was.
- **Implication:** find→fuzz / DEFER-TO-DYNAMIC is the **oracle / tiebreaker**, not the primary
  road to a reachability verdict. The primary lever is forcing the trace to terminate at the
  invariant's actual definition, wherever it lives.
- **Change:** finder + triage prompts should instruct: when a verdict hinges on a dependency's
  behaviour, vendor and open that dependency's source before concluding. Pairs with L1.

### L3 — A "smarter" review layer is not self-correcting  `[PROVEN]` · medium effort
The curator (the human-in-the-loop assistant) reproduced the *same* reachability over-claim one
level up — twice ("reachable via pub-field construction"; a read-only "1 solid + 1 info" tally) —
each caught only by an outside question ("where does the PR's test even point?", "shouldn't you
re-check?"). Adding a more capable layer did not stop the error class; **reviewer pressure** did.
- **Change:** make reachability verdicts carry an explicit `premise → checked_at` field
  (`file:line` or an execution result), and run an **adversarial reviewer whose only job is to
  attack that link**. rust-in-peace already has adversarial-verify patterns — specialise one for
  reachability premises.

### L4 — Route by target shape; the byte-crash track is blind on logic-heavy targets  `[PROVEN]` · medium effort
Both autonomous runs returned **0 crashes** (35 min / 93 min of OAuth burn) — the *correct* result,
because x509-parser's genuine defects are logic/latent: no input makes the parser itself panic, so
a crash-oriented find agent cannot reach them. `capabilities.json` already classifies the surface.
- **Change:** use it as a **gate**. When the surface is logic/latent (no memory-unsafe, panic paths
  guarded), down-rank or skip the crash-find track and lead with curated static + targeted in-image
  dynamic verification. The blind fuzzer's null result is still worth having as *corroboration*, but
  as confirmation, not discovery.

---

## Medium-value (observed → proposed)

### L5 — Find agents rabbit-hole in reverse-engineering  `[PROVEN observation]` · low effort
Both crash-find runs burned their turn budget on `objdump`/`nm`/`strings`/`od` over the binary,
chasing panic strings, instead of crafting inputs — on a pure-Rust target where there is nothing
to reverse.
- **Change:** guardrail — "N tool calls without a candidate input → refocus or yield"; bias the
  find prompt toward input generation over disassembly on pure-Rust targets.

### L6 — Cross-model disagreement is signal, and it belongs at triage  `[PROVEN]` · medium effort
Both models raised the RSA candidate at find; they diverged at **triage** (Sonnet `false_positive`
✓, Opus `real` ✗). Union-of-N votes across *runs*; extend it to **cross-model triage**: a real-vs-FP
disagreement is exactly `CONTESTED`, and it should force the cheap dependency-source / dynamic check.
- Caveat: **neither model dominates** — Opus was better-calibrated on the soft PEM
  proportional-allocation class (`contested` vs Sonnet's `real`×3). So this is union, not
  replacement.

### L7 — The autonomous track has an operational cost the curated track doesn't  `[PROVEN observation]` · informational
One find agent was blocked **12×** by Anthropic's real-time cyber safeguards
(`triggered cyber-related safeguards … Cyber Verification Program`) and dead-ended in retries. The
curated, read-only source review never trips this. Factor into the cost model; another reason to
lead curated on security-sensitive targets.

### L8 — Report unit is verdicts, not counts  `[PROVEN]` · already-project-philosophy
"5 real" was a counting artifact (a weak dedup key in a throwaway script left 3 near-identical PEM
findings unmerged; real distinct ≈ 3). The per-finding **disposition + evidence** is the unit —
never headline raw counts. Reinforces the existing scorecard discipline; nothing in the harness
needs fixing for the specific artifact.

### L9 — Make responsible disclosure a first-class output  `[DEMONSTRATED]` · medium effort
The campaign produced a repeatable disclosure workflow: verify by execution → honest severity
(reachability caveat, *not* CVE inflation) → detect the private channel (no SECURITY.md /
`private-vulnerability-reporting: {"enabled":false}` → email) → private-first → a ready-to-fire PR
with a **test verified in the crate's own harness**. Candidate for a `/disclose` skill or pipeline
stage.

---

## What worked — do NOT change

- **Recall-first finders over-including the RSA candidate was correct.** The failure was at
  *triage*, not *find*. Do not penalise finder recall to suppress FPs.
- **The 3-way disposition + R11 + `CONTESTED` taxonomy held up.** The gap was **evidence
  enforcement**, not the vocabulary. L1/L3 add enforcement *within* the existing taxonomy.
- **In-image, offline `cargo` verification (zero API quota) was the highest-ROI tool of the whole
  campaign** — every genuine result came from it, not from the expensive autonomous runs.
  Institutionalise it as the standard verification step.

---

## Suggested next step

Promote the three cheap wins — **L1** (cite-the-dependency rule), **L4** (capability-gate the crash
track), **L8** (verdicts-not-counts) — into `IMPROVEMENTS.md` first; they are near-zero-code and
directly close the failure this campaign exposed. L2/L3/L6/L9 are larger and worth their own design
pass.
