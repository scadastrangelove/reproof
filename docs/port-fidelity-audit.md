# Port fidelity audit — harness → reproof (2026-10-03)

Question asked: was the Reproof port of the original vuln-pipeline harness
ported *honestly*, or "fitted to the answer"? Method: full file-by-file diff
of `harness/` (rust-in-peace) vs `reproof/reproof/`, plus empirical checks on
the 2026-10-02 campaign-benchmark transcripts on the runner.

## Verdict A — the pipeline itself was ported faithfully

**Prompts: verbatim.** `prompts/{find,grade,recon,report,judge,patch,
report_grader,maintainer_review,system,untrusted}` and
`rust/{find,grade,judge,patch,report}_prompt.py` are byte-identical to the
original at the benchmark commit (`git diff` vs `5de1a30` = 0 lines on every
prompt file). The ONLY prompt changes in the port's history are the
2026-10-02/03 class-agnostic grade rubric + reasoning-first methodology
(`0ce1c7c`, `462a4cd`, `88d68f4e`) — made *after* the benchmark, requested
by the operator, validated by a dedicated rustdesk run (both grades PASS 1.0
where the verbatim prompts had rejected by class).

**Orchestration logic: identical.** Of 25 differing files, every diff is a
mechanical rename (`agent`→`agent_kimi` import, `VULN_PIPELINE_*`→`REPROOF_*`,
`vuln-pipeline`→`reproof` strings) or the documented backend swap. Vote
counting, union aggregation, dedup keying, judge/compare gates, grading
thresholds, scorecard discipline: unchanged. `aggregate.py`,
`capabilities.py`, `config.py`, `corpus.py`, `feedback.py`, `gates.py`,
`asan.py`, `artifacts.py`, `admissibility.py` are byte-identical.

**Backend swap (auth/agent_image/sandbox/agent_kimi): documented and clean.**
Env-only Kimi auth (ADR-001 R5), Node 22 base, per-run config.toml; the agent
prompt is passed **verbatim** via `kimi -p` (verified in
`agent_kimi.build_argv`); system prompt + tool set go through an agent
Markdown file with the same content upstream passed via flags. No injected
context. Sandbox model preserved: gVisor, `--internal` network, egress
allowlist proxy.

**Oracle hygiene: held out.** `targets/{h2,rustls,rustdesk}/poc/` and
`JOURNAL.md` never enter the images (verified: Dockerfiles COPY only `gen`
(build stage), `driver`, `run_detectors.sh`; the rustdesk challenge key and
`m_b` exist only in the gen stage's process memory). `known_bugs: []` and no
`crash_signatures` in all three configs; `attack_surface` is shown only to
the *report* agent, never to find/grade (same as upstream).

## Verdict B — two contaminations found (the "подгонка" surface)

### B1. Full `.git` history inside the new target images — port-introduced leak

Original harness targets carry **no VCS history**: htslib is a release
tarball (`ADD .../htslib-1.23.tar.bz2`), canary/rust-canary/dvra3-parser are
`COPY`ed local sources. The three new benchmark targets instead
`git clone <upstream> && git checkout <pin>` — the image contains every
upstream commit **including post-fix ones**, and egress-blocked sandboxes do
not stop local `git log`.

Empirical taint (benchmark transcripts):

| Target | Finding runs | Read the actual upstream fix commit before the PoC? |
|---|---|---|
| h2 | 3 (blind, TM, CVE) | **Yes, all 3** — `git log HEAD..<master> -- src/` listed `3a241be "fix: prevent double counting pushed streams after 1xx responses (#936)"` (the GHSA-8r6j-x8wp-qpm3 fix); agents then ran `git show 3a241be` and read `recv.rs`/`counts.rs` minutes before landing the PoC |
| rustls | 5 | **No** — history browsed for orientation (`git log -- quic.rs`, pre-pin commits); the fix (PR #3173 / merge `7299721a`) appears in 0 of 9 transcripts |
| rustdesk | 5+5 | **No** — most runs never touched git; finds are organic crypto reasoning |

So the h2 rows of the benchmark are confirmation-mode results, not blind
rediscovery. (Caveat: agents also had parallel organic hypotheses — panic-site
greps predated the git step — but the final approach chain is fix-guided.)

Fix: clone shallow at the pin and strip history
(`git clone --depth 1 --branch <tag>`, or `rm -rf .git` after checkout) —
this restores the original harness's tarball-equivalent baseline.
Landed 2026-10-03 (`9da755ad`) for h2/rustls/rustdesk.

Operational gotcha found while deploying the fix: `agent_image.ensure()`
returns early when the agent tag exists, and the agent image embeds
`COPY --from=<target> /work /work` — so a rebuilt *target* image does NOT
propagate into agent containers until the agent image
(`reproof-<target>-latest-agent:*`) is removed. The first re-run attempt
silently reused yesterday's agent image (with `.git`) despite the rebuilt
target image. Rule: after changing a target Dockerfile, delete both images.

### B2. Fresh rust find-runs get the *re-attack* prompt — inherited upstream bug

`find.py:59` always passes `target.reattack_harness`; the rust profile's
`build_find_prompt` treats any non-None value as a post-patch re-attack and
swaps `FIND_PROMPT_TEMPLATE` for `HARNESS_FIND_TEMPLATE`:

> "find a crash in the PATCHED crate. Read the original PoC in /poc/ first to
> learn the format and **the code path the fix touched** …"

Every rust benchmark run (all lenses, all three targets) was therefore primed
with "a bug exists, it was fixed, find the path the fix touched" — which both
breaks blind-lens purity and *actively encourages git archaeology* (the agent
reasonably looks for "the fix" — and `.git` serves it up; B1 and B2 compound).
Agents dutifully probed `/poc/` first (absent — oracle held out).

The bug exists verbatim in the original harness (same line, same template
selection), so the Claude-era rust campaigns ran under the same framing —
Kimi-vs-Claude comparisons remain apples-to-apples on this axis, but absolute
"blind discovery" claims in both are weaker than intended. cpp targets are
unaffected (they don't set `reattack_harness`).

Fix: `find.py` should pass `reattack_harness=None` on fresh runs (or the
profile should select the harness template on an explicit `patched=True`),
plus a regression test asserting fresh-run prompts contain no
"PATCHED"/`/poc/` framing. **Landed 2026-10-03 (`9da755ad`):** explicit
`patched` flag in both profiles' `build_find_prompt` (`reattack_harness` now
only supplies the harness path), `run_find(..., patched=True)` from the
patch-grade re-attack, fresh cli.py runs default to `patched=False`; three
regression tests in `tests/test_upstream_focus.py`.

## Verdict C — by-design steering (acknowledged, to fix in benchmark v2)

- **rustdesk** is an answer-key oracle: the challenge brief names the win
  condition (key-less recovery of `m_b`). CTF, not discovery. v2: property
  oracle ("plaintext recovered without key = violation") over a generic
  transport-peer driver.
- **rustls**' driver pre-builds the bug's precondition (mixed provider with
  `quic: None`) — documented as a supported provider shape, but the agent
  never has to think of the configuration itself. v2: agent chooses the
  provider.
- **Judge mis-dedup on logic-oracle findings**: the manifest excerpt is the
  driver's identical challenge banner, so the 2026-10-03 re-run produced two
  reports for one root cause (blind and CVE cells). Manifest excerpts for
  logic classes should carry `crash_type` + the oracle marker line.
- h2 TM `agent_failed` (rc=137, 2/3 runs) — infra SIGKILL, recall understated.

## What survives the audit

- The port added **no** steering in prompts, scoring, dedup, or grading —
  the pipeline is faithful.
- rustls and rustdesk finds are organic (rustdesk on a guided oracle).
- h2 finds are real and correct (the PoCs reproduce the ground-truth panic)
  but were fix-guided; re-run with history-free images for a clean claim.
- The 2026-10-03 prompt-fix validation and rustdesk re-run are unaffected by
  B1/B2 for their own purpose (they measure grade-rubric behaviour, not
  discovery).
