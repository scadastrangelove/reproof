# lopdf campaign journal (WORKING DRAFT)

Target: [`J-F-Liu/lopdf`](https://github.com/J-F-Liu/lopdf) `0.44.0`
(commit `1efa270`), default features (chrono + jiff + rayon + time). 38 rs files,
~692 KB src, edition 2024, rust 1.88, **1 `unsafe`** → surface = panic-DoS +
resource-exhaustion + logic, not memory corruption. Entry: `Document::load_mem(&[u8])`
(+ `parser::content` / `Content::decode` for content streams). Stance: responsible disclosure.

Experiment shape: **2×2 = {Track A autonomous crash pipeline, Track B curated} × {Opus 4.8, Sonnet 5}**.
Chosen as the L4 contrast to x509: a **byte-rich** parser where the crash track *should* pay off.

## L11 — why the dynamic-fuzz stage never actually ran (root cause) — 2026-07-18

Prompted by a sharp reviewer question: across BOTH campaigns, Miri / ASan / cargo-fuzz and the
`reattack` find→fuzz bridge were **never exercised end-to-end**, even on x509 where all three were
installed in the image (`reattack` dir absent on every batch). Honest root cause, three layers:

1. **Operator (me) substituted manual verification for the stage.** The find→fuzz bridge exists to
   turn a *static* finding into a reproducing cargo-fuzz/Miri harness. Track B produced findings
   (ASN1Time::add, inline-image), but I verified them with ad-hoc in-image `cargo` PoCs instead of
   routing them through `reattack`. Faster per-finding, but the flagship stage got bypassed —
   partly this session's OAuth-cost caution, partly the convenience of `cargo` being right there.
2. **Experiment design didn't wire the tracks together.** I built the 2×2 as two *independent* cells
   to compare (A vs B). The pipeline's intended flow is that static findings **feed** the dynamic
   stage (B → reattack → fuzz). My structure had no such wire; "left for later," and later didn't
   come until asked.
3. **Genuine skill/prompt gaps (yes, partly the skills):**
   - **The find skill does not self-escalate to cargo-fuzz when hand-crafting stalls.** On x509 the
     agent hand-crafted inputs and reverse-engineered the binary for 93 min and never wrote a
     libfuzzer harness — although `fuzzing.md`'s staircase (blind-fuzz → cargo-fuzz) prescribes
     exactly that. The staircase is **documented but not enforced** in the find loop.
   - **`reattack` triggers only on graded *crash* findings, not on *static* (Track B) findings.**
     When Track A is empty, the whole dynamic arsenal dead-ends with no automatic static→fuzz path.

**The one lever:** the pipeline never makes the dynamic-fuzz stage **mandatory / always-run** — it's
gated behind a crash (which may not exist) or an operator choosing to run it, and the find skill
doesn't auto-escalate. So installed-but-unused tools are the predictable outcome.

> **L11 (proposed):** make coverage-guided fuzzing a **first-class, always-run stage**, seeded from
> *both* the corpus and the static findings (B → fuzz), not gated on a Track A crash. And have the
> find skill **auto-escalate to writing a cargo-fuzz harness** after N tool-calls without a
> candidate input (enforce the `fuzzing.md` staircase, don't just describe it). Corollary of L10:
> run the fuzz build with the target's shipping profile (overflow-checks off) so crashes are
> production-real.

This gap is being closed now for lopdf (see the cargo-fuzz section below); x509 should get the same
retroactive fuzz pass since its tools sat installed-but-unused.

## Applied lessons from the x509 campaign

- **L4 — tooling matched to surface:** dropped the ASan build-std driver (1-unsafe safe-Rust →
  panic-DoS, not memory corruption). Detector = **panic + overflow-checks + debug-assertions +
  hang-timeout**. Lean image, fast build. `capabilities.json`: untrusted_deserialization +
  **decompression** + **concurrency** (rayon default) → vote budget → **runs=5**.
- **L1/L2 — dependency-citation enforced structurally:** Track B triage schema has a **required
  `dep_citation` field** (`vendor/<crate>/src file:line` or `n/a`). Deps vendored so agents can
  actually open nom-8 / flate2 / weezl / jiff / rangemap.
- **Corpus:** seeded from the crate's 6 real `assets/*.pdf`.
- **Driver validated:** 6 seeds → `ok objects=6..616`; garbage → `reject:`; no false panics.

## Track B (curated static) — COMPLETE. Rich, as expected for PDF.

| | Opus 4.8 | Sonnet 5 |
|---|---|---|
| raw → unique | 27 → 27 | 26 → 26 |
| triage | **12 real / 15 FP** | **18 real / 8 FP** |

**These are candidates — NOT yet recorded as confirmed.** The campaign discipline (do not record
`real` on argument alone) applies; verification is under way (Track A is the execution oracle for
the `load_mem`-reachable ones; targeted PoCs for the rest).

**L1 worked.** Several triage verdicts carry real dependency citations
(`vendor/nom-8.0.0/src/multi/mod.rs`, `vendor/flate2-1.1.9/src/zlib/read.rs:267`,
`vendor/rangemap-1.7.1/...`); where the field is `n/a` the agents explicitly state "the verdict
rests on lopdf's own code, not a dependency." That is exactly the structural forcing L1/L3 called
for — no uncited dependency-behaviour premise slipped through.

### Candidate clusters (both models overlap heavily)

- **Resource-exhaustion / decompression bombs** — xref-stream `/W` width unbounded alloc
  (`parser_aux.rs:568`), zero-width `/W` → unbounded entry loop (`:576`), ObjStm/FlateDecode bomb
  (`object_stream.rs:58`, `object.rs`), PNG-predictor row alloc (`object.rs:1116`). **Reachability
  fact (verified):** `LoadOptions::max_decompressed_size` defaults to **`None` = no limit**
  (documented as such), and `Stream::decompressed_content()` = `decode_filters(None)` = unbounded.
  So the default `load_mem` path is genuinely unguarded — *but the crate documents the risk and
  ships the opt-in `max_decompressed_size` guard*, so this is borderline documented/by-design
  (cf. x509 "parse ≠ validate"). Honest severity: medium, maintainer-acknowledged.
- **Uncontrolled recursion → stack overflow** — Pages tree (`reader.rs:771`, `document.rs:662`),
  outlines (`outlines.rs:79,145`). Cycle-guarded by `seen` but **not depth-bounded**. Real DoS,
  no build-config dependency. Strong candidates.
- **Overflow panics** — `read_big_endian_integer` u32 (`parser_aux.rs:619`), `start+length`
  (`reader.rs:1096`), inline-image `W*H*BPC` (`parser/mod.rs:690`). **Conditional:** panic only
  under `overflow-checks=on` (my driver has it; release-default off → R7 wrong-value). Track A
  will catch these on the instrumented build; production severity depends on the consumer's build.
- **Logic panics (unconditional)** — see the verified one below; empty `/ColorSpace` `array[0]`
  (`document.rs:779`, with nom dep_citation); outlines/destinations `array[0]/[1]` (`outlines.rs:118`).

### ✅ VERIFIED by execution (in-image, offline, zero quota)

**Inline-image `.unwrap()` on missing `/ColorSpace` — CONFIRMED panic** (`parser/mod.rs:670`,
raised by **both** models). `Content::decode(b"BI /W 1 /H 1 /BPC 8 ID \x00 EI")` → **PANICKED**;
controls `/IM true` and `/CS /DeviceGray` → no panic. A real, unconditional panic in lopdf's own
code, reachable from the public `Content::decode` / page-content-parse API (used by any text/image
extractor). PoC: [`poc/inline_image_unwrap/`](poc/).

- **2×2 lesson (driver scope):** this bug lives behind `content()`, a *second* public API. The
  crash-pipeline driver is scoped to `load_mem` (it fetches raw page-content bytes but does not
  parse them into operations), so **Track A structurally cannot reach it** — only Track B did.
  → widen the driver to also `Content::decode` page content, or accept that the crash track's
  reach is exactly its driver's call graph. (Actionable project note.)

## Track A (autonomous crash pipeline) — Sonnet: 4 crashes, but 0 reproduce in release (!)

Launched post-setup, `--parallel --stream --auto-focus --aggregate union --max-turns 150`,
runs=5, seeded from `assets/*.pdf`. Unlike x509, the find agents immediately **crafted PDF inputs**
(object-streams via zlib, xref, content) rather than reverse-engineering the binary — L4's
prediction held. Killed at ~46 min (4/5 runs done, productive). Result: **4 crashes → 3 distinct
panic sites**, all found on the `load_mem` surface:

| PoC | site | call chain |
|---|---|---|
| run_000 | `parser_aux.rs:596` **add-overflow** | `decode_xref_stream_with_limit` ← `xref_and_trailer` ← `Reader::read` ← `load_mem` |
| run_003 | `filters/png.rs:88` **overflow** | PNG predictor |
| run_002/004 | `object.rs:1125` **mul-overflow** | `decompress_predictor` ← `decode_filters` ← `decompressed_content` |

Every one **cross-references a Track B candidate** — so far this looked like the 2×2 loop closing
(dynamic confirms static), the opposite of x509.

### ⚠️ But on honest re-test, NONE reproduce in lopdf's shipping build

The detector image builds the driver with `RUSTFLAGS="-C overflow-checks=on"`. All 4 crashes are
`panic_const_{add,mul}_overflow` — they exist **only because of that flag**. Re-ran each PoC
against a second driver built with a plain `cargo build --release` (overflow-checks OFF = lopdf's
release default; the crate sets no `[profile.release]` override — confirmed by the build behaving
so):

| PoC | overflow-checks ON (detector) | OFF (release default) |
|---|---|---|
| `parser_aux.rs:596` | panic (rc 101) | **`reject: Parse(InvalidXref)`** (rc 0) |
| `object.rs:1125` (×2) | panic | **`ok objects=4`** (rc 0) |
| `filters/png.rs:88` | panic | **`ok objects=3`** (rc 0) |

**All 4 Track A crashes are detector-configuration artifacts, not production panic-DoS.** In the
shipping profile the overflow wraps silently and the parse gracefully rejects or completes — R7
wrong-value with no observed harm at these sites. This is the *opposite* headline from what the raw
crash count suggested.

### L10 (NEW project lesson) — the detector's build flags are part of the threat model

The grader re-ran each PoC against the **same** instrumented (overflow-checks-on) binary, so it
confirmed the crash and graded it `real` — with no way to know it's build-config-gated. Meanwhile
**Track B's static triage correctly flagged these very sites as overflow-checks-conditional / R7
wrong-value** (Opus verbatim: "with overflow-checks off it silently truncates … R7"). So on this
cluster the *curated static triage was more honest about severity than the autonomous crash
grader* — because the grader never re-tests against the target's shipping profile.

- **Change:** a crash found under a non-default build flag (overflow-checks, debug-assertions) must
  be **re-tested against the target's real release profile before grading `real`**; if it doesn't
  reproduce there, label it `overflow-checks-gated / R7` and downgrade. Either build the detector
  with the target's actual profile, or add a shipping-profile re-test to the grade stage.
- This also refines L4: even on a byte-rich target where the crash track *fires*, its raw crashes
  needed the same execution-discipline filter — and here that filter took 4 → **0 production-real**.
  The crash track's advantage on byte-rich targets is real (it *reaches* the sites), but grading
  still has to account for the build profile.

### Opus: 1 crash, same L10 outcome

Opus Track A killed ~32 min (1/5 runs, one agent rabbit-holing on `example.pdf`, **many
cyber-safeguard blocks** as with x509 Opus). 1 crash: `parser/mod.rs:516` (xref `(start+index) as
u32` overflow — a Track B candidate). L10 on/off re-test: **ON panic (rc 101) → OFF `ok objects=0`
(rc 0)** — another overflow-checks artifact, not production-real.

### Net (both models done)

- **Track A production-real panic-DoS: 0.** 5 crashes total across both models (sonnet 4 + opus 1),
  **every one overflow-checks-gated** — all verified to NOT reproduce under lopdf's release default.
  The crash track *reached* the arithmetic-overflow sites (L4 held: it fires on byte-rich targets),
  but 0 survive the shipping-profile filter (L10).
- **Track B production-real, execution-confirmed: 1** — the inline-image `.unwrap()` panic,
  *unconditional* (panics under plain release), which Track A **structurally could not reach**
  (behind `content()`, not `load_mem`). Plus strong unconditional candidates not yet PoC'd end-to-end
  (`document.rs:779` empty `/ColorSpace` `array[0]` via the public `get_page_images` — code-confirmed
  reachable, full-PDF PoC pending; Pages-tree / outlines stack-overflow recursion). And Track B
  *correctly* triaged the overflow cluster as R7/overflow-checks-conditional — matching L10, ahead of
  the crash grader.

## cargo-fuzz — closing the L11 gap (2026-07-18)

Built a real cargo-fuzz harness (`targets/lopdf/crate/fuzz/`, image
`reproof-lopdf-fuzz:latest` = nightly + cargo-fuzz): two targets, `load_mem` (seeded from the
6 real `assets/*.pdf`) and `content_decode` (seeded + the inline-image fixture). **Fuzz build uses
the shipping profile — `overflow-checks = false`, `debug-assertions = false`** (L10) so any crash is
production-real, not a detector artifact.

**`content_decode` sanity run (120 s) — VALIDATED the harness AND L11.** cargo-fuzz found a crashing
input in ~2 min:
`BI /W 1 /H 1 /BPC 8 /C… ID… E` (a mangled inline image). L10 re-test under plain release →
**`panicked at parser/mod.rs:670`** = the inline-image `.unwrap()` on missing `/ColorSpace`, the
*same* production-real bug I had earlier confirmed by hand-written PoC.

→ **Empirical proof of L11:** coverage-guided fuzzing, seeded, rediscovered the real bug **on its own
in 2 minutes** — no manual PoC, no LLM hand-crafting. Had the dynamic-fuzz stage been run as part of
the pipeline, it would have surfaced this automatically. The stage was the missing piece, not the
capability.

**`load_mem` fuzz, 600 s (overflow-checks off) — CLEAN.** 113,153 executions, cov 5093 edges,
corpus grew 6 → 1413 (2015 new units), 188 exec/s, EXIT 0, **0 crashes**. A 10-minute
coverage-guided pass over the main parse + stream-decode path found **no production-real crash** —
materially stronger evidence than the blind 46-min LLM find run (which surfaced only
overflow-checks artifacts). Consistent with the analysis: `load_mem`'s overflow bugs are
overflow-checks-gated (this build has them off) and the unconditional bugs live behind `content()`,
not `load_mem`. (An infra note: the first launch attempt died mid-build — a backgrounded ssh `&`
got SIGHUP when the tool call returned and took the container with it; relaunched detached via
`nohup`+`disown`. Operator error, not a target/harness issue.)

**6-hour soak — CLEAN (the headline dynamic result).** `load_mem`, fork=8, `-ignore_crashes=1`,
persistent corpus, overflow-checks off, `-timeout=25`. Final:

```
#8,974,065 execs | cov: 5754 edges | ft: 24303 | corp: 2852 | oom/timeout/crash: 0/0/0
time: 21612s (full 6h) | job: 715 (fork restarts) | EXIT 0
```

**~9M executions, ~48 CPU-hours, coverage saturated (~5754 edges), 0 crashes / 0 OOM / 0 hangs.**
No L10 filtering needed — nothing to filter. This is a strong, defensible statement:
**lopdf `Document::load_mem` is production-clean under deep coverage-guided fuzzing** (overflow-checks
off = shipping profile). The blind 46-min LLM find run's "4 crashes" were, in full, overflow-checks
artifacts; real coverage-guided fuzzing at 10⁴× the volume confirms 0 production crashes on this
entry. (The one genuine unconditional panic — inline-image `.unwrap()` — is on the *other* entry
`Content::decode`, which `content_decode` fuzzing found in ~2 min.)

### Staged soaks (stage 0/1/3a) — interim live triage 2026-07-18

3 parallel 6h fork soaks (overflow-checks off, `-ignore_crashes`). Mid-run, pulled the crash
artifacts from the *running* containers and triaged live:

- **`content_decode` — 67 crashes, ALL one site.** Ran every crash artifact through `Content::decode`
  in a plain-release build (overflow-checks off) with a panic-location hook: **67/67 →
  `parser/mod.rs:670`** (the inline-image `.unwrap()`, finding #1). **Zero new panic sites.** The
  content-decode surface holds exactly the one already-disclosed bug — nothing hiding in the pile, so
  no advisory update / follow-up needed. Stage 0 ("enumerate all content panics") is effectively
  answered: one unique site.
- **`load_pw` (encryption/decrypt) — 0 crashes** at ~1.6M execs. The largest previously untested
  surface (AES/CBC/ECB + password KDF over attacker crypto params) is clean so far; running to 6h.
- **`get_page_images` — 0 crashes** at ~2.8M execs. The fuzzer did not synthesize the empty
  `/ColorSpace []` structure from the seed corpus — #2 stands on its targeted PoC + reattack repro.

**Final (soaks stopped at ~11.2k/21.6k s ≈ 52% of the 6h budget, to finalize the goal):**
- `content_decode`: **72 crashes, all `parser/mod.rs:670`** (finding #1) — 0 new sites, 229M execs.
- `load_pw` (encryption): **0 crashes**, 1.67M execs, cov 5300.
- `get_page_images`: **0 crashes**, 2.99M execs, cov 5491.

Honest caveat: the encryption (`load_pw`) surface is **clean at ~1.7M execs**, a strong but not
exhaustive signal — the soak was cut at ~half its 6h budget; re-runnable to the full 6h if a stronger
"encryption production-clean" statement is wanted. Nothing in the finding ledger changed: content =
only #1; encryption and get_page_images produced no crashes.

## Stage 3 (targeted PoCs) — progress 2026-07-18

- **✅ Pages-tree recursion → stack overflow — CONFIRMED prod-real** (`reader.rs:771`, CWE-674,
  both models). `Document::load_metadata` on a deep linear `/Pages` chain (N=200000, each
  `/Type/Pages /Kids[next]`, **no `/Count`**) → `get_pages_tree_count` recurses per Kid,
  cycle-guarded but not depth-bounded → `fatal runtime error: stack overflow, aborting`
  (SIGABRT, exit 134), plain release, unconditional, uncatchable. First attempt with a `/Count`
  on the root did NOT overflow (the `/Count` short-circuits `extract_page_count` before it
  descends — the "no /Count" condition is load-bearing) — a reachability subtlety caught by
  execution. Entry is `load_metadata`, not `load_mem` (`load_mem`+`get_pages` used a different,
  non-overflowing traversal). Fuzzing can't synthesize a ~10⁵-deep chain — targeted PoC only.
  PoC: [`poc/pagetree_recursion/`](poc/pagetree_recursion/).
- **~ decompression-bomb — dispositioned documented/by-design, no PoC.** `max_decompressed_size`
  defaults `None` (unbounded), but the crate documents the risk and ships the opt-in guard; the
  9M-exec `load_mem` soak produced 0 OOM at a 4 GB rss cap. Honest call: documented limitation,
  not a hidden vuln — building an elaborate `/ObjStm` bomb to confirm a documented default would
  be rabbit-holing. Left as-is.
- **✅ document.rs:779 empty `/ColorSpace` `array[0]` — CONFIRMED** by the stage-2 reattack bridge:
  `panicked at document.rs:779:83: index out of bounds` (CWE-125, via public `get_page_images`).
  Unconditional. (The `get_page_images` fuzz soak may corroborate at collection.)

## Stage 2 — reattack (static→harness bridge) — DONE, L11 closed

`reproof reattack` on the 4 Track B static findings (`--findings ~/lopdf-trackb-findings.json`,
sonnet, --parallel). The bridge routed each finding → fuzz template + sanitizer and synthesized a
reproducing harness. **3/4 auto-reproduced:**

| finding | CWE | verdict | crash |
|---|---|---|---|
| inline-cs-unwrap | 248 | reproduced | `panicked parser/mod.rs:670 (unwrap on Err)` |
| getpageimages-cs-array0 | 125 | reproduced | `panicked document.rs:779:83 index out of bounds` |
| xrefstream-w-alloc | 789 | reproduced | `memory allocation of 1099511627776 bytes` + SIGABRT |
| pagetree-recursion | 674 | build_failed | agent hit `stack overflow`+SIGABRT in-transcript, but the generated harness didn't compile |

This is the find→fuzz bridge (L11's missing stage) validated end-to-end on **static** findings — the
"we never ran static→fuzz" gap closed properly. The 3 reproductions are all unconditional (unwrap /
OOB-index / 1 TB alloc-abort) → **L10-clean, production-real**. Net: reattack alone closed 2 findings
that were still candidates (`document.rs:779`, `xref-W-alloc`). The one `build_failed` is an honest
bridge limitation (generative deep-chain harness hard to auto-build; the bug itself is real — hand
PoC + agent transcript both hit the SIGABRT). scorecard: `reattack/SCORECARD.md`. It also flagged a
routing gap: `concurrency_async` (rayon default) needs a **TSAN** image, not the ASan default — an
untested surface for a future pass.

**Confirmed prod-real total: 4** (inline-unwrap, document.rs:779, xref-W-alloc, pagetree-recursion).

## Status

- Track A / Sonnet: **running** (≥1 candidate panic found on the `load_mem` surface).
- Track A / Opus: pending (sequential — starts when Sonnet finishes).
- Track B: **done** (candidates above; 1 execution-confirmed, rest under verification).

## Next

- Collect Track A crashes; cross-reference against Track B candidates (dynamic ⟷ static

  confirmation — the 2×2 actually closing the loop here, unlike x509).
- Verify the strongest remaining Track B reals by targeted PoC: Pages-tree stack overflow;
  decompression bomb as a hang; `document.rs:779` empty-array panic.
- Characterise severity honestly per cluster (documented-guard vs unconditional vs
  overflow-checks-gated). Then consolidate the lopdf 2×2 and compare with x509 (did the crash
  track pay off on a byte-rich target? — the central L4 hypothesis).

## Soak enumeration (2026-07-18, full 6h soaks, production profile overflow-checks=off)

Two fork-mode soaks on the runner (`run_fuzz_soak.sh`, `-ignore_crashes=1` fork=N), corpus carried.
Checked mid-run by reproducing in-container artifacts (libFuzzer copies to /out only at SOAK-DONE;
the live crash inputs live inside the container at `fuzz/artifacts/<tgt>/`).

- **content_decode — STAGE-0 ENUMERATION COMPLETE (definitive, not sampled).**
  5518 crash *inputs* (libFuzzer input-hash dedup) reproduced through the production-profile
  binary and deduped **by panic location**: **all 5518 → a single site**
  `src/parser/mod.rs:670:61` — `get_abbr(b"CS", b"ColorSpace").unwrap()` on `Err(DictKey("ColorSpace"))`.
  Reachable from untrusted bytes: an inline image (`BI…ID…EI`) that is not an image-mask
  (`/IM true`) and omits `/CS`+`/ColorSpace` hits the one `.unwrap()` on a line whose siblings all
  use `?`. This is the known prod-real **#1** (inline-image unwrap); trivial fix = replace `.unwrap()`
  with `?`. **No new/second panic site exists on the content-decode surface** — cov plateaued (1529),
  single-site over the *entire* crash set. The `-ignore_crashes` counter (~5k) is repeat-hits of this
  one shallow bug, NOT distinct sites (L-ops: the counter is not an enumeration; the artifact dir is).
- **load_pw (encryption) — clean so far.** 2.06M execs, cov 5398 (path well-exercised),
  crash/oom/timeout = **0/0/0**, **0 crash artifacts** in-container. No panic on the crypto-over-
  attacker-parameters surface yet; soak continuing to full 6h budget.

Net: **zero new findings.** content_decode = the single known #1 (now proven single-site over the full
5518-input crash set); encryption zero. Answers "new срабатываний?" → none.

## Soaks STOPPED by operator (2026-07-18 12:23 UTC — "достаточно находок")

Operator ended both soaks at ~47-48% of the 6h budget; findings judged sufficient. Final:
- **content_decode:** 135M execs, cov 1537 (plateaued), 6911 crash inputs — **all one site**
  `parser/mod.rs:670` (ColorSpace `.unwrap()` = #1). Enumeration saturated: single site over the
  entire crash set well before the budget; extra wall-clock would only grow the repeat-hit counter.
- **load_pw (encryption):** 2.31M execs, cov 5400 (path well-exercised), **0 crashes / 0 artifacts**.
  The crypto-over-attacker-parameters surface produced no panic in 2.31M execs — clean at stop
  (not a full-6h clean, but a substantive negative result on the largest previously-untested surface).

**lopdf campaign closed.** Net dynamic result: 1 real prod bug (#1 content unwrap, disclosed) + the
Track-B structural reals (#2/#3/#4, targeted-PoC confirmed, disclosed); encryption surface clean at
2.31M execs. No new sites beyond the known set.
