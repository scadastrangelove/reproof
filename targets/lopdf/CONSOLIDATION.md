# lopdf — 2×2 campaign consolidation

**Target:** [`J-F-Liu/lopdf`](https://github.com/J-F-Liu/lopdf) `0.44.0` (commit `1efa270`),
default features. **Question:** the same 2×2 as x509 —
{Track A autonomous crash pipeline, Track B curated static} × {Opus 4.8, Sonnet 5} — but on a
deliberately **byte-rich** target (a PDF parser: xref, streams, filters, object graph) chosen to
test the L4 hypothesis that the crash track should pay off where it didn't on logic-heavy x509.

## The 2×2

| | **Opus 4.8** | **Sonnet 5** |
|---|---|---|
| **A — autonomous crash pipeline** (panic + overflow-checks + hang detector) | 1 crash (`parser/mod.rs:516`), killed ~32 min, 1/5 runs, many cyber-safeguard blocks. **Overflow-checks-gated → 0 production-real.** | 4 crashes → 3 sites (`parser_aux.rs:596`, `object.rs:1125`×2, `filters/png.rs:88`), killed ~46 min, 4/5 runs. **All overflow-checks-gated → 0 production-real.** |
| **B — curated static scan+triage** (L1 `dep_citation` enforced) | 27 → 27 → **12 real / 15 FP** (candidates) | 26 → 26 → **18 real / 8 FP** (candidates) |

## Headline results

**1. The crash track fired — but produced 0 production-real crashes (L10).**
L4 held in the narrow sense: unlike x509 (0 crashes in 93 min), lopdf's crash agents immediately
crafted PDF inputs and found **5 crashes** across both models within minutes. But every one was a
`panic_const_{add,mul}_overflow` that fires **only** because the detector image builds with
`overflow-checks=on`. Re-tested against a plain `cargo build --release` (lopdf's shipping default,
overflow-checks off), **all 5 fail to reproduce** — they `reject:` or parse `ok`. So the honest
count is **0 production-real panic-DoS from Track A**, on both models.

→ **L10 (new project lesson):** the detector's build flags are part of the threat model. A crash
under a non-default flag must be re-tested against the target's real release profile before grading
`real`. The grader re-used the same instrumented binary, so it graded these `real`; the fix is a
shipping-profile re-test at the grade stage (or build the detector with the target's actual profile).

**2. On the same overflow sites, the curated static triage was more honest than the crash grader.**
Track B independently flagged the exact same arithmetic-overflow sites and *correctly* dispositioned
them as R7 / overflow-checks-conditional (Opus verbatim: "with overflow-checks off it silently
truncates … R7"). So the human-in-the-loop static track out-calibrated the autonomous crash grader
on severity — because it reasoned about the shipping semantics instead of trusting one instrumented
run.

**3. Track B found a real bug the crash track structurally could not reach.**
The one **execution-confirmed, unconditional** production panic is the inline-image `.unwrap()` on a
missing `/ColorSpace` (`parser/mod.rs:670`): `Content::decode(b"BI /W 1 /H 1 /BPC 8 ID \x00 EI")`
panics under plain release. It lives behind the public `Content::decode` API (text/image
extraction), **not** `load_mem`. The crash driver is scoped to `load_mem` (it fetches raw
page-content bytes but never parses them into operations), so **Track A could never reach it** —
only the curated review did. → **Driver scope = the crash track's reachable set.** To cover it you
must widen the driver's call graph (add `Content::decode`), or accept the blind spot.

**4. L1 dependency-citation worked, structurally.**
Track B's triage schema required a `dep_citation` field. Verdicts carry real citations
(`vendor/nom-8.0.0/...`, `vendor/flate2-1.1.9/src/zlib/read.rs:267`, `vendor/rangemap-1.7.1/...`);
`n/a` entries explicitly state the verdict rests on lopdf's own code. No uncited dependency-behaviour
premise slipped through — the failure mode that produced x509's one wrong verdict was closed.

## Honest finding ledger (production severity)

- **Confirmed production-real: 4** (all unconditional — none overflow-checks artifacts; L10-clean):
  1. inline-image `/ColorSpace` `.unwrap()` panic (`parser/mod.rs:670`, CWE-248) — via
     `Content::decode`. Confirmed **3 ways**: hand PoC, `content_decode` fuzz (~2 min), reattack bridge.
  2. **`document.rs:779` empty `/ColorSpace` `array[0]`** (CWE-125) — via public `get_page_images`.
     Reattack reproduced: `panicked at document.rs:779:83: index out of bounds`. (Was PoC-pending;
     the bridge closed it.)
  3. **xref-stream `/W` width → 1 TB allocation → abort** (`parser_aux.rs:568`, CWE-789). Reattack
     reproduced: `memory allocation of 1099511627776 bytes` + SIGABRT. (Was a Track B candidate;
     the bridge closed it.)
  4. **Pages-tree recursion → stack overflow** (`reader.rs:771`, CWE-674) — via `Document::load_metadata`
     on a deep linear `/Pages` chain (no `/Count`). Confirmed by hand PoC (N=200000 → SIGABRT) and by
     the reattack agent in-transcript; the auto-generated harness `build_failed` (a bridge limitation
     on generative/structural harnesses, not a false finding). PoC: `poc/pagetree_recursion/`.

### Adversarial maintainer review (all 4)

Each finding was re-verified by execution, then reviewed by an independent agent role-playing a
skeptical lopdf maintainer trying to reject it. **All 4 survived as file-worthy; none rejected.** The
pass corrected my drafts: **severity Moderate → Low across the board** (all availability-only,
memory-safe panics/aborts — lopdf's prior RUSTSEC panic-DoS class); fixed the #1 fix snippet
(`.unwrap()`→`?`, not the `.ok()` form); and killed two would-be dismissals with the crate's own
code — #3 is **not** the documented decompression-bomb class (`max_decompressed_size` doesn't cover
the `/W` vectors; PoC has no `/Filter`), #4 is an **inconsistency not by-design** (`PageTreeIter`
already caps depth at 256). It also re-confirmed #2's parse-reachability was genuine (the reattack
harness's builder-API repro would have been rejectable — the x509-RSA construction trap — but the
real `load_mem` PoC holds). Advisories + full verdicts: `poc/advisories/` (`00-ADVERSARIAL-REVIEW.md`).

## Stage 2 — reattack (static→harness bridge) — L11 closed properly

Ran `vuln-pipeline reattack` on the 4 Track B static findings (`--findings` file). The bridge
dispatched each to a fuzz template + sanitizer and had an agent synthesize a reproducing harness:

| finding | CWE | template | verdict |
|---|---|---|---|
| inline-cs-unwrap | 248 | byte_parser / asan | **reproduced** |
| getpageimages-cs-array0 | 125 | grammar_parser / asan | **reproduced** |
| xrefstream-w-alloc | 789 | grammar_parser / asan | **reproduced** |
| pagetree-recursion | 674 | grammar_parser / asan | build_failed (agent still confirmed the overflow in-transcript) |

**3/4 auto-reproduced.** This is the flagship find→fuzz bridge validated end-to-end on real static
findings — the L11 gap ("we never ran the static→fuzz stage") closed the right way. The bridge also
correctly emitted a *routing map* for the one capability it can't cover with ASan (concurrency_async
→ needs TSAN — `rayon` is on by default). The one `build_failed` is an honest bridge limitation:
generative/structural harnesses (a 10⁵-deep object chain) are hard to auto-synthesize — the recursion
bug is real (hand PoC + agent transcript both hit the SIGABRT), the *template* just couldn't build it.
- **Overflow-checks-gated (R7 in release):** the whole `parser_aux.rs:596` / `object.rs:1125` /
  `parser/mod.rs:516` / `png.rs:88` arithmetic cluster — real latent bugs, not shipping panic-DoS.
- **Documented / by-design:** unbounded decompression on default `load_mem`
  (`max_decompressed_size = None`) — the crate documents the risk and ships the opt-in guard.

## x509 vs lopdf — what the two campaigns together show

| | x509-parser (logic-heavy) | lopdf (byte-rich) |
|---|---|---|
| Track A crashes | 0 (93 min, rabbit-holed) | 5 → **0 production-real** (overflow-checks artifacts) |
| Track B genuine reals | 2 (ASN1Time::add, CRL-dup) | ≥1 confirmed + strong candidates |
| Decisive lesson | opening the dependency (L1/L2); model triage divergence | detector build-profile (L10); driver scope; static triage > crash grader on severity |
| Net | curated track carried it | curated track carried it *again* |

**Across both targets, the autonomous crash pipeline produced 0 production-real bugs; every genuine
finding came from the curated static track.** On the logic-heavy target the crash track couldn't
reach the bugs; on the byte-rich target it reached sites but only surfaced build-config artifacts
that its grader couldn't distinguish from real. The consistent lever is **execution-grounded triage
against the real shipping profile** — which the curated track did by hand and the autonomous grader
did not.

## Dynamic fuzzing (added after the initial 2×2 — closing the L11 gap)

The autonomous "crash pipeline" is a blind LLM find loop, not coverage-guided fuzzing; the
find→fuzz bridge was never run (L11). Retrofitted a real cargo-fuzz harness (`crate/fuzz/`, two
targets, shipping profile: overflow-checks off) and ran it:

| target | budget | result |
|---|---|---|
| `content_decode` | 120 s | **crash in ~2 min** → `parser/mod.rs:670` inline-image `.unwrap()` — *the same production-real bug found by hand*. Empirical proof that seeded coverage-fuzzing would have surfaced it automatically. |
| `load_mem` (sanity) | 600 s / 113 K execs | **clean** (0 crashes) |
| `load_mem` (soak) | **~9 M execs, ~48 CPU-hours, fork=8** | **CLEAN — 0 crashes / 0 OOM / 0 hangs, coverage saturated (~5754 edges)** |

**This reframes the whole lopdf crash story.** Track A's 4 "crashes" were overflow-checks
artifacts (L10); deep coverage-guided fuzzing at 10⁴× the volume, on the shipping profile, finds
**0 production crashes on `load_mem`**. The only genuine unconditional panic is on the *other*
entry (`Content::decode`), which its own fuzz target caught in minutes. So: the crash-DoS surface
reachable from `load_mem` is empirically clean; the real bug lived exactly where the `load_mem`-
scoped autonomous driver couldn't see it, and a proper fuzz harness — not the LLM find loop — is
what nails both facts cheaply.

## Staged deep-dynamic pass (goal "поэтапно") — final

Beyond the initial 2×2, a staged dynamic pass was run to close every reachable surface:

| Stage | What | Result |
|---|---|---|
| 0 | `content_decode` soak (`-ignore_crashes`) — enumerate all content panics | **72 crashes → 1 site** (`parser/mod.rs:670`, #1). 0 new sites. |
| 1 | `load_pw` encryption soak (`load_mem_with_options`+password) — largest untested surface | **0 crashes** at 1.67M execs (cut at ~52% of the 6h budget; re-runnable for a fuller statement). |
| 2 | `reattack`/`scorecard` through the pipeline (static→harness bridge, L11) | **3/4 auto-reproduced**; closed #2 and #3 as candidates → confirmed. |
| 3 | targeted PoCs for `document.rs:779` / recursion / decompression-bomb | #2 parse-verified (real 487 B PDF), #4 confirmed (hand PoC, SIGABRT), decompression = documented/by-design. |
| — | `get_page_images` soak | 0 crashes at 2.99M execs (fuzzer didn't synthesize `/ColorSpace []`; #2 stands on PoC+bridge). |

**Net:** the deep pass added **no new findings** beyond the 4 confirmed — it *confirmed* two candidates
(#2, #3), enumerated the content surface (only #1), and left the encryption surface clean so far. The
4-finding ledger above is stable.

## Artifacts

- PoC: `poc/inline_image_unwrap/` (run in-image, offline, zero quota).
- On/off overflow-checks re-test evidence + full narrative: `JOURNAL.md`.
- Track B raw results: workflow `wwscdy271`.
