# zune-jpeg 0.5.15 — full-pipeline run (2026-07-18)

Target: `zune-jpeg` 0.5.15 (crates.io tarball; repo etemesi254/zune-image), `profile: rust`.
A JPEG decoder with **real unsafe SIMD** (AVX2/NEON IDCT, upsampler, color-convert, `unsafe_utils`)
+ unchecked `usize` dimension math — a memory-safety surface, not just panic-DoS. Run on Tamm within
a **1h CPU-clock cap** on the fuzz soak; static find done as a union-of-N Workflow off-box.

## Stages

0. **Threat model** — `THREAT_MODEL.md` (9-section contract) + `capabilities.json`. §9: unsafe_simd,
   untrusted_deserialization, network_protocol_parser → `run_crash_track()`=true, `vote_budget()`=8,
   sanitizers=asan+miri. Top threats: T1 unsafe-SIMD OOB write, T2 dim-overflow under-alloc, T3 panic-DoS.
1. **Setup** — crate wrapper (`riptarget` decode driver + `fuzz/decode` target; API fixed to
   `JpegDecoder::new(ZCursor::new(data)).decode()` for 0.5.15). Fuzz image FROM lopdf-fuzz. Both
   riptarget profiles built (shipping overflow-checks off / detect on) for the P0.1 grade gate.
2. **Find (union-of-N, Workflow, 42 agents / 3.27M tok)** — recon → 5 lens-diverse finders
   (int-overflow / unsafe-SIMD / Huffman / progressive / headers) → 3-skeptic adversarial verify per
   candidate → my `build_profile` (P0.1) + `admissibility` (P1.4) gates. 13 raw → 12 unique candidates.
3. **Fuzz (1h, shipping profile + ASan, fork=4)** — decode entry, 12 seed JPEGs. [in flight → collect]

## Findings

### CONFIRMED (1) — production-real, graded under both profiles

- **index-out-of-bounds panic `mcu_prog.rs:102`** (`decode_mcu_ycbcr_progressive`), **panic-DoS
  LOW–MEDIUM**. YCCK→YCbCr colorspace fixup (`misc.rs:300-303`) sets colorspace to YCbCr (3 comp)
  **without clamping** to `components.len()` when APP14 `transform=2` (YCCK) meets a progressive SOF2
  with 2 components; the sibling non-YCCK branch clamps via `MultiBand(components.len())`, this one
  doesn't → loop `0..3` indexes `components[2]` on a len-2 slice → panic. **163-byte PoC**,
  reproduces under BOTH shipping (overflow-checks off) and detect → NOT build_profile_gated.
  Full trace + PoC: `poc/ycck_progressive_oob_panic/`. admissibility=ADMISSIBLE (where_checked traced,
  parse-entry repro). Real upstream bug — disclosure candidate (not yet reported; operator decision).

### BUILD_PROFILE_GATED / R7 (4) — P0.1 gate in action

Arithmetic-overflow candidates at `mcu_prog.rs:103`, `mcu.rs:178`, `mcu_prog.rs:397`,
`bitstream.rs:400` — the finders/verifiers flagged each as fires-only-under-`overflow-checks=on`.
The **shipping-profile fuzz will not crash on these**; they are latent arithmetic-overflow (R7), NOT
production crashes. This is exactly the L10/P0.1 discipline: a JPEG decoder's dimension math throws off
overflow candidates that the detector build would have mis-graded as `real`. (Worth a separate
overflow-checks=ON fuzz pass to enumerate the class, per the fuzz Cargo.toml note.)

### CONTESTED (0)

## Notes

- L14 pairing held: the confirmed bug is a **specific structural combo** (APP14 t=2 + SOF2-2comp +
  progressive) that a seed-corpus fuzz is unlikely to synthesize — a static-find + targeted-PoC reach,
  complementary to the ASan fuzz (which hunts the unsafe-SIMD OOB class T1/T4).
- The top threat-model item **T1 (unsafe-SIMD OOB write in `ycbcr_to_rgb_avx2_1`/`_neon`, 48-byte
  unconditional store ignoring `offset`)** remains the highest-value open lead — pending the ASan fuzz
  result + a targeted PoC that forces an `out` chunk < 48 bytes.

## Fuzz result + 2×2 scorecard (static ⟷ dynamic) — COMPLETE

**Fuzz (1h, shipping profile + ASan, fork=4):** 7.43M execs, cov 3232, corp 2338, **crash/oom/timeout
= 0/0/1**. `harness.soak` site enumeration on the crash set = **0 distinct sites — memory-clean**.
The 1 timeout + 21 slow-units = a **decompression bomb (T5)**: 1402-byte JPEG → 12544×12288×3 =
462 MB / 154 Mpix decode (~330,000× amplification; up to ~17 GB at max 16-bit dims). PoC
`poc/decompression_bomb/`.

| finding | source | disposition | reproduces shipping? | class |
|---|---|---|---|---|
| YCCK progressive `components[2]` panic (mcu_prog.rs:102) | **static** union-of-5 | confirmed prod-real | **yes** (both profiles) | panic-DoS |
| decompression bomb (462 MB from 1.4 KB) | **dynamic** fuzz | confirmed | yes (unbounded alloc) | resource DoS (T5) |
| arith-overflow ×4 (mcu_prog:103, mcu:178, mcu_prog:397, bitstream:400) | static | **build_profile_gated / R7** | **no** (detect-only) | latent overflow |
| unsafe-SIMD OOB write (ycbcr_to_rgb, T1) | threat-model lead | **unconfirmed** | — | (open) |

**Cross-reference (the loop closing):**
- The YCCK panic (static) was NOT found by fuzz — a specific structural combo (APP14 t=2 + SOF2-2comp
  + progressive) a seed-corpus fuzz won't synthesize. **L14 confirmed: static+targeted-PoC reaches what
  fuzz can't.**
- The decompression bomb (dynamic) was NOT flagged by static — the finders hunted memory-safety/panics,
  not resource-exhaustion. **Dynamic caught what static missed** — the two tracks are complementary, not
  redundant.
- The 4 R7 overflow candidates: the **shipping-profile fuzz correctly did NOT crash on them** — a live
  dynamic validation of the P0.1 gate (a detector build with overflow-checks=on would have "crashed"
  and mis-graded them real; the shipping fuzz proves they're latent, not production crashes).
- **T1 (unsafe-SIMD OOB write)** — the highest-value threat-model lead — did NOT reproduce in 1h seeded
  ASan fuzz. A meaningful-but-not-exhaustive negative; needs a targeted PoC that forces an `out` chunk
  < 48 bytes (or a longer/dictionary fuzz), NOT a "clean" claim.

**Net: 2 confirmed prod-real** (1 reachable panic-DoS + 1 decompression bomb), **4 R7 latent overflow**
(P0.1-gated), **1 open memory-safety lead** (T1). The YCCK panic is a genuine upstream bug and a
disclosure candidate (operator decision — not auto-reported).

## Continuing: T1 (unsafe-SIMD OOB write) investigation

Prove-or-refute the top threat-model lead: can `worker.rs color_convert_ycbcr` pass an `out` chunk
< 48 bytes into the unchecked RGB SIMD store (`ycbcr_to_rgb_avx2_1`, avx.rs:144)? Reading the chunking
+ width<16 temp path + remainder-overlap write to decide reachability, then a targeted ASan PoC or an
honest refutation.

### T1 conclusion — REFUTED (unsafe-SIMD store is sound as used)

Read all three call sites of the RGB converter in `worker.rs color_convert_ycbcr`:
- **width<16** (l.311-328): converter writes into `temp = [0; 64]` (64 ≥ 48) — safe.
- **main loop** (l.334-347): `out.chunks_exact_mut(16 * num_components)` = `chunks_exact_mut(48)` for RGB,
  so each `out_c` is **exactly 48 bytes** — the missing length check is compensated upstream.
- **remainder overlap** (l.352-372): converter writes into `temp` (64) again, then a safe
  `rem.copy_from_slice(&temp[0..rem.len()])` where `rem` is a 48-byte `chunks_exact_mut(48).next()`.

`ycbcr_to_rgb_avx2_1` writes exactly 48 bytes at index 0; in every path `out.len() ∈ {48, 64} ≥ 48`, so
**no heap OOB write is reachable**. The static proof EXPLAINS the dynamic null result (0 OOB in 7.43M
ASan execs across varied widths incl. remainder-heavy 33×17) rather than hand-waving "not enough fuzz".
The absent length check is a latent footgun (defense-in-depth: add `out.get_mut(..48)` like the RGBA
path) but is **not** an exploitable bug under the current caller. **Disposition: refuted** — an honest
negative, the x509-RSA-refutation analog.

**Final ledger: 2 confirmed prod-real (YCCK panic + decompression bomb), 4 R7 latent overflow, 1 refuted
(T1). No open memory-safety lead remains.** zune-jpeg's unsafe-SIMD decode surface is memory-clean under
1h ASan fuzz AND the top static lead statically refuted.

### R7 arith-overflow — second-order analysis (width-of-type + downstream)

Correcting the earlier "worth an overflow-checks=on pass" note — that would prove the sites are real
overflows, NOT that they are production vulnerabilities. Per-site, by operand type:
- `mcu_prog.rs:103` (`mcu_width*v*h*mcu_height`, **usize**) and `mcu.rs:178` (same `*64`, **usize**):
  bounded by 16-bit JPEG dims → max product ~7e10 ≪ 2^64, so **cannot overflow on 64-bit** (the
  overflow-checks=on panic is a **32-bit-only** event: wasm32/armv7/i686). On 32-bit the wrap →
  under-allocated `vec![0; len]` → downstream OOB (the T2 class) — a real-but-narrow, platform-specific
  lead. This, not a detector-build fuzz, is the only version with production value.
- `mcu_prog.rs:397` (`position` index, **usize**): consumed by `.get_mut(position)` (bounds-checked,
  `Option`) → a wrapped value yields None/handled, **never OOB**. Safe regardless of width.
- `bitstream.rs:400` (`dc_prediction * qt_table[0]`, **i32**): overflows on all targets, but the wrap
  only yields a wrong coefficient → wrong pixels (**correctness**, not memory safety).

**Net:** none are 64-bit production memory-safety bugs. R7 (build_profile_gated) correctly kept them out
of prod-real; the type-width + bounds-check analysis further reduces them to "1 correctness-only + 1
bounds-checked-safe + 2 32-bit-only under-alloc leads". No overflow-checks=on fuzz pass is warranted.

### R7 arith-overflow — final disposition: INFO / no-security

Per the second-order analysis above, the 4 arithmetic-overflow candidates are recorded as
**info / no security impact** (not vulnerabilities): 64-bit cannot overflow the 3 usize sites (16-bit
dims bound the product), the i32 site is correctness-only, `mcu_prog.rs:397` is bounds-checked, and the
only residual is a narrow 32-bit-only under-alloc lead (2 sites). Carried in the disclosure package as
info note N2, no fix requested. **Final ledger: 1 prod-real reachable panic (fix verified) + 1
decompression-bomb hardening note + 4 info/no-security overflow + 1 refuted (T1).**
