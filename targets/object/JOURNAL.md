# object 0.39.1 — full-pipeline run (2026-07-18)

Target: `object` 0.39.1 (gimli-rs), `profile: rust`. ELF/PE/COFF/Mach-O/XCOFF/archive/wasm reader.
A **mature, hardened, upstream-fuzzed** target (~534M downloads, core toolchain dep) — bounds-checked
zero-copy `pod.rs` (checked_mul + get + align), 0-unsafe `read_ref.rs`/`util.rs`. So the realistic
surface is **logic DoS** (reachable panic / unbounded alloc / hang), not easy memory corruption.
Honest expectation: fewer/harder finds than a fresh decoder.

## Stages

0. **Threat model FIRST** (per operator) — `THREAT_MODEL.md` (9 sections, bootstrap) + `capabilities.json`.
   §9: untrusted_deserialization + network_protocol_parser → `run_crash_track()`=true, vote_budget=3,
   asan. Priorities: T1 reachable-panic DoS, T2 unbounded-alloc / decompression bomb; T4 (pod-cast
   corruption) rated well-guarded/mitigated.
1. **Setup** — crate wrapper (`riptarget` driver: `File::parse` + walk sections/symbols/relocations/
   imports/exports + `uncompressed_data` for the compression surface; fuzz target `parse`). Image FROM
   lopdf-fuzz. Both riptarget profiles built (shipping/detect) for the P0.1 grade gate. API compiled
   first try.
2. **Find (union-of-5 Workflow, wf_9745aa27-425)** — lens-diverse finders (ELF / PE-COFF / Mach-O /
   archive-wasm-xcoff / pod-compression), seeded from the threat model, told to hunt DEEP bugs (alloc-
   from-count T2, cycles/recursion T5, cross-table index) not shallow slice reads the checked layer +
   fuzzer already cover. → verify panel (build_profile + admissibility gates). [in flight]
3. **Fuzz (1h, shipping + ASan, fork=4)** — parse entry, 11 seeds (ELF/.a/.o + PE/Mach-O/wasm/fat
   stubs). Start 15:29 UTC → finish ~16:30 UTC. [in flight → collect]

[results pending — 2×2 consolidation to follow]

## Fuzz result + 2×2 scorecard (static ⟷ dynamic) — COMPLETE

**Fuzz (1h, shipping + ASan, fork=4):** 45.9M execs, cov 1507, **crash/oom/timeout = 159/16/0**. Diagnosed
live via the ASan binary: **37/40 sampled = `allocation-size-too-big`, 3/40 = OOM** — ALL one class:
count-driven / unbounded **resource-exhaustion** (T2). **0 panics, 0 memory corruption.** The 175
artifacts are one class, not 175 bugs. None reproduce as a hard crash under the non-ASan riptarget
(try_reserve fails gracefully or needs real RAM exhaustion) — the P0.1/L10 gate caught that "159 crashes"
is not 159 findings.

| finding | source | disposition | reproduces? | class |
|---|---|---|---|---|
| **Zstd decompress cap-bypass** (read/mod.rs) | **static** union-of-5 | **confirmed prod-real** | yes — 6.7KB ELF → 386MB RSS (ch_size=64 ignored); present on 0.39.1 AND master | unbounded alloc (T2) |
| PE `imports()` O(S²) alloc (read/pe/file.rs) | static | confirmed (static, not PoC'd) | — | complexity/alloc DoS |
| Mach-O `exports_trie()` infinite loop (exports_trie.rs) | static | confirmed (static; 2ndary API, not File::parse) | — | infinite loop (T5) |
| 175 alloc-too-big/OOM artifacts | **dynamic** fuzz | resource-exhaustion class (mostly by-design count allocs) | ASan-only | resource DoS (T2) |
| panics / memory corruption | both | **NONE** | — | — |

**Cross-reference / the loop closing:**
- **Threat model was accurate**: T4 (pod-cast corruption) = **0 findings** — the bounds-/checked_mul-
  guarded pod layer held exactly as predicted; T1 panic-DoS = 0; the whole real surface is **T2 resource-
  exhaustion**, the predicted priority. A hardened, upstream-fuzzed target behaves like one.
- **Static found the one genuine DEFECT the fuzz couldn't**: the Zstd cap-bypass is an *inconsistency*
  (Zlib caps, Zstd doesn't) — a real bug, not by-design — and the seed corpus had no valid zstd stream so
  the fuzzer never synthesized it (**L14**: static+targeted-PoC reaches what fuzz can't).
- **Dynamic characterized the by-design noise**: the fuzz's 175 count-alloc OOMs are the "parser allocates
  from attacker counts" class most parser maintainers treat as the caller's cap responsibility — value is
  in knowing it's ONE class, not a pile of bugs (P0.6 verdicts-not-counts).
- admissibility(Zstd) = **ADMISSIBLE** (where_checked traced, parse-entry repro).

**Net: 1 confirmed prod-real defect (Zstd cap-bypass, empirically verified, on latest+master)** + 2
static-confirmed secondary DoS (PE imports O(S²), macho trie loop) + a by-design count-alloc class. 0
panics, 0 corruption. Advisory for gimli-rs: `poc/zstd_decompress_cap_bypass/`.

## Re-verification pass (2026-07-18, before disclosing to gimli-rs)

Operator asked to re-verify everything independently before reporting to a serious team. Did not trust
the workflow agents (L3) — re-read the source + built empirical PoCs.
- **#1 Zstd cap-bypass — CONFIRMED + A/B proof.** Same ELF, only `ch_type` differs, both `ch_size=64`
  expanding to 200 MB: ZLIB → 3 MB RSS (caps, errors), ZSTD → 386 MB RSS (grows). Genuine per-format
  inconsistency, not a uniform no-cap policy. Reachable via default `File::parse`→`uncompressed_data()`.
  Present on 0.39.1 AND master.
- **#3 Mach-O exports_trie loop — UPGRADED static→CONFIRMED.** Re-read exports_trie.rs (no visited/
  depth/forward-progress guard, verified). Built `trie_driver` + a 52-byte cyclic-trie Mach-O → hangs
  `exports_trie()` (timeout, exit 124). Reachable via the SECONDARY public `exports_trie()` API, not
  File::parse. PoC: `poc/macho_exports_trie_loop/`.
- **#2 PE imports O(S²) — DOWNGRADED confirmed→code-observation.** Re-read pe/file.rs+import.rs: the
  no-cap claim is true, BUT each thunk push calls `hint_name(thunk.address())` which errors (aborts
  imports()) unless the reinterpreted bytes are valid hint/name RVAs → the O(S²) blow-up is NOT
  demonstrated and may be unachievable. Listed as an unverified code observation, not a finding.

**Re-verification worked as intended: strengthened the real (#1 A/B, #3 empirical), deflated the
speculative (#2). Final: 2 confirmed prod-real (#1 default-path unbounded-alloc, #3 secondary-API
infinite-loop) + 1 code-observation (#2) + a by-design count-alloc class. 0 panics, 0 corruption.**
