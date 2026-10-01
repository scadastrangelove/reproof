# gimli 0.34.0 — full-pipeline run (2026-07-19)

Target: `gimli` 0.34.0 (gimli-rs, SAME maintainers as object). DWARF debug-info parser under addr2line/
backtrace/rustc (498M downloads). Near-all safe Rust → surface = logic DoS (unbounded alloc, non-
terminating loop, panic) in its stateful interpreters over untrusted DWARF, NOT memory corruption.
Crown jewels: T1 unbounded-alloc (CFI `DW_CFA_remember_state` stack, op.rs Evaluation stack, counts),
T2 loop/super-linear (CFI / op eval / line program / DIE traversal). Heavily oss-fuzzed by a security-
conscious team → shallow bugs unlikely; realistic = a count/offset reaching alloc/loop without a cap
(the object-findings class).

## Stages
0. **Threat model FIRST** — `THREAT_MODEL.md` (9 sections) + `capabilities.json` (untrusted_deserialization
   + network_protocol_parser → run_crash_track=true, vote_budget=3, asan). Priorities T1/T2.
1. **Setup** — crate wrapper (riptarget + fuzz `eh_frame`: parse+unwind CFI, the richest state machine —
   covers remember_state T1 + CFI loop T2 + op.rs expressions via DW_CFA_*_expression). Image FROM
   lopdf-fuzz. Both riptarget profiles built (P0.1). edition-2024 API compiled first try.
2. **Find (union-of-5 Workflow, wf_73a8a88a-3d8)** — lenses: cfi-unwinder / dwarf-expr-eval / line-program /
   die-abbrev / lists-leb128, seeded from threat model → 3-skeptic verify (attacker count/offset reaching
   alloc/loop WITHOUT a cap). Same maintainer as object → high scrutiny. [in flight]
3. **Fuzz (1h, shipping + ASan, fork=4)** — eh_frame parse+unwind; corpus self-bootstrapped 1→261 from a
   minimal CIE (objcopy seed extraction returned 0, non-issue — fuzzer explores fine). Start 21:56 UTC →
   finish ~22:56 UTC. [in flight → collect]

[results pending — 2×2 consolidation to follow]

## Find result + triage (2026-07-19) — 1 disqualified, 1 confirmed reportable

**Static find (union-of-5, 53 agents):** 16 candidates → 2 confirmed (3/3) + 1 contested, all T1/T2
resource-exhaustion (as threat-model predicted). Re-verified each against code/docs/master (object+httparse
discipline — same gimli-rs maintainers, high scrutiny).

- **#1 DWARF-expression backward-branch infinite loop** (`op.rs:2026`, Evaluation) — **DISQUALIFIED.**
  A `DW_OP_skip`/`bra` with a backward in-range target loops forever; the only guard is `max_iterations`,
  which defaults to None. BUT `set_max_iterations` is **documented** (op.rs:1268): *"can be set to avoid
  denial of service attacks by bad DWARF bytecode."* → it is a **documented caller responsibility**, not a
  gimli bug (and reachable only if the consumer opts into `Expression::evaluation().evaluate()` on attacker
  bytes). Not reportable — the httparse/object-#2 lesson (verify against the maintainer's own docs).

- **#2 quadratic DIE-attribute parsing** (`unit.rs:2442` read_attributes) — **CONFIRMED, reportable.**
  An abbrev can declare K zero-byte attributes (`DW_FORM_flag_present`/`implicit_const`, 0 bytes in
  .debug_info) referenced by D one-byte DIEs; the caching `entries()` cursor parses all K attrs per DIE →
  work = D×K, the **product of two attacker-controlled section sizes**, bounded only by section length →
  Θ(input²). **Empirically verified** (quad_driver): 26 KB → 40M attr-parses/411 ms; **166 KB → 320M/3.05 s**;
  linear in D, unbounded scaling. **Live on master** (unit.rs:2442 unchanged), **undocumented**, **no known
  issue**. Memory stays bounded (cursor reuses the attr buffer) → CPU/wall-clock DoS (CWE-407). PoC:
  `poc/quad_die_attributes/`. Reachable via any consumer that walks the DIE tree (addr2line/backtrace) on
  untrusted DWARF.

**Net so far: 1 confirmed reportable (quadratic DIE-attrs, Low-Med algorithmic-complexity DoS).** Fuzz
(memory/OOM/timeout) still in flight → collect at ~22:56 for the 2×2 (T1 memory + any dynamic OOM/timeout
corroborating #2's class).

## Fuzz result + 2×2 + disclosure — COMPLETE

**Fuzz (1h eh_frame CFI, ASan, fork=4):** 547M execs, cov 713, corp 1867, **crash/oom/timeout = 0/0/0**.
The CFI unwinder (T1 remember_state, T2 CFI loop, op.rs expressions via DW_CFA_*_expression) is memory/
resource-clean. NB the fuzz targeted eh_frame, NOT the .debug_info/.debug_abbrev path where #2 lives —
so #2 is a static-only find (the fuzzer neither reaches nor synthesizes the abbrev(K flag_present)+D-DIE
structure, and its 3s/166KB is under the 25s timeout). L14: static + targeted PoC reaches what fuzz can't.

| finding | source | disposition |
|---|---|---|
| #2 quadratic DIE-attribute parsing (unit.rs:2442) | **static** union-of-5 | ✅ confirmed prod-real, reported → [issue #898](https://github.com/gimli-rs/gimli/issues/898) |
| #1 DWARF-expr backward-branch infinite loop (op.rs) | static | ❌ disqualified — documented `set_max_iterations` mitigation |
| CFI memory/OOM/loop (T1/T2 on eh_frame) | **dynamic** fuzz | clean (0/0/0, 547M execs) |
| memory corruption | both | NONE (gimli safe Rust — as threat model predicted) |

**Net: 1 confirmed reportable (quadratic DIE-attrs, issue #898), 1 disqualified (documented), fuzz
memory-clean.** Threat model was accurate: T5 (memory unsafety) refuted by safe-Rust design; T1/T2
resource-exhaustion was the surface; the one live/undocumented instance (#2) reported, the documented one
(#1) correctly dropped — the same verify-against-the-maintainer discipline that caught httparse bare-LF
and object-#2.
