# Threat Model: gimli (0.34.0)

## 1. System context

gimli (crate `gimli` 0.34.0, gimli-rs/gimli, ~498M downloads) is a lazy, zero-copy **DWARF debugging-
information parser**, written in (near-)all safe Rust. It reads the `.debug_*` / `.eh_frame` sections
extracted from an object file and exposes DIEs (Debugging Information Entries), abbreviations, line-number
programs, location/range lists, DWARF expressions, and call-frame-information (unwind) tables. It is the
DWARF engine under `addr2line`, `backtrace` (so every Rust panic backtrace), `rustc`/debuggers, profilers
(perf/pprof-style), crash reporters, and binary-analysis tooling.

The input is **untrusted**: debug info from a binary the operator did not author — a crate downloaded and
built, a core dump, an uploaded artifact scanned in CI, a binary under analysis. Parsing runs in-process
at the tool's privilege (often a developer's box or a CI runner), and — via `backtrace` — inside the very
process that is already crashing.

Because gimli is safe Rust, the realistic compromise shape is **not** memory corruption; it is **logic
denial-of-service**: a reachable panic, an unbounded allocation, or a non-terminating loop in one of its
several **stateful interpreters over attacker bytes** — the CFI unwinder (`cfi.rs`, ~8k LOC, with a
`DW_CFA_remember_state` rule-table stack), the DWARF-expression stack machine (`op.rs` `Evaluation`), and
the line-number program (`line.rs`). gimli is heavily oss-fuzzed by a security-conscious team (the same
gimli-rs maintainers as `object`), so shallow panics are unlikely; the realistic surface is a
resource-exhaustion or infinite-loop edge in those state machines (the class where `object` had real bugs).

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| service availability | The tool parses each artifact / unwinds each frame in bounded time and memory. A hang or unbounded allocation on crafted DWARF DoSes a CI scanner, a symbolizer, or — via `backtrace` — makes a crashing process hang instead of dying | high |
| host process integrity | Control-flow/memory integrity. gimli is safe Rust, so the ceiling is normally a panic/abort, not RCE — unless a rare `unsafe`/`arch`-specific path is reachable with an attacker length | medium |
| result integrity | Symbol/line/unwind results faithfully reflect the input; a mis-parse misleads a debugger or a crash report | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| CFI unwinder | `read/cfi.rs` — `EhFrame`/`DebugFrame` → `CieOrFde`/`FrameDescriptionEntry` → `UnwindTable`/`UnwindContext`; interprets CFA + register rules from attacker call-frame instructions, incl. `DW_CFA_remember_state`/`restore_state` (a stack of full rule tables) | untrusted `.eh_frame`/`.debug_frame` → process time/memory | service availability, host process integrity |
| DWARF expression evaluator | `read/op.rs` — `Operation::parse` + `Evaluation` (a stack machine: `DW_OP_*` push/dup/pick/deref/…); attacker bytes drive an operand stack and control flow | untrusted expression bytes → interpreter | service availability |
| DIE / unit / abbrev parse | `read/unit.rs`, `read/abbrev.rs` — attacker abbreviation counts, DIE trees (sibling/child chains), attribute forms; drives allocation and traversal | untrusted `.debug_info`/`.debug_abbrev` → allocation/recursion | service availability |
| line-number program | `read/line.rs` — the `DW_LNS`/`DW_LNE` state machine over attacker opcodes; file/dir tables, address advances | untrusted `.debug_line` → state machine | service availability |
| loclists / rnglists / aranges | `read/{loclists,rnglists,aranges}.rs` — attacker-counted list entries | untrusted sections → iteration/allocation | service availability |
| LEB128 / offsets | `leb128.rs`, offset/address arithmetic across the reader | untrusted varints → arithmetic | service availability |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Unbounded allocation / memory exhaustion: an attacker count or a `DW_CFA_remember_state` chain drives O(n) or worse memory from a small section | remote_unauth | cfi.rs remember_state stack, abbrev/DIE/loclists counts | service availability | high | possible | partially_mitigated | some bounds; lazy parsing | remember_state copies the full rule table per push (the object-style class) |
| T2 | Non-terminating / super-linear loop: the CFI unwinder, `op.rs` Evaluation stack machine, or the line program loops or runs in exponential/quadratic time on crafted opcodes (self-referential offset, cyclic sibling/child, unbounded expression) | remote_unauth | cfi.rs, op.rs, line.rs, unit.rs DIE traversal | service availability | high | possible | partially_mitigated | iteration/offset checks | the same class as object's exports-trie loop; the DWARF interpreters are the hot spots |
| T3 | Reachable panic (slice index / `unwrap` / arithmetic / `unreachable!`) on crafted DWARF → DoS, incl. inside a `backtrace` of an already-crashing process | remote_unauth | any read/* parser | service availability | medium | rare | partially_mitigated | fuzzing; returns `Err` by design | a panic during panic-unwinding is especially nasty |
| T4 | Integer overflow in offset/address/LEB128 arithmetic → wrong slice or under-read (esp. 32-bit) | remote_unauth | leb128.rs, offset math | service availability, result integrity | medium | rare | partially_mitigated | checked arithmetic in places | |
| T5 | Memory unsafety via a reachable `unsafe`/arch path with an attacker-controlled length | remote_unauth | any `unsafe` in read/ | host process integrity | critical | very_rare | mitigated | gimli is near-all safe Rust | only if a rare unsafe is reachable |
| T6 | Supply-chain compromise of gimli in the backtrace/addr2line dependency tree | supply_chain | crate release | host process integrity | critical | rare | partially_mitigated | gimli-rs maintainers | |

Priorities: **T1 (unbounded alloc)** and **T2 (loop/super-linear)** in the CFI/op/line interpreters are the crown jewels; T5 (memory unsafety) is highest-impact but near-refuted by gimli's safe-Rust design.

## 5. Deprioritized

| threat | reason |
|---|---|
| `write` side bugs | Out of scope: the `write` feature emits DWARF from trusted in-process data, not an untrusted-input boundary |
| Object-file container parsing (ELF/Mach-O/PE) | That's `object`'s surface (separately reviewed), not gimli's; gimli consumes already-extracted section bytes |
| Timing side-channels | No secret handling |
| Data race | Parsing is single-threaded over borrowed section slices |

## 6. Open questions

- Does the CFI `UnwindContext` cap the `remember_state` stack depth / total rule memory?
- Does `op.rs` `Evaluation` cap the operand-stack depth / total operations (unbounded `DW_OP_dup`/push)?
- Are DIE sibling/child traversals cycle/depth-bounded (a sibling offset pointing backward)?
- Are attacker counts (abbrev, list entries, file/dir tables) validated against the section length before allocation?
- 32-bit targets in scope (offset/address arithmetic)?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-19
- target: crates.io `gimli` @ 0.34.0 (repo gimli-rs/gimli)
- inputs: source read (read/{cfi,op,line,unit,abbrev,loclists,rnglists}.rs, leb128.rs) + module/feature inventory
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Cap the CFI `remember_state` stack depth and total remembered rule-table memory against the section length | T1 | partial | S |
| Cap the `op.rs` Evaluation operand-stack depth and total operations per expression | T1,T2 | partial | S |
| Bound DIE/list/table counts against the remaining section length before allocating, and depth-bound sibling/child traversal | T1,T2 | partial | M |
| Keep every read path returning `Err` rather than panicking; fuzz explicitly for panics and for time/RSS blow-ups (not just crashes) | T2,T3 | partial | M |
| Run untrusted-binary symbolication sandboxed / with an RSS+time rlimit | T1,T2,T3 | yes | L |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | parses attacker-controlled DWARF sections (DIEs, abbrev, line, CFI, expressions) into typed structures |
| network_protocol_parser | yes | byte-format parser over a strongly-adversarial container (the DWARF wire format) |
| unsafe_simd | no | no SIMD; gimli is near-all safe Rust |
| inbound_c_abi | no | pure-Rust API |
| outbound_ffi | no | no `-sys`/FFI deps in the read path |
| concurrency_async | no | single-threaded parse over borrowed slices |
| crypto_secrets | no | no secret handling |
| multi_tenant_authz | no | library, no auth surface |

Machine twin: `capabilities.json`. `run_crash_track()` = **true** (byte surface → asan catches the rare
unsafe + OOM/abort). Note the oracle emphasis: because gimli is safe Rust, ASan mostly reports **OOM /
allocation-size-too-big** (T1) and libFuzzer reports **timeouts** (T2), with panics (T3) as aborts —
the value here is resource-exhaustion + loop detection, plus a **static** hunt of the CFI/op/line state
machines for unbounded/cyclic constructs a fuzzer won't synthesize.
