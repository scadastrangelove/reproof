# Threat Model: object (0.39.1)

## 1. System context

`object` (gimli-rs/object, crate `object` 0.39.1) is a pure-Rust library for reading (and writing)
object-file formats: ELF, PE/COFF, Mach-O (including fat binaries and dyld shared caches), XCOFF,
Unix archives, and WebAssembly. It is one of the most-depended-on crates in the Rust ecosystem
(~534M downloads) — a core building block of the toolchain and of binary-analysis tooling:
`addr2line`, `backtrace`, `gimli`, `rustc`/`cargo` internals, debuggers, linkers, disassemblers,
malware/forensics analyzers, and CI pipelines that scan uploaded artifacts.

The unit of analysis here is the **read** side (the default `read` + `compression` features): a caller
hands untrusted bytes to `object::File::parse(data)` (or a format-specific `parse`) and walks sections,
symbols, relocations, imports/exports, segments, and (optionally) decompresses compressed sections. The
only trust boundary is between attacker-supplied file bytes and the embedding tool's address space;
there is no network layer, authentication, or internal privilege boundary. Parsing runs in-process at
the tool's privilege — often a developer's or a CI runner's.

`object` is a **mature, hardened** target, which shapes the threat model: the zero-copy layer
(`src/pod.rs`) reinterprets byte slices as `Pod` structs only behind explicit bounds + alignment +
`checked_mul` guards, `read_ref.rs`/`util.rs` are 0-`unsafe` bounds-checked accessors, and the project
ships an upstream `fuzz/` harness the maintainers run. So the realistic residual surface is **logic
DoS** (a reachable panic or unbounded allocation on a malformed header that escapes the checked layer),
not easy memory corruption.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Control-flow/memory integrity of the embedding tool. Mostly safe Rust, so the likely ceiling is a panic/abort, not RCE — but any `unsafe` Pod-cast reachable with an unchecked length would raise this to critical. | high |
| service availability | The tool parses each artifact in bounded time and memory (CI scanners, backtrace symbolication, package indexers process attacker-supplied binaries). | high |
| adjacent process memory | Heap near parser buffers, exposed only if an OOB read escapes the bounds-checked accessors. | medium |
| parsed-output integrity | Sections/symbols/relocations faithfully reflect the input (a wrong symbol address misleads a downstream analyzer). | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `File::parse` / `FileKind::parse` | Polymorphic entry (`read/any.rs:241`, `read/mod.rs:272`); sniffs magic and dispatches to the ELF/PE/COFF/Mach-O/XCOFF/archive/wasm parser. All header fields (counts, offsets, sizes) are attacker-controlled. | untrusted file bytes → process memory | host process integrity, service availability, adjacent process memory, parsed-output integrity |
| per-format section/symbol/relocation walkers | `read/{elf,pe,coff,macho,xcoff}/*` — iterate tables whose lengths/offsets come from the header; string-table lookups; relocation/symbol indexing. | untrusted file bytes → process memory | service availability, adjacent process memory, parsed-output integrity |
| compressed sections | `read/elf/compression.rs` + `read/gnu_compression.rs` (flate2/miniz_oxide + ruzstd) inflate ELF `SHF_COMPRESSED` / `.zdebug` sections; output size is driven by the (attacker) header. | untrusted file bytes → process memory (+ dep code) | service availability, host process integrity |
| container/nesting entry | `read/archive.rs` (member table), `read/macho/{fat,dyld_cache}.rs` (nested images), `read/pe/import.rs`/`resource.rs` (offset-chained tables) — self-referential structures. | untrusted file bytes → process memory | service availability |
| `pod.rs` zero-copy layer | `from_bytes` / `slice_from_bytes` reinterpret bytes as `Pod` (13 `unsafe`), guarded by size + alignment + `checked_mul`. The soundness of the whole `unsafe` surface rests on every caller passing a correct `count`. | in-process (invariant boundary) | host process integrity, adjacent process memory |
| crate supply chain | deps `flate2`/`miniz_oxide`, `ruzstd`, `memchr`, `hashbrown` (compression/std). | upstream crate → consumer build | host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Denial of service via a reachable panic (slice index / `unwrap` / `assert` / arithmetic) on a crafted header that escapes the bounds-checked layer | remote_unauth | `File::parse` + per-format walkers | service availability | high | possible | partially_mitigated | bounds-checked `pod.rs`/`read_ref.rs`; upstream fuzzing | parsing-DoS class has prior instances in object's history |
| T2 | Unbounded allocation / decompression bomb: an attacker count/size or a compressed section drives O(n) memory/CPU from a tiny file | remote_unauth | compressed sections, count-driven `Vec` allocations | service availability, host process integrity | high | possible | partially_mitigated | `checked_mul` in `slice_from_bytes`; some `Vec::with_capacity` from header counts remain | |
| T3 | Out-of-bounds read → information disclosure of adjacent heap in returned section/symbol/string data | remote_unauth | relocation/symbol/string-table indexing | adjacent process memory | medium | rare | partially_mitigated | `data.get(..)` accessors, alignment checks | |
| T4 | Memory corruption via an `unsafe` Pod-cast reached with an unchecked/overflowed length | remote_unauth | `pod.rs` `slice_from_bytes` callers | host process integrity | critical | rare | mitigated | `checked_mul` + `get(size..)` + alignment guard on every cast | |
| T5 | Infinite loop / hang via self-referential structures (archive member cycles, PE import/resource offset loops, Mach-O fat/dyld nesting) | remote_unauth | archive, pe import/resource, macho fat/dyld_cache | service availability | medium | possible | partially_mitigated | some depth/offset checks | |
| T6 | Supply-chain compromise via a malicious `flate2`/`ruzstd`/`miniz_oxide` release pulled unpinned | supply_chain | crate supply chain | host process integrity | critical | rare | partially_mitigated | crates.io ownership; consumer may pin | |
| T7 | Integer overflow on 32-bit targets in offset/size arithmetic not routed through `checked_mul` → under-alloc or wrong slice | remote_unauth | per-format offset math | service availability, adjacent process memory | medium | rare | partially_mitigated | `checked_mul` in the pod layer (not everywhere) | |

Sorted by (impact, likelihood): T1/T2 are the priorities; T4 is the highest-impact-but-well-guarded.

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing / authentication bypass | The library has no identity or auth semantics |
| Repudiation | No multi-user actions or audit trail |
| Elevation of privilege within the library | No internal privilege boundary; subsumed by T4 |
| Data race / concurrency corruption | The read path is single-threaded; no `unsafe` cross-thread sharing |
| Write-side (`write`/`build`) bugs | Out of scope: the `write`/`build` features emit files from trusted in-process data, not an untrusted-input boundary |

## 6. Open questions

- Which formats does the embedder actually accept — all of `File::parse`, or a single pinned `FileKind`?
- Is `compression` enabled in the embedder's build (it is a default feature)? If so, are decompressed sizes capped?
- Does the embedder run parsing sandboxed (a CI scanner in a container) or in-process at developer privilege (backtrace symbolication)?
- Are inputs size-capped before reaching `parse`?
- 32-bit targets in scope (wasm32 analyzers, embedded)? — gates T7.

## 7. Provenance

- mode: bootstrap
- date: 2026-07-18
- target: crates.io `object` @ 0.39.1 (repo gimli-rs/object)
- inputs: source read (crate/src: pod.rs, read/*, read/{elf,pe,macho,coff,xcoff}/*) + module/feature inventory
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Cap decompressed section size (and any count-driven `Vec::with_capacity`) against the remaining input length before allocating | T2 | partial | M |
| Route every offset/size multiply through `checked_*` (audit non-`pod.rs` arithmetic, esp. 32-bit) | T2,T7 | partial | M |
| Bound recursion/iteration depth on self-referential containers (archive members, PE import/resource chains, Mach-O fat/dyld nesting) | T5 | partial | M |
| Keep the `unsafe` Pod surface behind the guarded `from_bytes`/`slice_from_bytes` helpers only — never a raw cast with a caller-supplied length | T4 | yes | S |
| Run the parser sandboxed (seccomp/container/WASM) for untrusted-artifact scanning | T1,T2,T3,T5 | yes | L |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | the entire crate deserializes attacker-controlled object-file bytes into typed structures via `File::parse` |
| network_protocol_parser | yes | byte-format container parser over strongly-adversarial input (ELF/PE/Mach-O/COFF/archive/wasm) |
| inbound_c_abi | no | pure-Rust API; grep `extern "C"`/`#[no_mangle]` empty |
| outbound_ffi | no | deps are pure Rust (miniz_oxide/ruzstd); flate2 default backend is miniz_oxide, not the C zlib |
| unsafe_simd | no | no SIMD kernels in the read path |
| concurrency_async | no | single-threaded read path |
| crypto_secrets | no | no crypto/secrets surface |
| multi_tenant_authz | no | library, no auth surface |

Machine twin: `capabilities.json` (this dir). `run_crash_track()` = **true** (byte surface). Note: the
`unsafe` here is the `Pod` zero-copy layer (`pod.rs`), which is bounds-/align-/overflow-checked — a
*hardened* unsafe surface, not the raw-SIMD kind; the realistic oracle is panic/hang/alloc (ASan + a
hang/RSS cap), with Miri available to check the Pod casts for UB.
