# Threat Model: miniz_oxide (0.9.1)

## 1. System context

`miniz_oxide` (769M downloads, 151M/90d, ~251 direct rev-deps — but the crate sits under `flate2`, whose
own rev-dep graph is enormous: gzip/zlib/deflate decompression is used by nearly every HTTP client/server,
package manager, and archive tool in the Rust ecosystem) is a from-scratch Rust port of the C `miniz`
library — a DEFLATE/zlib compressor+decompressor. The **decompression** path (`inflate/`) is the
untrusted-input surface: any caller decompressing attacker-supplied bytes (an HTTP response body, a
downloaded package, an uploaded archive) drives `tinfl`-derived code with byte/bit-level state machines,
manual buffer indexing, and size fields taken directly from the compressed stream. The published crate
root is `miniz_oxide/src/` (the repo root `src/` is a separate, legacy `miniz_oxide_c_api` FFI crate, not
in scope). Already has `fuzz/` (5 targets: `fuzz_high`, `inflate_nonwrapping`, `roundtrip`,
`roundtrip_zlib`, `via_flate2`) — expect memory bugs to be scarce; the realistic surface is a subtle
edge in size/bound accounting, or a resource-exhaustion gap the size-based fuzzers don't naturally hit.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Memory/control-flow integrity of the embedding process; `unsafe` is used for performance (manual buffer indexing, `get_unchecked` in hot paths) | critical |
| service availability | Decompression completes in bounded time/memory for a given compressed-input size; a "small compressed input, huge/slow decompression" is the classic zip/zlib-bomb class | high |
| decoded output integrity | Decompressed bytes faithfully match what the compressor produced | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `decompress_to_vec` / `decompress_to_vec_zlib` | Allocate-as-you-go decompression with **no output-size limit** — the doc explicitly warns this is dangerous on untrusted input (classic decompression-bomb entry) | untrusted compressed bytes → unbounded `Vec` growth | service availability |
| `decompress_to_vec_with_limit` / `_zlib_with_limit` | Same, but caller supplies a max output size | untrusted bytes → bounded alloc | service availability (if caller sets a sane limit) |
| `inflate` (`inflate/stream.rs`) / `DecompressorOxide` (`inflate/core.rs`) | The core streaming decompressor state machine (`tinfl`); manual bit/byte cursor, Huffman table decode, LZ77 back-reference copy (distance/length from the stream) | untrusted bytes → raw pointer/index arithmetic in `unsafe` hot paths | host process integrity, service availability |
| `decompress_slice_iter_to_slice` | Decompress into a caller-provided fixed output slice across multiple input slices | untrusted bytes → slice-bounded writes | host process integrity (if a bound is miscalculated) |
| `deflate/*` (compression) | Lower priority — the compressor consumes data the local process already controls/produced, not the classic untrusted-input path (though a hostile compression *ratio choice* from attacker-influenced input could still matter for CPU cost) | local data → compressed bytes | service availability (lower priority) |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory corruption in the unsafe LZ77 back-reference copy or Huffman table decode (OOB read/write from a miscalculated distance/length/table index) | remote_unauth | `inflate/core.rs` | host process integrity | critical | rare | partially_mitigated | fuzzed (5 targets, incl. ASan-style via cargo-fuzz); ~10 years of production use under flate2/zip crates | a subtle boundary/off-by-one in the unsafe hot path that the fuzz corpus hasn't hit |
| T2 | Decompression bomb via unbounded output allocation (`decompress_to_vec`/`_zlib` with no limit) | remote_unauth | `inflate/mod.rs` | service availability | high | likely | partially_mitigated | a `_with_limit` sibling exists and is documented as the safe choice | any caller using the no-limit variant on untrusted input (the doc-example/quickstart risk, same shape as the httparse un-scoped-flag class: is the DANGEROUS variant the one a copy-pasting caller reaches for first?) |
| T3 | Resource-exhaustion via Huffman-table construction cost independent of output size (a compressed stream that is cheap to store but expensive to build decode tables for, repeated across many small streams) | remote_unauth | `inflate/core.rs` table-build | service availability | medium | possible | unmitigated | none identified yet | needs verification against the actual table-build cost function |
| T4 | Integer overflow/underflow in size/distance/length arithmetic feeding an allocation or copy bound (the classic zlib CVE-2018-25032/CVE-2022-37434 class — miniz_oxide is a *port* of the same algorithm family, so the same bug SHAPES are plausible even though the C bugs themselves don't transfer as code) | remote_unauth | `inflate/core.rs`, `inflate/output_buffer.rs` | host process integrity, availability | high | possible | partially_mitigated | Rust's default overflow-checks-off wrapping (release) / panic (debug) bounds *some* of this; fuzzed | whether an overflow can produce a WRONG-but-still-in-bounds value that under-allocates without panicking |

## 5. Deprioritized

| threat | reason |
|---|---|
| Compression-side bugs (deflate/) | Compresses locally-controlled data in the overwhelming majority of real use; not the classic untrusted-input path |
| C-API crate (`miniz_oxide_c_api`, repo root) | Separate published crate, FFI wrapper, not in scope — the 769M-download crate is `miniz_oxide/` |

## 6. Open questions

- Is `decompress_to_vec` (no limit) actually the one recommended/reached-for in the crate's own docs/
  examples, or is `_with_limit` clearly the primary-suggested API? (mirrors the httparse-lesson question:
  which variant does a doc-skimming caller actually copy?)
- Does every code path that computes an output/copy bound from stream-supplied length/distance fields
  validate against the ACTUAL remaining output buffer space uniformly, or is there an asymmetry between
  the streaming (`inflate::stream`) and the allocate-to-vec (`inflate::mod`) entry points?
- Are the 5 existing fuzz targets actually exercised in CI/OSS-Fuzz continuously, or are they present but
  dormant (the httparse lesson: a fuzz target existing in the repo doesn't mean it's continuously run)?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-19
- target: crates.io `miniz_oxide` @ 0.9.1 (repo `Frommi/miniz_oxide`, subdir `miniz_oxide/`)
- inputs: source read (inflate/{core,stream,mod,output_buffer}.rs, deflate/ overview, fuzz/fuzz_targets/ listing, Cargo.toml)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Make `_with_limit` the more prominent/default-recommended API in docs, or give the no-limit variant a stronger doc warning | T2 | partial | S |
| Audit Huffman table-build cost vs. compressed-stream size for a cheap-input/expensive-build asymmetry | T3 | partial | M |
| Cross-check size/distance/length arithmetic sites for overflow-then-under-allocate patterns | T4 | partial | M |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | decompression of attacker bytes is the core untrusted-input operation |
| network_protocol_parser | no | not a wire-format parser itself, but the payload of one (HTTP/gzip) |
| unsafe_simd | partial | optional `simd` feature (simd-adler32 for checksums, not core inflate); core inflate uses scalar `unsafe` indexing |
| inbound_c_abi | no (for `miniz_oxide` proper; the separate `miniz_oxide_c_api` crate does, out of scope) | |
| outbound_ffi | no | |
| concurrency_async | no | |
| crypto_secrets | no | |
| multi_tenant_authz | no | library |

Machine twin: `capabilities.json`. `run_crash_track` = true (memory-safety relevant, `unsafe` present);
sanitizers = asan (existing fuzz targets already build with cargo-fuzz/libFuzzer conventions).
