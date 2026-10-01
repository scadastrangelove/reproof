# Threat Model: httparse (1.10.1)

## 1. System context

httparse (crate `httparse` 1.10.1, ~602M downloads) is a low-level, push-style **HTTP/1.x
request/response header parser**. It is the parser underneath **hyper**, and therefore under most of the
Rust HTTP ecosystem (reqwest, axum, warp, actix's h1 path, tonic, …). A caller hands it a slice of raw
bytes read off a socket and a fixed-capacity `&mut [Header]` scratch slice; `Request::parse` /
`Response::parse` locate the request line/status line and the header block, returning `Complete(n)` or
`Partial` and borrowing name/value byte-slices back into the input buffer.

The input is **maximally adversarial**: it is whatever bytes an unauthenticated remote client (or, for
responses, an upstream/attacker-controlled server) sends, parsed **before any authentication**, in the
hot path of every connection. To go fast, httparse scans header names, values, and the URI with
**hand-written `unsafe` SIMD** (AVX2 / SSE4.2 / NEON, with a SWAR fallback) and a `unsafe` byte cursor
(`iter.rs`). So the parser combines the two worst properties for safety: fully attacker-controlled input
and manual `unsafe` pointer/lane arithmetic.

Two distinct compromise shapes matter here: **memory unsafety** in the `unsafe` scanners (network-
reachable corruption in a huge fraction of Rust servers), and **parser-behaviour differentials** — what
httparse accepts vs. what a front proxy / the HTTP spec / a back-end accepts — which drive **HTTP request
smuggling**, desync, and cache poisoning. httparse is heavily fuzzed (oss-fuzz + a security-conscious
hyper team), so shallow memory bugs are unlikely; the realistic surface is a subtle `unsafe`-SIMD edge,
a reachable panic, or a lenient-acceptance differential.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Control-flow/memory integrity of the server/client embedding hyper; an OOB in the `unsafe` SIMD/cursor over network bytes is pre-auth remote memory corruption | critical |
| request-routing / trust-boundary integrity | Which bytes are "a header" / "the body" / "the next request" — a parse differential vs a front proxy yields request smuggling, auth bypass, cache poisoning, credential theft across pipelined requests | critical |
| service availability | The server keeps accepting connections in bounded time/memory; a reachable panic or hang on a crafted request is a pre-auth DoS | high |
| adjacent process memory | Heap next to the parse buffers, exposed by an OOB read surfaced in a returned header slice | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `Request::parse` / `Response::parse` | `lib.rs:552 / :630` — the public entry over `&'b [u8]` of raw socket bytes; parses request/status line + header block, fills the caller's `&mut [Header]`. | unauth network bytes → process memory | all |
| SIMD scanners | `simd/{avx2,sse42,neon,swar}.rs` — `match_header_name_vectored` / `match_header_value_vectored` / `match_uri_vectored` scan attacker bytes with `unsafe` intrinsics + pointer math; chosen at runtime by `simd/runtime.rs` CPU detection. | unauth bytes → `unsafe` lane/ptr arithmetic | host process integrity, adjacent memory |
| byte cursor | `iter.rs` — the `Bytes` cursor advances over the buffer with `unsafe` (`get_unchecked`/ptr `advance`); every parser step relies on its bounds invariant. | unauth bytes → `unsafe` cursor | host process integrity |
| caller `&mut [Header]` | Fixed-capacity scratch; `parse` writes up to `headers.len()` entries and returns `TooManyHeaders` past that. | caller contract | service availability, routing integrity |
| tokenisation policy | Which byte values are accepted in a method/URI/header-name/header-value, how CRLF vs bare-LF / obs-fold / whitespace are handled — the differential surface. | spec-vs-implementation gap | routing integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Out-of-bounds read/write in the `unsafe` SIMD scanners or the `unsafe` byte cursor on a crafted header/URI → pre-auth remote memory corruption | remote_unauth | `simd/*`, `iter.rs` | host process integrity, adjacent memory | critical | rare | partially_mitigated | heavy oss-fuzz/ASan; SWAR fallback; SIMD bounds/tail handling | well-fuzzed → any survivor is a subtle lane/tail edge |
| T2 | HTTP request smuggling / desync: httparse accepts something a front proxy or the back-end interprets differently (bare LF as line end, obs-fold, odd whitespace around `:` or in the request line, duplicate/edge Content-Length or Transfer-Encoding tokens surfaced leniently) | remote_unauth | tokenisation policy | routing integrity | high | possible | partially_mitigated | strict-mode option; hyper enforces some rules above httparse | httparse is a *lenient* tokenizer by design; the differential lives at the httparse↔proxy↔hyper seams |
| T3 | Reachable panic (slice index / `unwrap` / arithmetic) on a crafted request → pre-auth DoS of the server | remote_unauth | `lib.rs` parse loop, header indexing | service availability | high | rare | partially_mitigated | fuzzing; the parser is written to return `Err`, not panic | a single reachable panic is a whole-server DoS |
| T4 | Incorrect header-count / offset handling: `TooManyHeaders` boundary, `Partial`/`Complete` offset returned past the buffer, or a value slice with wrong bounds → downstream OOB or logic error | remote_unauth | `&mut [Header]` fill, returned offsets | routing integrity, availability | medium | rare | partially_mitigated | explicit `TooManyHeaders`; offset asserts | off-by-one at the header-slice or offset boundary |
| T5 | Supply-chain: a malicious httparse release is pulled into the vast dependent tree | supply_chain | crate release | host process integrity | critical | rare | partially_mitigated | crates.io ownership; hyper maintainers | |

Sorted by (impact, likelihood): **T1 (memory corruption)** and **T2 (smuggling)** are the crown jewels; T1 is the highest-impact-but-well-guarded, T2 is the most likely to still have room.

## 5. Deprioritized

| threat | reason |
|---|---|
| Body parsing / chunked decoding bugs | Out of scope — httparse parses *headers only*; chunked/body handling lives in hyper |
| TLS / connection-level attacks | Below httparse; not its surface |
| Timing side-channels in header compare | Not applicable — httparse does no secret comparison |
| Data race / concurrency | The parse call is single-threaded over a borrowed slice; no shared `unsafe` state |

## 6. Open questions

- Which SIMD path actually runs in production (AVX2 vs SSE4.2 vs NEON vs SWAR)? — decided at runtime by `simd/runtime.rs`; the fuzz build should exercise each, and any bug may be path-specific.
- Is the embedder using httparse's strict mode, or the default lenient tokenizer (the T2 differential surface)?
- Does the embedder (hyper) re-validate header names/values above httparse, and where exactly is the httparse↔hyper acceptance seam (that seam is where smuggling lives)?
- Are inputs length-capped before `parse` (giant header blocks / header count)?
- 32-bit targets in scope (offset arithmetic)?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-19
- target: crates.io `httparse` @ 1.10.1
- inputs: source read (lib.rs parse entry, iter.rs cursor, simd/{avx2,sse42,neon,swar,runtime}.rs) + module/feature inventory
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Keep the `unsafe` SIMD behind exhaustive per-path differential fuzzing (avx2 == sse42 == neon == swar == scalar on every input), under ASan + Miri where the intrinsics allow | T1 | partial | M |
| Prefer strict-mode tokenisation at the embedder, and pin down / test the httparse↔hyper acceptance seam against a smuggling corpus (bare-LF, obs-fold, whitespace, CL/TE edges) | T2 | partial | M |
| Ensure every parse path returns `Err` rather than panicking on malformed input; fuzz for panics explicitly (panic = DoS) | T3 | partial | S |
| Cap total header bytes / header count at the embedder before `parse` | T3,T4 | partial | S |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| network_protocol_parser | yes | it *is* an HTTP/1.x wire-format parser over raw socket bytes |
| untrusted_deserialization | yes | `Request::parse` turns fully attacker-controlled bytes into typed request line + headers |
| unsafe_simd | yes | `simd/{avx2,sse42,neon}.rs` hand-written intrinsics + `unsafe` byte cursor (`iter.rs`), runtime-dispatched |
| inbound_c_abi | no | pure-Rust API; no `extern "C"` |
| outbound_ffi | no | no deps (std-only) |
| concurrency_async | no | single-threaded parse over a borrowed slice |
| crypto_secrets | no | no secret handling |
| multi_tenant_authz | no | library, no auth surface |

Machine twin: `capabilities.json`. `run_crash_track()` = **true** (byte surface, unsafe SIMD → asan);
`vote_budget()` = **8** (unsafe_simd = high-variance). Oracle: ASan (T1 SIMD/cursor OOB) + a
per-SIMD-path **differential** harness (T1 correctness + T2 acceptance) + panic detection (T3). Miri can
check the scalar/SWAR path for UB but cannot run the vector intrinsics.
