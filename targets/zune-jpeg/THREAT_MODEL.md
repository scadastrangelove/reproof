# Threat Model: zune-jpeg (0.5.15)

## 1. System context

zune-jpeg is a pure-Rust JPEG decoder (crate `zune-jpeg` 0.5.15, part of the
`etemesi254/zune-image` workspace), advertised as "a fast, correct and safe jpeg
decoder". A caller hands it untrusted bytes via
`JpegDecoder::new(ZCursor::new(bytes)).decode()` and receives decoded pixels
(RGB / RGBA / grayscale / CMYK / YCbCr) plus parsed image metadata. It supports
baseline and progressive JPEG, arbitrary chroma subsampling, and restart
intervals. There is no network layer, no authentication, and no internal
privilege boundary; the only trust boundary is between attacker-supplied bytes
and the embedding application's address space.

Despite the "safe" framing, the decode path is **not** all safe Rust: the hot
kernels (IDCT, chroma upsampling, YCbCr→RGB color conversion, and
`unsafe_utils`) have hand-written `unsafe` AVX2/NEON SIMD with raw pointer and
slice arithmetic whose bounds depend on caller-upheld invariants, and dimension
math (`width * height * components`) is done in unchecked `usize`. Typical
embedders — image pipelines, thumbnailers, upload/transcoding services — run the
decoder in-process at the embedder's privilege on files from untrusted sources.
`DecoderOptions::set_use_unsafe(false)` exists and routes to scalar fallbacks,
but the **default is unsafe SIMD ON**.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Control-flow and memory integrity of the embedding application; a heap OOB write in the unsafe SIMD path yields code execution at the embedder's privilege | critical |
| adjacent process memory | Heap data next to decoder buffers (keys, tokens, other users' images in a shared service) exposed via OOB read into decoded output | high |
| service availability | The embedder continues decoding in bounded time and memory; a panic/abort or unbounded allocation denies it | medium |
| decoded output integrity | Pixels and metadata (dimensions, colorspace, component layout) faithfully reflect the input | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `JpegDecoder::decode` | The public decode entry over `ZCursor<&[u8]>` of attacker bytes. Parses markers (SOF/SOS/DQT/DHT/DRI), builds Huffman tables, decodes entropy-coded MCUs, runs IDCT + upsampling + color conversion. Baseline and progressive. | untrusted file bytes → process memory | host process integrity, adjacent process memory, service availability, decoded output integrity |
| `JpegDecoder::decode_headers` | Header-only parse (SOF/SOS/DQT/DHT); sets sampling factors, component ids, quant/huff destinations, image dimensions that seed every downstream buffer size and index. | untrusted file bytes → process memory | service availability, decoded output integrity |
| unsafe SIMD kernels | `color_convert/avx.rs` + `neon64.rs`, `idct/avx2.rs` + `neon.rs`, `upsampler/avx2.rs`, `unsafe_utils_avx2.rs` / `_neon.rs` — reached from the decode path with sizes derived from attacker dimensions/sampling; safety rests on caller-upheld slice-length contracts. | in-process (invariant boundary) | host process integrity, adjacent process memory |
| crate supply chain | Single dependency `zune-core` (pure Rust) from crates.io; consumers pin `zune-jpeg = "0.5"` without a lockfile in the typical embedder. | upstream crate → consumer build | host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Heap out-of-bounds write → memory corruption / RCE via untrusted JPEG driving an unsafe SIMD store past its buffer | remote_unauth | unsafe SIMD kernels, `JpegDecoder::decode` | host process integrity | critical | possible | unmitigated | `set_use_unsafe(false)` disables SIMD (default ON) | recon: `ycbcr_to_rgb_avx2_1` (color_convert/avx.rs:144) + `ycbcr_to_rgb_neon` (neon64.rs:132) write 48 bytes unconditionally, ignore `offset`, no length check — unlike the RGBA/scalar paths (pending fuzz/verify) |
| T2 | Integer overflow in `width*height*components` sizing → under-allocation → OOB index/write (release wraps: overflow-checks OFF) | remote_unauth | `JpegDecoder::decode` (misc.rs `setup_component_params`, mcu.rs alloc) | host process integrity | high | possible | unmitigated | none | recon: unchecked usize multiplies (misc.rs:213-250, mcu.rs:161/178-184) |
| T3 | Denial of service via panic (index-out-of-bounds / `unwrap` / `assert_eq!`) aborting the process on crafted markers/coefficients | remote_unauth | `JpegDecoder::decode`, `decode_headers` | service availability | medium | likely | unmitigated | none | recon: idct `store!` `.unwrap()` (idct/avx2.rs), upsampler `assert_eq!` (upsampler/avx2.rs), huff_extend `1<<(s-1)` |
| T4 | Out-of-bounds read returning adjacent heap memory in decoded pixels / metadata | remote_unauth | unsafe SIMD kernels, entropy decode | adjacent process memory | high | possible | unmitigated | `set_use_unsafe(false)` | recon: strided IDCT stores / SIMD loads bound by caller channel length |
| T5 | Denial of service via resource exhaustion; attacker dimensions/scan counts drive large allocations or slow progressive decode | remote_unauth | `JpegDecoder::decode` (progressive buffers) | service availability | medium | possible | partially_mitigated | `DecoderOptions` max dimension limits | recon: progressive `mcu_width*vert*horiz*mcu_height*64` buffers (mcu_prog.rs) |
| T6 | Supply-chain compromise via a malicious `zune-core`/`zune-jpeg` release pulled unpinned into a consumer build | supply_chain | crate supply chain | host process integrity | critical | rare | partially_mitigated | crates.io ownership; consumer may pin | |
| T7 | Tampering with decoded pixels/metadata (dimensions, colorspace) causing downstream logic errors in the embedder | remote_unauth | `JpegDecoder::decode` | decoded output integrity | low | possible | unmitigated | none | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing of image source identity | Decoder has no identity/authentication semantics; provenance is the embedder's concern |
| Repudiation of decode actions | No multi-user actions or audit semantics; nothing to repudiate |
| Elevation of privilege within the library | No internal privilege boundary; subsumed by T1 (memory corruption at embedder privilege) |
| Data race / concurrency corruption | The decode path is single-threaded (no rayon/threads); TSan not applicable |

## 6. Open questions

- Does the embedder run the decoder in-process at full privilege, or sandboxed (seccomp / separate UID / WASM)?
- Are `DecoderOptions` dimension caps set by typical embedders, or is the default (large) limit in force?
- Do consumers set `set_use_unsafe(false)` in hardened builds, or ship the default unsafe SIMD path?
- Is input size / dimension capped upstream before bytes reach `decode()`?
- Which SIMD path actually executes in production (AVX2 vs NEON vs scalar) — decided at runtime by target features?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-18
- target: crates.io `zune-jpeg` @ 0.5.15 (repo etemesi254/zune-image)
- inputs: source read (crate/src) + workflow recon map (wf_1d3692c6-2c4, union-of-5 finders)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Add an explicit length check to every unsafe SIMD store (match the RGBA path's `out.get_mut(offset..offset+N).expect`) before the `_mm*_storeu`/`vst*` | T1,T4 | yes | S |
| Use checked/saturating arithmetic (or a checked-multiply helper) for all `width*height*components` sizing before any `Vec::with_capacity` or index | T2 | partial | M |
| Default `set_use_unsafe(false)` (scalar) unless the caller opts into SIMD, or gate SIMD behind a fuzzed, bounds-checked wrapper | T1,T4 | partial | M |
| Run the decoder in a sandboxed subprocess (seccomp + rlimit, or WASM) and marshal pixels out over a pipe | T1,T2,T3,T4,T5 | yes | L |
| Cap image dimensions and progressive scan counts via `DecoderOptions` before allocation | T5 | partial | S |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | `JpegDecoder::decode()` parses fully attacker-controlled JPEG bytes (markers, DHT/DQT tables, entropy-coded MCUs) |
| network_protocol_parser | yes | byte-format container parser (baseline/progressive, YCbCr/CMYK, arbitrary subsampling) over strongly-adversarial input |
| unsafe_simd | yes | `unsafe_utils_avx2.rs` / `_neon.rs` + `idct/avx2` + `upsampler/avx2` + `color_convert/avx` — pointer/slice arithmetic in SIMD kernels |
| inbound_c_abi | no | grep `extern "C"` / `#[no_mangle]` empty — pure-Rust API |
| outbound_ffi | no | only dep is `zune-core` (pure Rust); no `-sys`/bindgen |
| concurrency_async | no | single-threaded decode; no rayon/threads/async in the decode path |
| crypto_secrets | no | image decoder — no secrets/crypto surface |
| multi_tenant_authz | no | library, no auth surface |

The machine twin is `capabilities.json` (this dir); `harness/capabilities.py`
resolves it — `run_crash_track()` = **true** (byte surface, sanitizer ≠ none),
`vote_budget()` = **8** (unsafe_simd → high-variance), sanitizers = asan + miri.
