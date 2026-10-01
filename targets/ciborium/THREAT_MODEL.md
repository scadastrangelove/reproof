# Threat Model: ciborium (0.2.2)

## 1. System context

`ciborium` (195M downloads, 49M/90d, 698 rev-deps including security-relevant consumers `webauthn-rs` and
`coset`) is a `serde`-integrated CBOR (RFC 8949) codec, split across 3 crates: `ciborium-io` (I/O traits),
`ciborium-ll` (low-level header/tag decode primitives), `ciborium` (the serde `Deserializer`/`Serializer`
and the `Value` enum). It is the crates.io-recommended **replacement** for `serde_cbor`, which was
archived/unmaintained specifically because of that (RUSTSEC-2021-0127) — and `serde_cbor` itself had a
real, disclosed CVE (RUSTSEC-2019-0025 / CVE-2019-25001): excessively nested semantic *tags* caused a
stack overflow via <1KB crafted CBOR. `ciborium` was written with this history in mind: `Deserializer` has
an explicit `recurse: usize` counter, default **256**, checked via a `self.recurse(|me| ...)` helper before
descending into any nested value — a deliberate, safe-by-default mitigation for exactly the predecessor's
CVE class. The threat-model question is whether that counter is enforced **uniformly** across every
recursive entry point, or whether — like the predecessor's tag-specific gap, and like the httparse
un-scoped-flag lesson from this campaign — one specific code path was missed.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Memory/control-flow integrity; safe Rust throughout the deserializer (no raw `unsafe` observed in `de/mod.rs`) — ceiling is panic/abort/stack-overflow, not memory corruption, unless a scratch-buffer/length-arithmetic bug surfaces | medium |
| service availability | Deserializing untrusted CBOR completes in bounded time/stack/memory — the direct RUSTSEC-2019-0025 class | high |
| authentication-decision integrity | `webauthn-rs`/`coset` use CBOR for WebAuthn/COSE credential and signature structures — a parsing differential or DoS here has outsized impact (an auth flow, not just a data pipe) | critical (for this specific consumer class) |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `from_reader` / `from_reader_with_buffer` | Default deserialization entry; sets `recurse: 256` — a **safe default**, unlike httparse's un-scoped-flag lesson | untrusted CBOR bytes → typed value | host process integrity, service availability |
| `from_reader_with_recursion_limit` / `deserializer_from_reader_with_buffer_and_recursion_limit` | Caller-tunable recursion limit; doc explicitly warns "set a high limit at your own risk" | untrusted bytes → typed value, caller-controlled depth budget | service availability (caller-dependent) |
| `Deserializer::deserialize_any` / `_seq` / `_map` / `_struct` / `_enum` | The recursive-descent visitor dispatch — each nested array/map/tagged-value/enum-variant should re-enter through `self.recurse(...)` | untrusted structure depth → native call-stack depth | service availability |
| CBOR **tag** handling (`Header::Tag`, `tag.rs` helpers `AllowAny`/`AllowExact`/`RequireExact`) | The exact surface class of the predecessor's CVE (RUSTSEC-2019-0025: "semantic tags nested excessively"). Observed: `deserialize_any`'s tag arm goes through `self.recurse(...)` (de/mod.rs ~line 204); a separate consecutive-tag-skip `loop { Header::Tag(..) => continue, ... }` (near `deserialize_enum`, ~line 608) does **not** visibly decrement/check `recurse` per iteration | untrusted tag nesting/repetition → stack depth or loop iteration count | service availability |
| `Value` (untyped tree, `value/mod.rs`) | The generic in-memory CBOR value type — does building/traversing it enforce the same depth discipline as the streaming deserializer? | untrusted structure → in-memory tree depth | service availability |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Stack overflow via nested arrays/maps/enums bypassing the `recurse` counter on an overlooked entry point (direct analog of RUSTSEC-2019-0025) | remote_unauth | `de/mod.rs` recursive dispatch | service availability | high | possible | partially_mitigated | `recurse: 256` default, checked at most observed recursion sites | whether EVERY recursive descent path (esp. the consecutive-tag-skip loop near `deserialize_enum`) actually decrements/checks it |
| T2 | The tag-skip loop (`Header::Tag(..) => continue`) allows an attacker to make one method consume an unbounded run of leading tags with no accounting — even if not directly a stack-overflow (it's iterative, not recursive), a hang/CPU-DoS if the loop can spin without making bounded progress per iteration | remote_unauth | `de/mod.rs` ~line 608 (near `deserialize_enum`) | service availability | medium | possible | unmitigated (unverified) | none identified in the code read so far | must confirm the loop always consumes a byte/advances the decoder each iteration |
| T3 | `Value` (the untyped tree) recursion during construction or `Drop` — even if the streaming deserializer's `recurse` counter is enforced going IN, does converting to/dropping a deeply-nested `Value` tree recurse unbounded on the way out (a "safe going in, unsafe going out" asymmetry, like a linked-list Drop stack-overflow) | remote_unauth | `value/mod.rs`, `de.rs`/`ser.rs` for `Value` | service availability | medium | possible | unmitigated (unverified) | none identified yet | |
| T4 | Integer/length handling in `ciborium-ll`'s header/segment decode (`hdr.rs`, `seg.rs`) — CBOR lengths for byte-strings/text-strings/arrays/maps are attacker-controlled 64-bit values; does any allocation trust a length without cross-checking remaining input, independent of the recursion-limit (a resource-exhaustion class distinct from T1/T2) | remote_unauth | `ciborium-ll/src/{hdr,seg}.rs` | service availability | medium | possible | unmitigated (unverified) | none identified yet | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Memory corruption / `unsafe`-driven OOB | No raw `unsafe` observed in the main deserializer path; ciborium is safe-Rust-first, so the realistic ceiling is panic/abort/hang, not corruption |
| Serialization-side bugs (`ser/`) | Serializes locally-controlled data; not the classic untrusted-input path |
| `ciborium-io` trait layer | Thin I/O abstraction, not itself a parsing surface |

## 6. Open questions

- Does the tag-skip loop near `deserialize_enum` (T2) always advance the decoder, or can a pathological
  byte sequence cause it to spin?
- Is `Value`'s construction/traversal/Drop path (T3) recursion-limited the same way the streaming
  deserializer is, or is it a completely separate, unguarded recursive structure?
- Does `ciborium-ll`'s length/segment decode (T4) ever allocate `with_capacity(attacker_length)` before
  validating against remaining input (the classic alloc-from-untrusted-size class we found in object's
  zstd bug and elsewhere this campaign)?
- Real-world exposure: do `webauthn-rs`/`coset` use `from_reader` (default 256 limit, safe) or construct
  their own `Deserializer` some other way that could bypass the default?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-19
- target: crates.io `ciborium` @ 0.2.2 (repo `enarx/ciborium`, workspace of 3 crates)
- inputs: source read (ciborium/src/{de/mod.rs, tag.rs, value/*}, ciborium-ll/src/{dec,hdr,seg}.rs overview), Cargo.toml, cross-reference against RUSTSEC-2019-0025/RUSTSEC-2021-0127 (serde_cbor)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Route the tag-skip loop through the same `self.recurse()` accounting as every other recursive entry | T1, T2 | partial | S |
| Bound the tag-skip loop's iteration count independent of the general recursion limit | T2 | partial | S |
| Audit `Value`'s construction/Drop for unbounded recursion | T3 | partial | M |
| Cross-check `ciborium-ll` length-driven allocations against remaining input before allocating | T4 | partial | M |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | the core purpose of the crate |
| network_protocol_parser | no (wire-format-adjacent — CBOR is a data-serialization format used ON wire protocols like WebAuthn/COSE, not a protocol parser itself) | |
| unsafe_simd | no | safe Rust |
| inbound_c_abi | no | |
| outbound_ffi | no | |
| concurrency_async | no | |
| crypto_secrets | no (ciborium itself doesn't hold secrets; its consumers coset/webauthn-rs do, making correctness here security-adjacent) | |
| multi_tenant_authz | no | library |

Machine twin: `capabilities.json`. `run_crash_track` = false (no raw unsafe in the primary surface);
oracle = panic/stack-overflow/hang detection + differential (does behavior match the documented
recursion-limit contract), not memory-sanitizer-driven.
