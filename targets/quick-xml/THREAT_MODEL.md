# Threat Model: quick-xml (0.41.0)

## 1. System context

quick-xml (crate `quick-xml` 0.41.0, ~334M downloads) is a fast, low-level, pull-based **XML reader/
writer**. A caller drives `Reader::read_event` over bytes and receives `Start`/`End`/`Text`/`CData`/
`Comment`/`PI`/`DocType`/`Empty` events, then optionally unescapes entities and (with the opt-in
`serialize` feature) deserializes into typed structures via serde. It sits under config loaders, SOAP/
XML-RPC clients, SVG/office-document (docx/xlsx) readers, RSS/Atom feeds, and countless app parsers.

The input is **untrusted**: config files, network SOAP/XML payloads, uploaded documents, feed data —
parsed pre-auth in many deployments. Default features are **minimal** (no serde, no encoding, no async),
so the core untrusted surface is `Reader::read_event` → the tokenizer (`parser/{element,comment,dtd,pi}`)
→ `escape.rs` entity/character-reference unescaping. quick-xml is a **thoughtful, hardened, safe-Rust**
parser: entity expansion during attribute normalization is **capped at 128** (`escape.rs`
`TooManyEntities`), so classic billion-laughs is mitigated by design; the `unsafe` in `escape.rs` is
largely NOTE-comments ("unsafe get_unchecked *could* be used…", i.e. safe indexing is used). Like object/
gimli/httparse, memory bugs are unlikely; the realistic surface is a subtle unsafe edge, a reachable
tokenizer panic, serde recursion (opt-in), or a **parser differential**.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| service availability | The caller parses each document in bounded time/memory. A reachable panic, unbounded allocation, or super-linear blowup on crafted XML is a pre-auth DoS (config loaders, SOAP endpoints, doc thumbnailers) | high |
| host process integrity | Memory/control-flow integrity. quick-xml is safe Rust (ceiling = panic/abort) unless a reachable `unsafe` in `escape.rs` is triggered with a bad index | medium |
| parsed-output / trust-boundary integrity | Which bytes are an element/attribute/text/entity — a parse differential vs an XML-signature verifier or another parser enables **signature-wrapping / SOAP-action confusion / access-control bypass** | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `Reader::from_str/from_reader` → `read_event(_into)` | the public pull entry over untrusted bytes; drives the tokenizer state machine (`reader/state.rs`, `parser/mod.rs`) | untrusted XML → process | all |
| tokenizer | `parser/{element,comment,dtd,pi}.rs` — parse tag names, attributes, comments, `<!DOCTYPE>`, processing instructions from attacker bytes | untrusted bytes → parser state | availability, output integrity |
| `escape.rs` unescape | resolves `&amp;`/`&#NN;`/custom entities; attribute normalization recursively expands general entities (capped 128); contains the crate's `unsafe` | untrusted entity/char refs → (mostly-safe) byte/char handling | host process integrity, availability |
| serde deserializer (`de/`, opt-in) | with `serialize`, recursively deserializes nested XML into typed structs — recursion depth follows document nesting | untrusted nesting → recursion (stack) | availability |
| namespace resolver (`reader/ns_reader.rs`) | resolves prefixes/namespaces from attacker declarations | untrusted decls → resolver | output integrity, availability |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory unsafety via a reachable `unsafe` in `escape.rs` (char/entity unescape) with a bad index/length on crafted refs | remote_unauth | escape.rs | host process integrity | critical | very_rare | mitigated | the `unsafe` is mostly NOTE-comments; safe indexing used; heavy fuzzing | only if a real `unsafe get_unchecked` is reachable with attacker index |
| T2 | Reachable panic in the tokenizer (slice/index/`unwrap`/arithmetic) on malformed/unclosed/huge tags, comments, DOCTYPE, PI → pre-auth DoS | remote_unauth | parser/*, reader/state | service availability | high | rare | partially_mitigated | returns `Err` by design; fuzzed | a single reachable panic is a whole-endpoint DoS |
| T3 | Resource-exhaustion DoS: entity expansion, quadratic attribute/normalization work, or unbounded allocation from attacker counts/lengths | remote_unauth | escape.rs unescape, attributes, DTD | service availability | medium | possible | partially_mitigated | **128-entity expansion cap** (billion-laughs handled); | quadratic normalization or an uncapped Vec elsewhere |
| T4 | Stack overflow via deep XML nesting through the serde deserializer (recursion follows document depth) | remote_unauth | `de/` (opt-in `serialize`) | service availability | medium | possible | partially_mitigated | opt-in feature; | serde recursion is a classic uncapped-depth crash |
| T5 | Parser differential: quick-xml accepts/normalizes something an XML-signature verifier or another parser treats differently → signature-wrapping / SOAP-action confusion / access bypass | remote_unauth | tokenizer + escape acceptance policy | trust-boundary integrity | high | possible | partially_mitigated | strict-ish parsing; | XML's namespace/entity/whitespace/CDATA edges are a rich differential surface |
| T6 | Supply-chain compromise in the huge dependent tree | supply_chain | crate release | host process integrity | critical | rare | partially_mitigated | maintainers | |

Priorities: **T2 (tokenizer panic)** and **T5 (parser differential)** are the most likely to still have room; T1 (memory) is highest-impact but near-refuted by design; T4 is real but opt-in.

## 5. Deprioritized

| threat | reason |
|---|---|
| XXE (external entity fetch) | quick-xml does NOT resolve external entities (no file/network I/O) — it surfaces entities to the caller; XXE is the caller's resolver, not quick-xml |
| Billion-laughs classic | mitigated by design — attribute-normalization entity expansion is capped at 128 (`TooManyEntities`) |
| Encoding-conversion bugs | opt-in `encoding` feature (encoding_rs); separate surface |
| Writer / serializer bugs | emit XML from trusted in-process data, not an untrusted-input boundary |

## 6. Open questions

- Is the `escape.rs` `unsafe` actually executed, or are the occurrences NOTE-comments over safe indexing?
- Does the serde `de/` path cap recursion depth (T4), or can deep nesting blow the stack?
- Is the 128-entity cap the ONLY expansion bound, or can numeric char refs / CDATA / DTD internal-subset drive other super-linear work (T3)?
- Where is the acceptance seam vs an XML-DSig verifier (T5) — whitespace in tags, duplicate attributes, namespace edges, CDATA-vs-text?
- Is input length capped by callers before `read_event`?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-19
- target: crates.io `quick-xml` @ 0.41.0
- inputs: source read (reader/, parser/{element,comment,dtd,pi}, escape.rs, de/) + feature/unsafe inventory
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Keep any `escape.rs` `unsafe` behind a proven-in-bounds invariant + a fuzz differential (unsafe vs safe indexing on every input) | T1 | partial | S |
| Ensure every tokenizer path returns `Err` not panic; fuzz explicitly for panics (panic = DoS) | T2 | partial | S |
| Cap serde deserialize recursion depth (T4) and audit non-entity super-linear work (T3) | T3,T4 | partial | M |
| Document the acceptance policy (whitespace/dup-attrs/namespace/CDATA) so downstream signature verifiers can align (T5) | T5 | partial | M |

## 9. Target capabilities

| capability | present | evidence |
|---|---|---|
| untrusted_deserialization | yes | `read_event` + serde `de/` turn attacker XML into events/typed structs |
| network_protocol_parser | yes | wire-format XML parser over strongly-adversarial input (SOAP/RSS/config) |
| unsafe_simd | no | no SIMD; the only `unsafe` is `escape.rs` byte/char indexing (mostly NOTE-comments) |
| inbound_c_abi | no | pure-Rust API |
| outbound_ffi | no | std-only in the default build (encoding_rs opt-in) |
| concurrency_async | no | default is sync; async-tokio is opt-in |
| crypto_secrets | no | no secret handling |
| multi_tenant_authz | no | library |

Machine twin: `capabilities.json`. `run_crash_track()` = **true**; oracle = ASan (rare unsafe + OOM) +
panic detection (T2) + a **differential** angle for T5 (accept-vs-spec), with the honest expectation
(hardened safe-Rust parser) that the reportable finds, if any, are static: a tokenizer panic, a serde
recursion overflow, or an acceptance differential — not memory corruption.
