# Threat model — `hyper` (hyperium/hyper), the HTTP library

**Pin:** `67ace6484db5d4a15367013847768f5f94f4b97d` (v1.11.0, 2026-07-20)
**Provenance:** bootstrap (code + CVE history), pre-hunt
**`target_layer`: protocol / state-machine (its own HTTP/1 framing) + integration seam** (ADR-1)
→ **invariant-first**, with a memory-safety finder warranted (see §2).

## 1. Why hyper, and why NOW (shell-first, L45)

hyper is the HTTP layer under axum / reqwest / tonic / warp — **what actually ships**. Its config
choices gate the layers below it: we saw h2's whole PUSH_PROMISE finding-cluster neutralized because
hyper hardcodes `enable_push(false)`. Impact lives in the shell. We went to the yolk (h2) first and
had to discount findings by the shell; this pass corrects the order. **hyper's own protocol protein
— `proto/h1` (8.7k LOC of HTTP/1 framing) — is the underexplored, maximum-blast-radius surface, and
it is NOT httparse** (httparse only tokenizes header bytes; hyper decides TE-vs-CL, chunked framing,
trailers, keep-alive/pipelining, body length). We reviewed actix/ntex (competitors); hyper's own h1
is the reference impl and was skipped.

## 2. Memory-safety IS in scope here (unlike rustls/h2)

hyper has **no `forbid(unsafe_code)`** — **61 `unsafe` blocks**. Most are in `ffi/` (the C API), but
several sit in the HTTP/1 parsing hot path on attacker-controlled bytes:
- `proto/h1/role.rs:56` `HeaderValue::from_maybe_shared_unchecked(bytes)` — a HeaderValue built
  without validation.
- `proto/h1/role.rs:261,1091,1118` `header.assume_init_ref()/mut()` — a `MaybeUninit` header array.
  **This is the exact area of GHSA-f67m (RUSTSEC-2022-0022): the parser previously created an invalid
  uninitialized `httparse::Header`.** Variant target: are all partial-init / early-error paths sound?
- `proto/h1/io.rs:235,244` `read_buf.chunk_mut().as_uninit_slice_mut()` — the read-buffer fill.
So realistic classes include **memory unsafety / uninit exposure**, in addition to
smuggling/desync/DoS/panic.

## 3. Primary surface (proto/h1) & assets

| Asset | File | Why |
|---|---|---|
| Request/response head parse, TE/CL reconciliation | `proto/h1/role.rs` (3.2k LOC) | request smuggling lives here |
| Chunked body decoder | `proto/h1/decode.rs` (`ChunkedState`, `chunk_len: u64`, trailers) | chunk-size overflow + terminator leniency |
| Body encoder | `proto/h1/encode.rs` | response-splitting / framing on the send side |
| Connection state / keep-alive / pipelining | `proto/h1/conn.rs`, `dispatch.rs` | request queue desync, half-close |
| Read/write buffering | `proto/h1/io.rs` | the read-buf unsafe |
Secondary: `proto/h2/` (client/server/ping-BDP/upgrade orchestration), `body/` (backpressure,
aggregation), `upgrade.rs` (CONNECT / websocket half-close).

## 4. Prior-vulnerability history (hyper's OWN — precise CVE-lens seeds)

| Advisory | Mechanism | Variant target in 1.x |
|---|---|---|
| CVE-2021-32714 / GHSA-5h46 | **integer overflow in chunked chunk-size** (>18 EB) → data loss / smuggling | `decode.rs` `chunk_len` hex accumulation — any `u64` overflow / silent wrap left? |
| CVE-2021-32715 / GHSA-f3pg | **lenient Content-Length** (illegal chars, `+` prefix) → smuggling via lenient proxy | `role.rs` CL parse — strict now? leading `+`/ws / multiple CL / CL+TE precedence |
| GHSA-f67m / RUSTSEC-2022-0022 | **uninit `httparse::Header`** (`mem::uninitialized`) | `role.rs` `assume_init` paths — sound on every partial-fill / error branch? |
| GHSA-q89x | **header value with newline splits messages** | header-value validation on parse AND encode |
| GHSA-h3qr (critical) / GHSA-6hfq | **HTTP request smuggling** | the whole TE/CL/chunked reconciliation |
Most are pre-1.x (1.x is a rewrite) — so the class is **variant analysis: did the rewrite reintroduce
a sibling?**, not the exact bug.

## 5. Invariants to walk (RFC 9112) & mirror axes (L43)

Invariants: TE-vs-CL precedence (§6.1 — if both present, CL must be ignored/rejected, not honored);
chunk-size is hex, bounded, hex-digit-seen before terminating 0-chunk; a message body length has
exactly one authority; header names/values reject CR/LF/NUL; keep-alive reuse requires the prior body
fully framed; `Connection` header tokens honored.

- **M1 client ↔ server.** hyper parses requests (server) AND responses (client) via `role.rs`. Is
  TE/CL/chunked validation symmetric? A lenient *response* parser lets a malicious server desync a
  reverse-proxy built on hyper (client role) — the h2-B shape.
- **M2 h1 ↔ h2.** Same message-length / header invariants enforced on both dispatch paths
  (`proto/h1` vs `proto/h2`)? A rule enforced in h1 but not h2 (or vice-versa) is a cross-protocol
  desync.
- **M3 parse ↔ encode.** A value accepted on parse but also emittable on encode (header with CRLF)
  → response splitting.
- **M4 TE ↔ CL precedence** (the classic smuggling seam) — exact RFC 9112 §6.1 handling, incl.
  obs-fold, multiple TE, `chunked` not-last.

## 6. Fuzz gate (ADR-1)

No in-tree `fuzz/` dir found; hyper is externally OSS-Fuzz'd. Byte-mutation of the parser is therefore
covered upstream → our marginal value is the **invariant-symmetry** + **differential** lenses (TE/CL
desync, h1↔h2 asymmetry, parse↔encode) and the **memory-safety** review of the proto/h1 unsafe.
NOT byte-fuzz-first.

## 7. Honesty & channel

- **Hardest target in the ecosystem**: most-scrutinized Rust HTTP impl, security-conscious maintainer
  (seanmonstar), own SECURITY.md, rich fix history. 1.x is a rewrite. **"0 findings" is a very real,
  expected outcome.** Do not manufacture severity. (Counter-weight: real on-class surface + unsafe on
  attacker data + a matching CVE history make it a legitimate, non-hopeless target.)
- **DoS / smuggling are in scope** (hyper issued advisories for both).
- **Channel:** `hyperium/hyper` has private vulnerability reporting **enabled**; SECURITY.md says
  report via its GHSA advisory form (covers the whole hyperium org, incl. h2). → any finding → draft
  GHSA at `hyperium/hyper`.
