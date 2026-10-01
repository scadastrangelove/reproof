# Advisory 01 — Panic (DoS) in `Content::decode` via inline image with missing `/ColorSpace`

- **Crate:** lopdf **Version tested:** 0.44.0 (commit 1efa270)
- **CWE:** CWE-248 (uncaught exception / reachable `unwrap`) → denial of service
- **Severity (proposed):** **Low** — a reachable, memory-safe single-thread panic (thread unwind; process abort only under `panic=abort`), matching lopdf's prior panic-DoS hardening advisories. (Adversarial review corrected an earlier "Moderate" over-rating.)

## Summary
`lopdf::content::Content::decode` (via the inline-image parser) calls `.unwrap()` on a missing
`/ColorSpace` entry. A crafted content stream with an inline image that has `/W /H /BPC` but no
`/ColorSpace` and no `/ImageMask true` makes the parser panic instead of returning an error.

## Details
`src/parser/mod.rs:670`, in `image_data_stream`:
```rust
let colorspace = get_abbr(b"CS", b"ColorSpace").unwrap().as_name()?;
```
`get_abbr` returns `Err` when neither `/CS` nor `/ColorSpace` is present. Width/height/BPC above it
use `?` (graceful), so a dict with `/W /H /BPC` but no colorspace and no `/IM true` reaches the
`.unwrap()` on an `Err` → panic. The panic fires inside `image_data_stream`, so the
skip-to-`EI` recovery in `inline_image_impl` never runs.

## Reproduction (public API, untrusted bytes)
```rust
lopdf::content::Content::decode(b"BI /W 1 /H 1 /BPC 8 ID \x00 EI");
// -> panicked at src/parser/mod.rs:670: called `Result::unwrap()` on an `Err` value
```
Confirmed three independent ways: hand PoC, coverage-guided `content_decode` fuzzing (crash in
~2 min), and the pipeline's reattack harness. Unconditional (reproduces under a plain
`--release` build, overflow-checks off).

## Impact & reachability
`Content::decode` is the public entry any text/image extractor calls on page-content bytes taken
from an untrusted PDF. A one-line inline image panics the calling thread → DoS.

## Suggested fix
Change the lone `.unwrap()` to `?` — one token, mirrors the `?`-siblings (W/H/BPC), converts the
panic into the already-public `Result::Err`, and re-engages the skip-to-`EI` recovery in
`inline_image_impl`:
```rust
let colorspace = get_abbr(b"CS", b"ColorSpace")?.as_name()?;
```
(An earlier draft suggested an `.ok().and_then(...)` form — adversarial review flagged that it leaves
`num_colors` undefined for the absent case; the plain `?` is the correct minimal fix.)
