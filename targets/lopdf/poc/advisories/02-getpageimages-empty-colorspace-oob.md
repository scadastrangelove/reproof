# Advisory 02 — Panic (DoS) in `Document::get_page_images` via empty `/ColorSpace []` array

- **Crate:** lopdf **Version tested:** 0.44.0 (commit 1efa270)
- **CWE:** CWE-125-adjacent, but this is a **safe-Rust bounds-check `panic!`**, not a memory-unsafe OOB read — do not badge as a memory-safety issue.
- **Severity (proposed):** **Low** — availability-only, safe single-thread panic (`catch_unwind`-recoverable), on the opt-in `get_page_images` extraction API rather than the default parse path. (Adversarial review corrected an earlier "Moderate".)

## Summary
`Document::get_page_images` indexes `array[0]` of an image XObject's `/ColorSpace` without checking
that the array is non-empty. A page whose image XObject declares `/ColorSpace []` (an empty array —
valid PDF array syntax) panics.

## Details
`src/document.rs:779`:
```rust
let color_space = match dict.get(b"ColorSpace") {
    Ok(cs) => match cs {
        Object::Array(array) => Some(String::from_utf8_lossy(array[0].as_name()?).to_string()),
        ...
```
`Object::Array(array)` with `array.len() == 0` → `array[0]` → `index out of bounds: the len is 0
but the index is 0`.

## Reproduction (public API, untrusted bytes — parse-reachable)
A **487-byte PDF** with a page whose `/Resources /XObject /Im0` is an image stream with
`/ColorSpace []`, parsed by the public `Document::load_mem`, then `get_page_images(page_id)`:
```
load_mem OK, objects=4
get_page_images(page (3,0)) -> panicked at src/document.rs:779:83: index out of bounds
```
PoC generator: `poc/getpageimages_empty_colorspace/gen.py`. Unconditional (plain release,
overflow-checks off).

**Reachability note (important, self-audited):** the pipeline's reattack harness reproduced this by
constructing the `Document` via lopdf's *builder* API, which alone would be rejectable ("you built
the bad object yourself"). This advisory instead demonstrates it via **`load_mem` on untrusted
bytes** — an empty `/ColorSpace []` is valid array syntax the parser accepts, so the sink is
genuinely reachable from a malicious PDF, not only by direct construction.

## Impact & reachability
`get_page_images` is public and a natural call for image-extraction/thumbnailing over untrusted
PDFs. A crafted PDF panics the calling thread → DoS.

## Suggested fix
Guard the array: `Object::Array(array) => array.first().and_then(|o| o.as_name().ok()).map(...)`,
treating an empty array as "no colorspace".
