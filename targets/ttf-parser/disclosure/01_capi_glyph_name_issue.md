# ISSUE — ttf-parser: c-api `ttfp_get_glyph_name` buffer overflow on CFF fonts with long glyph names

**Title:** `ttfp_get_glyph_name` panics (abort/UB) on CFF glyph names >= 256 bytes

### Summary

Tested against ttf-parser **0.25.1** (current crates.io release).

`ttfp_get_glyph_name` (c-api/lib.rs, function `ttfp_get_glyph_name`) copies the glyph name into a
hardcoded 256-byte buffer with no length check. CFF String INDEX entries have no length cap, so a crafted CFF font with an ASCII glyph
name >= 256 bytes causes an index-out-of-bounds panic across the `extern "C"` boundary:

- Rust >= 1.81: process abort (panic-in-extern = abort)
- Rust < 1.81 (crate MSRV 1.63): undefined behavior

PostScript standard names are all <= 255 bytes, so the 256-byte buffer assumption holds for the `post`
table path. It breaks for CFF, where `glyph_name()` returns uncapped strings from the String INDEX.

### Where

```rust
// c-api/lib.rs:687-701
pub extern "C" fn ttfp_get_glyph_name(face, glyph_id, name) -> bool {
    let name = unsafe { std::slice::from_raw_parts_mut(name as *mut _, 256) };
    // ...
    for (i, c) in n.bytes().enumerate() {
        name[i] = c;        // panics at i=256
    }
    name[n.len()] = 0;      // also panics if len >= 256
}
```

The Rust-side `face.glyph_name()` returns the raw String INDEX entry with no length cap
(cff1.rs:1054-1066).

### PoC

A 513-byte OTF font with a CFF table containing a 300-byte glyph name.

```toml
# Cargo.toml
[dependencies]
ttf-parser = { version = "=0.25.1", features = ["glyph-names"] }
```

Two layers. **(1)** The Rust API confirms the trigger condition — `face.glyph_name(GlyphId(1))` returns
the uncapped 300-byte name (`assert_eq!(name.len(), 300)`), so `n.len() >= 256`.

**(2)** The real C API aborts. The `c-api` crate (`crate-type = ["cdylib"]`) was built at tag `v0.25.1`
and its exported `ttfp_get_glyph_name` was called from a C harness on the crafted font:

```c
void* face = malloc(ttfp_face_size_of());
ttfp_face_init(data, len, 0, face);     // load the 513-byte OTF
char name[512];
ttfp_get_glyph_name(face, 1, name);     // glyph 1's CFF name is 300 bytes
```

Result — process abort (exit 134 / SIGABRT):

```text
thread '<unnamed>' panicked at lib.rs:697:17:
index out of bounds: the len is 256 but the index is 256
thread '<unnamed>' panicked at library/core/src/panicking.rs:226:5:
panic in a function that cannot unwind
...
  11:  _ttfp_get_glyph_name
  12:  _main
thread caused non-unwinding panic. aborting.
```

So this is a confirmed **process abort in the shipping C API**, not only a source-traced concern: the
`extern "C"` panic hits "panic in a function that cannot unwind" and becomes a hard abort (Rust ≥ 1.81).
The full crafted-font generator (`build_otf()`, ~200 lines of inline SFNT/CFF) + the C harness are
available as self-contained reproducers.

The crafted font uses:
- SFNT/OTTO container with head/hhea/maxp/CFF tables
- CFF String INDEX with 1 entry of 300 ASCII bytes
- Charset format 0 mapping GlyphId(1) → SID 391 (first custom string)

### Severity

**Medium** — the panic crosses an `extern "C"` boundary. On current Rust (>= 1.81) this is a guaranteed
process abort; on the crate's MSRV (1.63) it is UB. Violates the crate's documented no-panic guarantee.
Reachable from any C/C++ consumer that calls `ttfp_get_glyph_name` on an untrusted font.

The pure-Rust API (`face.glyph_name()`) is NOT affected — it returns a `&str` of arbitrary length, which
is correct. Only the C API's fixed-buffer copy is vulnerable.

### Fix

Check `n.len() < 256` before copying, or use `n.len().min(255)` and always NUL-terminate:

```rust
if n.len() >= 256 {
    return false;
}
```

### Relationship to existing filings

This is NOT covered by #218–#221. Those address CFF2 BLEND, avar overflow, glyf/gvar and COLR
exponential blowup — all in the pure-Rust parsing layer. This is in the C FFI wrapper (`c-api/lib.rs`),
a different code path with a different severity profile (abort/UB vs. panic).

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
