# ISSUE — lopdf: four crash bugs reachable from untrusted PDF bytes (3 panics, 1 stack-overflow abort)

**Title:** Four crash bugs from crafted PDFs — inline-image unwrap panic, empty-`/ColorSpace` OOB panic, xref `/W` huge-allocation abort, and unbounded `/Pages`-tree recursion

### Summary

Testing lopdf 0.44.0 with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) pipeline
turned up four independent ways a malformed PDF can crash a consumer. All are low severity:
availability-only, memory-safe (the crate is `#![forbid(unsafe_code)]`; none of these are memory-unsafety),
in the same class as lopdf's prior panic/DoS advisories (e.g. RUSTSEC-2026-0187). Each is reproduced
against a plain `cargo build --release` (overflow-checks off, the shipping profile), from untrusted bytes
through a public API.

| # | Where | Trigger (public API, untrusted input) | Effect | Fix |
|---|---|---|---|---|
| 1 | `parser/mod.rs:670` (`image_data_stream`) | `Content::decode` of a content stream with an inline image that has `/W /H /BPC` but no `/ColorSpace` and no `/IM true` | `.unwrap()` panic | `.unwrap()` → `?` |
| 2 | `document.rs:779` (`get_page_images`) | `load_mem` + `get_page_images` on a PDF whose image XObject has `/ColorSpace []` (empty array) | `array[0]` index panic | guard on `array.first()` |
| 3 | `parser_aux.rs:568` (`decode_xref_stream_with_limit`) | `load_mem` of a ~112-byte PDF with an `/XRef` stream `/W [1099511627776 1 1]` | `vec![0u8; 2^40]` → allocation abort (SIGABRT) | bound each `/W` width to ≤8 |
| 4 | `reader.rs:771` (`get_pages_tree_count`) | `load_metadata` on a deep linear `/Pages` chain (no `/Count`) | native recursion → stack overflow (uncatchable) | depth-bound it against the crate's existing `MAX_NESTING_DEPTH` |

### PoCs (before → after, all four confirmed both ways)

```rust
// #1
Content::decode(b"BI /W 1 /H 1 /BPC 8 ID \x00 EI"); // panics at parser/mod.rs:670

// #2 -- a 487-byte PDF (generator below) with an XObject /Im0 whose /ColorSpace is []
let doc = Document::load_mem(&pdf_bytes)?;
doc.get_page_images(page)?; // index out of bounds: len 0, index 0, at document.rs:779

// #3 -- 9 0 obj <</Type/XRef/Size 1/W [1099511627776 1 1]/Length 0>>stream ... endstream
Document::load_mem(&pdf_bytes); // memory allocation of 1099511627776 bytes failed

// #4 -- a generated PDF with a long linear /Pages chain (no /Count)
Document::load_metadata(path); // fatal runtime error: stack overflow, aborting
```

```python
# generator for #2 (487-byte empty-/ColorSpace PDF)
objs=[
 b"<</Type/Catalog/Pages 2 0 R>>",
 b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
 b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]/Resources<</XObject<</Im0 4 0 R>>>>>>",
 b"<</Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace[]/BitsPerComponent 8/Length 0>>stream\n\nendstream",
]
out=bytearray(b"%PDF-1.5\n"); offs=[0]
for i,b in enumerate(objs,1): offs.append(len(out)); out+=b"%d 0 obj %s endobj\n"%(i,b)
xo=len(out); n=len(objs)+1
out+=b"xref\n0 %d\n0000000000 65535 f \n"%n
for o in offs[1:]: out+=b"%010d 00000 n \n"%o
out+=b"trailer <</Root 1 0 R/Size %d>>\nstartxref\n%d\n%%%%EOF"%(n,xo)
open("img_empty_cs.pdf","wb").write(out)
```

Confirmed before/after against master (commit `1efa270`):

| # | before fix | after fix |
|---|---|---|
| 1 | `panicked ... called Result::unwrap() on an Err value: DictKey("ColorSpace")` | returns cleanly (`Err`) |
| 2 | `panicked ... index out of bounds: the len is 0 but the index is 0`, exit 101 | returns cleanly (`Ok`) |
| 3 | `memory allocation of 1099511627776 bytes failed`, SIGABRT | returns cleanly (`Err`) |
| 4 | `thread has overflowed its stack`, SIGABRT | returns cleanly, `load_metadata` succeeds |

I have a PR ready with all four fixes (small, independent diffs — 4 files, +21/-5), full test suite green.
Happy to split it if you'd rather review/merge them independently.

Found by the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
