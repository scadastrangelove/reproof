# Private disclosure — lopdf: 4 low-severity DoS bugs (draft, NOT sent)

**To:** Junfeng Liu (J-F-Liu) <china.liujunfeng@gmail.com> (maintainer; address from public git
history — the repo has no SECURITY.md and GitHub private vulnerability reporting is disabled)
**Subject:** [lopdf] 4 low-severity DoS (panics/abort on malformed PDFs) found while testing, with fixes

---

Hi Junfeng,

I tinker with agentic security and develop a small research pipeline around it
(https://github.com/scadastrangelove/rust-in-peace). While testing it against `lopdf` 0.44.0 I found
**four ways a malformed PDF can crash a consumer** — three reachable panics and one uncontrolled
recursion → stack-overflow abort. All are **low severity**: availability-only, memory-safe (the crate
is `#![forbid(unsafe_code)]` and stays so — none of these are memory-unsafety), in the same class as
lopdf's prior panic-DoS advisories (e.g. RUSTSEC-2026-0187). I'm sending these your way privately
first since the repo has no private-reporting channel; happy to open PRs, or you may prefer to route
any of them through RustSec — your call. I'm not asking for a specific severity or CVE.

Each finding below is reproduced against **plain `cargo build --release`** (overflow-checks off, i.e.
your shipping profile), from untrusted bytes through a public API, and each has a small fix. I also
put each through an adversarial self-review (playing a skeptical maintainer) to weed out
non-reachable or over-rated ones — these four are what survived.

| # | Where | Trigger (public API, untrusted input) | Effect | Fix |
|---|---|---|---|---|
| 1 | `parser/mod.rs:670` (`image_data_stream`) | `Content::decode` of a content stream with an inline image that has `/W /H /BPC` but no `/ColorSpace` and no `/IM true` | `.unwrap()` panic | `.unwrap()` → `?` (mirrors the `?`-siblings; re-engages skip-to-`EI`) |
| 2 | `document.rs:779` (`get_page_images`) | `load_mem` + `get_page_images` on a PDF whose image XObject has `/ColorSpace []` (empty array) | `array[0]` index panic | guard: `array.first().and_then(|o| o.as_name().ok())` |
| 3 | `parser_aux.rs:568` (`decode_xref_stream_with_limit`) | `load_mem` of a ~112-byte PDF with an `/XRef` stream `/W [1099511627776 1 1]` | `vec![0u8; 2^40]` → allocation **abort** (SIGABRT) | bound `/W` widths (≤8) on all three fields; reject otherwise |
| 4 | `reader.rs:771` (`get_pages_tree_count`) | `load_metadata` on a deep linear `/Pages` chain (no `/Count`) | native recursion → **stack overflow** (uncatchable) | depth-bound it; reuse the `PAGE_TREE_DEPTH_LIMIT = 256` you already apply in `PageTreeIter` |

**Minimal PoCs**

1. `Content::decode(b"BI /W 1 /H 1 /BPC 8 ID \x00 EI")` → panics at `parser/mod.rs:670`.
2. 487-byte PDF (generator attached) with `…/XObject<</Im0 N 0 R>>…`, `Im0 = <<…/Subtype/Image
   /Width 1/Height 1/ColorSpace[]…>>`; `load_mem` then `get_page_images(page)` → `index out of bounds`
   at `document.rs:779`. (Reached purely by parsing untrusted bytes — an empty array `[]` is valid PDF
   syntax your parser accepts.)
3. `9 0 obj <</Type/XRef/Size 1/W [1099511627776 1 1]/Length 0>>stream…` → `load_mem` →
   `memory allocation of 1099511627776 bytes failed`. Note: `max_decompressed_size` does not cover
   this — the `/W` vectors are sized from the dictionary, and this stream has no `/Filter`, so the
   existing guard isn't on the path.
4. A generated PDF with a long linear `/Pages` chain (no `/Count`) → `load_metadata` →
   `fatal runtime error: stack overflow, aborting`. (`load_mem`+`get_pages` is fine — that path uses
   your depth-capped iterator; only the `load_metadata` page-counter recurses unbounded.)

Full write-ups, per-finding PoC generators, and the reproduced crash outputs are attached
(4 short markdown advisories + `.py`/input files). Thanks for lopdf — glad to help harden it, and
happy to send PRs for any subset you'd like.

Best,
Sergey Gordeychik

---

## Package contents (attach these)

- `01-inline-image-colorspace-unwrap.md`
- `02-getpageimages-empty-colorspace-oob.md`  + `../getpageimages_empty_colorspace/gen.py`
- `03-xref-w-width-unbounded-alloc.md`         + `../xref_w_alloc/crash.pdf`
- `04-pagetree-recursion-stack-overflow.md`    + `../pagetree_recursion/gen_deep_pages.py`
- `00-ADVERSARIAL-REVIEW.md` (the skeptical-maintainer review summary)

## Channel notes (for us, not the maintainer)

- No SECURITY.md; GitHub private vulnerability reporting **disabled** → email is the private channel.
- Maintainer: Junfeng Liu <china.liujunfeng@gmail.com> (173 commits). Active recent contributors incl.
  Satoshi Kojima <skoji@skoji.jp> — optional cc.
- Precedent: lopdf has 3 prior RustSec advisories (incl. RUSTSEC-2026-0187), all DoS-class — the
  maintainer knows the RustSec flow; these four fit the same bucket.
- Sending is the user's action (outbound message to a person; no email channel wired here).
