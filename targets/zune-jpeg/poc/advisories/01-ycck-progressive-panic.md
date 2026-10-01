# Advisory 01 — reachable panic (index out of bounds) decoding a crafted progressive YCCK JPEG

- **Crate:** `zune-jpeg` 0.5.15 (etemesi254/zune-image)
- **Class:** uncaught panic / denial-of-service (availability). **Memory-safe** (a bounds-checked
  slice-index panic, not memory corruption).
- **Severity:** Low (availability only; a decoder that panics on a crafted input DoSes any service that
  decodes untrusted JPEGs without `catch_unwind`).
- **Reachable from:** the public `JpegDecoder::new(ZCursor::new(bytes)).decode()` on untrusted bytes.
- **Reproducer:** a **163-byte** JPEG (attached `poc.jpg`, generator `make_poc.py`).

## Summary

A JPEG that (a) carries an Adobe **APP14 marker with `transform = 2`** (YCCK) and (b) is a
**progressive** frame (`SOF2`) declaring **exactly 2 components** makes the decoder index a component
that does not exist, panicking with `index out of bounds: the len is 2 but the index is 2` at
`src/mcu_prog.rs:102`.

## Root cause

In `setup_component_params` (`src/misc.rs:299-345`), when the parsed `input_colorspace` has more
components than the frame actually declares, there are two branches. The **non-YCCK** branch clamps
correctly:

```rust
img.input_colorspace = ColorSpace::MultiBand(
    NonZeroU32::new(img.components.len() as u32).unwrap());   // num_components() == components.len()
```

The **YCCK** branch does **not** clamp — it sets the colorspace to `YCbCr` unconditionally:

```rust
// src/misc.rs:300-303
if img.input_colorspace == ColorSpace::YCCK {
    warn!("Treating YCCK colorspace as YCbCr as component length does not match");
    img.input_colorspace = ColorSpace::YCbCr;   // num_components() == 3, but components.len() may be 2
}
```

With an APP14 `transform=2` (YCCK, `num_components()==4`) and a 2-component SOF2, the condition
`4 > 2` enters the YCCK branch and sets the colorspace to `YCbCr` (**3** components) while
`self.components.len()` is still **2**. The progressive decoder then loops over the colorspace's
component count:

```rust
// src/mcu_prog.rs:100-102
for i in 0..self.input_colorspace.num_components() {   // 0..3
    let comp = &self.components[i];                     // i == 2 → len is 2, index is 2 → panic
```

The `==1` (Luma) and `==4` (CMYK) overrides in `parse_start_of_frame` do not fire for a 2-component
frame, and the 3-component RGB reset in the marker loop is skipped (needs `components.len()==3`), so
the YCCK colorspace survives to `setup_component_params` with a 2-component frame.

## Reproduce

```
python3 make_poc.py poc.jpg
# then, through the public API:
let mut d = JpegDecoder::new(ZCursor::new(&std::fs::read("poc.jpg")?));
let _ = d.decode();   // panics at mcu_prog.rs:102
```

Observed (release build, `overflow-checks` off — the default profile):

```
thread 'main' panicked at src/mcu_prog.rs:102:40:
index out of bounds: the len is 2 but the index is 2
```

It reproduces under both `overflow-checks=on` and `off`, so it is **not** a debug-only arithmetic
overflow — it is a plain slice-index panic present in the shipping release profile.

## Suggested fix

Clamp in the YCCK branch the way the sibling branch already does — only treat YCCK as YCbCr when there
really are ≥3 components, otherwise fall through to `MultiBand(components.len())`:

```rust
if img.input_colorspace == ColorSpace::YCCK {
    warn!("Treating YCCK colorspace as YCbCr as component length does not match");
    if img.components.len() >= 3 {
        img.input_colorspace = ColorSpace::YCbCr;
    } else if !img.components.is_empty() {
        img.input_colorspace = ColorSpace::MultiBand(
            NonZeroU32::new(img.components.len() as u32).unwrap());
    }
}
```

A ready diff is in `fix-ycck-clamp.patch`. Happy to open a PR if you prefer. `poc.jpg` also makes a
good fuzz seed for the upstream `fuzz/` harness (the combo — APP14 t=2 + progressive + 2 components —
is one a random corpus is unlikely to synthesize).
