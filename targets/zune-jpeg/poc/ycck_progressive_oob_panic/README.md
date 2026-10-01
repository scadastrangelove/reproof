# zune-jpeg 0.5.15 — reachable panic (index out of bounds) in progressive YCCK decode

**Disposition:** confirmed · production-real · **panic-DoS (LOW–MEDIUM)** · CWE-248 (uncaught panic) / CWE-125-adjacent
**Site:** `src/mcu_prog.rs:102:40` (`decode_mcu_ycbcr_progressive`)
**Root cause:** `src/misc.rs:300-303` (`setup_component_params`, the YCCK→YCbCr fixup)
**Entry:** public `JpegDecoder::new(ZCursor::new(bytes)).decode()` on a 163-byte crafted JPEG.

## Mechanism

An Adobe **APP14 segment with `transform = 2`** sets `input_colorspace = YCCK`
(`headers.rs:501`), whose `num_components()` is **4**. A progressive **SOF2**
frame that declares only **2 components** gives `components.len() == 2`.

In `setup_component_params` the YCCK-specific fixup fires because `4 > 2`:

```rust
// src/misc.rs:299-303
if img.input_colorspace.num_components() > img.components.len() {
    if img.input_colorspace == ColorSpace::YCCK {
        warn!("Treating YCCK colorspace as YCbCr as component length does not match");
        img.input_colorspace = ColorSpace::YCbCr        // ← now num_components()==3, but components.len() is still 2
    } else {
        // the SIBLING branch clamps correctly:
        img.input_colorspace = ColorSpace::MultiBand(NonZeroU32::new(img.components.len() as u32).unwrap())
    }
}
```

The YCCK branch sets the colorspace to **YCbCr (3)** but never clamps to
`components.len()` — unlike the sibling `MultiBand(components.len())` branch. Back
in `decode_mcu_ycbcr_progressive`:

```rust
// src/mcu_prog.rs:100-102
for i in 0..self.input_colorspace.num_components() {   // 0..3
    let comp = &self.components[i];                     // i==2 → len is 2, index is 2 → PANIC
```

The bounds-checked slice index aborts the process. It is a plain slice panic, so
it fires under the **shipping release profile** (overflow-checks OFF) — it is
**not** a build-config artifact.

## Grade evidence (P0.1 — re-tested under both build profiles)

```
$ riptarget_shipping poc.jpg   # -C overflow-checks=off (production)
thread 'main' panicked at src/mcu_prog.rs:102:40:
index out of bounds: the len is 2 but the index is 2      → exit 101

$ riptarget_detect   poc.jpg   # -C overflow-checks=on (detector)
thread 'main' panicked at src/mcu_prog.rs:102:40:
index out of bounds: the len is 2 but the index is 2      → exit 101
```

Reproduces under **both** → production-real (contrast the 4 arithmetic-overflow
candidates this run also surfaced, which reproduce ONLY under `overflow-checks=on`
and are therefore `build_profile_gated` / R7 — see JOURNAL).

## Reachability (admissibility — ADMISSIBLE)

`claims_reachable=true` with a full `where_checked` entry→sink trace (above), and
the reproduction drives the real parse entry `decode()` on crafted bytes (not a
builder-construction harness). `harness.admissibility.check` → **admissible**.

## Fix

Clamp in the YCCK branch exactly like the sibling, or drop through to it:

```rust
if img.input_colorspace == ColorSpace::YCCK && img.components.len() >= 3 {
    img.input_colorspace = ColorSpace::YCbCr;
} else if img.components.len() > 0 {
    img.input_colorspace = ColorSpace::MultiBand(
        NonZeroU32::new(img.components.len() as u32).unwrap());
}
```

## Reproduce

```
python3 make_poc.py poc.jpg
<riptarget> poc.jpg           # panics at mcu_prog.rs:102
```
