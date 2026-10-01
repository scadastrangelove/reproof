# ISSUE — jxl: oversized image dimensions can panic in allocation-length computation

**Title:** `Image::<u8>::new(...)` can panic in `RawImageBuffer::try_allocate` after passing the coarse size guard

Tested against published crate **`jxl 0.5.1`**.

### Summary

`jxl`'s image allocation path uses a coarse pre-check:

```rust
if bytes_per_row as u64 >= i64::MAX as u64 / 4 || num_rows as u64 >= i64::MAX as u64 / 4 {
    return Err(Error::ImageSizeTooLarge(bytes_per_row, num_rows));
}
```

but later computes:

```rust
let bytes_between_rows =
    bytes_per_row.div_ceil(CACHE_LINE_BYTE_SIZE) * CACHE_LINE_BYTE_SIZE;
let allocation_len = (num_rows - 1)
    .checked_mul(bytes_between_rows)
    .unwrap()
    .checked_add(bytes_per_row)
    .unwrap();
```

For some dimension pairs, the coarse guard passes, but the later padded-size computation still
overflows and panics on `unwrap()`.

### Dynamic confirmation

Using the published crate on a nightly toolchain, `Image::new` panics at **file-legal dimension
magnitudes** — the maximum a JXL `SizeHeader` can declare is `u32::MAX` (dimensions are `u32`, capped
only by `u32::try_from`; see `src/headers/size.rs:97,129`). Both the simplest single-channel `u8` case
and the `f32` frame-buffer case overflow and panic:

```rust
Image::<u8>::new((u32::MAX as usize, u32::MAX as usize))   // panics
Image::<f32>::new((u32::MAX as usize, u32::MAX as usize))  // panics
```

Observed result:

```text
thread 'main' panicked at .../jxl-0.5.1/src/image/internal.rs:223:14:
called `Option::unwrap()` on a `None` value
```

(An earlier reproducer used `(usize::MAX / 64, 65)`; that panics too, but those magnitudes are **not**
file-expressible. The `u32::MAX` case above uses exactly the largest values a `SizeHeader` can carry,
so it demonstrates the overflow at dimensions an untrusted file can actually declare.)

### Important nuance

Not every “huge dimensions” case panics.

For example, very large symmetric pairs like:

```rust
Image::<u8>::new(((i64::MAX as usize / 4) - 1, (i64::MAX as usize / 4) - 1))
```

return a clean:

```text
Err(ImageSizeTooLarge(...))
```

So the real issue is narrower than “all oversized dimensions panic”: the panic occurs for shapes
that pass the coarse bound but overflow after row-padding/alignment is applied.

### Why this seems wrong

The function already intends to reject impossible sizes gracefully via `Error::ImageSizeTooLarge`.
Using `checked_*().unwrap()` after a coarse pre-check leaves a panic path where a normal error would
be expected.

### Fix direction

Replace the two `unwrap()` calls with error propagation, e.g.:

```rust
let allocation_len = (num_rows - 1)
    .checked_mul(bytes_between_rows)
    .ok_or(Error::ImageSizeTooLarge(bytes_per_row, num_rows))?
    .checked_add(bytes_per_row)
    .ok_or(Error::ImageSizeTooLarge(bytes_per_row, num_rows))?;
```

That matches the existing intended behavior much better than aborting.

### Reachability from an untrusted file

The allocation guard is **per-dimension** (`bytes_per_row < i64::MAX/4`, `num_rows < i64::MAX/4`), but
the overflow is in the **product** `(num_rows - 1) * bytes_between_rows`, which is not bounded. Image
dimensions come from the `SizeHeader` and are only `u32`-bounded (`u32::try_from`, `size.rs:97,129`);
there is no total-pixel / total-size cap in header validation or frame setup. Frame buffers are
allocated via `Image::new` with the file-declared dimensions during decode (e.g. `frame/decode.rs:212`,
`frame/adaptive_lf_smoothing.rs:46`) **before** pixel data is processed, so a tiny crafted file whose
`SizeHeader` declares near-maximal (`~u32::MAX`) dimensions reaches this allocation and panics — the
product `~2^32 * ~2^32` exceeds `usize::MAX`. (A full crafted-bitstream file is the remaining nicety;
the `u32` dimension bound + the `u32::MAX` API reproducer already establish that an untrusted file can
reach it.)

### Severity

Medium — upstream robustness / availability: an untrusted JXL file declaring near-maximal dimensions
panics (process abort) at frame-buffer allocation. Memory-safe (panic/abort, not corruption).

### Toolchain note

In this environment, published `jxl 0.5.1` required a nightly toolchain to compile due to
`NonNull::from_ref` / `NonNull::from_mut` usage in the crate. The dynamic verification above was
performed on nightly for that reason.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
