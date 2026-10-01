# ISSUE — incremental-font-transfer: attacker-controlled `max_uncompressed_length` causes eager allocation before brotli decode

**Title:** patch `max_uncompressed_length` is forwarded unchecked into an eager `vec![0; len]` allocation on the default brotli path

Relevant versions:

- `incremental-font-transfer` **0.6.0**
- `shared-brotli-patch-decoder` **0.1.4**

### Summary

The IFT patch application paths forward an attacker-controlled `max_uncompressed_length` field
directly into the shared brotli decoder:

- `glyph_keyed.rs`:
  `patch.max_uncompressed_length() as usize`
- `table_keyed.rs`:
  `table_patch.max_uncompressed_length() as usize`

On the default `c-brotli` path, `shared-brotli-patch-decoder 0.1.4` then does:

```rust
let mut sink = vec![0u8; max_uncompressed_length];
```

before the stream is validated or decompressed.

So a tiny patch can force a large eager allocation purely by choosing a large declared
`max_uncompressed_length`.

### Dynamic confirmation

I confirmed this dynamically with an allocator-instrumented binary built against
`shared-brotli-patch-decoder = 0.1.4`.

Test setup:

- global allocator wrapped to log `alloc_zeroed` sizes
- call:
  `BuiltInBrotliDecoder.decode(&[0xff, 0xff, 0xff], None, 123_456_789)`

Observed output:

```text
decode result        = Err(InvalidStream)
last alloc_zeroed    = 123456789
max alloc_zeroed     = 123456789
requested max output = 123456789
```

This shows the exact requested `max_uncompressed_length` is allocated up front, even though the
input stream is invalid and only 3 bytes long.

### Why this seems wrong

The current behavior turns a metadata field into an immediate allocation knob:

- no cap is enforced in the IFT caller before decode
- the default decoder does not grow output incrementally
- the full claimed maximum is reserved eagerly

That makes memory pressure depend on the declared output limit rather than on actual valid decoded
output.

### Impact

Low — this is an uncontrolled allocation / DoS issue, not memory corruption.

Practical severity depends on allocator/host policy, but the behavior is definitely attacker-shaped:
the request size is honored exactly and happens before the stream is accepted as valid.

### Fix direction

One or both of:

1. enforce a sane upper bound on patch `max_uncompressed_length` before calling the decoder, and/or
2. switch the default decoder path away from eager `vec![0; len]` allocation to incremental bounded
   growth (similar in spirit to the `rust-brotli` bounded-output path)

Even a conservative global cap would turn this from “attacker chooses allocation size” into a normal
size-limit rejection.

### Notes

- This report is primarily about the IFT-facing behavior, but the eager allocation sink lives in
  `shared-brotli-patch-decoder 0.1.4`.
- The dynamic proof did not rely on actual multi-gigabyte allocation or OOM; it instrumented the
  allocator and showed that the requested size is passed through exactly.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
