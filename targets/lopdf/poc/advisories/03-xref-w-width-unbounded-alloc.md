# Advisory 03 — Unbounded allocation / abort in `Document::load_mem` via xref-stream `/W` widths

- **Crate:** lopdf **Version tested:** 0.44.0 (commit 1efa270)
- **CWE:** CWE-789 (memory allocation with excessive size) → denial of service
- **Severity (proposed):** **Low** (Moderate defensible at the top of the honest range) — unauthenticated allocation-abort DoS reachable directly from `load_mem`; availability-only, memory-safe.
- **Not the documented decompression-bomb class** (adversarial review, key point): `max_decompressed_size` bounds decompressed *content*, not the `/W` width vectors — and the PoC stream has **no `/Filter`**, so that guard is not even on the code path. A user who correctly sets the opt-in guard is still killed. So this cannot be filed under "you should have set the limit."

## Summary
When decoding a cross-reference (`/XRef`) stream, `lopdf` reads the `/W` field-width array and
eagerly allocates a buffer of `field_widths[k]` bytes **before** reading any content, with only a
non-negativity check and no upper bound. A tiny PDF declaring a huge `/W` width triggers a
multi-terabyte allocation → allocator abort (process kill).

## Details
`src/parser_aux.rs` (`decode_xref_stream_with_limit`, ~line 568): `/W = [w0, w1, w2]` is validated
only for `len >= 3` and non-negativity; then `vec![0u8; field_widths[k] as usize]` is allocated.
`max_decompressed_size` does not bound this (it caps decompressed *content*, not these width
vectors).

## Reproduction (public API, untrusted bytes — parse-reachable)
A **112-byte PDF**:
```
9 0 obj <</Type/XRef/Size 1/W [1099511627776 1 1]/Length 0>> stream endstream endobj
startxref 9 %%EOF
```
`Document::load_mem(bytes)` →
```
memory allocation of 1099511627776 bytes failed   (SIGABRT)
```
PoC: `poc/xref_w_alloc/crash.pdf`. `1099511627776 = 2^40` (1 TiB); an attacker can pick any value up
to `i64::MAX`. Unconditional (plain release, overflow-checks off).

## Impact & reachability
Directly reachable from `Document::load_mem` — the primary untrusted-PDF entry. A ~112-byte file
kills the process via allocation abort → DoS.

## Suggested fix
Bound the `/W` widths (a valid xref field width is a small byte count; `read_big_endian_integer`
accumulates into a `u32`, so any width > 4 is already semantically broken/truncating — a cap of ≤8,
or even ≤4, rejects zero legitimate documents). Apply to **all three** of `field_widths[0..=2]`, not
just `[0]`; reject with `ParseError::InvalidXref`. Optionally also cap the allocation against the
remaining stream length. Note in the changelog that `max_decompressed_size` did **not** cover this
path, so users don't assume the existing guard protected them.
