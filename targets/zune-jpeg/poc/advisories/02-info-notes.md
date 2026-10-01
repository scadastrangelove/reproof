# Info notes (no advisory requested) — zune-jpeg 0.5.15

These are **not** security vulnerabilities we're asking you to treat as such. We list them for
transparency (so you know what the pass looked at and dismissed) and in case any are worth a hardening
tweak.

## N1 — Decompression bomb / unbounded output (hardening, not a bug)

A ~1.4 KB JPEG can declare `SOF` dimensions up to 65535×65535×4, so `decode()` will allocate/produce a
very large output from a tiny input (measured: a 1402-byte file → 12544×12288×3 = **462 MB / 154 Mpix**,
~330,000× amplification; the 16-bit dimension fields allow ~17 GB). This is the standard image-decoder
resource-exhaustion shape and is normally the **caller's** responsibility.

`DecoderOptions` already exposes dimension limits — the note is only that they are **not on by default**,
so an embedder that hands `decode()` untrusted bytes without configuring a cap is exposed to a memory/CPU
DoS. A conservative default cap (or a prominent doc note) would be a nice defense-in-depth. `bomb.jpg`
attached for reference. **We are not asking for a fix here** — flagging in case it's useful.

## N2 — Unchecked arithmetic in sizing/indexing (info, not exploitable on 64-bit)

Our tooling flagged four unchecked-multiply sites; on analysis **none is a 64-bit memory-safety issue**:

| site | operand type | assessment |
|---|---|---|
| `mcu_prog.rs:103` `mcu_width*v*h*mcu_height` | `usize` | bounded by 16-bit dims (max product ~7e10 ≪ 2⁶⁴) → **cannot overflow on 64-bit**. On 32-bit (wasm32/armv7) it could wrap → under-alloc; a narrow, platform-specific hardening lead only. |
| `mcu.rs:178` same `*64` | `usize` | same — 64-bit safe, 32-bit-only wrap lead. |
| `mcu_prog.rs:397` `position` index | `usize` | consumed by `.get_mut(position)` (bounds-checked `Option`) → a wrapped value is handled, never OOB. Safe. |
| `bitstream.rs:400` `dc_prediction * qt_table[0]` | `i32` | overflows on all targets, but the wrap only yields a wrong coefficient → wrong pixels (**correctness**, not memory safety). |

If you build/ship for 32-bit targets, a `checked_mul` (or a size cap tied to N1) on the two `usize`
allocation sizes would close the only path with any security flavor. Not requested as an advisory.
