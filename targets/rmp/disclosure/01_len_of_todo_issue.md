# ISSUE — rmp: `MessageLen::len_of` panics via `todo!()` on all ext markers (including timestamps)

**Title:** `MessageLen::len_of` / `incremental_len` panics on any ext marker (FixExt, Ext8/16/32) — including standard timestamps

### Summary

Tested against `rmp 0.8.15` (current crates.io release).

`rmp::decode::MessageLen::len_of` (est.rs:165-167) and its incremental counterpart execute `todo!()` for
every MessagePack extension marker: `Ext8`, `Ext16`, `Ext32` (est.rs:167) and all five `FixExt` variants
(est.rs:178-182). This is the `std` feature's (enabled by default) public API for bounding the length of
an untrusted streaming MessagePack message before fully decoding it.

Standard MessagePack timestamps are encoded as ext type −1 (`FixExt4` marker `0xd6` for timestamp-32,
`FixExt8` / `Ext8` for timestamp-64/96), so **any call to `len_of` / `incremental_len` on a message
containing a timestamp panics**. The standard `read_ext_meta` / `read_fixext` decode paths handle ext
types correctly; only the length-estimation API is affected.

This is a guaranteed remote DoS for any application that calls `len_of` or `incremental_len` on
untrusted input containing extension types — and timestamps are by far the most common ext type in
practice.

### PoC

```toml
# Cargo.toml
[dependencies]
rmp = "0.8.15"
```

```rust
use std::panic::catch_unwind;

fn probe(name: &str, bytes: &[u8]) {
    let r = catch_unwind(|| rmp::decode::MessageLen::len_of(bytes));
    match r {
        Err(_) => println!("  {:<28} PANIC (todo!/not-yet-implemented)", name),
        Ok(v)  => println!("  {:<28} Ok = {:?}", name, v),
    }
}

fn main() {
    println!("rmp::decode::MessageLen::len_of on ext markers:");
    probe("FixExt1 (0xd4)",      &[0xd4, 0x00, 0x00]);
    probe("timestamp-32 (0xd6)", &[0xd6, 0xff, 0, 0, 0, 0]);      // FixExt4, type -1
    probe("Ext8 (0xc7)",         &[0xc7, 0x01, 0xff, 0x00]);
    probe("control: fixint",     &[0x01]);                          // should be Ok
    probe("control: str 'a'",    &[0xa1, 0x61]);                    // should be Ok
}
```

Result:
```
  FixExt1 (0xd4)               PANIC (todo!/not-yet-implemented)
  timestamp-32 (0xd6)          PANIC (todo!/not-yet-implemented)
  Ext8 (0xc7)                  PANIC (todo!/not-yet-implemented)
  control: fixint              Ok = ...
  control: str 'a'             Ok = ...
```

### Where

- `rmp/src/decode/est.rs:167` — `Marker::Ext8 | Marker::Ext16 | Marker::Ext32 => todo!()`
- `rmp/src/decode/est.rs:182` — `Marker::FixExt1 | ... | Marker::FixExt16 => todo!()`

### Severity

**Medium** — guaranteed remote DoS (panic) on any untrusted input containing an extension type. Timestamps
are the most common ext type; any MessagePack-based protocol using timestamps triggers this. A length
estimator whose documented purpose is bounding untrusted streaming input should return `LenError::ParseError`,
not `panic!`.

### Fix

Replace `todo!()` with the correct length computation (each ext variant has a known wire-format length) or,
if extension support is deliberately deferred, return `Err(LenError::ParseError)` instead of panicking.

```rust
// Ext8: 1 (marker) + 1 (length u8) + 1 (type) + length
Marker::Ext8 => { let len = buf[1] as usize; MessageLen::Complete(3 + len) }
// FixExt1: 1 (marker) + 1 (type) + 1 (data) = 3
Marker::FixExt1 => MessageLen::Complete(3),
// etc.
```

### Relationship to #381

This is NOT the same as #381 / PR #382: that issue covers `rmp-serde`'s recursion-guard gaps in
`Deserializer`. This is in `rmp` itself (the lower-level crate), in a completely different code path
(`decode::MessageLen::len_of`), with a different root cause (`todo!()` stub, not missing recursion guard).

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
