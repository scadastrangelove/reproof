# ISSUE — ttf-parser: self-referential GSUB/GPOS extension lookup overflows the stack

**Title:** `parse_extension_lookup` recurses until stack overflow on self-referential ExtensionSubst / ExtensionPos

### Summary

Tested against `ttf-parser 0.25.1` (current crates.io release).

OpenType extension lookups (`GSUB` type 7, `GPOS` type 9) are parsed recursively through
`parse_extension_lookup`. The parser does not reject a nested extension kind and does not enforce any depth
limit. A subtable with `format=1`, inner `kind=7` (or `9`), and `extensionOffset=0` therefore causes the
parser to re-enter itself on the same byte slice forever until the process hits stack exhaustion.

### Dynamic reproduction

Self-contained PoC: [docs/e13/poc/ttf-extension-recursion.rs](../../../docs/e13/poc/ttf-extension-recursion.rs)

The reproducer uses the public API:

- builds minimal `head`, `hhea`, `maxp`, and `GSUB` table bytes,
- constructs a face with `Face::from_raw_tables(...)`,
- fetches the first GSUB lookup via `face.tables().gsub.unwrap().lookups.get(0)`,
- calls `lookup.subtables.get::<ttf_parser::gsub::SubstitutionSubtable>(0)` on a 256 KB stack thread.

Observed result on `ttf-parser 0.25.1`:

```text
About to parse GSUB lookup subtable 0...
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

### Root cause

`src/ggg/lookup.rs:151-165`:

```rust
let kind = s.read::<u16>()?;
let offset = s.read::<Offset32>()?.to_usize();
parse(data.get(offset..)?, kind)
```

For `offset = 0`, `data.get(0..)` returns the same slice. If `kind` is the extension kind again
(`GSUB` 7 or `GPOS` 9), parsing re-enters `parse_extension_lookup` on identical input with no progress and
no recursion guard.

### Reachability

This is reachable through public layout-table access over attacker-controlled font bytes. The PoC uses
`LookupSubtables::get()` directly, which is the ordinary low-level API exported for OpenType layout
inspection.

### Severity

Medium — uncatchable stack-overflow DoS from malformed font data.

### Suggested fix

Reject nested extension kinds, or enforce a recursion / indirection depth budget before re-entering the
extension parser.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
