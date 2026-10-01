# PR — quick-xml: bound the namespace-resolver depth counter (fixes the `NamespaceResolver::push` overflow)

**Title:** Bound `NamespaceResolver` nesting depth — return `TooDeeplyNested` instead of overflowing the `u16`

**Body:**

Fixes #<ISSUE>. `NamespaceResolver::push` incremented its `u16` `nesting_level` with an unguarded
`+= 1`; a 65 536-deep document overflowed it — a panic under `overflow-checks`, or a silent wrap that
corrupts namespace-scope truncation in release (bindings from closed scopes leak / in-scope bindings
vanish). `pop` already saturates; the increment did not.

A `saturating_add` would stop the panic but not the scope corruption (at saturation all deep levels
collapse and `set_level` still over-truncates). This instead adds a depth bound that returns a clean
error at the `u16` boundary, matching the existing per-element `TooManyDeclarations` guard.

### The change (3 hunks in `src/name.rs`)

```rust
// 1) new error variant
pub enum NamespaceError {
    ...
    TooManyDeclarations(usize),
    /// The document nested elements more deeply than the namespace resolver's
    /// depth counter can track (`u16::MAX`). Bounds stack / bookkeeping work on
    /// untrusted input. Contains the depth limit that was exceeded.
    TooDeeplyNested(usize),
}

// 2) Display arm
Self::TooDeeplyNested(limit) => {
    write!(f, "document nests elements deeper than the supported limit of {}", limit)
}

// 3) the fix in push()
self.nesting_level = self.nesting_level
    .checked_add(1)
    .ok_or(NamespaceError::TooDeeplyNested(u16::MAX as usize))?;
```

Plus a regression test that drives a 70 000-deep document through `NsReader` and asserts a clean error
(no panic, no wrap).

### Validation
- `cargo test` (default features): **241 + 63 pass, 0 fail**.
- `cargo test --features serialize`: **1362 + 126 pass, 0 fail**.
- Regression test passes; the 490 KB PoC now returns `Err(TooDeeplyNested)` instead of panicking, and the
  namespace-misresolution demonstration no longer occurs (document is rejected at the boundary).

*Alternative considered:* widen `nesting_level` to `u32`/`usize` (overflow becomes practically
unreachable) — happy to switch if you'd prefer no new error variant; I chose the explicit cap to mirror
`max_declarations_per_element` and to keep the depth bound intentional on untrusted input.

*Discovered & fixed with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).*
