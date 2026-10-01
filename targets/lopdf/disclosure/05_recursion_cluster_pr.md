# PR — lopdf: bound object-graph recursion depth (`/Kids`, `/First`, `/Parent`)

**Title:** Bound recursion depth in `get_named_destinations`, `get_outlines`, `get_page_resources`, and `delete_outlines`

**Body:**

Fixes #<ISSUE>. RUSTSEC-2026-0187 bounded **parser** recursion via `MAX_NESTING_DEPTH`, but four post-load
`Document` graph-walks still recurse over the *parsed* object graph with no depth cap (two of them with no
cycle guard either): `get_named_destinations` (`/Kids`), `get_outlines` (`/First`), `get_page_resources`'s
`collect_resources` (`/Parent` — has a cycle guard but not a depth cap, so a long non-cyclic chain still
overflows), and `delete_outlines`'s `walk_outlines_del` (`/First`). All reachable from ordinary public APIs
on a crafted or self-referential PDF → uncatchable stack-overflow abort.

### The fix

Reuses the existing `MAX_NESTING_DEPTH` constant (the same one the 0187 parser fix uses) and adds
`Error::RecursionLimit`, matching the style/wording of the existing `Error::ReferenceLimit`:

```rust
/// Traversal of the document's object graph (e.g. a `/Kids`, `/First`, or `/Parent` chain)
/// exceeded the supported nesting depth.
/// This might indicate a reference cycle or a maliciously deep structure.
#[error("object graph traversal reached the nesting-depth limit, may indicate a reference cycle")]
RecursionLimit,
```

- `get_named_destinations` / `get_outlines` are **public API** — their signatures are unchanged; each gets
  a private `_impl` twin that threads a `depth: usize`, with the public function calling it at `depth = 0`.
- `collect_resources` (private, nested in `get_page_resources`) and `walk_outlines_del` (private) are
  internal, so their signatures were extended directly.
- `collect_resources` reuses `already_seen.len()` as the depth counter (no new state) — checked alongside
  the existing cycle check, before inserting/recursing.

### Validation

- Full `cargo test`: all green (no test changes needed).
- The 4 PoCs from the issue now return `Err(RecursionLimit)` instead of aborting:
  - self-referential `/Kids` (via `get_named_destinations`)
  - self-referential `/First` (via `get_outlines`)
  - a 200,000-deep **non-cyclic** `/Parent` chain (via `get_page_resources`)
  - self-referential `/First` on the delete path (via `delete_outlines`)
- Control case unaffected: a 2-node `/Parent` **cycle** through `get_page_resources` still returns
  `Err(ReferenceCycle(..))` (not `RecursionLimit`), exactly as before.

Found & fixed with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
