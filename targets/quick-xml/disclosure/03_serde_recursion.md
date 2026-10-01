# serde deserializer — no recursion-depth limit → stack-overflow DoS on deeply nested untrusted XML

**Relationship to #819:** #819 is a *correctness* bug — a **tiny** recursive-**newtype**-enum document
overflows even at depth ~3 (the struct-variant `$value` form works fine at the same depth). What follows is
**different and orthogonal**: the *working* deserialization path (struct variants, or `serde_json::Value`
via `deserialize_any`) has **no recursion-depth cap**, so an attacker-controlled **deeply nested** document
overflows the native call stack — a **DoS**, not a type-shape bug. A fix for #819 (make newtype recursion
terminate) would not address this; a depth cap would.

Presented as info so the maintainers can decide whether to fold it into #819 or track separately.

### Mechanism

`deserialize_struct` (`src/de/mod.rs`) consumes a `Start` and calls `visit_map(ElementMapAccess::new(..))`
while its own frame stays live; a nested child re-enters `deserialize_struct` via
`ElementMapAccess::next_value_seed` → `MapValueDeserializer::deserialize_struct` → `self.map.de
.deserialize_struct`. Each XML nesting level adds several native stack frames. The only bound in `de/` is
`event_buffer_size` (the `overlapped-lists` skip buffer) — it does not bound call-stack depth. No recursive
*user* type is even required: `deserialize_any` routes self-describing targets (e.g. `serde_json::Value`)
through the same path.

### PoC (dynamically confirmed — `stack overflow, aborting`, release build)

```rust
use serde::Deserialize;
#[derive(Deserialize)]
struct S { #[serde(default, rename = "$value")] v: Vec<S> }   // the "works" shape per #819

fn main() {
    for depth in [3usize, 1000, 20000, 60000] {
        let xml = "<a>".repeat(depth) + &"</a>".repeat(depth);
        let _: Result<S, _> = quick_xml::de::from_str(&xml);   // returns fine for small depth…
    }                                                          // …aborts (stack overflow) at ~20k
}
```

Observed (release, default 8 MB main-thread stack):

| depth | input | result |
|---|---|---|
| 3 | 21 B | returns cleanly |
| 1000 | 7 KB | returns cleanly |
| 20000 | 140 KB | **`fatal runtime error: stack overflow, aborting`** |
| 50000 | 350 KB | **abort** |

Key point vs #819: the **struct-variant / `$value`** shape #819 says *works* deserializes correctly at
shallow depth but **still aborts at attacker depth** — so this is depth-driven resource exhaustion on the
normal path, independent of the newtype-variant correctness bug. The crash is an **uncatchable `abort`**
(not a `Result::Err`), so a service that deserializes untrusted XML with the `serialize` feature (very
common) has a pre-auth crash it cannot handle. Worker threads with smaller stacks fail far earlier.

### Suggested direction

A configurable recursion-depth limit in the `Deserializer` that returns a clean `Error` past the cap —
mirroring `serde_json`'s `Deserializer::recursion_limit` and quick-xml's own `event_buffer_size` DoS guard.

*Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).*
