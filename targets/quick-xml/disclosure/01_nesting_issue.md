# ISSUE — quick-xml: unbounded `u16` depth counter in `NamespaceResolver::push` → panic / namespace-scope corruption on deeply nested XML

**Title:** `NamespaceResolver::push` increments a `u16` depth counter with no bound → pre-auth DoS (panic) and namespace-scope corruption on deeply nested XML

### Summary

`NamespaceResolver::push` (`src/name.rs`) increments its depth counter with an unguarded

```rust
self.nesting_level += 1;   // src/name.rs (nesting_level: u16, declared ~:514)
```

`push` is called once per `Start`/`Empty` event by `NsReader::process_event` (`src/reader/ns_reader.rs`),
so a document with **65 536 nested elements** drives `nesting_level` (a `u16`) past `u16::MAX`. There is
no depth cap anywhere on the `read_event` path. Note the asymmetry: the matching `pop()` already saturates —

```rust
pub fn pop(&mut self) {
    self.set_level(self.nesting_level.saturating_sub(1));   // src/name.rs:763
}
```

— but the increment does not. Reachable from the public `NsReader::read_resolved_event*` on untrusted XML.

### Impact (two facets, depending on build profile)

- **`overflow-checks` builds** (all debug builds; release profiles that opt in — common for security-
  conscious deployments): the 65 536-th `push` **panics** `attempt to add with overflow` at `src/name.rs`,
  i.e. a remote, pre-auth **DoS** with a ~490 KB document.
- **Default `--release`** (`overflow-checks` off): the `u16` **silently wraps** 65535 → 0, after which
  `set_level`'s scope-truncation (`rposition(|n| n.level <= level)`) operates on non-monotonic levels and
  **corrupts namespace resolution** — bindings from closed scopes leak, in-scope bindings vanish. For any
  consumer that trusts resolved namespaces (XML-DSig, SOAP action routing, element-by-namespace access
  decisions) this is a security-relevant correctness bug, not just a crash.

### PoC

```rust
use quick_xml::reader::NsReader;
use quick_xml::events::Event;

fn main() {
    let depth = 70_000;
    let xml = "<a>".repeat(depth) + &"</a>".repeat(depth);   // ~490 KB
    let mut r = NsReader::from_str(&xml);
    loop {
        match r.read_resolved_event() {
            Ok((_, Event::Eof)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
```

- `RUSTFLAGS="-Coverflow-checks=on"` → `thread 'main' panicked at src/name.rs:...: attempt to add with overflow`.
- Default release → completes, but the resolver is corrupted. Demonstration (same 65 534-deep frame, one
  `xmlns:p` bound outside and a different `xmlns:p` bound inside a nested `<x>`):

  | depth | inner `<p:e>` (expect `BBB`) | outer `<p:f>` (expect `AAA`) |
  |---|---|---|
  | 3 (control) | `BBB` ✓ | `AAA` ✓ |
  | 65534 | `BBB` | **`BBB`** ✗ (closed-scope binding leaked) |
  | ≥65535 | `BBB` | **`Unknown("p")`** ✗ (in-scope binding vanished) |

### Scope / novelty

- **Live on `master`** (`src/name.rs` still `self.nesting_level += 1;` with `pop` `saturating_sub`).
- **Distinct from the closed #970 / #972** — that capped *declarations per element*
  (`max_declarations_per_element` / `TooManyDeclarations`); this is the orthogonal *depth* counter.

### Suggested fix

A `saturating_add` (mirroring `pop`) removes the panic but **not** the misresolution — at saturation all
levels ≥ `u16::MAX` collapse to one, and `set_level` still over-truncates (verified). The correct fix is a
**depth cap that returns a clean error** at the `u16` boundary, in the same spirit as the existing
`TooManyDeclarations` guard — PR attached (all existing tests pass, incl. `--features serialize`).

*Discovered with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) — an LLM-driven
vulnerability-analysis pipeline for Rust. Happy to adjust framing/PoC.*
