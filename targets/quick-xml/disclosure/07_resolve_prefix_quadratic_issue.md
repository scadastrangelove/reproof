# ISSUE — quick-xml: `NamespaceResolver::resolve_prefix` is O(depth) per lookup → O(depth²) CPU DoS on deeply nested XML (sibling of RUSTSEC-2026-0194)

**Title:** `NamespaceResolver::resolve_prefix` linearly scans the entire binding stack per lookup — quadratic CPU cost on deeply nested documents

### Summary

RUSTSEC-2026-0194 (#969) fixed an O(N²) linear scan in `check_for_duplicates` (comparing each attribute
name against every prior name on the same tag) by adding a 64-bit hash pre-filter once a tag has more than
`SMALL_ATTRIBUTE_COUNT` (32) attributes (`events/attributes.rs`, fix commit 07f3db8).

`NamespaceResolver::resolve_prefix` (`src/name.rs:953`) has the identical shape, over a different axis:

```rust
let mut iter = self.bindings.iter().rev();
```
followed by a full linear `.find(...)` over the **entire** in-scope `bindings` stack — once per element
name resolved (line 958, unprefixed name with no default namespace: `iter.find(|n| n.prefix_len == 0)`) or
per prefixed name whose prefix was never bound (line 963: `iter.find(|n| n.prefix(&self.buffer) == prefix)`).
`bindings` grows by one entry per `xmlns[:*]` declaration on every currently-open ancestor element, so its
length is proportional to nesting **depth**. There is no `HashMap<prefix, binding>` index and no cap on
`bindings.len()` or nesting depth (only the u16 `nesting_level` ceiling from #977). A lookup that misses
(the common case for unprefixed names with no default namespace, or a genuinely unbound prefix) is
**O(depth)**; doing that once per event down a depth-D document is **O(D²)**.

### Measured (release build, single core)

Each nesting level declares one `xmlns:a` binding (so `bindings` grows) but element names are unprefixed
with no default namespace declared, so every `resolve_prefix` call misses and scans the full stack:

| N (nesting depth) | events | time | ratio vs previous (÷2N) |
|---|---|---|---|
| 5,000 | 10,000 | 0.019 s | — |
| 10,000 | 20,000 | 0.083 s | ×4.33 |
| 20,000 | 40,000 | 0.360 s | ×4.33 |
| 40,000 | 80,000 | 1.463 s | ×4.06 |

Each doubling of N roughly quadruples the time — textbook O(N²). A ~1.3 MB crafted document (`N=200,000`
would be needed to hit the same order the linked advisory used for #969) drives multi-second single-core
CPU stalls from ordinary-looking nested XML with one namespace declaration per level — no huge tag, no
huge attribute count, just ordinary depth.

### PoC

```rust
use quick_xml::reader::NsReader;
use quick_xml::events::Event;

fn main() {
    let n = 40_000;
    let xml = "<e xmlns:a='x'>".repeat(n) + &"</e>".repeat(n);
    let mut r = NsReader::from_str(&xml);
    loop {
        match r.read_resolved_event() {
            Ok((_, Event::Eof)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
```

### Suggested direction

Same shape of fix as #969's: an index (e.g. a `HashMap<prefix-hash, Vec<index>>` maintained alongside
`push`/`pop`, or a hash pre-filter analogous to `check_for_duplicates`'s once `bindings.len()` crosses a
threshold) so a miss doesn't require scanning every in-scope binding. Since `bindings` is a stack
(push/pop tracks scope), the index needs pop-side maintenance too — a bit more involved than #969's
per-tag scan, so I'm not proposing a specific PR; happy to help if useful.

Found with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
