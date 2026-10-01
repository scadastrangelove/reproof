# Advisory 04 — Stack overflow (DoS) in `Document::load_metadata` via deep `/Pages` tree

- **Crate:** lopdf **Version tested:** 0.44.0 (commit 1efa270)
- **CWE:** CWE-674 (uncontrolled recursion) → denial of service
- **Severity (proposed):** **Low** — unauthenticated, **uncatchable**-abort DoS (a stack overflow SIGABRT is not stopped by `catch_unwind`, so a metadata worker is killed outright — materially worse than the recoverable cost of a large file). Availability-only, memory-safe.
- **Inconsistency, not by-design** (adversarial review, key point): the crate's own `PageTreeIter` (`document.rs:836`) already carries `PAGE_TREE_DEPTH_LIMIT = 256` for exactly this threat. `get_pages_tree_count` is the **one** page-tree path that recurses natively with no depth bound — so "don't parse untrusted input" is not a posture this crate can claim here.

## Summary
Page-tree page counting (`get_pages_tree_count`) recurses once per `/Kids` entry with a cycle guard
but **no depth bound**. A PDF encoding a deep *linear* chain of `/Type/Pages` nodes overflows the
native thread stack → `fatal runtime error: stack overflow, aborting` (SIGABRT). The abort is
**uncatchable** (`catch_unwind` does not stop a stack overflow).

## Details
`src/reader.rs:771` (`get_pages_tree_count`) recurses on each `/Kids` reference. The `seen` HashSet
rejects revisiting the *same* object id (cycle guard) but does not bound recursion *depth*. A chain
of N distinct `/Type/Pages` nodes, each `/Kids [next 0 R]` and **without `/Count`** (so the
early-return that would short-circuit counting is skipped), drives recursion to depth N.

## Reproduction (public API, untrusted bytes — parse-reachable)
A generated PDF with N=200000 linear `/Pages` nodes (no `/Count`), via the public
`Document::load_metadata(path)` (a "cheap page-count/title" call):
```
Document::load_metadata(deep.pdf)
-> thread 'main' has overflowed its stack / fatal runtime error: stack overflow, aborting (SIGABRT)
```
PoC generator: `poc/pagetree_recursion/gen_deep_pages.py`. Unconditional (plain release, default
8 MB stack).

**Self-audited reachability notes:**
- The root `/Pages` must **not** carry `/Count` (a `/Count` short-circuits `extract_page_count`
  before it descends — verified: N=60000 *with* a root `/Count` did **not** overflow).
- The triggering entry is `load_metadata`, **not** `load_mem` — in testing, `load_mem` +
  `get_pages()` used a different, non-overflowing traversal. So the advisory is scoped to consumers
  that call `load_metadata` on untrusted PDFs.
- The pipeline's reattack harness could not auto-build a generative deep-chain harness for this
  (marked `build_failed`), but the agent hit the same SIGABRT in-transcript; the hand PoC is the
  authoritative reproduction.

## Impact & reachability
Any consumer calling `Document::load_metadata` on an untrusted PDF can be crashed by a generated
file → DoS.

## Suggested fix
Add a recursion depth bound (or convert to an explicit work-list/iterative traversal) in
`get_pages_tree_count`.
