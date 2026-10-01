# lopdf Pages-tree recursion → stack overflow (CONFIRMED prod-real, CWE-674)

`Document::load_metadata(path)` → `read_metadata` → `extract_page_count` → `get_pages_tree_count`
(`src/reader.rs:771`) recurses once per `/Kids` entry. The `seen` HashSet guards *cycles* but not
recursion *depth*. A PDF encoding a linear chain of N distinct `/Type/Pages` nodes, each with
`/Kids [next 0 R]` and **no `/Count`** (so the early return is skipped), drives native recursion to
depth N → **stack overflow → `fatal runtime error: stack overflow, aborting` (SIGABRT, exit 134)**.

- Verified 2026-07-18 in-image, plain release (`overflow-checks=false`, default 8 MB stack):
  N=200000 aborts; N=60000 with a `/Count` on the root did NOT (the `/Count` short-circuits
  `extract_page_count` before it descends — the finding's "no /Count" condition is load-bearing).
- **Unconditional** (not overflow-checks-gated) and **uncatchable** (`catch_unwind` does not stop a
  stack overflow abort). Production-real DoS.
- Reachability: via the public `Document::load_metadata` (a "cheap page-count/title" call an app may
  run on untrusted PDFs). The in-memory `load_mem`+`get_pages` path did NOT overflow in testing
  (different traversal), so the reachable entry is `load_metadata`. Honest severity: medium DoS.
- Fuzzing structurally cannot find this (needs a ~10^5-deep structured chain); targeted PoC only.
