# lopdf advisories — adversarial maintainer review (summary)

Each of the 4 confirmed findings was re-verified by execution (production profile, overflow-checks
off) and then handed to an independent agent role-playing a **skeptical lopdf maintainer** whose job
was to reject / downgrade / wontfix it. Result: **all 4 survive as file-worthy bugs; none rejected;
severity corrected Moderate → Low across the board; two of my drafts corrected.**

| # | Finding | Site | Verdict | Reachability | Severity | Fix |
|---|---|---|---|---|---|---|
| 1 | inline-image `/ColorSpace` `.unwrap()` | parser/mod.rs:670 | **ACCEPT** | holds (Content::decode is *the* extraction path; skip-to-EI recovery bypass verified) | Low | **`.unwrap()`→`?`** (my `.ok()` snippet was wrong) |
| 2 | empty `/ColorSpace []` `array[0]` | document.rs:779 | **ACCEPT (downgrade)** | holds — **parse-reachable, not the construction trap** (nom `many0` accepts `[]`) | Low | `array.first()…` (correct) |
| 3 | xref `/W` width → 1 TB alloc | parser_aux.rs:568 | **ACCEPT** | holds (alloc before content bound; abort uncatchable) | Low(–Mod) | bound `/W`≤8 on all 3 widths |
| 4 | Pages-tree recursion → stack overflow | reader.rs:771 | **ACCEPT (downgrade)** | holds (`load_metadata` is documented; no depth guard) | Low | reuse existing `PAGE_TREE_DEPTH_LIMIT=256` |

## What the adversarial pass changed (its value)

- **Severity reality-check:** every finding was rated **Low**, not Moderate — all are availability-only,
  memory-safe panics/aborts, matching lopdf's prior RUSTSEC panic-DoS class. My "Moderate
  unauthenticated DoS" framing was consistently one notch high. Corrected in every advisory.
- **Caught a wrong fix (#1):** my `.ok().and_then(...)` snippet leaves `num_colors` undefined; the
  correct minimal fix is the one-token `.unwrap()`→`?`. Corrected.
- **Killed two would-be maintainer dismissals with the crate's *own* code — strengthening the reports:**
  - #3 is **not** the documented decompression-bomb class: `max_decompressed_size` doesn't touch the
    `/W` vectors, and the PoC has no `/Filter` so the guard isn't even on the path.
  - #4 is an **inconsistency, not by-design**: `PageTreeIter` already caps depth at 256, so the crate
    already treats deep `/Pages` trees as an in-scope threat — `get_pages_tree_count` just missed the guard.
- **Confirmed the #2 reachability was genuine, not the x509-RSA construction trap** — the reattack
  harness had reproduced #2 by building the Document via the builder API (rejectable), but the
  re-verification with a real `load_mem`-parsed 487-byte PDF holds up under scrutiny.
- **CWE hygiene (#2):** it's a safe-Rust bounds-check panic, not a memory-unsafe OOB read — don't
  badge it as a memory-safety CVE.

## Net

4 genuine, execution-confirmed, parse-reachable, **Low-severity** DoS bugs in lopdf 0.44.0, each with
a verified PoC and a correct one-line-ish fix, each having survived an adversarial maintainer review.
Ready for coordinated disclosure. Cleanest lead report: **#1** (triple-confirmed, one-token fix).
