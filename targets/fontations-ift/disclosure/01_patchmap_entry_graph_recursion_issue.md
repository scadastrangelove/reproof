# ISSUE — incremental-font-transfer: format-2 patchmap child-entry recursion can overflow the stack

**Title:** `EntryIntersectionCache::coverage_intersection_impl` recurses without a depth bound on format-2 child-entry chains

Tested against upstream tag **`incremental-font-transfer-v0.6.0`**
(`b08fd8746782df7139580c68159041cd90c3892d`), which corresponds to crate version **0.6.0**.

### Summary

`incremental-font-transfer`'s format-2 patchmap handling recursively walks `Format2Entry.child_indices`
with no depth limit in:

- `EntryIntersectionCache::intersects` / `compute_intersection`
- `EntryIntersectionCache::coverage_intersection_impl`

The decoder enforces that child indices only point backward, so the structure is acyclic. But that
still allows a linear chain:

- `entry[0] -> []`
- `entry[1] -> [0]`
- `entry[2] -> [1]`
- ...
- `entry[N] -> [N-1]`

On such an input, recursion depth becomes `O(N)` and can exhaust the native stack.

### Dynamic confirmation

I confirmed this dynamically on the exact `v0.6.0` source tag by adding a throwaway internal test
that:

- constructs a `Vec<Format2Entry>` with a 50,000-entry linear child chain
- calls
  `EntryIntersectionCache::coverage_intersection_impl(&entries, &target, entries.len() - 1, &mut cache)`
- runs the call on a thread with a 64 KiB stack

Observed result:

```text
thread 'ift-linear-recursion' (...) has overflowed its stack
fatal runtime error: stack overflow, aborting
...
(signal: 6, SIGABRT: process abort signal)
```

So this is not just a theoretical source-trace concern — the recursion actually aborts the process.

### Why this seems reachable

The source already validates that child indices refer only to prior entries:

- malformed forward references are rejected
- but deep valid backward chains remain allowed

That means an attacker-controlled format-2 patchmap can encode a long acyclic dependency chain and
still pass structural validation.

### Affected code

Primary recursion points in `src/patchmap.rs`:

- `EntryIntersectionCache::intersects`
- `EntryIntersectionCache::compute_intersection`
- `EntryIntersectionCache::coverage_intersection_impl`

The stack-overflow reproduction used `coverage_intersection_impl`, but the same unbounded recursive
shape also exists in the intersection-check path.

### Fix direction

Two reasonable approaches:

1. add an explicit recursion-depth limit and return a `ReadError` when exceeded, or
2. rewrite the child traversal iteratively (explicit stack / post-order traversal), which would
   avoid process-stack growth entirely

The second option looks more robust long-term, but even a conservative depth cap would turn this
from process abort into a normal parse failure.

### Severity

Medium — attacker-controlled input can trigger an uncatchable stack-exhaustion abort.

This is an availability / DoS issue, not memory corruption.

### Notes

- This was verified on the version-matching upstream source tag for 0.6.0.
- I do not yet have a polished standalone font file reproducer; the dynamic confirmation used a
  narrow internal test-style harness directly against the crate’s format-2 entry logic.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
