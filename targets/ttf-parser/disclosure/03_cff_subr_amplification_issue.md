# ISSUE — ttf-parser: CFF global subroutines have depth cap but no total-invocation cap

**Title:** `outline_glyph` on CFF fonts can amplify work exponentially through repeated global subroutine fanout

### Summary

Tested against `ttf-parser 0.25.1` (current crates.io release).

The CFF charstring interpreter caps recursion depth (`STACK_LIMIT = 10`) but does not cap total
subroutine invocations and does not memoize repeated subroutine execution. A crafted glyph can therefore
stay within the allowed depth while repeatedly re-entering the same lower-level global subroutines many
times, creating exponential work amplification in `Face::outline_glyph`.

### Dynamic reproduction

Self-contained PoC: [docs/e13/poc/ttf-cff-subr-amplification.rs](../../../docs/e13/poc/ttf-cff-subr-amplification.rs)

The PoC builds a minimal CFF font with one glyph and a chain of global subroutines:

- control case: `fanout=1`, `depth=8`
- attack case: `fanout=4`, `depth=8`

Both go through the same public API:

```rust
face.outline_glyph(GlyphId(0), &mut Dummy)
```

Observed result on `ttf-parser 0.25.1`:

```text
control: fanout=1 depth=8 -> None in 12.375µs
attack:  fanout=4 depth=8 -> None in 29.745833ms
```

So a tiny crafted change in the charstring graph produces a runtime increase of roughly three orders of
magnitude while staying within the interpreter's depth cap. (Absolute timings are machine-dependent — an
independent run on a faster host measured ~0.6 µs vs ~2.2 ms; the ~10³× ratio, not the absolute
milliseconds, is the invariant. A higher `fanout`/`depth` within the depth cap amplifies further.)

### Root cause

The interpreter checks only call depth (`STACK_LIMIT`) in CFF/CFF2 subroutine handling. Repeated
`callgsubr` / `callsubr` re-executes the referenced subroutine body every time, with no total step budget
and no memoization, so a fanout tree expands as roughly `B^depth`.

### Reachability

Reachable through the normal public outline path on attacker-controlled CFF font bytes:

```rust
Face::outline_glyph(...)
```

### Severity

Medium — CPU DoS / work amplification on untrusted font input.

### Suggested fix

Add a total operation / total subroutine invocation budget in addition to the existing depth cap.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
