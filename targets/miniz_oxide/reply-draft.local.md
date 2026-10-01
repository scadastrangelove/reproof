DRAFT reply to oyvindln on Frommi/miniz_oxide#198 — for review before posting.
Everything below the "---" is the comment text. Opener is the user's own voice;
the rest is the LLM-checked fix analysis, disclosed as such in the opener.

---

I'm not a real developer, more of a security and fuzzing guy. I put together a
POC for you and asked LLM to check for possible fixes, the text is below.

---

**zlib and the fixed table.** zlib precomputes it — `inflate_fixed()` is just
`state->lencode = lenfix; state->distcode = distfix;`, pointing at a static table
generated once into `inffixed.h` (zlib's own comment sizes it at ~2KB). No
per-block build for `BTYPE=1`. So precomputing the fixed table matches zlib and
removes the static variant of this.

**Dynamic blocks — still a problem, measured.** A `BTYPE=2` block can be just as
degenerate: an EOB-only litlen table (symbol 256, 1-bit code — already accepted
as a legal incomplete table), an empty dist table, emit only end-of-block → 0
output, full `init_tree()` per block. Minimal such block is ~11.5 bytes.
Published 0.9.1, release build, `decompress_to_vec_with_limit(_, 1<<30)`:

```
block type   | N blocks  | payload | out | elapsed | bytes/block
static  (=1) | 1,000,000 | 1.25 MB |  0  | ~2.3 s  | 1.25
dynamic (=2) | 1,000,000 | 11.5 MB |  0  | ~2.0 s  | 11.50
```

Same per-block CPU; static is ~9x cheaper to send, but 11.5 MB for ~2
CPU-seconds of zero output is still trivial to deliver, and `_with_limit` never
engages either way. Precomputing the fixed table doesn't close this — a dynamic
block's tables are defined in the stream and rebuilt per block regardless. So
the two changes are complementary:

- precompute fixed table → removes the static variant, speeds up real static decoding
- bound per-block build work → covers the dynamic variant, which the first can't reach

**Code size.** The guard is a `u32` counter and one comparison in the
block-header path; the big-looking part of the PR is additive API
(`#[non_exhaustive]` enum + new `_with_limits` fns), no existing signatures
touched. If you'd rather not add a budget: the per-block cost comes from
`init_tree()` doing an unconditional `look_up.fill` (1024) + `tree.fill` (576)
every call regardless of symbol count. zlib avoids this — `inflate_table()`
fills only the region it uses. Making the fill proportional would blunt both
variants with no public knob (more invasive; that fill is a hot-path safety
mechanism).

Reproducer for both variants attached (`miniz_issue198_both_variants.rs`,
published `miniz_oxide` only): `cargo run` prints the table above;
`cargo test -- --ignored` is a timing regression that fails on `main` and passes
once per-block work is bounded, so you can run it against any fix branch. Can
reshape the PR whichever way you prefer.
