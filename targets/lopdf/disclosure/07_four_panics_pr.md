Fixes #532.

Four independent, small fixes for the four crash bugs described in the issue — each touches a different
file/function, so listed separately:

1. **`image_data_stream`** (`parser/mod.rs:670`): `.unwrap()` → `?` on `get_abbr(b"CS", b"ColorSpace")`,
   mirroring the `?`-siblings two lines above it (`W`/`H`/`BPC` already use `?`).
2. **`get_page_images`** (`document.rs:779`): guard `array.first()` before indexing, instead of
   `array[0]`. Preserves the existing `?`-propagation for a malformed (non-empty-but-invalid) name —
   only the empty-array case changes behavior (panic → `None` for that image's colorspace).
3. **`decode_xref_stream_with_limit`** (`parser_aux.rs`): bound each of the three `/W` field widths to
   `<= 8` (alongside the existing non-negativity check), before they size a `Vec` allocation.
4. **`get_pages_tree_count`** (`reader.rs`): added a `depth: usize` parameter, checked against the
   crate's existing `MAX_NESTING_DEPTH`, returning `Ok(0)` past the limit — matching the function's own
   graceful-degradation style (its caller already does `.or(Ok(0))`). The existing `seen: HashSet`
   cycle-guard is unaffected; it's a genuinely separate axis (a long, non-cyclic chain visits distinct
   ids the `HashSet` never repeats, so it never trips).

### Validation

- `cargo test`: all green, no test changes needed.
- All 4 PoCs from the issue, before → after this patch:

  | # | before | after |
  |---|---|---|
  | 1 | panics (`unwrap()` on `DictKey("ColorSpace")`) | returns `Err` cleanly |
  | 2 | panics (`index out of bounds: len 0, index 0`) | returns `Ok` cleanly |
  | 3 | aborts (`memory allocation of 1099511627776 bytes failed`) | returns `Err` cleanly |
  | 4 | aborts (`stack overflow`) | `load_metadata` succeeds |

Happy to split into 4 separate PRs if you'd prefer to review/merge them independently — the diffs don't
overlap (`document.rs`, `parser/mod.rs`, `parser_aux.rs`, `reader.rs`).

Found & fixed with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
