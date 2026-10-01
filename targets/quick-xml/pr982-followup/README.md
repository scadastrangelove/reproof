# quick-xml PR #982 — follow-up artifacts (recursion-depth limit)

Responding to Mingun's review on
[tafia/quick-xml#982](https://github.com/tafia/quick-xml/pull/982), against PR head
`6d763c1`. Two asks: (1) a full self-reference test matrix with an expected result
for every case, (2) evaluate moving the `deserialize_enum` guard into `EnumAccess`.

## `full-13-case-matrix.diff`

Adds all 13 requested cases to `tests/serde-issues.rs` `mod issue978`, each with an
asserted expected result, no `#[ignore]`d tests. Verified: full `serde-issues`
suite 34/34 green, full `cargo test --features serialize` green.

- Green depth tests (round-trips within the limit, `TooDeeplyNested` past it):
  #1, #2*, #3, #4*, #5*, #10, #11, #12, #13. (*already covered by cycle1/2/3.)
- `TooDeeplyNested` regardless of depth (self-referential enum re-entry — same
  mechanism as the existing `Box` newtype case, #819): #6, #7 slot-first,
  #8 slot-first. The PR's guarantee here is "catchable error, not stack overflow."
- Explicit assertion of a **pre-existing** shape limitation, independent of the
  depth cap (would need updating if the underlying shape is ever fixed):
  #7 and #8 recursive-slot-second (`Box` and `Vec` both) → `UnexpectedStart`;
  #9 self-referential named `Box` field → `Custom("unknown variant \`$text\`")`.
  #7/#8 slot-second confirms the limitation is shared by both container types,
  not `Box`-specific. The analogous `Vec`/`$value` forms (#10/#11) work for #9,
  so that one is a separate enum-shape issue, not this PR.

## `option-b-enumaccess-guard.diff`

Prototype of Mingun's "store `DepthGuard` inside `EnumAccess`" suggestion.
Compiles, full suite green. Net +17/-18 across `src/de/{var,mod}.rs`:
`DepthGuard` → `pub(crate)`, `EnumAccess`/`VariantAccess` hold a `DepthGuard`
instead of `&mut Deserializer`, `EnumAccess::new` becomes fallible (guards on
construction), and the five `EnumAccess`/`VariantAccess` methods take `mut self`
(mutating through the guard field needs it; a bare `&mut` reborrow didn't). No
`Drop for EnumAccess` — the existing `DepthGuard::Drop` fires when `VariantAccess`
(which now owns the guard) drops, after variant processing.

The other suggested shape — `Drop for EnumAccess` that decrements — does **not**
compile: `variant_seed` returns `VariantAccess { de: self.de }`, moving the
deserializer ref out, which E0713-conflicts with a `Drop` that needs `*self.de`.

Both diffs apply cleanly on PR head `6d763c1`.
