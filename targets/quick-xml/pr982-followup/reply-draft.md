DRAFT reply to Mingun on tafia/quick-xml#982 — for review before posting.

---

Fair point on covering everything — I went through the full matrix and tried
both guard shapes.

Small attribution note: I'm more of a fuzzer/security person than a quick-xml
maintainer, and I used an LLM-assisted local workflow to draft the tests and
refactor prototypes below. I re-ran them locally, but please double-check style
and fit for the crate.

Both diffs below apply independently on PR head 6d763c1, each passes full
`cargo test --features serialize`, and the full suite also stays green with
both applied together.

**Full matrix — all 13, with an asserted expected result, no ignored tests.**
Most land as clean depth tests (round-trip within the limit, `TooDeeplyNested`
past it): #1, #3, #10, #11, #12, #13 as new tests, #2/#4/#5 already covered by
cycle1/2/3. The self-referential enum re-entry cases (#6 `Vec` newtype, #7/#8
tuple with the recursive slot first) return `TooDeeplyNested` at any depth — the
same non-consuming re-entry as the existing `Box` newtype case (#819) — so the
asserted result there is "catchable error, not stack overflow," which is what
this PR guarantees.

Two spots assert **pre-existing** limitations that are independent of the depth
cap, so the behavior is pinned rather than skipped:

- Recursive slot second in a tuple variant (`Multi(bool, Box<Self>)` for #7,
  `Multi(bool, Vec<Self>)` for #8) → `UnexpectedStart` before depth is ever
  reached. Checked for both container types on purpose — same result for
  `Box` and `Vec`, so it's a tuple-variant limitation, not `Box`-specific.
- #9 self-referential named `Box` field (`<Named><Named>…`) → an "unknown
  variant `$text`" error. The `Vec` (#10) and `$value` (#11) analogues work,
  so this looks like a separate enum-shape issue, not this PR.

Flagging those because if the underlying shapes are ever fixed, those
assertions will need updating — they're characterization of current behavior.

**On moving the guard into `EnumAccess`.** I tried both shapes you suggested:

- `Drop for EnumAccess` that decrements — doesn't compile. `variant_seed` returns
  `VariantAccess { de: self.de }`, moving the deserializer ref out, and that
  conflicts with `Drop` needing exclusive access to `*self.de` when `EnumAccess`
  is dropped (`E0713`).
- Storing the `DepthGuard` inside instead — works, full suite green. It needs
  `DepthGuard` to be `pub(crate)`, `EnumAccess`/`VariantAccess` to hold a
  `DepthGuard` rather than `&mut Deserializer`, `EnumAccess::new` to become
  fallible (it guards on construction), and `mut self` on the five
  `EnumAccess`/`VariantAccess` methods (mutating through the guard field needs it).
  No `Drop for EnumAccess` — the existing `DepthGuard::Drop` fires when
  `VariantAccess` drops, after variant processing. Net +17/-18.

One observation either way: the recursion actually happens inside
`VariantAccess` (`newtype_variant_seed` re-enters `deserialize_enum`), so the
guard has to stay alive through variant processing — which the current local in
`deserialize_enum` already does, since it spans the whole `visit_enum`. So the
stored-guard version is the same RAII scope relocated into the type, at the cost
of threading it through `VariantAccess`; the current placement isn't wrong, just
less visually "owned." My preference would be to push the matrix first and treat
the guard relocation as optional cleanup if you prefer that ownership shape.
