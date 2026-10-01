# quick-xml A/B: blind find vs threat-model-first (the L18 experiment)

At the user's request we ran the finder **two ways** on the same target (quick-xml 0.41.0), same 3-skeptic
refute-by-default verify panel, same model, retry-resilient (v2) so neither side was handicapped by the
transient API failures that spoiled the v1 attempts:

- **Run A (blind)** — 5 *identical* generic finders: "find security vulnerabilities in this Rust XML
  parser (memory / DoS / logic)". No threat model, no surface decomposition. (`qxml_blind2.mjs`, `wih43svug`)
- **Run B (threat-model-first)** — 5 *surface-specific* finders seeded with the 9-section THREAT_MODEL:
  T1 escape-unsafe, T2 tokenizer-panic, T3 resource-exhaustion, T4 serde-recursion, T5 parser-differential,
  each carrying the TM's honest framing (memory near-refuted, billion-laughs capped at 128, no in-crate
  XXE — so don't re-report those). (`qxml_tm2.mjs`, `wl13t1mjm`)

## Results side by side

| # | finding | file:line | Run A (blind) | Run B (TM-first) | ground truth |
|---|---|---|---|---|---|
| 1 | `NamespaceResolver::push` u16 `nesting_level` overflow | name.rs:709 | ✅ **MED**, 5 votes | ✅ MED (T2+T3), 3 votes | **novel, PoC-confirmed** |
| 2 | serde deserializer unbounded recursion → stack overflow | de/mod.rs:3233 | ✅ MED, "not run" | ✅ **HIGH**, 3 votes, precise cycle | real, PoC-confirmed — but **known open #819** |
| 3 | unbounded alloc on unterminated token (streaming) | buffered_reader.rs | ✅ LOW, 3 votes | ❌ missed | real but by-design / #970-adjacent |
| 4 | namespace duplicate-binding differential (sig-wrap) | name.rs:713 | ❌ missed | ✅ LOW (T5), 2 votes | guarded (check_duplicates default true) |
| 5 | raw `<` accepted in attribute value (WFC) differential | attributes.rs:1342 | ❌ missed | ⚠️ contested LOW (T5) | plausible differential, low impact |
| — | escape.rs `unsafe` memory bug (T1) | escape.rs | (never examined) | ❌ refuted, 0 votes | correctly none — safe indexing by design |
| | **candidates / refuted** | | 4 cands, 0 refuted | 9 cands, **5 refuted** | |

## What the comparison actually shows (refines L18)

1. **Both runs find the two "big" bugs** (#1 overflow, #2 serde recursion). The obvious-shaped defects are
   found either way — a threat model is not required to trip over them.
2. **TM-first goes deeper on severity & precision.** On #2 it rated HIGH (correct — it's an uncatchable
   `abort` in *release* too; we confirmed 350 KB → stack overflow) with the exact recursion cycle
   (deserialize_struct→visit_map→next_value_seed→…), and noted `deserialize_any`/`serde_json::Value` hits
   it with *no* recursive user type. Blind rated the same bug MEDIUM and left it "not run / class-level".
3. **TM-first uniquely covers the parser-differential surface (T5).** Findings #4/#5 (namespace dup-binding,
   `<`-in-AttValue) live in a class a "find memory bugs / panics" prompt never hunts. Threat-model-first
   put a whole finder on that surface *because the TM named it a priority asset* (trust-boundary integrity).
   This is the L18 payload: **the threat model predicts the surface class, and coverage follows the model.**
4. **Blind has a breadth edge on generic classes the TM under-weighted.** Only the blind run found #3
   (unbounded allocation on an unterminated token) — a generic "unbounded allocation" hunt caught a
   streaming-design issue the TM's exhaustion lens (scoped to entity-expansion/escape) didn't target.
5. **TM-first trades a higher raw-false rate for recall; the verify panel pays it back.** Run B produced
   9 candidates and the skeptics **refuted 5** (escape-unsafe, normalize, QName-index, name_len,
   dup-check); Run A produced 4, refuted 0. Surface-specific lenses generate more (including weak)
   candidates — which is fine *only because* the adversarial verify gate is there to kill them.
6. **The TM's negative predictions held.** T1 "memory near-refuted by design" → escape-unsafe refuted 0-0.
   The 128-entity cap and no-XXE framing kept both runs off billion-laughs/XXE dead-ends.

### Synthesis (the actionable lesson)
Neither strictly dominates. **Threat-model-first wins on depth, severity calibration, and the
differential/logic surface a generic prompt is blind to; the blind sweep wins on generic classes the model
didn't enumerate.** The method upgrade is *both*: run the TM-seeded surface lenses **plus** keep ≥1 generic
"unbounded / panic / infinite-loop" blind lens so a class the threat model forgot still gets swept — then
let the shared verify panel arbitrate. (Feeds back into L18 / the find-Workflow lens set.)

## Honest disclosable output
- **#1 nesting_level u16 overflow — the one novel finding.** Distinct from the closed #970/#972 (that
  capped *declarations-per-element*; this is the *depth* counter), live on master, both facets confirmed
  (panic under overflow-checks; namespace misresolution in default release). → issue+PR candidate.
- **#2 serde recursion — real but already open as #819.** L15 gate caught it: do **not** re-report as
  novel; at most contribute a depth-cap fix PR referencing #819.
- #3 by-design/#970-adjacent; #4 guarded; #5 low-impact differential. Not disclosed.
- Fuzz (1 h ASan, shipping profile): memory-clean, 0 crash/oom — as predicted; it did not synthesize the
  65 536-deep or 350 KB-nested inputs (L14/L19: static finds the deep bug the fuzzer can't reach).
