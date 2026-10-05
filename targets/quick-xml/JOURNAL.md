# quick-xml 0.41.0 — campaign journal

Target: `quick-xml` 0.41.0 (334M downloads, pull-based XML reader/writer). Run as an **A/B method
experiment** at the user's request: Run A = "just point it at the code and find bugs" (blind, no threat
model, no surface decomposition); Run B = threat-model-first (5 surface-specific lenses derived from the
9-section THREAT_MODEL.md). Same verify panel (3 skeptics, refute-by-default) both sides.

## Stage 0 — threat model
`THREAT_MODEL.md` / `capabilities.json`. Verdict: hardened, heavily-fuzzed, safe-Rust parser. Memory
near-refuted (escape.rs `unsafe` is largely NOTE-comments over safe indexing). Billion-laughs mitigated
by design (attribute-normalization entity expansion capped at 128, `TooManyEntities`). No XXE in-crate
(external entities not resolved). Priority surface: T2 tokenizer panic, T5 parser differential; T4 serde
recursion (opt-in); T1 memory near-refuted; T3 non-entity resource exhaustion.

## A/B runs
- **Run A v1** (`w9rgo17jx`) — degraded by API "Connection closed" errors (5/11 agents died); 3/5 blind
  finders survived. Still surfaced the headline bug (below). Confirmed 1, contested 1.
- **Run B v1** (`wz6jkdigt`) — worse infra luck: 3/5 finders died, 2 survivors returned empty → n_raw=0.
  Not a method result — contaminated by network failures.
- **Fix:** added a `tryAgent` retry wrapper (3 attempts, transient null → retry). Relaunched both:
  - **Run A v2** `wih43svug` (blind, retry) — RUNNING
  - **Run B v2** `wl13t1mjm` (TM-seeded, retry) — RUNNING

## Headline finding (from Run A v1, independently re-verified by hand)
**Integer overflow in `NamespaceResolver::push` — unguarded u16 increment, asymmetric with `pop`.**
- `src/name.rs:514` `nesting_level: u16`; `:709` `self.nesting_level += 1;` (plain, unguarded);
  `:763` `pop()` → `set_level(self.nesting_level.saturating_sub(1))`. The maintainer saturates on the
  decrement but not the increment — the intended invariant (saturation) is shown by the sibling line.
- **No depth cap** anywhere on the read_event path (`opened_starts` in reader/state.rs grows unbounded;
  `max_declarations_per_element` is per-element only). `push` is called per Start/Empty event via
  `ns_reader.rs` process_event → reachable from the public `NsReader::read_resolved_event*`.
- **Live on master** (checked raw.githubusercontent tafia/quick-xml/master/src/name.rs — still
  `+= 1` / `saturating_sub`). Survives the L15/L16 already-fixed check.

### PoC (the runner, fuzz image; `poc/src/main.rs` + `poc/src/bin/misres.rs`)
- **overflow-checks ON** (debug builds; hardened/security release profiles that opt in): 70000-deep doc
  (490 KB) → `panicked at name.rs:709:9: attempt to add with overflow` → **DoS**.
- **overflow-checks OFF** (default `cargo build --release`): no panic, but the u16 wraps 65535→0 and the
  `set_level` `rposition(|n| n.level <= level)` scope-truncation then operates on non-monotonic levels →
  **namespace misresolution** (demonstrated, `misres` bin):
  | depth | `<p:e>` expect BBB | `<p:f>` expect AAA |
  |---|---|---|
  | 3 (control) | BBB ✓ | AAA ✓ |
  | 65534 | BBB | **BBB** ✗ (closed-scope binding leaks) |
  | 65535 / 65536 / 70000 | BBB | **Unknown("p")** ✗ (in-scope binding vanishes) |
- **Honest L10 classification:** NOT pure R7. The *panic* is overflow-checks-gated, but the
  *namespace-scope corruption* is reachable in the **default release profile** and is security-relevant
  for any consumer that trusts resolved namespaces (XML-DSig / SOAP action routing / element-by-namespace
  access decisions). Severity MEDIUM (needs ~490 KB + a namespace-trusting consumer; not memory-unsafe).
- **Fix shape (L17):** minimal = `saturating_add(1)` to match `pop` (stops the panic and the wrap; at
  saturation deep nesting shares level 65535, benign-ish). Cleaner = a real depth cap returning an
  `Error` (like `max_declarations_per_element`). One-line, maintainer-obvious → issue+PR candidate.

## Submission re-verify (DONE)
- **nesting_level fix validated.** `saturating_add` (mirror pop) removes the panic but **NOT** the
  misresolution (at saturation all deep levels collapse to 65535, `set_level` still over-truncates —
  measured: `<p:f>` still `Unknown` at depth ≥65534). Correct fix = `checked_add` → clean
  `NamespaceError::TooDeeplyNested` at the u16 boundary (new variant, mirrors `TooManyDeclarations`).
  Patch = 3 hunks in `src/name.rs` + regression test; **all tests green** (default 241+63; serialize
  1362+126; 0 fail). PoC now returns `Err(TooDeeplyNested)` not panic; misresolution gone (doc rejected).
  Packages: `disclosure/01_nesting_issue.md`, `disclosure/02_nesting_pr.md`, `poc/name.rs.patched`.
- **serde-recursion vs #819 — brings NEW.** #819 = *correctness* (tiny recursive-**newtype**-enum doc
  overflows at depth ~3; struct-variant `$value` form works). Ours = *DoS*: the **working** path
  (struct-variant / `serde_json::Value` via `deserialize_any`) has no depth cap and **aborts at
  attacker depth** — proven: struct-variant `S{$value:Vec<S>}` returns fine at depth 3/1000 but
  `stack overflow, aborting` at 20 000 (140 KB). So it's independent of #819's newtype bug. Contribution
  = DoS framing + PoC + "affects the working path" + fix direction (configurable recursion limit à la
  serde_json). Package: `disclosure/03_serde_recursion.md`.
- **Fuzz soak DONE:** memory-clean, 0 crash/oom/timeout over ~108M execs (L14/L19 confirmed).

## Awaiting user "go"
- File nesting_level issue + PR (novel, complete). No SECURITY.md → public issue+PR path.
- serde-recursion: new issue cross-referencing #819 (recommended) vs comment on #819 — user's call.
