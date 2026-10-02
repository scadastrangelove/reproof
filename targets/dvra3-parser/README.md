# `dvra3-parser` — DVRA-3 parser target + a benchmark experiment log

A `profile: rust` target that runs the full autonomous pipeline against the
binary-record parser from the [Damn Vulnerable Rust Application](https://github.com/scadastrangelove/damn-vulnerable-rust-app)
`dvra-3` (`crates/parser`, Apache-2.0). The planted defect is **DVRA-003 —
"stale parser offsets after normalization"**: `validate()` records payload ranges
against the *original* byte stream, `normalize()` then strips escape pairs
(shrinking the buffer), and records are sliced out of the *shortened* buffer with
the *stale* ranges → an out-of-bounds slice-index panic (or cross-record
disclosure) on a crafted multi-record input.

## Files

- **`config.yaml`** — `profile: rust`; `binary_path /work/riptarget`.
- **`parser/src/bin/riptarget.rs`** — the ASan + `panic=unwind` driver: reads
  `argv[1]` as bytes, calls `dvra_parser::parse_vulnerable(&bytes)`. A panic / OOB
  unwinds to exit 101 (a crash the harness catches); a graceful `Err(...)` prints
  `reject:` — correct handling, not a finding.
- **`capabilities.json`** — `untrusted_deserialization` + `network_protocol_parser`
  (→ vote-budget N=3, dispatch → `byte_parser.rs` / ASan).
- **`Dockerfile`** — nightly + `-Zsanitizer=address -Zbuild-std` driver build +
  cargo-fuzz + Miri (crib of `rust-canary`).
- **`parser/`** — the DVRA-3 parser crate, vendored standalone (edition 2021), with
  the benchmark answer key held out (see *Benchmark hygiene*).

## Run it

```sh
export KIMI_MODEL_NAME=... KIMI_MODEL_API_KEY=... KIMI_MODEL_BASE_URL=...
reproof run dvra3-parser --parallel --stream --auto-focus --aggregate union --model <model>
reproof reattack  results/dvra3-parser/<ts>/ --parallel --aggregate union
reproof scorecard results/dvra3-parser/<ts>/
```

(Add `--dangerously-no-sandbox` on a throwaway Linux box without gVisor.)

## What happened — staged run, blind

Run on a Linux builder, model reached over a proxy via an OAuth token, with the
DVRA oracle held out so the find agent worked blind:

| stage | result |
|---|---|
| recon → find×3 (union-of-N) | **2/3** agents landed `crash_found` |
| find PoC | `445652410201021b000201aa` — **bit-identical to the DVRA-003 gold seed** |
| crash | `panic at parser/src/lib.rs:37: range start index 11 out of range for slice of length 10` |
| grade → report | passed; exploitability report **10/10, MEDIUM** |
| reattack (find→fuzz bridge) | **2/2 reproduced** (`byte_parser.rs` / ASan, first build) |
| scorecard | **exit 0** — every finding characterized (no clean-without-reason) |

The blind find agent independently derived the exact input the benchmark authors
planted — a clean end-to-end reproduction of DVRA-003, confirmed dynamically.

## Parity record — Kimi Code CLI backend (reproof, 2026-10-01)

Same target, same commands, Kimi Code CLI 2.1.1 (`kimi-for-coding`) behind the
gVisor sandbox + egress proxy (host `Tamm`, results dir
`results/dvra3-parser/20261001T215518Z/`):

| stage | Claude baseline | Kimi backend |
|---|---|---|
| recon → find×3 (union-of-N) | 2/3 `crash_found` | **2/3 `crash_found`** (votes 2/3, both passed grade) |
| find PoC | gold-seed-identical | **gold-seed-identical** (`445652410201021b000201aa`) |
| grade → report | 10/10, MEDIUM | **10/10, MEDIUM** |
| reattack | 2/2 reproduced | **1/1 reproduced** (`byte_parser.rs` / ASan) |
| scorecard | exit 0 | **exit 0** |

Backend bugs the live benchmark exposed (all fixed the same day, see
`docs/deployment.md` and git history): Node 22 required in the agent image;
`--model` needs a real config alias; resume-hint absent on mid-stream drops
(on-disk session discovery added); the egress proxy dropped fat request
bodies (EAGAIN in a non-blocking pump) once agent context exceeded ~100 KB.

## The broader experiment

This target is the *dynamic* slice — 1 of dvra-3's 10 gold findings (the one clean
byte-crash). The full pipeline was also run over all of `dvra-3`:

- **Static `/vuln-scan` + `/triage`** over the 6 crates recalled **9/9** real
  findings — cross-tenant IDOR, shell injection, SSRF, zip-slip, false `Sync`
  (data race), panic-safety double-drop, secret-in-logs, the stale-offset parser
  bug, and the unreachable legacy shell export — and correctly did **not** file the
  `defect:false` decoy (0 false positives). DVRA-003 was additionally confirmed by
  the live crash here.
- **Blind-variant experiment** — to test whether recall rode on the benchmark's
  self-documenting naming, `dvra-3` was `/vuln-scan`'d at three build levels:
  - **hinted** — original `dvra-3` (`_vulnerable`/`_fixed` names, exploit-demonstrating tests present);
  - **neutral** — neutral names, demonstrating tests stripped, `_alt` safe siblings still present;
  - **solo** — safe siblings removed + lab-gate string neutralized (= the published
    [`dvra-3-blind`](https://github.com/scadastrangelove/damn-vulnerable-rust-app/pull/1)).

  **Recall held 9/9 → 9/9 → 9/9**, and the `defect:false` decoy was rejected every
  time — on these textbook classes the naming / sibling / control-flow-divergence
  crutches were **not** load-bearing. Each cell is the finding id `/vuln-scan`
  assigned in that run (ids are per-run; the behavioral signature is the same bug):

  | gold | hinted build | neutral build | solo build | behavioral signature |
  |---|---|---|---|---|
  | DVRA-001 IDOR | F-002 `get_unscoped` | F-003 `find_artifact` | F-008 `find_artifact` | lookup has no per-tenant ownership check |
  | DVRA-002 cmd-inj | F-004 `run_vulnerable` | F-002 `run_hook` | F-007 `run_hook` | `sh -c` with `artifact_name` interpolated |
  | DVRA-003 stale-offset | F-003 `parse_vulnerable` | F-001 `parse_records` (conf 1.0) | F-003 `parse_records` | pre-normalization ranges indexed into the shrunk buffer |
  | DVRA-004 double-drop | F-007 `PanicCell` | F-008 `SlotCell::replace_with` | F-004 `SlotCell::replace_with` | `initialized` stays true across a panicking callback |
  | DVRA-005 false-Sync | F-008 `RacyCounter` | F-006 `SharedCounter` | F-005 `SharedCounter` | unconditional `unsafe impl Sync` over unsynchronized state |
  | DVRA-006A unreachable shell | F-009 `unreachable_legacy_export` | F-009 `legacy_export` | F-010 `legacy_export` | same shell-injection pattern (unreachable from the API) |
  | DVRA-007 secret-log | F-006 `secret_token` | F-007 `secret_token` | F-006 `secret_token` | secret carried in a derived `Debug` |
  | DVRA-008 zip-slip | F-001 `extract_vulnerable` | F-005 `extract_bundle` | F-001 `extract_bundle` | attacker path joined without sanitization |
  | DVRA-009 SSRF | F-005 `fetch_vulnerable` | F-004 `fetch_url` | F-002 `fetch_url` | no egress allowlist + follows redirects |
  | DVRA-006B decoy (`defect:false`) | not filed | not filed | not filed | correctly ignored — 0 over-reports |

  The **solo** run additionally surfaced one candidate not in the gold — F-009
  `fetch_url` buffering the full response body with no size cap (an
  unbounded-buffer / DoS, a `real_latent` bonus rather than a miss). The
  neutralized tree is contributed back as `dvra-3-blind` with a deterministic
  generator, so it tracks upstream instead of forking.

## Benchmark hygiene

For a credible blind measurement the answer material — `instructor-oracle/`,
`scenarios/`, `fuzz/` differentials, and `// DVRA-NNN` comments — was held out of
the scanned/vendored tree; only the scorer sees the gold. DVRA's structural
`_vulnerable` naming is inherent to its design; the blind variant above removes it.

---
*The `parser/` crate is derived from DVRA (Apache-2.0). Deliberately vulnerable —
not for production; run only in a disposable environment.*
