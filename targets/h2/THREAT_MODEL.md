# Threat model — `h2` (hyperium/h2), HTTP/2 protocol implementation

**Pin:** `9416dc875da6d6b900eedc22636413c62dae912b` (v0.4.15, HEAD 2026-07-24)
**Provenance:** bootstrap (code + advisory history), pre-hunt
**`target_layer`: protocol / state-machine** (ADR-1) → **invariant-first**, NOT fuzz-first.

## 1. Context

`h2` is the HTTP/2 implementation under `hyper`, therefore under axum / reqwest / tonic / warp /
most of the Rust HTTP ecosystem. It implements **both peers** (`client.rs`, `server.rs`) over a
shared `proto/` state machine. Wire side is fully attacker-controlled on both sides: a malicious
client against a server, and a malicious/compromised **server against a client** (the latter is the
historically under-hardened direction — see mirror axis M1).

Sizes: `hpack/` 9.1k LOC, `proto/` 8.4k, `frame/` 3.0k, `codec/` 1.2k, `client.rs` 1.7k,
`server.rs` 1.8k.

## 2. Layer routing & why fuzzing is deprioritized (ADR-1 gate)

The crate already ships fuzz targets — `fuzz/fuzz_targets/fuzz_client.rs`, `fuzz_e2e.rs`,
`fuzz_hpack.rs`, plus `tests/h2-fuzz` and an in-tree `hpack/test/fuzz.rs` and `src/fuzz_bridge.rs`.
HPACK and end-to-end byte-mutation are therefore **already covered by the project's own fuzzing**.
Per ADR-1 the marginal value is in the classes that fuzzing cannot reach:

- deep valid-handshake/stream states a mutation fuzzer will not construct,
- bugs with **no crash oracle** (silent accounting drift, wrong-accept, unbounded growth that only
  manifests as OOM after minutes),
- **domain invariants** (RFC 9113 / RFC 7541 rules) that are not encoded as assertions.

So: **invariant-first**, with the two lenses from `docs/lenses/protocol-invariant.md`.

## 3. Assets & entry points

| Asset | Why it matters |
|---|---|
| Connection/stream bookkeeping (`proto/streams/`) | unbounded growth = OOM; all 3 past advisories live here |
| Flow-control accounting (`flow_control.rs`, `recv.rs`, `send.rs`) | window desync → stall, or overflow → protocol break |
| HPACK dynamic table (`hpack/table.rs`, `decoder.rs`) | decompression bomb / table poisoning / index OOB |
| Stream state machine (`state.rs`) | illegal transition acceptance = request smuggling-adjacent |
| Peer-controlled limits (`settings.rs`) | attacker-chosen bounds applied to *our* allocations |

Entry points: every frame type from the peer (`frame/*.rs`) → `codec/framed_read.rs` →
`proto/connection.rs` → `proto/streams/*`; plus the application-facing builder config
(`client.rs`/`server.rs`) which sets the limits.

## 4. Prior-vulnerability history (all resource-exhaustion — the house bug-class)

| Advisory | Mechanism | Fix shape |
|---|---|---|
| RUSTSEC-2023-0034 (CVE-2023-26964) | HEADERS/RST_STREAM flood → **pending-accept queue** grows unbounded → OOM | added `max_pending_accept_reset_streams` (#668) |
| RUSTSEC-2024-0003 (rel. CVE-2019-9514) | invalid frames force *our* RST_STREAM generation; attacker closes recv window → **our reset frames queue unbounded** → OOM/CPU | added a cap on total internal-error resets (#737) |
| RUSTSEC-2024-0332 | **CONTINUATION flood** → unbounded processing → CPU | bounded CONTINUATION handling (0.4.4) |

**The generalization that drives this hunt:** every fix added a **counter/limit**. A counter is only
as good as (a) the completeness of the paths that check it, (b) the symmetry of its application, and
(c) the non-porousness of its reset. That is exactly the L43 lens.

## 5. Invariants to walk (RFC 9113 / RFC 7541)

1. Stream state machine transitions (§5.1) — illegal frame for state must be rejected.
2. Stream IDs (§5.1.1) — monotonic, correct parity, no reuse, post-GOAWAY IDs ignored.
3. Flow control (§5.2, §6.9) — **connection-level AND stream-level**; window ≤ 2^31-1;
   WINDOW_UPDATE increment 0 is an error; DATA debits both levels.
4. SETTINGS (§6.5) — ACK required; `INITIAL_WINDOW_SIZE` change retroactively re-adjusts *every*
   open stream's window (classic overflow/desync source).
5. HPACK (RFC 7541) — dynamic table bounded by `SETTINGS_HEADER_TABLE_SIZE`; size-update ordering;
   index bounds; huffman bounded.
6. CONTINUATION (§6.10) — must immediately follow HEADERS/PUSH_PROMISE on the same stream.
7. MAX_CONCURRENT_STREAMS (§5.1.2) enforcement.
8. Bookkeeping bounds — pending-accept, local/remote reset counters, send buffer.

## 6. Mirror axes (the primary hunt — L43)

- **M1 client ↔ server.** All three advisories were **server-motivated**. `h2` implements both
  peers over shared `proto/`. Is the **client** equally bounded against a malicious server? A
  reqwest/tonic client is a real target. (This is exactly the rustls-B shape: guard on one side only.)
- **M2 stream-level ↔ connection-level.** Flow control, counters and buffers exist at both levels;
  a bound applied at one level only is the classic h2 killer.
- **M3 send ↔ recv.** `proto/streams/send.rs` vs `recv.rs` — is validation symmetric?
- **M4 local-reset ↔ remote-reset.** Two separate counters
  (`num_local_reset_streams` vs `num_remote_reset_streams`, plus `num_local_error_reset_streams`) —
  same guards on each path?
- **M5 bounded ↔ optionally-unbounded.** `max_local_error_reset_streams: Option<usize>`;
  `can_inc_num_local_error_resets()` returns **`true` when `None`** — i.e. a configuration where the
  RUSTSEC-2024-0003 mitigation is off. Which builder/default paths can produce `None`, and is that
  reachable from a plausible config? Also `max_recv_streams: config.remote_max_initiated.unwrap_or(usize::MAX)`.
- **M6 counter increment ↔ counter release.** Is a counter **reset/decremented by a cheap legal peer
  action**, re-arming the budget (the "porous reset" shape)? E.g. does an accepted stream, a
  successful response, or a SETTINGS round-trip release reset-budget?

## 7. Named panic candidates (assert-in-increment)

`proto/streams/counts.rs` has `assert!(self.can_inc_…())` inside
`inc_num_local_error_resets()` and `inc_num_recv_streams()`, documented "Panics on failure as this
should have been validated before hand." Any caller path that increments **without** the paired
check — or where the check and the increment are separated by a state change — is a reachable panic
(the exact rustls-A shape: guard and unwrap drift apart). Enumerate all callers of both.

## 8. Churn zone (L40)

HEAD is a **revert** of "perf(header): optimize `HeaderValue` creation via zero-copy sharing"
(#924, merged 2026-07-23). Recently-reverted/re-landed HPACK decode paths are elevated-risk; check
whether the revert left any partial state, and what the original defect was.

## 9. Scope & honesty notes

- `forbid(unsafe_code)`? — verify per-crate; if unsafe exists (bytes handling), memory-corruption is
  in scope, else the realistic classes are DoS / panic / protocol-logic.
- **DoS is explicitly in-scope for this project** — the maintainers have issued three DoS advisories
  themselves (contrast: image-rs, where crashes/DoS were declared out of scope and our reports caused
  friction). Read `hyperium/hyper`'s SECURITY.md before filing.
- Mature, post-CVE-hardened target: **"0 findings" is a legitimate, expected outcome.** Do not
  manufacture severity.

## 10. Disclosure channel (pre-established)

`hyperium/h2` has **private vulnerability reporting DISABLED**; `hyperium/hyper` has it **enabled**,
and hyper's SECURITY.md explicitly says to report issues "in hyper, **or another crate in the
hyperium organization**" via hyper's advisory form. → File any h2 security finding as a **draft GHSA
at `hyperium/hyper`**, not at `h2`. Non-security correctness bugs → normal public h2 issue/PR.
