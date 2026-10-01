# h2 campaign JOURNAL — hyperium/h2 v0.4.15 (pin 9416dc875da6)

Layer-routed **protocol/state-machine → invariant-first** (ADR-1; h2 already OSS-Fuzz'd, so the
marginal value is the invariant/differential lens, not byte-fuzz). Threat model: `THREAT_MODEL.md`.

## Stage 2 — 3-lens × 2-model find + verify (wf_69e5611b-3ce)

6 finders (threat-model / blind / cve-seeded × opus / sonnet) on isolated corpora → 18 raw findings,
weak dedup (~6 real clusters), 10 verified (cap 12→10, 8 not verified but **logged, not dropped**).
Both models independently converged on the **client-role PUSH_PROMISE** cluster — mirror axis M1
(all 3 past DoS advisories were server-motivated; the client push-receive path was under-hardened).

## Findings & their reachability (the crux)

| Cluster | Mechanism | Reachable via hyper? |
|---|---|---|
| **A** 1xx-on-reserved panic | 2nd 1xx HEADERS on a PUSH_PROMISE-reserved stream re-enters the `initial` branch → `assert!(!is_counted)` (counts.rs:111 / state.rs:157) → **remote client panic** | ❌ push-gated |
| **B** reserved→open MAX_CONCURRENT bypass → `assert!` panic | ❌ push-gated |
| **C** PUSH_PROMISE flood → unbounded reserved-stream state | ❌ push-gated |
| **D** zero-length DATA flood → unbounded recv-buffer | ✅ **yes** |
| **E** unbounded 1xx queue on a normal stream | weaker (poll_response drains) |

**Push-gate (independently verified + dynamically proven):** h2 enables server push by default
(`connection.rs:112` `is_push_enabled().unwrap_or(true)`; `Builder::new` leaves it `None`), but
**hyper hardcodes `.enable_push(false)`** (`proto/h2/client.rs:115`) and h2 rejects PUSH_PROMISE when
push is off (`recv.rs:979`). Differential PoC (`poc/` — `h2-push-boundary-poc`): same malicious
sequence, TEST A (native h2, default) PANICS at counts.rs:111; TEST B (hyper) does not — hyper
advertised `enable_push=Some(false)` on the wire. So **A/B/C are default-h2-only, NOT reachable
through hyper/axum/reqwest/tonic** — same shape as rustls Finding A (real bug, official integration
immune). Reportable at reduced severity (remote panic on default-config direct-h2 clients).

**8 capped candidates triaged by hand (not blindly re-run):** 7 = dups of the push clusters or
push-gated/niche; only **E** was independent + potentially hyper-reachable. Verified E directly: real
queue-structure (recv.rs:277-281, no cap, 1xx costs no window) BUT `poll_response` drains 1xx in a
loop (recv.rs:344-349), so it's a weaker sibling of D, not a standalone finding. Fold one sentence
into D.

## D — CONFIRMED, the one finding that reaches through hyper  ← PENDING DISCLOSURE PACKAGE

**Zero-length DATA frames bypass HTTP/2 receive-window flow control.** `recv_data` (recv.rs) gives a
zero-length frame `flow_controlled_len()=0`, so `consume_connection_window(0)` / `recv_flow.send_data(0)`
neither fail nor consume window, yet the frame is still `pending_recv.push_back(...)`'d — with no
frame-count cap. A malicious server floods a non-reading client (backpressure / slow downstream) →
unbounded recv-buffer growth, ~8–22× amplification (9 wire bytes → ~74–197 buffered).

**Clean dynamic differential** (`poc/` — `h2-zerolen-data-poc`, native h2, default 65535 window):
- payload 1 MiB flood → client emits **GOAWAY(FLOW_CONTROL_ERROR)** → BOUNDED (the oracle).
- 0-byte × 1e6 → **no GOAWAY**, recv buffer climbs to +100 MB → UNBOUNDED.
Through hyper the zero-length bypass still holds (zero-length costs no window, so it evades even
hyper's 16 MiB BDP adaptive-window cap; measured ~190 MB/1e6 frames).

Detour lesson (see LESSONS L46): my first RSS differential looked REFUTED because the 4 KB payload
control piled up in the **mock's own pipe buffer**, not the client — a protocol oracle (GOAWAY), not
RSS, settled it. Finder was right; my skepticism was the error.

**Status: D confirmed + PoC saved. Pending packaging** (Medium/Low memory-DoS, precondition = app
holds body unread; channel = `hyperium/hyper` GHSA since h2 PVR is disabled). Novelty: no upstream
empty-DATA-flood issue found. A/B/C reportable separately as default-h2-only remote panics.

## Next
Campaign pivoted to **hyper** (L45 — shell-first). D packaging held in backlog until the hyper pass
lands, so related h2/hyper findings can be filed coherently.

---

## Seam iteration (hyper+h2 tandem) — Phase 1 matrix + Phase 2 trailers dynamic confirm (2026-07-25)

**Phase 1 — tandem seam-symmetry matrix** (wf_739d42df-ddc): 8 map agents (opus+sonnet × 4 seam
families) → 31 gap-claims → 12 adversarially verified → **9 CONFIRMED**. Marquee result is negative
and cross-validated: **G2 (h2→h1 downgrade smuggle) independently REFUTED** — the map agents, blind to
the Phase-2 rig, all cited `h2 frame/headers.rs:915-928` load_hpack; the rig had already hit
`User(MalformedHeaders)`. Two methods, same conclusion: **§8.2.2 is enforced on h2 ingress decode.**
All 9 confirmed gaps share the honest shape **DEMONSTRATED code asymmetry / INFERRED-or-fail-closed
smuggle** (hyper h1 egress hard-fails TE+CL; h2 receiver RSTs forbidden headers; typed re-encode drops
stray pseudos). No Medium+ smoking gun. Residue = a Low/hardening/conformance family: G1 (h1
client-response TE+CL kept), G3/D (zero-length DATA), multiple-CL on h2 ingress, CONNECT/Upgrade
body-over-tunnel, response/trailer pseudo conformance.

**Phase 2 — TRAILERS §8.2.2 send/recv asymmetry, DYNAMICALLY CONFIRMED**
(`scratchpad/hyper-trailer-egress-rig/`). The one gap where BOTH guards are simultaneously absent on
egress: hyper's `strip_connection_headers` runs only at `server.rs:476`/`client.rs:709` (main head,
never trailers); h2's `send_trailers` (`send.rs:312`) is the ONLY send path that skips `check_headers`
(send_headers:139, send_push_promise:116, send_interim:187 all call it). Yet on RECEIVE, load_hpack
rejects connection-headers in trailer blocks. So h2 **emits in a trailer exactly what it rejects on
receive** — an RFC 9113 §8.2.2 "MUST NOT generate" violation on the send side.

Rig: hyper h2 client (bundled h2 0.4.15 == our audited pin) sends a body with a poisoned
`transfer-encoding: chunked` TRAILER → raw h2 0.4.15 server oracle. Control = benign `x-checksum`
trailer. Wire trace (decisive lines in `results-trace-excerpt.txt`):
- `send_trailers -- queuing; frame=Headers {END_HEADERS|END_STREAM}` → `framed_write: send frame=Headers{…END_STREAM}` — **hyper PUT `transfer-encoding` on the wire in a trailer.**
- receiver: `load_hpack; connection level header` → `malformed message` → `stream error PROTOCOL_ERROR` → `send_reset PROTOCOL_ERROR`.
- verdict EXIT=0: control trailer received cleanly; poisoned trailer emitted then RST by the compliant peer.

**Honest impact: Low / conformance-hardening.** Emission is now WIRE-DEMONSTRATED (upgraded from
source-traced). But a **compliant** h2 peer RSTs it → **fails closed**; the smuggle/injection surface
is only against a non-validating or downgrading downstream, and needs attacker-influenced trailer
content (a malicious upstream body forwarded by a proxy, or app misuse). Fix is a trivial symmetric
one-liner: call `check_headers` in `send_trailers` (h2) and/or strip connection headers from trailers
in hyper's `PipeToSendStream` (`mod.rs:233`).

L46 re-applied: the rig's FIRST verdict printed "REFUTED" — an instrumentation artifact (my
accept-then-handle loop wasn't driving the connection during body reads, so the RST surfaced as a
timeout). The frame trace showed the truth; spawning per-request handlers fixed the self-verdict to
match. Verify your own skepticism, not just the finder's claim.

**Status: seam iteration complete. Net new reportable = the TRAILERS §8.2.2 generate-violation (Low,
wire-demonstrated). D still pending packaging/go-ahead. Channel/file decision for trailers = pending
user go-ahead.**

---

## Seam Phase 2b — proxy reachability + h1-egress mirror (2026-07-25)

Built `scratchpad/hyper-trailer-proxy-rig/` to answer "does a MALICIOUS UPSTREAM's poisoned trailer
travel through a real hyper reverse proxy?" — the reachability question the app-supplied egress rig
left open. Two directions, both differential (benign control + poisoned attack):

- **h1-in → h2-out (reachability):** raw h1 backend emits a `transfer-encoding` trailer → hyper
  (h1-client back / h2-server front) → h2 client. Control `x-ok` arrives clean (200); attack →
  `Reset(StreamId(1), PROTOCOL_ERROR, Library)` at the client. **hyper re-emitted the forbidden trailer
  on the h2 wire; author = upstream, not the app.** An h2 upstream can't stage this (hyper's h2 client
  rejects on ingest) — the h1 backend is the ingress that gets it past the receive checks. Reachability
  PROVEN.
- **h1-in → h1-out (mirror #2):** same backend, hyper h1-server front, raw capture client. Emitted
  bytes: trailer section = `x-keep: 1` only, `transfer-encoding` DROPPED. hyper's h1 encoder filters it
  via `is_valid_trailer_field` (encode.rs:264-280: denies TRANSFER_ENCODING/TE/CONTENT_LENGTH/… + a
  `Trailer`-header allow-list). **h1-egress mirror CLOSED.**

Net mapping: hyper's **h1 trailer egress is RFC-7230-strict; its h2 trailer egress (via h2
`send_trailers`) filters nothing** — same crate stack, opposite discipline on the two egress
directions. That asymmetry is the strongest argument for the h2 `send_trailers` fix (brings h2 egress in
line with both h1 egress and the receive path). Residual: `is_valid_trailer_field` omits
CONNECTION/UPGRADE/KEEP_ALIVE (narrow, needs Trailer-declaration, weakly honored) — noted, not chased.

Evidence copied into `h2-trailers-connection-headers-pr/evidence/`. PR body + EXPLAINER updated with the
reachability proof and the 2×2. **PR still pending user go-ahead to file.**
