# actix-http HTTP/1 smuggling — campaign journal

## Stage 1 — differential harness built + run (2026-07-23, the runner)
Harness (`poc/` mirror in scratchpad `actix-harness/`): external bin depending on `actix-http`
@ pin `eee23e2`, drives the REAL public `h1::Codec` (`tokio_util::codec::Decoder`, run inside a
tokio `LocalSet` because `ServiceConfig::default()` spawns a date task) over crafted byte streams;
reports actix's body-framing decision + whether a smuggled request-2 decodes from the remainder.
Controls both hold → oracle trustworthy:
- CONTROL-A (valid 1.1 chunked): actix chunk-decodes body, no smuggle. ✓ no-FP.
- CONTROL-B (double Content-Length): REJECTED (ParseError::Header). ✓ hardening visible.

## Stage 1 result — all 3 seed-anchored candidates REFUTED (actix is hardened)
Source-reading `set_length` alone OVER-PREDICTED; the wrapper `Request::decode` has a second
validation block (decoder.rs:277-296) I initially missed. Dynamic harness + that block refute all:
- **#1 HTTP/1.0 + TE:chunked** → `Err` at decoder.rs:279 ("Transfer-Encoding is not allowed in
  HTTP/1.0 requests"). REFUTED.
- **#2 TE:chunked + Content-Length** → `Err` at decoder.rs:289 ("both Content-Length and
  Transfer-Encoding are set", RFC 9112 §6.1 compliant). REFUTED.
- **#3 TE:identity** → `Err` at decoder.rs:284 ("request Transfer-Encoding must be chunked", via
  `HttpMessage::chunked()`). REFUTED.
Also enforced: HTTP/1.0 POST without Content-Length → `Err` (decoder.rs:297).
**Verdict: actix-http h1 request decoder is hardened against the classic HTTP/1 smuggling vectors.**
Honest negative result (x509-style). Lesson: fetch the FULL decode path, not just the length calc,
before rating a source-level candidate; the harness caught the over-prediction before any claim.

## Residual actix surfaces NOT yet tested (if we return)
chunked.rs internals (chunk-ext/trailer/oversized-size), client/response decoder (resp splitting),
the decoder.rs:297 HTTP/1.0 branch, header-name/obs-fold validation delegated to httparse.

## Stage 2 lead — ntex-http (actix fork) LACKS the hardening block  [NEXT]
`ntex/src/http/h1/decoder.rs` has NONE of actix's 277-296 validation strings. TE still gated to
HTTP_11 (ntex:311) but with NO "TE-on-1.0 → Err" follow-up → 1.0+TE:chunked likely frames as
`PayloadLength::None` (candidate #1 possibly LIVE in ntex). Also order-dependent TE/CL: TE:chunked
sets chunked only if `content_length.is_none()` (ntex:314); CL-after-chunked rejected (ntex:280) →
CL-then-TE vs TE-then-CL asymmetry = fresh desync seed. MUST confirm dynamically (build the same
harness against ntex; check `ntex::http::h1::Codec` public surface). L40 fork-is-the-yield payoff.

## Stage 3 — full 3-pass find (Workflow wf_60378e46-544, 2026-07-23)
9 finders (3 blind ∪ 3 threat-model ∪ 3 CVE-seeded) over ISOLATED upstream source, dedup, then 3
adversarial lenses (correctness/reachability/impact) per candidate. 48 agents, 0 errors. 13 raw →
13 deduped → 3 CONFIRMED / 7 CONTESTED / 3 REFUTED. Disposition = TRIAGE, not truth — both real
candidates still need an independent dynamic PoC.

### Real yield (2 clusters)
1. **CPU busy-loop DoS — dispatcher.rs:1135 — STANDOUT.** Independently found by TWO blind finders
   (blind-2 + blind-3), all correctness/impact votes confirmed, reachability confirmed by one panel
   / contested-on-preconditions by the other. Mechanism: when `read_buf.len() >= MAX_BUFFER_SIZE`
   (131072) AND the pipeline queue is full (`messages.len() >= MAX_PIPELINED_MESSAGES` = 16),
   `read_available` self-wakes via `cx.waker().wake_by_ref()` (1135) but `poll_request` refuses to
   drain (queue full) → 100% CPU spin until the 16 queued service futures resolve. Reachable
   unauth: pipeline ~256KB of tiny requests to an async/slow handler. Severity: honest **medium**
   (needs a handler that stays Pending; self-limited to handler-latency window; repeatable across
   connections to peg all cores). NOT the smuggling class we set out for — a blind-pass bonus.
2. **Chunked size-parser lenient-accept — chunked.rs:54/61 — ON-CLASS.** `read_size` has no
   "hex-digit-seen" invariant: a whitespace-only or digit-less chunk-size line (`" \r\n"`, bare
   `\r\n`, `";ext\r\n"`) resolves with size==0 → treated as the TERMINATING 0-chunk (RFC 7230 wants
   `1*HEXDIG`). Confirmed correctness+reachability (:61); impact CONTESTED = conditional on a
   fronting proxy that draws the body boundary differently (true smuggling primitive only then).
   Severity low but it is exactly the framing-divergence class. Directly testable with the existing
   differential harness.

### Contested tail (known-limitation / conditional — not chasing unless a PoC elevates them)
slow-body Slowloris (no body-read deadline, dispatcher.rs:861); chunk-extension unbounded
(slowloris-class); MAX_PIPELINED_MESSAGES not enforced inside the decode loop (queue amplification);
Connection comma-list `close` treated as keep-alive (conformance, impact refuted); Upgrade+CL
interaction.
### Refuted (3): the `Upgrade: websocket` overrides Content-Length cluster (framing) — refuted.

### Methodology note
Blind pass caught the highest-severity item (CPU DoS, orthogonal to the smuggling hypothesis);
TM/CVE passes caught the on-class chunked divergence — validates running all three lenses. Next:
dynamic PoC for #1 (dispatcher busy-loop repro) and #2 (chunked terminator via the existing harness).

## Stage 4a — finding #2 (chunked terminator) DYNAMICALLY CONFIRMED (2026-07-23, the runner harness)
Extended the differential harness with terminator cases (harness-chunked-divergence.txt). actix's
`ChunkedState::read_size` accepts THREE non-RFC chunk-size lines as the terminating zero-chunk (RFC
7230/9112 require chunk-size = 1*HEXDIG), ending the body early and re-decoding the trailing bytes
as a new pipelined request:
- DIGITLESS  bare `\r\n`      -> body ends, `GET /SMUGGLED_DIGITLESS` decoded from remainder.
- WS         `" \r\n"`        -> after 5B "HELLO", body ends, `GET /SMUGGLED_WS` decoded.
- EXT-ONLY   `;foo\r\n`       -> body ends, `GET /SMUGGLED_EXT` decoded.
Controls hold: CONTROL-A (valid chunk) = body only, no trailing req; CHUNK-CTRL (`0\r\n\r\n`) =
legit pipelined GET (valid terminator, not a smuggle). **Confirmed: lenient-accept parser
differential.** Severity LOW / CONDITIONAL — a smuggle only against a front-end that forwards the
same bytes but rejects/re-frames these size lines (the 2021-0081 posture). Real RFC-conformance gap;
disclosure worth considering but low-SNR — check actix SECURITY.md scope before filing (image-rs
pushback lesson). Root cause: `read_size` has no "hex-digit-seen" invariant (chunked.rs:54-70).

## Stage 4b — finding #1 (dispatcher busy-loop) DYNAMICALLY CONFIRMED (2026-07-23, the runner)
In-tree test appended to actix-http/src/h1/dispatcher_tests.rs (poc-busyloop-test.rs): drives the
REAL h1::Dispatcher via HttpFlow + TestBuffer preloaded with ~420KB of pipelined bodyless GETs and
an always-Pending service; counting Waker measures self-wakes. Result (harness-busyloop-result.txt):
`200 polls, NO new input: self_wakes=200, consumed Δ=0, writes Δ=0` → BUSY-LOOP CONFIRMED. Over 200
polls the dispatcher demanded an immediate re-poll every time while consuming 0 bytes and writing 0
bytes; src_remaining pinned at 157796B (internal read_buf at MAX). A correct dispatcher parks
(self_wakes ~0). **Confirmed: 100% CPU spin while read_buf >= MAX_BUFFER_SIZE AND the pipeline queue
is full (16) AND the in-flight service future is Pending** (dispatcher.rs:1135 unconditional
`cx.waker().wake_by_ref()` + poll_request refusing to drain at :840). Remote, unauthenticated:
pipeline ~256KB of tiny requests to any endpoint whose handler stays Pending (normal for I/O-bound
routes); one such connection pegs a worker core, repeatable across connections. Severity: **medium**
(needs a Pending handler; self-resolves when handlers complete; but trivially sustainable and
unconditional — no proxy required, unlike #2).

## Campaign status
Two dynamically-confirmed findings on current actix-http main (eee23e2):
- #1 dispatcher busy-loop CPU DoS — medium, unconditional remote DoS. STRONGEST.
- #2 chunked lenient terminator — low, conditional smuggling primitive.
Both real. Disclosure pending: check actix SECURITY.md scope first (image-rs low-SNR/DoS lesson),
then decide bundle vs #1-only. Do NOT file without explicit user go (outward-facing).

## Stage 5 — ntex fork comparison (L40 payoff, 2026-07-23, the runner harness)
Built the SAME differential harness against ntex 3.11.0 (pin 9b1e464) via its public
`ntex::http::h1::Codec`. ntex LACKS actix's post-length validation block. Results
(harness-ntex-fork-results.txt) — controls hold (valid chunked ok, double-CL rejected):
- **NTEX-1-GET — LIVE, ntex-specific: `GET / HTTP/1.0` + `Transfer-Encoding: chunked`** → ntex
  assigns `PayloadType::None` (no body) and decodes the trailing bytes as a new pipelined request
  (`GET /SMUGGLED_10TE`). actix REJECTS this exact case (decoder.rs:279 "TE not allowed in
  HTTP/1.0"). This is the pingora-RUSTSEC-2026-0034 pattern (HTTP/1.0 + TE) live in ntex; RFC 9112
  §6.1 says treat a 1.0 message with TE as faulty framing. The 1.0-POST variant is caught by ntex's
  own 1.0-POST-no-CL check, but GET slips through. Severity **medium / conditional** (smuggle needs
  a front-end that honors TE on the 1.0 request or a 1.1->1.0 downgrade; but it's the canonical
  vector a hardening block exists to stop, in a widely-used framework).
- **NTEX-3 — TE:identity accepted** (frames by CL): actix rejects ("must be chunked"), ntex allows.
  Weaker/conditional divergence.
- NTEX-2 (TE+CL): ntex REJECTS (both orders) — refuted, same as actix.
- NTEX-CHUNK digit-less / whitespace terminator: same gap as actix #2 (present in ntex too).

Fork-lag confirmed: ntex diverges from its upstream's (actix's) framing-hardening posture on the
1.0+TE and TE:identity vectors. NTEX-1-GET is the strongest ntex-specific result. Next: decide
disclosure (ntex is a separate project/advisory channel) + optionally check ntex dispatcher for the
busy-loop (#1) too.

## Stage 6 — ntex dispatcher busy-loop check: REFUTED by architecture (2026-07-23)
Checked whether actix's dispatcher.rs:1135 busy-loop (finding #1) has a structural analog in ntex's
h1 dispatcher. It does not — REFUTED at the source level, no PoC needed. ntex's dispatcher
(ntex/src/http/h1/dispatcher.rs) is a genuinely different architecture, not a fork-lagged copy of
actix's: a single-in-flight `State` machine (ReadRequest -> CallPublish/CallControl -> SendPayload
-> ReadRequest) that reads ONE request via `io.poll_recv_decode` (delegated to the external
`ntex-io` crate), waits for its service call to fully resolve, THEN reads the next. There is no
`MAX_PIPELINED_MESSAGES`-style decode-ahead queue and no `wake_by_ref()` self-wake-on-full-buffer
pattern in this file — the exact precondition pair that causes the actix spin (read_buf pinned at
MAX_BUFFER_SIZE AND a queue of up-to-16 pre-decoded messages blocking drainage) cannot arise because
ntex never decodes ahead of the in-flight request. Buffering/backpressure now lives in the separate
`ntex-io` crate, out of scope for this campaign (would be a new target, not a fork-variant check).
Honest negative: not a fork-lag gap, a genuine architectural divergence that happens to close the bug.

## Stage 7 — ntex blind+TM find (resumed after network failure) + dynamic verification (2026-07-23)
Prior run wf_ce99ca19-b37 lost 5/6 finders to a transient network ENOTFOUND after retries
exhausted (survivor: tm-2, its 1 finding was refuted — a misleadingly "clean" empty result).
Resumed via Workflow({scriptPath, resumeFromRunId}): tm-2 replayed from cache, 5 finders re-ran
clean. 27/27 agents, 0 errors. 7 raw findings / 7 deduped / 7 CONFIRMED (0 contested/refuted) by
the workflow's own majority-vote disposition — but disposition is triage, not truth (per standing
discipline); two of the four distinct root causes needed dynamic PoC to actually resolve.

**No fuzzing needed** — for both priority findings the mechanism was precise enough (from source
analysis) to construct a deterministic byte-level PoC directly; fuzzing would add discovery value
we didn't need here, not confirmation value. Harness: ntex/poc-panic-and-consumed.rs, run on the runner
against the real public `ntex::http::h1::Codec`. Full output: ntex/harness-poc-results.txt.

### Panic via non-char-boundary slice (decoder.rs:526) — DYNAMICALLY REFUTED
Workflow majority-voted CONFIRMED (2 confirmed / 1 refuted) on `connection_type()`'s `val[i..pos]`
slicing with no char-boundary check. Built the exact byte construction (`"cXX€"`, 6 bytes, where
byte index 5 sits mid-way through the 3-byte € encoding) and ran it through the REAL Codec — no
panic; the request decoded normally. Root cause: `HeaderValue::to_str()`
(ntex-http/src/value.rs:221-231) explicitly checks `is_visible_ascii(b)` on EVERY byte before
returning `Ok`, so a non-ASCII byte (any byte with the high bit set — required for ANY multi-byte
UTF-8 char) makes `to_str()` return `Err`, and `connection_type()` is never called (the CONNECTION
arm's `else { None }` fires instead). Since every character `to_str()` ever yields is single-byte
ASCII, char-boundary panics are structurally impossible in `connection_type()`. The one dissenting
"impact=refuted" verify vote had already identified this exact gate textually — majority vote count
was wrong, same "vote-count ≠ correctness" lesson as x509/gitoxide. **Verdict: REFUTED, dynamically
confirmed.**

### Inner::consumed never resets (decoder.rs:180/185) — DYNAMICALLY CONFIRMED, decisive
Found independently 3x (blind-2, tm-2, tm-3). PoC: fed 1261 complete, individually-valid
`GET /a HTTP/1.1` requests through the real Codec (each fully buffered so `pending=false`, no error
per call) until the running `consumed` total passed the 64KB `max_buf_size` default. Then sent one
ordinary 30-byte PARTIAL request (headers not yet terminated — the everyday case of a request
split across TCP reads). Result: `TooLarge(65602)` — REJECTED, even though this one request alone
is 2000x under the limit. Root cause confirmed exactly as predicted: `inner.consumed` (decoder.rs:25)
is initialized once per `MessageDecoder` (i.e. once per TCP connection) and incremented on EVERY
`decode()` call (`inner.consumed += len - src.len()`, line 185) but never reset when a message
completes successfully — only the `TooLarge` guard at line 180 reads it, gated on `pending` (a
message left incomplete this call). A long-lived keep-alive/pipelined connection that has processed
enough cumulative header bytes over its lifetime gets a random LEGITIMATE later request killed the
moment it happens to arrive split across two reads. **Verdict: CONFIRMED, decisive dynamic proof.**
Medium severity (self-inflicted DoS of legitimate traffic, availability not integrity/confidentiality,
but trivially reachable — no attacker needed, ordinary sustained traffic triggers it eventually).

### Campaign status update
ntex now has TWO real dynamically-confirmed findings of its own (in addition to the shared chunked-
terminator gap #2 and the NTEX-1-GET 1.0+TE fork-lag desync from Stage 5):
- `Inner::consumed` never resets — medium, ntex-specific, STRONGEST from this stage.
- NTEX-1-GET (1.0+TE desync, Stage 5) — medium, ntex-specific fork-lag.
- Shared chunked terminator gap (Stage 4a) — low, both actix+ntex.
Remaining Stage-7 candidates (5-byte Connection-token truncation, its RFC-conformance variant,
read-rate accounting) not yet dynamically verified — lower priority (low severity / one reachability
already contested by a verify lens).
