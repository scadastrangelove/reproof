# rustls — threat model

**Target:** `rustls` core crate (workspace `rustls/rustls`), the sans-IO TLS protocol implementation.
**Pin:** `main` @ `bd9f7f59aa79` (2026-07-23), current HEAD at campaign start.
**Why this target:** TLS termination is the single primary trust boundary for HTTPS traffic across
most of the Rust ecosystem. Logical extension "up the stack" from the earlier x509-parser campaign
(cert *parsing*) into the layer that actually drives the protocol *and* consumes parsing/validation
results (record layer, handshake state machine, message sequencing).

**Scope note:** the campaign targets `rustls` core specifically, not `rustls-webpki` (default cert
verifier) or the crypto providers (`rustls-ring`/`rustls-aws-lc-rs`) — those are separate repos/
crates, explicitly in-scope per rustls's own `SECURITY.md`, but a full campaign there would largely
re-run the already-completed x509-parser campaign's territory (both are X.509/cert-validation
focused). webpki's very recent RUSTSEC history (below) is used only as CVE-seed *pattern* material
for the TM/CVE lenses against rustls core's own validation logic, not as a target in itself.

## Prior due diligence — do not re-derive, already checked

- **`SECURITY.md` read in full.** Explicit in-scope classes on the network-input boundary:
  integer over/underflow in length fields, buffer over-read during fragment reassembly, infinite
  loops, reachable loops with attacker-controlled complexity/amplification, reachable panics, auth
  bypass, protocol downgrade, memory exhaustion with amplification. Explicitly OUT of scope:
  examples/bench/test code, the **`rustls-util` crate**, the website. Public-API boundary explicitly
  excludes "caller deliberately configures something insecure" (e.g. accept-all cert verifier).
  **Disclosure requirement: "Make sure to disclose any use of AI assistance upfront"** — distinct
  from and in addition to this session's standing rust-in-peace credit convention; must be satisfied
  explicitly, not just implied via a tool-name link, in any eventual report.
- **`forbid(unsafe_code)`** on the entire wire-facing crate (confirmed in SECURITY.md, this is the
  crate's own stated mitigation). Memory-corruption-class findings are structurally excluded — do
  not spend lens budget hunting for them. The realistic yield here is panics / logic / state-machine
  / resource-exhaustion / (if very lucky) auth-bypass or downgrade.
- **Already fuzzed, maturely.** OSS-Fuzz-registered, own `fuzz/` dir with **7 targets** (client,
  deframer, fragment, message, persist, server, server_name), corpus seeded with **real handshake
  traces** (`corpus/unbuffered/tls12-client.bin`, `tls13-server.bin`, etc. — not just synthetic),
  and a dedicated `rustls-fuzzing-provider` crate providing mock crypto specifically so pre-*and*
  post-auth code paths are fuzzer-reachable (i.e. they've already solved the "crypto blocks fuzzer
  reachability" problem). **`SECURITY.md` itself invites more fuzzing** ("would benefit from more
  runtime, targets and corpora") — this is a standing, explicit invitation, relevant to any
  controlled-fuzz decision below.
- **Checked, ruled OUT:** `complete_io`/`Stream`/`StreamOwned` (the API in RUSTSEC-2024-0336) has
  been **relocated to the `rustls-util` crate** since that CVE — confirmed by grep, not just by
  reading the policy doc. `rustls-util` is explicitly out-of-scope per SECURITY.md. Do not re-chase
  this API.
- **Checked, ruled OUT:** hypothesized that the new `ServerHandshake::start()` → `NeedsInput::
  process()` → `Accepted` sans-IO API (the modern shape of server-side ClientHello acceptance —
  functionally the successor to the old `Acceptor::accept()` that had RUSTSEC-2024-0399, a
  fragmented-ClientHello panic) might lack fuzz coverage, since `fuzz/fuzzers/server.rs`'s obvious
  path (`ServerConnection::new`) doesn't touch it. **Wrong — verified by reading the actual fuzzer
  source**: `fuzz_handshake_api` in `fuzzers/server.rs` explicitly drives exactly this path
  (`ServerHandshake::start()` → `.process()` loop → `Accepted::choose_config()`), byte-at-a-time via
  `io::Cursor`, which naturally exercises fragmentation. **Do not claim this as a fuzz gap** without
  re-verifying against the current fuzzer source at whatever pin is live at the time.

## Known-fixed CVE patterns (seed material, both fixed — looking for siblings, not reruns)

1. **RUSTSEC-2024-0336 / CVE-2024-32650**: `complete_io` infinite loop if a `close_notify` alert is
   received *during* handshake. Pattern: a specific message arriving at an unexpected *state*
   (mid-handshake) breaks a caller-facing loop that assumed forward progress. **Now out of scope**
   (moved to `rustls-util`) — but the *pattern* (state-timing bug in a loop/driving API) generalizes:
   are there other loops *inside core* (not just the old wrapper) with a similar unbounded-retry-on-
   certain-input shape?
2. **RUSTSEC-2024-0399 / CVE-2024-11738**: reachable panic in the ClientHello-acceptance path when
   the ClientHello arrives *fragmented* across records. Fixed; the fixed code is now fuzzed directly
   (see above). Pattern: fragmentation/reassembly interacting badly with a *specific narrow, early*
   API surface, not the general/well-trodden path. Are there *other* narrow/early/special-cased entry
   points (QUIC's `quic.rs`, 0-RTT/early-data accept path, HelloRetryRequest handling, the ECH
   (Encrypted Client Hello) code in `client/ech.rs`) with similarly less-trodden fragmentation
   handling?

## webpki pattern material (different repo, used only as generalizable pattern seed)

Very recent (April 2026), same external reporter, both in webpki's **name-constraint evaluation**:
RUSTSEC-2026-0098 (URI name constraints silently ignored — constraint type present but never
checked against), RUSTSEC-2026-0099 (DNS wildcard name vs subtree constraint granularity mismatch —
constraint checked, but against the wrong granularity of the asserted name). General pattern:
**"is every declared constraint/check-flag actually enforced, at the correct granularity, for every
relevant enum variant/branch?"** — worth asking of rustls core's own validation logic: version
negotiation, the TLS 1.3 downgrade sentinel, extension-presence/absence enforcement per RFC (e.g.
is *every* extension that must not appear in a given message/version actually rejected, not just
the commonly-tested ones?), cipher-suite/group negotiation completeness. Also RUSTSEC-2026-0104:
reachable panic in CRL parsing *before* signature verification (pre-auth, on a syntactically-valid-
but-unusual DER encoding, an empty `BIT STRING`) — pattern: "unusual but spec-valid encoding of a
rarely-exercised field, reachable pre-auth." Ask the same of rustls core's own message/extension
codec for rarely-exercised fields.

## Lens guidance

- **Blind**: broad, independent sweep. No hypothesis. Cover state machines (`client/hs.rs`,
  `client/tls12.rs`, `client/tls13.rs`, `server/hs.rs`, `server/tls12.rs`, `server/tls13.rs`),
  record/message layer (`msgs/deframer/`, `msgs/fragmenter.rs`, `msgs/handshake.rs`, `msgs/codec.rs`),
  `tls13/key_schedule.rs`, `ticketer.rs` (session resumption), `common_state.rs`, `conn/` (kernel,
  receive, send, split). "0 novel findings" is a fully valid, expected, honest outcome given this
  target's maturity — do not manufacture a finding to satisfy the pass.
- **Threat-model-first**: specifically hunt the *state-timing/sequence* class (per the two real CVE
  patterns above) rather than single-message parse bugs (already heavily fuzzed with real-handshake-
  seeded corpora). Concretely: out-of-order or repeated messages (a second ClientHello, a
  HelloRetryRequest loop, KeyUpdate at an unexpected point, NewSessionTicket before/after unexpected
  states, CertificateRequest/post-handshake-auth timing, 0-RTT/early-data accept-then-reject
  interactions, alerts arriving at unusual points across TLS1.2 *and* TLS1.3 code paths
  specifically since they're separate state machines that could diverge). Also: the downgrade
  sentinel and version-negotiation completeness (per the webpki-pattern note above).
- **CVE-seeded**: variant-analysis off the *patterns* above (not literal bug reruns) — explicitly
  told that "0 novel" is valid; do not force a match.

## Oracle

No new oracle needed — standard grade/patch_grade crash-signal pipeline applies (panic = the
in-scope signal per SECURITY.md, given `forbid(unsafe_code)` excludes memory-corruption). A found
candidate needs an independent dynamic PoC (a hand-built harness reproducing the exact message
sequence against the real crate at the pin) before any claim, per standing session discipline —
static "looks reachable" is triage, not truth.

## Controlled-fuzz decision (deferred to post-find)

`SECURITY.md` explicitly invites more fuzzing ("would benefit from more runtime, targets and
corpora"), which pre-authorizes this in spirit if warranted. Decide AFTER the 3-pass find + verify:
if a candidate needs dynamic confirmation better served by fuzzing a narrowed target (vs. a
hand-built single-sequence PoC), or if the find surfaces a genuinely under-covered surface (unlike
the `Acceptor` false lead above — verify any "gap" claim against the live fuzzer source before
acting on it), build a targeted, memory-capped fuzz harness rather than a generic broad campaign
against an already-maturely-fuzzed target.
