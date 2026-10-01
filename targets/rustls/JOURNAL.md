# rustls campaign journal

## Stage 1 — recon + threat model (2026-07-23)
Full write-up in THREAT_MODEL.md. Key takeaways: `SECURITY.md` gives an explicit in-scope threat
list + explicitly invites more fuzzing; `forbid(unsafe_code)` on the whole wire-facing crate rules
out memory-corruption as a class; crate is OSS-Fuzz-registered with 7 targets seeded from real
handshake traces. Two real prior CVEs (2024-0336 infinite loop on close_notify-during-handshake,
now out-of-scope since the API moved to `rustls-util`; 2024-0399 panic on fragmented ClientHello,
fixed and now directly fuzzed) both state-timing bugs, not parse bugs — shaped the TM lens toward
sequence/timing over single-message parsing. One hypothesis (new `NeedsInput`/`Accepted` sans-IO
API lacks fuzz coverage) was formed then DISPROVEN by reading the actual fuzzer source before it
went into the threat model doc — recorded as a ruled-out lead, not a claim.

## Stage 2 — 3-pass find + adversarial verify (Workflow wf_0cfc5b7f-14d, 2026-07-23)
9 finders (3 blind ∪ 3 TM-first ∪ 3 CVE-seeded off webpki's very-recent name-constraint-
completeness + pre-auth-reachable-panic patterns) over an isolated clone pinned at `bd9f7f59aa79`.
21 agents total (9 find + verify), 0 errors, 6 empty results (finders that correctly returned "0
findings" — expected/honest for several lenses given this target's maturity). 4 raw findings, 4
deduped, verify = **3 CONFIRMED (unanimous 3/3 each) / 0 contested / 1 refuted**.

### Stage 3 — MY OWN independent re-verification (not just trusting the 3/3 votes)
Per standing discipline (disposition = triage not truth, vote-count ≠ correctness — x509 2×2, ntex
panic precedent), re-read every load-bearing claim against the pinned source directly, byte-for-byte,
before accepting anything. **All three survived intact — every cited line, every "zero call sites"
claim, every doc-comment quote checked out exactly as the agents reported.**

**Finding A — QUIC suite-compatibility not enforced during negotiation → pre-auth panic.**
`tls13/key_schedule.rs:354,437,586` all do `self.ks.suite.quic.unwrap()` gated only on
`output.quic().is_some()` (is this a QUIC connection) never on whether the *negotiated* suite
actually supports QUIC. `Tls13CipherSuite.quic: Option<...>` is explicitly documented ("Provide
`None` to opt out... it will not be offered in QUIC handshakes") as a real, intended shape for a
mixed-suite provider. The actual enforcement function, `usable_for_protocol`, has exactly ONE call
site crate-wide (`client/hs.rs:738`, filtering the client's own OUTGOING hello) — never called by
server-side suite selection (`choose_suite_and_kx_group`, server/hs.rs:610, verified no
protocol/quic reference in its body) nor by the client's ACCEPTANCE of the server's chosen suite
(client/hs.rs:157-160, checks provider-membership only, error misleadingly named
`SelectedUnofferedCipherSuite` but doesn't check offered-ness). A purpose-built accessor,
`Tls13CipherSuite::quic_suite()` (tls13/mod.rs:83), has **zero call sites anywhere** (confirmed by
grep). The only "compatibility" check anywhere is an existence check at connection-construction
(`quic.rs:94,517`, `.any(|scs| scs.quic.is_some())` — "at least one", never "all/only"). Server-side:
attacker's first QUIC Initial ClientHello offers only the quic-incompatible suite from a mixed
provider → selected regardless of preference policy → panic before any auth step. Client-side
(symmetric, arguably worse — no control over server config needed): malicious/on-path server picks
any suite from the client's own provider in ServerHello, including ones the client didn't offer,
since acceptance doesn't check offered-ness → same unwrap panic. Severity: reachable panic (DoS),
pre-auth on the server side. Class: missing protocol-compatibility validation.

**Finding B — client accepts a TLS1.2 ServerHello on a QUIC connection (asymmetric vs. server).**
`client/hs.rs:209`'s TLS1.2-acceptance branch is gated only by `config.supports_version(TLSv1_2)` —
no `is_quic()` check anywhere in `ExpectServerHello::handle`. Server-side has the exact symmetric
check TWICE (`server/hs.rs:506-507,516-517`, `self.protocol.is_quic() → Err(Tls13RequiredForQuic)`)
— confirming the crate's own authors know this combination must be rejected, just didn't wire the
check into the client's accept-path. `ClientHelloInput.protocol: Protocol` (client/hs.rs:418) is
already present and used two lines away (556, `input.protocol.is_quic()` for `forbids_tls12` on the
OUTGOING hello) — the guard was straightforwardly omittable by oversight, not by missing
information. `quic::ClientConnection::new` only checks tls13 suites are QUIC-capable, never checks
tls12 suites are ABSENT — so any default (ring/aws-lc-rs) provider reaches this. Consequence: client
runs the full TLS1.2 state machine, which unconditionally emits ChangeCipherSpec;
`Quic::send_msg` (quic.rs:636-642) has `debug_assert!(matches!(payload, Handshake{..}|
HandshakeFlight(_)), "QUIC uses TLS for the cryptographic handshake only")` — CCS matches neither
arm → panics in any debug-assertions build (default `cargo build`/`test`). In `--release`
(assertions compiled out) the CCS silently drops and the client believes the handshake completed
with no QUIC 1-RTT keys ever derived — a silent connection-state desync, not just a crash. Attacker
model: an ordinary malicious TLS server the app connects to over QUIC, using its own legitimately-
issued cert (no MITM/forgery needed) — squarely inside rustls's own stated threat model
("malicious peers, pre- or post-authentication"). Class: protocol-downgrade / missing version-
protocol binding (secondary: reachable panic in debug builds).

**Finding C — `NeedsInput::process()` silently discards the first post-handshake ApplicationData
record.** `server/connection.rs:311`'s outer loop matches `Some(Ok(_)) => {}` (discards the payload)
BEFORE its `is_traffic()` check (318-325) can act — that check only stops a *further* `next()` call,
it can't recover what the current call already returned and threw away. `MessageIter::next()`
(conn/receive.rs:64+) has its own inner `while st.wants_input()` loop; `wants_input()`
(server/hs.rs:74) is `!matches!(self, ChooseConfig(_))` — true for every state INCLUDING the
just-transitioned-to Traffic state — so one `next()` call can process the client's Finished
*and* decrypt+dispatch the very next buffered ApplicationData record in the same call, handing it to
`ExpectTraffic::handle` → `received_plaintext()`, whose return is what gets thrown away at line 311.
Reachable by ANY ordinary, non-malicious client that writes its handshake-completing flight and its
first request back-to-back in one `write()`/TCP segment (RFC-legal, encouraged by Nagle coalescing)
— no attacker needed, 100% deterministic once triggered, not probabilistic. **Confirmed the public
rustdoc on `NeedsInput::process()` says nothing about this** (re-read directly: only lists the 3
`ServerHandshake` return variants, no mention of possible data loss) — the only acknowledgment
anywhere is an inline `//` implementation comment ("the above loop drops incoming appdata"), which
is invisible in rendered API docs. This makes it worse, not better, than an already-known/accepted
limitation: the maintainers evidently knew the mechanism (wrote the comment) but never surfaced it
to the public contract callers actually read. Class: message-sequencing logic error / silent data
loss across the handshake-to-traffic boundary in the new (explicitly "Temporary escape hatch during
migration") sans-IO API.

**Refuted (1):** "HelloRetryRequest with an unvalidated TLS1.2 cipher_suite reaches an ECH
unreachable!() panic" (blind pass, src/client/hs.rs) — not independently re-checked by me yet
(lower priority given 2/3 verify lenses refuted it and it wasn't in the survivor set); revisit only
if time permits after A/B/C are through dynamic verification.

### Emergent pattern (bugs travel in packs)
Findings A and B are BOTH instances of the same higher-level gap: **QUIC mode does not
re-validate that negotiated/accepted protocol parameters are actually QUIC-compatible** — A at the
cipher-suite level (post-selection), B at the protocol-version level (post-ServerHello-acceptance).
Worth treating as one theme when reporting, and worth a quick targeted look at OTHER
negotiation-adjacent parameters (key-exchange group, ALPN, — anything else gated only by
"provider contains X" rather than "provider contains X AND X is QUIC-usable") once a QUIC test
harness exists for A/B's dynamic PoCs, since building one is shared infrastructure.

## Stage 4 — dynamic PoC construction: NOT STARTED
Per standing discipline, static verification (however thorough) is triage, not truth. Need an
executed PoC against the real crate at the pin for each of A/B/C before any claim/disclosure
language stronger than "statically confirmed, independently re-verified, pending dynamic proof".

## Stage 4 — dynamic PoC for Findings A + B (2026-07-23)

Built a standalone harness (`poc/quic_poc_a_b.rs` + `poc/Cargo-quic-poc.toml`) depending directly on
`rustls`/`rustls-ring`/`rustls-test` as git deps pinned at `bd9f7f59aa79`. Discovered and reused
existing rustls-test infrastructure rather than hand-rolling TLS wire format from scratch:
`rustls_test::encoding` module (raw `client_hello()`/`server_hello()`/`Extension` builders — exactly
the toolkit needed), `make_server_config`/`make_client_config` (take an explicit `&CryptoProvider`
param, so a custom mixed provider can be passed straight through with real ring-backed crypto and
real bundled test certs), `rustls_ring::DEFAULT_PROVIDER`/`cipher_suite::*` (confirmed: ALL of
ring's own real TLS1.3 suites have `quic: Some(...)` -- stock official providers alone cannot
trigger Finding A; a genuinely mixed provider must be hand-assembled, confirming this is a real gap
in defense-in-depth for *custom* CryptoProvider implementations, not something the two official
providers happen to paper over by accident). Confirmed via grep: no QUIC fuzz target exists at all
(re-confirming the Stage 1 recon), and even the crate's own `rustls-fuzzing-provider` has only ONE
TLS1.3 suite (quic:None) -- a non-mixed provider that would itself fail the "any quic-capable
suite" construction gate, meaning this exact scenario has never been fuzzer-reachable either.

### Finding A -- FULLY DYNAMICALLY CONFIRMED, decisive
Built `CryptoProvider { tls13_cipher_suites: [real TLS13_AES_128_GCM_SHA256 (quic:Some), a
byte-for-byte clone of real TLS13_CHACHA20_POLY1305_SHA256 with only `.quic` forced to `None`],
..DEFAULT_PROVIDER }`. `quic::ServerConnection::new` succeeds (passes the existence-only gate).
Crafted a 178-byte real ClientHello (`encoding::client_hello`) offering ONLY the quic:None suite's
wire ID, with a real kx_group/dummy-key-share/wide-sig-algs/quic-transport-params extension set,
fed via `server.read_hs(&mut SliceInput::new(...))`. Result:
```
thread 'main' panicked at .../rustls/src/tls13/key_schedule.rs:354:36:
called `Option::unwrap()` on a `None` value
```
Exact line, exact mechanism, predicted in advance by static analysis and now fired for real against
the live pinned crate. No caveats -- this is as decisive as the quinn/BMP dynamic PoCs earlier in
the session.

### Finding B -- CORE MECHANISM dynamically confirmed; downstream consequence traced, not re-fired
Built a real `quic::ClientConnection` with `rustls_ring::DEFAULT_PROVIDER` (ordinary mixed
TLS1.2+1.3 provider, "not a contrived setup" exactly as the finding describes) via
`make_client_config`. Crafted a 44-byte legacy TLS1.2 `ServerHello` (`encoding::server_hello`,
`legacy_version=TLSv1_2`, no `supported_versions` extension) and fed it via `client.read_hs(...)`.
Result: **accepted with no error** -- the client took the TLS1.2 branch on a QUIC connection with
zero pushback, dynamically proving the missing `is_quic()` guard is reachable exactly as claimed.
This is the crux of the finding (the guard bypass itself). The further consequence -- driving
Certificate/ServerKeyExchange/ServerHelloDone to reach the actual `debug_assert!` in
`Quic::send_msg` at `emit_ccs` -- was NOT additionally fired dynamically: `rustls-test`'s public API
does not expose raw certificate DER bytes (`KeyType::bytes_for` is crate-private) or any
Certificate/SKE/SHD wire-format builders in `encoding`, so completing this leg would require either
hand-rolling a throwaway X.509 CA+leaf cert or reimplementing TLS1.2 ServerKeyExchange signing from
scratch -- disproportionate additional engineering to confirm a consequence whose exact call chain
(`ExpectServerDone::handle_input -> emit_ccs -> Quic::send_msg`'s `debug_assert!`) was already
independently re-verified against source in Stage 3. Judged not worth the additional cost given the
root-cause guard-bypass is already decisively proven; noting this honestly rather than overstating
PoC B as "fully" confirmed end-to-end.

### Both findings' disclosure-readiness
Finding A: ready to report as a fully dynamically-confirmed pre-auth remote panic (Medium-High --
severity calibration TBD alongside Finding C work). Finding B: ready to report as a confirmed
protocol-downgrade / guard-bypass (the actually-dangerous part -- the client accepting the wrong
protocol/version combination) with the debug_assert/release-mode-silent-desync consequence
described as statically-traced-and-independently-verified, not dynamically re-fired -- this is an
honest, sufficient basis to report, matching how e.g. the Chromium BMP report distinguished
harness/code-path-inspection reproduction from an in-Chrome crash.

## Stage 5 — dynamic PoC for Finding C (2026-07-23)

Built a second standalone harness (`poc/needsinput_poc_c.rs` + `poc/Cargo-needsinput-poc.toml`),
following `rustls-test/tests/api/io.rs`'s own `test_full_server_handshake` pattern (a real classic
`ClientConnection` driving the non-QUIC sans-IO `ServerHandshake`/`NeedsInput`/`Accepted` server
API) rather than hand-rolling wire bytes. Real TLS1.3 handshake (Ed25519, ring-backed).

**Clean A/B, both branches using real encrypted application data, only the batching differs:**
- **CONTROL** (Finished flight and the client's first request fed as two *separate*
  `process()`/`read()` calls): request correctly delivered —
  `split.receive.read()` returns `Available` with the full plaintext
  `"GET /control HTTP/1.1\r\nHost: x\r\n\r\n"`.
- **ATTACK** (identical construction, but Finished + first request concatenated into ONE buffer fed
  to a single `process()` call — the exact "co-batched" scenario the finding describes): server
  still reaches `Complete`, but `split.receive.read()` has **nothing** to deliver — the request
  vanished.

This is the most decisive of the three dynamic PoCs: a genuine, isolated A/B where the only
variable is whether the two records were batched together, run against real cryptography with no
mocking, no caveats, no partial-confirmation hedging needed. **Finding C: FULLY dynamically
confirmed.**

## Summary — all three findings, final disposition

| Finding | Static (independent re-verify) | Dynamic | Status |
|---|---|---|---|
| A — QUIC suite-compat unwrap panic | ✅ | ✅ real panic, exact line | **Fully confirmed** |
| B — TLS1.2 ServerHello accepted on QUIC | ✅ | ✅ core guard-bypass; debug_assert traced not refired | **Confirmed** (honest scope noted) |
| C — NeedsInput silent app-data loss | ✅ | ✅ clean A/B, real crypto, no caveats | **Fully confirmed** |

All PoC artifacts in `targets/rustls/poc/`. Next: severity calibration + disclosure package
preparation (channel: rustls has GHSA private vulnerability reporting — verify — plus its
SECURITY.md explicitly requires "disclose any use of AI assistance upfront", distinct from and in
addition to the standing rust-in-peace credit convention).

## Stage 6 — model-comparison run (Opus, wf_9024729d-0f8, separate isolated clone), 2026-07-23

Same 3-pass methodology, identical lens prompts, model=opus, against a genuinely separate isolated
clone (`rustls-src-isolated-opus/`, same pin) per [[model-comparison-corpus-isolation]].

**Yield: far more conservative than the Sonnet run.** 8/9 finders returned 0 findings (blind ×3, TM
×2, CVE ×3) -- correctly honest given this target's maturity, but a much higher empty-result rate
than Sonnet's run (which returned 0 findings from only ~5-6/9 finders and surfaced A/B/C from the
rest). 1 raw finding total, from tm-1 (the "downgrade sentinel / extension-completeness" TM lens).

**The one Opus candidate is in a COMPLETELY DIFFERENT area than A/B/C** -- no overlap: TLS1.3
client session-ticket handling (`client/tls13.rs:1472`, post-handshake `NewSessionTicket`
processing), not QUIC compatibility (A/B) or the sans-IO NeedsInput API (C). Claim: each received
NewSessionTicket deep-clones the full (bare, non-Arc) `peer_identity: Identity<'static>` (the
server's cert chain, up to `CERTIFICATE_MAX_SIZE_LIMIT`=64KB) via `self.session_input.clone()`
(tls13.rs:1472, confirmed verbatim); the only anti-flood guard (`TrafficTemperCounters`, 32
consecutive handshake messages) is unconditionally reset by ANY application_data record regardless
of size (`received_app_data()`, conn/receive.rs:651-653, confirmed verbatim, explicitly commented as
mirroring BoringSSL's `kMaxKeyUpdates`) -- so a 1-byte app_data record re-arms 32 more tickets,
letting a malicious-but-certificate-authenticated server force repeated ~64KB memcpys for a few
dozen wire-bytes each.

**Verify panel split 1 contested / 1 refuted / 1 contested** (workflow disposition: CONTESTED,
survived since only 1 of 3 votes was outright refuted). I independently re-verified the two
load-bearing code claims myself against source (not the isolated-opus clone -- same pin, so
identical -- used my own clone for consistency): both check out exactly as reported (`peer_identity`
is bare `Identity<'static>`, not `Arc`-wrapped, at `client/mod.rs:211`; the counter reset is
unconditional on payload length, with the explicit BoringSSL-precedent comment, at
`conn/receive.rs:651-657`).

**My own independent judgment (not deferring to either side of the Opus panel):**
- The reachability-refuting vote's blanket "requires authentication, therefore not reachable from
  attacker-controlled bytes alone, default to refuted" framing does **not** match rustls's own
  SECURITY.md, which explicitly lists "malicious peers (whether pre- or post-authentication)" as
  in-scope. That specific refutation rationale is wrong for this project.
- However, the impact-lens's independent reasoning holds regardless of the auth-timing question and
  is why I am **not** elevating this to a 4th disclosable finding: the cost is *linear* in
  attacker-sent bytes (a bounded per-message multiplier), not the superlinear/unbounded blowup
  SECURITY.md's "significant amplification" criterion targets (contrast the *exponential*
  webpki path-building CVE used as CVE-seed material for this very campaign); the realistic
  multiplier is modest (~100-200x for an ordinary chain, ~1000x+ only with an attacker-inflated
  private-CA chain); there is no crash and no persistent memory growth (8-ticket retention cap); and
  critically, the per-ticket cost is *cheaper* than the certificate validation the same
  attacker-controlled server already forced once at handshake time -- so this is unbounded
  repetition of an already-paid-for, already-cheaper operation, not a qualitatively new attack
  surface. The porous reset is also a deliberate, BoringSSL-precedented design choice, not an
  oversight.
- **Verdict: real code behavior, independently confirmed, but does not clear the bar for a
  reportable security defect** -- same category as this session's x509-parser "0
  attacker-reachable" and httparse's disqualified bare-LF candidate. Worth noting as a cheap
  hardening suggestion (wrap `peer_identity` in `Arc` to make the clone O(1)) but NOT being added
  to the disclosure set alongside A/B/C.

**Comparison takeaway:** same methodology, same pin, independently isolated corpora -- Sonnet's run
found 3 real, dynamically-confirmed defects (A/B/C) with a much lower empty-result rate; Opus's run
was substantially more conservative (8/9 empty) and its one surviving candidate, while genuinely
novel and non-overlapping, turned out on independent scrutiny to be a well-reasoned near-miss rather
than a qualifying finding.

---

## Stage 7: severity calibration + disclosure package drafting (2026-07-23)

User confirmed: proceed with severity calibration and disclosure-package prep for A/B/C.

**Channel decision.** Checked `gh api repos/rustls/rustls/private-vulnerability-reporting` ->
`{"enabled":true}`. rustls's SECURITY.md describes GHSA private advisories as the *only* reporting
path and asks reporters to self-filter by threat model before reporting at all -- unlike
actix-web/ntex, it has no public-issue carve-out by severity. Decision: all three findings go
through GHSA private reporting, differentiated by severity *within* each report rather than by
channel choice -- an explained departure from the actix/ntex severity-splits-channel precedent,
justified by this project's own differently-stated policy rather than treated as an unexplained
inconsistency. Filed as three *separate* advisories (not bundled into one), per the standing
one-root-cause-per-report discipline -- cross-referenced as companion findings from the same review
pass in each package's FILING-INSTRUCTIONS.md.

**Severity landed, after tracing exact preconditions/consequences against source (not asserted):**
- **A (QUIC suite panic): Medium**, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` ~5.9. AC:H
  reflects the non-default mixed-`CryptoProvider` precondition -- confirmed neither official
  provider (ring, aws-lc-rs) ships suites this way, so a fully stock deployment is not affected.
- **B (QUIC downgrade): Medium**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` ~6.5. Reachable
  with a *stock* provider (no special config, unlike A) but requires the peer to be a
  malicious/on-path server. Report states explicitly what's dynamically demonstrated (the
  TLS1.2-ServerHello acceptance itself, no error) vs. what's traced-but-not-refired (the
  `debug_assert!` panic further down the flow, plus an honestly-open release-mode consequence that
  depends on the embedding QUIC library) -- did not overclaim a confirmed crash.
- **C (NeedsInput data loss): Low**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` ~5.3 (stated as
  a qualitative floor, not a hard number -- no attacker needed at all for the basic trigger, impact
  bounded to a single hung connection under ordinary idle-timeout handling).

**rustls-specific requirement:** SECURITY.md additionally asks reporters to "disclose any use of AI
assistance upfront" -- distinct from and additional to this project's standing rust-in-peace credit
convention. Each REPORT.md opens with an explicit AI-assistance disclosure paragraph naming
rust-in-peace (https://github.com/scadastrangelove/rust-in-peace) satisfying this, separate from the
Disclosure section's credit line at the bottom. No report names "Claude" anywhere.

**Packages assembled**, each self-contained (no relative-path cross-references inside REPORT.md
itself -- companion-finding cross-references live only in FILING-INSTRUCTIONS.md, which is
maintainer-facing process guidance, not part of the report body):
- `rustls-quic-suite-panic-disclosure/` -- REPORT.md, FILING-INSTRUCTIONS.md, poc/{Cargo.toml,
  Cargo.lock, src/main.rs, harness-results.txt, BUILD-AND-RUN.md} (shares its PoC binary with B --
  both `poc_a_*`/`poc_b_*` functions live in one `main.rs`, copied identically into both packages).
- `rustls-quic-downgrade-disclosure/` -- same structure, same shared PoC binary.
- `rustls-needsinput-dataloss-disclosure/` -- same structure, its own independent PoC binary
  (`needsinput_poc_c.rs` -> `src/main.rs`), CONTROL+ATTACK isolated A/B preserved in full in the
  report body.

All three directories confirmed gitignored (`.gitignore` lines 40-42, `git check-ignore -v` verified
against all three); `git status` shows nothing from any of the three tracked or staged.

**Status: disclosure packages complete, NOT YET FILED.** Filing (GHSA private advisory submission,
an outward-facing irreversible action) requires an explicit separate user go-ahead per this
session's standing practice -- drafting completion is not itself authorization.

---

## Stage 8: auditor re-check + release-diff verification — MATERIAL CORRECTION (2026-07-23)

An Opus-model adversarial re-read of the three disclosure packages raised four points. Treated as
triage, not truth — independently re-verified each against pinned source AND (the step that changed
everything) diffed the dev pin against released **v/0.23.42**. Findings:

**Setup fact:** pin `bd9f7f59aa79` = `rustls 0.24.0-dev.1`; latest published stable = `v/0.23.42`.
So the pin is unreleased — but each finding's release-applicability had to be checked separately.

**Finding C — auditor right: UNRELEASED.** `NeedsInput`/`ServerHandshake`/`SplitConnection`: grep =
0 occurrences in v/0.23.42. The whole sans-IO API is 0.24-dev-only. ⟹ reframed as an unreleased-API
correctness bug (normal dev-branch issue/PR), dropped CWE/CVSS, not a GHSA advisory.

**Finding B — auditor right: panic gated behind cert verification.** Read `ExpectServerDone::
handle_input` (client/tls12.rs): `verify_identity` (cert chain, :750) and `verify_tls12_signature`
(:787) both `?`-return BEFORE `emit_ccs` (:859, the Quic::send_msg debug_assert site). So on-path
reaches only the version-downgrade *acceptance* (low direct impact); the panic needs a TRUSTED
malicious server (valid cert + signed SKX), not a mere on-path attacker. The acceptance branch IS
present in released v/0.23.42 (client/hs.rs:694, unguarded), so B is the one finding that affects
shipped code. ⟹ reframed Low, no CVSS, "acceptance proven / panic trusted-server-gated". Also
accepted the auditor's panic=unwind-vs-abort point (don't self-assign A:H anywhere).

**Finding A — went BEYOND the auditor: it's a 0.24-dev REGRESSION, not a released-code finding.**
The auditor called A a strong released-code report. But: released v/0.23.42
`choose_suite_and_kx_group` (server/hs.rs:~601) filters candidate suites with
`&& suite.usable_for_protocol(protocol)` — so 0.23.x never selects a quic:None suite on a QUIC
connection and the panic is NOT reachable there. The 0.24-dev refactor (new `cipher_suite_selector`
abstraction) DROPPED that filter: dev `choose_suite_and_kx_group` (server/hs.rs:682-688) reduces by
signature-scheme and kx-algorithm only, never references `protocol`. Confirmed by call-site census:
`usable_for_protocol` at 0.23.42 = {client/hs.rs, server/hs.rs:601, suites.rs-dispatch}; at dev =
{client/hs.rs, suites.rs-dispatch} — the server selection call site is gone. My PoC panic firing at
the dev pin proves dev-reachability; the 0.23.42 source proves the guard existed. ⟹ A is a valuable
PRE-RELEASE regression catch (restore the filter before 0.24 ships), reframed as a dev-branch
PR/issue, no CVSS.

**Packaging (auditor right):** split the shared A+B PoC into independent single-finding binaries
(rustls-quic-poc → A-only; new rustls-downgrade-poc → B-only; rustls-needsinput-poc → C, refactored
to return verdicts). Added outcome-reflecting exit codes to all three (0 = reproduced as described,
non-zero = not reproduced / fixed) so `cargo run` doubles as a regression check — replacing the old
unconditional `TEST-EXIT=0`. All three rebuilt and re-ran green locally (A exit 0 on caught panic;
B exit 0 on acceptance; C exit 0 on control-delivers + attack-drops).

**Net corrected picture:** NOT "3 Medium GHSA advisories." It is **1 Low released-code protocol item
(B, via GHSA) + 2 unreleased-code items (A = 0.24-dev regression; C = unreleased-API bug), both as
normal dev-branch PR/issue.** All 3 REPORT.md + FILING-INSTRUCTIONS.md rewritten accordingly; PoC
artifacts refreshed. Still NOT filed — awaiting explicit user go-ahead.

**Methodological lesson (for LESSONS.md):** verifying a finding "against pinned source" is not
enough when the pin is a dev/unreleased commit — must also diff against the latest RELEASED tag to
know whether the defect is shipped, dev-only-new, or a dev-only regression of an existing guard. The
release-diff reclassified all three (C unreleased, A a regression, only B shipped) and flipped the
whole disclosure strategy. An external auditor got the direction right on B and C but missed A's
regression status — reinforces that even a good adversarial review is triage to be independently
checked, in both directions (they can under- as well as over-state).

---

## Stage 9: pre-file adversarial review round + rustls AI-policy compliance (2026-07-23)

User asked for one more pre-release analysis of the submissions + to re-verify rustls's LLM-disclosure
ask. Ran 3 independent adversarial reviewers (general-purpose agents, one per finding), each
forbidden from reading any notes and required to re-derive claims against BOTH the dev pin and the
released v/0.23.42 tarball, and to try to refute / worsen each report.

**Finding A — BLOCKER, independently confirmed and extended.** Reviewer: my "reachable only in
0.24-dev / not a vulnerability in any shipped release" claim is contradicted by a CLIENT-acceptance
path that reaches the same `.quic.unwrap()` in shipped 0.23.42. I verified the crux myself: 0.23.42
`client/hs.rs:770-777` accepts the server's suite via `find_cipher_suite`, which (`client_conn.rs:446`)
searches the WHOLE provider, not the offered list — `SelectedUnofferedCipherSuite` fires only on a
provider miss; only a version check follows, no QUIC re-check. So a malicious server can pick a
quic:None suite the client has-but-didn't-offer → key derivation → unwrap (`key_schedule.rs:253`).
**I then BUILT a client-side PoC and it fired the panic at key_schedule.rs:354 on the first attempt.**
Merged both paths into the A package's single binary (PATH 1 server regression + PATH 2 client
shipped-code gap; exit 0 iff both panic). A now correctly: ONE defect, TWO paths — client path in
shipped 0.23.x + dev (PoC-fired at dev, source-identical in 0.23.42), server path a 0.24-dev
regression. Channel moved to GHSA (affects shipped code). Root lesson: during Stage 8 I over-hedged A
into "dev-only" and dropped the client-side gap I had actually flagged in my very first analysis —
the review resurfaced it. Verify corrections in BOTH directions, not just the one that de-escalates.

**Finding B — no blocker, Low stands.** Reviewer independently confirmed in both trees that the panic
is not on-path reachable (cert-verify + sig-verify precede emit_ccs; 0.23.42 verify_server_cert ~873
/ verify_tls12_signature ~910 / emit_ccs 989), and found a SECOND emit_ccs on the resumption path
(ExpectFinished, 0.23.42 tls12.rs:1266) gated on Finished-verification — also trusted-server-equivalent,
so severity unchanged. Applied: quote the REAL PoC output (report had paraphrased "ACCEPTED" vs actual
">>> BUG PRESENT"); add the resumption emission site; label dev-pin vs released line numbers/method
names (0.23.42 ExpectServerDone::handle not handle_input; CommonState::send_msg not Quic::send_msg);
note the PoC binds the dev pin; fix supports_version description (also checks config.versions).

**Finding C — no blocker, confirmed decisively.** Reviewer traced the full data path and confirmed the
decrypted payload is dropped and not retrievable anywhere (not in ChunkVecBuffer, not in outputs;
input bytes discarded at connection.rs:328). Applied: mechanism precision (the `while wants_input()`
loop is INSIDE MessageIter::next() at receive.rs:74 — one next() call over-consumes; process()'s
is_traffic() break fires one record too late; quoted rustls's own inline comment "the above loop
drops incoming appdata"); retracted the unviable "change wants_input()" fix option (shared with
ReceiveTraffic::read()); fixed the "Temporary escape hatch" attribution (it's on
into_buffered_connection, not the API).

**rustls AI policy (user was right, plus more).** TWO asks: SECURITY.md "Make sure to disclose any use
of AI assistance upfront" (already satisfied atop each REPORT), and CONTRIBUTING.md's full `## AI
policy`: comments to maintainers must be HUMAN-WRITTEN (AI-looking ones "may be hidden without
notice"); describe issues/PRs "in your own words"; don't paste AI replies to maintainer questions;
AI-interaction context only in disclosed `>` quote blocks, no long snippets; AI *coding* welcome. ⟹
the REPORT.md files must NOT be pasted verbatim as issue/PR/advisory bodies. Added an "AI-policy
compliance" section + a plain-facts skeleton (raw facts for the human to phrase themselves) to all 3
FILING-INSTRUCTIONS. This bites hardest on C (public issue/PR); A/B via GHSA are governed by
SECURITY.md but should still be human-owned.

**Corrected routing after this round:** A (GHSA; 2 paths, shipped client + dev server; no CVSS;
mixed-provider precondition) + B (GHSA; Low; shipped) + C (public issue/PR; unreleased; no CWE/CVSS).
All 3 PoCs rebuilt green with outcome-reflecting exit codes; A binary now reproduces both paths.
Packages still gitignored, nothing tracked, no "Claude" anywhere, rust-in-peace + AI disclosure in
all three. Still NOT filed — the human must write the submission bodies in their own words per the AI
policy, and give an explicit go-ahead.

---

## Stage 10: A and B FILED as private GHSA advisories (2026-07-23)

User gave go-ahead to publish A and B (C on hold). Corrected my own over-application of the
CONTRIBUTING human-authored rule to the GHSA channel — GHSA is governed by SECURITY.md, which only
requires disclosing AI use upfront (satisfied atop each REPORT); CONTRIBUTING's human-authored rule
is for public issues/PRs (so it binds C, not the GHSA advisories). Fixed the A/B FILING-INSTRUCTIONS
AI-policy sections to match.

**Filing attempt via gh:** `gh api POST /repos/rustls/rustls/security-advisories/reports` returned
HTTP 500 on every variant (full payload w/ severity+cwe_ids, minimal summary+description, report-only
9.8KB, `-f` flag form). Verified nothing was created (no notification, advisory list length 0, 500
doesn't persist). General API healthy (/user ok, rate-limit fine); JSON valid; ~10KB. The SAME
endpoint + token had worked for quinn-proto (GHSA-hmxj) and gitoxide (GHSA-pmm9) days earlier → the
500 was rustls-repo-specific or a transient endpoint blip, not token scope. Stopped hammering,
reported the blocker honestly with options.

**User filed both via the web "Report a vulnerability" form.** Confirmed post-filing via
`gh api .../security-advisories/GHSA-…` (reporter read access works):
- **A = GHSA-j99h-2h74-pcqx** — state `triage`, severity `low`, created 2026-07-23T20:22:55Z.
- **B = GHSA-4xwv-fw6q-5gvr** — state `triage`, severity `low`, created 2026-07-23T20:16:43Z.

Both advisory bodies = the reviewed REPORT.md + inline self-contained PoC, AI-disclosed. Recorded in
DISCLOSURES.md (scorecard "private advisory awaiting first response" 4→6; new rustls section).

**Status:** A + B awaiting rustls-team triage. C on hold (unreleased → normal issue/PR later). Next:
offer fix PRs (A: unwraps→errors + restore server filter + client-side check; B: accept-path is_quic
guard) once maintainers respond; any public issue/PR or maintainer-thread replies authored by the
human per CONTRIBUTING AI policy.
