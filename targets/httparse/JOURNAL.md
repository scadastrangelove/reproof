# httparse 1.10.1 — full-pipeline run (2026-07-19)

Target: `httparse` 1.10.1 — the HTTP/1.x header parser under hyper (602M downloads), `profile: rust`.
Maximally adversarial surface: unauth network bytes parsed pre-auth, with hand-written **unsafe SIMD**
(avx2/sse42/neon/swar) + an **unsafe byte cursor** (iter.rs). Two crown-jewel classes: **T1 unsafe-SIMD/
cursor OOB** (network-reachable memory corruption under hyper) and **T2 request-smuggling differential**
(lenient acceptance vs a front proxy / RFC 9112). Heavily oss-fuzzed → shallow memory bugs unlikely;
realistic = subtle SIMD tail edge, reachable panic, or an acceptance differential (which fuzzing misses).

## Stages
0. **Threat model FIRST** — `THREAT_MODEL.md` (9 sections) + `capabilities.json` (network_protocol_parser
   + untrusted_deserialization + unsafe_simd → run_crash_track=true, vote_budget=8, asan+miri). Priorities
   T1 (SIMD/cursor OOB) + T2 (smuggling).
1. **Setup** — crate wrapper (riptarget: Request+Response::parse over argv file; fuzz target `parse`).
   Image FROM lopdf-fuzz. Both riptarget profiles built (shipping/detect) for P0.1. API compiled first try.
2. **Find (union-of-5 Workflow, wf_1de5eee3-2a6)** — lenses: simd-oob / cursor-oob / panic-dos /
   smuggling-differential / header-boundary, seeded from the threat model → 3-skeptic verify (memory
   guard OR genuine accept-vs-spec divergence). [in flight]
3. **Fuzz (1h, shipping + ASan, fork=4)** — Request+Response::parse, 22 HTTP seeds (real req/resp +
   SIMD-boundary value lengths 15..128 + many headers + chunked + edge whitespace). Start 21:11 UTC →
   finish ~22:12 UTC. [in flight → collect]

[results pending — 2×2 consolidation to follow]

## Find result + triage (2026-07-19) — T2 differential is INTENTIONAL, not a bug

**Static find (union-of-5, 59 agents):** 22 raw → 18 candidates → **all in one class: bare-LF acceptance**
(httparse treats a lone `\n` as a line terminator on the request line, header end, and header value end).
1 confirmed (value-split: `Foo: bar\nContent-Length: 27` → 3 headers incl. CL as its own) + 5 contested,
all the same bare-LF family (+ one obs-fold, off-by-default).

**Re-verified against the maintainer's own code/tests/docs (did NOT trust the finders) — DISQUALIFIED:**
- `test_request_newlines` (lib.rs:1578) asserts `b"GET / HTTP/1.1\nHost: foo.bar\n\n"` (all bare-LF)
  parses successfully — a **passing test**, i.e. intended behavior.
- The `parse_headers` **doc example** (lib.rs:953) uses bare LF (`b"Host: foo.bar\nAccept: */*\n\n..."`)
  with the exact expected output — **documented public behavior**.
- **No strict-CRLF config flag** exists (ParserConfig has spaces/obs-fold flags, nothing for bare-LF) →
  unconditional by design. RFC 9112 §2.2 **permits** bare-LF (recipient MAY). hyper (the consumer)
  re-serializes with CRLF + enforces CL/TE consistency above httparse.
- The obs-fold finding is gated on `allow_obsolete_multiline_headers_in_responses` (off by default) and
  documented "use at your own risk."

**Disposition: NOT a vulnerability, NOT reportable** — httparse's intentional/documented/tested,
RFC-permitted lenient tokenization. Reporting it would tell the hyper team their own design decision
(the object-#2 lesson: verify against the maintainer's tests/docs before reporting). **0 reportable
static findings.**

---

## Second pass — cross-crate CVE variant analysis + blind A/B (2026-07-19)

Revisited httparse with the post-quick-xml discipline: seed variant-analysis from **historical CVEs of
the target's heaviest consumer** (httparse itself has zero RUSTSEC/CVE history), run alongside a **blind**
(no threat model, no CVE seeding) pass on the same target — the L21 A/B pattern, applied here as a third
track on top of the original TM-first campaign above. Ground truth pre-work in
`targets/httparse/CVE-VARIANT-GROUNDTRUTH.md`. Model: session default (Sonnet 5, per explicit user request
to run this pass on Sonnet). Engine: `scratchpad/variant_engine.mjs` (CVE-seeded, workflow `wshg3i3be`) +
`scratchpad/httparse_blind.mjs` (blind, workflow `w854z9kr7`).

### Seeds (hyper's RUSTSEC history — 7 read, 5 kept relevant)
httparse parses only the request-line + header list (no body/chunked decoding, no CL/TE semantic
interpretation) — RUSTSEC-2016-0002 (TLS) and RUSTSEC-2017-0002 (header-serialization injection) ruled
out immediately as out-of-scope. Kept: RUSTSEC-2021-0020 (CVE-2021-21299, multiple-TE-headers smuggling —
class = "header-parsing leniency creates a framing differential"), RUSTSEC-2022-0022 (unsound
`mem::uninitialized()` on `httparse::Header` — API-misuse-shape seed), RUSTSEC-2020-0008 (GET-with-body
smuggling — body-framing-decision seed, ruled out on inspection: httparse never decides this), RUSTSEC-
2021-0078 (lenient Content-Length value parsing — value-opacity seed), RUSTSEC-2021-0079 (chunk-size
integer overflow — direct hit: httparse exposes its own `pub fn parse_chunk_size`).

### Pre-verified by hand before launching lenses (do not re-derive)
- `allow_spaces_after_header_name` (the RFC 7230 §3.2.4 space-before-colon smuggling knob): **hardcoded
  `false` for REQUEST parsing** (lib.rs:507, no config knob exists request-side at all); only configurable
  response-side via `allow_spaces_after_header_name_in_responses`, default `false`
  (`ParserConfig` derives `Default`). **Correctly and intentionally scoped already** — confirmed negative.
- `parse_chunk_size` (lib.rs:1259, the direct RUSTSEC-2021-0079 analog): caps at `count > 15` hex digits →
  bounds to 60 bits, safely inside `u64`. Already hardened.
- `EMPTY_HEADER` (lib.rs:758): the safe, documented construction pattern already exists — the historic
  CVE-2022-0022 was pure hyper-side misuse of an API httparse already made safe.

### CVE-seeded run (`wshg3i3be`) — 4 lenses (H1 ParserConfig full coverage, H2 header-value injection,
H3 API-misuse shapes, H4 compound leniency), clean run (16/16 agents, 0 errors) → **4 confirmed candidates,
0 contested, 0 refuted**, collapsing into 2 distinct root causes.

### Blind run (`w854z9kr7`) — 5 identical generic finders, clean (50/50 agents) → 15 raw → 2 confirmed
(one a re-discovery of the same area as the CVE run's finding, one a fuzz-coverage meta-observation),
6 contested, 7 refuted.

### Empirical verification (Tamm, direct `httparse` calls — did NOT trust either panel's self-reported
"I compiled and verified this" claims; reproduced independently, P1)

**Bug #1 — silent header-section truncation on a whitespace-only first line — SURVIVES, real, novel.**
`ParserConfig::allow_space_before_first_header_name(true)` + a line consisting only of whitespace
immediately after the request/status-line → the entire header block is silently discarded:

```
req  = b"GET / HTTP/1.1\r\n \r\nHost: example.com\r\n\r\n"
flag ON  -> Ok(Complete(19)), headers=[], unconsumed tail = "Host: example.com\r\n\r\n"
flag OFF -> Err(HeaderName)                      (control: confirms this is leniency-branch-specific)
flag ON, documented non-degenerate shape (" Host: example.com\r\n\r\n") -> Ok(Complete(38)), headers=["Host"]
response variant (Content-Length) reproduces identically -> Ok(Complete(20)), headers=[]
```
Root cause: `allow_space_before_first_header_name` is the **only one of ParserConfig's 7 leniency flags
with no `_in_requests`/`_in_responses` split** — its doc comment and sole test (lib.rs:2700-2719) exclusively
describe/exercise **response** parsing (a curl-issue-11605 browser-compat workaround), yet the single
shared field is wired identically into both `Request::parse` (line 509) and `Response::parse` (line 713),
and neither the doc nor the test ever exercises the whitespace-only degenerate case (only "space + real
header"). **Checked against docs/tests (L15) — genuinely undocumented, untested edge case. Survives.**
Real-world exposure check: `gh search code` across GitHub found **zero** uses of this flag outside
httparse's own source/docs (hyper does not enable it) — not a default-vulnerable-out-of-the-box issue,
but a real footgun for any consumer who follows the crate's own doc example and hits the edge case.

**Bug #2 — raw CRLF left inside a folded header value — DOES NOT SURVIVE, documented/intended, do not
report.** Initially PoC-confirmed (`ParserConfig::allow_obsolete_multiline_headers_in_responses(true)` +
a folded continuation → `Header.value == b"real\r\n Evil-Header: injected"`, containing a raw CR+LF that
byte-for-byte resembles an injected header) — but checking the doc comment (lib.rs:279-282) **after** the
PoC (not before, a real lapse — see below) found the crate's own documented example asserts exactly this:
`response.headers[0].value == b"hello\r\n there"` is the *intended, tested, documented* contract, with an
explicit warning: "the newlines (\r and \n) should be replaced by spaces before handing the header value
to the user" (i.e., caller responsibility — the same shape as the bare-LF disqualification above). The
blind run's own verify panel caught this nuance better than my first pass did, rating the equivalent
candidate only 1-vote CONTESTED (citing the same doc line) rather than confirmed.

### Process lesson (own discipline lapse, worth recording)
I PoC'd Bug #2 (mechanism verified empirically) and initially called it "confirmed, a second distinct
finding" **before** checking whether it was already documented/tested/intended (the L15 step) — i.e. I ran
half the checklist (reproduce) and skipped the other half (check docs/tests for the maintainer's own
stated contract) on my own manual verification, exactly the shortcut L15 exists to prevent. The blind
run's independent verify panel did the doc-check and correctly downgraded the same finding to contested.
Caught and corrected before any disclosure prep — logged here so it doesn't recur: **"I reproduced it" is
necessary but not sufficient; the docs/tests check is not optional just because a human is doing the
verifying instead of an agent.**

### Net result
- **1 disclosable finding**: Bug #1 (silent header-section truncation), httparse's first-ever
  RUSTSEC/CVE-class lead. Fix shape: either (a) check the byte after the stripped leading whitespace is
  not CR/LF before `continue`ing, erroring otherwise, or (b) split the flag into
  `_in_requests`/`_in_responses` matching its 6 siblings and document the degenerate case either way.
- **A/B methodology payoff (extends L21)**: on an already-heavily-scrutinized, previously-clean target,
  CVE-seeding surfaced a genuine novel bug via specific, targeted lenses; the blind pass surfaced nothing
  new (its "finds" were a re-discovery of documented-safe behavior + a legitimate but non-vulnerability
  fuzz-coverage observation). This is the flip side of the quick-xml A/B result: sometimes blind adds
  nothing beyond what focused CVE-seeded lenses already cover — the value of running both is finding out
  which is true for a given target, not assuming it in advance.
- Disclosure prep pending (issue + PR for Bug #1; Bug #2 dropped, not reported).
