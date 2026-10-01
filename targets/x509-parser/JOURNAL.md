# x509-parser campaign journal (WORKING DRAFT — formalize into README later)

Target: [`rusticata/x509-parser`](https://github.com/rusticata/x509-parser), default
features (`verify` OFF → pure Rust, no ring/aws-lc). 46 rs files, edition 2018,
1 `unsafe`. Realistic surface = **panic-DoS + logic** reachable from the public parse
API (`parse_x509_certificate` / `_crl` / `_pem`), *not* memory corruption. Stance:
**responsible disclosure** — nothing published until confirmed and offered to upstream first.

Experiment shape: **2×2 = {Track A autonomous pipeline, Track B curated} × {Opus 4.8, Sonnet 5}**.

## Timeline (2026-07-17)

- Built `vuln-pipeline-x509-parser:latest` (nightly + ASan build-std + miri + cargo-fuzz),
  `capabilities.json` = untrusted_deserialization + network_protocol_parser (→ vote budget N=3),
  driver `riptarget.rs` over `parse_x509_certificate`.
- **Both credit pools hit their ceiling simultaneously**: Tamm OAuth `out of usage credits,
  resets 15:20 UTC`; workflow session `session limit, resets 13:30 MSK`.
  → did not hammer blocked pools; pivoted to the highest-value quota-free work: **curated
  dynamic verification** of the one complete cell.

## Track B / Opus 4.8 — COMPLETE (+ my dynamic verification)

- 8 focus-area finders (recall-first) → **21 raw → 19 unique**; then per-candidate triage.
- Opus self-triage: **16 false_positive / 1 real / 1 real_latent / 1 contested**.
- Headline candidate: **empty RSA modulus/exponent → `[0]` index panic** in
  `validate/structure.rs:169,172` (`X509PublicKeyValidator`). Self-evidencing hook: the
  crate's own `public_key.rs::key_size()` (l.62) and `try_exponent()` (l.52) **guard
  `is_empty()`** before `[0]`; the validator does not.

### My curated dynamic verification (in-image `cargo`, NO API quota)

Built a PoC against the *real* crate inside the prebuilt image (registry cached offline,
so no network / no token needed). Three shapes:

| DER shape | result |
|---|---|
| `30 04 02 00 02 00` — `SEQ{ INTEGER(len0), INTEGER(len0) }` (Opus's assumed trigger) | **REJECTED** `Error(InvalidSPKI)` |
| `30 06 02 01 00 02 01 00` — canonical zero INTEGERs | ACCEPTED, `modulus.len()=1` (never empty) |
| `RSAPublicKey{ modulus:&[], .. }` built via **pub fields**, then `modulus[0]` indexed *by my own code* | panics (`index out of bounds: len 0 index 0`) — but see correction below |

**Verdict: the headline "real" finding is a FALSE POSITIVE by reachability.** asn1-rs
enforces the DER rule "INTEGER ≥ 1 content octet", so `parse_rsa_key`'s
`<(Integer,Integer)>::parse_der` rejects the only encoding (`02 00`) that would yield an
empty slice.

**CORRECTION (my own first pass was also wrong).** I initially wrote that the validator's
panic was "reachable via pub-field construction". That is **false**, and it is worth
recording as its own lesson. `X509PublicKeyValidator` takes a `SubjectPublicKeyInfo`, and
the only constructor of the `PublicKey::RSA` variant is `SubjectPublicKeyInfo::parsed()`
(`x509.rs:250-254`), which **re-parses** the raw `subject_public_key` bytes through
`RSAPublicKey::from_der` on every call. SPKI's pub fields are raw bytes
(`algorithm`, `subject_public_key: BitString`), so a hand-built SPKI *still* goes through
the rejecting parser. There is **no public path — malformed cert or caller-side
construction — that reaches `rsa.modulus[0]` with an empty slice.** My third PoC row only
proves that indexing an empty slice panics (a fact about Rust), not that the *validator*
can be made to do it.

→ Opus's `real` **and** `real_latent` both demote to **false_positive (unreachable via
parser)**. Only survivor is the CONTESTED PEM proportional-allocation (R5 availability
lens — a soft, already-known class). **Net for x509-parser default features this pass:
0 attacker-reachable bugs.**

## Track B / Sonnet 5 — COMPLETE. The model comparison is the real result.

29 raw → 27 unique → **21 false_positive / 5 real / 1 real_latent** (Opus: 21→19 →
16 FP / 1 real / 1 real_latent / 1 contested).

### The decisive cell: both finders raised the RSA candidate; only Sonnet's triage got it right

Identical rubric, identical prompts, identical source tree. **Both** finders raised
`validate/structure.rs:169` (correct — recall-first finders are *supposed* to over-include).
The triage diverged, and that is where the whole result lives:

| | Opus 4.8 | Sonnet 5 |
|---|---|---|
| verdict | **`real`** ❌ | **`false_positive` (R1)** ✅ |
| the load-bearing claim | "asn1-rs does not reject a zero-length DER INTEGER (`02 00`)" — asserted **twice** (finder + triage), **zero citations**, and **false** | traced into the **pinned dependency source**: `asn1-rs-0.8.0-beta.1/src/asn1_types/integer.rs:620-622`, `check_der_int_constraints_input` → first arm `[] => Err(DerConstraint::IntegerEmpty)` |
| self-labelling | wrote "**TRACE (verified against source)**" — it verified x509-parser's source, but the invariant lives in the dependency it never opened | grep-confirmed `RSAPublicKey` has exactly one constructor (`public_key.rs:81`, inside `parse_rsa_key`) — no bypass path |
| corroboration used | **a social signal**: "the maintainers guard `is_empty()` in `key_size()`/`try_exponent()`, *proving* they know empty is reachable" — plausible, and wrong (the guards exist because the fields are `pub`) | explicitly rejected the R9 rescue ("R9 is about *this* crate's unreached public paths, not a third-party invariant changing in a future release") |
| bonus | — | independently recommended "downgrade to a hardening suggestion" — the exact framing we landed on hours later |

I verified Sonnet's citation is **real, not fabricated** (`integer.rs:622` reads exactly as
quoted). So Sonnet **statically derived, from the dependency source, the thing I only
established later with `cargo run`** — and got there first.

### The lesson — corrected (three over-claims, including two of mine)

1. **Opus's finder+triage** over-claimed on an **unverified dependency invariant**, and
   substituted a social inference for checking it.
2. **I over-claimed** — "reachable via pub-field construction" — by reasoning about
   `RSAPublicKey` in isolation instead of tracing the validator's entry (`parsed()`
   re-parses, so the struct cannot be injected). Caught only when asked where the PR's test
   would point.
3. **I over-claimed about the lesson itself.** I first wrote this up as "static reasoning is
   unreliable; dynamic execution saves you." Sonnet's run refutes that: a sufficiently
   diligent **static** trace reached the correct verdict *earlier and cheaper* than my
   `cargo run`. Dynamic was the **oracle/tiebreaker**, not the only road.

The differentiator was never static-vs-dynamic. It was **whether the agent opened the
dependency**.

### Revised rubric proposal (supersedes my earlier one)

My first proposal — "reachability resting on a dependency's accept/reject behaviour ⇒
DEFER-TO-DYNAMIC by construction" — is **too strong, and misdiagnoses the gap**. R1 already
covers "an invariant that dominates the sink", and Sonnet applied R1 correctly. The rubric
wasn't the hole; **evidence enforcement** was:

> **Proposed R-rule:** any claim about a *dependency's* accept/reject behaviour must cite
> that dependency's source (`file:line`). An uncited dependency-behaviour claim is
> inadmissible — it cannot be the load-bearing premise of a finding *or* of a
> `false_positive`.

Cheap, static, no quota — and it would have killed this at triage without any dynamic step.

### Neither model dominates — the honest scoreboard

- **Hard reachability question:** Sonnet right, Opus wrong. Decisive.
- **Soft allocation class** (PEM proportional-alloc): Opus said `contested`, Sonnet said
  `real` ×3. Here Opus's conservatism is arguably better calibrated — the class is
  input-proportional, not attacker-amplified.
- **Counting artifact (NOT a harness bug — correcting my own earlier label):** Sonnet's
  "5 real" is inflated because the dedup key in **my throwaway Track-B workflow script**
  (`cwe|file|title[:32]`) failed to merge **three near-identical `pem.rs` unbounded-alloc
  findings**. This is *not* `harness/aggregate.py` — the pipeline's union-of-N dedups by
  (CWE + crash-site), a different mechanism that was never exercised here (Track B is static,
  it doesn't run the harness). Distinct reals ≈ 3, not 5. **Do not quote the raw counts**;
  nothing in rust-in-peace needs fixing for this.

### Verifying Sonnet's reals (dynamic, in-image, quota-free — same discipline as the RSA FP)

The cell's own lesson forbids recording a `real` on argument alone. Verifying each:

**✅ `time.rs:199` `ASN1Time::add` — CONFIRMED, and it's a genuine defect in x509-parser's
own code (unlike the RSA FP).** Dynamic PoC (`time 0.3.41`, no `large-dates`):
- built `ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC))` → `t + Duration::days(1)`
  **PANICKED** (not `None`).
- `ASN1Time::parse_der(0x18 0x0F "99991231235959Z")` **ACCEPTED** — year-9999 (RFC 5280's
  conventional "no well-defined expiration" `notAfter`) is reachable straight from a cert.

The signature is `fn add(self, rhs) -> Option<ASN1Time>` — it *promises* `None` on failure —
but the body is `Some(ASN1Time::new(self.time + rhs))`, and `OffsetDateTime + Duration`
panics on overflow. So the impl **violates its own `Option` contract**. This is materially
better than the RSA candidate: the defect is in x509-parser's *own* code, the fix is real
and testable (`self.time.checked_add(rhs).map(ASN1Time::new)`), and there is a natural
consumer pattern (`cert.validity().not_after + grace_period`).

Reachability caveat (stated, not hidden): x509-parser never calls `Add` itself
(`time_to_expiration` uses the checked `Sub`), so a live crash needs a **downstream caller**
using `+`. → honest disposition **`real_latent` leaning real** (Sonnet said `real` under R9;
defensible).

**DISCLOSURE PACKAGE READY (fix verified by execution).** Applied the one-line fix
`self.time.checked_add(rhs).map(ASN1Time::new)` to the crate and re-ran: patched crate
**compiles**; `9999-12-31 + 1d` → **`None`** (contract honored, no panic); `2025-01-01 + 1d`
→ **`Some("Jan 2 2025")`** (normal case unchanged). Draft report + verified patch:
[`disclosure/asn1time-add-panic.md`](disclosure/) + [`disclosure/asn1time-add-checked.patch`](disclosure/).
PoC saved: [`poc/asn1time_add/`](poc/). **NOT sent** — notifying `rusticata/x509-parser` is an
outbound public action; needs explicit go-ahead. This is the one genuine, cleanly-fixable
defect the whole 2×2 produced.

**✅ `revocation_list.rs` dup-extension accessors (Sonnet `real`, R8) — EXECUTION-CONFIRMED,
reachable, info-severity.** First recorded from a code-read; **re-verified by execution** after
a fair challenge that a read-only verdict is exactly what keeps failing here. Built a real DER
CRL carrying **two** `CRLNumber` (2.5.29.20) extensions (`poc/crl_dup_extensions/`):

```
[parse] CRL with DUPLICATE CRLNumber extensions ACCEPTED by parser
[exts]  extensions() len = 2                       <- both stored, no parse-time dedup
[find]  crl_number() = 1                           <- silently first-matched
[map]   extensions_map() = Err(DuplicateExtensions)  <- DIVERGENCE CONFIRMED
```

Reachability holds here (**unlike** the RSA trap): `parse_opt_tagged_extensions`
(`extensions/mod.rs:654`) uses `many0` and appends everything to a `Vec` — the only
`DuplicateExtensions` checks in the whole crate live *inside* `extensions_map()`, never on the
parse path. So a malformed CRL genuinely reaches the accessor. RFC 5280 forbids a repeated
extension; x509-parser accepts it and two consumers of the same CRL disagree (one sees
`crl_number()==1`, the other gets an error). **Real, execution-backed, severity=info** — no
panic/memory impact, and the CRL-number's role in freshness/replay ordering is the only (mild)
security angle. Sonnet was right.

**✗ `signature_algorithm.rs` `try_from` (Sonnet `real_latent`, R8) — DOWNGRADE to
false_positive / by-design; downgrade now evidence-backed.** `TryFrom` accepts an
`AlgorithmIdentifier` without checking `parameters`. I first downgraded this purely on reading
a comment — the load-bearing premise was actually Sonnet's claim that *no in-crate caller gates
on `try_from`*. **Verified that claim rather than trusting it:** the only mentions of
`SignatureAlgorithm` outside its own file are **doc comments** (`certification_request.rs:21,151`,
ASN.1 spec text), and `verify.rs` references it **0 times** — `verify_signature` takes an
`&AlgorithmIdentifier` and matches raw OIDs directly, bypassing `try_from` entirely. Combined
with the explicit comment at `:36-38` ("would make a strict parser… best go to a verifier") and
`lib.rs:117` ("does not validate any cryptographic parameter"), the permissiveness is
**documented, intentional, and unrelied-upon**. Sonnet over-included intended behaviour.

**~ PEM unbounded-alloc — verdict is a JUDGMENT, not an execution result (stated plainly).**
Executing it would only re-demonstrate "large input → proportional allocation", which nobody
disputes; the question is whether input-proportional allocation counts as a vuln, and per
`scan-extras` DO-NOT-REPORT + R5 it does not. Opus's `contested` is the better-calibrated call.
Flagged as unexecuted so it isn't mistaken for a verified verdict.

**~ PEM unbounded-alloc (Sonnet `real` ×3 → really ×1; soft R5 class).** Input-proportional
allocation, no attacker amplification beyond the in-memory input size. Opus's `contested`
here is the better-calibrated call. Not a crash; a robustness/DoS-surface note at most.

### Residual → one **defensive nit** — DECISION: **do not file** (2026-07-17)

`X509PublicKeyValidator` is the odd one out vs the crate's own `key_size()`/`try_exponent()`,
which guard `is_empty()` before `[0]`. A guard there is pure defense-in-depth — it matters
only if asn1-rs ever accepts a zero-length INTEGER, or a laxer BER path appears.

**Decided: no upstream PR.** It guards a state that cannot occur through any public path,
carries no possible regression test, and would land on a maintainer as noise. Sending it
would also quietly misrepresent the campaign's actual result (0 findings) as a contribution.
Not filing is the honest outcome, not a failure.

Artifacts are **kept as evidence, not as a pending action**:
- [`hardening/validate-structure-guard.patch`](hardening/) — verified: applies clean on a
  pristine checkout, patched crate compiles. Kept to show the fix *was* worked out, and that
  the reason for not shipping is reachability, not effort.
- [`hardening/PR-BODY.md`](hardening/) — the honest write-up we *would* have sent. Useful as
  a worked example of the disclosure framing (no reachability claim, explicit "close this if
  it's noise").
- [`poc/`](poc/) — pins the *parser's* rejection behaviour (`02 00` → `Err`), which is the
  actual load-bearing evidence for the FP verdict. It does not exercise the validator and
  proves nothing about the patch.

### Why this is a useful research result anyway

The deliverable of this cell is **not a bug and not a patch — it is a measured failure mode
of the method**, which is what the campaign is for:

- A confident, well-argued, source-cited finding with a *real* sink survived a full
  recall-first scan **and** a full R1–R11 triage pass, and was still wrong — because its
  load-bearing premise was an **assumption about a dependency's behaviour that nobody
  executed**.
- The triage rubric didn't catch it: R1–R11 are about *this* crate's invariants, so an
  unverified *upstream* invariant slides straight through. Possible rubric gap worth
  considering: a rule that any finding whose reachability rests on a dependency's accept/
  reject behaviour is DEFER-TO-DYNAMIC by construction.
- The curated layer reproduced the same class of error one level up, and was corrected only
  by an outside question ("where does the PR's test point?"). Reviewer pressure caught what
  neither the finder nor the curator did.
- Cost of the refutation: **one `cargo run`, zero API quota** — the check was cheap and was
  simply not demanded early enough.

## Track A (autonomous crash pipeline) — both models: 0 crashes

Launched sonnet post-OAuth-reset (15:26 UTC), `run --resume` of the earlier batch,
`--parallel --stream --auto-focus --aggregate union --max-turns 150`. Ran **~93 min**, then
killed: **0 crashes, 0/3 runs completed**. The find agents stayed active (log live to the
end) but rabbit-holed in **binary reverse-engineering** — `objdump`/`nm`/`strings`/`od` over
`/work/riptarget` chasing `debug_assert`/`bitvec`/panic strings — instead of crafting inputs,
and burned toward the turn cap without emitting a single crashing PoC. They did run the crate's
own `assets/*.der` through `riptarget` (all clean). Killed per the pre-authorized "agents are
spinning, record the 0-crash result" rule.

`reattack`/`scorecard` are **N/A**: both operate on graded findings, and Track A find produced
zero. The honest record is simply **0 crashes**.

This is the *expected, consistent* result, not a failure of the run: Track B already
established x509-parser (default features) has **no byte-triggered panic** — the genuine
findings (`ASN1Time::add`, CRL-dup) are logic/latent and a crash-oriented find agent cannot
reach them (no input makes the parser itself panic). A blind byte-fuzzer's null result here
*corroborates* the static conclusion. It also flags a real limitation of the autonomous crash
track on logic-heavy targets — the exact motivation for the curated Track B.

### Opus: 0 crashes (+ Anthropic cyber-safeguard friction)

Launched opus post-reset (17:02 UTC), same flags, `--results-dir ~/x509res-opus`, 13 recon
focus areas. Killed at ~35 min: **0 crashes, 0/3 runs completed**. Behaviour mirrored sonnet
(find:0/2 crafting DER + fuzzing the crate's `assets/*.der`, plus binary reverse-engineering)
— killed early per the pre-authorized rule once it was clearly heading to the same null result,
to conserve the just-reset OAuth pool.

New this run: **one find agent (find:1) was blocked 12× by Anthropic's real-time cyber
safeguards** — `API Error … triggered cyber-related safeguards … Cyber Verification Program`,
dead-ending in the retry loop. A real operational cost of the *autonomous* crash track (an
agent autonomously crafting attack inputs trips the safeguard) that the *curated* track
(interactive, read-only source review) never hits. Worth noting for anyone running the crash
pipeline at scale on security targets.

Both A cells = 0 crashes; `reattack`/`scorecard` N/A (they operate on graded findings, of which
Track A produced zero). Full cross-cell synthesis: [`CONSOLIDATION.md`](CONSOLIDATION.md).

### Disclosure decision (2026-07-17) — see the assessment recorded with the campaign

- `ASN1Time::add` → **PR + issue candidate**, framed as a correctness/robustness bug (NOT a
  RustSec/CVE advisory — no demonstrated attacker-reachable DoS in the crate; asserting
  "vulnerability" would repeat this campaign's own over-claim failure mode). Fix + PoC verified.
- CRL-dup → **info-severity, low risk**; fold as a secondary note or skip. Arguably within the
  crate's documented "parse ≠ validate" stance.
- **Channel decision: private to maintainer FIRST** (user's call), public only after he responds.
- Channel facts: repo has **no SECURITY.md**, **private vulnerability reporting is DISABLED**
  (`/private-vulnerability-reporting` → `{"enabled":false}`), 0 prior RustSec advisories. So the
  only private channel is **email**: Pierre Chifflier <chifflier@wzdftpd.net> (from public git
  history; primary rusticata maintainer), optional cc Jalil Salamé.
- **Email SENT by the user** (private, to the maintainer) with the rust-in-peace context +
  "if it's just a bug I'll PR it" framing. Draft archived: `disclosure/email-draft.md`.
- **PR prepared locally, ready-to-fire** (in case the maintainer says "just PR it"):
  - Local clone on branch `fix/asn1time-add-checked-add` with commit `661bd83` (fix + regression
    test), at `~/Documents/x509-parser-pr` — applies clean on upstream `master`.
  - **Test verified in the crate's own harness**: `cargo test --lib time::` → 3 passed.
  - `disclosure/pr/`: `PR-BODY.md`, `asn1time-add-fix-and-test.patch`, `OPEN-PR.sh` (forks →
    pushes → `gh pr create`; run only on the maintainer's go). Nothing pushed/opened yet.

## Status matrix

| | Opus 4.8 | Sonnet 5 |
|---|---|---|
| **A (autonomous, Tamm)** | ✅ **0 crashes** (killed ~35min, 0/3 runs, 12× cyber-safeguard blocks) | ✅ **0 crashes** (killed ~93min, 0/3 runs) |
| **B (curated)** | ✅ 21→19; 16 FP / **1 real (WRONG)** / 1 real_latent / 1 contested | ✅ 29→27; 21 FP / 5 real (≈3 after dedup fix) / 1 real_latent — **correctly closed the RSA candidate Opus got wrong** |

## Next

- ~~Collect Track B / Sonnet~~ ✅ done — see the model comparison above (Sonnet closed the
  RSA candidate correctly; Opus did not).
- ~~Fix the union dedup key~~ — **not a real action item**: the weak key was in my throwaway
  Track-B script, not in the harness. Just don't quote the raw `real` counts (use the
  per-finding verdicts above).
- **Triage Sonnet's 5 reals properly** — none are dynamically verified yet. Given this
  cell's whole lesson, do NOT record them as real without a trace/execution:
  `time.rs` `ASN1Time::add` (R9 public-API panic), `revocation_list.rs` `find()`-based
  dup-extension accessors (R8 logic), `signature_algorithm.rs` `try_from` (real_latent),
  PEM unbounded-alloc (×3, soft class).
- After 15:20 UTC: run Track A sonnet + opus on Tamm (`--resume` the killed sonnet batch),
  then reattack + scorecard per model.
- Consolidate the 2×2. (Upstream hardening PR: **decided against — do not file**. Closed, not pending.)
- Then next targets: httparse → png → lopdf (same 2-track treatment) if confirmed.
