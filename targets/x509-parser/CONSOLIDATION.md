# x509-parser — 2×2 campaign consolidation

**Target:** [`rusticata/x509-parser`](https://github.com/rusticata/x509-parser), default
features (pure Rust; `verify` off). **Question:** how do an *autonomous crash pipeline* and a
*curated static review* compare, across **Opus 4.8** vs **Sonnet 5**, on a security-critical
DER/X.509 parser whose realistic attack surface is panic-DoS + logic (not memory corruption —
1 `unsafe`, `#![forbid(unsafe_code)]` on the crate proper)? Stance: responsible disclosure.

## Ground truth (what's actually in the crate)

Established by curated review **plus execution** (in-image `cargo`, offline, zero API quota):

- **0 attacker-reachable memory/panic-DoS bugs** in default features. No malformed certificate
  makes the parser itself panic.
- **2 genuine defects, both in x509-parser's own code, both execution-confirmed:**
  1. `ASN1Time`'s `Add<Duration>` (`time.rs:199`) returns `Option` but **panics instead of
     `None`** on date overflow — violates its own contract. Reachable input (year-9999
     `notAfter`) parses fine; a live crash needs a downstream `not_after + duration` caller.
     `real_latent`. Fix verified (`checked_add`). → disclosure draft ready.
  2. Duplicate CRL extensions: `crl_number()` first-matches while `extensions_map()` rejects
     (`DuplicateExtensions`); parser accepts the duplicate (`many0`, no dedup). `real`,
     info-severity. Execution-confirmed.
- Everything else across both models (RSA empty-index, offset underflows, alloc-proportionality,
  time-Sub, SCT, PEM, …) is `false_positive` or soft/by-design.

## The 2×2

| | **Opus 4.8** | **Sonnet 5** |
|---|---|---|
| **A — autonomous crash pipeline** (recon→find×3→grade, ASan/panic/Miri) | **0 crashes.** Killed ~35 min, 0/3 runs completed, 13 focus areas. **12× blocked by Anthropic's real-time cyber-safeguards** (one find agent dead-ended in retry). | **0 crashes.** Killed ~93 min, 0/3 runs completed. Agents active but rabbit-holed in binary reverse-engineering (`objdump`/`strings`) instead of crafting inputs. |
| **B — curated static scan+triage** (rust rubric, R1–R11) | 21 raw → 19 unique → 16 FP / **1 `real` (WRONG)** / 1 real_latent / 1 contested. The one `real` (RSA empty-index) was **false**. | 29 raw → 27 unique → 21 FP / 5 `real` (≈3 after dedup) / 1 real_latent. **Correctly closed the RSA candidate Opus got wrong**; surfaced both genuine defects. |

## What each axis showed

**Track (autonomous vs curated) — the decisive axis.** Both autonomous runs found **nothing**;
both curated runs found the real issues. This isn't the pipeline failing — it's the *right*
result for a logic-heavy target: the genuine bugs are logic/latent (`ASN1Time::add` needs a
`+` caller; CRL-dup is a semantic divergence), so **no crashing byte-string exists** for a
crash-oriented find agent to discover. The blind fuzzer's null result *corroborates* the static
"no panic-DoS" conclusion — and cleanly exposes the autonomous crash track's blind spot. This
is the empirical case for leading with static review on logic-heavy targets (the lesson from the
earlier dvra3 run, now confirmed on real OSS).

**Model (Opus vs Sonnet) — decided on the one reachability call that mattered.** Both finders
raised the RSA empty-index candidate (`validate/structure.rs:169`). Their **triage** diverged:

- **Opus → `real` (wrong).** Asserted "asn1-rs does not reject a zero-length INTEGER" **twice,
  uncited and false**, labelled itself "TRACE (verified against source)" while never opening the
  dependency, and corroborated with a *social* signal ("maintainers guard `is_empty()` in
  siblings → must be reachable" — actually because the fields are `pub`).
- **Sonnet → `false_positive` R1 (right).** Opened the **pinned dependency source**
  (`asn1-rs-0.8.0-beta.1/src/asn1_types/integer.rs:622`, `[] => Err(IntegerEmpty)` — citation
  verified real), grep-confirmed the single constructor, and even pre-empted the hardening
  framing. It derived *statically* what a `cargo run` later confirmed — earlier and cheaper.

Neither model dominates everywhere: on the soft PEM proportional-allocation class Opus's
`contested` is arguably better-calibrated than Sonnet's `real`. But on the hard reachability
question, Sonnet was right and Opus was wrong.

## Lessons (the campaign's actual product)

1. **The differentiator wasn't static-vs-dynamic — it was whether the agent opened the
   dependency.** A diligent static trace (Sonnet) beat execution on time and cost; execution was
   the tiebreaker/oracle, not the only road.
2. **Over-claim happened at every layer, caught only by execution + outside pressure:** the
   finder (uncited dep invariant), *and the curator* — I twice wrote confident, wrong reachability
   conclusions ("reachable via pub-field construction"; "1 solid + 1 info" recorded from reading),
   corrected only when the user asked "where does the PR's test point?" and "shouldn't you
   re-check?". The curator is **not** automatically the trustworthy layer.
3. **Proposed rubric hardening:** any claim about a *dependency's* accept/reject behaviour must
   cite that dependency's source `file:line`; an uncited dep-behaviour claim is inadmissible as
   the load-bearing premise of a finding **or** a `false_positive`. (Cheap, static, no quota; would
   have killed the Opus FP at triage.)
4. **Operational:** Anthropic's real-time cyber-safeguards blocked an autonomous find agent 12×
   on this run — real friction for the crash-pipeline track that the curated track (interactive,
   read-only) doesn't hit.

## Artifacts

- Findings/PoCs: `poc/{asn1time_add, crl_dup_extensions, rsa_empty_modulus}/` (+ `mkcrl.py`) —
  all run in-image, offline, zero API quota.
- Disclosure draft (ready, **not sent** — needs go-ahead): `disclosure/asn1time-add-panic.md` +
  verified `disclosure/asn1time-add-checked.patch`.
- Full narrative + corrections log: `JOURNAL.md`.
- Not filed: the `structure.rs` `is_empty()` guard (unreachable defensive nit) — `hardening/`,
  kept as evidence only.
