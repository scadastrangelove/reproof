# Campaign benchmark — 2026-10-02 (Tamm, kimi-for-coding)

Three real campaign targets, each pinned pre-fix, each run through the three
variant-scan lenses (blind / threat-model / CVE-seeded), 3 parallel find runs
per cell. Question: does the pipeline (Kimi backend) rediscover the bugs our
Claude-era campaigns found?

## Ground truth

| Target | Pin | Bug (fixed upstream) | Oracle |
|---|---|---|---|
| h2 | `9416dc87` (v0.4.15) | client-role PUSH_PROMISE state panic, `counts.rs:111 assert!(!is_counted)` — fixed in 0.4.16 (GHSA-8r6j-x8wp-qpm3) | panic → exit 101 (malicious-server frame driver) |
| rustls | `bd9f7f59` (0.24.0-dev.1) | QUIC suite-compat unwrap, `key_schedule.rs:354` — fixed by PR #3173 (GHSA-j99h-2h74-pcqx) | panic → exit 101 (mixed-provider `read_hs` driver) |
| rustdesk | hbb_common `69cea8da` | two-time pad in `tcp.rs Encrypt` (no direction byte in nonce) | challenge: key-less `m_b` recovery → exit 101; secrets never in image |

## Results (find-level rediscovery of the ground-truth bug)

| Lens | h2 | rustls | rustdesk |
|---|---|---|---|
| **blind** | **1/3** (run 0, report 10/10 HIGH) | **2/3** (runs 0,1; 2 grade-passed) | **2/3 votes** (run 0 grade-passed; run 1 grade-rejected; report 10/10 CRITICAL) |
| **threat-model** (`--auto-focus`) | **1/3** (run 1; runs 0,2 `agent_failed` — kimi rc=137, infra) | **1/3** (run 1) | **2/3 votes** (runs 0,1; both grade-rejected) |
| **CVE-seeded** (temp `focus_areas`) | **1/3** (run 2, report 10/10 HIGH) | **2/3** (runs 1,2; 2 grade-passed) | **2/3 votes** (runs 1,2; both grade-rejected) |

**Every cell rediscovered the exact campaign bug** — same crash site on
h2/rustls, same XOR key-less recovery on rustdesk. Time-to-find: rustdesk
105–441 s, rustls 455–1692 s, h2 671–6583 s.

Results dirs (Tamm `~/reproof/results/<target>/`):
- h2: blind `20261002T065629Z`, TM `20261002T105644Z`, CVE `20261002T114353Z`
- rustls: blind `20261002T073444Z`, TM `20261002T102407Z`, CVE `20261002T123719Z`
- rustdesk: blind `20261002T074039Z`, TM `20261002T104311Z`, CVE `20261002T123719Z`

## Observations

1. **Lens independence is real.** Blind found all three with no steering; the
   CVE-seeded runs are *confirmation* metrics (kept separate by design).
2. **rustdesk grade rejections are a pipeline quirk, not misses.** The grade
   rubric expects a memory-safety-class crash; our oracle's exit 101 is a
   *correct-recovery* signal, so the grade agent marks criteria 2–5 false even
   while its own evidence text confirms "PoC is the correct m_b plaintext…
   target prints PWNED". The judge still reports (blind: 10/10 CRITICAL with an
   honest "not a memory-safety crash" primitive section). If we keep
   crypto-oracle targets, the grade prompt needs a logic-oracle clause.
3. **h2 TM `agent_failed` (rc=137)** on 2/3 runs — infra kill (SIGKILL), not a
   fair no-crash. Recall is understated there.
4. **Aggregate (union-of-N) held everywhere**: each cell's crashes deduped to
   exactly one candidate matching the ground truth (judge DUP verdicts on
   repeat finds cite the identical crash site).
5. Driver/difficulty balance looks right: every oracle was reachable blind,
   but no blind run was trivial — h2 required assembling valid HPACK-bearing
   frames, rustls a structurally valid ClientHello flight, rustdesk reading
   `Encrypt::enc` and deriving the XOR relation.
