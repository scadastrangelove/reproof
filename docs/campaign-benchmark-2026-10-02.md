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

| Lens | h2 ⚠ | rustls | rustdesk |
|---|---|---|---|
| **blind** | **1/3** (run 0, report 10/10 HIGH) ⚠ | **2/3** (runs 0,1; 2 grade-passed) | **2/3 votes** (run 0 grade-passed; run 1 grade-rejected; report 10/10 CRITICAL) |
| **threat-model** (`--auto-focus`) | **1/3** (run 1; runs 0,2 `agent_failed` — kimi rc=137, infra) ⚠ | **1/3** (run 1) | **2/3 votes** (runs 0,1; both grade-rejected) |
| **CVE-seeded** (temp `focus_areas`) | **1/3** (run 2, report 10/10 HIGH) ⚠ | **2/3** (runs 1,2; 2 grade-passed) | **2/3 votes** (runs 1,2; both grade-rejected) |

⚠ h2 rows: git-archaeology-assisted — all three finding runs read the
upstream fix commit before the PoC (target image ships full `.git`; see
"Prompt fix" section's taint caveat and docs/port-fidelity-audit.md).

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
   **→ Fixed 2026-10-03, see "Prompt fix" below.**
3. **h2 TM `agent_failed` (rc=137)** on 2/3 runs — infra kill (SIGKILL), not a
   fair no-crash. Recall is understated there.
4. **Aggregate (union-of-N) held everywhere**: each cell's crashes deduped to
   exactly one candidate matching the ground truth (judge DUP verdicts on
   repeat finds cite the identical crash site).
5. Driver/difficulty balance looks right: every oracle was reachable blind,
   but no blind run was trivial — h2 required assembling valid HPACK-bearing
   frames, rustls a structurally valid ClientHello flight, rustdesk reading
   `Encrypt::enc` and deriving the XOR relation.

## Prompt fix (2026-10-03)

Observation 2 root-caused to the grade prompt rejecting findings by bug
*class* instead of grading reachability/exploitability conditions. The
rejected rustdesk runs all showed the same pattern in the grader's own
evidence: "All 3 runs print PWNED … exit 101 … no panic, no sanitizer output,
**not a crash**" — the effect verified, the class rejected. Fix landed in two
commits (`0ce1c7c`, `462a4cd`, `88d68f4e`), covering BOTH prompt layers (the
cpp base in `reproof/prompts/` and the rust profile overrides in
`reproof/rust/` — the first fix round only touched the base and validation
caught the profile still rejecting):

- **Grade prompts** are now class-agnostic: a finding is a reproducing crash
  OR a declared logic oracle (exit-code/marker signal for crypto-relation
  breaks, injection, SSRF, authz bypass, data loss). Criterion 2 gained a
  wrong-input control for logic classes (signal must fire for the PoC and NOT
  for a mutated input); criterion 4 verifies the defect lives in the project
  code, not the harness. Rejecting a genuine reproducing finding because of
  its class is now explicitly called out as a grader error.
- **Find prompts** gained a methodology section: reasoning-first,
  hypothesis-driven PoCs; mass mutation/fuzz loops are explicitly the separate
  find→fuzz reattack stage's job, not the find-agent's. `crash_type` accepts
  `logic-oracle:<class>`. An honest no-finding beats an hours-long fuzz
  campaign.

Validation run (`results/rustdesk/20261002T151645Z`, 2 runs, fixed prompts):
both finds submitted `logic-oracle:crypto-key-recovery`; both grades
**passed 1.0, all 5 criteria** (previously rejected); judge NEW; report
**10/10 HIGH** with the grader evidence reading "64-byte PoC = exact m_b. All
3 runs: PWNED + exit 101; mutated control rejected."

### Re-run of the grade-affected cells (2026-10-03, fixed prompts)

The fix only affects rustdesk — h2 and rustls had zero grade rejections
(their misses were find-side `no_crash_found` / infra `agent_failed`). All
three rustdesk lens cells were re-run with the fixed prompts, same protocol
(`--runs 3 --parallel --stream`; TM = `--auto-focus`; CVE = temp single-area
`focus_areas`, reverted after). Result dirs: blind `20261003T043820Z`, TM
`20261003T045253Z`, CVE `20261003T050546Z`.

| Lens | Pre-fix | Post-fix re-run |
|---|---|---|
| **blind** | 2/3 votes (run 1 grade-rejected) | **3/3 finds, 3/3 grade PASS 1.0**; reports 10/10 HIGH + 10/10 CRITICAL |
| **threat-model** | 2/3 votes (runs 0,1 grade-rejected) | **1/3 find** (runs 1,2 honest no_crash), grade PASS 1.0, report 10/10 HIGH |
| **CVE-seeded** | 2/3 votes (runs 1,2 grade-rejected) | **2/3 finds, both grade PASS 1.0**; reports 10/10 CRITICAL + 10/10 HIGH |

**Zero class-based rejections** — every reproduced logic-oracle finding now
passes grade on reachability/exploitability merits. One residual quirk: the
judge mis-deduped the same two-time-pad finding twice (blind cell: bug_00 +
bug_01; CVE cell likewise) because the manifest excerpt for logic-oracle
findings is the driver's identical challenge banner — no crash site, no
class. Follow-up: manifest excerpts for logic-oracle classes should carry
`crash_type` + the oracle marker line, not the stdout head.

**⚠ Taint caveat (2026-10-03 audit, see docs/port-fidelity-audit.md):** the
h2 rows above (all lenses) are **git-archaeology-assisted** — the target
images shipped the full upstream `.git` history and all three finding runs
read the actual upstream fix commit (`3a241be`, "prevent double counting
pushed streams", #936) before crafting the PoC. The original harness's
targets ship tarballs/local copies with no history, so this channel was a
port-introduced regression, not an inherited property. rustls and rustdesk
finds showed no fix-commit exposure (organic).

### h2 clean re-run (2026-10-03, history-free image + B2 template fix)

Fixed in `9da755ad`: images strip `.git` at build; fresh find runs get the
fresh prompt (the re-attack framing — "patched crate, read /poc/, find the
path the fix touched" — is gated behind an explicit `patched=True`, and no
longer leaks into fresh runs; upstream-inherited bug B2). Re-run of all three
h2 lens cells on the clean image, same protocol, no fuzzing (verified: zero
fuzz-loop patterns in the transcripts; agents' residual `git log` probes hit
"not a git repository" and returned nothing):

| Lens | Tainted (2026-10-02) | Clean re-run (2026-10-03) |
|---|---|---|
| **blind** | 1/3 ⚠ fix-guided | **1/3** — run_000, counts.rs:111 `assert!(!stream.is_counted)` via 1xx-on-ReservedRemote, grade PASS 1.0, report 10/10 HIGH. Time-to-find 2009 s |
| **threat-model** | 1/3 ⚠ fix-guided (+2 infra rc=137) | **2/3** — runs 0,1, same site; judge correctly DUP_SKIPed the second; grade PASS 1.0 ×2, report 10/10 HIGH. No infra failures this time |
| **CVE-seeded** | 1/3 ⚠ fix-guided | **2/3** — runs 0,2, same site; judge DUP_SKIP correct; grade PASS 1.0 ×2, report 10/10 HIGH. Time-to-find 582–1264 s |

Result dirs: blind `20261003T060144Z`, TM `20261003T071338Z`, CVE
`20261003T082903Z`. Every find is the ground-truth `counts.rs:111` panic,
reached by source reading + crafted frame sequences — the git-archaeology
channel is closed (verified live in-container: `/work/h2/.git` absent). The
clean blind-lens rediscovery of h2 now stands. Also fixed operationally:
`agent_image.ensure()` caches by tag and does not notice rebuilt target
images — delete `reproof-<target>-latest-agent:*` after target Dockerfile
changes (this bit us once on the first re-run attempt).
