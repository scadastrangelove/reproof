# targets/rustdesk — JOURNAL

Campaign `rustdesk-2026-08`. Target: RustDesk app + `hbb_common` @ pinned main
`a5018a02` / `69cea8da` (2026-08-03). Full detail: `../../rustdesk-campaign-disclosure/`.

## 2026-08-03 — scope & pin
- Evaluated RustDesk as a target: app+C-FFI, not a crates.io library. Wire protocol is
  rust-protobuf (memory-safe); the memory-unsafe surface is C-FFI to upstream codecs
  (not RustDesk-attributable). Productive surface = logic/trust-boundary/DoS/crypto in Rust.
- No SECURITY.md, GitHub private reporting OFF, 0 GHSA — disclosure channel is a real problem.
- Pinned current main; verified all recent security fixes present (post-fix state). The obvious
  entry point (file-transfer path traversal) was already patched (CVE-2026-2490 / PR #14678) →
  reframed as a **variant-analysis** campaign seeded on the recent fixes.

## 2026-08-03 — 2×3 lens matrix
- Ran blind / cve-seeded / threat-model on Opus AND Sonnet, each lens its own agent.
- Blind/cve on an isolated tree copy (no THREAT_MODEL.md) for clean attribution (L38).
- threat-model bootstrapped `THREAT_MODEL.md` (multi-layer: authz-protocol / codec-parser /
  file-path / framing+compress / IPC / config+deep-link+update), then the lens hunted its leads.
- Opus-cve was an interrupt casualty on the first launch (0 work); relaunched, completed.
- KEY OBSERVATION: the two blind passes (Opus vs Sonnet) were **nearly disjoint** — Opus found
  online-states/cliprdr-alloc/addrmangle; Sonnet found macOS-clipboard-write/cliprdr-gate/UDP-unauth/
  2FA/audio/mediacodec. Union ≫ either. Model diversity paid for itself.

## 2026-08-03 — /triage (adversarial verify)
- 17 candidates → 5 code-locality clusters of skeptics (default-wrong, 16 exclusion rules).
- Confirmed: RD-02(High), nonce-reuse(High), SB1(High/Critical), B1(Med-High), F3-token(Med), SB2/B2(Med),
  SB3/F5/RD-03/SB4/SB6(Low-Med).
- Dropped (FALSE_POSITIVE): CONTESTED-fs (WAI — 2 Opus lenses right vs 1 Sonnet-tm), write_block-TOCTOU
  (rule 16), SB5-linux-audio (n≤buffer.len — the only mem-unsafety candidate, refuted), F3-bytescodec
  (rule 1 volumetric — despite 3-lens corroboration), B3-addrmangle (release wraps), RD-04-Windows-cliprdr
  (bounded UINT32).
- RD-01 sig-bypass recalibrated High→Low (inert: the documented unsigned host= filename already does
  the same redirect).

## 2026-08-04 — PoC phase (two "confirmed" items flipped in OPPOSITE directions)
- **nonce-reuse: CONFIRMED.** Independent source re-derivation (one shared secretbox key both
  directions, both counters from 0, no direction byte) + dynamic PoC on the **real
  hbb_common::tcp::Encrypt** — a key-less relay recovers the peer's plaintext (two-time pad). Packaged.
- **RD-02: REFUTED-so-far.** Dynamic PoC on GitHub Actions windows-latest showed Rust std does NOT
  apply the Win32 trailing-space canonicalization the finding assumed (treats `.. ` as a literal
  component, `\\?\`-verbatim). Only plain `..` escapes (guard catches it). Overturned a conf-9 triage
  TRUE_POSITIVE. Held `needs-full-Windows` per operator; likely FP.
- **SB1: CONFIRMED (primitive).** Same join+create primitive on macos-latest ESCAPES (relative +
  absolute + home-dir; base/ left empty). Standard Unix semantics, no verbatim layer — the opposite
  of RD-02. Reachability triage-confirmed; full 2-instance live demo optional.
- Lesson: a platform-path finding must be verified through the actual **runtime file API**, not OS
  docs — even a rigorous skeptic missed the Rust-std layer (RD-02). And the same primitive can be
  real on one OS and a false alarm on another.

## Status
- Two solid Highs (nonce-reuse + SB1), both dynamically verified. ~8 confirmed Low/Med (source-traced).
  RD-02 held. Nothing filed (no channel). Next: coordinate email disclosure for the two Highs;
  optionally dynamic-PoC B1 (unauth online-states DoS) and the full RD-02 Windows check.
## 2026-08-04 — adversarial refutation pass (pre-disclosure gate), both packages
Cross-model hostile review (finding found by one model, refuted by the other):
- **nonce-reuse → SURVIVES** (Sonnet, could not break it). All invariants verified against source
  (shared key both dirs; both counters from 0; relay sees both + lacks key; trivial frame alignment;
  secretbox layout vs the vendored crate). Two upgrades: (a) websocket.rs reuses the same Encrypt →
  the bug is BROADER (WS + TCP); (b) it is NOT a duplicate of CVE-2026-30785 (that is
  password_security.rs local at-rest constant-zero-nonce, fixed e1bdb06; tcp.rs Encrypt untouched) —
  distinction added to the report. Cosmetic: relabeled the code exhibit as "condensed/faithful".
- **SB1 → SURVIVES** (Opus, could not break the arbitrary-write). Ships in the notarized DMG,
  unsandboxed, name unvalidated (grep: 0 sanitizers), std::fs (probe representative). Control-asymmetry:
  RustDesk's own validator is on the file-transfer path but NOT the clipboard path (commit 00293a99).
  SEVERITY REFRAMED honestly: requires a victim paste (1-click precondition, not 0-click); impact =
  create-new-file → LaunchAgent persistence → code-exec at LOGIN (not instant RCE / not overwrite).
- Both Highs cleared the gate. Remaining pre-file: is-latest re-check on current main + coordinate an
  email channel. RESULT: two solid, cross-model-refutation-hardened High findings ready to disclose.

## 2026-08-05 — coordinated-disclosure package + fixes for ALL 9 survivors
- Assembled `../../rustdesk-coordinated-disclosure/` (auto-gitignored): COVER-LETTER.md (to
  info@rustdesk.com — no SECURITY.md / PVR off), FINDINGS-REPORT.md (9 findings, honest severity +
  preconditions), poc/, and the zip (moved in from repo root; tracked .gitignore extended so a
  stray `*-disclosure*.zip` can't leak).
- **Proposed fixes for all 9** via 6 parallel patch agents (2 findings each on the multi-item ones).
  8 concrete patches in `patches/01..08`, each independently `git apply --check`-verified against the
  pin (a5018a022 / hbb_common 69cea8d), individually AND all-8-together clean. `PATCHES.md` indexes
  them. Patch generation caveats handled: F3 diff was HTML-escaped in the agent transcript →
  regenerated via Edit-in-pin + submodule `git diff` (paths rewritten repo-root-relative) + revert to
  pristine; SB3 agent died mid-response but its patch file survived and was type-verified
  (`FramedSocket::next` → `TargetAddr`) by hand since the agent never self-reviewed.
- TWO patches are NOT drop-in, flagged loudly in PATCHES.md + cover letter: (04) nonce-reuse changes
  the wire format → needs a negotiated `nonce_v2` capability bit + lockstep rustdesk-server patch
  (fails closed old↔new, so safe but flag-day); (06) access-token deliberately departs from the
  report's literal call-site direction (would break Flutter OIDC — Dart reads the token as a raw
  Bearer header, no key) and fixes at the LocalConfig load/store chokepoint instead.
- SB4 (2FA trusted-device) is design-only (server-issued `trusted_device_token` in LoginResponse —
  proto+server+client change), described not diffed. No `cargo` build run — apply-check + code-read
  only; full workspace build is the maintainer-side gate. Pin left pristine (submodule reverted).
- STATUS: package + patches complete, ready for the operator to send. Nothing filed/pushed (private).
