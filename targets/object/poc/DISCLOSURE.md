# Disclosure package — object (gimli-rs/object)

**Status:** DRAFT — not sent. Prepared for operator review. Re-verified 2026-07-18.
**Channel (recommended):** GitHub Private Vulnerability Reporting on gimli-rs/object
(https://github.com/gimli-rs/object/security/advisories → "Report a vulnerability"). No `SECURITY.md`
exists; if private reporting is disabled, fall back to a public issue + PR (this is a memory-safe DoS,
visible in the code — not embargo-critical). Primary maintainer: Philip Craig (@philipc).
**Framing:** private-first, low–medium severity, availability/DoS, memory-safe, found by the
rust-in-peace pipeline, PR offered, "happy to make this a public issue+PR if you prefer."
**Do NOT include:** the PE `imports()` item as a finding — it is an unverified code observation only.

---

## Paste-ready GitHub advisory

**Title:** `object: unbounded allocation decoding a crafted zstd-compressed section (+ exports-trie infinite loop)`

**Ecosystem / package:** RustSec / crates.io — `object`
**Affected versions:** `<= 0.39.1` (and `master` as of 2026-07-18)
**Severity:** Low–Medium (CVSS ~5.5, availability only: AV:L or N /AC:L /PR:N /UI:N /S:U /C:N /I:N /A:H)
**Weaknesses:** CWE-770 (allocation without limits), CWE-835 (infinite loop)

**Description (markdown):**

> Two availability issues (memory-safe DoS) reachable when parsing untrusted object files with `object`.
> Both were reproduced against 0.39.1 and confirmed present on `master`.
>
> ### 1. Zstd-compressed section ignores the reserved size cap (unbounded allocation → OOM)
>
> `CompressedData::decompress` (`src/read/mod.rs`) reserves `try_reserve_exact(size)` where `size` is the
> attacker-controlled `ch_size` from the compression header, then decompresses. The **Zlib** branch
> (`flate2::Decompress::decompress_vec`) writes only into the reserved capacity and errors if exceeded,
> so it is bounded by `ch_size`. The **Zstandard** branch calls `decoder.read_to_end(&mut decompressed)`,
> which grows the `Vec` to the *actual* decoded length, ignoring the reservation; the
> `if size != decompressed.len()` sanity check runs only *after* the allocation.
>
> A crafted ELF with an `SHF_COMPRESSED` section declaring a tiny `ch_size` (so the reservation succeeds)
> but carrying a zstd stream that expands to gigabytes drives an unbounded allocation via the default
> `Section::uncompressed_data()` path (requires the default `compression` feature).
>
> **A/B (same ELF, only `ch_type` differs, both `ch_size=64`, both expand to 200 MB):**
> `ELFCOMPRESS_ZLIB` → ~3 MB RSS (capped, errors); `ELFCOMPRESS_ZSTD` → ~386 MB RSS (grows). A
> RLE-maximized frame reaches ~40,000× (sub-MB file → multi-GB → hard OOM). 6.7 KB PoC attached.
>
> **Fix:** bound the Zstandard decode to `size` like the Zlib branch (e.g. decode through
> `Read::take(size as u64)` / a capacity-limited writer and error before the buffer grows past the
> reservation).
>
> ### 2. Mach-O exports trie has no cycle/depth guard (infinite loop → hang / unbounded `Vec`)
>
> `NodeIterator` (`src/read/macho/exports_trie.rs`) follows child edges by absolute offset
> (`self.offset = child_offset as usize`) with no forward-progress check, visited-set, or depth cap. A
> node whose child edge points back to its own offset makes the DFS re-push a `Frame` every iteration and
> never terminate — `Vec<Frame>` grows until OOM. Reachable via the public
> `LinkeditDataCommand::exports_trie()` iterator (used by callers that enumerate exports via the trie),
> **not** via `File::parse` / `Object::exports()`. A 52-byte Mach-O with a 4-byte self-referential trie
> node (`[0x00,0x01,0x00,0x00]`) hangs the iterator (attached).
>
> **Fix:** require `child_offset` to advance past the current node (or add a visited-set / depth cap /
> node-count bound against the trie length).
>
> ### Reproducers
> Attached: `poc.elf` + `make_poc.py` (issue 1), `poc.bin` + `make_poc.py` + `trie_driver.rs` (issue 2).
> Happy to open PRs for both fixes.

---

## Draft cover (if emailing / opening an issue instead)

> Hi — I've been running a Rust security pipeline over `object` and found two low/medium-severity,
> memory-safe availability issues, reported privately first. (1) The zstd branch of
> `CompressedData::decompress` ignores the `try_reserve_exact(ch_size)` cap that the zlib branch honors,
> so a crafted compressed ELF section allocates unbounded via `uncompressed_data()`. (2) The Mach-O
> `exports_trie()` iterator has no cycle/depth guard and hangs on a 4-byte self-referential trie node.
> Both reproduced on 0.39.1 and master, PoCs attached, and I'm happy to PR the fixes — or just turn this
> into a public issue+PR if you'd rather handle it in the open. Thanks for object!
> — Serg (https://github.com/scadastrangelove/rust-in-peace/)

## After sending (fill in)

- Sent: _(not yet)_ — channel used: _____
- Follow-up if silent: ~14 days.
- Response log: _(none)_
