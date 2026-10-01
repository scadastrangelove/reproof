# object — Zstandard decompression ignores its own size cap (unbounded alloc / OOM)

- **Crate:** `object` 0.39.1 (gimli-rs/object). **Also present on `master`** (verified 2026-07-18).
- **Class:** unbounded allocation / resource-exhaustion DoS (memory-safe). CWE-409 / CWE-770.
- **Severity:** Low–Medium (availability; a crafted object file OOMs the embedder — backtrace
  symbolication, CI artifact scanners, disassemblers that call `uncompressed_data()`).
- **Reachable from:** the public default path `File::parse(bytes)` → `section.uncompressed_data()`
  (requires the default `compression` feature).
- **Reproducer:** a **6.7 KB** ELF (attached `poc.elf`, generator `make_poc.py`) that decompresses to
  200 MB; scale the generator to force a hard OOM.

## The defect — an inconsistency, not by-design

`CompressedData::decompress` (`src/read/mod.rs`) reserves exactly the header-declared uncompressed
size, then decompresses:

```rust
let mut decompressed = Vec::new();
decompressed.try_reserve_exact(size)...;          // size = attacker ch_size (e.g. 64)

match self.format {
    CompressionFormat::Zlib => {
        // flate2 writes into the RESERVED capacity and errors if exceeded → cap HONORED
        decompress.decompress_vec(self.data, &mut decompressed, Finish)...;
    }
    CompressionFormat::Zstandard => {
        // ruzstd read_to_end grows `decompressed` to the ACTUAL decoded length,
        // ignoring the reservation → cap BYPASSED
        decoder.read_to_end(&mut decompressed)...;
    }
}
if size != decompressed.len() { return Err(...) }  // runs only AFTER the OOM
```

The Zlib branch honors the `try_reserve_exact(size)` cap; the Zstandard branch does not — `read_to_end`
grows the buffer to whatever the stream decodes to, and the size-mismatch check runs only *after* the
allocation. So an attacker sets the compression-header `ch_size` to a tiny value (the reservation
succeeds) but ships a zstd stream that expands to gigabytes → the process OOMs before the check.

## Reproduce (through the real parse entry)

```
python3 make_poc.py poc.elf 200        # 200 MB; use e.g. 8000 to force OOM
riptarget poc.elf                       # File::parse(...).sections()[i].uncompressed_data()
```

Observed (release, `overflow-checks` off):

```
ok format=Elf sections
  Maximum resident set size: 395816 kbytes    # ~386 MB, though ch_size declared 64 bytes
```

A ~6.7 KB file allocated ~386 MB (the 200 MB payload + overhead) — the declared 64-byte cap was
ignored. A fully RLE-maximized frame reaches ~40,000× (a sub-MB file → multi-GB → hard OOM); this is
also the dominant class the 1h ASan fuzz hit (159 `allocation-size-too-big` + 16 OOM artifacts, though
those came from count-driven ELF allocations, not this zstd path — the fuzz seeds carried no valid zstd
stream, so #1 here is a static find the fuzzer did not synthesize).

### A/B proof of the inconsistency (Zlib caps, Zstd doesn't)

The exact same ELF with only `ch_type` changed (ELFCOMPRESS_ZLIB vs ZSTD), both declaring `ch_size=64`
and both carrying a stream that expands to 200 MB:

```
ch_type = ZLIB : ok format=Elf, Maximum resident set size:   3072 kbytes   (~3 MB — Zlib CAPS at the reservation, errors)
ch_type = ZSTD : ok format=Elf, Maximum resident set size: 395944 kbytes   (~386 MB — Zstd GROWS past the cap)
```

Same attack, same structure — Zlib safely refuses at 3 MB (`decompress_vec` won't grow past the
reserved capacity), Zstd balloons to 386 MB. This is a genuine per-format inconsistency, not a
uniform "no cap" policy. (Verified empirically 2026-07-18; the `ch_type=ZLIB` PoC generator is
`make_poc.py` with the format byte switched.)

## Suggested fix

Bound the Zstandard decode to the reserved size like the Zlib branch does — e.g. decode through a
`Read::take(size as u64)` / a capacity-limited writer and error if the stream produces more than `size`,
before the buffer can grow past the reservation.

## Related findings (re-verified 2026-07-18)

- **Mach-O `exports_trie()` infinite loop — CONFIRMED (separate PoC).** The trie DFS follows child
  offsets with no visited-set / forward-progress / depth cap (verified by reading the source), so a node
  whose child edge points back to itself loops forever, growing `Vec<Frame>` unbounded. **Empirically
  reproduced**: a 52-byte Mach-O hangs `exports_trie()` (killed by `timeout`). Reachable via the
  **secondary** public `exports_trie()` API, **not** `File::parse` / `Object::exports()`. Full PoC:
  `../macho_exports_trie_loop/`.
- **PE `imports()` no count cap — code-confirmed, exploitability UNVERIFIED (do not over-claim).** The
  import walk has no cap and ignores the declared directory size (verified by reading
  `read/pe/file.rs` + `read/pe/import.rs`), so it *could* be quadratic via overlapping RVAs. **But** each
  pushed thunk calls `hint_name(thunk.address())`, which errors (aborting the whole `imports()`) unless
  the reinterpreted bytes point at a valid hint/name — so the O(S²) blow-up is not demonstrated and may
  be unachievable. Listed as a code-level observation only, **not** a confirmed finding. (No PoC.)
