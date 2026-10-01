# gimli — quadratic-time DIE attribute parsing via zero-byte forms (CWE-407 DoS)

- **Crate:** `gimli` 0.34.0 (and `master`, HEAD 843c38e — verified). **Class:** algorithmic-complexity
  DoS (CWE-407), memory-safe (CPU/wall-clock only).
- **Severity:** Low–Medium (availability). Reachable by any consumer that walks the DIE tree of an
  untrusted binary: addr2line, `backtrace` (Rust panic backtraces), debuggers, profilers, CI scanners.
- **Site:** `src/read/unit.rs:2442` (`EntriesRaw::read_attributes`).

## Mechanism

Parsing a DIE eagerly constructs one `Attribute` per attribute declared in its abbreviation. Two forms —
`DW_FORM_flag_present` and `DW_FORM_implicit_const` — consume **zero** bytes of `.debug_info` (the former
is always `true`; the latter's value lives in the abbrev). So a single abbreviation can declare **K** such
attributes (~2 bytes each in `.debug_abbrev`), and every DIE that references it costs just **1 byte** in
`.debug_info` yet yields **K** `Attribute`s.

`read_attributes` does `attrs.reserve(specs.len())` then pushes one `Attribute` per spec with no cap.
Walking **D** such DIEs (the caching `entries()` cursor) therefore performs **D × K** attribute
constructions — the product of two independently attacker-controlled section sizes, each bounded only by
its section length → **Θ(input²)** from a tiny input. Memory stays bounded (the cursor reuses the
attribute buffer), so it is a CPU/wall-clock DoS.

## Measured (master HEAD 843c38e; K=2000 fixed, D varied)

| input | attribute parses (D×K) | time |
|---|---|---|
| 26 KB  | 40 M  | 0.40 s |
| 46 KB  | 80 M  | 0.78 s |
| 86 KB  | 160 M | 1.56 s |
| 166 KB | 320 M | 3.18 s |

Scaling both sections: ~1 MB → minutes, ~10 MB → hours. `quad_driver.rs` builds the sections + walks +
times (self-contained, gimli public API).

## Fix directions (a judgment call — no clean one-liner, zero-byte forms are legitimate)

- Cap total attributes parsed per unit against the section length; or
- a `set_max_attributes`-style resource limit mirroring the existing `set_max_iterations` (which is
  documented "to avoid denial of service attacks by bad DWARF bytecode"); or
- document `entries_raw()` as the untrusted-input path.
