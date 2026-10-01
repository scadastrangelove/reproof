# ISSUE — gimli: `.debug_aranges` consecutive null tuples recurse until stack overflow

**Title:** `ArangeEntry::parse` stack-overflows on consecutive `(0,0)` `.debug_aranges` tuples

### Summary

Tested against `gimli 0.34.0` (current crates.io release).

`ArangeEntry::parse` recurses on every null tuple `(address=0, length=0)` in `.debug_aranges` and has no
depth cap or iterative loop. A crafted DWARF section containing a long run of consecutive null tuples
causes stack exhaustion and process abort when a consumer iterates aranges entries.

This is reachable from ordinary public read APIs: a real ELF object file can be parsed with
`object::File::parse`, the `.debug_aranges` section extracted, and then `gimli::DebugAranges` iteration
overflows the stack in `header.entries().next()`.

### Dynamic reproduction

Self-contained PoC: [docs/e13/poc/gimli-elf.rs](../../../docs/e13/poc/gimli-elf.rs)

What it does:

- builds a real ELF object with a malicious `.debug_aranges` section,
- parses it through `object::File::parse`,
- extracts `.debug_aranges`,
- constructs `gimli::DebugAranges`,
- calls `header.entries().next()` on a 256 KB stack thread.

Observed result on `gimli 0.34.0`:

```text
wrote real ELF: /tmp/malicious.o (3200472 bytes)
parsed ELF, .debug_aranges = 3200016 bytes; iterating via gimli...
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

### Root cause

`src/read/aranges.rs:355` handles a null entry by recursively calling `Self::parse` on the remaining data
instead of iterating. A long run of null tuples therefore creates one Rust stack frame per tuple.

### Severity

Medium — uncatchable stack-overflow DoS from untrusted DWARF bytes. This is availability-only, but it is
reachable through real consumer flows such as DWARF inspection / symbolization over attacker-controlled
ELF objects.

### Distinct from existing reports

This is not the already-filed `read_attributes` quadratic-DIE issue ([gimli#898](https://github.com/gimli-rs/gimli/issues/898)).
That report is an algorithmic CPU blowup in `.debug_info`; this one is a stack-overflow in `.debug_aranges`.

### Suggested fix

Replace the recursive skip-over-null-entry logic with an iterative loop, or enforce a depth/entry budget
while consuming consecutive null tuples.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
