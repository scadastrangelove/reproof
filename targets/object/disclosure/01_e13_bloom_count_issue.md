# ISSUE — object: `Builder::write` panics when `.gnu.hash` has `bloom_count == 0`

**Title:** `write_gnu_hash` panics on `bloom_count == 0` (subtract-with-overflow then OOB index)

Tested against object **0.39.1** (current crates.io release).

### Bug

`build/elf.rs:1433` guards `bucket_count == 0` but not `bloom_count == 0`. When `bloom_count` is 0
and there are dynamic symbols to hash, `write_gnu_hash` (writer.rs:1484) computes
`bloom_count - 1` which panics on u32 subtraction overflow (debug), or wraps to `0xFFFFFFFF` and
OOB-indexes into the empty `bloom_filters` vec (release).

```
build/elf.rs:1433:  if self.gnu_hash_bucket_count == 0 { return Err(...) }
                    // no bloom_count == 0 check
build/elf.rs:1439:  self.gnu_hash_bloom_count,  // passed through as-is

writer.rs:1481:     let mut bloom_filters = vec![0; bloom_count as usize];  // empty
writer.rs:1484:     bloom_filters[((h / 64) & (bloom_count - 1)) as usize]  // underflow + OOB
```

### PoC

A 704-byte ELF64 with `.gnu.hash` header `bloom_count=0`, one dynamic symbol, and a PT_LOAD segment:

```toml
# Cargo.toml
[dependencies]
object = { version = "=0.39.1", features = ["build", "elf", "read", "write", "std"] }
```

```
$ cargo run
Builder::read()...
  OK: gnu_hash_bloom_count = 0
Builder::write()...
  thread panicked at 'attempt to subtract with overflow', writer.rs:1484
```

Full self-contained reproducer (~170 lines, builds a 704-byte ELF64 inline) available on request.

Reachable via `Builder::read` → `Builder::write` on any untrusted ELF (e.g. object-rewrite consumers).

### Fix

Add the same guard as `bucket_count`:

```rust
// build/elf.rs, after the bucket_count == 0 check at line 1433
if self.gnu_hash_bloom_count == 0 {
    return Err(Error::new(".gnu.hash bloom count is zero"));
}
```

### Severity

Low — panic/DoS on the write path, requires an untrusted ELF to flow through `Builder::read` → `write`.

### Context

Distinct from #950 (Zstd cap bypass) and #952 (exports-trie DoS). This is a missing input-validation
guard in the ELF builder, same pattern as the existing `bucket_count == 0` check one line above.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
