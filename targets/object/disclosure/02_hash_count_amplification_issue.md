# ISSUE — object: tiny ELF with forged `.hash` count breaks `Builder::write` layout

**Title:** `Builder::read` accepts absurd `.hash` `bucket_count`, then `Builder::write` fails on a tiny ELF with an inflated reserved layout

Tested against object **0.39.1**.

### Bug

`object::build::elf::Builder::read()` trusts the SysV `.hash` header's `bucket_count` from the input ELF.
On a tiny crafted ELF this is enough to inflate the builder's internal rewrite layout far beyond the original
file structure, even though the input file itself is only 704 bytes long.

With `bucket_count = 33_554_432`, the parsed builder reports:

- `builder.hash_bucket_count = 33554432`
- `builder.hash_size() = 134217744`

Then a normal `Builder::write(...)` on the same parsed object fails with:

```text
Unsupported sh_offset value 0xd0 for section '.dynamic', expected at least 0x80000c8
```

So the write path is already materially affected by the attacker-controlled count: the rewritten `.hash`
layout expands enough that preserving the original `.dynamic` offset becomes impossible.

### Reproducer

The attached PoC uses only the public API:

```rust
let builder = Builder::read(elf.as_slice()).unwrap();
println!("{}", builder.hash_bucket_count);
println!("{}", builder.hash_size());
let mut out = ProbeBuffer::default();
println!("{:?}", builder.write(&mut out));
```

Observed output on `0.39.1`:

```text
tiny ELF size             = 704 bytes
builder.hash_bucket_count = 33554432
builder.hash_size()       = 134217744 bytes
write reserve(size)       = None
Builder::write() error    = Unsupported sh_offset value 0xd0 for section '.dynamic', expected at least 0x80000c8
```

The important property here is not “large allocation happened on my machine”, but that a tiny untrusted ELF
is accepted and immediately perturbs the rewrite layout by ~128 MiB solely via a forged header count.

### Why this seems wrong

The `.hash` section body in the input is tiny: just the header plus one bucket and two chain entries. But the
builder does not cross-check the claimed `bucket_count` against the actual section extent before using it in
size/layout calculations for the rewrite path.

That makes the count field act as an amplification knob for any consumer that does:

`Builder::read(untrusted ELF)` -> `Builder::write(...)`

### Fix direction

I think the simplest fix is to reject inconsistent `.hash` metadata early, either:

- during `Builder::read()`, by validating that the claimed bucket/chain counts fit in the section body, or
- before rewrite-size computation, by refusing absurd/inconsistent `.hash` counts instead of feeding them into
  `hash_size()` / section reservation logic.

### Severity

Low — this is a write-path denial-of-service / hard failure on untrusted ELF input, not memory corruption.
But it does seem maintainer-actionable because the public rewrite path accepts a tiny malformed object and lets
attacker-controlled metadata drive large internal layout expectations.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
