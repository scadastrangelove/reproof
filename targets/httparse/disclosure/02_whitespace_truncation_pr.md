Fixes #222.

`ParserConfig::allow_space_before_first_header_name(true)` + a line consisting only of whitespace right
after the request/status-line silently dropped the entire header block: the parser returned
`Ok(Status::Complete)` with `headers == []`, leaving every real header (`Host`, `Content-Length`, ...)
unconsumed in the buffer.

### The fix

After stripping the leading whitespace run, peek at the next byte before deciding to continue:

```rust
match bytes.peek() {
    None => return Ok(Status::Partial),
    Some(b'\r') | Some(b'\n') => break 'header Error::HeaderName,
    _ => {}
}
```

- A whitespace-only line (next byte is `\r`/`\n`) now rejects with `Error::HeaderName` — the same error
  the non-leniency path already returns for a malformed first byte, rather than being silently absorbed
  as the terminating blank line.
- If there's no more data yet (`peek()` returns `None`), returns `Status::Partial` so the streaming/
  incremental case is unaffected — a caller that hasn't yet read the byte deciding whitespace-only vs. a
  real header isn't penalized.
- The documented, tested, non-degenerate case (space followed by a real header) is untouched.

### Tests added

- `test_allow_space_before_first_header_name_rejects_whitespace_only_line` — both request and response
  variants of the whitespace-only-line case now return `Err(HeaderName)` instead of silently truncating.
- `test_allow_space_before_first_header_name_partial_after_whitespace` — a buffer ending right after the
  whitespace run still returns `Status::Partial`, confirming the fix doesn't regress incremental parsing.

### Validation

- Full test suite: 99 → 101 tests, all green (`cargo test --release`).
- Existing `test_allow_response_response_with_space_before_first_header` (the documented non-degenerate
  case) unaffected.
- Manually re-verified both PoCs from the issue now return `Err(HeaderName)` instead of
  `Ok(Complete)`/`headers==[]`.

Found & fixed with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
