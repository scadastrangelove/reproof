# ISSUE — httparse: `allow_space_before_first_header_name` silently truncates the whole header block on a whitespace-only line

**Title:** `ParserConfig::allow_space_before_first_header_name` silently drops all headers when the first header line is whitespace-only

### Summary

With `allow_space_before_first_header_name(true)` enabled, a line consisting **only of whitespace**
immediately after the request/status-line is silently treated as the blank line that ends the header
section — the parser returns `Ok(Status::Complete(n))` with `headers == []`, and every real header that
follows (`Host`, `Content-Length`, etc.) is left **unconsumed** in the buffer, for a caller to potentially
misinterpret as body bytes or the start of a smuggled second request.

### Where

`parse_headers_iter_uninit` (`src/lib.rs`), in the `allow_space_before_first_header_name` branch:

```rust
if config.allow_space_before_first_header_name
    && autoshrink.num_headers == 0
    && (b == b' ' || b == b'\t')
{
    //advance past white space and then try parsing header again
    while let Some(peek) = bytes.peek() {
        if peek == b' ' || peek == b'\t' {
            next!(bytes);
        } else {
            break;
        }
    }
    bytes.slice();
    continue 'headers;   // <-- re-enters the outer loop with no check of what follows
}
```

After stripping the leading whitespace run, this unconditionally `continue`s the outer `'headers` loop.
If the very next byte is `\r` or `\n` — i.e. the "header line" was whitespace-only, not "whitespace + a
real header" — the outer loop's own terminator check (a few lines above, `if b == b'\r' { ... return
Complete }` / `if b == b'\n' { ... return Complete }`) fires on the next iteration and reports the head as
fully, successfully parsed, with `num_headers` still `0`.

The crate's own doc comment and its only test for this flag
(`test_allow_response_response_with_space_before_first_header`) exclusively cover the intended,
non-degenerate shape ("space then a real header follows" — a curl-issue-11605 browser-compat workaround);
neither ever exercises a whitespace-only line, so this gap was never caught.

### PoC (confirmed on current master, commit `a0fa552`)

```rust
use httparse::{Request, Response, EMPTY_HEADER, ParserConfig};

// Request side
let buf: &[u8] = b"GET / HTTP/1.1\r\n \r\nHost: example.com\r\n\r\n";
let mut headers = [EMPTY_HEADER; 16];
let mut req = Request::new(&mut headers);
let r = ParserConfig::default().allow_space_before_first_header_name(true).parse_request(&mut req, buf);
// r == Ok(Status::Complete(19)), req.headers == []
// buf[19..] == "Host: example.com\r\n\r\n"  <-- never parsed, left in the buffer

// Response side, same shape
let buf2: &[u8] = b"HTTP/1.1 200 OK\r\n \r\nContent-Length: 500\r\n\r\n";
let mut headers2 = [EMPTY_HEADER; 16];
let mut resp = Response::new(&mut headers2);
let r2 = ParserConfig::default().allow_space_before_first_header_name(true).parse_response(&mut resp, buf2);
// r2 == Ok(Status::Complete(20)), resp.headers == []
// Content-Length silently vanishes
```

Control (flag off, identical buffer): `Err(HeaderName)` — confirms this is specifically a gap introduced
by the leniency branch, not baseline behavior. Documented non-degenerate shape (flag on, `" Host:
example.com\r\n\r\n"`): parses correctly (`headers == ["Host"]`) — confirms the bug is isolated to the
untested whitespace-only edge case.

### Impact

Requires the opt-in `allow_space_before_first_header_name` flag (off by default; a `gh search code`
across GitHub found no uses of this flag outside httparse's own source/docs — hyper does not enable it).
Not a default-vulnerable-out-of-the-box issue, but a real footgun for any consumer who follows the crate's
own documented example and encounters this edge case: a framing-critical header silently disappearing
from the parsed result while its bytes remain in the buffer is the classic precondition for a
request/response-smuggling desync between two nodes that disagree on where the head ends.

### Fix

I have a fix + 2 regression tests ready (PR incoming): after stripping the whitespace run, peek at the
next byte before continuing — if it's `\r`/`\n` (whitespace-only line), reject with the same
`Error::HeaderName` the non-leniency path already uses; if there's no more buffered data yet, return
`Status::Partial` (preserves streaming/incremental correctness). The documented non-degenerate case is
unaffected. Full existing test suite (99 → 101 tests) passes.

Found by the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
