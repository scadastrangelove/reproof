# GHSA — actix-multipart field stream hangs forever after EOF on truncated boundary prefix

**Title:** `Field::next()` hangs indefinitely after EOF on a truncated boundary prefix

### Summary

Tested against `actix-multipart 0.8.0` (current crates.io release).

If a field body ends with a truncated CR-boundary prefix (e.g. `\r\n-`) and the transport then reaches
EOF, the field stream does not resolve to `Error::Incomplete` or `None`. Instead, `Field::next()` stays
`Pending` forever — no waker will fire because the underlying stream is already exhausted.

The attacker can disconnect immediately after sending the truncated body. The handler task remains
wedged indefinitely with zero ongoing attacker effort.

### Dynamic reproduction

Verified 2026-08-06 against the exact published crate (`~/.cargo/registry/.../actix-multipart-0.8.0`,
not just the git repo), through three independent reproductions.

**Instance 1 — unit-level PoC** (direct API): [docs/e13/poc/actix-multipart-cr-hang.rs](../../../docs/e13/poc/actix-multipart-cr-hang.rs)

```text
first chunk = b"data\r\n"
TIMEOUT: field.next() stayed pending after EOF on truncated CR-boundary
```

**Instance 2 — separate code path, unit-level PoC**: [docs/e13/poc/actix-multipart-cr-hang-instance2.rs](../../../docs/e13/poc/actix-multipart-cr-hang-instance2.rs)

Uses a realistic 10-character boundary (`abcdefghij`) so the truncated suffix lands in the
early-boundary-check branch (field.rs:316-317) instead of the main-loop branch (field.rs:334) —
confirming this is a second, independently-triggerable site, not a restatement of instance 1:

```text
first chunk = b"DATA"
TIMEOUT: field.next() stayed pending -- Instance 2 CONFIRMED (line 316-317, distinct from line 334)
```

**End-to-end verification** through the real actix-web HTTP stack (actix-web 4.14.0 / actix-http
3.13.1, 1-worker server, `POST /upload` with a multipart handler):

1. Normal request → handler enters, processes field, exits. `200 OK` in ~350µs.
2. Attack request: truncated `\r\n-` body, then the client **immediately** closes the TCP
   connection with `SO_LINGER(0)` (sends RST, not a graceful FIN — the strongest "attacker is
   fully gone" signal the OS can produce). Measured time from write to RST: **23.7µs**.
3. Second normal request → still works (server not crashed; only the one handler is affected).
4. Server monitor polled every 2s for **30 seconds after the RST**: `stuck=1` on every single
   sample. The handler is never released.

This rules out the objection "the hang is just as long as the client stays connected" — the
client's socket ceased to exist in 24 microseconds, and the server-side task was still parked
30 seconds later with no sign of ever resolving.

### Root cause

Two instances of the same bug in `InnerField::read_stream`:

**Instance 1 (primary):** In the main loop, when the residual buffer starts with `\r` and
`cur + 4 > len` (i.e. fewer than 4 bytes remain), the code returns `Poll::Pending` without
checking `payload.eof`. The sibling `len == 0` branch correctly converts EOF-with-no-data
into `Error::Incomplete`, but this branch does not:

```rust
// len == 0 branch (correct):
if len == 0 {
    return if payload.eof {
        Poll::Ready(Some(Err(Error::Incomplete)))  // ← handles EOF
    } else {
        Poll::Pending
    };
}

// ...in the loop, when cur + 4 > len (BUGGY):
if cur + 4 > len {
    // ...
    return Poll::Pending;  // ← no payload.eof check
}
```

**Instance 2:** The early boundary check (`len > 4 && buf[0] == b'\r'`) has the same pattern:

```rust
if len < b_size {
    return Poll::Pending;  // ← also no payload.eof check
}
```

This triggers when the buffer has >4 bytes containing a valid boundary prefix but fewer
bytes than the full boundary size. A slightly longer truncated body hits this path.

No waker will fire after either return: `poll_stream` re-polls the exhausted stream, which
returns `None` again and sets `eof = true`, but the eof flag is never checked in these
branches.

### Severity

**Medium** — remotely triggerable per-connection-slot DoS, cheaper than classic slowloris.

**No framework timeout bounds this hang** (verified by reading `actix-web` 4.14.0's own doc
comments, not inferred):

| Timeout | Default | What it actually covers (per its own doc comment) |
|---|---|---|
| `client_request_timeout` | 5000ms | "reading client request **head**" only — the request head (headers) is already fully read by the time our handler is invoked, so this has already elapsed harmlessly |
| `client_disconnect_timeout` | 1000ms | "connection **shutdown**" procedure — traced in `actix-http` 3.13.1's `h1/dispatcher.rs`: this deadline (`client_disconnect_deadline`/`enter_linger`) is only consulted in the `SendPayload`/`SendErrorPayload` states, i.e. **after** a response has already been sent. It never fires while stuck in `ServiceCall` (our handler, still pending) |
| `tls_handshake_timeout` | 3000ms | TLS handshake only; not applicable to body parsing (and not applicable at all over plaintext) |
| `shutdown_timeout` | — | graceful **worker** shutdown drain, unrelated to a single request |

The connection isn't force-closed on disconnect either: `h1_allow_half_closed` defaults to
**`true`** (`actix-http` 3.13.1 `config.rs:168,193` / `builder.rs:52`), and the dispatcher's
`READ_DISCONNECT`-triggered shutdown only fires when `state_is_none` — i.e. when there is no
in-flight `ServiceCall`. While our handler is wedged, `state_is_none` is false, so the
dispatcher takes no action on the peer's RST. This is exactly what the end-to-end test
observed: RST at t=23.7µs, still stuck 30s later.

`actix_multipart::MultipartConfig` (the crate's own extractor config) has exactly one knob,
`buffer_limit` (bytes, default 64 KiB) — no timeout option exists at the multipart-crate level
either. A ~70-byte truncated body never approaches this limit.

- **Cost asymmetry, verified at three independent layers**, not just inferred from source:
  1. *Future-level* (application instrumentation): the handler's own entry/exit counters show
     it never exits, for the full 30s observation window (above).
  2. *OS fd-level* (`lsof` on the live server process): 18s after the RST, the connection's
     file descriptor is still allocated to the process — `TCP localhost:19998->...  (CLOSED)`.
     The OS has fully torn down the TCP state; the server process still holds the fd because
     nothing ever calls `close()` on it.
  3. *Source-level*: `actix-server` 2.7.0's worker accepts a connection by creating a
     `WorkerCounterGuard` (RAII, decrements `max_concurrent_connections` on `Drop`) and moving
     it **into** the per-connection service future itself (`worker.rs:695-699`,
     `let guard = this.counter.guard(); ...service.call((guard, msg.io))`). The guard is only
     dropped when that future completes. Our future never completes, so the guard is never
     dropped, so the slot is never freed.
  
  Net effect: attacker sends one ~70-byte request and one RST (measured **23.7µs** of
  attacker-side work) and permanently consumes one of `max_connections`
  (`actix-server` 2.7.0 default: **25,600 per worker**, `worker.rs:256`). This is cheaper than
  classic slowloris, which requires the attacker to keep a socket open for the duration of the
  attack.
- **Per-connection resource hold:** each stuck handler holds its request state, partially-parsed
  multipart data, a tokio task, an unclosed file descriptor, and one `max_connections` slot,
  indefinitely.
- **Multiplied by endpoints:** any route using the `Multipart` extractor is affected.
- **Mitigating:** the server continues serving other requests on other connections (not a full
  crash); only multipart endpoints are affected; application-level `tokio::time::timeout`
  wrapped around `field.next()` calls would work around it, but the framework provides no such
  default and it is not standard practice in example code or tutorials.

### Suggested fix

In both `Poll::Pending` return sites within `read_stream`, check `payload.eof` first:

```rust
if payload.eof {
    return Poll::Ready(Some(Err(Error::Incomplete)));
}
return Poll::Pending;
```

This matches the existing pattern in the `len == 0` branch.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
