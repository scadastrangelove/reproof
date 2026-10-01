# ISSUE — ntex websocket codec accepts fragmented control frames

**Title:** `ws::Codec` accepts fragmented `Ping`/`Pong` control frames instead of rejecting them

### Summary

Tested against `ntex 3.12.0` (latest crates.io release).

RFC 6455 §5.5 requires control frames to be non-fragmented (`FIN` MUST be set). `ntex::ws::Codec`
accepts a `Ping` or `Pong` frame with `FIN=0` and returns `Frame::Ping` / `Frame::Pong` instead of a
protocol error.

This is a protocol-conformance bug in a public decoder over untrusted wire bytes.

### Dynamic reproduction

Self-contained PoC: [docs/e13/poc/ntex-ws-fragmented-control.rs](../../../docs/e13/poc/ntex-ws-fragmented-control.rs)

Input frame:

- first byte `0x09` = `FIN=0`, opcode `Ping`
- second byte `0x80` = masked, zero-length payload
- 4-byte mask key

Observed result on `ntex 3.12.0`:

```text
ACCEPTED fragmented Ping as Frame::Ping(b"")
```

Expected result: protocol error / rejected frame.

### Root cause

In `ntex/src/ws/codec.rs`, the `fin == false` branch still accepts `OpCode::Ping` and `OpCode::Pong`
directly:

```rust
OpCode::Ping => Ok(Some(Frame::Ping(...)))
OpCode::Pong => Ok(Some(Frame::Pong(...)))
```

instead of rejecting fragmented control frames.

### Severity

Low — protocol-conformance / state-machine hardening issue. It is reachable from network input, but the
observable effect is incorrect acceptance of invalid frames rather than memory unsafety.

### Suggested fix

Reject `Ping`, `Pong`, and `Close` in the `FIN=0` branch with a protocol error, matching RFC 6455 §5.5.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
