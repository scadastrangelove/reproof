# actix-http — HTTP/1 framing / request-smuggling threat model

**Target:** `actix-http` (workspace `actix/actix-web`), h1 request decoder.
**Pin:** actix-web `main` @ `eee23e2326d1` (2026-07-20), the current HEAD.
**Class:** PROTOCOL-LOGIC — HTTP/1 request smuggling (HRS) / framing desync.
**Oracle:** differential — feed one byte stream to actix's h1 framing decoder and to an
RFC-9112-compliant reference; a disagreement on **body length / next-request boundary** is a
smuggling primitive. (Not a crash/panic oracle.)

## Why this target
- Own history: **RUSTSEC-2021-0081 / CVE-2021-38512** — "request smuggling due to lack of input
  validation" (HRS when behind a vulnerable front-end proxy). CVSS 7.5.
- Sibling seeds (variant analysis, "bugs travel in packs") from the 2026 Cloudflare Pingora
  cluster: **RUSTSEC-2026-0033** (premature Upgrade — forward bytes after `Upgrade` before a `101`)
  and **RUSTSEC-2026-0034** (HTTP/1.0 close-delimited bodies + multiple/mis-parsed
  `Transfer-Encoding`; fix = parse message length per RFC 9112).

## The code (actix-http/src/h1/decoder.rs @ eee23e2)
`MessageType::set_length` (the header loop, ~L80–L214) computes `PayloadLength`. Resolution order:
`chunked` > `has_upgrade_websocket` > `content_length` > `None`.
Existing hardening (do NOT re-report as novel):
- multiple `Content-Length` → `Err` (L101); `+`-prefixed CL → `Err` (L107); non-`u64` CL → `Err`.
- multiple `Transfer-Encoding` → `Err` (L130); non-chunked/identity TE value → `Err`.
- zero-length CL removed post-loop "to prevent request smuggling issues" (comment L114).

## Seed-anchored candidate patterns (source-level; must be dynamically confirmed via the oracle)
1. **HTTP/1.0 + `Transfer-Encoding: chunked` → body desync** *(sibling RUSTSEC-2026-0034).*
   The TE-processing arm is guarded by `version == Version::HTTP_11` (L135). For an HTTP/1.0
   request, `TE: chunked` matches no TE arm → `chunked` stays false; with no CL the request
   resolves to `PayloadLength::None` (empty body). The chunked body bytes then remain in the buffer
   and are decoded as the **next request**. Desync vs any front-end that honors TE on 1.0 (or on a
   1.1→1.0 downgrade). **Looks live at HEAD.** Confirm: (a) actix reads empty body; (b) dispatcher
   keeps the connection alive after a 1.0 request with `Connection: keep-alive` and parses the
   trailing bytes as a new request; (c) an RFC-9112 parser would frame it as a chunked body.
2. **`TE: chunked` + `Content-Length` coexistence** *(class RUSTSEC-2021-0081).*
   Both present is not rejected: `chunked` wins for actix's framing, but the `Content-Length`
   header is retained in the `HeaderMap` (RFC 9112 §6.1 requires removing it or erroring). Desync
   vs a front-end/backend that prefers CL. Confirm the CL header survives on the parsed request and
   that actix frames by TE.
3. **`TE: identity` silent-allow** (L140). A non-RFC-9112 transfer coding is accepted with no body
   framing effect (`chunked` stays false). Explore combinations (`identity` + CL; `identity` where
   a peer treats any TE presence as chunked) for a desync.

## Oracle / harness plan
Differential decoder harness depending on `actix-http` @ pin, driving the **public** `h1::Codec`
(`tokio_util::codec::Decoder`) over crafted byte buffers:
- report, per input: resolved body-framing mode, bytes consumed for request 1, and whether a
  second `Message::Item` (a smuggled request) is decoded from the remainder.
- reference side: an RFC-9112 framing oracle (or httparse + explicit length rules) over the same
  bytes; **finding = framing disagreement on the request-2 boundary.**
- canary/control first: (a) a compliant `1.1 + TE: chunked` request must frame identically both
  sides (no FP); (b) the 2021-0081 fixed patterns (multiple CL/TE) must be rejected by actix
  (proves the harness sees current hardening) before trusting any positive.

## Reachability notes
actix-http is primarily an **origin** server, not a proxy — HRS here needs a front-end proxy that
disagrees with actix on framing (the 2021-0081 model). Rate severity by that: a desync exploitable
only behind a mis-parsing proxy is Medium-ish (matches 2021-0081's own framing), not a standalone
RCE. State this honestly in any disclosure; do not inflate to proxy-grade CVSS without a proxy in
the loop.
