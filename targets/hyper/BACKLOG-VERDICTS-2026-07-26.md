# Backlog dynamic-verification verdicts (hyper 1.11.0 registry + h2 v0.4.15)

## G1 — h1 client TE+CL response reconciliation — CONFIRMED Low/hardening (mechanism sharpened)
- **Ingress:** hyper h1 *client* (`Client::decoder`, role.rs ~1259) frames the body by TE (chunked
  "hello", 5 bytes — no CL-truncation) BUT **surfaces the stale `content-length: 999` to the app**
  alongside `transfer-encoding: chunked`. The CL-removal I first read (role.rs:276-277/288-289) +
  multiple-CL-reject (293-300) live in **`Server::parse`** (incoming *requests*), NOT the client
  response path. Real client/server asymmetry vs RFC 9112 §6.1 (receiver should drop CL on TE).
- **Egress:** hyper h1 *server* **refuses to encode** the TE+CL response → `user sent unexpected header`,
  connection closed, nothing forwarded. **Fail-closed** — no pure-hyper proxy desync.
- **Verdict:** not retracted, not upgraded. Low/hardening; residual = app trusting the surfaced CL.
  Optional tiny hardening PR: strip CL from client-response headers when TE present (match Server).
- g1.rs (client surfaces CL:999 + body "hello"); g1_proxy.rs (egress "user sent unexpected header").

## N-CONNECT — hyper h1 server decodes a CONNECT body — CONFIRMED mis-framing, Low
- Dynamic: `CONNECT ... Content-Length: 5\r\n\r\nHELLO<tunnel>` → hyper 200, upgraded tunnel receives
  `"TUNNELDATA..."` — the leading 5 bytes ("HELLO") were **consumed as a request body**. hyper decodes a
  CL body on CONNECT (RFC 9110 §9.3.6: CONNECT has no defined payload).
- **Impact Low/deployment-specific:** a direct requester corrupts its OWN tunnel (self-harm); cross-hop
  smuggle only against a front-end that treats CONNECT as bodyless and disagrees on the boundary.
- **Verdict:** confirmed (real), Low/hardening. Legit hardening lead: hyper should reject a body on
  CONNECT. Not upgraded. (nconnect.rs)

## N-CL — h2 multiple/differing content-length — CONFIRMED Low (asymmetry real, CL-vs-DATA mitigates)
- Source: h2 recv.rs:179 `.get(CONTENT_LENGTH)` = FIRST value, no dup-differing rejection (vs h1
  Server::parse role.rs:293-300 which rejects). Asymmetry real.
- Dynamic: h2 accepts CL:20 then RSTs PROTOCOL_ERROR when DATA(3B)+END_STREAM ≠ CL (recv.rs:188-198 +
  dec_content_length + ensure_content_length_zero). **h2 enforces CL-vs-DATA** — the mitigating defense.
- Test artifact: frames::.field() dedups HeaderMap, so the wire carried one CL; genuine-dup wire would
  surface both to the app but h2 still enforces CL-vs-DATA against the first. Verdict: confirmed-Low,
  fail-closed for the practical desync. Not upgraded. (ncl.rs)

## N-PSEUDO — misplaced pseudo-headers — CONFIRMED Info, no impact
- Source: load_hpack (headers.rs:882-886) marks malformed (→RST) on pseudo-not-at-head AND repeated
  pseudo. So h2 rejects those, stronger than the "accept+drop" claim. Residual = wrong-direction pseudo
  (e.g. :status in a request), Info-level, neutralized by hyper typed re-encode. Not a finding.

## is_valid_trailer_field connection-family residual — CONFIRMED real, Low hardening (NEW concrete lead)
- Dynamic: hyper h1 reverse proxy re-emitted a backend's `connection: keep-alive` trailer on the wire
  (trailer section = `connection: keep-alive` + `x-keep: 1`). hyper's is_valid_trailer_field
  (encode.rs:264-280) denies transfer-encoding/te/content-length/... but NOT CONNECTION/UPGRADE/
  KEEP_ALIVE/PROXY_CONNECTION.
- Refines earlier "T-h1 CLOSED": closed for transfer-encoding, OPEN for the connection-family.
- Impact Low: needs backend to control the `Trailer:` declaration + value; a connection-header in a
  TRAILER is weakly honored. Hardening lead: add the connection-family to is_valid_trailer_field's
  deny-list. (trailer_residual.rs)

## ============ OVERALL ============
No RETRACTIONS, no UPGRADES to high-severity. Every backlog item held AND was dynamically confirmed;
the verification sharpened each mechanism and surfaced 3 concrete Low hyper-hardening leads, all in
hyper proto/h1, bundleable into ONE optional hyper hardening PR/issue if desired:
  (1) G1  — h1 client: strip Content-Length from a response when TE present (match Server::parse).
  (2) N-CONNECT — h1 server: reject a body on CONNECT (don't decode CL over the tunnel).
  (3) trailer-residual — add CONNECTION/UPGRADE/KEEP_ALIVE/PROXY_CONNECTION to is_valid_trailer_field.
N-CL and N-PSEUDO stay Low/Info (h2's CL-vs-DATA + load_hpack pseudo checks are the mitigating defenses).
The strong request-smuggling defenses (G2 refuted, TE+CL egress fail-closed, CL-vs-DATA enforced,
§8.2.2 on ingest) all re-confirmed working.
