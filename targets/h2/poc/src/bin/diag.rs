// Diagnostic: a NON-reading native h2 client is sent far more DATA than its advertised receive
// window. Does it (a) auto-release the window (emit WINDOW_UPDATEs -> no backpressure by design),
// (b) enforce the window (GOAWAY/RST FLOW_CONTROL_ERROR), or (c) silently accept beyond-window data
// (a real bug)? This settles whether finding D has any residue.
use futures::StreamExt;
use h2::frame::Frame;
use h2_support::prelude::*;
use std::time::Duration;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let (io, mut srv) = mock::new_with_write_capacity(1 << 20);

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let client = tokio::spawn(async move {
        let (mut client, conn) = client::handshake(io).await.expect("h2 handshake");
        let ch = tokio::spawn(async move { let _ = conn.await; });
        let req = Request::get("https://example.com/").body(()).unwrap();
        let (resp, _s) = client.send_request(req, true).unwrap();
        let response = resp.await.expect("response");
        let _body = response.into_body(); // hold, never read, never release_capacity
        let _keep = (_body, client);
        let _ = stop_rx.await;
        ch.abort();
    });

    let settings = srv.assert_client_handshake().await;
    println!("client SETTINGS: initial_window_size = {:?}", settings.initial_window_size());
    // request
    let id = loop {
        match srv.next().await {
            Some(Ok(Frame::Headers(h))) => break h.stream_id(),
            Some(Ok(_)) => continue,
            other => panic!("no request: {other:?}"),
        }
    };
    srv.send_frame(frames::headers(id).response(200)).await;

    // Send 64 frames of 16 KiB = 1 MiB of body — ~16x the default 65535 connection/stream window.
    let payload = vec![0u8; 16 * 1024];
    for _ in 0..64 {
        srv.send_frame(frames::data(id, &payload[..])).await;
    }
    println!("sent 64 x 16KiB = 1 MiB of DATA to a non-reading client (window is 65535)");

    // Read what the client emits for 800 ms.
    let mut window_update_conn = 0u64;
    let mut window_update_stream = 0u64;
    let mut wu_bytes = 0u64;
    let mut goaway = false;
    let mut reset = false;
    let deadline = tokio::time::sleep(Duration::from_millis(800));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            f = srv.next() => match f {
                Some(Ok(Frame::WindowUpdate(wu))) => {
                    wu_bytes += wu.size_increment() as u64;
                    if wu.stream_id().is_zero() { window_update_conn += 1; } else { window_update_stream += 1; }
                }
                Some(Ok(Frame::GoAway(_))) => { goaway = true; break; }
                Some(Ok(Frame::Reset(_))) => { reset = true; }
                Some(Ok(_)) => {}
                _ => break,
            }
        }
    }
    let _ = stop_tx.send(());
    let _ = client.await;

    println!("\n== client reaction to 1 MiB over a 65535 window ==");
    println!("  WINDOW_UPDATE (conn):   {window_update_conn}");
    println!("  WINDOW_UPDATE (stream): {window_update_stream}");
    println!("  WINDOW_UPDATE bytes:    {wu_bytes}");
    println!("  GOAWAY (FLOW_CONTROL?): {goaway}");
    println!("  RST_STREAM:             {reset}");
    if wu_bytes >= 900_000 {
        println!("  => AUTO-RELEASE: the client hands back ~all the window without the app reading -> no");
        println!("     effective flow-control backpressure for a non-reading app (payload or zero-length).");
    } else if goaway {
        println!("  => ENFORCED: the client FLOW_CONTROL_ERRORs the overrun -> payload IS bounded; then a");
        println!("     zero-length flood (which never touches the window) is the real bypass.");
    } else {
        println!("  => Neither clean auto-release nor GOAWAY; inspect.");
    }
}
