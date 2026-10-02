// riptarget — pipeline driver for the h2 target.
//
// Reads a file of raw bytes and plays them as a malicious SERVER's HTTP/2 frame
// stream to a default-config native h2 client (h2::client::handshake, all
// defaults) over an in-memory duplex channel. The exchange is:
//
//   client: preface + SETTINGS + HEADERS(GET /, END_STREAM)
//   driver: SETTINGS + SETTINGS-ACK + HEADERS(:status 200, stream left open)
//   driver: <input file bytes, verbatim — every subsequent frame on the wire>
//
// A panic anywhere in the process (e.g. an assert in the client's connection /
// stream state machine while processing those bytes) exits 101 via the panic
// hook = a finding. A graceful protocol error (GOAWAY / RST / conn error) is
// correct handling and exits 0.
//
// The input format is literally the wire format: 9-byte frame header
// (24-bit length, type, flags, 31-bit stream id) + payload, frame after frame.
// HPACK header blocks are the caller's responsibility.

use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 1 << 20;

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
}

async fn read_frame(s: &mut DuplexStream) -> Option<Frame> {
    let mut hdr = [0u8; 9];
    s.read_exact(&mut hdr).await.ok()?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    if len > MAX_FRAME {
        return None;
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await.ok()?;
    Some(Frame {
        ty: hdr[3],
        flags: hdr[4],
        stream: u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]),
    })
}

async fn write_frame(
    s: &mut DuplexStream,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len();
    let hdr = [
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
        ty,
        flags,
        ((stream >> 24) & 0x7f) as u8,
        ((stream >> 16) & 0xff) as u8,
        ((stream >> 8) & 0xff) as u8,
        (stream & 0xff) as u8,
    ];
    s.write_all(&hdr).await?;
    s.write_all(payload).await
}

/// Returns a verdict string; a crash never returns (the hook exits 101).
async fn drive(bytes: &[u8]) -> &'static str {
    let (client_io, mut srv) = duplex(1 << 20);

    // Default-config native h2 client (server push stays enabled — the h2 default).
    let client = tokio::spawn(async move {
        let (mut client, conn) = match h2::client::handshake(client_io).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[client] handshake error: {e:?}");
                return;
            }
        };
        let conn_task = tokio::spawn(async move {
            match conn.await {
                Ok(()) => eprintln!("[client] conn closed cleanly"),
                Err(e) => eprintln!("[client] conn error: {e}"),
            }
        });
        let req = http::Request::get("https://example.com/").body(()).unwrap();
        match client.send_request(req, true) {
            Ok((resp, _send)) => match resp.await {
                Ok(r) => eprintln!("[client] got response: {:?}", r.status()),
                Err(e) => eprintln!("[client] response error: {e}"),
            },
            Err(e) => eprintln!("[client] send_request error: {e}"),
        }
        // Keep the connection alive so post-response frames are still processed.
        tokio::time::sleep(Duration::from_secs(10)).await;
        conn_task.abort();
    });

    // --- server side of the wire ---
    let mut preface = vec![0u8; PREFACE.len()];
    if srv.read_exact(&mut preface).await.is_err() || preface != PREFACE {
        return "reject: bad/missing client preface";
    }
    // Read client frames until its request HEADERS arrives; answer SETTINGS.
    let request_stream = loop {
        let f = match read_frame(&mut srv).await {
            Some(f) => f,
            None => return "reject: eof before client request",
        };
        match f.ty {
            0x4 if f.flags & 0x1 == 0 => {
                // Client SETTINGS -> our (empty) SETTINGS + ACK of theirs.
                if write_frame(&mut srv, 0x4, 0x0, 0, &[]).await.is_err() {
                    return "reject: write server settings";
                }
                if write_frame(&mut srv, 0x4, 0x1, 0, &[]).await.is_err() {
                    return "reject: write settings ack";
                }
            }
            0x1 => break f.stream, // HEADERS = the client's request
            _ => {}                // WINDOW_UPDATE / PRIORITY / ... — ignore
        }
    };
    // 200 OK (HPACK indexed :status=200 == 0x88); stream left open (no END_STREAM).
    if write_frame(&mut srv, 0x1, 0x4, request_stream, &[0x88])
        .await
        .is_err()
    {
        return "reject: write response";
    }

    // The untrusted bytes: every subsequent frame the "server" sends, verbatim.
    if srv.write_all(bytes).await.is_err() {
        return "reject: write attack bytes";
    }
    let _ = srv.flush().await;

    // Let the client chew on it. A panic fires the hook and we never get here.
    tokio::time::sleep(Duration::from_secs(3)).await;
    client.abort();
    "done: no crash"
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("CRASH(panic): {info}");
        std::process::exit(101);
    }));
    let path = std::env::args().nth(1).expect("usage: riptarget <input-file>");
    let bytes = std::fs::read(&path).expect("read input");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let verdict = rt.block_on(drive(&bytes));
    println!("{verdict}");
}
