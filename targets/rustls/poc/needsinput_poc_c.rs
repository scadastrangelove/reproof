// Dynamic PoC for Finding C: NeedsInput::process() silently discards the first post-handshake
// ApplicationData record when it arrives co-batched with the client's final handshake flight.
// Follows rustls-test's own test_full_server_handshake pattern (a real classic ClientConnection
// driving the sans-IO ServerHandshake/NeedsInput/Accepted server API), pinned bd9f7f59aa79.
//
// Two branches, same construction, differing only in batching:
//   CONTROL: Finished flight and first request fed to the server as two SEPARATE process() calls
//            -> the request must be delivered via SplitConnection::receive.read().
//   ATTACK:  Finished flight and first request concatenated into ONE buffer, fed as a single
//            process() call -> the request should vanish (per the finding).
use std::io::Write as _;
use std::sync::Arc;

use rustls::server::ServerHandshake;
use rustls::split::ReceiveTrafficState;
use rustls::{Connection, SliceInput, VecInput};
use rustls_ring::DEFAULT_PROVIDER;
use rustls_test::{KeyType, make_client_config, make_server_config, server_name};

/// Drive a full handshake up to (but not including) the client's final flight.
/// Returns (client, server_still_needing_input, client_final_flight_bytes).
fn handshake_up_to_final_flight() -> (rustls::ClientConnection, rustls::server::NeedsInput, Vec<u8>) {
    let provider = DEFAULT_PROVIDER;
    let client_config = Arc::new(make_client_config(KeyType::Ed25519, &provider));
    let mut client = client_config
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();

    let receive = ServerHandshake::start();
    let mut acceptor_input = VecInput::default();
    acceptor_input.read(&mut buf.as_slice()).unwrap();

    let mut server_output = vec![];
    let ServerHandshake::Accepted(accepted) = receive
        .process(&mut acceptor_input, &mut server_output)
        .unwrap()
    else {
        panic!("unexpected state after ClientHello");
    };
    let server = accepted
        .choose_config(
            Arc::new(make_server_config(KeyType::Ed25519, &provider)),
            &mut server_output,
        )
        .unwrap();
    let ServerHandshake::NeedsInput(server) = server else {
        panic!("unexpected state after choose_config");
    };

    // client receives server's flight (Certificate/ServerHello/etc), computes and buffers its
    // own final flight (Finished) -- write_tls() here yields exactly that final flight.
    let mut server_flight = server_output.concat();
    client
        .process_new_packets(&mut SliceInput::new(&mut server_flight))
        .unwrap();
    let mut client_final_flight = vec![];
    client.write_tls(&mut client_final_flight).unwrap();

    (client, server, client_final_flight)
}

fn control_separate_calls() {
    println!("==== CONTROL: Finished flight and first request fed as two SEPARATE process()/read() calls");
    let (mut client, server, mut client_final_flight) = handshake_up_to_final_flight();

    // Step 1: feed ONLY the Finished flight -- nothing co-batched.
    let mut server_output = vec![];
    let ServerHandshake::Complete(split) = server
        .process(&mut SliceInput::new(&mut client_final_flight), &mut server_output)
        .unwrap()
    else {
        panic!("unexpected state after client's final flight alone");
    };
    println!("  server reached Complete after the Finished-only call");

    // Step 2: the SAME kind of client-queued request as the attack case, but fed as its own,
    // separate read() call -- this is the control: identical request construction, only the
    // batching differs.
    client
        .writer()
        .write_all(b"GET /control HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut request_flight = vec![];
    client.write_tls(&mut request_flight).unwrap();
    println!("  separate request flight: {}B, fed as its own read() call", request_flight.len());

    match split
        .receive
        .read(&mut SliceInput::new(&mut request_flight))
    {
        Ok(ReceiveTrafficState::Available(mut data)) => {
            println!(
                "  >>> CONTROL OK: request DELIVERED via split.receive.read(): {:?}",
                String::from_utf8_lossy(data.data())
            );
        }
        Ok(other) => println!(
            "  CONTROL UNEXPECTED: split.receive.read() yielded {other:?} instead of Available -- oracle itself may be broken",
            other = std::any::type_name_of_val(&other)
        ),
        Err(e) => println!("  CONTROL UNEXPECTED: split.receive.read() -> Err({e:?})"),
    }
    println!();
}

fn attack_cobatched_call() {
    println!("==== ATTACK: Finished flight + first request CONCATENATED into ONE process() call");
    let (mut client, server, mut client_final_flight) = handshake_up_to_final_flight();

    // Client queues its first request as plaintext application data BEFORE asking rustls to
    // produce more wire bytes. This is completely ordinary application usage (rustls documents
    // that plaintext can be queued via the Writer before the handshake is reported complete) --
    // no attacker control of the CLIENT is needed, just ordinary eagerness / one write() call.
    client
        .writer()
        .write_all(b"GET /attack HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut client_request_flight = vec![];
    client.write_tls(&mut client_request_flight).unwrap();

    println!(
        "  client final handshake flight: {}B, subsequent request flight: {}B",
        client_final_flight.len(),
        client_request_flight.len()
    );

    // The server-facing application concatenates whatever arrived in one read() -- exactly the
    // co-batching scenario: the Finished record and the ApplicationData record land in the SAME
    // buffer handed to ONE process() call.
    let mut combined = client_final_flight.clone();
    combined.extend_from_slice(&client_request_flight);
    println!("  combined buffer fed to a single NeedsInput::process() call: {}B", combined.len());

    let mut server_output = vec![];
    let outcome = server.process(&mut SliceInput::new(&mut combined), &mut server_output);
    match outcome {
        Ok(ServerHandshake::Complete(split)) => {
            println!("  server reached Complete from the single combined call (as the finding predicts)");
            // Try to read anything further -- per the finding, nothing should be available: the
            // request was already decrypted+dispatched+discarded inside the process() call above.
            let mut nothing_more = vec![];
            match split.receive.read(&mut SliceInput::new(&mut nothing_more)) {
                Ok(ReceiveTrafficState::ReadMore(_)) => println!(
                    "  >>> CONFIRMED: split.receive.read() has NOTHING to deliver -- the request \
                       was silently dropped during the combined process() call. The server is now \
                       waiting for a request that will never (fully) arrive, while the client \
                       believes it already sent one."
                ),
                Ok(other) => println!(
                    "  UNEXPECTED: split.receive.read() yielded {other:?} -- finding may be REFUTED for this construction",
                    other = std::any::type_name_of_val(&other)
                ),
                Err(e) => println!("  split.receive.read() -> Err({e:?})"),
            }
        }
        Ok(other) => println!("  UNEXPECTED server state: {other:?}", other = std::any::type_name_of_val(&other)),
        Err(e) => println!("  UNEXPECTED error: {e:?}"),
    }
    println!();
}

fn main() {
    control_separate_calls();
    attack_cobatched_call();
    println!("TEST-EXIT=0");
}
