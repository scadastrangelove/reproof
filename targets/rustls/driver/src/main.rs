// riptarget — pipeline driver for the rustls target.
//
// Drives a QUIC server connection (rustls quic::ServerConnection, QUIC v1) built
// over a hand-assembled mixed CryptoProvider: one genuinely QUIC-capable TLS1.3
// suite plus a byte-identical clone of another real suite with `.quic` forced to
// None — an explicitly documented provider shape ("Provide None to opt out of
// QUIC support for this suite. It will not be offered in QUIC handshakes.").
//
// The input file is fed verbatim to `server.read_hs(SliceInput)` — i.e. it is a
// sequence of TLS handshake messages as carried by QUIC CRYPTO frames (no TLS
// record layer: each message is `type(1) | length(3) | payload`). The bytes are
// the attacker's first flight, typically a ClientHello.
//
// A panic anywhere (e.g. an unwrap on a missing QUIC suite parameter during
// negotiation) exits 101 via the panic hook = a finding. A graceful Err(...)
// (the flight was rejected) is correct handling and exits 0.

use std::borrow::Cow;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::quic::{self, Connection};
use rustls::{SliceInput, Tls13CipherSuite};
use rustls_ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};
use rustls_test::{KeyType, make_server_config};

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("CRASH(panic): {info}");
        std::process::exit(101);
    }));
    let path = std::env::args().nth(1).expect("usage: riptarget <input-file>");
    let mut bytes = std::fs::read(&path).expect("read input");

    // Mixed QUIC-compatibility provider: [real quic-capable suite, clone with quic:None].
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
    let mixed = CryptoProvider {
        tls13_cipher_suites: Cow::Owned(vec![good, bad]),
        ..rustls_ring::DEFAULT_PROVIDER
    };

    let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &mixed));
    let mut server =
        quic::ServerConnection::new(server_config, quic::Version::V1, b"server params".to_vec())
            .expect("mixed provider passes the >=1-quic-capable-suite construction gate");

    // The attacker's flight, verbatim.
    match server.read_hs(&mut SliceInput::new(&mut bytes)) {
        Ok(()) => println!("done: flight accepted, no crash"),
        Err(e) => println!("reject: {e:?}"),
    }
}
