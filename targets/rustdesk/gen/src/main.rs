// Challenge generator for the rustdesk benchmark target — runs ONCE at image
// build time (Docker stage `gen`). Uses the real production encryption path
// (hbb_common::tcp::Encrypt) to produce the two peers' first on-wire
// ciphertexts over one shared symmetric key. Prints ONLY public challenge
// material to stdout: m_a (public known plaintext), c_a, c_b, sha256(m_b).
// The key and m_b never touch the filesystem and never leave this stage.
use hbb_common::tcp::Encrypt;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::secretbox;

/// Peer A's first plaintext — public, known to the relay (stands in for the
/// protocol's predictable first handshake message). Exactly 64 bytes.
const M_A: &[u8; 64] = b"RustDesk session bootstrap, message A (public, known to relay)00";
const _: () = assert!(M_A.len() == 64);

fn main() {
    sodiumoxide::init().expect("sodiumoxide init");
    let key = secretbox::gen_key();
    let mut m_b = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut m_b);

    // Two independent peers, one shared key, each encrypting its FIRST message.
    let c_a = Encrypt::new(key.clone()).enc(M_A);
    let c_b = Encrypt::new(key).enc(&m_b);

    let hash = Sha256::digest(m_b);
    println!(
        "{{\"m_a\":\"{}\",\"c_a\":\"{}\",\"c_b\":\"{}\",\"m_b_sha256\":\"{}\"}}",
        hex::encode(M_A),
        hex::encode(&c_a),
        hex::encode(&c_b),
        hex::encode(hash)
    );
}
