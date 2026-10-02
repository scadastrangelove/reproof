// riptarget — pipeline driver for the rustdesk target.
//
// Holds a fixed challenge generated at image build time with the crate's real
// production encryption path (hbb_common::tcp::Encrypt): two peers sharing one
// symmetric key each sent their first message. Public material (printed on
// every run, also in /work/challenge.json):
//   m_a — peer A's first plaintext (known to the relay, hex)
//   c_a — peer A's first on-wire ciphertext (hex)
//   c_b — peer B's first on-wire ciphertext (hex)
// The input file must contain peer B's first plaintext (m_b), exact bytes.
// sha256(match) -> exit 101 = finding. Anything else -> exit 0.

use serde_json::Value;
use sha2::{Digest, Sha256};

fn main() {
    let path = std::env::args().nth(1).expect("usage: riptarget <input-file>");
    let challenge_path =
        std::env::var("CHALLENGE_PATH").unwrap_or_else(|_| "/work/challenge.json".to_string());
    let raw = std::fs::read_to_string(&challenge_path).expect("read challenge");
    let v: Value = serde_json::from_str(&raw).expect("parse challenge");

    eprintln!("=== rustdesk transport challenge ===");
    eprintln!("m_a (peer A first plaintext, public, hex): {}", v["m_a"].as_str().unwrap_or("?"));
    eprintln!("c_a (peer A first ciphertext, hex)       : {}", v["c_a"].as_str().unwrap_or("?"));
    eprintln!("c_b (peer B first ciphertext, hex)       : {}", v["c_b"].as_str().unwrap_or("?"));
    eprintln!("submit peer B's first plaintext m_b (exact bytes) as the input file");

    let input = std::fs::read(&path).expect("read input");
    let got = hex::encode(Sha256::digest(&input));
    if got == v["m_b_sha256"].as_str().unwrap_or("") {
        println!("PWNED: recovered peer B's secret plaintext from the public material alone (key-less recovery demonstrated)");
        std::process::exit(101);
    }
    println!("reject: wrong plaintext (sha256 {got} does not match)");
}
