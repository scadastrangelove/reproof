// Characterizes the X509PublicKeyValidator empty-RSA-component index.
//
// Findings (verified against x509-parser default features, 2026-07-17):
//   (A) A malformed cert CANNOT reach the sink: asn1-rs rejects a zero-length
//       DER INTEGER (`02 00`), so parse_rsa_key never yields an empty slice.
//   (B) Nor can a caller inject one: X509PublicKeyValidator takes a
//       SubjectPublicKeyInfo, and the sole constructor of the PublicKey::RSA
//       variant is SubjectPublicKeyInfo::parsed() (x509.rs:250-254), which
//       RE-PARSES the raw subject_public_key bytes through the same rejecting
//       parser on every call. So the validator's rsa.modulus[0] is unreachable
//       through any public path.
//
// Therefore the reported "empty RSA modulus panic" is a FALSE POSITIVE by
// reachability, and the corresponding guard is an unreachable defensive nit,
// not a security patch.
//
// NOTE on the last assertion below: it indexes a hand-built RSAPublicKey, which
// only demonstrates that indexing an empty slice panics (a fact about Rust). It
// does NOT show the validator can be made to panic, and it is patch-independent
// — it passes both before and after the guard. Do not read it as a regression
// test. The real value of this program is rows (A)/(A'): pinning the parser's
// rejection behaviour, which is what makes the finding a FP.
use x509_parser::prelude::*; // re-exports asn1_rs::FromDer
use x509_parser::public_key::RSAPublicKey;

fn main() {
    // (A) parser rejects the only empty-slice-producing encoding
    let empty_ints = [0x30u8, 0x04, 0x02, 0x00, 0x02, 0x00]; // SEQ{ INT(len0), INT(len0) }
    assert!(
        RSAPublicKey::from_der(&empty_ints).is_err(),
        "parser unexpectedly accepted zero-length INTEGERs"
    );

    // (A') canonical zeros parse, and never produce an empty slice
    let zeros = [0x30u8, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
    let (_r, k) = RSAPublicKey::from_der(&zeros).expect("canonical zeros should parse");
    assert_eq!(k.modulus.len(), 1);
    assert_eq!(k.exponent.len(), 1);

    // (B) the sink panics only when constructed empty via pub fields (not from parsing)
    let empty = RSAPublicKey { modulus: &[], exponent: &[] };
    assert_eq!(empty.key_size(), 0, "guarded key_size must not panic on empty");
    let panicked = std::panic::catch_unwind(|| {
        // exactly what X509PublicKeyValidator does at structure.rs:169 (pre-guard)
        let _ = empty.modulus[0] & 0x80;
    })
    .is_err();
    assert!(panicked, "unguarded modulus[0] should panic on an empty slice");

    println!("OK: parser rejects empty INTEGERs; sink reachable only via pub-field construction");
}
