# validate: guard empty RSA modulus/exponent before indexing `[0]`

## What

`X509PublicKeyValidator::validate` indexes `rsa.modulus[0]` and `rsa.exponent[0]`
(`src/validate/structure.rs:169,172`) with no `is_empty()` check. This adds the guard,
matching the idiom `RSAPublicKey::key_size()` and `try_exponent()` already use.

## Reachability: this is **not** a security fix

Being explicit so it gets triaged correctly — **I could not reach this panic from any
public API path, and I do not believe it is reachable today.**

The `PublicKey::RSA` variant is only ever constructed by `SubjectPublicKeyInfo::parsed()`
(`src/x509.rs:250-254`), which calls `RSAPublicKey::from_der` →
`<(Integer, Integer)>::parse_der`. asn1-rs rejects a zero-length DER INTEGER, so the
modulus/exponent slices are never empty by the time the validator sees them. Verified
against the current crate:

| input to `RSAPublicKey::from_der` | result |
|---|---|
| `30 04 02 00 02 00` — `SEQ{ INTEGER(len 0), INTEGER(len 0) }` | `Err(InvalidSPKI)` — rejected |
| `30 06 02 01 00 02 01 00` — canonical zero INTEGERs | `Ok`, `modulus.len() == 1` |

And because `parsed()` re-parses the raw `subject_public_key` bytes on every call, a
hand-constructed `SubjectPublicKeyInfo` cannot inject an empty-slice `RSAPublicKey`
either. So there is no malformed certificate, and no caller-side construction, that
reaches the index.

## Why offer it at all

Purely **defense-in-depth + internal consistency**:

- `RSAPublicKey::key_size()` (`public_key.rs:62`) and `try_exponent()` (`public_key.rs:52`)
  both already check `is_empty()` before touching `[0]`. The validator is the odd one out.
- It keeps the validator correct if a future asn1-rs ever accepts a zero-length INTEGER,
  or if a laxer BER path is added.

## The change

```rust
Ok(PublicKey::RSA(rsa)) => {
    if rsa.modulus.is_empty() {
        l.warn("Public key: (RSA) modulus is empty");
    } else if rsa.modulus[0] & 0x80 != 0 {
        l.warn("Public key: (RSA) modulus is negative");
    }
    if rsa.exponent.is_empty() {
        l.warn("Public key: (RSA) exponent is empty");
    } else if rsa.exponent[0] & 0x80 != 0 {
        l.warn("Public key: (RSA) exponent is negative");
    }
}
```

Builds clean. **No regression test is included, because the guarded state is unreachable
through the public API** — there is nothing to assert from outside. If you'd rather not
carry an unreachable branch, feel free to close this; no objection.
