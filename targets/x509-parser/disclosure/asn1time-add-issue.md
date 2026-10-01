# ISSUE — x509-parser: `ASN1Time + Duration` panics on overflow instead of returning `None`

**Title:** `impl Add<Duration> for ASN1Time` panics on date overflow despite an `Option` return type

### Bug

In `src/time.rs`, `impl Add<Duration> for ASN1Time` has return type `Option<ASN1Time>` but cannot ever
return `None` — instead it panics on date overflow:

```rust
fn add(self, rhs: Duration) -> Option<ASN1Time> {
    Some(ASN1Time::new(self.time + rhs))   // OffsetDateTime + Duration panics on overflow
}
```

`OffsetDateTime + Duration` is `checked_add(...).expect(...)` internally, so `add` aborts the thread
where its signature promises a `None`. The sibling `impl Sub<ASN1Time>` right below already guards
correctly and returns `None`.

### Reachability / severity

`self.time` can be attacker-influenced: a certificate `notAfter` of `99991231235959Z` (RFC 5280
§4.1.2.5's conventional "no well-defined expiration") parses to a max-year `Date`. x509-parser itself
never calls `Add` (its own `time_to_expiration` uses the checked `Sub`), so a live crash requires
downstream code doing something like `cert.validity().not_after + grace_period` on an untrusted cert —
a natural "is this cert valid N days from now?" pattern. I'd frame this as a **correctness/robustness**
bug with a latent DoS in consumer code, not an exploitable vulnerability in x509-parser itself. Not
requesting a CVE/RustSec advisory.

### Repro (against current default features)

```rust
use x509_parser::time::ASN1Time;
use time::{Duration, macros::datetime};

let t = ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC));
let _ = t + Duration::days(1);   // panics: "resulting value is out of range"
```

### Fix (verified: compiles; max-year+1d → `None`; normal case unchanged)

```diff
     fn add(self, rhs: Duration) -> Option<ASN1Time> {
-        Some(ASN1Time::new(self.time + rhs))
+        self.time.checked_add(rhs).map(ASN1Time::new)
     }
```

PR incoming with this fix + a regression test.

### Minor secondary note (info only, no fix requested)

Duplicate CRL extensions are accepted by the parser (`many0`, no dedup), so
`CertificateRevocationList::crl_number()` first-matches while `extensions_map()` returns
`Err(DuplicateExtensions)` on the same input — two accessors disagree. RFC 5280 §5.2 forbids
duplicates, but since CRLs are CA-signed this isn't an attacker vector, and it may well be within the
crate's intended "parse, don't validate" stance. Mentioning only for completeness.

For what it's worth, x509-parser came out clean on memory-safety and panic-DoS in my broader testing —
this is the one genuine item I ended up with, and it's low impact.

Found with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
