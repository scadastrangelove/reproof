# x509-parser: `ASN1Time`'s `Add<Duration>` panics instead of returning `None`

**Crate:** `x509-parser` (rusticata) · **File:** `src/time.rs` · **Kind:** correctness /
robustness (contract violation) · **Severity:** low · **Status:** draft — NOT yet sent to
the maintainer (needs explicit go-ahead; this is an outbound public action).

## Summary

`impl Add<Duration> for ASN1Time` has return type `Option<ASN1Time>` — signalling that the
addition can fail — but its body cannot ever produce `None`, and instead **panics** on date
overflow:

```rust
impl Add<Duration> for ASN1Time {
    type Output = Option<ASN1Time>;
    #[inline]
    fn add(self, rhs: Duration) -> Option<ASN1Time> {
        Some(ASN1Time::new(self.time + rhs))   // `OffsetDateTime + Duration` panics on overflow
    }
}
```

`OffsetDateTime + Duration` (the `time` crate) is `checked_add(...).expect(...)` internally —
it panics when the result leaves the representable date range. So `add` violates its own
`Option` contract: it promises `None` on failure but aborts the thread instead.

The sibling `impl Sub<ASN1Time>` immediately below already does the correct thing (checks
before operating, returns `None`), so the intended pattern is established in the same file.

## Reproduction (verified)

`self.time` is attacker-controlled: a certificate `notAfter` of `99991231235959Z` — RFC
5280 §4.1.2.5's conventional "no well-defined expiration date" value — parses to a `Date`
at the maximum representable year (no `large-dates` feature needed).

```rust
use x509_parser::time::ASN1Time;
use time::{Duration, macros::datetime};

let t = ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC));
let _ = t + Duration::days(1);   // panics: "resulting value is out of range"
```

(`ASN1Time::parse_der` accepts the year-9999 `GeneralizedTime` straight from DER — confirmed
— so the operand is reachable from a parsed certificate.) Full PoC:
[`poc/asn1time_add/`](../poc/asn1time_add/).

## Impact (stated honestly)

This is a **contract-violation / robustness** bug, not a demonstrated remote DoS.
x509-parser itself never calls `Add` (its `time_to_expiration` uses the checked `Sub` path),
so triggering a live crash requires a **downstream caller** doing something like
`cert.validity().not_after + grace_period` — a natural "is this cert valid N days from now"
pattern — on an attacker-supplied certificate. Any such caller, having chosen the
`Option`-returning API specifically to handle failure, gets a panic instead.

## Suggested fix (verified: compiles, returns `None`, preserves normal behaviour)

```diff
     fn add(self, rhs: Duration) -> Option<ASN1Time> {
-        Some(ASN1Time::new(self.time + rhs))
+        self.time.checked_add(rhs).map(ASN1Time::new)
     }
```

Verified against the crate in a clean build:
- patched crate compiles;
- `ASN1Time::from(9999-12-31…) + Duration::days(1)` → **`None`** (no panic);
- `ASN1Time::from(2025-01-01…) + Duration::days(1)` → **`Some("Jan 2 2025")`** (unchanged).

Patch: [`asn1time-add-checked.patch`](asn1time-add-checked.patch). (`Sub` is already correct;
optionally its magnitude could use `checked_sub` too, but it cannot panic today since it
guards `self.time > rhs.time` first.)

## Secondary, lower-priority note (not part of this report unless asked)

Duplicate CRL extensions: `CertificateRevocationList::crl_number()` /
`RevokedCertificate::{reason_code,invalidity_date}` use `.find()` (first-match), while
`extensions_map()` on the same list returns `Err(DuplicateExtensions)`. A CRL with a
repeated extension (RFC 5280 forbids this; the parser accepts it — `many0`, no dedup) is
therefore interpreted differently by different accessors. Info-severity; arguably within the
crate's documented "parse, don't validate" stance. PoC: [`poc/crl_dup_extensions/`](../poc/crl_dup_extensions/).
