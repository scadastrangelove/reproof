# fix(time): return `None` on `ASN1Time + Duration` overflow instead of panicking

## What

`impl Add<Duration> for ASN1Time` (`src/time.rs`) has return type `Option<ASN1Time>`, but the
body was `Some(ASN1Time::new(self.time + rhs))`. `OffsetDateTime + Duration` panics on overflow
(internally `checked_add(...).expect(...)`), so `add` aborts the thread in exactly the case its
`Option` signature exists to report. The sibling `impl Sub<ASN1Time>` right below already guards
and returns `None`.

```diff
     fn add(self, rhs: Duration) -> Option<ASN1Time> {
-        Some(ASN1Time::new(self.time + rhs))
+        self.time.checked_add(rhs).map(ASN1Time::new)
     }
```

## Why it matters

`self.time` can come from a parsed certificate — e.g. a `notAfter` of `99991231235959Z`
(RFC 5280 §4.1.2.5's conventional "no well-defined expiration"), which parses to a max-year
date. Downstream code doing `cert.validity().not_after + grace_period` on an untrusted
certificate — a natural "is this cert valid N days from now?" pattern — then panics instead of
getting the `None` the API promises.

I'd frame this as a **correctness/robustness** fix rather than a security vulnerability:
`x509-parser` itself never calls `Add` (its `time_to_expiration` uses the checked `Sub`), so
the impact is confined to downstream callers that use the operator. Reported privately to the
maintainer first; opening as a PR at his suggestion.

## Test

Adds `time::tests::test_add_duration_overflow_returns_none`:

- `ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC)) + Duration::days(1)` → `None` (was: panic);
- a normal date `+ Duration::days(1)` → `Some(..)` (unchanged).

Verified locally: `cargo test --lib time::` → `3 passed; 0 failed`.
