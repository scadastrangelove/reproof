// CONFIRMED (2026-07-17): ASN1Time's `Add<Duration>` panics instead of returning None.
//
// `impl Add<Duration> for ASN1Time { type Output = Option<ASN1Time>; ... }` promises
// fallibility, but the body is `Some(ASN1Time::new(self.time + rhs))` and
// `OffsetDateTime + Duration` panics on overflow => the impl VIOLATES ITS OWN CONTRACT.
// The defect is in x509-parser's own code; fix is one line:
//   self.time.checked_add(rhs).map(ASN1Time::new)
//
// Reachability (stated honestly): year-9999 is parseable straight from a cert, but
// x509-parser never calls `Add` itself (time_to_expiration uses the checked `Sub`), so a
// live crash needs a downstream caller doing `cert.validity().not_after + duration`.
// => real_latent (leaning real).
use x509_parser::time::ASN1Time;
use ::time::{Duration, macros::datetime};
use asn1_rs::{DerParser, Input};

fn main() {
    let t = ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC));
    println!("[built] ASN1Time = {t}");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (t + Duration::days(1)).is_some()));
    match r {
        Err(_)   => println!("[add] PANICKED -> Add<Duration> panics on max-year (CONFIRMED)"),
        Ok(some) => println!("[add] no panic (Some={some}) -> REFUTED"),
    }
    // reachability of the max-year input from DER (RFC5280's "no well-defined expiration")
    let mut der = vec![0x18u8, 0x0F]; der.extend_from_slice(b"99991231235959Z");
    match ASN1Time::parse_der(Input::from(&der[..])) {
        Ok((_r, pt)) => println!("[parse] ACCEPTED year-9999 from DER: {pt} -> reachable from a cert"),
        Err(e)       => println!("[parse] REJECTED: {e:?}"),
    }
}
