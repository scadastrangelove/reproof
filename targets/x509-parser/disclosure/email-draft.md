# Private disclosure email — draft (NOT sent)

**To:** Pierre Chifflier <chifflier@wzdftpd.net> (rusticata maintainer; address from public
git history — no SECURITY.md / private reporting on the repo)
**Cc (optional):** Jalil David Salamé Messina <jalil.salame@gmail.com> (recent active contributor)
**Subject:** [x509-parser] Two possibly-security-relevant issues found while testing (low severity, reporting privately first)

---

Hi Pierre,

I tinker with agentic security and develop a small project around it
(https://github.com/scadastrangelove/rust-in-peace). While testing it against x509-parser I
found two issues that *look* security-related, but I honestly find their severity hard to pin
down — it really depends on how the crate is embedded and used downstream. They're "reachable"
enough that I'd rather flag them to you privately first than guess in public. If either turns
out to be just a plain bug, I'm happy to drop it straight into a PR instead.

(The repo doesn't have private vulnerability reporting enabled and there's no SECURITY.md, so
email seemed like the least noisy first step — apologies if this isn't your preferred channel.)

**Bug.** In `src/time.rs`, `impl Add<Duration> for ASN1Time` has return type
`Option<ASN1Time>` but cannot ever return `None`, and instead panics on date overflow:

```rust
fn add(self, rhs: Duration) -> Option<ASN1Time> {
    Some(ASN1Time::new(self.time + rhs))   // OffsetDateTime + Duration panics on overflow
}
```

`OffsetDateTime + Duration` is `checked_add(...).expect(...)` internally, so `add` aborts the
thread where its signature promises a `None`. The sibling `impl Sub<ASN1Time>` right below
already guards correctly and returns `None`.

**Reachability / severity.** `self.time` can be attacker-influenced: a certificate `notAfter`
of `99991231235959Z` (RFC 5280 §4.1.2.5's conventional "no well-defined expiration") parses to
a max-year `Date`. x509-parser itself never calls `Add` (its `time_to_expiration` uses the
checked `Sub`), so a live crash requires downstream code doing something like
`cert.validity().not_after + grace_period` on an untrusted cert. That makes this a
correctness/robustness bug with a *latent* DoS in consumer code — I would not call it an
exploitable vulnerability in x509-parser itself, and I'm not requesting a RustSec advisory;
your call entirely.

**Repro (against current default features):**
```rust
use x509_parser::time::ASN1Time;
use time::{Duration, macros::datetime};
let t = ASN1Time::from(datetime!(9999-12-31 23:59:59 UTC));
let _ = t + Duration::days(1);   // panics: "resulting value is out of range"
```

**Suggested one-line fix** (verified: compiles; max-year+1d → `None`; normal case unchanged):
```diff
     fn add(self, rhs: Duration) -> Option<ASN1Time> {
-        Some(ASN1Time::new(self.time + rhs))
+        self.time.checked_add(rhs).map(ASN1Time::new)
     }
```
Happy to open a PR with this (+ a small test) whenever suits you.

**Minor secondary note (info only).** Duplicate CRL extensions are accepted by the parser
(`many0`, no dedup), so `CertificateRevocationList::crl_number()` first-matches while
`extensions_map()` returns `Err(DuplicateExtensions)` on the same input — two accessors
disagree. RFC 5280 §5.2 forbids duplicates, but since CRLs are CA-signed this isn't an attacker
vector, and it may well be within your intended "parse, don't validate" stance. Mentioning only
for completeness.

For what it's worth, x509-parser came out clean on memory-safety and panic-DoS in my testing —
these two are the only genuine items I ended up with, both low impact.

Thanks for the crate, and for maintaining so much of the Rust parsing-security ecosystem.

Best,
Sergey Gordeychik
