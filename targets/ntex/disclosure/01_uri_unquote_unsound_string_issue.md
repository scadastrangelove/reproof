# ISSUE / GHSA — ntex-router: percent-decoded path bytes are turned into `String` with `from_utf8_unchecked`

**Title:** `ResourcePath::unquote` can construct an invalid `String` from percent-decoded path bytes

### Summary

Tested against `ntex-router 1.0.0` (current crates.io release).

`ResourcePath::unquote` percent-decodes attacker-controlled path segments into raw bytes and then builds a
`String` via `unsafe String::from_utf8_unchecked(data)`. The decoder accepts arbitrary `%XX` octets, so a
path like `/%FF` yields bytes `[47, 255]`, which are not valid UTF-8. This violates the `String`/`str`
UTF-8 invariant and creates an unsound value inside safe API surface.

Important scope note: this report is about a Rust soundness/invariant break. I am **not** claiming a
demonstrated memory-corruption exploit from the current reproducer. The concrete proof is that the crate
creates a `String` containing bytes that `std::str::from_utf8` rejects.

### Dynamic reproduction

Self-contained PoCs (verified 2026-08-02 against `ntex-router 1.0.0`, the current crates.io max):
- Direct trait call: [docs/e13/poc/ntex-uri-ub.rs](../../../docs/e13/poc/ntex-uri-ub.rs)
- Framework routing path: [docs/e13/poc/ntex-uri-ub-router.rs](../../../docs/e13/poc/ntex-uri-ub-router.rs)

Observed result on `ntex-router 1.0.0` (stable):

```text
uri.path() = "/%FF"
unquoted bytes = [47, 255]
INVALID UTF-8 STORED IN String: invalid utf-8 sequence of 1 bytes from index 1
```

**Miri result (must be stated — it bounds the claim).** Running both PoCs under Miri does **not**
report undefined behavior at the `from_utf8_unchecked` call. `str`'s UTF-8 requirement is a *safety*
invariant, not a machine *validity* invariant, so Miri's abstract machine does not treat the bad
construction as UB (the only Miri errors are unrelated heap leaks from the router's static
allocations). An earlier PoC comment claimed "immediate UB under Miri" — that was wrong and has been
retracted. **Honest claim: this is a soundness bug (an `unsafe` contract violation that puts an
invalid `str` into safe API surface), not a Miri-visible or otherwise demonstrated
memory-corruption.**

### Root cause

`ntex-router/src/quoter.rs:45` does:

```rust
unsafe { String::from_utf8_unchecked(data) }
```

but `restore_ch` can decode any `%XX` pair to any `u8`, not just UTF-8-preserving ASCII bytes. The
comment that `http::Uri` has already done “utf-8 checks” applies only to the percent-encoded ASCII source,
not to the decoded octets.

### Reachability (traced through the framework, 2026-08-02)

Reachable on the **default** ntex-web routing path, not just via a direct `unquote` call:

- `ntex 3.12.0` `web/app_service.rs:206` builds the routing key as `Path::new(head.uri.clone())` →
  the request path type is **`Path<Uri>`**.
- `web/request.rs:244` `fn resource_path(&mut self) -> &mut Path<Uri>`; `app_service.rs:241`
  `self.router.recognize_checked(&mut req, …)` matches on it.
- `ntex-router` `path.rs:216` `impl<T: ResourcePath> Resource<T> for Path<T>`, so matching runs with
  `T = Uri`; `tree.rs:400` calls `T::unquote(&segment)` for **every** path segment.
- `lib.rs:141` `impl ResourcePath for Uri` (behind default feature `http`) overrides `unquote` to call
  `quoter::requote` → the `from_utf8_unchecked` at `quoter.rs:45`.

So any request whose path has a `%XX` segment that decodes to a non-UTF-8 byte drives the unsafe
construction during ordinary route matching. (Note: the safe *default* `unquote` — `lib.rs:29`, used by
the `String`/`&str`/`ByteString` impls — is `s.into()` and does **not** hit this; only the `Uri` impl
does. ntex-web uses `Path<Uri>`, so the framework path is the vulnerable one.)

### Real-impact investigation (2026-08-02) — can the unsoundness be escalated?

Probed empirically against the real router (`docs/e13/poc/ntex-uri-impact-probe.rs`,
`…-probe2.rs`). Result: **the invalid-UTF-8 case does not escalate; the security-relevant behaviors
are the percent-DECODING semantics, which are separate and most likely intended.**

- **Invalid UTF-8 (`%FF`, `%c0%af`, …) dead-ends in a routing MISS.** A single dynamic segment or a
  static compare over an invalid-UTF-8 `str` fails to match (`/api/%FF/data` → `None`), so the unsound
  `str` is constructed transiently inside `recognize()` and dropped. Prefix/tail routes don't decode
  the tail at all (`/files/%FF` → tail stays raw `%FF`), so the invalid `str` isn't even built there.
  No request-time panic, no bypass, no corruption reproduced **from the invalidity itself**. Miri-clean.
- **Percent-decoding DOES inject dangerous *valid* bytes into params — but this is decoder behavior,
  not the UTF-8 bug, and is very likely WAI:**
  - `%2F` → `/` captured inside a single param (`/api/a%2Fb/data` → `ver = "a/b"`): a separator smuggled
    into one path parameter (traversal/segment-confusion primitive **for a downstream consumer** that
    trusts the param).
  - `%00` → NUL in a param (`/%00` → `x = "\0"`).
  - decode-before-match: `/%61%64%6d%69%6e` matches static `/admin` → a front-filter that inspects the
    **raw** path is bypassed (a normalization differential).

  These are inherited from actix-router and are how percent-decoding routers are generally expected to
  behave; reporting them as vulnerabilities would most likely draw a "validate your inputs / WAI"
  response unless tied to a guard ntex itself claims to provide.

**Bottom line:** the hypothesis "corrupted URI handling → filter/routing bypass" is plausible in the
abstract, but **could not be demonstrated flowing from this bug** — the invalid-UTF-8 path is inert
(routing miss), and the genuinely dangerous decode behaviors are separate, valid-UTF-8, and intended.
The finding stands as a **Low soundness bug**, not a demonstrated bypass or DoS.

### Severity / channel — recalibrated after the Miri result

**Low (soundness, no demonstrated memory-safety exploit).** The demonstrated effect is construction of a
`str`/`String` that violates the UTF-8 safety invariant inside safe API surface. Miri does not flag it;
no memory corruption is shown. This is the RustSec `informational: unsound` shape, which the ecosystem
normally handles as a **public issue + PR**, not an embargoed private advisory.

**Recommended channel: public Issue + PR** (fix is one line — validate or keep bytes). A private GHSA
would over-escalate a Low-impact, non-exploit soundness bug — the same severity-inflation the project was
warned about before (see LESSONS disclosure-severity). File a GHSA only if the ntex maintainers explicitly
ask to handle soundness reports privately.

### Suggested fix

Do not use `from_utf8_unchecked` here. Either:

- validate with `std::str::from_utf8`,
- keep the decoded bytes as bytes,
- or reject percent-decoded non-UTF-8 path segments.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
