# Disclosure package — zune-jpeg 0.5.15

**Status:** DRAFT — not sent. Prepared for operator review.
**Maintainer:** caleb <etemesicaleb@gmail.com> (etemesi254/zune-image).
**Channel:** no `SECURITY.md` in the repo. Prefer **GitHub private vulnerability reporting** on
`etemesi254/zune-image` if enabled (Security → Report a vulnerability); otherwise the private email
above. The crate ships an upstream `fuzz/` harness, so framing as a fuzz/robustness finding + a seed
fits how the maintainer already works.
**Framing:** private-first, low-severity availability/robustness bug, memory-safe, "happy to PR the
fix", found by the rust-in-peace security pipeline.

## What we're reporting

1. **Advisory 01 — reachable panic (DoS)** decoding a crafted progressive YCCK JPEG
   (`01-ycck-progressive-panic.md`). Low severity, availability-only, memory-safe. 163-byte PoC,
   root-caused, **fix verified** (`fix-ycck-clamp.patch` — the PoC then decodes cleanly and normal
   JPEGs are unaffected). This is the one item we're asking you to fix / advise on.

2. **Info notes** (`02-info-notes.md`) — a decompression-bomb hardening note (caller's responsibility;
   not a bug) and four unchecked-arithmetic sites that are **not** 64-bit memory-safety issues (one is
   correctness-only, one is bounds-checked, two are 32-bit-only under-alloc leads). Listed for
   transparency; no fix requested.

## Attachments

- `01-ycck-progressive-panic.md` — the advisory.
- `poc.jpg` (163 B) + `make_poc.py` — reproducer + generator (also a good fuzz seed).
- `fix-ycck-clamp.patch` — the verified fix diff (against `crates/zune-jpeg/src/misc.rs`).
- `02-info-notes.md` + `bomb.jpg` — the info notes.

## Draft cover email

> **Subject:** zune-jpeg: reachable panic decoding a crafted progressive YCCK JPEG (low-sev DoS) + fix
>
> Hi Caleb,
>
> I've been running a Rust security pipeline over `zune-jpeg` 0.5.15 and found one small,
> reachable panic I wanted to report privately first. It's low severity — a bounds-checked
> slice-index panic (memory-safe, availability only), not memory corruption — but it does abort the
> process from the public `decode()` on a crafted 163-byte input.
>
> **The bug:** a JPEG with an Adobe APP14 marker `transform=2` (YCCK) that is also a *progressive*
> `SOF2` frame declaring only **2 components** hits `index out of bounds` at
> `src/mcu_prog.rs:102`. The YCCK→YCbCr fixup in `setup_component_params` (`src/misc.rs:300`) sets the
> colorspace to YCbCr (3 components) without clamping to the frame's actual component count, unlike the
> sibling branch which clamps via `MultiBand(components.len())`; the progressive loop then indexes
> `components[2]` on a 2-element slice.
>
> A 163-byte reproducer, the root-cause write-up, and a small fix (fall through to
> `MultiBand(components.len())` when there aren't 3 components — verified: the PoC then decodes and
> normal JPEGs are unaffected) are attached. Happy to open a PR if you'd prefer. The PoC also makes a
> reasonable seed for your `fuzz/` harness — the specific combo is one a random corpus won't easily
> synthesize.
>
> I've also attached a couple of non-security info notes (a decompression-bomb hardening thought and
> some unchecked-arithmetic sites that turned out not to be 64-bit memory-safety issues) purely for
> transparency — nothing to action there.
>
> Let me know how you'd like to handle it — I'm not requesting a CVE, and I'll follow your lead on
> timing/advisory.
>
> Thanks for zune-image,
> [name]

## After sending (fill in)

- Sent: _(not yet)_
- Follow-up if silent: ~14 days.
- Response log: _(none)_
