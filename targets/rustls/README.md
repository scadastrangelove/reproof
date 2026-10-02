# rustls — campaign-benchmark target (rust profile)

**Upstream:** https://github.com/rustls/rustls @ `bd9f7f59aa79` (0.24.0-dev.1, pre-fix)
**Ground truth:** the 2026-07 3-lens campaign (see `JOURNAL.md`) found that QUIC
suite-compatibility is not enforced during negotiation → pre-auth `.quic.unwrap()`
panic (`tls13/key_schedule.rs`) when a mixed-compatibility provider's quic:None
suite is selected. Fixed upstream by PR #3173 (merged `7299721a`). Filed as
GHSA-j99h-2h74-pcqx (two paths: server-side selection, a 0.24-dev regression;
client-side acceptance, also in shipped 0.23.x — this benchmark targets the
server path).

## Shape

- `driver/` — `/work/riptarget`: builds a `quic::ServerConnection` over a
  hand-assembled mixed CryptoProvider (one real quic-capable TLS1.3 suite + one
  byte-identical clone with `quic: None`, a documented provider shape), then feeds
  the input file verbatim to `read_hs()` — bytes are TLS handshake messages as
  carried by QUIC CRYPTO frames (`type(1)|len(3)|payload`). Panic → exit 101;
  graceful Err → exit 0. Path-deps on `/work/rustls` so patch-phase rebuilds work.
- `poc/` — **oracle, host-only** (dockerignored): campaign PoCs +
  `gold-client-hello/` (gold-seed generator). Never copied into the image.

## Lens protocol (benchmark)

| Lens | How to run |
|---|---|
| blind | `bin/reproof-sandboxed run rustls --model <m> --runs 3 --parallel --stream` |
| threat-model | add `--auto-focus --aggregate union` |
| cve-seeded | temporary `focus_areas:` naming GHSA-j99h-2h74-pcqx ("QUIC cipher-suite compatibility not enforced during negotiation"), run, revert. Seeded runs measure *confirmation*, not discovery — report separately. |

## Smoke (gold seed)

```
cd poc/gold-client-hello && cargo run -q > /tmp/gold.bin
docker run --rm -v /tmp:/tmp reproof-rustls:latest /work/riptarget /tmp/gold.bin  # expect exit 101
docker run --rm reproof-rustls:latest /work/riptarget /dev/null                   # expect exit 0
```
