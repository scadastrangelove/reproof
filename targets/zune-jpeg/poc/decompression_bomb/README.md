# zune-jpeg 0.5.15 — decompression bomb / resource-exhaustion DoS (T5)

**Disposition:** confirmed · DoS (LOW–MEDIUM) · default-config unbounded · CWE-409 / CWE-789
**Found by:** the 1h ASan fuzz soak (libFuzzer `timeout-` artifact), NOT the static find.
**Entry:** `JpegDecoder::new(ZCursor::new(bytes)).decode()`.

## Mechanism

A **1402-byte** JPEG declares SOF0 dimensions **12544 × 12288 × 3 components** =
**462,422,016 bytes** of decoded output (154 megapixels, ~455 MB RSS, ~1.85 s).
Amplification ≈ **330,000×**. The 16-bit SOF width/height fields allow up to
65535 × 65535 × 4 ≈ **17 GB** from a ~1.4 KB file → guaranteed OOM. The default
`DecoderOptions` does not impose an effective dimension/output cap, so a caller
that hands `decode()` untrusted bytes without setting a limit is exposed.

## Grade evidence

```
$ /usr/bin/time -v riptarget_shipping bomb.jpg
ok pixels=462422016
  Elapsed (wall clock) time: 0:01.85
  Maximum resident set size: 455168 kbytes
```

Under the fuzzer's 25 s `-timeout` + `-rss_limit_mb=2048` this tripped the
timeout (loaded box + fork mode). It is not a crash — it is unbounded
allocation/CPU driven by attacker dimensions.

## Fix / mitigation

The control already exists but is not on by default: callers should set
`DecoderOptions::set_max_width` / `set_max_height` (or a max-output-size cap)
before decoding untrusted input. Upstream could ship a conservative default cap.
Borderline "by-design if the caller configures limits" — same class as many
image-decoder bombs; recorded as a real default-config DoS, not memory unsafety.
