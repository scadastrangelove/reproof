# ISSUE — lopdf: two more crash bugs from crafted PDFs (compressed-object-container cycle, decompress_predictor overflow)

**Title:** Two more crash bugs from crafted PDFs — compressed-object container cycle (stack overflow) and decompress_predictor multiply overflow

### Summary

Follow-up to #532 (merged): testing lopdf **0.44.0** (current crates.io release) with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) pipeline's SAST-driven re-verification turned up two more independent crash paths from malformed PDF bytes. Both are low severity: availability-only, memory-safe (`#![forbid(unsafe_code)]`).

| # | Where | Trigger (public API, untrusted input) | Effect | Fix |
|---|---|---|---|---|
| 1 | `reader.rs:1131` (`get_compressed_object`) | `load_metadata_mem` on a PDF whose xref stream declares two mutually-referencing compressed-object containers (type-2 entry A → container B, type-2 entry B → container A) | Unbounded mutual recursion `get_object` ↔ `get_compressed_object` → stack overflow (uncatchable abort) | Thread the caller's `already_seen` through `get_compressed_object` into the nested `get_object` call, or add a depth budget |
| 2 | `object.rs:1125` (`decompress_predictor`) | `Document::load_mem` or `stream.decompressed_content()` on a stream with `/DecodeParms { /Predictor 12 /Columns 1099511627776 /Colors 33554432 /BitsPerComponent 8 }` | `bytes_per_pixel * pixels_per_row` overflows at `png::decode_frame`. Under overflow-checks (debug/cargo-fuzz): panic. Under release: the multiply wraps and the call returns `Ok` (empty output in a release smoke test) — no OOB and no under-allocation | Validate each `/DecodeParms` value against a sane upper bound before arithmetic (e.g. max 65536 for `/Columns`, max 256 for `/Colors`) |

### Distinct from existing fixes

- **#1 is NOT the same as #530 (recursion cluster):** #530 fixed post-load `Document` graph-walk recursion (get_named_destinations, deep_clone, etc.) via `MAX_NESTING_DEPTH`. This new finding is in the Reader's object-stream resolver — `get_compressed_object` (reader.rs:1131) allocates a FRESH `already_seen` HashSet (line 1140) and calls `get_object` (line 1141), but when `get_object` (line 1147) encounters a Compressed xref entry (line 1157), it calls `self.get_compressed_object(id)` WITHOUT passing the caller's `already_seen`, so the cycle detection is defeated.
- **#1 is NOT the same as #532 bug #4 (pagetree stack-overflow):** that was in `get_pages_tree_count` over `/Pages` `/Kids` and is now capped. This one is in the xref compressed-object resolver.
- **#2 is NOT the same as #532 bug #3 (xref /W alloc-abort):** that was unvalidated `/W` widths causing a huge allocation. This one is in the PNG predictor path after FlateDecode decompression — unchecked arithmetic on `/Columns`, `/Colors`, `/BitsPerComponent`.

### PoC — #1: compressed-object container cycle

A ~200-byte PDF with an xref stream where object A's container is B and B's container is A:

```rust
use lopdf;

fn main() {
    // load the crafted lopdf-cycle.pdf
    let bytes = std::fs::read("lopdf-cycle.pdf").unwrap();
    // run on a small-stack thread so the stack overflow is observable
    let h = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || lopdf::Document::load_metadata_mem(&bytes))
        .unwrap();
    match h.join() {
        Ok(_) => println!("returned"),
        Err(_) => println!("ABORT: stack overflow in get_object <-> get_compressed_object"),
    }
}
```

Result: `fatal runtime error: stack overflow`, process abort.

Root cause: `get_compressed_object` (reader.rs:1131) creates its own `already_seen: HashSet` (line 1140)
and passes it to `get_object` (line 1141). But `get_object` (line 1147), when it hits a Compressed xref
entry at line 1157, calls `self.get_compressed_object(id)` — which creates ANOTHER fresh HashSet,
discarding the caller's cycle-tracking state. So: resolve A → container is B → `get_object(B)` →
B is Compressed → `get_compressed_object(B)` (fresh HashSet) → container is A → `get_object(A)` →
A is Compressed → `get_compressed_object(A)` (fresh HashSet) → infinite loop, stack overflow.

### PoC — #2: decompress_predictor multiply overflow

```toml
# Cargo.toml
[dependencies]
lopdf = "0.44"
flate2 = "1"
```

```rust
use lopdf::{Dictionary, Object, Stream};

fn main() {
    let mut dict = Dictionary::new();
    dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));

    let mut parms = Dictionary::new();
    parms.set("Predictor", Object::Integer(12));
    parms.set("Columns", Object::Integer(1_099_511_627_776));  // 2^40
    parms.set("Colors", Object::Integer(33_554_432));           // 2^25
    parms.set("BitsPerComponent", Object::Integer(8));
    dict.set("DecodeParms", Object::Dictionary(parms));

    // valid zlib-compressed empty payload
    let compressed = {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"").unwrap();
        enc.finish().unwrap()
    };

    let stream = Stream::new(dict, compressed);
    let _ = stream.decompressed_content();
    // debug build: panicked at 'attempt to multiply with overflow', png.rs:88
    // release build: multiply wraps; call returns Ok(0 bytes) in a smoke test (no OOB)
}
```

Result (debug/overflow-checks): `panicked at 'attempt to multiply with overflow'` at `png.rs:88`.

Root cause: `object.rs:1125` computes `bytes_per_pixel = colors * bits / 8 = 2^25 * 8 / 8 = 2^25` (no
overflow here), then `png::decode_frame` computes `bytes_per_row = bytes_per_pixel * pixels_per_row =
2^25 * 2^40 = 2^65` — overflow. Both values are attacker-controlled via `/DecodeParms`.

### Severity

Both: **Low** — availability-only (DoS via panic/abort), memory-safe, no data corruption or RCE. Same class as the prior lopdf crash advisories.

Found with [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace).
