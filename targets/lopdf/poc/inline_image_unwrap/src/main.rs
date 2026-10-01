// CONFIRMED (2026-07-17): lopdf's inline-image parser panics via `.unwrap()` on a missing
// /ColorSpace. In `image_data_stream` (src/parser/mod.rs:670), when an inline image has
// /W /H /BPC but neither /IM(ImageMask)==true nor /CS(ColorSpace), the code does
// `get_abbr(b"CS", b"ColorSpace").unwrap()` on an Err -> index/lookup panic.
//
// Reachable from the PUBLIC `Content::decode(&[u8])` API (used by page-content / text /
// image extraction), NOT from `Document::load_mem` alone — so the load_mem-scoped crash
// pipeline (Track A) structurally cannot reach it; only the curated static review did.
// Unconditional panic (independent of overflow-checks). Raised by BOTH models in Track B.
use lopdf::content::Content;
fn try_case(label: &str, data: &[u8]) {
    let r = std::panic::catch_unwind(|| Content::decode(data));
    match r {
        Err(_)  => println!("[{label}] PANICKED"),
        Ok(res) => println!("[{label}] no panic (ok={})", res.is_ok()),
    }
}
fn main() {
    try_case("no-CS-no-IM", b"BI /W 1 /H 1 /BPC 8 ID \x00 EI");            // -> PANIC
    try_case("IM-true",     b"BI /W 1 /H 1 /BPC 8 /IM true ID \x00 EI");   // control: no panic
    try_case("with-CS",     b"BI /W 1 /H 1 /BPC 8 /CS /DeviceGray ID \x00 EI"); // control: no panic
}
