#![no_main]
use libfuzzer_sys::fuzz_target;
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::bytestream::ZCursor;
fuzz_target!(|data: &[u8]| {
    let mut d = JpegDecoder::new(ZCursor::new(data));
    let _ = d.decode();
});
