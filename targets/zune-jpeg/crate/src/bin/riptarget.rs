// rust-in-peace crash driver for zune-jpeg: exercise the untrusted-JPEG decode path.
use std::io::Read;
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::bytestream::ZCursor;
fn main() {
    let path = std::env::args().nth(1).expect("usage: riptarget <jpg>");
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .expect("read input");
    let mut dec = JpegDecoder::new(ZCursor::new(bytes.as_slice()));
    match dec.decode() {
        Ok(px) => println!("ok pixels={}", px.len()),
        Err(e) => println!("reject: {e:?}"),
    }
}
