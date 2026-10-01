use std::process;

fn main() {
    let font_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../crafted_cursive.ttf".to_string());

    let font_bytes = std::fs::read(&font_path).unwrap_or_else(|e| {
        eprintln!("Cannot read font {font_path}: {e}");
        process::exit(1);
    });

    let font_ref = match harfrust::FontRef::new(&font_bytes) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("FontRef::new failed: {e}");
            process::exit(1);
        }
    };

    let shaper_data = harfrust::ShaperData::new(&font_ref);
    let shaper = shaper_data.shaper(&font_ref).build();

    // Ba (U+0628) + 32768 Fathah marks (U+064E) + Meem (U+0645)
    let mut text = String::with_capacity(32770 * 4);
    text.push('\u{0628}');
    for _ in 0..32768 {
        text.push('\u{064E}');
    }
    text.push('\u{0645}');

    eprintln!("Text length: {} chars", text.len());

    let mut buffer = harfrust::UnicodeBuffer::new();
    buffer.push_str(&text);
    buffer.set_direction(harfrust::Direction::RightToLeft);
    buffer.set_script(harfrust::script::ARABIC);

    eprintln!("Shaping with harfrust 0.12.0 (stable API, {} glyphs in buffer)...", text.len());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        shaper.shape(buffer, harfrust::ShapeOptions::new())
    }));

    match result {
        Ok(glyph_buf) => {
            eprintln!("Shaping completed WITHOUT panic — {} output glyphs", glyph_buf.len());
            eprintln!("BUG NOT REPRODUCED");
            process::exit(1);
        }
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "unknown panic payload".to_string()
            };
            eprintln!("PANIC CAUGHT: {msg}");
            eprintln!("BUG REPRODUCED — out-of-bounds index via i16 attach_chain overflow");
            process::exit(0);
        }
    }
}
