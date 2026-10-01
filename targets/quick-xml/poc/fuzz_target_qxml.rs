#![no_main]
use libfuzzer_sys::fuzz_target;
use quick_xml::reader::{Reader, NsReader};
use quick_xml::events::Event;
use serde::Deserialize;

// Recursive target type to exercise the serde deserializer's stack recursion (T4).
#[derive(Debug, Deserialize)]
struct Node {
    #[serde(default, rename = "n")]
    n: Vec<Node>,
    #[serde(rename = "@a", default)]
    _a: String,
}

fn drive_reader(data: &[u8], toggles: u8) {
    let mut r = Reader::from_reader(data);
    let c = r.config_mut();
    c.check_end_names = toggles & 1 != 0;
    c.expand_empty_elements = toggles & 2 != 0;
    c.trim_text(toggles & 4 != 0);
    c.check_comments = toggles & 8 != 0;
    let mut buf = Vec::new();
    let mut n = 0u32;
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Eof) | Err(_) => break,
            Ok(ev) => {
                // exercise unescape (escape.rs) on text and attribute values
                if let Event::Text(e) = &ev {
                    if let Ok(s) = e.decode() { let _ = quick_xml::escape::unescape(&s); }
                }
                if let Event::Start(e) | Event::Empty(e) = &ev {
                    for a in e.attributes().flatten() {
                        let _ = a.unescape_value();
                        let _ = a.normalized_value(quick_xml::XmlVersion::Implicit1_0);
                    }
                }
            }
        }
        buf.clear();
        n += 1;
        if n > 2_000_000 { break; }
    }
}

fn drive_ns(data: &[u8]) {
    let mut r = NsReader::from_reader(data);
    let mut buf = Vec::new();
    let mut n = 0u32;
    loop {
        match r.read_resolved_event_into(&mut buf) {
            Ok((_, Event::Eof)) | Err(_) => break,
            Ok(_) => {}
        }
        buf.clear();
        n += 1;
        if n > 2_000_000 { break; }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }
    let toggles = data[0];
    let body = &data[1..];
    drive_reader(body, toggles);
    drive_ns(body);
    // serde path (T4): only on a size-bounded slice so the stack-recursion signal is the crash, not OOM
    if body.len() < 200_000 {
        if let Ok(s) = std::str::from_utf8(body) {
            let _: Result<Node, _> = quick_xml::de::from_str(s);
        }
    }
});
