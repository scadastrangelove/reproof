use quick_xml::reader::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;

fn run(depth: usize) {
    let mut xml = String::new();
    xml.push_str("<r xmlns:p=\"AAA\">");
    for _ in 0..depth { xml.push_str("<a>"); }
    xml.push_str("<x xmlns:p=\"BBB\"><p:e/></x>");
    for _ in 0..depth { xml.push_str("</a>"); }
    xml.push_str("<p:f/></r>");
    let mut r = NsReader::from_str(&xml);
    let (mut e_uri, mut f_uri) = (String::from("<none>"), String::from("<none>"));
    loop {
        match r.read_resolved_event() {
            Ok((_, Event::Eof)) => break,
            Ok((rr, Event::Empty(el))) => {
                let local = String::from_utf8_lossy(el.local_name().as_ref()).to_string();
                let uri = match rr { ResolveResult::Bound(ns) => String::from_utf8_lossy(ns.as_ref()).to_string(), o => format!("{:?}", o) };
                if local == "e" { e_uri = uri; } else if local == "f" { f_uri = uri; }
            }
            Ok(_) => {}
            Err(err) => { eprintln!("depth={} Err: {:?}", depth, err); return; }
        }
    }
    eprintln!("depth={:6} : <p:e> -> {:10}  <p:f> -> {:10}  (expect e=BBB, f=AAA)", depth, e_uri, f_uri);
}
fn main() { run(3); run(65534); run(65535); run(65536); run(70000); }
