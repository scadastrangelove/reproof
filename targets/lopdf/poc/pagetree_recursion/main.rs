// PoC harness: docker run --rm -v $PWD:/poc vuln-pipeline-lopdf:latest \
//   bash -c 'cd /poc && python3 gen_deep_pages.py deep.pdf && cargo run --release --offline -- deep.pdf'
// (needs a Cargo.toml with lopdf path-dep + [profile.release] overflow-checks=false)
use lopdf::Document;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    println!("-> Document::load_metadata (extract_page_count -> get_pages_tree_count)");
    let _ = Document::load_metadata(&path);   // <-- stack overflow aborts here (SIGABRT, uncatchable)
    println!("SURVIVED (no overflow)");
}
