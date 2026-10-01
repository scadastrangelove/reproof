// PoC driver for the Mach-O exports-trie infinite loop (secondary public API, not File::parse).
use object::read::macho::{MachOFile64, LoadCommandVariant};
use object::Endianness;
fn main() {
    let path = std::env::args().nth(1).expect("usage: trie_driver <macho>");
    let data = std::fs::read(&path).expect("read");
    let file = match MachOFile64::<Endianness>::parse(&*data) {
        Ok(f) => f, Err(e) => { println!("parse-reject: {e}"); return; }
    };
    let endian = file.endian();
    let mut cmds = match file.macho_load_commands() { Ok(c) => c, Err(e) => { println!("lc-err: {e}"); return; } };
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(LoadCommandVariant::LinkeditData(linkedit)) = cmd.variant() {
            if let Ok(trie) = linkedit.exports_trie(endian, &*data) {
                println!("entering exports_trie iteration...");
                let mut n: u64 = 0;
                for _ in trie { n += 1; if n > 5_000_000 { println!("HANG >5M"); std::process::exit(42);} }
                println!("trie done, iterations={n}");
            }
        }
    }
    println!("ok done");
}
