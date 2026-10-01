// Reproducer: quadratic-time DIE attribute parsing in gimli.
// Cargo.toml:  gimli = "0.34"   (also reproduces on master)
//   cargo run --release
use gimli::{LittleEndian, read::{DebugInfo, DebugAbbrev}};

fn uleb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 { b |= 0x80; }
        out.push(b);
        if v == 0 { break; }
    }
}

/// One abbreviation declaring `k` zero-byte `DW_FORM_flag_present` attributes,
/// and a compile unit whose body is `d` one-byte DIEs (each just the abbrev code).
fn build(d: usize, k: usize) -> (Vec<u8>, Vec<u8>) {
    let mut abbrev = Vec::new();
    uleb(1, &mut abbrev);              // abbrev code 1
    uleb(0x34, &mut abbrev);           // DW_TAG_variable
    abbrev.push(0);                    // DW_CHILDREN_no
    for i in 0..k {
        uleb(0x2000 + i as u64, &mut abbrev);   // attribute name (DW_AT_lo_user+)
        uleb(0x19, &mut abbrev);                // DW_FORM_flag_present: consumes 0 bytes of .debug_info
    }
    abbrev.push(0); abbrev.push(0);    // end of attribute specs
    abbrev.push(0);                    // end of abbreviations table

    let mut body = Vec::new();
    body.extend_from_slice(&5u16.to_le_bytes());   // DWARF version 5
    body.push(1);                                  // DW_UT_compile
    body.push(8);                                  // address_size
    body.extend_from_slice(&0u32.to_le_bytes());   // debug_abbrev_offset
    body.extend(std::iter::repeat(1u8).take(d));   // d DIEs, each one byte
    let mut info = (body.len() as u32).to_le_bytes().to_vec();  // unit_length
    info.extend_from_slice(&body);
    (info, abbrev)
}

fn walk(info: &[u8], abbrev: &[u8]) -> usize {
    let debug_info = DebugInfo::new(info, LittleEndian);
    let debug_abbrev = DebugAbbrev::new(abbrev, LittleEndian);
    let mut n = 0;
    let mut units = debug_info.units();
    while let Ok(Some(header)) = units.next() {
        if let Ok(abbrevs) = header.abbreviations(&debug_abbrev) {
            let mut entries = header.entries(&abbrevs);
            while let Ok(Some(entry)) = entries.next_dfs() {
                n += entry.attrs().len();
            }
        }
    }
    n
}

fn main() {
    let k = 2000;
    for d in [20_000usize, 40_000, 80_000, 160_000] {
        let (info, abbrev) = build(d, k);
        let start = std::time::Instant::now();
        let attrs = walk(&info, &abbrev);
        println!("input = {:>7} B   attributes parsed = {:>11}   time = {:?}",
                 info.len() + abbrev.len(), attrs, start.elapsed());
    }
}
