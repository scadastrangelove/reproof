use gimli::{LittleEndian, read::{DebugInfo, DebugAbbrev}};
fn uleb(v:u64,out:&mut Vec<u8>){let mut v=v;loop{let mut b=(v&0x7f)as u8;v>>=7;if v!=0{b|=0x80}out.push(b);if v==0{break}}}
fn build(d:usize,k:usize)->(Vec<u8>,Vec<u8>){
    let mut ab=Vec::new();
    uleb(1,&mut ab); uleb(0x34,&mut ab); ab.push(0);
    for i in 0..k { uleb(0x2000+i as u64,&mut ab); uleb(0x19,&mut ab); }
    ab.push(0); ab.push(0); ab.push(0);
    let mut body=Vec::new();
    body.extend_from_slice(&5u16.to_le_bytes()); body.push(1); body.push(8); body.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..d { body.push(1); }
    let mut info=Vec::new(); info.extend_from_slice(&(body.len() as u32).to_le_bytes()); info.extend_from_slice(&body);
    (info,ab)
}
fn walk(info:&[u8],ab:&[u8])->usize{
    let di=DebugInfo::new(info,LittleEndian);
    let da=DebugAbbrev::new(ab,LittleEndian);
    let mut n=0usize; let mut units=di.units();
    while let Ok(Some(h))=units.next(){
        if let Ok(abbrevs)=h.abbreviations(&da){
            let mut e=h.entries(&abbrevs);
            while let Ok(Some(ent))=e.next_dfs(){ n+=ent.attrs().len(); }
        }
    }
    n
}
fn main(){
    let k=2000usize;
    for d in [20000usize,40000,80000,160000]{
        let (info,ab)=build(d,k);
        let t=std::time::Instant::now(); let n=walk(&info,&ab);
        println!("D={:>7} K={} input={:>7}B attrs={:>11} time={:?}", d,k, info.len()+ab.len(), n, t.elapsed());
    }
}
