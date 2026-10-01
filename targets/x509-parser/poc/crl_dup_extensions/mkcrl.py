import struct
def tlv(tag, content):
    l = len(content)
    if l < 128: lb = bytes([l])
    else:
        b = l.to_bytes((l.bit_length()+7)//8, 'big'); lb = bytes([0x80|len(b)]) + b
    return bytes([tag]) + lb + content
SEQ, SET, INT, OID, NULL, OCT, BIT, PRT, UTC = 0x30,0x31,0x02,0x06,0x05,0x04,0x03,0x13,0x17

alg   = tlv(SEQ, tlv(OID, bytes([0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B])) + tlv(NULL, b''))
cn    = tlv(SEQ, tlv(OID, bytes([0x55,0x04,0x03])) + tlv(PRT, b't'))
issuer= tlv(SEQ, tlv(SET, cn))
this  = tlv(UTC, b'250101000000Z')
def crlnum(n): return tlv(SEQ, tlv(OID, bytes([0x55,0x1D,0x14])) + tlv(OCT, tlv(INT, bytes([n]))))
# TWO CRLNumber extensions — the duplicate the finding needs
exts  = tlv(SEQ, crlnum(1) + crlnum(2))
tagged= tlv(0xA0, exts)                      # [0] EXPLICIT crlExtensions
tbs   = tlv(SEQ, tlv(INT, b'\x01') + alg + issuer + this + tagged)   # version v2
crl   = tlv(SEQ, tbs + alg + tlv(BIT, b'\x00\x00'))
open('/tmp/dupcrl.der','wb').write(crl)
print("wrote /tmp/dupcrl.der", len(crl), "bytes:", crl.hex())
