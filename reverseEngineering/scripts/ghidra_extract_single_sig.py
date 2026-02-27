# -*- coding: utf-8 -*-
"""
ghidra_extract_single_sig.py - Extract byte signature for a function at a known RVA

Usage: analyzeHeadless ... -postScript ghidra_extract_single_sig.py <RVA_hex> [sig_bytes]

Example: ... ghidra_extract_single_sig.py 0x303d10 32

Outputs a SourceMod-compatible byte signature with relocated bytes as \x2A.

@category Insurgency
@author SmartBots project
"""

import jarray

IMAGE_BASE = 0x10000000
DEFAULT_SIG_BYTES = 32


def read_bytes(addr, length):
    mem = currentProgram.getMemory()
    buf = jarray.zeros(length, 'b')
    try:
        mem.getBytes(addr, buf)
        return bytes(bytearray([b & 0xFF for b in buf]))
    except:
        return None


def make_signature(addr, length):
    """Build a SM-style byte signature.  Relocated bytes become \\x2A."""
    raw = read_bytes(addr, length)
    if not raw:
        return None, None

    reloc_offsets = set()
    reloc_table = currentProgram.getRelocationTable()
    base = addr.getOffset()
    for reloc in reloc_table.getRelocations():
        ra = reloc.getAddress().getOffset()
        if ra >= base and ra < base + length:
            off = ra - base
            for j in range(4):
                if off + j < length:
                    reloc_offsets.add(int(off + j))
        if ra >= base + length:
            break

    parts = []
    for i in range(len(raw)):
        b = raw[i] if isinstance(raw[i], int) else ord(raw[i])
        if i in reloc_offsets:
            parts.append("\\x2A")
        else:
            parts.append("\\x%02X" % (b & 0xFF))

    sig = "".join(parts)
    raw_hex = " ".join("%02X" % (b if isinstance(b, int) else ord(b)) for b in raw)
    return sig, raw_hex


def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: Usage: ghidra_extract_single_sig.py <RVA_hex> [sig_bytes]")
        print("  Example: ghidra_extract_single_sig.py 0x303d10")
        return

    rva = int(args[0], 16)
    sig_len = int(args[1]) if len(args) > 1 else DEFAULT_SIG_BYTES

    va = IMAGE_BASE + rva
    addr = toAddr(va)

    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionAt(addr)

    print("=" * 60)
    print("RVA:     0x%x" % rva)
    print("Address: 0x%x" % va)

    if func:
        fsize = func.getBody().getNumAddresses()
        print("Function: %s (%d bytes)" % (func.getName(), fsize))
    else:
        print("WARNING: No function defined at this address")

    sig, raw_hex = make_signature(addr, sig_len)

    if sig:
        print("\nRaw bytes:  %s" % raw_hex)
        print("\nSM signature (%d bytes):" % sig_len)
        print('  "%s"' % sig)

        # Also output a shorter version if the first 16 bytes are unique enough
        if sig_len > 16:
            sig16, _ = make_signature(addr, 16)
            print("\nShorter (16 bytes):")
            print('  "%s"' % sig16)
    else:
        print("ERROR: Could not read bytes at address 0x%x" % va)

    print("=" * 60)

main()
