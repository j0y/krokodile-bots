# -*- coding: utf-8 -*-
"""
ghidra_find_nonvirtual.py - Find non-virtual functions in Windows server.dll

Targets:
  1. CINSPlayer::GiveAmmo — find via callers of GetMagazines (RVA 0x2acfd0)
  2. CNavMesh::GetNearestNavArea — find via "searchMarker" string xref

Usage: analyzeHeadless ... -postScript ghidra_find_nonvirtual.py /output/dir

@category Insurgency
@author SmartBots project
"""

import os
import jarray
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

IMAGE_BASE = 0x10000000
GETMAGAZINES_RVA = 0x2acfd0  # Known from smartbots_ammobox.txt
DECOMPILE_TIMEOUT = 120

def read_bytes(addr, length):
    mem = currentProgram.getMemory()
    buf = jarray.zeros(length, 'b')
    try:
        mem.getBytes(addr, buf)
        return bytes(bytearray([b & 0xFF for b in buf]))
    except:
        return None

def make_signature(addr, length=32):
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

def read_string_at(addr, max_len=256):
    mem = currentProgram.getMemory()
    chars = []
    for i in range(max_len):
        try:
            b = mem.getByte(addr.add(i)) & 0xFF
            if b == 0:
                break
            chars.append(chr(b))
        except:
            break
    return "".join(chars)

def decompile_func(decomp, func, monitor):
    try:
        dr = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
        if dr and dr.decompileCompleted():
            df = dr.getDecompiledFunction()
            if df:
                return df.getC()
    except:
        pass
    return None


def find_giveammo(decomp, monitor):
    """Find CINSPlayer::GiveAmmo by looking at callers of GetMagazines."""
    print("\n=== Finding CINSPlayer::GiveAmmo ===")

    func_mgr = currentProgram.getFunctionManager()

    # GetMagazines is at known RVA
    getmag_addr = toAddr(IMAGE_BASE + GETMAGAZINES_RVA)
    getmag_func = func_mgr.getFunctionAt(getmag_addr)

    if not getmag_func:
        print("  ERROR: GetMagazines not found at %s" % getmag_addr)
        return []

    print("  GetMagazines found at %s (%d bytes)" % (
        getmag_addr, getmag_func.getBody().getNumAddresses()))

    # Find all callers of GetMagazines
    refs = list(getReferencesTo(getmag_addr))
    print("  Found %d references to GetMagazines" % len(refs))

    callers = {}
    for ref in refs:
        from_addr = ref.getFromAddress()
        caller = func_mgr.getFunctionContaining(from_addr)
        if caller:
            entry = caller.getEntryPoint()
            if entry not in callers:
                callers[entry] = caller

    print("  Found %d unique calling functions" % len(callers))

    results = []
    for entry, caller in sorted(callers.items()):
        fsize = caller.getBody().getNumAddresses()
        rva = entry.getOffset() - IMAGE_BASE
        sig, raw_hex = make_signature(entry)

        # Decompile to help identify which is GiveAmmo
        code = decompile_func(decomp, caller, monitor)
        preview = ""
        if code:
            lines = code.split("\n")
            preview = "\n".join(lines[:30])

        print("  Caller at %s (RVA 0x%x, %d bytes)" % (entry, rva, fsize))
        results.append({
            "name": "GetMagazines caller",
            "addr": entry,
            "rva": rva,
            "size": fsize,
            "sig": sig,
            "raw_hex": raw_hex,
            "preview": preview,
        })

    return results


def find_getnearestnavarea(decomp, monitor):
    """Find CNavMesh::GetNearestNavArea via 'searchMarker' string xref."""
    print("\n=== Finding CNavMesh::GetNearestNavArea ===")

    mem = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()

    # On Linux, GetNearestNavArea has a static local: "searchMarker"
    # Search for this string in the binary
    pattern = bytearray(b"searchMarker")
    results = []

    addr = mem.getMinAddress()
    search_count = 0
    while addr is not None:
        found = mem.findBytes(addr, pattern, None, True, monitor)
        if found is None:
            break
        search_count += 1

        # Verify null termination
        next_byte = read_bytes(found.add(len("searchMarker")), 1)
        if next_byte and (next_byte[0] if isinstance(next_byte[0], int) else ord(next_byte[0])) == 0:
            print("  Found 'searchMarker' string at %s" % found)

            # Find refs to this string
            refs = list(getReferencesTo(found))
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                if func:
                    entry = func.getEntryPoint()
                    fsize = func.getBody().getNumAddresses()
                    rva = entry.getOffset() - IMAGE_BASE
                    sig, raw_hex = make_signature(entry)
                    code = decompile_func(decomp, func, monitor)
                    preview = ""
                    if code:
                        lines = code.split("\n")
                        preview = "\n".join(lines[:30])

                    print("  Referencing function at %s (RVA 0x%x, %d bytes)" % (entry, rva, fsize))
                    results.append({
                        "name": "GetNearestNavArea candidate",
                        "addr": entry,
                        "rva": rva,
                        "size": fsize,
                        "sig": sig,
                        "raw_hex": raw_hex,
                        "preview": preview,
                    })

        addr = found.add(1)

    if search_count == 0:
        print("  'searchMarker' string not found in binary")

        # Fallback: search for unique constants from GetNearestNavArea
        # The function uses 99999.0f (0x47C34F80) as maxDist default
        # and accesses TheNavMesh global
        print("  Trying fallback: searching for 99999.0f constant (0x47C34F80)")
        float_pattern = jarray.zeros(4, 'b')
        float_pattern[0] = -128  # 0x80 as signed byte
        float_pattern[1] = 0x4F
        float_pattern[2] = -61   # 0xC3 as signed byte
        float_pattern[3] = 0x47
        addr = mem.getMinAddress()
        while addr is not None:
            found = mem.findBytes(addr, float_pattern, None, True, monitor)
            if found is None:
                break
            func = func_mgr.getFunctionContaining(found)
            if func:
                entry = func.getEntryPoint()
                fsize = func.getBody().getNumAddresses()
                if fsize > 100:  # GetNearestNavArea is substantial
                    rva = entry.getOffset() - IMAGE_BASE
                    sig, raw_hex = make_signature(entry)
                    code = decompile_func(decomp, func, monitor)
                    preview = ""
                    if code:
                        lines = code.split("\n")
                        preview = "\n".join(lines[:30])
                    print("  99999.0f in function at %s (RVA 0x%x, %d bytes)" % (entry, rva, fsize))
                    results.append({
                        "name": "GetNearestNavArea candidate (99999.0f)",
                        "addr": entry,
                        "rva": rva,
                        "size": fsize,
                        "sig": sig,
                        "raw_hex": raw_hex,
                        "preview": preview,
                    })
            addr = found.add(1)

    return results


def find_giveammo_5arg(decomp, monitor):
    """
    Alternative: find GiveAmmo by looking for the 5-argument overload pattern.
    CINSPlayer::GiveAmmo(int, int, int, bool, int) on Linux is at 0x006a0f30.
    It calls GetMagazines and also does AddMags. It accesses flag 0x4 to check
    magazine-based weapons.
    """
    print("\n=== Finding CINSPlayer::GiveAmmo (via AddMags pattern) ===")

    mem = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    results = []

    # GiveAmmo references "AddMags" or accesses player magazine data
    # Also look for "GiveAmmo" debug string
    for search_str in ["GiveAmmo", "AddMags"]:
        pattern = bytearray(search_str.encode('ascii'))
        addr = mem.getMinAddress()
        while addr is not None:
            found = mem.findBytes(addr, pattern, None, True, monitor)
            if found is None:
                break

            next_byte = read_bytes(found.add(len(search_str)), 1)
            if next_byte and (next_byte[0] if isinstance(next_byte[0], int) else ord(next_byte[0])) == 0:
                context = read_string_at(found.subtract(20), 60)
                print("  Found '%s' string at %s (context: '%s')" % (search_str, found, context))

                refs = list(getReferencesTo(found))
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    func = func_mgr.getFunctionContaining(from_addr)
                    if func:
                        entry = func.getEntryPoint()
                        fsize = func.getBody().getNumAddresses()
                        rva = entry.getOffset() - IMAGE_BASE
                        sig, raw_hex = make_signature(entry)
                        code = decompile_func(decomp, func, monitor)
                        preview = ""
                        if code:
                            lines = code.split("\n")
                            preview = "\n".join(lines[:30])
                        print("  -> function at %s (RVA 0x%x, %d bytes)" % (entry, rva, fsize))
                        results.append({
                            "name": "GiveAmmo candidate (%s string)" % search_str,
                            "addr": entry,
                            "rva": rva,
                            "size": fsize,
                            "sig": sig,
                            "raw_hex": raw_hex,
                            "preview": preview,
                        })

            addr = found.add(1)

    return results


def write_output(output_dir, giveammo_callers, getnav_results, giveammo_strings):
    print("\n=== Writing output ===")

    path = os.path.join(output_dir, "nonvirtual_report.txt")
    with open(path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("Non-Virtual Function Analysis\n")
        f.write("=" * 70 + "\n")

        f.write("\n## CINSPlayer::GiveAmmo — callers of GetMagazines\n")
        f.write("(GiveAmmo calls GetMagazines to manage magazine data)\n\n")
        for r in giveammo_callers:
            f.write("-" * 60 + "\n")
            f.write("Address:  %s (RVA 0x%x)\n" % (r["addr"], r["rva"]))
            f.write("Size:     %d bytes\n" % r["size"])
            f.write("Sig:      \"%s\"\n" % r["sig"])
            f.write("Raw:      %s\n" % r["raw_hex"])
            if r["preview"]:
                f.write("\nDecompiled:\n")
                for line in r["preview"].split("\n"):
                    f.write("  %s\n" % line)
            f.write("\n")

        if giveammo_strings:
            f.write("\n## CINSPlayer::GiveAmmo — string xref candidates\n\n")
            for r in giveammo_strings:
                f.write("-" * 60 + "\n")
                f.write("Match:    %s\n" % r["name"])
                f.write("Address:  %s (RVA 0x%x)\n" % (r["addr"], r["rva"]))
                f.write("Size:     %d bytes\n" % r["size"])
                f.write("Sig:      \"%s\"\n" % r["sig"])
                if r["preview"]:
                    f.write("\nDecompiled:\n")
                    for line in r["preview"].split("\n"):
                        f.write("  %s\n" % line)
                f.write("\n")

        f.write("\n## CNavMesh::GetNearestNavArea\n\n")
        for r in getnav_results:
            f.write("-" * 60 + "\n")
            f.write("Match:    %s\n" % r["name"])
            f.write("Address:  %s (RVA 0x%x)\n" % (r["addr"], r["rva"]))
            f.write("Size:     %d bytes\n" % r["size"])
            f.write("Sig:      \"%s\"\n" % r["sig"])
            if r["preview"]:
                f.write("\nDecompiled:\n")
                for line in r["preview"].split("\n"):
                    f.write("  %s\n" % line)
            f.write("\n")

    print("Report: %s" % path)


def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: No output directory specified.")
        return

    output_dir = args[0]
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    monitor = ConsoleTaskMonitor()

    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(currentProgram)

    giveammo_callers = find_giveammo(decomp, monitor)
    getnav_results = find_getnearestnavarea(decomp, monitor)
    giveammo_strings = find_giveammo_5arg(decomp, monitor)

    write_output(output_dir, giveammo_callers, getnav_results, giveammo_strings)

    decomp.dispose()
    print("\nDone!")

main()
