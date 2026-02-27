# -*- coding: utf-8 -*-
"""
ghidra_extract_win_signatures.py - Ghidra headless postScript

Analyzes Windows server.dll to extract byte signatures for SourceMod gamedata.
Uses RTTI to find class vtables, then reads vtable entries at known indices
(from Linux binary analysis) to generate Windows byte signatures.

Usage: analyzeHeadless ... -postScript ghidra_extract_win_signatures.py /output/dir

@category Insurgency
@author SmartBots project
"""

import os
import struct
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

# ── Configuration ──────────────────────────────────────────────────────────

# Target functions with their Linux vtable indices.
# MSVC typically has 1 fewer dtor entry than GCC, so Windows index = Linux - 1
# for indices above the dtor slot.  We probe a ±3 window to be safe.
#
# Format: (class_rtti_name, display_name, linux_vtable_index_or_None)
# None = non-virtual, must find via string xrefs / other means

VTABLE_TARGETS = [
    (".?AVCINSBotCombat@@",                  "CINSBotCombat::Update",                          50),
    (".?AVCINSBotActionCheckpoint@@",         "CINSBotActionCheckpoint::Update",                50),
    (".?AVCINSBotLocomotion@@",               "CINSBotLocomotion::Approach",                    50),
    (".?AVCINSBotLocomotion@@",               "CINSBotLocomotion::Update",                      47),
    (".?AVCINSBotLocomotion@@",               "CINSBotLocomotion::FaceTowards",                 77),
    (".?AVCNavArea@@",                        "CNavArea::IsPotentiallyVisible",                  33),
    (".?AVCNavArea@@",                        "CNavArea::IsBlocked",                             18),
    (".?AVCINSRules@@",                       "CINSRules::IsCounterAttack",                     271),
    (".?AVCINSNextBot@@",                     "CINSNextBot::Spawn",                              23),
    (".?AVCINSNextBotIntention@CINSNextBot@@", "CINSNextBot::CINSNextBotIntention::Update",       47),
    (".?AVPlayerLocomotion@@",                "PlayerLocomotion::Run",                            59),
    (".?AVILocomotion@@",                     "ILocomotion::ClearStuckStatus",                   101),
    (".?AVCINSNextBot@@",                     "CINSNextBot::GetLocomotionInterface",             603),
]

# Non-virtual functions: find via string xrefs or unique byte patterns
NON_VTABLE_TARGETS = [
    "CNavMesh::GetNearestNavArea",
    "CINSPlayer::GiveAmmo",
    "CINSPlayer::GetMagazines",
]

# Strings that might appear near / inside target functions
STRING_HINTS = {
    "CNavMesh::GetNearestNavArea": [
        "GetNearestNavArea",
        "searchMarker",
    ],
    "CINSPlayer::GiveAmmo": [
        "GiveAmmo",
    ],
    "CINSPlayer::GetMagazines": [
        "GetMagazines",
    ],
    # Global pointers
    "TheNavMesh": ["TheNavMesh"],
    "g_pGameRules": ["g_pGameRules"],
}

SIG_BYTES = 32          # bytes per signature
PROBE_WINDOW = 3        # ±entries around expected vtable index
DECOMPILE_TIMEOUT = 60  # seconds per function

# ── Helpers ────────────────────────────────────────────────────────────────

def read_dword(addr):
    mem = currentProgram.getMemory()
    try:
        return mem.getInt(addr) & 0xFFFFFFFF
    except:
        return None

def read_bytes(addr, length):
    import jarray
    mem = currentProgram.getMemory()
    buf = jarray.zeros(length, 'b')
    try:
        mem.getBytes(addr, buf)
        # Convert signed Java bytes to unsigned Python bytes
        return bytes(bytearray([b & 0xFF for b in buf]))
    except:
        return None

def read_string(addr, max_len=256):
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

def is_code_addr(val):
    addr = toAddr(val)
    blk = currentProgram.getMemory().getBlock(addr)
    return blk is not None and blk.isExecute()

def make_signature(addr, length=SIG_BYTES):
    """Build a SM-style byte signature.  Relocated bytes become \\x2A."""
    raw = read_bytes(addr, length)
    if not raw:
        return None, None

    # Collect relocation offsets
    reloc_offsets = set()
    reloc_table = currentProgram.getRelocationTable()
    base = addr.getOffset()
    for reloc in reloc_table.getRelocations():
        ra = reloc.getAddress().getOffset()
        if ra >= base and ra < base + length:
            off = ra - base
            for j in range(4):          # 32-bit relocation span
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

# ── Phase 1: Find RTTI type descriptors ────────────────────────────────────

def find_rtti_vtables(monitor):
    """Search for .?AV RTTI type descriptors and trace back to vtables."""
    print("\n=== Phase 1: Finding RTTI vtables ===")

    mem = currentProgram.getMemory()
    pattern = bytearray(b".?AV")

    # Collect all needed RTTI class names
    needed = set()
    for rtti_name, _, _ in VTABLE_TARGETS:
        needed.add(rtti_name)

    vtable_map = {}   # rtti_name -> [vtable_addr, ...]

    search_addr = mem.getMinAddress()
    end_addr = mem.getMaxAddress()

    while search_addr is not None and search_addr.compareTo(end_addr) < 0:
        found = mem.findBytes(search_addr, pattern, None, True, monitor)
        if found is None:
            break

        name_str = read_string(found, 512)

        if name_str in needed:
            # TypeDescriptor starts 8 bytes before the name
            td_addr = found.subtract(8)

            # Find xrefs TO TypeDescriptor -> should be from COL at +12
            refs_to_td = list(getReferencesTo(td_addr))
            for ref in refs_to_td:
                from_addr = ref.getFromAddress()
                # COL starts at from_addr - 12
                col_addr = from_addr.subtract(12)
                sig_val = read_dword(col_addr)
                if sig_val is not None and sig_val == 0:
                    # Find xrefs TO COL -> should be from vtable[-1]
                    refs_to_col = list(getReferencesTo(col_addr))
                    for ref2 in refs_to_col:
                        vt_meta_addr = ref2.getFromAddress()
                        vt_addr = vt_meta_addr.add(4)
                        first_entry = read_dword(vt_addr)
                        if first_entry and is_code_addr(first_entry):
                            if name_str not in vtable_map:
                                vtable_map[name_str] = []
                            vtable_map[name_str].append(vt_addr)
                            print("  %s vtable at %s" % (name_str, vt_addr))

        search_addr = found.add(1)

    print("Found vtables for %d / %d needed classes" % (len(vtable_map), len(needed)))
    return vtable_map

# ── Phase 2: Read vtable entries & generate signatures ─────────────────────

def extract_vtable_signatures(vtable_map, decomp, monitor):
    """For each target function, read the vtable entry and generate a signature."""
    print("\n=== Phase 2: Extracting vtable-based signatures ===")

    func_mgr = currentProgram.getFunctionManager()
    results = []  # (display_name, func_addr, sig, raw_hex, preview, confidence)

    for rtti_name, display_name, linux_idx in VTABLE_TARGETS:
        if rtti_name not in vtable_map:
            print("  %s: RTTI class not found (%s)" % (display_name, rtti_name))
            results.append((display_name, None, None, None, "RTTI class not found", "MISSING"))
            continue

        vt_addr = vtable_map[rtti_name][0]  # primary vtable

        # Probe window around expected index (MSVC may differ by ±1-2 from GCC)
        candidates = []
        for delta in range(-PROBE_WINDOW, PROBE_WINDOW + 1):
            idx = linux_idx + delta
            if idx < 0:
                continue
            entry_addr = vt_addr.add(idx * 4)
            func_ptr = read_dword(entry_addr)
            if func_ptr is None or not is_code_addr(func_ptr):
                continue

            faddr = toAddr(func_ptr)
            func = func_mgr.getFunctionAt(faddr)

            # Get function size
            fsize = 0
            if func:
                fsize = func.getBody().getNumAddresses()

            sig, raw_hex = make_signature(faddr)

            # Brief decompilation
            preview = ""
            if func:
                try:
                    dr = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
                    if dr and dr.decompileCompleted():
                        df = dr.getDecompiledFunction()
                        if df:
                            lines = df.getC().split("\n")
                            preview = "\n".join(lines[:20])
                except:
                    preview = "/* decompilation failed */"

            confidence = "EXACT" if delta == 0 else ("NEAR(%+d)" % delta)
            candidates.append((idx, delta, faddr, sig, raw_hex, fsize, preview, confidence))

        if not candidates:
            print("  %s: No valid vtable entries in probe window" % display_name)
            results.append((display_name, None, None, None, "No entries in window", "MISSING"))
            continue

        # Flag tiny functions as suspicious (likely __purecall stubs)
        exact_hit = [c for c in candidates if c[1] == 0]
        if exact_hit and exact_hit[0][5] < 16:
            print("  WARNING: %s: EXACT hit at %s is only %d bytes (likely a stub)" % (
                display_name, exact_hit[0][2], exact_hit[0][5]))

        # Output all candidates so user can pick the right one
        for idx, delta, faddr, sig, raw_hex, fsize, preview, confidence in candidates:
            label = "%s [vtable %d, delta=%+d, %d bytes]" % (display_name, idx, delta, fsize)
            results.append((label, faddr, sig, raw_hex, preview, confidence))
            if delta == 0:
                print("  %s: vtable[%d] -> %s (%d bytes) %s" % (display_name, idx, faddr, fsize, confidence))

    # Check for address collisions
    exact_addrs = {}
    for name, addr, sig, raw_hex, preview, confidence in results:
        if confidence == "EXACT" and addr:
            addr_str = str(addr)
            if addr_str in exact_addrs:
                print("  COLLISION: %s and %s both point to %s (one is likely wrong)" % (
                    exact_addrs[addr_str], name.split(" [")[0], addr_str))
            else:
                exact_addrs[addr_str] = name.split(" [")[0]

    return results

# ── Phase 3: Find non-virtual functions via string xrefs ───────────────────

def find_by_string_xrefs(decomp, monitor):
    """Search for known strings and trace back to containing functions."""
    print("\n=== Phase 3: String xref search ===")

    mem = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    results = []

    for target_name, search_strings in STRING_HINTS.items():
        found_funcs = set()

        for search_str in search_strings:
            pattern = bytearray(search_str.encode('ascii'))
            addr = mem.getMinAddress()

            while addr is not None:
                found = mem.findBytes(addr, pattern, None, True, monitor)
                if found is None:
                    break

                # Check it's a proper null-terminated string
                next_byte = read_bytes(found.add(len(search_str)), 1)
                if next_byte and next_byte[0] == 0:
                    refs = list(getReferencesTo(found))
                    for ref in refs:
                        from_addr = ref.getFromAddress()
                        func = func_mgr.getFunctionContaining(from_addr)
                        if func:
                            found_funcs.add(func.getEntryPoint())

                addr = found.add(1)

        for faddr in found_funcs:
            func = func_mgr.getFunctionAt(faddr)
            sig, raw_hex = make_signature(faddr)
            fsize = func.getBody().getNumAddresses() if func else 0

            preview = ""
            if func:
                try:
                    dr = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
                    if dr and dr.decompileCompleted():
                        df = dr.getDecompiledFunction()
                        if df:
                            lines = df.getC().split("\n")
                            preview = "\n".join(lines[:20])
                except:
                    preview = "/* decompilation failed */"

            print("  %s: candidate at %s (%d bytes)" % (target_name, faddr, fsize))
            results.append(("%s (string xref)" % target_name, faddr, sig, raw_hex, preview, "STRING_XREF"))

    return results

# ── Phase 4: Write output ──────────────────────────────────────────────────

def write_output(output_dir, vtable_results, string_results):
    print("\n=== Phase 4: Writing output ===")

    report_path = os.path.join(output_dir, "win_signatures_report.txt")
    gamedata_path = os.path.join(output_dir, "win_signatures_gamedata.txt")

    all_results = vtable_results + string_results

    with open(report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("Windows server.dll Signature Extraction Report\n")
        f.write("=" * 70 + "\n\n")

        for name, addr, sig, raw_hex, preview, confidence in all_results:
            f.write("-" * 60 + "\n")
            f.write("Function: %s\n" % name)
            f.write("Address:  %s\n" % (addr if addr else "NOT FOUND"))
            f.write("Match:    %s\n" % confidence)
            if sig:
                f.write("Sig:      \"%s\"\n" % sig)
                f.write("Raw:      %s\n" % raw_hex)
            if preview:
                f.write("\nDecompiled:\n")
                for line in preview.split("\n"):
                    f.write("  %s\n" % line)
            f.write("\n")

    print("Report: %s" % report_path)

    # Write a ready-to-use gamedata snippet
    with open(gamedata_path, "w") as f:
        f.write("// Windows signatures for SourceMod gamedata\n")
        f.write("// Extracted from server.dll via Ghidra RTTI analysis\n")
        f.write("// Review decompiled output in win_signatures_report.txt to verify matches\n\n")
        f.write("\"Signatures\"\n{\n")

        seen = set()
        for name, addr, sig, raw_hex, preview, confidence in all_results:
            # Only output EXACT or STRING_XREF matches as primary suggestions
            base_name = name.split(" [")[0].split(" (")[0]
            if base_name in seen:
                continue
            if sig and confidence in ("EXACT", "STRING_XREF"):
                seen.add(base_name)
                f.write("\t// %s @ %s [%s]\n" % (base_name, addr, confidence))
                f.write("\t\"%s\"\n" % base_name)
                f.write("\t{\n")
                f.write("\t\t\"library\"\t\"server\"\n")
                f.write("\t\t\"windows\"\t\"%s\"\n" % sig)
                f.write("\t}\n\n")

        f.write("}\n")

    print("Gamedata: %s" % gamedata_path)

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: No output directory specified.")
        return

    output_dir = args[0]
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    monitor = ConsoleTaskMonitor()

    # Set up decompiler
    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(currentProgram)

    vtable_map = find_rtti_vtables(monitor)
    vtable_results = extract_vtable_signatures(vtable_map, decomp, monitor)
    string_results = find_by_string_xrefs(decomp, monitor)
    write_output(output_dir, vtable_results, string_results)

    decomp.dispose()
    print("\nDone!")

main()
