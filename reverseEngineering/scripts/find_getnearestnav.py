#!/usr/bin/env python3
"""
Find CNavMesh::GetNearestNavArea and TheNavMesh in Windows server.dll
using pefile + capstone (no Ghidra needed).

Strategy:
1. Find "CNavMesh::GetNavArea" VPROF string → find function referencing it (GetNavArea)
2. Find callers of GetNavArea → one of them is GetNearestNavArea
3. Confirm by checking: large function, calls IsBlocked (0x103186f0), has grid-search pattern
4. Extract TheNavMesh global address from the function that reads it

Known Windows addresses:
  - CNavArea::IsBlocked: 0x103186f0 (RVA 0x3186f0)
  - Image base: 0x10000000
"""

import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL_PATH = "reverseengeneer/server.dll"
IMAGE_BASE = 0x10000000
ISBLOCKED_RVA = 0x3186f0

def load_dll():
    pe = pefile.PE(DLL_PATH)
    return pe

def rva_to_offset(pe, rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None

def offset_to_rva(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
            return offset - section.PointerToRawData + section.VirtualAddress
    return None

def find_string(data, s):
    """Find all occurrences of null-terminated string s in data."""
    needle = s.encode('ascii') + b'\x00'
    results = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results

def find_dword_refs(data, text_offset, text_size, target_va):
    """Find all locations in .text that contain a 4-byte reference to target_va."""
    target_bytes = struct.pack('<I', target_va)
    results = []
    start = text_offset
    end = text_offset + text_size
    pos = start
    while pos < end:
        idx = data.find(target_bytes, pos, end)
        if idx == -1:
            break
        results.append(idx)
        pos = idx + 1
    return results

def find_call_refs(data, text_offset, text_size, target_rva, pe):
    """Find all E8 (relative call) instructions in .text that target target_rva."""
    results = []
    for i in range(text_offset, text_offset + text_size - 5):
        if data[i] == 0xE8:  # CALL rel32
            rel = struct.unpack_from('<i', data, i + 1)[0]
            caller_rva = offset_to_rva(pe, i)
            if caller_rva is None:
                continue
            call_target_rva = caller_rva + 5 + rel
            if call_target_rva == target_rva:
                results.append(i)
    return results

def find_function_start(data, offset, text_offset):
    """Walk backwards from offset to find the function prologue (push ebp / 55 8B EC or similar)."""
    # Search backwards for common function prologues
    search_start = max(text_offset, offset - 4096)
    # Look for 55 8B EC (push ebp; mov ebp, esp) or 56/53 patterns
    best = None
    pos = offset
    while pos > search_start:
        pos -= 1
        # Common x86 function prologues
        if data[pos] == 0x55 and pos + 2 < offset and data[pos+1] == 0x8B and data[pos+2] == 0xEC:
            best = pos
            break
        # Also check for 0xCC padding before function start
        if data[pos] == 0xCC and pos + 1 < len(data) and data[pos+1] != 0xCC:
            # Next byte after CC padding is likely function start
            candidate = pos + 1
            if candidate < offset:
                best = candidate
                break
    return best

def find_function_end(data, func_start, text_end):
    """Estimate function end by looking for ret or next function prologue."""
    # Use capstone to find ret instructions
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    max_size = min(8192, text_end - func_start)
    code = data[func_start:func_start + max_size]

    last_ret = func_start
    for insn in md.disasm(code, IMAGE_BASE):
        off = func_start + (insn.address - IMAGE_BASE)
        # Track the last ret/retn
        if insn.mnemonic in ('ret', 'retn'):
            last_ret = off + insn.size
        # If we see CC padding after a ret, that's definitely the end
        if insn.mnemonic == 'int3':
            return last_ret

    return last_ret

def get_relocations(pe):
    """Get set of RVAs that have relocations."""
    relocs = set()
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in base_reloc.entries:
                if entry.type != 0:  # skip IMAGE_REL_BASED_ABSOLUTE (padding)
                    relocs.add(entry.rva)
    return relocs

def make_signature(data, pe, func_offset, relocs, length=32):
    """Generate SourceMod-compatible signature with wildcards for relocated bytes."""
    func_rva = offset_to_rva(pe, func_offset)
    if func_rva is None:
        return None, None

    raw_bytes = data[func_offset:func_offset + length]
    parts = []
    raw_hex = []

    for i in range(min(length, len(raw_bytes))):
        b = raw_bytes[i]
        byte_rva = func_rva + i
        # Check if any of the 4 bytes starting at byte_rva-3..byte_rva are relocated
        is_reloc = False
        for j in range(4):
            if (byte_rva - j) in relocs and j <= i:
                is_reloc = True
                break
        if is_reloc:
            parts.append("\\x2A")
        else:
            parts.append("\\x%02X" % b)
        raw_hex.append("%02X" % b)

    return "".join(parts), " ".join(raw_hex)

def analyze_function_calls(data, pe, func_start, func_end, text_section):
    """Analyze what a function calls (E8 relative calls)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    func_rva = offset_to_rva(pe, func_start)
    code = data[func_start:func_end]
    calls = []

    for insn in md.disasm(code, func_rva + IMAGE_BASE):
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            try:
                target = int(insn.op_str, 16)
                calls.append(target - IMAGE_BASE)  # store as RVA
            except ValueError:
                pass

    return calls

def check_function_reads_global(data, pe, func_start, func_end):
    """Find global variable addresses read by mov eax, [addr] (A1 xx xx xx xx) or similar."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    func_rva = offset_to_rva(pe, func_start)
    code = data[func_start:func_end]
    globals_read = []

    for insn in md.disasm(code, func_rva + IMAGE_BASE):
        # Look for mov reg, [imm32] patterns that load from global
        if insn.mnemonic == 'mov' and '[0x' in insn.op_str:
            # Extract the address
            import re
            m = re.search(r'\[0x([0-9a-f]+)\]', insn.op_str)
            if m:
                addr = int(m.group(1), 16)
                if addr > IMAGE_BASE and addr < IMAGE_BASE + 0x1000000:
                    globals_read.append((insn.address - IMAGE_BASE, addr - IMAGE_BASE, str(insn)))

    return globals_read


def main():
    print("Loading DLL...")
    pe = load_dll()
    data = pe.__data__

    # Find .text section
    text_section = None
    rdata_section = None
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name == '.text':
            text_section = section
        elif name == '.rdata':
            rdata_section = section

    if not text_section:
        print("ERROR: .text section not found")
        return

    text_offset = text_section.PointerToRawData
    text_size = text_section.SizeOfRawData
    text_rva = text_section.VirtualAddress
    text_end = text_offset + text_size

    print(f"  .text: offset=0x{text_offset:x}, size=0x{text_size:x}, RVA=0x{text_rva:x}")

    # Get relocations
    print("Loading relocations...")
    relocs = get_relocations(pe)
    print(f"  {len(relocs)} relocation entries")

    # =========================================================================
    # Step 1: Find "CNavMesh::GetNavArea" string
    # =========================================================================
    print("\n=== Step 1: Find CNavMesh::GetNavArea VPROF string ===")
    vprof_string = "CNavMesh::GetNavArea"
    offsets = find_string(data, vprof_string)

    if not offsets:
        print(f"  ERROR: '{vprof_string}' not found in binary")
        return

    for off in offsets:
        rva = offset_to_rva(pe, off)
        print(f"  Found at offset 0x{off:x} (RVA 0x{rva:x}, VA 0x{IMAGE_BASE + rva:08x})")

    # =========================================================================
    # Step 2: Find references to this string → GetNavArea function
    # =========================================================================
    print("\n=== Step 2: Find GetNavArea function (references VPROF string) ===")

    getnavarea_funcs = []
    for str_offset in offsets:
        str_rva = offset_to_rva(pe, str_offset)
        str_va = IMAGE_BASE + str_rva

        # Find push/mov instructions that reference this string address
        refs = find_dword_refs(data, text_offset, text_size, str_va)
        print(f"  Found {len(refs)} references to string VA 0x{str_va:08x}")

        for ref_off in refs:
            ref_rva = offset_to_rva(pe, ref_off)
            func_start = find_function_start(data, ref_off, text_offset)
            if func_start:
                func_rva = offset_to_rva(pe, func_start)
                func_end = find_function_end(data, func_start, text_end)
                func_size = func_end - func_start
                print(f"    -> Function at offset 0x{func_start:x} (RVA 0x{func_rva:x}, VA 0x{IMAGE_BASE + func_rva:08x}, ~{func_size} bytes)")
                getnavarea_funcs.append((func_start, func_rva, func_size))

    if not getnavarea_funcs:
        print("  ERROR: Could not find GetNavArea function")
        return

    # =========================================================================
    # Step 3: Find callers of GetNavArea → candidates for GetNearestNavArea
    # =========================================================================
    print("\n=== Step 3: Find callers of GetNavArea ===")

    for gna_start, gna_rva, gna_size in getnavarea_funcs:
        print(f"\n  Searching for callers of GetNavArea (RVA 0x{gna_rva:x})...")
        call_refs = find_call_refs(data, text_offset, text_size, gna_rva, pe)
        print(f"  Found {len(call_refs)} call sites")

        candidates = []
        for call_off in call_refs:
            func_start = find_function_start(data, call_off, text_offset)
            if func_start:
                func_rva = offset_to_rva(pe, func_start)
                func_end = find_function_end(data, func_start, text_end)
                func_size = func_end - func_start

                # Skip tiny functions
                if func_size < 100:
                    continue

                # Check if it also calls IsBlocked
                calls = analyze_function_calls(data, pe, func_start, func_end, text_section)
                calls_isblocked = ISBLOCKED_RVA in calls
                calls_getnavarea = gna_rva in calls

                # Check what globals it reads
                globals_read = check_function_reads_global(data, pe, func_start, func_end)

                print(f"    Caller at RVA 0x{func_rva:x} (VA 0x{IMAGE_BASE + func_rva:08x}, ~{func_size} bytes)")
                print(f"      calls GetNavArea: {calls_getnavarea}, calls IsBlocked: {calls_isblocked}")
                print(f"      total calls: {len(calls)}, globals read: {len(globals_read)}")

                candidates.append({
                    'start': func_start,
                    'rva': func_rva,
                    'size': func_size,
                    'calls_isblocked': calls_isblocked,
                    'calls': calls,
                    'globals': globals_read,
                })

        # =====================================================================
        # Step 4: Identify GetNearestNavArea among candidates
        # =====================================================================
        print("\n=== Step 4: Identify GetNearestNavArea ===")

        # Best candidate: calls both GetNavArea AND IsBlocked, is large
        best = [c for c in candidates if c['calls_isblocked'] and c['size'] > 200]
        if not best:
            # Fallback: just large functions calling GetNavArea
            best = [c for c in candidates if c['size'] > 200]

        if not best:
            print("  No strong candidates found")
            continue

        # Sort by size descending (GetNearestNavArea is a big function)
        best.sort(key=lambda c: c['size'], reverse=True)

        print(f"\n  Top candidates (calls GetNavArea + IsBlocked, >200 bytes):")
        for i, c in enumerate(best[:5]):
            sig, raw = make_signature(data, pe, c['start'], relocs, 32)
            print(f"\n  [{i+1}] RVA 0x{c['rva']:x} (VA 0x{IMAGE_BASE + c['rva']:08x})")
            print(f"      Size: ~{c['size']} bytes")
            print(f"      Calls IsBlocked: {c['calls_isblocked']}")
            print(f"      Total outgoing calls: {len(c['calls'])}")
            print(f"      Sig: \"{sig}\"")
            print(f"      Raw: {raw}")

            # Show globals accessed (one might be TheNavMesh)
            if c['globals']:
                print(f"      Globals read:")
                for grva, gaddr, ginstr in c['globals'][:10]:
                    print(f"        RVA 0x{grva:x}: reads 0x{IMAGE_BASE + gaddr:08x} — {ginstr}")

    # =========================================================================
    # Step 5: Find TheNavMesh address
    # =========================================================================
    print("\n=== Step 5: Find TheNavMesh global address ===")
    print("  Looking for pattern: function reads a global pointer, dereferences it,")
    print("  then uses it as 'this' for GetNavArea or GetNearestNavArea...")

    # TheNavMesh is typically accessed as: mov eax, [TheNavMesh]; test eax,eax; jz ...
    # It's a CNavMesh* pointer. Functions like GetNavArea use VPROF, so the global
    # is usually read before the VPROF call.
    # Let's look at the GetNavArea function itself and check what globals it accesses
    for gna_start, gna_rva, gna_size in getnavarea_funcs:
        print(f"\n  GetNavArea (RVA 0x{gna_rva:x}) reads these globals:")
        func_end = find_function_end(data, gna_start, text_end)
        globals_read = check_function_reads_global(data, pe, gna_start, func_end)
        for grva, gaddr, ginstr in globals_read:
            print(f"    0x{IMAGE_BASE + gaddr:08x} (RVA 0x{gaddr:x}) — {ginstr}")

    # Also check the GetNearestNavArea candidates
    if best:
        for c in best[:3]:
            print(f"\n  GetNearestNavArea candidate (RVA 0x{c['rva']:x}) reads these globals:")
            for grva, gaddr, ginstr in c['globals'][:15]:
                print(f"    0x{IMAGE_BASE + gaddr:08x} (RVA 0x{gaddr:x}) — {ginstr}")

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
