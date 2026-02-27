#!/usr/bin/env python3
"""
Find CNavMesh::GetNearestNavArea in Windows server.dll - approach 2.

Strategy: Scan all function prologues in .text that call GetNavArea (0x33e730)
early in the function body. GetNearestNavArea does a "quick check" calling
GetNavArea within the first ~50 instructions. Cross-reference with calling
GetGroundHeight and accessing m_grid to confirm.

Also determine TheNavMesh by finding callers of GetNearestNavArea candidates
that load a global into ecx before calling.
"""

import struct
import re
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL_PATH = "reverseengeneer/server.dll"
IMAGE_BASE = 0x10000000
GETNAVAREA_RVA = 0x33e730  # from Step 2 of first script

def load_dll():
    return pefile.PE(DLL_PATH)

def rva_to_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

def offset_to_rva(pe, offset):
    for s in pe.sections:
        if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
            return offset - s.PointerToRawData + s.VirtualAddress
    return None

def get_relocations(pe):
    relocs = set()
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in base_reloc.entries:
                if entry.type != 0:
                    relocs.add(entry.rva)
    return relocs

def make_signature(data, pe, func_offset, relocs, length=32):
    func_rva = offset_to_rva(pe, func_offset)
    if func_rva is None:
        return None, None
    raw_bytes = data[func_offset:func_offset + length]
    parts = []
    raw_hex = []
    for i in range(min(length, len(raw_bytes))):
        b = raw_bytes[i]
        byte_rva = func_rva + i
        is_reloc = any((byte_rva - j) in relocs for j in range(4) if j <= i)
        parts.append("\\x2A" if is_reloc else "\\x%02X" % b)
        raw_hex.append("%02X" % b)
    return "".join(parts), " ".join(raw_hex)


def find_all_function_prologues(data, text_offset, text_size):
    """Find all function entry points by scanning for common prologues."""
    prologues = []
    end = text_offset + text_size - 16

    i = text_offset
    while i < end:
        # Pattern 1: push ebp; mov ebp, esp (55 8B EC)
        if data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
            prologues.append(i)
            i += 3
            continue
        # Pattern 2: push ebx; mov ebx, esp; ... (53 8B DC) - stack alignment
        if data[i] == 0x53 and data[i+1] == 0x8B and data[i+2] == 0xDC:
            prologues.append(i)
            i += 3
            continue
        # Pattern 3: push esi (56) followed by mov esi, ecx (8B F1) - thiscall
        if data[i] == 0x56 and data[i+1] == 0x8B and data[i+2] == 0xF1:
            prologues.append(i)
            i += 3
            continue
        # Pattern 4: mov eax, [addr] (A1) at function start after CC padding
        if i > text_offset and data[i-1] == 0xCC and data[i] != 0xCC:
            prologues.append(i)
            i += 1
            continue
        i += 1

    return prologues


def analyze_function(data, pe, func_start, text_end, target_rva=GETNAVAREA_RVA, max_scan=2048):
    """Analyze a function for calls to target_rva. Returns info dict or None."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    func_rva = offset_to_rva(pe, func_start)
    if func_rva is None:
        return None

    scan_size = min(max_scan, text_end - func_start)
    code = data[func_start:func_start + scan_size]

    calls = []
    call_count = 0
    first_target_call_offset = None
    total_insn = 0
    last_ret_offset = 0
    func_size_estimate = 0
    vtable_calls = 0

    for insn in md.disasm(code, func_rva + IMAGE_BASE):
        total_insn += 1
        rel_offset = insn.address - (func_rva + IMAGE_BASE)

        if insn.mnemonic in ('ret', 'retn'):
            last_ret_offset = rel_offset + insn.size
        if insn.mnemonic == 'int3':
            func_size_estimate = last_ret_offset
            break

        if insn.mnemonic == 'call':
            call_count += 1
            if insn.op_str.startswith('0x'):
                try:
                    target = int(insn.op_str, 16) - IMAGE_BASE
                    calls.append((rel_offset, target))
                    if target == target_rva and first_target_call_offset is None:
                        first_target_call_offset = rel_offset
                except ValueError:
                    pass
            else:
                # Indirect call (vtable)
                vtable_calls += 1

    if func_size_estimate == 0:
        func_size_estimate = last_ret_offset if last_ret_offset > 0 else scan_size

    if first_target_call_offset is None:
        return None

    return {
        'start': func_start,
        'rva': func_rva,
        'size': func_size_estimate,
        'first_target_call': first_target_call_offset,
        'total_calls': call_count,
        'direct_calls': calls,
        'vtable_calls': vtable_calls,
        'total_insn': total_insn,
    }


def disassemble_function(data, pe, func_start, max_bytes=512):
    """Disassemble first N bytes of a function for inspection."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    func_rva = offset_to_rva(pe, func_start)
    code = data[func_start:func_start + max_bytes]
    lines = []
    for insn in md.disasm(code, func_rva + IMAGE_BASE):
        lines.append(f"  0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ('ret', 'retn', 'int3'):
            break
        if len(lines) > 60:
            lines.append("  ...")
            break
    return "\n".join(lines)


def find_callers_of(data, pe, text_offset, text_size, target_rva):
    """Find all E8 call sites targeting target_rva."""
    results = []
    for i in range(text_offset, text_offset + text_size - 5):
        if data[i] == 0xE8:
            rel = struct.unpack_from('<i', data, i + 1)[0]
            caller_rva = offset_to_rva(pe, i)
            if caller_rva is not None:
                dest_rva = caller_rva + 5 + rel
                if dest_rva == target_rva:
                    results.append(i)
    return results


def main():
    print("Loading DLL...")
    pe = load_dll()
    data = pe.__data__

    text_section = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name == '.text':
            text_section = s
            break

    text_offset = text_section.PointerToRawData
    text_size = text_section.SizeOfRawData
    text_end = text_offset + text_size
    relocs = get_relocations(pe)

    # =========================================================================
    # Approach: Find function prologues and check which ones call GetNavArea
    # GetNearestNavArea should call GetNavArea within the first ~150 bytes
    # =========================================================================
    print(f"\nScanning for function prologues...")
    prologues = find_all_function_prologues(data, text_offset, text_size)
    print(f"  Found {len(prologues)} function prologues")

    print(f"\nChecking which functions call GetNavArea (RVA 0x{GETNAVAREA_RVA:x})...")
    print(f"  Looking for calls within first 200 bytes of function body...\n")

    candidates = []
    for p_off in prologues:
        info = analyze_function(data, pe, p_off, text_end, GETNAVAREA_RVA, max_scan=4096)
        if info and info['first_target_call'] < 200:
            candidates.append(info)

    print(f"Found {len(candidates)} functions that call GetNavArea within first 200 bytes:\n")

    # Sort by first_target_call offset (earliest call = most likely quick check)
    candidates.sort(key=lambda c: (c['first_target_call'], -c['size']))

    for i, c in enumerate(candidates):
        sig, raw = make_signature(data, pe, c['start'], relocs, 32)
        print(f"[{i+1}] RVA 0x{c['rva']:x} (VA 0x{IMAGE_BASE + c['rva']:08x})")
        print(f"    Size: ~{c['size']} bytes")
        print(f"    GetNavArea call at offset +{c['first_target_call']} bytes")
        print(f"    Total calls: {c['total_calls']} direct + {c['vtable_calls']} vtable")
        print(f"    Sig: \"{sig}\"")
        print(f"    Raw: {raw}")

        # Check other calls this function makes
        call_targets = set(rva for _, rva in c['direct_calls'])
        print(f"    Unique direct call targets: {len(call_targets)}")

        # Show first 40 instructions
        print(f"    Disassembly (first ~512 bytes):")
        disasm = disassemble_function(data, pe, c['start'], 512)
        print(disasm)
        print()

    # =========================================================================
    # For the best candidate, find its callers to determine TheNavMesh
    # =========================================================================
    if candidates:
        print("\n" + "=" * 70)
        print("=== Finding TheNavMesh global ===")
        print("=" * 70)

        # Check the top candidates
        for c in candidates[:3]:
            target_rva = c['rva']
            print(f"\nSearching for callers of candidate at RVA 0x{target_rva:x}...")

            call_sites = find_callers_of(data, pe, text_offset, text_size, target_rva)
            print(f"  Found {len(call_sites)} call sites")

            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for cs_off in call_sites[:8]:
                # Disassemble 30 bytes before the call to see setup
                pre_start = max(text_offset, cs_off - 60)
                pre_code = data[pre_start:cs_off + 5]
                pre_rva = offset_to_rva(pe, pre_start)

                print(f"\n  Call site at offset 0x{cs_off:x} (RVA 0x{offset_to_rva(pe, cs_off):x}):")
                for insn in md.disasm(pre_code, pre_rva + IMAGE_BASE):
                    marker = " <-- CALL" if insn.address == offset_to_rva(pe, cs_off) + IMAGE_BASE else ""
                    print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}{marker}")


if __name__ == "__main__":
    main()
