#!/usr/bin/env python3
"""
Post-process Ghidra decompiled .c files to resolve PIC GOT-relative references.

Ghidra's decompiler doesn't resolve 32-bit PIC thunk patterns, leaving references
as raw `unaff_EBX + 0x...` / `extraout_ECX + 0x...` offsets. This script:

1. Finds the thunk call in each function's binary to determine the base address
2. Computes actual virtual addresses from decompiler offsets
3. Resolves addresses to string literals, symbol names, or section labels
4. Annotates the .c files with inline /* comments */

Formula: actual_VA = thunk_return_address + signed_offset_from_decompiler

Ghidra loads server_srv.so with a 0x10000 image base, so:
    real_VA = ghidra_address - IMAGE_BASE
"""

import os
import re
import struct
import subprocess
import sys
from bisect import bisect_right
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(REPO_ROOT)

BINARY = os.path.join(
    PROJECT_ROOT,
    "insurgency-server/server-files/insurgency/bin/server_srv.so",
)

# Ghidra image base (auto-detected, this is the default)
IMAGE_BASE = 0x10000

# ELF section boundaries (real VAs from readelf)
RODATA_VADDR = 0x008A8280
RODATA_END = 0x008A8280 + 0x000DE324  # 0x009865A4
TEXT_VADDR = 0x0011AC80
TEXT_END = 0x0011AC80 + 0x0078D5C8  # 0x008A8248
DATA_REL_RO_VADDR = 0x00B0FF20
DATA_REL_RO_END = 0x00B0FF20 + 0x00086464  # 0x00B96384
GOT_VADDR = 0x00B96484
GOT_END = 0x00B96484 + 0x00000CF4  # 0x00B97178
GOT_PLT_VADDR = 0x00B97178
GOT_PLT_END = 0x00B97178 + 0x0000030C  # 0x00B97484
DATA_VADDR = 0x00B974A0
DATA_END = 0x00B974A0 + 0x0006FB60  # 0x00C07000
BSS_VADDR = 0x00C07000
BSS_END = 0x00C07000 + 0x0011BFA0  # 0x00D22FA0

# Second LOAD segment: vaddr = file_offset + 0x1000
SEG2_FILE_OFFSET_DELTA = 0x1000
# Boundary between segments (approximate): sections before .data.rel.ro use seg1
SEG2_START_VADDR = DATA_REL_RO_VADDR

# Known PIC thunk addresses (real VAs)
THUNK_ADDRS = {
    0x00169162,  # __i686.get_pc_thunk.bx
    0x001694A2,  # __i686.get_pc_thunk.cx
    0x0030C025,  # __i686.get_pc_thunk.dx
}

# Regex to match PIC offset patterns in decompiled C
# Matches: unaff_EBX + 0x1234, extraout_ECX + -0x5678, etc.
PIC_OFFSET_RE = re.compile(
    r'\b(unaff_EBX|unaff_EBP|extraout_ECX|extraout_EDX|extraout_EBX)'
    r' \+ (-?0x[0-9a-fA-F]+)'
)

# Regex to extract function address from comment headers
FUNC_ADDR_RE = re.compile(r'^\s*\* Address: ([0-9a-fA-F]+)\s*$', re.MULTILINE)


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def vaddr_to_file_offset(vaddr):
    """Convert real virtual address to file offset."""
    if vaddr < SEG2_START_VADDR:
        return vaddr  # first LOAD segment: file_offset == vaddr
    return vaddr - SEG2_FILE_OFFSET_DELTA


def extract_cstring(data, vaddr, max_len=256):
    """Read a null-terminated ASCII string from the binary at a real VA."""
    offset = vaddr_to_file_offset(vaddr)
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b'\x00', offset, offset + max_len)
    if end == -1 or end == offset:
        return None
    raw = data[offset:end]
    try:
        s = raw.decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None
    if len(s) < 2:
        return None
    if not all(c.isprintable() or c in '\t\n\r' for c in s):
        return None
    return s


def build_symbol_table(binary_path):
    """Build sorted symbol list and address lookup from nm."""
    result = subprocess.run(
        ["nm", "-C", "-n", binary_path],
        capture_output=True, text=True,
    )
    sym_list = []  # [(addr, name)]
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                sym_list.append((addr, name))
            except ValueError:
                continue
    sym_list.sort()
    return sym_list


def find_nearest_symbol(sym_list, addr):
    """Find the symbol at or just before the given address."""
    addrs = [a for a, _ in sym_list]
    idx = bisect_right(addrs, addr) - 1
    if idx < 0:
        return None
    sym_addr, sym_name = sym_list[idx]
    if addr - sym_addr > 0x10000:
        return None  # too far away
    if addr == sym_addr:
        return sym_name
    return "%s+0x%x" % (sym_name, addr - sym_addr)


def find_exact_symbol(sym_list, addr):
    """Find exact symbol match only."""
    addrs = [a for a, _ in sym_list]
    idx = bisect_right(addrs, addr) - 1
    if idx < 0:
        return None
    if sym_list[idx][0] == addr:
        return sym_list[idx][1]
    return None


def find_thunk_return(data, ghidra_addr):
    """Find the PIC thunk call in a function and return the thunk_return real VA.

    Scans the first 40 bytes of the function for a call (E8) to a known thunk.
    Returns the real VA of the instruction after the call, or None.
    """
    real_va = ghidra_addr - IMAGE_BASE
    file_off = vaddr_to_file_offset(real_va)
    if file_off < 0 or file_off + 45 > len(data):
        return None

    for i in range(40):
        pos = file_off + i
        if pos + 5 > len(data):
            break
        if data[pos] == 0xE8:
            rel32 = struct.unpack_from("<i", data, pos + 1)[0]
            call_real_va = real_va + i
            target = call_real_va + 5 + rel32
            if target in THUNK_ADDRS:
                return call_real_va + 5  # thunk_return = address after call
    return None


def resolve_address(addr, data, sym_list):
    """Resolve a real VA to a human-readable annotation.

    Returns (annotation_string, is_string_literal) or (None, False).
    """
    # Check .rodata for string literals
    if RODATA_VADDR <= addr < RODATA_END:
        s = extract_cstring(data, addr)
        if s:
            # Truncate very long strings
            if len(s) > 80:
                s = s[:77] + "..."
            return '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"'), True
        # Not a string — could be a float constant, vtable, etc.
        sym = find_nearest_symbol(sym_list, addr)
        if sym:
            return sym, False
        return "rodata:0x%08x" % addr, False

    # Check .text for function pointers
    if TEXT_VADDR <= addr < TEXT_END:
        sym = find_nearest_symbol(sym_list, addr)
        if sym:
            # Clean up the symbol name for readability
            name = sym
            # Remove long parameter lists for brevity
            paren = name.find('(')
            if paren > 0:
                name = name[:paren]
            return name, False
        return "text:0x%08x" % addr, False

    # Check .data.rel.ro (vtables, typeinfo, etc.)
    if DATA_REL_RO_VADDR <= addr < DATA_REL_RO_END:
        sym = find_nearest_symbol(sym_list, addr)
        if sym:
            name = sym
            paren = name.find('(')
            if paren > 0:
                name = name[:paren]
            return name, False
        return "data.rel.ro:0x%08x" % addr, False

    # Check GOT / GOT.PLT
    if GOT_VADDR <= addr < GOT_PLT_END:
        # This is a GOT entry — read the value it points to
        file_off = vaddr_to_file_offset(addr)
        if file_off + 4 <= len(data):
            got_value = struct.unpack_from("<I", data, file_off)[0]
            sym = find_exact_symbol(sym_list, got_value)
            if sym:
                name = sym
                paren = name.find('(')
                if paren > 0:
                    name = name[:paren]
                return "&%s" % name, False
        return "got:0x%08x" % addr, False

    # Check .data
    if DATA_VADDR <= addr < DATA_END:
        sym = find_nearest_symbol(sym_list, addr)
        if sym:
            name = sym
            paren = name.find('(')
            if paren > 0:
                name = name[:paren]
            return name, False
        return "data:0x%08x" % addr, False

    # Check BSS
    if BSS_VADDR <= addr < BSS_END:
        sym = find_nearest_symbol(sym_list, addr)
        if sym:
            name = sym
            paren = name.find('(')
            if paren > 0:
                name = name[:paren]
            return name, False
        return "bss:0x%08x" % addr, False

    return None, False


def process_c_file(filepath, data, sym_list, stats):
    """Process a single decompiled .c file, resolving PIC references in-place."""
    with open(filepath, "r") as f:
        content = f.read()

    # Find all function boundaries and their addresses
    # Each function block starts with: /* Address: XXXXXXXX */
    func_addrs = []
    for m in FUNC_ADDR_RE.finditer(content):
        ghidra_addr = int(m.group(1), 16)
        func_addrs.append((m.start(), ghidra_addr))

    if not func_addrs:
        return content, False

    # Build thunk_return cache for each function
    thunk_cache = {}  # ghidra_addr -> thunk_return (real VA)
    for _, ghidra_addr in func_addrs:
        if ghidra_addr not in thunk_cache:
            tr = find_thunk_return(data, ghidra_addr)
            thunk_cache[ghidra_addr] = tr

    # For each PIC offset match, find which function it belongs to and resolve
    replacements = []  # (match_start, match_end, replacement_string)

    for m in PIC_OFFSET_RE.finditer(content):
        reg_name = m.group(1)
        offset_str = m.group(2)

        # Parse signed hex offset
        if offset_str.startswith("-"):
            offset_val = -int(offset_str[1:], 16)
        else:
            offset_val = int(offset_str, 16)

        # Find which function this match belongs to
        match_pos = m.start()
        func_ghidra_addr = None
        for i, (fpos, faddr) in enumerate(func_addrs):
            if i + 1 < len(func_addrs) and match_pos >= func_addrs[i + 1][0]:
                continue
            if match_pos >= fpos:
                func_ghidra_addr = faddr
                break

        if func_ghidra_addr is None:
            # Fallback: use the last function before this position
            for fpos, faddr in reversed(func_addrs):
                if match_pos >= fpos:
                    func_ghidra_addr = faddr
                    break

        if func_ghidra_addr is None:
            continue

        thunk_return = thunk_cache.get(func_ghidra_addr)
        if thunk_return is None:
            stats["no_thunk"] += 1
            continue

        # Compute actual address
        actual_va = (thunk_return + offset_val) & 0xFFFFFFFF

        # Resolve
        annotation, is_string = resolve_address(actual_va, data, sym_list)
        if annotation is None:
            stats["unresolved"] += 1
            continue

        # Build replacement: original expression + /* annotation */
        original = m.group(0)
        replacement = "%s /* %s */" % (original, annotation)

        replacements.append((m.start(), m.end(), replacement))
        if is_string:
            stats["strings"] += 1
        else:
            stats["symbols"] += 1

    if not replacements:
        return content, False

    # Apply replacements in reverse order to preserve positions
    result = content
    for start, end, repl in reversed(replacements):
        result = result[:start] + repl + result[end:]

    return result, True


def main():
    decompiled_dir = os.path.join(REPO_ROOT, "decompiled")

    if not os.path.isfile(BINARY):
        print("ERROR: Binary not found: %s" % BINARY)
        sys.exit(1)

    if not os.path.isdir(decompiled_dir):
        print("ERROR: Decompiled directory not found: %s" % decompiled_dir)
        sys.exit(1)

    print("Loading binary...")
    data = load_binary(BINARY)

    print("Building symbol table...")
    sym_list = build_symbol_table(BINARY)
    print("  %d symbols loaded" % len(sym_list))

    # Verify image base by checking a known thunk
    # The thunks should be at known addresses in the binary
    for thunk_addr in sorted(THUNK_ADDRS):
        file_off = vaddr_to_file_offset(thunk_addr)
        if file_off < len(data):
            # Thunk is: mov (%esp), %reg; ret — typically 8B 04 24 C3 or 8B 0C 24 C3
            b = data[file_off:file_off + 4]
            if b[0] == 0x8B and b[2] == 0x24 and b[3] == 0xC3:
                print("  Verified thunk at real VA 0x%08x" % thunk_addr)

    # Process all .c files
    c_files = sorted(
        f for f in os.listdir(decompiled_dir)
        if f.endswith(".c")
    )

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(decompiled_dir, filename)
        result, modified = process_c_file(filepath, data, sym_list, stats)
        if modified:
            with open(filepath, "w") as f:
                f.write(result)
            modified_count += 1
            file_resolved = (
                result.count("/*") - open(os.path.join(decompiled_dir, filename)).read().count("/*")
                if False else 0  # skip re-count
            )
            print("  %s" % filename)

    total = stats["strings"] + stats["symbols"]
    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  References resolved: %d" % total)
    print("    Strings: %d" % stats["strings"])
    print("    Symbols: %d" % stats["symbols"])
    print("    No thunk found: %d" % stats["no_thunk"])
    print("    Unresolved: %d" % stats["unresolved"])


if __name__ == "__main__":
    main()
