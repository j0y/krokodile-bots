#!/usr/bin/env python3
"""
Post-process Ghidra decompiled .c files to resolve misleading PIC annotations.

resolve_pic_refs.py annotates PIC-relative references with the nearest nm symbol.
For .rodata addresses that contain float constants (not strings), this produces
misleading annotations like:

    *(float *)(unaff_EBX + 0x20e551 /* typeinfo name for CBaseGameSystem+0x22 */)

This script:
1. Parses these annotations to recover the actual .rodata address
2. Reads the raw bytes from the binary
3. Replaces with the decoded float value (or raw hex if not a nice float)

Example:
    /* typeinfo name for CBaseGameSystem+0x22 */  ->  /* 5.0f */
"""

import math
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(REPO_ROOT)

BINARY = os.path.join(
    PROJECT_ROOT,
    "insurgency-server/server-files/insurgency/bin/server_srv.so",
)

DECOMPILED_DIR = os.path.join(REPO_ROOT, "decompiled")

# Segment boundaries (from resolve_pic_refs.py)
SEG2_START_VADDR = 0x00B0FF20  # .data.rel.ro start
SEG2_FILE_OFFSET_DELTA = 0x1000

# Well-known 32-bit constants
SPECIAL_VALUES = {
    0x00000000: "0.0f",
    0x80000000: "SIGN_BIT_MASK",
    0x7F7FFFFF: "FLT_MAX",
    0x7F800000: "+INF",
    0xFF800000: "-INF",
    0xFFFFFFFF: "NaN / -1",
    0x3F800000: "1.0f",
    0xBF800000: "-1.0f",
}

# Regex to match misleading "typeinfo name for" annotations with offset.
# Captures:
#   group(1): full symbol name, e.g. "typeinfo name for CBaseGameSystem"
#   group(2): hex offset, e.g. "22"
ANNOTATION_RE = re.compile(
    r'/\* (typeinfo name for .+?)\+0x([0-9a-fA-F]+) \*/'
)


def vaddr_to_file_offset(vaddr):
    """Convert real virtual address to file offset."""
    if vaddr < SEG2_START_VADDR:
        return vaddr
    return vaddr - SEG2_FILE_OFFSET_DELTA


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def build_symbol_dict(binary_path):
    """Build symbol name -> address mapping from nm -C."""
    result = subprocess.run(
        ["nm", "-C", "-n", binary_path],
        capture_output=True, text=True,
    )
    sym_dict = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                sym_dict[name] = addr
            except ValueError:
                continue
    return sym_dict


def read_float_at(data, vaddr):
    """Read 4 bytes at virtual address and interpret as IEEE 754 float."""
    offset = vaddr_to_file_offset(vaddr)
    if offset < 0 or offset + 4 > len(data):
        return None
    try:
        return struct.unpack_from("<f", data, offset)[0]
    except struct.error:
        return None


def read_uint32_at(data, vaddr):
    """Read 4 bytes at virtual address as unsigned 32-bit integer."""
    offset = vaddr_to_file_offset(vaddr)
    if offset < 0 or offset + 4 > len(data):
        return None
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error:
        return None


def is_nice_float(f):
    """Check if a float value looks like a deliberate constant.

    Mirrors the logic from annotate_floats.py.
    """
    if math.isnan(f) or math.isinf(f):
        return False

    absf = abs(f)
    if absf < 0.0001 or absf > 100000:
        return False

    s = "%.7g" % f
    if "." in s:
        s = s.rstrip("0").rstrip(".")

    digits = s.lstrip("-").replace(".", "")
    return len(digits) <= 6


def format_float(f):
    """Format a float value for annotation."""
    s = "%.7g" % f
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if "." not in s and "e" not in s and "E" not in s:
        s = s + ".0"
    return s + "f"


def process_file(filepath, data, sym_dict, stats):
    """Process a single .c file, replacing misleading typeinfo annotations."""
    with open(filepath) as f:
        content = f.read()

    replacements = []

    for m in ANNOTATION_RE.finditer(content):
        sym_name = m.group(1).strip()
        offset = int(m.group(2), 16)

        sym_addr = sym_dict.get(sym_name)
        if sym_addr is None:
            stats["sym_not_found"] += 1
            continue

        actual_addr = sym_addr + offset

        # Read raw 32-bit value
        u_val = read_uint32_at(data, actual_addr)
        if u_val is None:
            stats["unresolved"] += 1
            continue

        # Check well-known special constants first
        if u_val in SPECIAL_VALUES:
            new_annotation = "/* %s */" % SPECIAL_VALUES[u_val]
            replacements.append((m.start(), m.end(), new_annotation))
            stats["special"] += 1
            continue

        # Try interpreting as IEEE 754 float
        f_val = read_float_at(data, actual_addr)
        if f_val is not None and is_nice_float(f_val):
            new_annotation = "/* %s */" % format_float(f_val)
            replacements.append((m.start(), m.end(), new_annotation))
            stats["float"] += 1
            continue

        # Fall back to raw hex
        new_annotation = "/* rodata:0x%08X */" % u_val
        replacements.append((m.start(), m.end(), new_annotation))
        stats["hex"] += 1

    if not replacements:
        return content, False

    # Apply in reverse order
    result = content
    for start, end, repl in sorted(replacements, key=lambda r: r[0], reverse=True):
        result = result[:start] + repl + result[end:]

    return result, True


def main():
    if not os.path.isfile(BINARY):
        print("ERROR: Binary not found: %s" % BINARY)
        sys.exit(1)

    if not os.path.isdir(DECOMPILED_DIR):
        print("ERROR: Decompiled directory not found: %s" % DECOMPILED_DIR)
        sys.exit(1)

    print("Loading binary...")
    data = load_binary(BINARY)

    print("Building symbol table...")
    sym_dict = build_symbol_dict(BINARY)
    print("  %d symbols loaded" % len(sym_dict))

    c_files = sorted(f for f in os.listdir(DECOMPILED_DIR) if f.endswith(".c"))

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        result, modified = process_file(filepath, data, sym_dict, stats)
        if modified:
            with open(filepath, "w") as f:
                f.write(result)
            modified_count += 1
            print("  %s" % filename)

    total = stats["float"] + stats["hex"] + stats["special"]
    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  Annotations replaced: %d" % total)
    print("    Float constants: %d" % stats["float"])
    print("    Special values: %d" % stats["special"])
    print("    Raw hex: %d" % stats["hex"])
    print("    Symbol not found: %d" % stats["sym_not_found"])
    print("    Unresolved: %d" % stats["unresolved"])


if __name__ == "__main__":
    main()
