#!/usr/bin/env python3
"""
Post-process Ghidra decompiled .c files to decode IEEE 754 float constants.

Ghidra often decompiles float constants as raw hex integers when the variable
type information is lost. This script finds hex literals that are plausible
IEEE 754 floats and annotates them with the decoded value.

Examples:
  0x3F800000  ->  0x3F800000 /* 1.0f */
  -0x40800000 ->  -0x40800000 /* -1.0f */
  0x42C80000  ->  0x42C80000 /* 100.0f */
"""

import os
import re
import struct
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DECOMPILED_DIR = os.path.join(REPO_ROOT, "decompiled")

# Match hex literals that could be floats.
# Positive: 0x38000000 to 0x4EFFFFFF (roughly 0.00003 to 1.8e9)
# Negative via two's complement: -0x01000001 to -0x48000000
#   (unsigned 0xB8000000 to 0xFEFFFFFF, roughly -0.00003 to -1.7e38)
# Also handle the special case -0x40800000 (very common, = -1.0f)
FLOAT_HEX_RE = re.compile(
    r'(?<!/\* )'           # not already inside a comment annotation
    r'(-?0x[0-9a-fA-F]{7,8})'  # group 1: hex literal (7-8 digits)
    r'(?!\s*/\*)'          # not already annotated
)

# Patterns immediately BEFORE the hex literal that mean it's NOT a float:
#   "VAR + " → struct offset
#   "(type *)" → pointer address
#   Already annotated → has /* */ after
SKIP_BEFORE_RE = re.compile(
    r'(?:'
    r'\w\s*\+\s*$'            # preceded by "VAR + " (struct/vtable offset)
    r'|'
    r'\*\)\s*$'               # preceded by "(type *)" cast directly on this value
    r')'
)


def hex_to_float(hex_str):
    """Convert hex literal (possibly negative) to IEEE 754 float.

    Returns (float_value, is_valid) tuple.
    """
    try:
        if hex_str.startswith("-"):
            # Negative hex: -0xNNNNNNNN
            # Convert to unsigned 32-bit: (-val) & 0xFFFFFFFF
            val = int(hex_str, 16)
            unsigned = val & 0xFFFFFFFF
        else:
            unsigned = int(hex_str, 16)

        if unsigned > 0xFFFFFFFF:
            return 0.0, False

        # Convert unsigned int to float via IEEE 754
        packed = struct.pack("<I", unsigned)
        f = struct.unpack("<f", packed)[0]
        return f, True
    except (ValueError, struct.error):
        return 0.0, False


def is_nice_float(f):
    """Check if a float value looks like a deliberate constant.

    Returns True for values like 0.1, 0.5, 1.0, 2.0, 30.0, etc.
    Returns False for values that are likely addresses or garbage.
    """
    import math

    if math.isnan(f) or math.isinf(f):
        return False

    absf = abs(f)

    # Must be in a reasonable range for game constants
    if absf < 0.001 or absf > 100000:
        return False

    # Check if the decimal representation is "clean"
    # Format with enough precision and check for simplicity
    s = "%.7g" % f
    # Remove trailing zeros after decimal point
    if "." in s:
        s = s.rstrip("0").rstrip(".")

    # A "nice" float has a short representation
    # Strip minus sign for length check
    digits = s.lstrip("-").replace(".", "")
    if len(digits) > 6:
        return False

    return True


def format_float(f):
    """Format a float value for annotation."""
    # Try to produce a clean representation
    s = "%.7g" % f
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    # Add .0 if it looks like an integer
    if "." not in s and "e" not in s and "E" not in s:
        s = s + ".0"
    return s + "f"


def process_file(filepath, stats):
    """Process a single .c file, annotating float constants."""
    with open(filepath) as f:
        content = f.read()

    replacements = []  # (start, end, new_text)

    for m in FLOAT_HEX_RE.finditer(content):
        hex_str = m.group(1)

        # Check length — must be exactly 8 hex digits (after 0x prefix)
        clean = hex_str.lstrip("-")
        if clean.startswith("0x") or clean.startswith("0X"):
            digits = clean[2:]
        else:
            continue
        if len(digits) != 8:
            continue

        # Skip if preceded by patterns indicating this is NOT a float:
        #   "VAR + 0xHEX" — struct/vtable offset
        #   "(type *)0xHEX" — pointer cast on the value
        before = content[max(0, m.start() - 10):m.start()]
        if SKIP_BEFORE_RE.search(before):
            stats["skipped_context"] += 1
            continue

        f_val, valid = hex_to_float(hex_str)
        if not valid:
            continue

        if not is_nice_float(f_val):
            stats["skipped_ugly"] += 1
            continue

        annotation = format_float(f_val)
        new_text = "%s /* %s */" % (hex_str, annotation)
        replacements.append((m.start(), m.end(), new_text))
        stats["annotated"] += 1

    if not replacements:
        return content, False

    # Apply in reverse
    result = content
    for start, end, repl in sorted(replacements, key=lambda r: r[0], reverse=True):
        result = result[:start] + repl + result[end:]

    return result, True


def main():
    if not os.path.isdir(DECOMPILED_DIR):
        print("ERROR: decompiled directory not found: %s" % DECOMPILED_DIR)
        sys.exit(1)

    c_files = sorted(f for f in os.listdir(DECOMPILED_DIR) if f.endswith(".c"))

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        result, modified = process_file(filepath, stats)
        if modified:
            with open(filepath, "w") as f:
                f.write(result)
            modified_count += 1
            print("  %s" % filename)

    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  Float constants annotated: %d" % stats["annotated"])
    print("  Skipped (pointer context): %d" % stats["skipped_context"])
    print("  Skipped (offset arithmetic): %d" % stats["skipped_offset"])
    print("  Skipped (not a nice float): %d" % stats["skipped_ugly"])


if __name__ == "__main__":
    main()
