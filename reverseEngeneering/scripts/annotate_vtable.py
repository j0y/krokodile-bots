#!/usr/bin/env python3
"""
Post-process Ghidra decompiled .c files to annotate vtable dispatches with method names.

Resolves patterns like:
  (**(code **)(*(int *)in_stack_0000000c + 0x974))(...)
to:
  (**(code **)(*(int *)in_stack_0000000c + 0x974 /* GetVisionInterface */))(...)

Also tracks interface getter return values to annotate component method calls:
  piVar = (...)(**(code **)(*(int *)bot + 0x974))(bot)  -> piVar = Vision
  (**(code **)(*piVar + 0xd0))(piVar)  -> Vision::GetPrimaryKnownThreat

Strategy:
1. Load vtable_map.json for CINSNextBot and component vtables
2. For each function, identify bot pointers (used with high unique offsets)
3. Track interface getter return values line-by-line
4. Annotate vtable dispatches with method names
5. Fix incorrect PIC annotations that landed on vtable dispatches
"""

import json
import os
import re
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

VTABLE_MAP_PATH = os.path.join(REPO_ROOT, "analysis", "vtable_map.json")
DECOMPILED_DIR = os.path.join(REPO_ROOT, "decompiled")

# Interface getter vtable offsets (decimal) -> component vtable class key
INTERFACE_GETTERS = {
    2412: "CINSBotLocomotion",   # 0x96c  GetLocomotionInterface
    2416: "CINSBotBody",         # 0x970  GetBodyInterface
    2420: "CINSBotVision",       # 0x974  GetVisionInterface
    2428: "CINSNextBotIntention", # 0x97c  GetIntentionInterface
}

# Minimum vtable offset unique to CINSNextBot (above all component vtable max offsets)
# CINSBotLocomotion max = 436 (0x1b4), so 440 (0x1b8) and above are unique
BOT_UNIQUE_MIN_OFFSET = 440

# Vtable dispatch pattern:
#   **(code **)(*[opt (int *)]VAR + 0xHEX [opt /* comment */])
VTABLE_RE = re.compile(
    r'\*\*\(code \*\*\)'
    r'\('
    r'\*(\(int \*\))?'           # group 1: optional (int *) cast
    r'(\w+)'                     # group 2: variable name
    r' \+ '
    r'(0x[0-9a-fA-F]+)'         # group 3: hex offset
    r'(\s*/\*[^*]*\*/)?'        # group 4: optional existing /* comment */
    r'\)'
)

# Function header boundary pattern
FUNC_HEADER_RE = re.compile(
    r'/\* -{20,}\s*\n'
    r' \* (\S+.*?)\s*\n'
    r' \* Address: ([0-9a-fA-F]+)\s*\n'
    r' \* -{20,} \*/',
    re.MULTILINE
)


def load_vtable_map(path):
    """Load vtable map and build offset lookup tables (decimal int keys)."""
    with open(path) as f:
        data = json.load(f)

    tables = {}
    for cls_name, entries in data["vtables"].items():
        tbl = {}
        for dec_str, method_name in entries.items():
            tbl[int(dec_str)] = method_name
        tables[cls_name] = tbl

    return tables


def simplify_method(name):
    """Simplify method name for inline annotation. Strip params and templates."""
    paren = name.find("(")
    if paren > 0:
        name = name[:paren]
    name = name.replace("<CINSNextBot>", "")
    name = name.replace("<CINSPlayer>", "")
    name = name.replace("<CBasePlayer>", "")
    return name


def process_file(filepath, vtables, global_stats):
    """Process a single .c file, annotating vtable dispatches in-place."""
    with open(filepath) as f:
        content = f.read()

    # Find function boundaries
    headers = list(FUNC_HEADER_RE.finditer(content))
    if not headers:
        return content, False

    func_ranges = []
    for i, m in enumerate(headers):
        start = m.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(content)
        func_ranges.append((start, end))

    bot_vtable = vtables.get("CINSNextBot", {})

    # --- Phase 1: identify bot pointer variables per function ---
    # A variable is a "bot pointer" if it's used in a vtable dispatch at a
    # CINSNextBot-unique offset (>= BOT_UNIQUE_MIN_OFFSET).
    func_bot_vars = []  # parallel to func_ranges
    for fstart, fend in func_ranges:
        func_text = content[fstart:fend]
        bot_vars = set()
        for m in VTABLE_RE.finditer(func_text):
            offset = int(m.group(3), 16)
            if offset >= BOT_UNIQUE_MIN_OFFSET and offset in bot_vtable:
                bot_vars.add(m.group(2))
        func_bot_vars.append(bot_vars)

    # --- Phase 2: line-by-line processing with interface tracking ---
    # We process each function's lines, tracking interface variable assignments.
    # Then we collect all replacement positions (absolute in the full content).

    replacements = []  # (abs_start, abs_end, new_text)

    for func_idx, (fstart, fend) in enumerate(func_ranges):
        bot_vars = func_bot_vars[func_idx]
        interface_vars = {}  # var_name -> component class key

        func_text = content[fstart:fend]
        line_start = 0  # relative to func_text

        for line in func_text.split("\n"):
            line_end = line_start + len(line)

            # Find all vtable dispatches on this line
            dispatches = list(VTABLE_RE.finditer(line))

            # --- Annotate dispatches ---
            for dm in dispatches:
                var_name = dm.group(2)
                offset = int(dm.group(3), 16)
                existing_comment = dm.group(4)

                method_name = None

                # Check interface_vars FIRST — it tracks current variable type
                # via line-by-line analysis, while bot_vars is a whole-function scan
                # that doesn't account for variable reassignment
                if var_name in interface_vars:
                    component = interface_vars[var_name]
                    comp_vtable = vtables.get(component, {})
                    method_name = comp_vtable.get(offset)
                elif var_name in bot_vars:
                    method_name = bot_vtable.get(offset)

                if method_name is None:
                    global_stats["skipped"] += 1
                    continue

                method_name = simplify_method(method_name)
                offset_str = dm.group(3)
                new_text = "%s /* %s */" % (offset_str, method_name)

                # Absolute positions in full content
                rep_start = fstart + line_start + dm.start(3)
                rep_end = fstart + line_start + (
                    dm.end(4) if existing_comment else dm.end(3)
                )

                replacements.append((rep_start, rep_end, new_text))

                if existing_comment:
                    global_stats["replaced_pic"] += 1
                else:
                    global_stats["new"] += 1

            # --- Track interface getter assignments ---
            # Look for: VAR = ...(bot + 0x96c/0x970/0x974/0x97c)...
            for dm in dispatches:
                var_name = dm.group(2)
                offset = int(dm.group(3), 16)
                if var_name in bot_vars and offset in INTERFACE_GETTERS:
                    # Find the assignment target at the start of this statement
                    assign_match = re.match(r"\s*(\w+)\s*=", line)
                    if assign_match:
                        assigned = assign_match.group(1)
                        interface_vars[assigned] = INTERFACE_GETTERS[offset]

            # --- Clear interface vars on non-getter reassignment ---
            for var in list(interface_vars.keys()):
                # Check if this var is assigned on this line
                if re.search(r"\b" + re.escape(var) + r"\s*=", line):
                    # But don't clear if this IS the interface getter assignment
                    is_getter = False
                    for dm in dispatches:
                        if dm.group(2) in bot_vars and int(dm.group(3), 16) in INTERFACE_GETTERS:
                            assign_match = re.match(r"\s*(\w+)\s*=", line)
                            if assign_match and assign_match.group(1) == var:
                                is_getter = True
                                break
                    if not is_getter:
                        del interface_vars[var]

            line_start = line_end + 1  # +1 for newline

    if not replacements:
        return content, False

    # Apply replacements in reverse position order
    result = content
    for start, end, repl in sorted(replacements, key=lambda r: r[0], reverse=True):
        result = result[:start] + repl + result[end:]

    return result, True


def main():
    if not os.path.isfile(VTABLE_MAP_PATH):
        print("ERROR: vtable_map.json not found: %s" % VTABLE_MAP_PATH)
        sys.exit(1)

    if not os.path.isdir(DECOMPILED_DIR):
        print("ERROR: decompiled directory not found: %s" % DECOMPILED_DIR)
        sys.exit(1)

    print("Loading vtable map...")
    vtables = load_vtable_map(VTABLE_MAP_PATH)
    for cls, tbl in vtables.items():
        print("  %s: %d entries (max offset %d / 0x%x)" % (
            cls, len(tbl), max(tbl.keys()), max(tbl.keys())))

    c_files = sorted(f for f in os.listdir(DECOMPILED_DIR) if f.endswith(".c"))

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        result, modified = process_file(filepath, vtables, stats)
        if modified:
            with open(filepath, "w") as f:
                f.write(result)
            modified_count += 1
            print("  %s" % filename)

    total = stats["new"] + stats["replaced_pic"]
    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  Vtable dispatches annotated: %d" % total)
    print("    New annotations: %d" % stats["new"])
    print("    Replaced PIC annotations: %d" % stats["replaced_pic"])
    print("    Skipped (ambiguous): %d" % stats["skipped"])


if __name__ == "__main__":
    main()
