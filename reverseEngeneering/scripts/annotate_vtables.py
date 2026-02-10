#!/usr/bin/env python3
"""
Annotate vtable dispatches in decompiled .c files with method names.

Matches virtual call patterns like:
  (**(code **)(*(int *)EXPR + 0xOFFSET))(...)     -- Pattern A: cast deref
  (**(code **)(*VAR + 0xOFFSET))(...)              -- Pattern B: simple deref
  (**(code **)(**(int **)EXPR + 0xOFFSET))(...)    -- Pattern C: double deref
and adds inline /* ClassName::MethodName */ comments.

Uses vtable_map.json (pre-built from binary vtable dumps + nm symbols).

Class determination strategy:
  1. If expression contains '+ 0x2060' -> CINSBotVision (embedded at that offset)
  2. If vtable offset > 436 (max CINSBotLocomotion) -> CINSNextBot
  3. Track interface getter assignments to resolve component vtable calls
  4. For remaining small offsets: prefer CINSNextBot, fall back to other vtables
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

# Known embedded sub-object offsets within CINSNextBot
SUBOBJECT_CLASS = {
    0x2060: "CINSBotVision",
}

# CINSNextBot vtable offsets for interface getters -> component class
INTERFACE_GETTER_OFFSETS = {
    0x96c: "CINSBotLocomotion",
    0x970: "CINSBotBody",
    0x974: "CINSBotVision",
    0x97c: "CINSNextBotIntention",
}

# Max vtable offset per class (for disambiguation)
MAX_SUB_INTERFACE_OFFSET = 436  # CINSBotLocomotion max


def load_vtable_map(path):
    """Load vtable_map.json and build lookup structures."""
    with open(path) as f:
        data = json.load(f)

    offset_to_methods = defaultdict(list)
    class_vtables = {}

    for cls_name, entries in data["vtables"].items():
        vtable = {}
        for offset_str, method_name in entries.items():
            offset_int = int(offset_str)
            vtable[offset_int] = method_name
            offset_to_methods[offset_int].append((cls_name, method_name))
        class_vtables[cls_name] = vtable

    return class_vtables, offset_to_methods


def resolve_vtable_call(vtable_offset, context_expr, hint_class,
                        class_vtables, offset_to_methods):
    """Determine the class and method name for a vtable dispatch.

    Args:
        vtable_offset: The vtable offset (int)
        context_expr: The expression before '+ 0xOFFSET', for sub-object hints
        hint_class: If set, the class is already known (from interface tracking)
        class_vtables: Per-class vtable lookup
        offset_to_methods: Global offset -> [(class, method)] mapping

    Returns:
        "ClassName::MethodName" or None
    """
    # If caller already determined the class (from interface tracking)
    if hint_class:
        vtable = class_vtables.get(hint_class, {})
        if vtable_offset in vtable:
            return _clean_method(vtable[vtable_offset])
        return None

    # Check for known embedded sub-object patterns in the expression
    for member_offset, cls_name in SUBOBJECT_CLASS.items():
        marker = "+ 0x%x" % member_offset
        if marker in context_expr or ("+ 0x%X" % member_offset) in context_expr:
            vtable = class_vtables.get(cls_name, {})
            if vtable_offset in vtable:
                return _clean_method(vtable[vtable_offset])
            return "%s::vfunc_0x%x" % (cls_name, vtable_offset)

    # High offsets can only be CINSNextBot (or CINSPlayer, same hierarchy)
    if vtable_offset > MAX_SUB_INTERFACE_OFFSET:
        vtable = class_vtables.get("CINSNextBot", {})
        if vtable_offset in vtable:
            return _clean_method(vtable[vtable_offset])
        vtable = class_vtables.get("CINSPlayer", {})
        if vtable_offset in vtable:
            return _clean_method(vtable[vtable_offset])
        return None

    # For lower offsets, try to disambiguate
    candidates = offset_to_methods.get(vtable_offset, [])
    if not candidates:
        return None

    # If all candidates agree on the method name
    method_names = set(_clean_method(m) for _, m in candidates)
    if len(method_names) == 1:
        return method_names.pop()

    # Prefer CINSNextBot for direct dispatches
    for cls, method in candidates:
        if cls == "CINSNextBot":
            return _clean_method(method)

    cls, method = candidates[0]
    return "%s::%s" % (cls, _clean_method(method))


def _clean_method(name):
    """Clean up a method name for annotation."""
    paren = name.find("(")
    if paren > 0:
        name = name[:paren]
    # "CINSNextBot::CINSNextBot::Method" -> "CINSNextBot::Method"
    parts = name.split("::")
    if len(parts) >= 3 and parts[0] == parts[1]:
        parts = parts[1:]
        name = "::".join(parts)
    return name


# Pattern A: (code **)(*(int *)EXPR + 0xOFFSET)  -- cast dereference
PATTERN_A = re.compile(
    r'\(code \*\*?\)'          # (code **) or (code *)
    r'\(\*\(int \*\)'          # (*(int *)
    r'(.+?)'                   # EXPR (non-greedy)
    r' \+ (0x[0-9a-fA-F]+)'   # + 0xOFFSET
    r'\)'                      # closing paren
)

# Pattern B: (code **)(*VAR + 0xOFFSET)  -- simple dereference (interface calls)
PATTERN_B = re.compile(
    r'\(code \*\*?\)'          # (code **) or (code *)
    r'\(\*(\w+)'               # (*VARNAME  -- word chars only
    r' \+ (0x[0-9a-fA-F]+)'   # + 0xOFFSET
    r'\)'                      # closing paren
)

# Pattern C: (code **)(**(int **)EXPR + 0xOFFSET)  -- double pointer deref
PATTERN_C = re.compile(
    r'\(code \*\*?\)'          # (code **) or (code *)
    r'\(\*\*\(int \*\*\)'     # (**(int **)
    r'(.+?)'                   # EXPR (non-greedy)
    r' \+ (0x[0-9a-fA-F]+)'   # + 0xOFFSET
    r'\)'                      # closing paren
)

# Regex to detect interface getter assignments:
#   piVarX = (int/type *)(**(code **)(*(int *)BOT + 0x974))(BOT);
# We look for assignments where the vtable offset is a known getter
INTERFACE_ASSIGN_RE = re.compile(
    r'(\w+)\s*='               # variable name =
    r'.*?'                     # cast/stuff
    r'\+ (0x(?:96c|970|974|97c))\b'  # known getter offset
)


# Regex to find function boundaries in decompiled output
FUNC_HEADER_RE = re.compile(r'/\* -{40}')


def build_interface_map_at(content, position):
    """Track which variables hold interface pointers at a given position.

    Scans backwards from position to the start of the current function,
    building a mapping of variable names to interface class names.
    Variables are scoped to the current function.
    """
    # Find the start of the current function (search backwards for header)
    func_start = content.rfind('/* ----', 0, position)
    if func_start == -1:
        func_start = 0

    # Only scan from function start to current position
    func_text = content[func_start:position]

    var_types = {}
    for m in INTERFACE_ASSIGN_RE.finditer(func_text):
        var_name = m.group(1)
        getter_offset = int(m.group(2), 16)
        cls = INTERFACE_GETTER_OFFSETS.get(getter_offset)
        if cls:
            var_types[var_name] = cls
    return var_types


def process_c_file(filepath, class_vtables, offset_to_methods, stats):
    """Process a single .c file, adding vtable annotations."""
    with open(filepath) as f:
        content = f.read()

    replacements = []  # (start, end, replacement_string)
    seen_positions = set()  # avoid double-annotating the same position

    # Process all three patterns
    for pattern, pattern_name in [
        (PATTERN_A, "A"),
        (PATTERN_B, "B"),
        (PATTERN_C, "C"),
    ]:
        for m in pattern.finditer(content):
            # Skip if this position was already handled
            if m.start() in seen_positions:
                continue

            context_expr = m.group(1)
            offset_hex = m.group(2)
            vtable_offset = int(offset_hex, 16)

            # Skip very low offsets (destructors at 0/4)
            if vtable_offset <= 4:
                continue

            # Skip if already annotated
            end_pos = m.end()
            after = content[end_pos:end_pos + 4]
            if after.startswith(" /*"):
                continue

            # Determine hint class from interface tracking (Pattern B only)
            hint_class = None
            if pattern_name == "B":
                interface_vars = build_interface_map_at(content, m.start())
                hint_class = interface_vars.get(context_expr)

            annotation = resolve_vtable_call(
                vtable_offset, context_expr, hint_class,
                class_vtables, offset_to_methods
            )
            if annotation is None:
                stats["unresolved"] += 1
                continue

            original = m.group(0)
            replacement = "%s /* %s */" % (original, annotation)
            replacements.append((m.start(), m.end(), replacement))
            seen_positions.add(m.start())
            stats["annotated"] += 1

    if not replacements:
        return content, False

    # Sort by position and apply in reverse order
    replacements.sort(key=lambda x: x[0], reverse=True)
    result = content
    for start, end, repl in replacements:
        result = result[:start] + repl + result[end:]

    return result, True


def main():
    if not os.path.isfile(VTABLE_MAP_PATH):
        print("ERROR: vtable_map.json not found: %s" % VTABLE_MAP_PATH)
        sys.exit(1)

    if not os.path.isdir(DECOMPILED_DIR):
        print("ERROR: decompiled dir not found: %s" % DECOMPILED_DIR)
        sys.exit(1)

    print("Loading vtable map...")
    class_vtables, offset_to_methods = load_vtable_map(VTABLE_MAP_PATH)
    for cls, vtable in class_vtables.items():
        print("  %s: %d entries (max offset 0x%x)" % (cls, len(vtable), max(vtable.keys())))

    c_files = sorted(
        f for f in os.listdir(DECOMPILED_DIR) if f.endswith(".c")
    )

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        result, modified = process_c_file(
            filepath, class_vtables, offset_to_methods, stats
        )
        if modified:
            with open(filepath, "w") as f:
                f.write(result)
            modified_count += 1
            print("  %s" % filename)

    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  Vtable calls annotated: %d" % stats["annotated"])
    print("  Unresolved: %d" % stats["unresolved"])


if __name__ == "__main__":
    main()
