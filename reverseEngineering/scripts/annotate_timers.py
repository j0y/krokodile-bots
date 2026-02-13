#!/usr/bin/env python3
"""
Annotate CountdownTimer patterns in decompiled bot AI code.

Identifies timer constructors, IsElapsed checks, Start operations,
Invalidate operations, and NetworkStateChanged dispatches. Adds inline
comments so the decompiled code reads semantically.

CountdownTimer layout (12 bytes):
  +0x00: vtable ptr       (→ vtable for CountdownTimer + 0x8)
  +0x04: float m_duration (duration arg; -1.0f = not started)
  +0x08: float m_timestamp (Now() + duration; -1.0f = invalidated)

Timer semantics:
  Start(d):      m_duration = d; m_timestamp = Now() + d
  IsElapsed():   Now() > m_timestamp (and m_timestamp != -1.0f)
  Invalidate():  m_timestamp = -1.0f; m_duration = -1.0f
  HasStarted():  m_timestamp >= 0
"""

import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DECOMPILED_DIR = os.path.join(REPO_ROOT, "decompiled")


@dataclass
class TimerInfo:
    vtable_off: int       # byte offset of vtable ptr
    duration_off: int     # byte offset of m_duration
    timestamp_off: int    # byte offset of m_timestamp
    name: str             # timer_0, timer_1, ...


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Function block header: "* ClassName::MethodName"
FUNC_HEADER_RE = re.compile(
    r'^\s*\*\s+(\w+)::(\w+)', re.MULTILINE
)

# vtable for CountdownTimer+0x8 anywhere on a line
VTABLE_CT_RE = re.compile(r'vtable for CountdownTimer\+0x8')

# Direct array-index vtable assignment:
#   var[0xHEX] = ... /* vtable for CountdownTimer+0x8 */
VTABLE_ARRAY_ASSIGN_RE = re.compile(
    r'(\w+)\[(0x[0-9a-fA-F]+|\d+)\]\s*=\s*.*vtable for CountdownTimer\+0x8'
)

# Byte-offset deref vtable assignment:
#   *(int *)(var + 0xHEX) = ... /* vtable for CountdownTimer+0x8 */
VTABLE_DEREF_ASSIGN_RE = re.compile(
    r'\*\(int \*\)\((\w+) \+ (0x[0-9a-fA-F]+)\)\s*=\s*.*'
    r'vtable for CountdownTimer\+0x8'
)

# Indirect vtable load into variable:
#   iVar = unaff_EBX + ... /* vtable for CountdownTimer+0x8 */
VTABLE_VAR_LOAD_RE = re.compile(
    r'(\w+)\s*=\s*.*vtable for CountdownTimer\+0x8'
)

# Assignment of variable to array slot: var[IDX] = otherVar;
ARRAY_ASSIGN_VAR_RE = re.compile(
    r'(\w+)\[(0x[0-9a-fA-F]+|\d+)\]\s*=\s*(\w+)\s*;'
)

# CountdownTimer::Now() call
NOW_CALL_RE = re.compile(r'CountdownTimer::Now\(\)')

# Now() result capture: fVar = (float10)CountdownTimer::Now()
NOW_RESULT_RE = re.compile(
    r'(\w+)\s*=\s*\(float10\)CountdownTimer::Now\(\)'
)

# ---------------------------------------------------------------------------
# IsElapsed patterns
# ---------------------------------------------------------------------------

# Positive: *(float *)(... + OFF) <= (float)fVar
ISELAPSED_POS_RE = re.compile(
    r'\*\(float \*\)\((?:\(int\))?(\w+) \+ (0x[0-9a-fA-F]+)\)\s*<=\s*\(float\)(\w+)'
)

# Negative: (float)fVar < *(float *)(... + OFF)
ISELAPSED_NEG_RE = re.compile(
    r'\(float\)(\w+)\s*<\s*\*\(float \*\)\((?:\(int\))?(\w+) \+ (0x[0-9a-fA-F]+)\)'
)

# Array-index positive: *(float *)(var[IDX]) <= ... -- not typically seen
# Array-index IsElapsed negative: (float)fVar < *(float *)(var + OFF)
# where var is int (not pointer), so + OFF is byte offset

# ---------------------------------------------------------------------------
# Start pattern: store Now() + duration to m_timestamp
# ---------------------------------------------------------------------------

# Now() + inline float: (float)fVar + *(float *)(.../* Xf */)
NOW_PLUS_INLINE_FLOAT_RE = re.compile(
    r'\(float\)(\w+) \+ \*\(float \*\)\([^)]+/\*\s*([\d.]+f)\s*\*/'
)

# Store to byte-offset: *(float *)(...VAR + OFF) = expr;
STORE_BYTE_OFF_RE = re.compile(
    r'\*\(float \*\)\((?:\(int\))?(\w+) \+ (0x[0-9a-fA-F]+)\)\s*=\s*(.+);'
)

# Store to array-index: var[IDX] = expr;
STORE_ARRAY_RE = re.compile(
    r'(\w+)\[(0x[0-9a-fA-F]+|\d+)\]\s*=\s*(.+);'
)

# ---------------------------------------------------------------------------
# Invalidate: -1.0f stored to m_timestamp
# ---------------------------------------------------------------------------

NEG1_PATTERN = re.compile(r'(?:0xbf800000|-0x40800000)\s*/\*\s*-1\.0f')

# ---------------------------------------------------------------------------
# NetworkStateChanged vtable dispatch
# ---------------------------------------------------------------------------

# Byte-offset form: (**(code **)(*(int *)(...VAR + OFF) + 4))(...)
VTABLE_DISPATCH_BYTE_RE = re.compile(
    r'\(\*\*\(code \*\*\)\(\*\(int \*\)\((?:\(int\))?(\w+) \+ (0x[0-9a-fA-F]+)\) \+ 4\)\)'
)

# Array-index form: (**(code **)(var[IDX] + 4))(...)
VTABLE_DISPATCH_ARRAY_RE = re.compile(
    r'\(\*\*\(code \*\*\)\((\w+)\[(0x[0-9a-fA-F]+|\d+)\] \+ 4\)\)'
)

# Already-annotated check
TIMER_ANNOTATION_RE = re.compile(r'/\* timer_\d+\.')


def parse_int(s):
    """Parse a hex or decimal integer string."""
    s = s.strip()
    if s.startswith(('-0x', '-0X')):
        return -int(s[1:], 16)
    if s.startswith(('0x', '0X')):
        return int(s, 16)
    return int(s)


def build_offset_lookup(timers):
    """Build byte_offset -> (timer_name, field_name) lookup dict."""
    lookup = {}
    for t in timers:
        lookup[t.vtable_off] = (t.name, "vtable")
        lookup[t.duration_off] = (t.name, "m_duration")
        lookup[t.timestamp_off] = (t.name, "m_timestamp")
    return lookup


# ---------------------------------------------------------------------------
# Pass 1: Extract timer maps from constructors
# ---------------------------------------------------------------------------

def extract_timers_from_constructor(func_lines):
    """Extract timer vtable byte offsets from constructor function lines.

    Handles three forms:
    1. Direct array: var[IDX] = ... vtable for CountdownTimer+0x8
    2. Byte-offset deref: *(int *)(var + OFF) = ... vtable for CountdownTimer
    3. Indirect: iVar = ... vtable ...; then var[IDX] = iVar;

    For form 3, tracks variable reassignment: if a vtable var is later
    assigned a different value, it's removed from the vtable set.
    """
    vtable_offsets = set()
    vtable_vars = set()  # variable names currently holding the vtable value

    # Single sequential pass — handles variable reassignment correctly
    # Pattern to detect variable reassignment: varName = <something>;
    VAR_ASSIGN_RE = re.compile(r'^\s*(\w+)\s*=\s*')

    for line in func_lines:
        # Form 1: direct array-index assignment
        m = VTABLE_ARRAY_ASSIGN_RE.search(line)
        if m:
            idx = parse_int(m.group(2))
            vtable_offsets.add(idx * 4)
            continue

        # Form 2: byte-offset deref assignment
        m = VTABLE_DEREF_ASSIGN_RE.search(line)
        if m:
            vtable_offsets.add(parse_int(m.group(2)))
            continue

        # Form 3 (part a): variable load of vtable value
        if VTABLE_CT_RE.search(line):
            m = VTABLE_VAR_LOAD_RE.search(line)
            if m:
                vtable_vars.add(m.group(1))
                continue

        # Form 3 (part b): indirect assignment of vtable var to array slot
        if vtable_vars:
            m = ARRAY_ASSIGN_VAR_RE.search(line)
            if m and m.group(3) in vtable_vars:
                idx = parse_int(m.group(2))
                vtable_offsets.add(idx * 4)
                continue

        # Track variable reassignment: if a vtable var is assigned a
        # different value, remove it from vtable_vars
        if vtable_vars:
            m = VAR_ASSIGN_RE.match(line)
            if m and m.group(1) in vtable_vars:
                vtable_vars.discard(m.group(1))

    return sorted(vtable_offsets)


def build_class_timer_maps():
    """Scan all .c files for constructors and extract timer layouts.

    Returns dict: class_name -> list of TimerInfo
    """
    class_timers = {}

    c_files = sorted(f for f in os.listdir(DECOMPILED_DIR) if f.endswith('.c'))

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        with open(filepath) as f:
            content = f.read()

        lines = content.split('\n')
        functions = parse_functions(lines)

        # Merge timer offsets from all constructors of the same class
        all_offsets = set()
        for class_name, method_name, start, end in functions:
            if class_name == method_name:  # constructor
                func_lines = lines[start:end + 1]
                vtable_offsets = extract_timers_from_constructor(func_lines)
                all_offsets.update(vtable_offsets)

        if all_offsets and functions:
            class_name = functions[0][0]
            timers = []
            for i, vt_off in enumerate(sorted(all_offsets)):
                timers.append(TimerInfo(
                    vtable_off=vt_off,
                    duration_off=vt_off + 4,
                    timestamp_off=vt_off + 8,
                    name="timer_%d" % i,
                ))
            class_timers[class_name] = timers

    return class_timers


# ---------------------------------------------------------------------------
# Function parsing
# ---------------------------------------------------------------------------

def parse_functions(lines):
    """Parse lines into function blocks.

    Returns list of (class_name, method_name, start_line_idx, end_line_idx).
    """
    # Find all function header blocks: /* --- \n * Class::Method \n ...
    functions = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Look for function block start: /* --------
        if line.strip().startswith('/* ---') and '---' * 5 in line:
            # Scan next few lines for "* ClassName::MethodName"
            for j in range(i + 1, min(i + 5, len(lines))):
                m = FUNC_HEADER_RE.search(lines[j])
                if m:
                    class_name = m.group(1)
                    method_name = m.group(2)
                    func_start = i

                    # Find end: next function block or end of file
                    func_end = len(lines) - 1
                    for k in range(j + 5, len(lines)):
                        if (lines[k].strip().startswith('/* ---') and
                                '---' * 5 in lines[k]):
                            func_end = k - 1
                            break

                    functions.append((class_name, method_name,
                                      func_start, func_end))
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1

    return functions


# ---------------------------------------------------------------------------
# Pass 2: Annotate timer operations
# ---------------------------------------------------------------------------

def find_duration_near(lines, now_line, store_line):
    """Look for Now() + duration pattern between now_line and store_line.

    Returns duration string (e.g. '0.5f') or None.
    """
    for j in range(now_line, min(store_line + 1, len(lines))):
        line = lines[j]
        # Pattern: (float)fVar + *(float *)(.../* Xf */)
        m = NOW_PLUS_INLINE_FLOAT_RE.search(line)
        if m:
            return m.group(2)
        # Pattern: (float)fVar + 0xHEX /* Xf */
        m2 = re.search(
            r'\(float\)\w+ \+ 0x[0-9a-fA-F]+\s*/\*\s*([\d.]+f)\s*\*/', line)
        if m2:
            return m2.group(1)
    return None


def try_byte_offset_from_line(line):
    """Extract all byte-offset references from a line.

    Returns list of (offset_value, is_from_array_index) tuples.
    """
    results = []

    # Byte-offset form: (int)VAR + 0xHEX  or  VAR + 0xHEX (in pointer deref)
    for m in re.finditer(
            r'\((?:\(int\))?(\w+) \+ (0x[0-9a-fA-F]+)\)', line):
        results.append((parse_int(m.group(2)), False))

    # Array-index form: var[0xHEX]
    for m in re.finditer(r'(\w+)\[(0x[0-9a-fA-F]+|\d+)\]', line):
        idx = parse_int(m.group(2))
        results.append((idx * 4, True))

    return results


def annotate_function_lines(lines, timers, is_constructor):
    """Annotate timer operations in a function's lines.

    Returns list of (line_offset, annotation_string) pairs.
    """
    if not timers:
        return []

    lookup = build_offset_lookup(timers)
    # Collect all known m_timestamp offsets for quick checks
    ts_offsets = {t.timestamp_off for t in timers}
    dur_offsets = {t.duration_off for t in timers}
    vt_offsets = {t.vtable_off for t in timers}

    annotations = []  # (line_offset, annotation)
    annotated_lines = set()  # line offsets already annotated

    # State tracking
    last_now_line = -100
    last_now_var = None

    # For constructor: track vtable vars for indirect assignment labeling
    ctor_vtable_vars = set()
    VAR_ASSIGN_RE = re.compile(r'^\s*(\w+)\s*=\s*')

    for i, line in enumerate(lines):
        # Skip already-annotated lines
        if TIMER_ANNOTATION_RE.search(line):
            continue

        # --- Track Now() calls ---
        if NOW_CALL_RE.search(line):
            last_now_line = i
            m = NOW_RESULT_RE.search(line)
            if m:
                last_now_var = m.group(1)

        # --- IsElapsed positive ---
        # *(float *)(...VAR + OFF) <= (float)fVar
        m = ISELAPSED_POS_RE.search(line)
        if m and i - last_now_line <= 3 and i not in annotated_lines:
            off = parse_int(m.group(2))
            if off in lookup:
                tname, fname = lookup[off]
                if fname == "m_timestamp":
                    annotations.append((i, "/* %s.IsElapsed() */" % tname))
                    annotated_lines.add(i)
                    continue

        # --- IsElapsed negative ---
        # (float)fVar < *(float *)(...VAR + OFF)
        m = ISELAPSED_NEG_RE.search(line)
        if m and i - last_now_line <= 3 and i not in annotated_lines:
            off = parse_int(m.group(3))
            if off in lookup:
                tname, fname = lookup[off]
                if fname == "m_timestamp":
                    annotations.append(
                        (i, "/* !%s.IsElapsed() */" % tname))
                    annotated_lines.add(i)
                    continue

        # --- Store to m_timestamp (potential Start or Invalidate) ---

        # Check for -1.0f store → Invalidate
        if NEG1_PATTERN.search(line) and i not in annotated_lines:
            # Byte-offset form
            m = STORE_BYTE_OFF_RE.search(line)
            if m:
                off = parse_int(m.group(2))
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_timestamp":
                        if is_constructor and i - last_now_line > 10:
                            annotations.append(
                                (i, "/* %s.m_timestamp = -1 (not running) */"
                                 % tname))
                        else:
                            annotations.append(
                                (i, "/* %s.Invalidate() */" % tname))
                        annotated_lines.add(i)
                        continue

            # Array-index form
            m = STORE_ARRAY_RE.search(line)
            if m and NEG1_PATTERN.search(line):
                idx = parse_int(m.group(2))
                off = idx * 4
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_timestamp":
                        if is_constructor and i - last_now_line > 10:
                            annotations.append(
                                (i, "/* %s.m_timestamp = -1 (not running) */"
                                 % tname))
                        else:
                            annotations.append(
                                (i, "/* %s.Invalidate() */" % tname))
                        annotated_lines.add(i)
                        continue

        # --- Store to m_timestamp near Now() → Start ---
        if i - last_now_line <= 8 and i not in annotated_lines:
            # Byte-offset store
            m = STORE_BYTE_OFF_RE.search(line)
            if m:
                off = parse_int(m.group(2))
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_timestamp":
                        dur = find_duration_near(lines, last_now_line, i)
                        if dur:
                            annotations.append(
                                (i, "/* %s.Start(%s) */" % (tname, dur)))
                        else:
                            annotations.append(
                                (i, "/* %s.Start(...) */" % tname))
                        annotated_lines.add(i)
                        continue

            # Array-index store near Now()
            m = STORE_ARRAY_RE.search(line)
            if m:
                idx = parse_int(m.group(2))
                off = idx * 4
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_timestamp":
                        dur = find_duration_near(lines, last_now_line, i)
                        if dur:
                            annotations.append(
                                (i, "/* %s.Start(%s) */" % (tname, dur)))
                        else:
                            annotations.append(
                                (i, "/* %s.Start(...) */" % tname))
                        annotated_lines.add(i)
                        continue

        # --- Store to m_duration near Now() → part of Start ---
        if i - last_now_line <= 10 and i not in annotated_lines:
            m = STORE_BYTE_OFF_RE.search(line)
            if m:
                off = parse_int(m.group(2))
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_duration":
                        annotations.append(
                            (i, "/* %s.m_duration */" % tname))
                        annotated_lines.add(i)
                        continue

            m = STORE_ARRAY_RE.search(line)
            if m and 'vtable for CountdownTimer' not in line:
                idx = parse_int(m.group(2))
                off = idx * 4
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "m_duration":
                        # Only annotate if the value looks like a duration
                        # (not just = 0 in a constructor init block)
                        expr = m.group(3).strip()
                        if not is_constructor or expr != '0':
                            annotations.append(
                                (i, "/* %s.m_duration */" % tname))
                            annotated_lines.add(i)
                            continue

        # --- NetworkStateChanged vtable dispatch ---
        if i not in annotated_lines:
            # Byte-offset form
            m = VTABLE_DISPATCH_BYTE_RE.search(line)
            if m:
                off = parse_int(m.group(2))
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "vtable":
                        annotations.append(
                            (i, "/* %s.NetworkStateChanged() */"
                             % tname))
                        annotated_lines.add(i)
                        continue

            # Array-index form
            m = VTABLE_DISPATCH_ARRAY_RE.search(line)
            if m:
                idx = parse_int(m.group(2))
                off = idx * 4
                if off in lookup:
                    tname, fname = lookup[off]
                    if fname == "vtable":
                        annotations.append(
                            (i, "/* %s.NetworkStateChanged() */"
                             % tname))
                        annotated_lines.add(i)
                        continue

        # --- Constructor: annotate vtable assignment lines ---
        if is_constructor and i not in annotated_lines:
            # Track vtable vars (same logic as extract_timers_from_constructor)
            if VTABLE_CT_RE.search(line):
                m = VTABLE_VAR_LOAD_RE.search(line)
                if m:
                    ctor_vtable_vars.add(m.group(1))

                # Direct array form with vtable text
                m = VTABLE_ARRAY_ASSIGN_RE.search(line)
                if m:
                    idx = parse_int(m.group(2))
                    off = idx * 4
                    if off in lookup:
                        tname, _ = lookup[off]
                        annotations.append(
                            (i, "/* CountdownTimer %s */" % tname))
                        annotated_lines.add(i)
                        continue

                # Byte-offset deref form with vtable text
                m = VTABLE_DEREF_ASSIGN_RE.search(line)
                if m:
                    off = parse_int(m.group(2))
                    if off in lookup:
                        tname, _ = lookup[off]
                        annotations.append(
                            (i, "/* CountdownTimer %s */" % tname))
                        annotated_lines.add(i)
                        continue

            # Indirect: var[IDX] = vtable_var (no vtable text on line)
            elif ctor_vtable_vars:
                m = ARRAY_ASSIGN_VAR_RE.search(line)
                if m and m.group(3) in ctor_vtable_vars:
                    idx = parse_int(m.group(2))
                    off = idx * 4
                    if off in lookup:
                        tname, _ = lookup[off]
                        annotations.append(
                            (i, "/* CountdownTimer %s */" % tname))
                        annotated_lines.add(i)
                        continue

                # Track reassignment of vtable vars
                m = VAR_ASSIGN_RE.match(line)
                if m and m.group(1) in ctor_vtable_vars:
                    ctor_vtable_vars.discard(m.group(1))

    return annotations


def annotate_file(filepath, class_timers, stats):
    """Process a single .c file and add timer annotations.

    Returns (new_content, was_modified).
    """
    with open(filepath) as f:
        content = f.read()

    lines = content.split('\n')
    functions = parse_functions(lines)

    all_annotations = []  # (global_line_idx, annotation)

    for class_name, method_name, start, end in functions:
        # Try the function's own class first
        timers = class_timers.get(class_name)
        if not timers:
            continue

        is_ctor = (class_name == method_name)
        func_lines = lines[start:end + 1]
        func_anns = annotate_function_lines(func_lines, timers, is_ctor)

        for line_off, ann in func_anns:
            all_annotations.append((start + line_off, ann))

    if not all_annotations:
        return content, False

    # Apply annotations (append to end of line)
    changed = False
    for line_idx, ann in all_annotations:
        line = lines[line_idx]
        # Don't add duplicate annotations
        if ann in line:
            continue
        lines[line_idx] = line.rstrip() + ' ' + ann
        stats["annotations"] += 1
        changed = True

    if not changed:
        return content, False

    return '\n'.join(lines), True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not os.path.isdir(DECOMPILED_DIR):
        print("ERROR: Decompiled directory not found: %s" % DECOMPILED_DIR)
        sys.exit(1)

    print("Pass 1: Building timer maps from constructors...")
    class_timers = build_class_timer_maps()
    print("  Found timers in %d classes:" % len(class_timers))
    for cls in sorted(class_timers):
        timers = class_timers[cls]
        offsets = ", ".join(
            "%s@0x%x" % (t.name, t.vtable_off) for t in timers)
        print("    %s: %s" % (cls, offsets))

    print("\nPass 2: Annotating timer operations...")
    c_files = sorted(f for f in os.listdir(DECOMPILED_DIR) if f.endswith('.c'))

    stats = defaultdict(int)
    modified_count = 0

    for filename in c_files:
        filepath = os.path.join(DECOMPILED_DIR, filename)
        result, modified = annotate_file(filepath, class_timers, stats)
        if modified:
            with open(filepath, 'w') as f:
                f.write(result)
            modified_count += 1
            print("  %s" % filename)

    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  Annotations added: %d" % stats["annotations"])


if __name__ == "__main__":
    main()
