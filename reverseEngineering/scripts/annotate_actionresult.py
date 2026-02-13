#!/usr/bin/env python3
"""
Post-process Ghidra decompiled .c files to annotate ActionResult type codes.

Source Engine bot actions return ActionResult structs with a type code at offset 0:
  *(undefined4 *)param_1 = 0;  ->  Continue
  *(undefined4 *)param_1 = 1;  ->  ChangeTo
  *(undefined4 *)param_1 = 2;  ->  SuspendFor
  *(undefined4 *)param_1 = 3;  ->  Done
"""

import os
import re
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DECOMPILED_DIR = os.path.join(REPO_ROOT, "decompiled")

RESULT_TYPES = {
    "0": "Continue",
    "1": "ChangeTo",
    "2": "SuspendFor",
    "3": "Done",
}

# Match: *(undefined4 *)param_1 = N;  (with optional existing annotation)
ACTION_RESULT_RE = re.compile(
    r'(\*\(undefined4 \*\)param_1 = )([0-3])'
    r'(\s*/\*[^*]*\*/)?'   # group 3: optional existing comment
    r'(;)'
)


def process_file(filepath, stats):
    """Process a single .c file, annotating ActionResult type codes."""
    with open(filepath) as f:
        content = f.read()

    def replacer(m):
        prefix = m.group(1)
        code = m.group(2)
        existing = m.group(3)
        semi = m.group(4)

        label = RESULT_TYPES.get(code)
        if not label:
            return m.group(0)

        new_comment = " /* %s */" % label

        if existing:
            # Check if already correctly annotated
            if label in existing:
                stats["already"] += 1
                return m.group(0)
            stats["replaced"] += 1
        else:
            stats["new"] += 1

        return "%s%s%s%s" % (prefix, code, new_comment, semi)

    result, count = ACTION_RESULT_RE.subn(replacer, content)
    if count == 0:
        return content, False

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

    total = stats["new"] + stats["replaced"]
    print("\nDone!")
    print("  Files modified: %d / %d" % (modified_count, len(c_files)))
    print("  ActionResult annotations: %d" % total)
    print("    New: %d" % stats["new"])
    print("    Replaced: %d" % stats["replaced"])
    print("    Already correct: %d" % stats["already"])


if __name__ == "__main__":
    main()
