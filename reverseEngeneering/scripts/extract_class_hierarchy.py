#!/usr/bin/env python3
"""
Extract C++ class hierarchy from RTTI typeinfo structures in server_srv.so.

Parses nm symbols and readelf relocations to classify each typeinfo as root,
single-inheritance, or virtual/multiple-inheritance, then reads parent pointers
from the binary to build a full inheritance tree.

Output:
  - reverseEngeneering/analysis/class_hierarchy.json (machine-readable)
  - Console: tree visualization with bot AI subtrees highlighted
"""

import json
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

OUTPUT_JSON = os.path.join(REPO_ROOT, "analysis", "class_hierarchy.json")

# Segment layout (from resolve_pic_refs.py)
SEG2_START_VADDR = 0x00B0FF20
SEG2_FILE_OFFSET_DELTA = 0x1000


def vaddr_to_file_offset(vaddr):
    """Convert real virtual address to file offset."""
    if vaddr < SEG2_START_VADDR:
        return vaddr
    return vaddr - SEG2_FILE_OFFSET_DELTA


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def read_uint32(data, vaddr):
    """Read uint32 from binary at a virtual address."""
    offset = vaddr_to_file_offset(vaddr)
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def parse_typeinfo_symbols(binary_path):
    """Parse nm -C output to find all 'typeinfo for X' symbols.

    Returns dict: {vaddr: class_name}
    """
    result = subprocess.run(
        ["nm", "-C", binary_path],
        capture_output=True, text=True,
    )
    typeinfo_map = {}  # vaddr -> class_name
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[2]
        if name.startswith("typeinfo for "):
            class_name = name[len("typeinfo for "):]
            typeinfo_map[addr] = class_name
    return typeinfo_map


def parse_relocations(binary_path):
    """Parse readelf -rW to classify typeinfo vaddrs by RTTI kind.

    Returns:
        root_addrs: set of vaddrs for __class_type_info (no parent)
        si_addrs: set of vaddrs for __si_class_type_info (single inheritance)
        vmi_addrs: set of vaddrs for __vmi_class_type_info (virtual/multiple)
    """
    result = subprocess.run(
        ["readelf", "-rW", binary_path],
        capture_output=True, text=True,
    )

    root_addrs = set()
    si_addrs = set()
    vmi_addrs = set()

    # Mangled RTTI vtable symbol names
    ROOT_SYM = "_ZTVN10__cxxabiv117__class_type_infoE"
    SI_SYM = "_ZTVN10__cxxabiv120__si_class_type_infoE"
    VMI_SYM = "_ZTVN10__cxxabiv121__vmi_class_type_infoE"

    # Relocation format (readelf -rW):
    # 00b11d30  00009501 R_386_32  00000000  _ZTVN10...@CXXABI_1.3
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            offset = int(parts[0], 16)
        except ValueError:
            continue

        # Symbol is last field, possibly with @VERSION suffix
        sym = parts[-1].split("@")[0]

        if sym == ROOT_SYM:
            root_addrs.add(offset)
        elif sym == SI_SYM:
            si_addrs.add(offset)
        elif sym == VMI_SYM:
            vmi_addrs.add(offset)

    return root_addrs, si_addrs, vmi_addrs


def demangle_name(mangled):
    """Demangle an Itanium-mangled type name using c++filt."""
    result = subprocess.run(
        ["c++filt", "-t", mangled],
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def extract_name_from_binary(data, name_vaddr):
    """Read null-terminated string at vaddr (mangled type name), demangle it."""
    offset = vaddr_to_file_offset(name_vaddr)
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b'\x00', offset, offset + 512)
    if end == -1 or end == offset:
        return None
    raw = data[offset:end]
    try:
        return raw.decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None


def build_hierarchy(data, typeinfo_map, root_addrs, si_addrs, vmi_addrs):
    """Read parent pointers from binary and build class hierarchy.

    Returns dict: {class_name: {"parents": [...], "children": [...]}}
    """
    hierarchy = {}
    addr_to_name = typeinfo_map  # vaddr -> class_name

    # Initialize all classes
    for addr, name in addr_to_name.items():
        if name not in hierarchy:
            hierarchy[name] = {"parents": [], "children": []}

    resolved = 0
    unresolved = 0

    for addr, name in sorted(addr_to_name.items()):
        if addr in root_addrs:
            # No parents
            pass
        elif addr in si_addrs:
            # Single inheritance: parent typeinfo* at +8
            parent_addr = read_uint32(data, addr + 8)
            if parent_addr and parent_addr in addr_to_name:
                parent_name = addr_to_name[parent_addr]
                hierarchy[name]["parents"].append(parent_name)
                if parent_name not in hierarchy:
                    hierarchy[parent_name] = {"parents": [], "children": []}
                hierarchy[parent_name]["children"].append(name)
                resolved += 1
            elif parent_addr:
                unresolved += 1
        elif addr in vmi_addrs:
            # Virtual/multiple inheritance
            base_count = read_uint32(data, addr + 12)
            if base_count is None or base_count > 20:
                continue
            for i in range(base_count):
                base_ti_addr = read_uint32(data, addr + 16 + 8 * i)
                if base_ti_addr and base_ti_addr in addr_to_name:
                    parent_name = addr_to_name[base_ti_addr]
                    hierarchy[name]["parents"].append(parent_name)
                    if parent_name not in hierarchy:
                        hierarchy[parent_name] = {"parents": [], "children": []}
                    hierarchy[parent_name]["children"].append(name)
                    resolved += 1
                elif base_ti_addr:
                    unresolved += 1

    # Sort children for stable output
    for info in hierarchy.values():
        info["children"].sort()
        info["parents"].sort()

    return hierarchy, resolved, unresolved


def print_tree(hierarchy, root, prefix="", is_last=True, highlight_set=None, depth=0, max_depth=50):
    """Recursively print tree from a root class."""
    if depth > max_depth:
        return

    connector = "\u2514\u2500 " if is_last else "\u251c\u2500 "
    marker = " *" if highlight_set and root in highlight_set else ""

    if depth == 0:
        print(root + marker)
    else:
        print(prefix + connector + root + marker)

    children = hierarchy.get(root, {}).get("children", [])
    new_prefix = prefix + ("   " if is_last else "\u2502  ")

    for i, child in enumerate(children):
        is_last_child = (i == len(children) - 1)
        print_tree(hierarchy, child, new_prefix, is_last_child,
                   highlight_set, depth + 1, max_depth)


def find_bot_classes(hierarchy):
    """Find bot-relevant classes for highlighting."""
    bot_classes = set()
    patterns = [
        re.compile(r'Bot', re.IGNORECASE),
        re.compile(r'CINS'),
        re.compile(r'NextBot'),
        re.compile(r'IBody'),
        re.compile(r'IVision'),
        re.compile(r'IIntention'),
        re.compile(r'ILocomotion'),
        re.compile(r'Action<'),
        re.compile(r'Behavior<'),
    ]
    for name in hierarchy:
        for pat in patterns:
            if pat.search(name):
                bot_classes.add(name)
                break
    return bot_classes


def collect_subtree(hierarchy, root, result=None):
    """Collect all classes in a subtree rooted at 'root'."""
    if result is None:
        result = set()
    result.add(root)
    for child in hierarchy.get(root, {}).get("children", []):
        collect_subtree(hierarchy, child, result)
    return result


def main():
    if not os.path.isfile(BINARY):
        print("ERROR: Binary not found: %s" % BINARY)
        sys.exit(1)

    print("Loading binary...")
    data = load_binary(BINARY)

    print("Parsing typeinfo symbols (nm)...")
    typeinfo_map = parse_typeinfo_symbols(BINARY)
    print("  %d typeinfo symbols found" % len(typeinfo_map))

    print("Parsing relocations (readelf)...")
    root_addrs, si_addrs, vmi_addrs = parse_relocations(BINARY)
    print("  Root (no parent): %d" % len(root_addrs))
    print("  Single inheritance: %d" % len(si_addrs))
    print("  Virtual/multiple: %d" % len(vmi_addrs))

    # Cross-reference: how many typeinfo symbols have a classification?
    classified = 0
    unclassified = []
    for addr in typeinfo_map:
        if addr in root_addrs or addr in si_addrs or addr in vmi_addrs:
            classified += 1
        else:
            unclassified.append(addr)
    print("  Classified: %d / %d typeinfos" % (classified, len(typeinfo_map)))
    if unclassified:
        print("  WARNING: %d typeinfos not classified (no relocation at +0)" % len(unclassified))

    print("Building hierarchy...")
    hierarchy, resolved, unresolved = build_hierarchy(
        data, typeinfo_map, root_addrs, si_addrs, vmi_addrs
    )
    print("  %d classes in hierarchy" % len(hierarchy))
    print("  %d parent links resolved" % resolved)
    if unresolved:
        print("  %d parent links unresolved (typeinfo addr not in symbol table)" % unresolved)

    # Write JSON
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(hierarchy, f, indent=2, sort_keys=True)
    print("\nJSON written to: %s" % OUTPUT_JSON)

    # Find roots (classes with no parents)
    roots = sorted(name for name, info in hierarchy.items() if not info["parents"])
    print("\n%d root classes (no parent)" % len(roots))

    # Find bot-relevant classes
    bot_classes = find_bot_classes(hierarchy)
    print("%d bot-relevant classes" % len(bot_classes))

    # Collect bot-relevant subtrees
    bot_subtree_roots = set()
    for name in bot_classes:
        # If this class is a root or close to root, show the tree from here
        if not hierarchy[name]["parents"]:
            bot_subtree_roots.add(name)
        else:
            # Walk up to find the topmost ancestor that's still bot-related
            current = name
            while True:
                parents = hierarchy.get(current, {}).get("parents", [])
                bot_parents = [p for p in parents if p in bot_classes]
                if not bot_parents:
                    bot_subtree_roots.add(current)
                    break
                current = bot_parents[0]

    # Print bot AI subtrees
    print("\n" + "=" * 70)
    print("BOT AI CLASS HIERARCHY")
    print("=" * 70)

    for root in sorted(bot_subtree_roots):
        subtree = collect_subtree(hierarchy, root)
        if len(subtree) >= 2 or root in bot_classes:
            print()
            print_tree(hierarchy, root, highlight_set=bot_classes)

    # Print summary statistics
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Count by inheritance type
    multi_parent = sum(1 for info in hierarchy.values() if len(info["parents"]) > 1)
    single_parent = sum(1 for info in hierarchy.values() if len(info["parents"]) == 1)
    no_parent = sum(1 for info in hierarchy.values() if len(info["parents"]) == 0)

    print("Total classes: %d" % len(hierarchy))
    print("  No parent (root): %d" % no_parent)
    print("  Single parent: %d" % single_parent)
    print("  Multiple parents: %d" % multi_parent)

    # Top-level classes with most descendants
    print("\nLargest class trees (top 15):")
    tree_sizes = []
    for root in roots:
        subtree = collect_subtree(hierarchy, root)
        tree_sizes.append((len(subtree), root))
    tree_sizes.sort(reverse=True)
    for size, name in tree_sizes[:15]:
        print("  %4d  %s" % (size, name))


if __name__ == "__main__":
    main()
