#!/usr/bin/env python3
"""
Extract bot action state transition graph from server_srv.so.

Two detection methods:
1. Direct calls: `call rel32` to action constructor functions
2. Inlined constructors: vtable pointer loaded from GOT and installed into object
   (compiler inlines small constructors, so no call instruction exists)
"""

import struct
import sys
import subprocess
from collections import defaultdict
from bisect import bisect_right

BINARY = "/home/yar/Work/reverseengeneer/ins_server_files/ins/insurgency/bin/server_srv.so"

TEXT_VADDR = 0x0011ac80
TEXT_SIZE  = 0x0078d5c8
TEXT_END   = TEXT_VADDR + TEXT_SIZE

GOT_PLT_ADDR = 0x00B97178

# Second LOAD segment: vaddr = file_offset + 0x1000
SEG2_VADDR_OFFSET = 0x1000  # vaddr - file_offset for second segment

# GOT section
GOT_VADDR = 0x00B96484
GOT_SIZE  = 0x00000CF4
GOT_END   = GOT_VADDR + GOT_SIZE


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def parse_all_symbols(binary_path):
    """Get ALL symbols sorted by address."""
    result = subprocess.run(
        ["nm", "-C", "-n", binary_path],
        capture_output=True, text=True
    )
    symbols = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                sym_type = parts[1]
                name = parts[2]
                # Skip GCC local labels (.L123) — they are NOT function boundaries
                if name.startswith(".L") and name[2:].isdigit():
                    continue
                symbols.append((addr, sym_type, name))
            except ValueError:
                continue
    symbols.sort()
    return symbols


def build_addr_to_symbol(symbols):
    """Exact address → symbol lookup."""
    lookup = {}
    for addr, _, name in symbols:
        lookup[addr] = name
    return lookup


def build_addr_to_containing_symbol(symbols):
    """Code address → containing function."""
    func_syms = [(a, n) for a, t, n in symbols if t in ('t', 'T', 'W', 'w')]
    addrs = [a for a, _ in func_syms]
    names = [n for _, n in func_syms]

    def lookup(code_addr):
        idx = bisect_right(addrs, code_addr) - 1
        if idx >= 0 and code_addr - addrs[idx] < 0x10000:
            return names[idx]
        return None
    return lookup


def is_action_class(name):
    if "::" not in name:
        return False
    cls = name.split("::")[0]
    return (cls.startswith("CINSBot") or cls == "CINSNextBot" or
            cls.startswith("CINSNextBotManager"))


def is_constructor(name):
    if "::" not in name:
        return False
    parts = name.split("::")
    cls = parts[0].split("<")[0]
    method = parts[-1].split("(")[0].split("<")[0]
    return method == cls


def is_action_constructor(name):
    if not is_constructor(name):
        return False
    cls = name.split("::")[0]
    return cls.startswith("CINSBot")


def get_class_name(symbol):
    if "::" not in symbol:
        return symbol
    cls = symbol.split("::")[0]
    if "<" in cls:
        cls = cls[:cls.index("<")]
    return cls


def get_method_name(symbol):
    if "::" not in symbol:
        return symbol
    method = symbol.split("::")[-1]
    paren = method.find("(")
    if paren > 0:
        method = method[:paren]
    return method


def find_got_base_in_function(data, func_start, func_end):
    """Find GOT base register: call get_pc_thunk + add."""
    for i in range(func_start, min(func_end - 10, len(data) - 10)):
        if data[i] == 0xE8:
            next_ip = i + 5
            if next_ip < func_end - 5 and data[next_ip] == 0x81:
                modrm = data[next_ip + 1]
                if 0xC0 <= modrm <= 0xC7:
                    reg = modrm - 0xC0
                    imm32 = struct.unpack_from("<i", data, next_ip + 2)[0]
                    got_base = (next_ip + imm32) & 0xFFFFFFFF
                    if abs(got_base - GOT_PLT_ADDR) < 0x100:
                        return (reg, got_base)
    return None


def find_calls_in_function(data, func_start, func_end):
    """Find all call rel32 (E8) instructions."""
    calls = []
    for i in range(func_start, min(func_end - 4, len(data) - 4)):
        if data[i] == 0xE8:
            rel32 = struct.unpack_from("<i", data, i + 1)[0]
            target = (i + 5 + rel32) & 0xFFFFFFFF
            if TEXT_VADDR <= target < TEXT_END:
                calls.append((i, target))
    return calls


def find_vtable_installs(data, func_start, func_end, got_reg, got_base, vtable_got_map):
    """Find mov instructions that load vtable pointers from GOT.

    Pattern: mov GOT_disp(%got_reg), %dest  →  opcode 8B, ModRM with mod=10, r/m=got_reg
    If the GOT entry contains a vtable address for an action class, that's an inlined constructor.
    """
    installs = []

    for i in range(func_start, min(func_end - 6, len(data) - 6)):
        if data[i] == 0x8B:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if mod == 2 and rm == got_reg and rm != 4:
                disp32 = struct.unpack_from("<i", data, i + 2)[0]
                got_entry_vaddr = (got_base + disp32) & 0xFFFFFFFF
                if got_entry_vaddr in vtable_got_map:
                    installs.append((i, vtable_got_map[got_entry_vaddr]))
    return installs


def find_push_imm_before(data, call_site):
    """Find push imm before operator new call to get object size."""
    for offset in range(1, 30):
        pos = call_site - offset
        if pos < 0:
            break
        if data[pos] == 0x6A and offset >= 2:
            return data[pos + 1]
        if data[pos] == 0x68 and pos + 5 <= call_site:
            return struct.unpack_from("<I", data, pos + 1)[0]
        # movl $imm32, (%esp) — C7 04 24 <imm32>
        if (pos + 7 <= call_site and data[pos] == 0xC7 and
                data[pos + 1] == 0x04 and data[pos + 2] == 0x24):
            val = struct.unpack_from("<I", data, pos + 3)[0]
            if 0 < val < 0x1000:
                return val
    return None


def main():
    print("Loading binary...", file=sys.stderr)
    data = load_binary(BINARY)

    print("Loading symbols...", file=sys.stderr)
    symbols = parse_all_symbols(BINARY)
    func_symbols = [(a, n) for a, t, n in symbols if t in ('t', 'T', 'W', 'w')]
    addr_to_sym = {a: n for a, _, n in symbols}
    containing_sym = build_addr_to_containing_symbol(symbols)

    # Build function ranges
    func_addrs = [a for a, _ in func_symbols]
    func_names = [n for _, n in func_symbols]
    func_ranges = []
    for i in range(len(func_symbols)):
        start = func_addrs[i]
        end = func_addrs[i + 1] if i + 1 < len(func_symbols) else start + 0x1000
        if end - start > 0x10000:
            end = start + 0x10000
        func_ranges.append((start, end, func_names[i]))

    # Collect vtable addresses and build GOT → vtable mapping
    vtable_to_class = {}
    for addr, sym_type, name in symbols:
        if sym_type == 'd' and name.startswith("vtable for CINSBot"):
            cls = name.replace("vtable for ", "")
            vtable_to_class[addr] = cls

    print(f"Found {len(vtable_to_class)} CINSBot vtables", file=sys.stderr)

    # Build GOT entry → class mapping
    # Read all GOT entries and check if they point to known vtables
    vtable_got_map = {}  # got_entry_vaddr → class_name
    for got_vaddr in range(GOT_VADDR, GOT_END, 4):
        file_offset = got_vaddr - SEG2_VADDR_OFFSET
        if file_offset + 4 > len(data):
            continue
        val = struct.unpack_from("<I", data, file_offset)[0]
        if val in vtable_to_class:
            vtable_got_map[got_vaddr] = vtable_to_class[val]

    # Also scan .got.plt
    GOT_PLT_SIZE = 0x30C
    for got_vaddr in range(GOT_PLT_ADDR, GOT_PLT_ADDR + GOT_PLT_SIZE, 4):
        file_offset = got_vaddr - SEG2_VADDR_OFFSET
        if file_offset + 4 > len(data):
            continue
        val = struct.unpack_from("<I", data, file_offset)[0]
        if val in vtable_to_class:
            vtable_got_map[got_vaddr] = vtable_to_class[val]

    print(f"Found {len(vtable_got_map)} GOT entries pointing to action vtables", file=sys.stderr)

    # Filter bot functions
    bot_funcs = [(s, e, n) for s, e, n in func_ranges
                 if "non-virtual thunk" not in n and is_action_class(n)]

    # Find constructor addresses
    constructor_addrs = set()
    for addr, _, name in symbols:
        if is_action_constructor(name):
            constructor_addrs.add(addr)

    # Find operator new addresses
    new_addrs = set()
    for addr, _, name in symbols:
        if "operator new(unsigned int)" in name or "operator new(unsigned long)" in name:
            new_addrs.add(addr)

    print(f"Scanning {len(bot_funcs)} bot functions...", file=sys.stderr)

    transitions = []
    action_sizes = {}

    for func_start, func_end, func_name in bot_funcs:
        src_cls = get_class_name(func_name)
        src_method = get_method_name(func_name)

        # Method 1: Direct call to constructor
        calls = find_calls_in_function(data, func_start, func_end)
        recent_new_size = None

        for call_site, target_addr in calls:
            target_sym = addr_to_sym.get(target_addr)
            if not target_sym:
                continue

            if target_addr in new_addrs:
                size = find_push_imm_before(data, call_site)
                if size and 0 < size < 0x1000:
                    recent_new_size = size
                continue

            if target_addr in constructor_addrs and is_action_constructor(target_sym):
                target_cls = get_class_name(target_sym)
                if src_cls == target_cls and is_constructor(func_name):
                    continue
                if recent_new_size:
                    action_sizes[target_cls] = recent_new_size
                transitions.append((src_cls, src_method, target_cls, "call", recent_new_size))
                recent_new_size = None

        # Method 2: Inlined constructor (vtable install from GOT)
        got_info = find_got_base_in_function(data, func_start, func_end)
        if got_info:
            got_reg, got_base = got_info
            vtable_refs = find_vtable_installs(data, func_start, func_end,
                                                got_reg, got_base, vtable_got_map)
            for ref_site, target_cls in vtable_refs:
                if src_cls == target_cls:
                    continue  # skip self-vtable in own constructor
                # Check if we already found this via direct call
                already_found = any(t[0] == src_cls and t[1] == src_method and t[2] == target_cls
                                   for t in transitions)
                if not already_found:
                    # Try to find the new() size nearby
                    size = None
                    for call_site, target_addr in calls:
                        if target_addr in new_addrs and call_site < ref_site and ref_site - call_site < 200:
                            size = find_push_imm_before(data, call_site)
                            break
                    if size and 0 < size < 0x1000:
                        action_sizes[target_cls] = size
                    transitions.append((src_cls, src_method, target_cls, "vtable", size))

    # Deduplicate
    seen = set()
    unique_transitions = []
    for t in transitions:
        key = (t[0], t[1], t[2])
        if key not in seen:
            seen.add(key)
            unique_transitions.append(t)
    unique_transitions.sort()

    print(f"Found {len(unique_transitions)} unique transitions", file=sys.stderr)

    # Output
    print("# Bot Action State Transition Graph")
    print("# Extracted from server_srv.so")
    print(f"# {len(unique_transitions)} unique transitions")
    print("# Detection: 'call' = direct constructor call, 'vtable' = inlined constructor (vtable install)")
    print()

    by_source = defaultdict(list)
    for src_cls, src_method, target_cls, detect_type, obj_size in unique_transitions:
        by_source[src_cls].append((src_method, target_cls, detect_type, obj_size))

    for src_cls in sorted(by_source.keys()):
        trans = by_source[src_cls]
        print(f"## {src_cls}")
        for src_method, target_cls, detect_type, obj_size in sorted(trans):
            size_str = f" (size={obj_size})" if obj_size else ""
            dt = f" [{detect_type}]" if detect_type == "vtable" else ""
            print(f"  {src_method}() → **{target_cls}**{size_str}{dt}")
        print()

    # Action object sizes
    if action_sizes:
        print("## Action Object Sizes")
        print()
        for cls in sorted(action_sizes.keys()):
            print(f"  {cls}: {action_sizes[cls]} bytes (0x{action_sizes[cls]:x})")
        print()

    # DOT graph
    print("## DOT Graph")
    print()
    print("```dot")
    print("digraph BotActionTransitions {")
    print("  rankdir=TB;")
    print('  node [shape=box, fontname="Helvetica", fontsize=10];')
    print('  edge [fontname="Helvetica", fontsize=8];')
    print()

    type_colors = {
        "combat": "#ff6b6b",
        "movement": "#4ecdc4",
        "objective": "#45b7d1",
        "utility": "#f9ca24",
        "monitor": "#a29bfe",
        "gamemode": "#fd79a8",
    }

    type_map = {}
    for t, classes in {
        "combat": ["CINSBotCombat", "CINSBotAttack", "CINSBotAttackRifle",
                    "CINSBotAttackSniper", "CINSBotAttackLMG", "CINSBotAttackPistol",
                    "CINSBotAttackMelee", "CINSBotAttackCQC", "CINSBotAttackAdvance",
                    "CINSBotAttackFromCover", "CINSBotAttackInPlace", "CINSBotAttackIntoCover",
                    "CINSBotFireRPG", "CINSBotSuppressTarget"],
        "movement": ["CINSBotApproach", "CINSBotPursue", "CINSBotRetreat",
                      "CINSBotRetreatToCover", "CINSBotRetreatToHidingSpot",
                      "CINSBotEscort", "CINSBotFollowCommand", "CINSBotSweepArea",
                      "CINSBotInvestigate", "CINSBotInvestigateGunshot"],
        "objective": ["CINSBotCaptureCP", "CINSBotCaptureFlag", "CINSBotGuardCP",
                       "CINSBotGuardDefensive", "CINSBotDestroyCache"],
        "utility": ["CINSBotReload", "CINSBotThrowGrenade", "CINSBotDead",
                     "CINSBotFlashed", "CINSBotStuck", "CINSBotSpecialAction", "CINSBotChatter"],
        "monitor": ["CINSBotMainAction", "CINSBotTacticalMonitor",
                     "CINSBotGamemodeMonitor", "CINSBotInvestigationMonitor", "CINSBotPatrol"],
        "gamemode": ["CINSBotActionAmbush", "CINSBotActionCheckpoint",
                      "CINSBotActionConquer", "CINSBotActionFirefight",
                      "CINSBotActionFlashpoint", "CINSBotActionHunt",
                      "CINSBotActionInfiltrate", "CINSBotActionOccupy",
                      "CINSBotActionOutpost", "CINSBotActionPush",
                      "CINSBotActionSkirmish", "CINSBotActionStrike",
                      "CINSBotActionSurvival", "CINSBotActionTraining"],
    }.items():
        for c in classes:
            type_map[c] = t

    all_nodes = set()
    for t in unique_transitions:
        all_nodes.add(t[0])
        all_nodes.add(t[2])

    for node in sorted(all_nodes):
        t = type_map.get(node, "")
        color = type_colors.get(t, "#ffffff")
        short = node.replace("CINSBot", "").replace("CINSNextBot", "NextBot")
        if not short:
            short = "Bot"
        print(f'  "{node}" [label="{short}", style=filled, fillcolor="{color}"];')

    print()
    for src_cls, src_method, target_cls, detect_type, _ in unique_transitions:
        style = ', style=dashed' if detect_type == "vtable" else ""
        print(f'  "{src_cls}" -> "{target_cls}" [label="{src_method}"{style}];')

    print("}")
    print("```")


if __name__ == "__main__":
    main()
