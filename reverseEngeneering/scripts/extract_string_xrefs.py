#!/usr/bin/env python3
"""
Extract string cross-references per bot action class from server_srv.so.

For 32-bit x86 PIC code, string references use GOT-relative addressing:
  call __get_pc_thunk.XX   ; reg = IP
  add  $offset, %reg       ; reg = GOT_PLT base (always 0xB97178)
  lea  displacement(%reg), %dest  ; dest = string address

This script finds these patterns in each bot function and resolves the strings.
"""

import struct
import sys
import re
import subprocess
from collections import defaultdict
from bisect import bisect_right

BINARY = "/home/yar/Work/reverseengeneer/ins_server_files/ins/insurgency/bin/server_srv.so"

# ELF section info
RODATA_VADDR = 0x008a8280
RODATA_SIZE  = 0x000de324
RODATA_END   = RODATA_VADDR + RODATA_SIZE

GOT_PLT_ADDR = 0x00B97178  # .got.plt section start

# Register encoding for ModRM
REG_EAX, REG_ECX, REG_EDX, REG_EBX = 0, 1, 2, 3
REG_ESP, REG_EBP, REG_ESI, REG_EDI = 4, 5, 6, 7
REG_NAMES = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx',
             4: 'esp', 5: 'ebp', 6: 'esi', 7: 'edi'}


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def extract_cstring(data, offset, max_len=512):
    """Extract a null-terminated C string."""
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b'\x00', offset, offset + max_len)
    if end == -1:
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


def parse_all_symbols(binary_path):
    """Get ALL function symbols sorted by address."""
    result = subprocess.run(
        ["nm", "-C", "-n", binary_path],
        capture_output=True, text=True
    )
    symbols = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 3 and parts[1] in ('t', 'T', 'W'):
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                symbols.append((addr, name))
            except ValueError:
                continue
    symbols.sort()
    return symbols


def find_got_base_in_function(data, func_start, func_end):
    """Find the GOT base register setup in a function.

    Pattern:
      E8 xx xx xx xx       call __get_pc_thunk.XX
      81 C1/C2/C3 xx xx xx xx   add $imm32, %ecx/%edx/%ebx

    Returns (register_number, got_base_value) or None.
    """
    for i in range(func_start, min(func_end - 10, len(data) - 10)):
        # Look for call (E8) followed by add to register (81 Cx)
        if data[i] == 0xE8:
            # call rel32
            call_target_rel = struct.unpack_from("<i", data, i + 1)[0]
            next_ip = i + 5  # IP after the call
            # The next instruction should be add $imm32, %reg
            if next_ip < func_end - 5 and data[next_ip] == 0x81:
                modrm = data[next_ip + 1]
                # add $imm32: ModRM = 11 000 reg (0xC0 + reg)
                if 0xC0 <= modrm <= 0xC7:
                    reg = modrm - 0xC0
                    imm32 = struct.unpack_from("<i", data, next_ip + 2)[0]
                    got_base = (next_ip + imm32) & 0xFFFFFFFF
                    # Verify it's close to the known GOT.PLT
                    if abs(got_base - GOT_PLT_ADDR) < 0x100:
                        return (reg, got_base)
    return None


def find_lea_refs(data, func_start, func_end, got_reg, got_base):
    """Find all lea instructions that reference strings via GOT base.

    lea disp32(%got_reg), %dest  →  opcode 8D, ModRM with mod=10, r/m=got_reg
    Also: push through lea, mov with disp32
    """
    refs = []

    for i in range(func_start, min(func_end - 6, len(data) - 6)):
        # lea r32, [got_reg + disp32]: 8D <ModRM> <disp32>
        if data[i] == 0x8D:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if mod == 2 and rm == got_reg and rm != 4:  # mod=10 = 32-bit displacement, rm != ESP (SIB)
                disp32 = struct.unpack_from("<i", data, i + 2)[0]
                target = (got_base + disp32) & 0xFFFFFFFF
                if RODATA_VADDR <= target < RODATA_END:
                    refs.append(target)
            # With SIB byte (rm=4): 8D ModRM SIB disp32
            # Skip — less common for string refs

        # Also check for mov r32, [got_reg + disp32] for ConVar pointers
        # mov: 8B ModRM disp32  (loads value, not address - but could be loading string pointers from .data.rel.ro)

        # Also: mov [esp+N], computed_addr — not easily trackable without full emulation

    return refs


def is_meaningful_string(s):
    """Filter strings to those that reveal bot behavior logic."""
    sl = s.lower()

    # ConVars
    if s.startswith(("bot_", "ins_bot_", "nb_", "sv_", "mp_")):
        return "convar"

    # Class/type names
    if s.startswith(("CINSBot", "CINSNext", "CINSNav", "CINSPath", "NextBot", "CNav",
                     "Action", "Behavior")):
        return "class"

    # Action names (returned by GetName())
    if re.match(r'^[A-Z][a-z]', s) and 4 <= len(s) <= 40 and s.isalpha():
        return "action_name"

    # Debug/format strings
    if "%" in s and any(c in s for c in "sdfixXp") and len(s) > 5:
        return "debug"
    if any(w in sl for w in ["error", "warning", "failed", "invalid", "assert",
                              "null", "debug", "can't", "cannot", "unable",
                              "unexpected", "missing", "not found", "bad "]):
        return "debug"

    # Bot behavior keywords
    bot_keywords = ["attack", "retreat", "combat", "cover", "enemy",
                    "threat", "target", "patrol", "capture", "defend",
                    "grenade", "weapon", "reload", "stuck", "path",
                    "investigate", "suppress", "flank", "crouch",
                    "prone", "sprint", "hurry", "escort", "guard",
                    "difficulty", "arousal", "silhouette", "visible",
                    "hearing", "sight", "injur", "killed", "dead",
                    "spawn", "objective", "cache", "checkpoint",
                    "nav_area", "hiding", "sniper", "rpg", "fire",
                    "knife", "melee", "bayonet", "ammo", "clip",
                    "formation", "reinforce", "wave", "ambush",
                    "smoke", "flash", "suppres", "approach",
                    "move", "walk", "run", "stand", "position",
                    "door", "gate", "setup"]
    if any(w in sl for w in bot_keywords):
        # Filter out animation sequences (ACT_xxx, all-caps with underscores)
        if s.startswith("ACT_"):
            return None
        if re.match(r'^[A-Z_]+$', s) and len(s) > 15:
            return None
        return "behavior"

    # Game/engine keywords
    if any(w in sl for w in ["timer", "think", "update", "reset", "interval",
                              "player", "team", "distance", "range", "radius",
                              "speed", "velocity", "area", "random", "duration",
                              "delay", "score", "count", "max", "min"]):
        if s.startswith("ACT_"):
            return None
        if re.match(r'^[A-Z_]+$', s) and len(s) > 15:
            return None
        return "keyword"

    return None


def main():
    print("Loading binary...", file=sys.stderr)
    data = load_binary(BINARY)

    print("Loading symbols...", file=sys.stderr)
    symbols = parse_all_symbols(BINARY)
    sym_addrs = [a for a, _ in symbols]
    sym_names = [n for _, n in symbols]

    # Build function ranges: each function extends to the next symbol
    func_ranges = []
    for i in range(len(symbols)):
        start = sym_addrs[i]
        end = sym_addrs[i + 1] if i + 1 < len(symbols) else start + 0x1000
        # Cap at 64KB per function
        if end - start > 0x10000:
            end = start + 0x10000
        func_ranges.append((start, end, sym_names[i]))

    # Filter to bot-related functions
    bot_funcs = []
    for start, end, name in func_ranges:
        if "non-virtual thunk" in name:
            continue
        cls = name.split("::")[0] if "::" in name else ""
        if (cls.startswith("CINSBot") or cls.startswith("CINSNext") or
            cls.startswith("CINSNav") or cls.startswith("CINSPath") or
            "NextBotManager" in name):
            bot_funcs.append((start, end, name))

    print(f"Processing {len(bot_funcs)} bot functions...", file=sys.stderr)

    # Process each function
    class_strings = defaultdict(lambda: defaultdict(set))
    string_categories = {}
    total_refs = 0
    funcs_with_got = 0

    for idx, (func_start, func_end, full_name) in enumerate(bot_funcs):
        if idx % 200 == 0:
            print(f"  {idx}/{len(bot_funcs)} functions...", file=sys.stderr)

        # Find GOT base setup
        got_info = find_got_base_in_function(data, func_start, func_end)
        if not got_info:
            continue
        funcs_with_got += 1

        got_reg, got_base = got_info

        # Find string references
        refs = find_lea_refs(data, func_start, func_end, got_reg, got_base)

        # Resolve strings
        cls = full_name.split("::")[0] if "::" in full_name else full_name
        if "<" in cls:
            cls = cls[:cls.index("<")]
        method = full_name.split("::")[-1] if "::" in full_name else full_name
        paren = method.find("(")
        if paren > 0:
            method = method[:paren]

        for ref_addr in refs:
            s = extract_cstring(data, ref_addr)
            if s:
                cat = is_meaningful_string(s)
                if cat:
                    class_strings[cls][s].add(method)
                    string_categories[s] = cat
                    total_refs += 1

    print(f"  Found GOT base in {funcs_with_got}/{len(bot_funcs)} functions", file=sys.stderr)
    print(f"  Total meaningful string refs: {total_refs}", file=sys.stderr)

    # Output
    print(f"# String Cross-References per Bot Class")
    print(f"# Extracted from server_srv.so via PIC GOT-relative lea resolution")
    print(f"# {total_refs} meaningful string references across {len(class_strings)} classes")
    print()

    for cls in sorted(class_strings.keys()):
        strings = class_strings[cls]
        if not strings:
            continue

        by_cat = defaultdict(list)
        for s, methods in sorted(strings.items()):
            cat = string_categories.get(s, "other")
            methods_str = ", ".join(sorted(methods))
            by_cat[cat].append((s, methods_str))

        total = sum(len(v) for v in by_cat.values())
        print(f"## {cls} ({total} strings)")
        print()

        cat_labels = {
            "convar": "ConVars Referenced",
            "class": "Class/Type Names",
            "action_name": "Action Names",
            "debug": "Debug/Format Strings",
            "behavior": "Behavior Keywords",
            "keyword": "General Keywords",
        }

        for cat in ["convar", "action_name", "behavior", "class", "debug", "keyword"]:
            items = by_cat.get(cat, [])
            if items:
                print(f"  **{cat_labels.get(cat, cat)}:**")
                for s, m in items:
                    display = s if len(s) <= 120 else s[:117] + "..."
                    print(f"    `{display}` ← {m}")
                print()
        print()


if __name__ == "__main__":
    main()
