#!/usr/bin/env python3
"""
Extract class data layouts from constructor disassembly of server_srv.so.

Analyzes constructors to find:
- Member initialization (movl/movb/movw to object offsets)
- Vtable pointer installations
- Sub-object constructor calls (with 'this' pointer offsets)
- Float/int/bool member type inference from initial values
- Base class size estimation from sub-object offsets

Works with 32-bit x86 PIC (Position-Independent Code).
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
SEG2_VADDR_OFFSET = 0x1000

# .rodata for string resolution
RODATA_VADDR = 0x008a8280
RODATA_SIZE  = 0x000de324
RODATA_END   = RODATA_VADDR + RODATA_SIZE

# GOT section
GOT_VADDR = 0x00B96484
GOT_SIZE  = 0x00000CF4
GOT_END   = GOT_VADDR + GOT_SIZE

# .data section (vtables live here)
DATA_VADDR = 0x00B97484  # approximate start of .data
DATA_END   = 0x00BE0000  # approximate end


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def parse_all_symbols(binary_path):
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
                if name.startswith(".L") and name[2:].isdigit():
                    continue
                symbols.append((addr, sym_type, name))
            except ValueError:
                continue
    symbols.sort()
    return symbols


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


def read_cstring(data, file_offset, max_len=200):
    """Read a C string from file offset."""
    if file_offset < 0 or file_offset >= len(data):
        return None
    end = file_offset
    while end < len(data) and end - file_offset < max_len and data[end] != 0:
        end += 1
    if end == file_offset:
        return None
    try:
        s = data[file_offset:end].decode('ascii')
        if all(c.isprintable() or c in '\t\n\r' for c in s):
            return s
    except (UnicodeDecodeError, ValueError):
        pass
    return None


REG_NAMES = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7: "edi"}


def is_float_bits(val):
    """Check if a 32-bit value looks like a float constant."""
    if val == 0:
        return False
    f = struct.unpack("<f", struct.pack("<I", val))[0]
    # Common float patterns: small values, powers of 2, etc.
    if abs(f) < 1e-30 or abs(f) > 1e10:
        return False
    # Check if it's a "round" float (common for initial values)
    s = f"{f:.6f}"
    # Heuristic: most initial floats have few significant digits
    return True


def float_val(bits):
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def infer_type(offset, size, value, is_vtable=False, is_sub_obj=False, sub_obj_class=None):
    """Infer member type from initialization pattern."""
    if is_vtable:
        return "vtable*"
    if is_sub_obj:
        return f"{sub_obj_class}*" if sub_obj_class else "sub_object"
    if size == 1:
        if value in (0, 1):
            return "bool"
        return "uint8_t"
    if size == 2:
        return "int16_t"
    if size == 4:
        if value == 0:
            return "int/ptr/float"  # ambiguous
        # Check if float
        f = float_val(value)
        if is_float_bits(value):
            return f"float ({f:.4g})"
        if 0 < value < 0x10000:
            return f"int ({value})"
        if value > 0x80000000:
            signed = value - 0x100000000
            if -10000 < signed < 0:
                return f"int ({signed})"
        if value == 0xFFFFFFFF:
            return "int (-1)"
        if TEXT_VADDR <= value < TEXT_END:
            return "func_ptr"
        if DATA_VADDR <= value < DATA_END:
            return "data_ptr"
        return f"uint32_t (0x{value:08x})"
    return f"bytes[{size}]"


class MemberInfo:
    def __init__(self, offset, size, value, mtype, extra=""):
        self.offset = offset
        self.size = size
        self.value = value
        self.mtype = mtype
        self.extra = extra  # vtable class name, string value, etc.

    def __repr__(self):
        return f"  +0x{self.offset:04x} ({self.offset:4d})  {self.mtype:<20s}  = {self.format_value():<16s}  {self.extra}"

    def format_value(self):
        if self.size == 1:
            return f"0x{self.value:02x}"
        if self.size == 2:
            return f"0x{self.value:04x}"
        if self.size == 4:
            return f"0x{self.value:08x}"
        return f"0x{self.value:x}"


def analyze_constructor(data, func_start, func_end, func_name, all_symbols,
                        addr_to_sym, vtable_syms, got_vtable_map, got_reg_info=None):
    """Analyze a constructor to extract class member layout.

    Looks for:
    1. movl $imm32, offset(%reg)  — store 32-bit value (C7 84/85/86/87 or C7 40-47)
    2. movb $imm8, offset(%reg)   — store byte (C6 80-87 or C6 40-47)
    3. movw $imm16, offset(%reg)  — store 16-bit (66 C7 ...)
    4. movl %src, offset(%reg)    — store register (89 xx)
    5. mov GOT_disp(%got_reg), %dest — vtable from GOT
       followed by mov %dest, offset(%this)  — vtable install
    6. lea offset(%this), %arg + call constructor — sub-object init
    7. fstps offset(%reg) — float store after fld constant
    8. movss/movsd xmm, offset(%reg) — SSE float store
    """
    members = {}  # offset → MemberInfo

    # Determine 'this' register: usually the first mov that saves arg to register
    # In cdecl, 'this' comes as first arg: mov 0x8(%ebp), %reg or directly from %ecx (thiscall)
    # For Action constructors, typically: push %ebp; mov %esp,%ebp; ...
    # this is at 8(%ebp) and gets loaded into a register.

    # We need the GOT base for vtable resolution
    got_info = find_got_base_in_function(data, func_start, func_end)
    got_reg = got_info[0] if got_info else None
    got_base = got_info[1] if got_info else None

    # Track register values for vtable installations
    reg_values = {}  # reg → (value, source_description)

    # Scan for member stores
    i = func_start
    while i < func_end - 2 and i < len(data) - 6:
        # === Pattern 1: movl $imm32, disp8(%reg) — C7 40-47 disp8 imm32 ===
        if data[i] == 0xC7:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            reg_field = (modrm >> 3) & 7  # /0 for mov immediate

            if reg_field == 0:  # /0 = mov
                if mod == 1 and rm != 4 and i + 7 <= len(data):
                    # mod=01: disp8
                    disp = struct.unpack_from("<b", data, i + 2)[0]
                    imm32 = struct.unpack_from("<I", data, i + 3)[0]
                    offset = disp & 0xFF if disp >= 0 else disp + 256
                    offset = disp  # Keep signed
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 4, imm32)
                        extra = ""
                        # Check if value is a vtable address
                        if imm32 in vtable_syms:
                            mtype = "vtable*"
                            extra = vtable_syms[imm32]
                        members[disp] = MemberInfo(disp, 4, imm32, mtype, extra)
                    i += 7
                    continue

                elif mod == 2 and rm != 4 and i + 10 <= len(data):
                    # mod=10: disp32
                    disp = struct.unpack_from("<i", data, i + 2)[0]
                    imm32 = struct.unpack_from("<I", data, i + 6)[0]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 4, imm32)
                        extra = ""
                        if imm32 in vtable_syms:
                            mtype = "vtable*"
                            extra = vtable_syms[imm32]
                        members[disp] = MemberInfo(disp, 4, imm32, mtype, extra)
                    i += 10
                    continue

                elif mod == 1 and rm == 4 and i + 8 <= len(data):
                    # SIB byte present: C7 44 SIB disp8 imm32
                    sib = data[i + 2]
                    base = sib & 7
                    disp = struct.unpack_from("<b", data, i + 3)[0]
                    imm32 = struct.unpack_from("<I", data, i + 4)[0]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 4, imm32)
                        extra = ""
                        if imm32 in vtable_syms:
                            mtype = "vtable*"
                            extra = vtable_syms[imm32]
                        members[disp] = MemberInfo(disp, 4, imm32, mtype, extra)
                    i += 8
                    continue

                elif mod == 2 and rm == 4 and i + 11 <= len(data):
                    # SIB byte: C7 84 SIB disp32 imm32
                    sib = data[i + 2]
                    disp = struct.unpack_from("<i", data, i + 3)[0]
                    imm32 = struct.unpack_from("<I", data, i + 7)[0]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 4, imm32)
                        extra = ""
                        if imm32 in vtable_syms:
                            mtype = "vtable*"
                            extra = vtable_syms[imm32]
                        members[disp] = MemberInfo(disp, 4, imm32, mtype, extra)
                    i += 11
                    continue

        # === Pattern 2: movb $imm8, disp(%reg) — C6 40-47 disp8 imm8 or C6 80-87 disp32 imm8 ===
        if data[i] == 0xC6:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            reg_field = (modrm >> 3) & 7

            if reg_field == 0:  # /0 = mov byte
                if mod == 1 and rm != 4 and i + 4 <= len(data):
                    disp = struct.unpack_from("<b", data, i + 2)[0]
                    imm8 = data[i + 3]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 1, imm8)
                        members[disp] = MemberInfo(disp, 1, imm8, mtype)
                    i += 4
                    continue

                elif mod == 2 and rm != 4 and i + 7 <= len(data):
                    disp = struct.unpack_from("<i", data, i + 2)[0]
                    imm8 = data[i + 6]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 1, imm8)
                        members[disp] = MemberInfo(disp, 1, imm8, mtype)
                    i += 7
                    continue

                elif mod == 1 and rm == 4 and i + 5 <= len(data):
                    sib = data[i + 2]
                    disp = struct.unpack_from("<b", data, i + 3)[0]
                    imm8 = data[i + 4]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 1, imm8)
                        members[disp] = MemberInfo(disp, 1, imm8, mtype)
                    i += 5
                    continue

                elif mod == 2 and rm == 4 and i + 8 <= len(data):
                    sib = data[i + 2]
                    disp = struct.unpack_from("<i", data, i + 3)[0]
                    imm8 = data[i + 7]
                    if 0 <= disp < 0x1000:
                        mtype = infer_type(disp, 1, imm8)
                        members[disp] = MemberInfo(disp, 1, imm8, mtype)
                    i += 8
                    continue

        # === Pattern 3: mov %reg, disp(%base) — 89 xx (store register to memory) ===
        # This catches vtable installs: mov %eax, 0x0(%ecx) where eax was loaded from GOT
        if data[i] == 0x89:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            src_reg = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 1 and rm != 4 and i + 3 <= len(data):
                disp = struct.unpack_from("<b", data, i + 2)[0]
                if 0 <= disp < 0x1000 and src_reg in reg_values:
                    val, desc = reg_values[src_reg]
                    if desc.startswith("vtable:"):
                        cls_name = desc[7:]
                        members[disp] = MemberInfo(disp, 4, val, "vtable*", cls_name)
                    elif desc.startswith("secondary_vtable:"):
                        cls_name = desc[17:]
                        members[disp] = MemberInfo(disp, 4, val, "secondary_vtable*", cls_name)
                i += 3
                continue

            elif mod == 2 and rm != 4 and i + 6 <= len(data):
                disp = struct.unpack_from("<i", data, i + 2)[0]
                if 0 <= disp < 0x1000 and src_reg in reg_values:
                    val, desc = reg_values[src_reg]
                    if desc.startswith("vtable:"):
                        cls_name = desc[7:]
                        members[disp] = MemberInfo(disp, 4, val, "vtable*", cls_name)
                    elif desc.startswith("secondary_vtable:"):
                        cls_name = desc[17:]
                        members[disp] = MemberInfo(disp, 4, val, "secondary_vtable*", cls_name)
                i += 6
                continue

            elif mod == 0 and rm != 4 and rm != 5:
                # mod=0, disp=0: mov %src, (%rm)
                if src_reg in reg_values:
                    val, desc = reg_values[src_reg]
                    if desc.startswith("vtable:"):
                        cls_name = desc[7:]
                        members[0] = MemberInfo(0, 4, val, "vtable*", cls_name)
                    elif desc.startswith("secondary_vtable:"):
                        cls_name = desc[17:]
                        members[0] = MemberInfo(0, 4, val, "secondary_vtable*", cls_name)
                i += 2
                continue

        # === Pattern 4: mov GOT_disp(%got_reg), %dest — vtable load from GOT (8B modrm disp32) ===
        if data[i] == 0x8B and got_reg is not None:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            dest_reg = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and rm == got_reg and rm != 4 and i + 6 <= len(data):
                disp32 = struct.unpack_from("<i", data, i + 2)[0]
                got_entry_vaddr = (got_base + disp32) & 0xFFFFFFFF
                if got_entry_vaddr in got_vtable_map:
                    cls_name = got_vtable_map[got_entry_vaddr]
                    # Read actual vtable address from GOT
                    file_off = got_entry_vaddr - SEG2_VADDR_OFFSET
                    if 0 <= file_off < len(data) - 4:
                        vtable_addr = struct.unpack_from("<I", data, file_off)[0]
                        reg_values[dest_reg] = (vtable_addr, f"vtable:{cls_name}")
                i += 6
                continue

        # === Pattern 5: lea disp32(%got_reg), %dest — could load vtable addr ===
        if data[i] == 0x8D and got_reg is not None:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            dest_reg = (modrm >> 3) & 7
            rm = modrm & 7

            if mod == 2 and rm == got_reg and rm != 4 and i + 6 <= len(data):
                disp32 = struct.unpack_from("<i", data, i + 2)[0]
                resolved = (got_base + disp32) & 0xFFFFFFFF
                # Check if this resolves to a known vtable
                if resolved in vtable_syms:
                    reg_values[dest_reg] = (resolved, f"vtable:{vtable_syms[resolved]}")
                else:
                    reg_values[dest_reg] = (resolved, f"addr:0x{resolved:08x}")
                i += 6
                continue

        # === Pattern 5b: add $imm32, %reg — modifies tracked register (e.g. secondary vtable) ===
        if data[i] == 0x05 and i + 5 <= len(data):
            # add $imm32, %eax (short form)
            imm32 = struct.unpack_from("<I", data, i + 1)[0]
            if 0 in reg_values:
                old_val, old_desc = reg_values[0]
                new_val = (old_val + imm32) & 0xFFFFFFFF
                if old_desc.startswith("vtable:"):
                    reg_values[0] = (new_val, f"secondary_vtable:{old_desc[7:]}")
                else:
                    reg_values[0] = (new_val, f"adjusted:{old_desc}")
            i += 5
            continue

        if data[i] == 0x81 and i + 6 <= len(data):
            modrm = data[i + 1]
            mod = (modrm >> 6) & 3
            reg_field = (modrm >> 3) & 7
            rm = modrm & 7
            if mod == 3 and reg_field == 0:  # add $imm32, %reg
                imm32 = struct.unpack_from("<I", data, i + 2)[0]
                if rm in reg_values:
                    old_val, old_desc = reg_values[rm]
                    new_val = (old_val + imm32) & 0xFFFFFFFF
                    if old_desc.startswith("vtable:"):
                        reg_values[rm] = (new_val, f"secondary_vtable:{old_desc[7:]}")
                    else:
                        reg_values[rm] = (new_val, f"adjusted:{old_desc}")
                i += 6
                continue

        # === Pattern 6: movl $imm32, (%esp) followed by call — sub-object init ===
        # (Tracked via call pattern below)

        # === Pattern 7: call rel32 — sub-object constructor or base class init ===
        if data[i] == 0xE8 and i + 5 <= len(data):
            rel32 = struct.unpack_from("<i", data, i + 1)[0]
            target = (i + 5 + rel32) & 0xFFFFFFFF
            target_sym = addr_to_sym.get(target)
            # Check if this calls a known constructor
            if target_sym and "::" in target_sym:
                parts = target_sym.split("::")
                cls = parts[0].split("<")[0]
                method = parts[-1].split("(")[0].split("<")[0]
                if method == cls and cls != func_name.split("::")[0]:
                    # This is a sub-object constructor call
                    # Look for lea disp(%reg), %ecx or push lea offset before call
                    # to determine where the sub-object starts
                    sub_offset = find_sub_object_offset(data, i, func_start)
                    if sub_offset is not None and 0 <= sub_offset < 0x1000:
                        members[sub_offset] = MemberInfo(
                            sub_offset, 4, 0, f"sub_object", f"{target_sym.split('(')[0]}")
            i += 5
            continue

        i += 1

    return members


def find_sub_object_offset(data, call_site, func_start):
    """Look backwards from a call to find what offset of 'this' was passed.

    Patterns:
    - lea offset(%reg), %ecx; call — thiscall, sub-object at offset
    - lea offset(%reg), %eax; mov %eax, (%esp); call — cdecl with lea
    - add $offset, %eax; mov %eax, (%esp); call — this + offset
    - push %reg where reg was lea'd — harder to track
    """
    # Scan backwards up to 20 bytes
    for back in range(2, 30):
        pos = call_site - back
        if pos < func_start:
            break

        # lea disp8(%reg), %dest — 8D 40-7F disp8 (mod=01, no SIB)
        if data[pos] == 0x8D:
            modrm = data[pos + 1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7

            if mod == 1 and rm != 4 and pos + 3 <= call_site:
                disp = struct.unpack_from("<b", data, pos + 2)[0]
                if 0 <= disp < 0x1000:
                    return disp

            if mod == 2 and rm != 4 and pos + 6 <= call_site:
                disp = struct.unpack_from("<i", data, pos + 2)[0]
                if 0 <= disp < 0x1000:
                    return disp

    return None


def get_constructor_symbols(symbols):
    """Find all bot-related constructors."""
    constructors = {}
    for addr, sym_type, name in symbols:
        if sym_type not in ('t', 'T', 'W', 'w'):
            continue
        if "::" not in name:
            continue
        parts = name.split("::")
        cls = parts[0].split("<")[0]
        method = parts[-1].split("(")[0].split("<")[0]
        if method == cls:
            # It's a constructor
            if (cls.startswith("CINSBot") or cls.startswith("CINSNextBot") or
                cls == "CINSNextBot"):
                if name not in constructors.values():
                    constructors[addr] = name
    return constructors


def get_function_end(addr, func_symbols):
    """Get end address of a function."""
    addrs = [a for a, _ in func_symbols]
    idx = bisect_right(addrs, addr)
    if idx < len(addrs):
        end = addrs[idx]
        if end - addr > 0x10000:
            end = addr + 0x10000
        return end
    return addr + 0x1000


def main():
    print("Loading binary...", file=sys.stderr)
    data = load_binary(BINARY)

    print("Loading symbols...", file=sys.stderr)
    symbols = parse_all_symbols(BINARY)
    func_symbols = [(a, n) for a, t, n in symbols if t in ('t', 'T', 'W', 'w')]
    addr_to_sym = {a: n for a, _, n in symbols}

    # Vtable symbols: exact vtable addresses
    vtable_syms = {}
    for addr, sym_type, name in symbols:
        if name.startswith("vtable for "):
            cls = name[len("vtable for "):]
            # Vtable pointer in objects typically points to vtable+8 (past RTTI info)
            # But the symbol points to the start. We'll check both.
            vtable_syms[addr] = cls
            vtable_syms[addr + 8] = cls  # common offset past typeinfo/offset entries

    # GOT → vtable map
    got_vtable_map = {}
    for got_vaddr in range(GOT_VADDR, GOT_END, 4):
        file_offset = got_vaddr - SEG2_VADDR_OFFSET
        if file_offset + 4 > len(data):
            continue
        val = struct.unpack_from("<I", data, file_offset)[0]
        if val in vtable_syms:
            got_vtable_map[got_vaddr] = vtable_syms[val]
    # Also scan .got.plt
    GOT_PLT_SIZE = 0x30C
    for got_vaddr in range(GOT_PLT_ADDR, GOT_PLT_ADDR + GOT_PLT_SIZE, 4):
        file_offset = got_vaddr - SEG2_VADDR_OFFSET
        if file_offset + 4 > len(data):
            continue
        val = struct.unpack_from("<I", data, file_offset)[0]
        if val in vtable_syms:
            got_vtable_map[got_vaddr] = vtable_syms[val]

    print(f"Found {len(got_vtable_map)} GOT vtable entries", file=sys.stderr)

    # Find all bot constructors
    constructors = get_constructor_symbols(symbols)
    print(f"Found {len(constructors)} bot constructors", file=sys.stderr)

    # Known object sizes from transition graph (operator new allocations)
    known_sizes = {
        "CINSBotVision": 640,
        "CINSBotBody": 376,
        "CINSBotCombat": 136,
        "CINSBotEscort": 156,
        "CINSBotTacticalMonitor": 152,
        "CINSBotAttack": 80,
        "CINSBotAttackRifle": 80,
        "CINSBotAttackSniper": 80,
        "CINSBotAttackLMG": 80,
        "CINSBotAttackPistol": 80,
        "CINSBotAttackMelee": 80,
        "CINSBotAttackCQC": 80,
    }

    # Analyze each constructor
    results = {}
    for addr, name in sorted(constructors.items()):
        cls = name.split("::")[0].split("<")[0]
        func_end = get_function_end(addr, func_symbols)
        func_size = func_end - addr

        print(f"  Analyzing {name} @ 0x{addr:08x} ({func_size} bytes)...", file=sys.stderr)

        members = analyze_constructor(
            data, addr, func_end, name,
            symbols, addr_to_sym, vtable_syms, got_vtable_map
        )

        if members:
            results[name] = {
                "addr": addr,
                "size": func_size,
                "cls": cls,
                "obj_size": known_sizes.get(cls),
                "members": members,
            }

    # === Post-processing: annotate known patterns ===

    # Action<CINSNextBot> base class layout (56 bytes = 0x38)
    # Derived from source-sdk-2013 Action.h + NWI secondary vtable
    ACTION_BASE = {
        0x00: ("vtable*", "Action<CINSNextBot> primary vtable"),
        0x04: ("secondary_vtable*", "IContextualQuery vtable (vtable+0x1A0)"),
        0x08: ("Behavior*", "m_behavior — owning Behavior tree"),
        0x0C: ("Action*", "m_parent — containing Action"),
        0x10: ("Action*", "m_child — active child (top of stack)"),
        0x14: ("Action*", "m_buriedUnderMe — action below in stack"),
        0x18: ("Action*", "m_coveringMe — action above in stack"),
        0x1C: ("CINSNextBot*", "m_actor — the bot entity"),
        0x20: ("int", "m_eventResult.type (ActionResultType)"),
        0x24: ("Action*", "m_eventResult.m_action"),
        0x28: ("const char*", "m_eventResult.m_reason"),
        0x2C: ("int", "m_eventResult.m_priority (EventResultPriorityType)"),
        0x30: ("bool", "m_isStarted"),
        0x31: ("bool", "m_isSuspended"),
        0x34: ("int", "m_eventResult (secondary/unused)"),
    }
    ACTION_BASE_SIZE = 0x38

    # CountdownTimer layout: vtable(4) + m_timestamp(4) + m_duration(4) = 12 bytes
    COUNTDOWN_TIMER_VTABLE = 0x00b181b8
    COUNTDOWN_TIMER_SIZE = 12

    # IntervalTimer layout: vtable(4) + m_timestamp(4) = 8 bytes
    INTERVAL_TIMER_VTABLE = 0x00b28688

    def is_action_derived(cls):
        return (cls.startswith("CINSBotAction") or
                cls.startswith("CINSBotAttack") or
                cls in ("CINSBotApproach", "CINSBotCombat", "CINSBotReload",
                         "CINSBotCaptureCP", "CINSBotCaptureFlag", "CINSBotDestroyCache",
                         "CINSBotEscort", "CINSBotFireRPG", "CINSBotFollowCommand",
                         "CINSBotGuardCP", "CINSBotGuardDefensive", "CINSBotInvestigate",
                         "CINSBotInvestigateGunshot", "CINSBotMainAction", "CINSBotPatrol",
                         "CINSBotPursue", "CINSBotRetreat", "CINSBotRetreatToCover",
                         "CINSBotRetreatToHidingSpot", "CINSBotSpecialAction",
                         "CINSBotSuppressTarget", "CINSBotSweepArea",
                         "CINSBotTacticalMonitor", "CINSBotGamemodeMonitor",
                         "CINSBotInvestigationMonitor", "CINSBotThrowGrenade",
                         "CINSBotDead", "CINSBotFlashed", "CINSBotStuck",
                         "CINSBotChatter"))

    def postprocess_members(cls, members):
        """Annotate known patterns in member layout."""
        annotated = {}
        consumed = set()  # offsets consumed by multi-byte sub-objects

        for offset in sorted(members.keys()):
            if offset in consumed:
                continue  # already part of a grouped sub-object

            m = members[offset]

            # Annotate Action<T> base class members
            if is_action_derived(cls) and offset in ACTION_BASE:
                base_type, base_note = ACTION_BASE[offset]
                annotated[offset] = MemberInfo(offset, m.size, m.value, base_type, base_note)
                continue

            # Detect CountdownTimer sub-objects: vtable + 0 + -1.0f pattern
            if (m.mtype == "vtable*" and m.extra == "CountdownTimer" and
                    m.value == COUNTDOWN_TIMER_VTABLE):
                # Check if next two slots match pattern
                ts_offset = offset + 4
                dur_offset = offset + 8
                ts = members.get(ts_offset)
                dur = members.get(dur_offset)
                if ts and dur and ts.value == 0 and dur.value == 0xBF800000:
                    annotated[offset] = MemberInfo(offset, 12, m.value,
                                                    "CountdownTimer[12]", "{ vtable, m_timestamp=0, m_duration=-1.0f }")
                    consumed.add(ts_offset)
                    consumed.add(dur_offset)
                    continue
                else:
                    # Standalone CountdownTimer vtable (maybe only vtable init'd)
                    annotated[offset] = MemberInfo(offset, 4, m.value, "CountdownTimer.vtable*", "")
                    continue

            # Detect IntervalTimer sub-objects
            if m.mtype == "vtable*" and "IntervalTimer" in m.extra:
                annotated[offset] = MemberInfo(offset, 8, m.value,
                                                "IntervalTimer[8]", "{ vtable, m_timestamp }")
                ts_offset = offset + 4
                consumed.add(ts_offset)
                continue

            # Default: keep as-is
            annotated[offset] = m

        return annotated

    # Group by class (some classes have multiple constructor overloads)
    by_class = defaultdict(list)
    for name, info in results.items():
        by_class[info["cls"]].append((name, info))

    # Process all classes
    for cls in sorted(by_class.keys()):
        entries = by_class[cls]
        # Pick the constructor with the most members (best info)
        best_name, best_info = max(entries, key=lambda x: len(x[1]["members"]))

        # Merge members from all constructors
        if len(entries) > 1:
            all_members = dict(best_info["members"])
            for n, i in entries:
                for offset, member in i["members"].items():
                    if offset not in all_members:
                        all_members[offset] = member
                    elif all_members[offset].mtype == "int/ptr/float" and member.mtype != "int/ptr/float":
                        all_members[offset] = member
            best_info["members"] = all_members

        # Post-process
        best_info["members"] = postprocess_members(cls, best_info["members"])

    # Output report
    print("# Class Data Layouts — Extracted from Constructor Disassembly")
    print(f"# Source: server_srv.so")
    print(f"# {len(results)} constructors analyzed")
    print()

    # Action<T> base class documentation
    print("## Action<CINSNextBot> Base Class Layout")
    print()
    print("All Action-derived classes share this 56-byte (0x38) base layout:")
    print("(From source-sdk-2013 Action.h + NWI secondary vtable)")
    print()
    print("```")
    print(f"{'Offset':>8s}  {'Type':<20s}  {'Member Name'}")
    print(f"{'------':>8s}  {'----':<20s}  {'-----------'}")
    for off in sorted(ACTION_BASE.keys()):
        atype, anote = ACTION_BASE[off]
        print(f"+0x{off:04x}     {atype:<20s}  {anote}")
    print("```")
    print()

    for cls in sorted(by_class.keys()):
        entries = by_class[cls]
        best_name, best_info = max(entries, key=lambda x: len(x[1]["members"]))

        print(f"## {cls}")
        obj_size = best_info["obj_size"]
        if obj_size:
            print(f"Object size: {obj_size} bytes (0x{obj_size:x})")
        print(f"Constructor: `{best_name}` @ 0x{best_info['addr']:08x}")
        print(f"Constructor size: {best_info['size']} bytes")

        # Count only non-base members for action classes
        all_offsets = sorted(best_info["members"].keys())
        if is_action_derived(cls):
            derived_members = {k: v for k, v in best_info["members"].items() if k >= ACTION_BASE_SIZE}
            print(f"Derived members: {len(derived_members)} (+ {len(ACTION_BASE)} base)")
        else:
            derived_members = best_info["members"]
            print(f"Members found: {len(derived_members)}")
        print()

        if len(entries) > 1:
            other = [(n, i) for n, i in entries if n != best_name]
            for n, i in other:
                print(f"  Also: `{n}` @ 0x{i['addr']:08x} ({len(i['members'])} members)")
            print()

        print("```")
        print(f"{'Offset':>8s}  {'Type':<24s}  {'Init Value':<16s}  {'Notes'}")
        print(f"{'------':>8s}  {'----':<24s}  {'----------':<16s}  {'-----'}")

        # For Action-derived, show base class fields condensed
        if is_action_derived(cls):
            # Show primary vtable
            if 0x00 in best_info["members"]:
                m = best_info["members"][0x00]
                print(f"+0x0000     {'vtable*':<24s}  {m.format_value():<16s}  {m.extra}")
            if 0x04 in best_info["members"]:
                m = best_info["members"][0x04]
                print(f"+0x0004     {'secondary_vtable*':<24s}  {m.format_value():<16s}  {m.extra}")
            print(f"  ...       {'[Action<T> base]':<24s}  {'(0x08-0x34)':<16s}  see base layout above")
            print(f"  ----      {'--- derived members ---':<24s}  {'----------':<16s}  -----")

            for offset in sorted(derived_members.keys()):
                m = derived_members[offset]
                # Skip sub-parts of CountdownTimer (indented)
                notes = m.extra
                print(f"+0x{offset:04x}     {m.mtype:<24s}  {m.format_value():<16s}  {notes}")
        else:
            for offset in all_offsets:
                m = best_info["members"][offset]
                notes = m.extra
                if m.mtype == "vtable*" and not notes:
                    notes = "(primary vtable)"
                print(f"+0x{offset:04x}     {m.mtype:<24s}  {m.format_value():<16s}  {notes}")

        print("```")
        print()

        # Show gaps analysis
        members_to_check = derived_members if is_action_derived(cls) else best_info["members"]
        if members_to_check and obj_size:
            d_offsets = sorted(members_to_check.keys())
            if d_offsets:
                last_known = max(d_offsets)
                start_offset = ACTION_BASE_SIZE if is_action_derived(cls) else 0
                print(f"  Coverage: {len(d_offsets)} derived members "
                      f"(+0x{start_offset:04x} to +0x{last_known:04x}), "
                      f"object size: 0x{obj_size:04x}")

                # Find large gaps (accounting for member sizes)
                gaps = []
                prev_off = start_offset
                prev_size = 0
                for off in d_offsets:
                    m = members_to_check[off]
                    member_size = m.size
                    if "CountdownTimer[12]" in m.mtype:
                        member_size = 12
                    elif "IntervalTimer[8]" in m.mtype:
                        member_size = 8
                    expected_next = prev_off + prev_size
                    gap = off - expected_next
                    if gap > 4 and prev_off != start_offset:
                        gaps.append((expected_next, off, gap))
                    prev_off = off
                    prev_size = member_size
                # Check gap to end
                last_m = members_to_check[last_known]
                last_size = last_m.size
                if "CountdownTimer[12]" in last_m.mtype:
                    last_size = 12
                elif "IntervalTimer[8]" in last_m.mtype:
                    last_size = 8
                end_of_last = last_known + last_size
                if obj_size - end_of_last > 4:
                    gaps.append((end_of_last, obj_size, obj_size - end_of_last))
                if gaps:
                    print(f"  Gaps (>4 bytes):")
                    for start, end, size in gaps:
                        print(f"    +0x{start:04x} to +0x{end:04x} ({size} bytes uninstrumented)")
                print()

    # Summary statistics
    print("## Summary")
    print()
    total_members = sum(len(info["members"]) for _, info in results.items())
    action_classes = sum(1 for cls in by_class if is_action_derived(cls))
    component_classes = len(by_class) - action_classes
    countdown_timers = sum(
        1 for _, info in results.items()
        for m in info["members"].values() if "CountdownTimer[12]" in m.mtype
    )
    interval_timers = sum(
        1 for _, info in results.items()
        for m in info["members"].values() if "IntervalTimer" in m.mtype
    )
    sub_obj_count = sum(
        1 for _, info in results.items()
        for m in info["members"].values() if "sub_object" in m.mtype
    )
    print(f"- Total constructors analyzed: {len(results)}")
    print(f"- Total classes: {len(by_class)} ({action_classes} Action-derived, {component_classes} components)")
    print(f"- Total member slots found: {total_members}")
    print(f"- CountdownTimer sub-objects: {countdown_timers}")
    print(f"- IntervalTimer sub-objects: {interval_timers}")
    print(f"- Sub-object constructor calls: {sub_obj_count}")


if __name__ == "__main__":
    main()
