# -*- coding: utf-8 -*-
"""
ghidra_decompile_ammo_win.py - Decompile ammo/magazine functions from Windows server.dll

Targets GetMagazines, GiveAmmo, and all related callees to understand
the magazine system internals.

Usage: analyzeHeadless ... -postScript ghidra_decompile_ammo_win.py /output/dir

@category Insurgency
@author SmartBots project
"""

import os
import jarray
from collections import OrderedDict
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

IMAGE_BASE = 0x10000000
DECOMPILE_TIMEOUT = 120

# Known/identified functions to decompile (RVA from image base)
SEED_FUNCTIONS = {
    0x2acfd0: "CINSPlayer::GetMagazines",
    0x2ad670: "CINSPlayer::GiveAmmo",
    # Callers of GetMagazines (context)
    0x27e7c0: "GetMagazines_caller_1 (Resupply?)",
    0x2b7140: "GetMagazines_caller_3 (GiveDefaultAmmo?)",
    0x3028b0: "GetMagazines_caller_4 (weapon handling?)",
    0x30a190: "GetMagazines_caller_5 (ammo check?)",
}

# How many levels deep to chase callees
MAX_DEPTH = 2
# Max functions to decompile total (safety limit)
MAX_FUNCTIONS = 80


def decompile_func(decomp, func, monitor):
    try:
        dr = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
        if dr and dr.decompileCompleted():
            df = dr.getDecompiledFunction()
            if df:
                return df.getC()
    except:
        pass
    return None


def get_callees(func):
    """Get addresses of functions called by this function."""
    callees = set()
    func_mgr = currentProgram.getFunctionManager()
    body = func.getBody()
    ref_mgr = currentProgram.getReferenceManager()

    for addr_range in body:
        addr = addr_range.getMinAddress()
        end = addr_range.getMaxAddress()
        while addr is not None and addr.compareTo(end) <= 0:
            refs = ref_mgr.getReferencesFrom(addr)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    target_func = func_mgr.getFunctionAt(target)
                    if target_func:
                        callees.add(target.getOffset())
            addr = addr.next()

    return callees


def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: No output directory specified.")
        return

    output_dir = args[0]
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    monitor = ConsoleTaskMonitor()
    func_mgr = currentProgram.getFunctionManager()

    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(currentProgram)

    # Build worklist: seed functions + their callees (up to MAX_DEPTH)
    to_decompile = OrderedDict()  # offset -> label
    for rva, label in SEED_FUNCTIONS.items():
        to_decompile[IMAGE_BASE + rva] = label

    # Chase callees
    visited = set()
    for depth in range(MAX_DEPTH):
        new_targets = OrderedDict()
        for offset, label in list(to_decompile.items()):
            if offset in visited:
                continue
            visited.add(offset)

            func = func_mgr.getFunctionAt(toAddr(offset))
            if not func:
                continue

            callees = get_callees(func)
            for callee_off in sorted(callees):
                if callee_off not in to_decompile and callee_off not in new_targets:
                    callee_func = func_mgr.getFunctionAt(toAddr(callee_off))
                    if callee_func:
                        fsize = callee_func.getBody().getNumAddresses()
                        # Skip tiny thunks and huge library functions
                        if 4 < fsize < 5000:
                            rva = callee_off - IMAGE_BASE
                            new_targets[callee_off] = "callee_d%d (RVA 0x%x, %db, called by %s)" % (
                                depth + 1, rva, fsize, label.split(" ")[0])

        to_decompile.update(new_targets)
        if len(to_decompile) >= MAX_FUNCTIONS:
            break

    print("Will decompile %d functions" % len(to_decompile))

    # Decompile all
    results = []
    for offset, label in to_decompile.items():
        func = func_mgr.getFunctionAt(toAddr(offset))
        if not func:
            print("  SKIP %s: no function at 0x%x" % (label, offset))
            continue

        fsize = func.getBody().getNumAddresses()
        rva = offset - IMAGE_BASE
        code = decompile_func(decomp, func, monitor)

        if code:
            print("  OK  0x%x (%d bytes) %s" % (rva, fsize, label))
        else:
            code = "/* decompilation failed */"
            print("  FAIL 0x%x %s" % (rva, label))

        results.append((offset, rva, fsize, label, code))

    decomp.dispose()

    # Write output
    out_path = os.path.join(output_dir, "win_ammo_decompiled.c")
    with open(out_path, "w") as f:
        f.write("/*\n")
        f.write(" * Windows server.dll — Ammo/Magazine system decompilation\n")
        f.write(" * %d functions decompiled\n" % len(results))
        f.write(" */\n\n")

        for offset, rva, fsize, label, code in results:
            f.write("/* " + "=" * 66 + "\n")
            f.write(" * %s\n" % label)
            f.write(" * Address: 0x%08x  RVA: 0x%06x  Size: %d bytes\n" % (offset, rva, fsize))
            f.write(" * " + "=" * 66 + " */\n")
            f.write(code)
            f.write("\n\n")

    print("\nWrote %s (%d functions)" % (out_path, len(results)))

main()
