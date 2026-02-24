# -*- coding: utf-8 -*-
# Ghidra postScript: Decompile ammo, magazine, and reload functions from server_srv.so
# Usage: analyzeHeadless ... -postScript ghidra_decompile_ammo.py /output/dir
#
# Targets weapon reload, magazine management, ammo transfer, and resupply functions.
#
# @category Insurgency
# @author SmartBots project

import os
import re
import time
from collections import defaultdict

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

# --- Configuration ---

# Function name prefixes/patterns to include
INCLUDE_PREFIXES = (
    "CINSWeaponMagazines",
    "CINSWeaponBallistic",
    "CAmmoDef",
)

# Specific class::method patterns (class name must match, method is substring-checked)
INCLUDE_CLASS_METHODS = {
    "CINSWeapon": (
        "Reload", "FinishReload", "GetMagazineCapacity", "GetMaxClip1",
        "ShouldLoseAmmoOnReload", "GiveDefaultAmmo", "DecrementAmmo",
        "IsEmpty", "HasAmmo", "ChamberRound", "UseChamberRound",
        "HasChamberedRound", "CheckReload", "GetPrimaryAmmoType",
        "IsSingleReload", "CanReload", "Ammo",
    ),
    "CINSPlayer": (
        "Resupply", "GetMagazines", "GetAmmoCount", "SetAmmoCount",
        "GiveAmmo", "RemoveAmmo", "Weapon_Equip",
    ),
    "CBaseCombatWeapon": (
        "Reload", "FinishReload", "GiveAmmo", "DefaultReload",
        "HasAmmo", "HasPrimaryAmmo", "HasSecondaryAmmo",
        "UsesClipsForAmmo", "GetMaxClip",
    ),
    "CBaseCombatCharacter": (
        "GiveAmmo", "RemoveAmmo", "GetAmmoCount", "SetAmmoCount",
        "Weapon_Equip", "Weapon_EquipAmmoOnly",
    ),
    "CBasePlayer": (
        "GiveAmmo", "RemoveAmmo", "GetAmmoCount", "SetAmmoCount",
    ),
}

# Substrings to exclude (noise)
EXCLUDE_SUBSTRINGS = (
    "non-virtual thunk",
    "CUtlVector",
    "CUtlMemory",
    "operator new",
    "operator delete",
    "__cxa_",
    "__gnu_cxx",
    "std::",
    "typeinfo",
    "vtable for",
    "VTable for",
    "guard variable",
    "GCC_except_table",
)

DECOMPILE_TIMEOUT = 120


def should_include(full_name):
    """Check if a function name matches our ammo/reload filter."""
    for excl in EXCLUDE_SUBSTRINGS:
        if excl in full_name:
            return False

    # Include by prefix (entire class)
    for prefix in INCLUDE_PREFIXES:
        if full_name.startswith(prefix):
            return True

    # Include specific class::method combinations
    if "::" in full_name:
        cls_part = full_name.split("::")[0].strip()
        method_part = full_name.split("::")[-1].strip()
        # Remove params from method
        paren = method_part.find("(")
        if paren > 0:
            method_part = method_part[:paren]

        if cls_part in INCLUDE_CLASS_METHODS:
            allowed_methods = INCLUDE_CLASS_METHODS[cls_part]
            for m in allowed_methods:
                if m in method_part:
                    return True

    return False


def extract_class_name(func_name):
    if "::" in func_name:
        cls = func_name.split("::")[0].strip()
    else:
        cls = func_name
    cls = cls.replace("<", "_").replace(">", "").replace(" ", "").replace(",", "_")
    return cls


def extract_method_name(func_name):
    if "::" not in func_name:
        return func_name
    method = func_name.split("::")[-1]
    paren = method.find("(")
    if paren > 0:
        method = method[:paren]
    return method.strip()


def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: No output directory specified.")
        print("Usage: -postScript ghidra_decompile_ammo.py /output/dir")
        return

    output_dir = args[0]
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    print("=" * 60)
    print("Ghidra Ammo/Reload Decompiler")
    print("=" * 60)

    monitor = ConsoleTaskMonitor()
    program = currentProgram
    func_mgr = program.getFunctionManager()

    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(program)

    # Collect matching functions
    print("\nScanning functions...")
    target_functions = []
    total_funcs = func_mgr.getFunctionCount()
    scanned = 0

    for func in func_mgr.getFunctions(True):
        scanned += 1
        if scanned % 10000 == 0:
            print("  Scanned %d / %d functions..." % (scanned, total_funcs))

        name = func.getName()
        sym = func.getSymbol()
        if sym:
            ns = sym.getParentNamespace()
            if ns and ns.getName() != "Global":
                full_name = ns.getName() + "::" + name
            else:
                full_name = name
        else:
            full_name = name

        if should_include(full_name):
            cls = extract_class_name(full_name)
            method = extract_method_name(full_name)
            target_functions.append((func, full_name, cls, method))

    print("\nFound %d ammo/reload functions out of %d total" % (
        len(target_functions), scanned))

    # Group by class
    by_class = defaultdict(list)
    for func, full_name, cls, method in target_functions:
        by_class[cls].append((func, full_name, method))

    print("Grouped into %d classes:" % len(by_class))
    for cls in sorted(by_class.keys()):
        print("  %s: %d functions" % (cls, len(by_class[cls])))

    # Decompile
    print("\nDecompiling...")
    results = {}
    failed = []
    decompiled_count = 0
    start_time = time.time()

    for cls in sorted(by_class.keys()):
        funcs = by_class[cls]
        class_results = []

        for func, full_name, method in funcs:
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()

            try:
                decomp_result = decomp.decompileFunction(
                    func, DECOMPILE_TIMEOUT, monitor)

                if decomp_result and decomp_result.decompileCompleted():
                    dec_func = decomp_result.getDecompiledFunction()
                    if dec_func:
                        c_code = dec_func.getC()
                        class_results.append((method, full_name, str(addr), size, c_code))
                        decompiled_count += 1
                    else:
                        class_results.append((method, full_name, str(addr), size,
                            "/* DECOMPILE COMPLETED BUT NO OUTPUT */\n"))
                        failed.append((full_name, "completed but no output"))
                elif decomp_result and decomp_result.getErrorMessage():
                    err = decomp_result.getErrorMessage()
                    class_results.append((method, full_name, str(addr), size,
                        "/* DECOMPILE ERROR: %s */\n" % err))
                    failed.append((full_name, err))
                else:
                    class_results.append((method, full_name, str(addr), size,
                        "/* DECOMPILE FAILED: no result */\n"))
                    failed.append((full_name, "no result"))
            except Exception as e:
                class_results.append((method, full_name, str(addr), size,
                    "/* DECOMPILE EXCEPTION: %s */\n" % str(e)))
                failed.append((full_name, str(e)))

        results[cls] = class_results
        print("  %s: %d functions decompiled" % (cls, len(class_results)))

    elapsed = time.time() - start_time
    print("\nDecompilation complete: %d succeeded, %d failed in %.1fs" % (
        decompiled_count, len(failed), elapsed))

    # Write per-class .c files
    print("\nWriting output files...")
    class_stats = []

    for cls in sorted(results.keys()):
        funcs = results[cls]
        if not funcs:
            continue

        # Sort alphabetically by method name
        funcs.sort(key=lambda x: x[0].lower())

        file_name = cls + ".c"
        file_path = os.path.join(output_dir, file_name)

        with open(file_path, "w") as f:
            f.write("/*\n")
            f.write(" * %s -- Decompiled ammo/reload functions\n" % cls)
            f.write(" * Source: server_srv.so (Insurgency 2014)\n")
            f.write(" * Decompiled by Ghidra %s\n" % str(
                program.getMetadata().get("Created With", "unknown")))
            f.write(" * Functions: %d\n" % len(funcs))
            f.write(" */\n\n")

            for method, full_name, addr, size, c_code in funcs:
                f.write("/* ----------------------------------------\n")
                f.write(" * %s\n" % full_name)
                f.write(" * Address: %s  Size: %d bytes\n" % (addr, size))
                f.write(" * ---------------------------------------- */\n")
                f.write(c_code)
                f.write("\n\n")

        class_stats.append((cls, len(funcs), file_name))
        print("  Wrote %s (%d functions)" % (file_name, len(funcs)))

    # Write index
    index_path = os.path.join(output_dir, "_ammo_index.md")
    with open(index_path, "w") as f:
        f.write("# Decompiled Ammo/Reload System -- Index\n\n")
        f.write("Source: `server_srv.so` (Insurgency 2014, 32-bit x86)\n\n")
        f.write("| Class | Functions | File |\n")
        f.write("|-------|-----------|------|\n")

        total_written = 0
        for cls, count, fname in sorted(class_stats):
            f.write("| %s | %d | [%s](%s) |\n" % (cls, count, fname, fname))
            total_written += count

        f.write("\n**Total: %d functions across %d classes**\n" % (
            total_written, len(class_stats)))

        # Function listing
        f.write("\n## All Functions\n\n")
        for cls in sorted(results.keys()):
            for method, full_name, addr, size, c_code in results[cls]:
                status = "ok" if "DECOMPILE" not in c_code[:50] else "FAILED"
                f.write("- `%s` @ %s (%d bytes) [%s]\n" % (full_name, addr, size, status))

        if failed:
            f.write("\n## Failed Decompilations (%d)\n\n" % len(failed))
            for func_name, err in sorted(failed):
                f.write("- `%s`: %s\n" % (func_name, err))

    print("\nWrote %s" % index_path)
    print("\nDone! %d classes, %d functions written to %s" % (
        len(class_stats), sum(c for _, c, _ in class_stats), output_dir))

    decomp.dispose()


main()
