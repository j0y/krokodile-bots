# -*- coding: utf-8 -*-
# Ghidra postScript: Decompile bot AI functions from server_srv.so
# Usage: analyzeHeadless ... -postScript ghidra_decompile_bots.py /output/dir
#
# Iterates all functions, filters bot-related classes, decompiles each,
# and writes per-class .c files + _index.md summary.
#
# @category Insurgency
# @author SmartBots project

import os
import re
import sys
import time
from collections import defaultdict, OrderedDict

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

# --- Configuration ---

# Function name prefixes to include
INCLUDE_PREFIXES = (
    "CINSBot",
    "CINSNextBot",
    "CINSNavArea",
    "CINSPathCost",
)

# Template-based action/behavior classes (demangled names contain these)
INCLUDE_TEMPLATES = (
    "Action<CINSNextBot>",
    "Behavior<CINSNextBot>",
)

# Substrings to exclude (noise)
EXCLUDE_SUBSTRINGS = (
    "non-virtual thunk",
    "CUtlVector",
    "CUtlMemory",
    "CUtlMap",
    "CUtlRBTree",
    "CUtlString",
    "CUtlBuffer",
    "NavAreaBuildPath",
    "BotStatement",
    "CUtlLinkedList",
    "CUtlHash",
    "CUtlFixedLinkedList",
    "CUtlSymbolTable",
    "KeyValues",
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

# Lifecycle methods that should appear first in output
LIFECYCLE_ORDER = [
    "OnStart",
    "InitialContainedAction",
    "Update",
    "OnEnd",
    "OnSuspend",
    "OnResume",
    "GetName",
    "ShouldHurry",
    "IsAbleToAndShouldRetreat",
    "ShouldRetreat",
    "ShouldAttack",
    "OnContact",
    "OnMoveToSuccess",
    "OnMoveToFailure",
    "OnStuck",
    "OnUnStuck",
    "OnInjured",
    "OnKilled",
    "OnOtherKilled",
    "OnSight",
    "OnLostSight",
    "OnSound",
    "OnWeaponFired",
    "OnEnteredSite",
    "OnExitedSite",
    "OnPickUp",
    "OnDrop",
    "OnCommandApproach",
    "OnCommandString",
    "QueryCurrentPath",
    "SelectMoreDangerousThreat",
    "IsHindrance",
    "ShouldPickUp",
]

# Decompile timeout per function (seconds)
DECOMPILE_TIMEOUT = 60


def should_include(func_name):
    """Check if a function name matches our bot AI filter."""
    # Exclude noise first
    for excl in EXCLUDE_SUBSTRINGS:
        if excl in func_name:
            return False

    # Include by prefix
    for prefix in INCLUDE_PREFIXES:
        if func_name.startswith(prefix):
            return True

    # Include template-based action/behavior methods
    for tmpl in INCLUDE_TEMPLATES:
        if tmpl in func_name:
            return True

    return False


def extract_class_name(func_name):
    """Extract the class name from a demangled function name.

    Examples:
      CINSBotCombat::Update(CINSNextBot*) -> CINSBotCombat
      Action<CINSNextBot>::InvokeOnStart -> Action_CINSNextBot
      CINSNextBot::GetIntentionInterface -> CINSNextBot
    """
    # Handle namespaced names: Class::Method(...)
    if "::" in func_name:
        cls = func_name.split("::")[0]
    else:
        cls = func_name

    # Clean up template parameters for filename
    cls = cls.strip()

    # Handle templates: Action<CINSNextBot> -> Action_CINSNextBot
    cls = cls.replace("<", "_").replace(">", "").replace(" ", "")
    cls = cls.replace(",", "_")

    return cls


def extract_method_name(func_name):
    """Extract just the method name from a demangled function name."""
    if "::" not in func_name:
        return func_name
    method = func_name.split("::")[-1]
    # Remove parameters
    paren = method.find("(")
    if paren > 0:
        method = method[:paren]
    return method.strip()


def lifecycle_sort_key(method_name):
    """Sort key that puts lifecycle methods first, in canonical order."""
    try:
        idx = LIFECYCLE_ORDER.index(method_name)
        return (0, idx, method_name)
    except ValueError:
        # Constructor comes before lifecycle
        if method_name.startswith("CINSBot") or method_name.startswith("CINSNextBot"):
            return (0, -1, method_name)
        # Everything else alphabetically after lifecycle
        return (1, 0, method_name)


def main():
    args = getScriptArgs()
    if not args:
        print("ERROR: No output directory specified.")
        print("Usage: -postScript ghidra_decompile_bots.py /output/dir")
        return

    output_dir = args[0]
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    print("=" * 60)
    print("Ghidra Bot AI Decompiler")
    print("=" * 60)

    monitor = ConsoleTaskMonitor()
    program = currentProgram
    func_mgr = program.getFunctionManager()

    # Set up decompiler
    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(program)

    # Collect all bot functions
    print("\nScanning functions...")
    bot_functions = []  # (func, demangled_name, class_name, method_name)
    total_funcs = func_mgr.getFunctionCount()
    scanned = 0

    for func in func_mgr.getFunctions(True):
        scanned += 1
        if scanned % 5000 == 0:
            print("  Scanned %d / %d functions..." % (scanned, total_funcs))

        name = func.getName()
        # Try to get demangled name
        sig = func.getSignature()
        demangled = sig.getPrototypeString() if sig else name

        # Use the symbol's demangled name if available
        sym = func.getSymbol()
        if sym:
            # getParentNamespace gives us the class
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
            bot_functions.append((func, full_name, cls, method))

    print("\nFound %d bot AI functions across scan of %d total" % (
        len(bot_functions), scanned))

    # Group by class
    by_class = defaultdict(list)
    for func, full_name, cls, method in bot_functions:
        by_class[cls].append((func, full_name, method))

    print("Grouped into %d classes" % len(by_class))

    # Decompile all functions
    print("\nDecompiling...")
    results = {}  # class -> [(method, full_name, addr, decompiled_c)]
    failed = []
    decompiled_count = 0
    start_time = time.time()

    for cls in sorted(by_class.keys()):
        funcs = by_class[cls]
        class_results = []

        for func, full_name, method in funcs:
            addr = func.getEntryPoint()

            try:
                decomp_result = decomp.decompileFunction(
                    func, DECOMPILE_TIMEOUT, monitor)

                if decomp_result and decomp_result.decompileCompleted():
                    dec_func = decomp_result.getDecompiledFunction()
                    if dec_func:
                        c_code = dec_func.getC()
                        class_results.append((method, full_name, str(addr), c_code))
                        decompiled_count += 1
                    else:
                        class_results.append((method, full_name, str(addr),
                            "/* DECOMPILE COMPLETED BUT NO OUTPUT */\n"))
                        failed.append((full_name, "completed but no output"))
                elif decomp_result and decomp_result.getErrorMessage():
                    err = decomp_result.getErrorMessage()
                    class_results.append((method, full_name, str(addr),
                        "/* DECOMPILE ERROR: %s */\n" % err))
                    failed.append((full_name, err))
                else:
                    class_results.append((method, full_name, str(addr),
                        "/* DECOMPILE FAILED: no result */\n"))
                    failed.append((full_name, "no result"))
            except Exception as e:
                class_results.append((method, full_name, str(addr),
                    "/* DECOMPILE EXCEPTION: %s */\n" % str(e)))
                failed.append((full_name, str(e)))

            if (decompiled_count + len(failed)) % 100 == 0:
                elapsed = time.time() - start_time
                total_done = decompiled_count + len(failed)
                rate = total_done / elapsed if elapsed > 0 else 0
                remaining = len(bot_functions) - total_done
                eta = remaining / rate if rate > 0 else 0
                print("  %d/%d done (%.1f/s, ETA %.0fs) - %d failed" % (
                    total_done, len(bot_functions), rate, eta, len(failed)))

        results[cls] = class_results

    elapsed = time.time() - start_time
    print("\nDecompilation complete: %d succeeded, %d failed in %.1fs" % (
        decompiled_count, len(failed), elapsed))

    # Write per-class .c files
    print("\nWriting output files...")
    class_stats = []  # (class_name, func_count, file_name)

    for cls in sorted(results.keys()):
        funcs = results[cls]
        if not funcs:
            continue

        # Sort: lifecycle methods first, then alphabetical
        funcs.sort(key=lambda x: lifecycle_sort_key(x[0]))

        file_name = cls + ".c"
        file_path = os.path.join(output_dir, file_name)

        with open(file_path, "w") as f:
            f.write("/*\n")
            f.write(" * %s -- Decompiled bot AI functions\n" % cls)
            f.write(" * Source: server_srv.so (Insurgency 2014)\n")
            f.write(" * Decompiled by Ghidra %s\n" % str(
                program.getMetadata().get("Created With", "unknown")))
            f.write(" * Functions: %d\n" % len(funcs))
            f.write(" */\n\n")

            for method, full_name, addr, c_code in funcs:
                f.write("/* ----------------------------------------\n")
                f.write(" * %s\n" % full_name)
                f.write(" * Address: %s\n" % addr)
                f.write(" * ---------------------------------------- */\n")
                f.write(c_code)
                f.write("\n\n")

        class_stats.append((cls, len(funcs), file_name))
        print("  Wrote %s (%d functions)" % (file_name, len(funcs)))

    # Write index
    index_path = os.path.join(output_dir, "_index.md")
    with open(index_path, "w") as f:
        f.write("# Decompiled Bot AI -- Index\n\n")
        f.write("Source: `server_srv.so` (Insurgency 2014, 32-bit x86)\n\n")
        f.write("| Class | Functions | File |\n")
        f.write("|-------|-----------|------|\n")

        total_funcs_written = 0
        for cls, count, fname in sorted(class_stats):
            f.write("| %s | %d | [%s](%s) |\n" % (cls, count, fname, fname))
            total_funcs_written += count

        f.write("\n**Total: %d functions across %d classes**\n" % (
            total_funcs_written, len(class_stats)))

        if failed:
            f.write("\n## Failed Decompilations (%d)\n\n" % len(failed))
            for func_name, err in sorted(failed):
                f.write("- `%s`: %s\n" % (func_name, err))

    print("\nWrote %s" % index_path)
    print("\nDone! %d classes, %d functions written to %s" % (
        len(class_stats), sum(c for _, c, _ in class_stats), output_dir))

    decomp.dispose()


main()
