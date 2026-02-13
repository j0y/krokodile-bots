# Decompilation Scripts

## Pipeline

First run Ghidra headless decompilation, then the annotation scripts in order:

```bash
# 1. Decompile (from repo root) — first run takes ~30-50 min, re-runs skip analysis
./reverseEngineering/decompile.sh

# 2. Resolve PIC GOT-relative references (strings, symbols)
python3 reverseEngineering/scripts/resolve_pic_refs.py

# 3. Replace misleading .rodata PIC annotations with actual float values
python3 reverseEngineering/scripts/annotate_rodata_floats.py

# 4. Annotate vtable dispatches with method names
python3 reverseEngineering/scripts/annotate_vtable.py

# 5. Annotate IEEE 754 float constants in hex literals
python3 reverseEngineering/scripts/annotate_floats.py

# 6. Annotate ActionResult type codes (Continue/ChangeTo/SuspendFor/Done)
python3 reverseEngineering/scripts/annotate_actionresult.py

# 7. Annotate CountdownTimer patterns (IsElapsed, Start, Invalidate)
python3 reverseEngineering/scripts/annotate_timers.py
```

Order matters: `resolve_pic_refs` must run first. `annotate_rodata_floats` must run before `annotate_vtable` since both replace PIC annotations — rodata_floats handles float constants, then vtable replaces remaining PIC annotations on vtable dispatches.

## Analysis Scripts (Ghidra postScripts)

These run inside Ghidra via `decompile.sh` and are not part of the post-processing pipeline:

- `ghidra_decompile_bots.py` — decompile bot AI functions to per-class .c files
- `extract_string_xrefs.py` — extract string cross-references per class
- `extract_transitions.py` — extract action transition graph
- `extract_class_layouts.py` — extract class data layouts
