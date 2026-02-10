# Decompilation Scripts

## Pipeline

First run Ghidra headless decompilation, then the annotation scripts in order:

```bash
# 1. Decompile (from repo root) — first run takes ~30-50 min, re-runs skip analysis
./reverseEngeneering/decompile.sh

# 2. Resolve PIC GOT-relative references (strings, symbols)
python3 reverseEngeneering/scripts/resolve_pic_refs.py

# 3. Annotate vtable dispatches with method names
python3 reverseEngeneering/scripts/annotate_vtable.py

# 4. Annotate IEEE 754 float constants
python3 reverseEngeneering/scripts/annotate_floats.py

# 5. Annotate ActionResult type codes (Continue/ChangeTo/SuspendFor/Done)
python3 reverseEngeneering/scripts/annotate_actionresult.py
```

Order matters: `resolve_pic_refs` must run first since `annotate_vtable` can replace its annotations on vtable dispatches.

## Analysis Scripts (Ghidra postScripts)

These run inside Ghidra via `decompile.sh` and are not part of the post-processing pipeline:

- `ghidra_decompile_bots.py` — decompile bot AI functions to per-class .c files
- `extract_string_xrefs.py` — extract string cross-references per class
- `extract_transitions.py` — extract action transition graph
- `extract_class_layouts.py` — extract class data layouts
