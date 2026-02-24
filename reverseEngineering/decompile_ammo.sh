#!/usr/bin/env bash
# Decompile ammo/reload/magazine functions from server_srv.so using Ghidra headless.
#
# First run: imports binary + full auto-analysis (~20 min) + decompile
# Re-runs:   skips analysis, only re-runs decompile script (~2 min)
#
# Usage: ./reverseEngineering/decompile_ammo.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$REPO_ROOT/reverseengeneer/ins_server_files/ins/insurgency/bin/server_srv.so"
GHIDRA_SCRIPT="$SCRIPT_DIR/scripts/ghidra_decompile_ammo.py"
OUTPUT_DIR="$SCRIPT_DIR/decompiled"
PROJECT_DIR="$SCRIPT_DIR/.ghidra_project"

PROJECT_NAME="insurgency_server"
GHIDRA_IMAGE="blacktop/ghidra:11.3"
MAXMEM="6G"
DOCKER_USER="$(id -u):$(id -g)"

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    exit 1
fi

# Verify script exists
if [ ! -f "$GHIDRA_SCRIPT" ]; then
    echo "ERROR: Ghidra script not found: $GHIDRA_SCRIPT"
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$PROJECT_DIR"

echo "=========================================="
echo "Ghidra Headless Ammo/Reload Decompilation"
echo "=========================================="
echo "Binary:  $BINARY ($(du -h "$BINARY" | cut -f1))"
echo "Script:  $GHIDRA_SCRIPT"
echo "Output:  $OUTPUT_DIR"
echo "Project: $PROJECT_DIR"
echo ""

# Check if Ghidra project already exists (analysis was done before)
if [ -d "$PROJECT_DIR/${PROJECT_NAME}.rep" ]; then
    echo "Existing Ghidra project found — skipping import & analysis."
    echo "Will re-run decompile script only."
    echo ""

    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server_srv.so:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_decompile_ammo.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -process server_srv.so \
        -noanalysis \
        -scriptPath /scripts \
        -postScript ghidra_decompile_ammo.py /output
else
    echo "No existing project — will import binary and run full analysis."
    echo "This will take ~20 minutes for import+analysis, then ~2 min for decompilation."
    echo ""

    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server_srv.so:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_decompile_ammo.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -import /input/server_srv.so \
        -processor x86:LE:32:default \
        -scriptPath /scripts \
        -postScript ghidra_decompile_ammo.py /output
fi

echo ""
echo "=========================================="
echo "Done!"
echo "=========================================="

if [ -f "$OUTPUT_DIR/_ammo_index.md" ]; then
    echo ""
    cat "$OUTPUT_DIR/_ammo_index.md"
else
    echo ""
    echo "WARNING: No _ammo_index.md found — decompilation may have failed."
fi
