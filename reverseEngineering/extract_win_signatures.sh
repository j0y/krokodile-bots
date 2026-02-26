#!/usr/bin/env bash
# Extract Windows byte signatures from server.dll using Ghidra headless analysis.
#
# First run: imports binary + full auto-analysis (~10-15 min for 7MB DLL) + extract
# Re-runs:   skips analysis, only re-runs extraction script (~2 min)
#
# Usage: ./reverseEngineering/extract_win_signatures.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$REPO_ROOT/reverseengeneer/server.dll"
GHIDRA_SCRIPT="$SCRIPT_DIR/scripts/ghidra_extract_win_signatures.py"
OUTPUT_DIR="$SCRIPT_DIR/win_signatures"
PROJECT_DIR="$SCRIPT_DIR/.ghidra_project_win"

PROJECT_NAME="insurgency_server_win"
GHIDRA_IMAGE="blacktop/ghidra:11.3"
MAXMEM="6G"
DOCKER_USER="$(id -u):$(id -g)"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    echo "Download it first (Windows server.dll from Insurgency dedicated server)"
    exit 1
fi

if [ ! -f "$GHIDRA_SCRIPT" ]; then
    echo "ERROR: Ghidra script not found: $GHIDRA_SCRIPT"
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$PROJECT_DIR"

echo "=========================================="
echo "Windows server.dll Signature Extraction"
echo "=========================================="
echo "Binary:  $BINARY ($(du -h "$BINARY" | cut -f1))"
echo "Script:  $GHIDRA_SCRIPT"
echo "Output:  $OUTPUT_DIR"
echo "Project: $PROJECT_DIR"
echo ""

if [ -d "$PROJECT_DIR/${PROJECT_NAME}.rep" ]; then
    echo "Existing Ghidra project found — skipping import & analysis."
    echo "Will re-run extraction script only (~2 min)."
    echo "(Delete $PROJECT_DIR to force re-analysis)"
    echo ""

    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server.dll:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_extract_win_signatures.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -process server.dll \
        -noanalysis \
        -scriptPath /scripts \
        -postScript ghidra_extract_win_signatures.py /output
else
    echo "No existing project — will import binary and run full analysis."
    echo "This will take ~10-15 minutes for a 7MB PE, then extraction."
    echo ""

    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server.dll:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_extract_win_signatures.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -import /input/server.dll \
        -processor x86:LE:32:default \
        -cspec windows \
        -scriptPath /scripts \
        -postScript ghidra_extract_win_signatures.py /output
fi

echo ""
echo "=========================================="
echo "Done!"
echo "=========================================="

if [ -f "$OUTPUT_DIR/win_signatures_report.txt" ]; then
    echo ""
    echo "Report: $OUTPUT_DIR/win_signatures_report.txt"
    echo "Gamedata: $OUTPUT_DIR/win_signatures_gamedata.txt"
    echo ""
    echo "--- Gamedata snippet ---"
    cat "$OUTPUT_DIR/win_signatures_gamedata.txt"
else
    echo ""
    echo "WARNING: No output files found — extraction may have failed."
    echo "Check the Ghidra output above for errors."
fi
