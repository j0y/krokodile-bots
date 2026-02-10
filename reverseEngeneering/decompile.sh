#!/usr/bin/env bash
# Decompile bot AI functions from server_srv.so using Ghidra headless.
#
# First run: imports binary + full auto-analysis (15-25 min) + decompile
# Re-runs:   skips analysis, only re-runs decompile script (15-25 min)
#
# Usage: ./reverseEngeneering/decompile.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$REPO_ROOT/insurgency-server/server-files/insurgency/bin/server_srv.so"
GHIDRA_SCRIPT="$SCRIPT_DIR/scripts/ghidra_decompile_bots.py"
OUTPUT_DIR="$SCRIPT_DIR/decompiled"
PROJECT_DIR="$SCRIPT_DIR/.ghidra_project"

PROJECT_NAME="insurgency_server"
GHIDRA_IMAGE="blacktop/ghidra:11.3"
MAXMEM="6G"
DOCKER_USER="$(id -u):$(id -g)"

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    echo "Make sure the game server files are present."
    exit 1
fi

# Verify script exists
if [ ! -f "$GHIDRA_SCRIPT" ]; then
    echo "ERROR: Ghidra script not found: $GHIDRA_SCRIPT"
    exit 1
fi

# Create directories
mkdir -p "$OUTPUT_DIR" "$PROJECT_DIR"

echo "=========================================="
echo "Ghidra Headless Bot AI Decompilation"
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

    # Re-run: process existing project, skip analysis
    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server_srv.so:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_decompile_bots.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -process server_srv.so \
        -noanalysis \
        -scriptPath /scripts \
        -postScript ghidra_decompile_bots.py /output
else
    echo "No existing project — will import binary and run full analysis."
    echo "This will take 15-25 minutes for import+analysis, then 15-25 min for decompilation."
    echo ""

    # First run: import + full analysis + decompile
    docker run --rm \
        --memory=8g \
        --user "$DOCKER_USER" \
        --entrypoint /ghidra/support/analyzeHeadless \
        -e MAXMEM="$MAXMEM" \
        -v "$BINARY:/input/server_srv.so:ro" \
        -v "$GHIDRA_SCRIPT:/scripts/ghidra_decompile_bots.py:ro" \
        -v "$OUTPUT_DIR:/output" \
        -v "$PROJECT_DIR:/project" \
        "$GHIDRA_IMAGE" \
        /project "$PROJECT_NAME" \
        -import /input/server_srv.so \
        -processor x86:LE:32:default \
        -scriptPath /scripts \
        -postScript ghidra_decompile_bots.py /output
fi

echo ""
echo "=========================================="
echo "Done!"
echo "=========================================="

# Show results summary
if [ -f "$OUTPUT_DIR/_index.md" ]; then
    echo ""
    echo "Index: $OUTPUT_DIR/_index.md"
    CLASS_COUNT=$(grep -c '\.c)' "$OUTPUT_DIR/_index.md" 2>/dev/null || echo "?")
    C_FILES=$(find "$OUTPUT_DIR" -name "*.c" | wc -l)
    echo "Classes: $CLASS_COUNT"
    echo "Files:   $C_FILES .c files"
else
    echo ""
    echo "WARNING: No _index.md found — decompilation may have failed."
    echo "Check the Docker output above for errors."
fi
