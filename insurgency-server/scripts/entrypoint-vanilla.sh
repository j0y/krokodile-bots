#!/bin/bash
set -e

SERVER_DIR="/home/steam/insurgency-server"
GAME_DIR="${SERVER_DIR}/insurgency"

echo "=============================================="
echo " Insurgency 2014 - VANILLA TEST SERVER"
echo "=============================================="

# Disable MetaMod/SourceMod by renaming the addons loader
if [ -f "${GAME_DIR}/addons/metamod.vdf" ]; then
    echo "[*] Disabling MetaMod for vanilla test..."
    mv "${GAME_DIR}/addons/metamod.vdf" "${GAME_DIR}/addons/metamod.vdf.disabled"
fi

# Minimal server.cfg - no cheats, no mods
cat > "${GAME_DIR}/cfg/server.cfg" << 'EOF'
hostname "Vanilla Test Server"
sv_lan 1
EOF

echo "[*] Starting vanilla server..."

cd "${SERVER_DIR}"
export LD_LIBRARY_PATH="${SERVER_DIR}:${SERVER_DIR}/bin:${LD_LIBRARY_PATH}"
exec ./srcds_linux \
    -game insurgency \
    -console \
    -32bit \
    -port 27015 \
    +sv_lan 1 \
    -insecure \
    +map ministry_coop \
    +maxplayers 32 \
    -tickrate 64 \
    -sv_playlist coop
