#!/bin/bash
set -e

SERVER_DIR="/home/steam/insurgency-server"
GAME_DIR="${SERVER_DIR}/insurgency"

# ============================================================
# Default environment variables
# ============================================================
SERVER_HOSTNAME="${SERVER_HOSTNAME:-Insurgency Smart Bots Dev Server}"
SERVER_PASSWORD="${SERVER_PASSWORD:-}"
RCON_PASSWORD="${RCON_PASSWORD:-changeme}"
MAX_PLAYERS="${MAX_PLAYERS:-32}"
START_MAP="${START_MAP:-ministry_coop}"
GAME_MODE="${GAME_MODE:-coop}"
TICKRATE="${TICKRATE:-64}"
AI_HOST="${AI_HOST:-127.0.0.1}"

echo "=============================================="
echo " Insurgency 2014 Dedicated Server"
echo " with SourceMod + NavBot"
echo "=============================================="

# ============================================================
# Generate server.cfg from environment variables
# ============================================================
echo "[*] Writing server.cfg..."
cat > "${GAME_DIR}/cfg/server.cfg" << EOF
// ---------------------------------------------------------------
// Server Info
// ---------------------------------------------------------------
hostname "${SERVER_HOSTNAME}"
rcon_password "${RCON_PASSWORD}"
sv_password "${SERVER_PASSWORD}"

// ---------------------------------------------------------------
// Network
// ---------------------------------------------------------------
sv_minrate 30000
sv_maxrate 0
sv_minupdaterate 20
sv_maxupdaterate ${TICKRATE}
sv_mincmdrate 20
sv_maxcmdrate ${TICKRATE}

// ---------------------------------------------------------------
// Logging
// ---------------------------------------------------------------
log on
sv_logbans 1
sv_logecho 1
sv_logfile 1
sv_log_onefile 0

// ---------------------------------------------------------------
// Bot Configuration (better defaults)
// Bot cvars are cheat-protected, sv_cheats required
// ---------------------------------------------------------------
sv_cheats 1
mp_limitteams 0
mp_autoteambalance 0
exec betterbots.cfg
$([ "${NB_DEBUG:-0}" = "1" ] && echo "exec nbdebug.cfg" || echo "// nbdebug.cfg disabled (NB_DEBUG!=1)")

// ---------------------------------------------------------------
// Round Timers (low for faster debugging)
// ---------------------------------------------------------------
mp_timer_pregame 3
mp_timer_preround 3
mp_timer_preround_first 3
mp_timer_postround 3


// ---------------------------------------------------------------
// SourceMod
// ---------------------------------------------------------------
// sv_pure 0 required for SourceMod/MetaMod
sv_pure 0
EOF

# ============================================================
# Custom plugins (mounted at plugins/custom/, SM auto-loads subdirs)
# ============================================================
if [ -d "${GAME_DIR}/addons/sourcemod/plugins/custom" ]; then
    echo "[*] Custom plugins detected (auto-loaded by SM from plugins/custom/):"
    ls -1 "${GAME_DIR}/addons/sourcemod/plugins/custom/"*.smx 2>/dev/null || echo "    (none)"
fi

# ============================================================
# Copy custom configs if mounted
# ============================================================
if [ -d "${GAME_DIR}/cfg/custom" ]; then
    echo "[*] Copying custom configs..."
    cp -f "${GAME_DIR}/cfg/custom/"*.cfg "${GAME_DIR}/cfg/" 2>/dev/null || true
fi

# ============================================================
# Verify MetaMod/SourceMod installation
# ============================================================
echo ""
echo "[*] MetaMod/SourceMod verification:"

if [ -f "${GAME_DIR}/addons/metamod.vdf" ]; then
    echo "[+] metamod.vdf found"
    echo "    $(cat "${GAME_DIR}/addons/metamod.vdf" | tr -d '\n')"
else
    echo "[!] WARNING: metamod.vdf not found!"
fi

if [ -f "${GAME_DIR}/addons/metamod/bin/metamod.2.insurgency.so" ]; then
    echo "[+] metamod.2.insurgency.so present"
else
    echo "[!] WARNING: metamod.2.insurgency.so missing!"
fi

if [ -f "${GAME_DIR}/addons/metamod/bin/server_srv.so" ]; then
    echo "[+] MetaMod stub server_srv.so present"
else
    echo "[!] WARNING: MetaMod stub server_srv.so missing!"
fi

if grep -q "addons/metamod/bin" "${GAME_DIR}/gameinfo.txt" 2>/dev/null; then
    echo "[+] gameinfo.txt has MetaMod GameBin entry"
else
    echo "[!] WARNING: gameinfo.txt not patched for MetaMod!"
fi

if [ -f "${GAME_DIR}/addons/metamod/sourcemod.vdf" ]; then
    echo "[+] SourceMod VDF in metamod dir"
else
    echo "[!] WARNING: sourcemod.vdf missing from metamod dir!"
fi

if [ -f "${GAME_DIR}/addons/sourcemod/bin/sourcemod_mm_i486.so" ]; then
    echo "[+] sourcemod_mm_i486.so present"
else
    echo "[!] WARNING: sourcemod_mm_i486.so missing!"
fi

if [ -f "${GAME_DIR}/addons/sourcemod/bin/sourcemod.2.insurgency.so" ]; then
    echo "[+] sourcemod.2.insurgency.so present"
else
    echo "[!] WARNING: sourcemod.2.insurgency.so missing!"
fi

echo ""

# ============================================================
# Determine playlist based on game mode
# ============================================================
case "${GAME_MODE}" in
    coop)
        PLAYLIST="coop"
        ;;
    pvp)
        PLAYLIST="pvp"
        ;;
    *)
        PLAYLIST="${GAME_MODE}"
        ;;
esac

# ============================================================
# Workaround: Insurgency 2014 GAME-prefix VDF bug
# The engine prepends "GAME" to VDF plugin paths, turning
# "addons/metamod/bin/server" into "GAMEaddons/metamod/bin/server".
# Create symlinks so the corrupted path resolves correctly.
# ============================================================
for dir in "${SERVER_DIR}" "${SERVER_DIR}/bin"; do
    if [ ! -e "${dir}/GAMEaddons" ]; then
        ln -s "${GAME_DIR}/addons" "${dir}/GAMEaddons"
        echo "[+] Created GAMEaddons symlink in $(basename "${dir}")/"
    fi
done

# ============================================================
# Start the server
# ============================================================
echo "[*] Starting Insurgency server..."
echo "    Map: ${START_MAP}"
echo "    Mode: ${GAME_MODE}"
echo "    Max Players: ${MAX_PLAYERS}"
echo "    Tickrate: ${TICKRATE}"
echo "    Bots: ${BOT_COUNT}"
echo "=============================================="

cd "${SERVER_DIR}"
export LD_LIBRARY_PATH="${SERVER_DIR}:${SERVER_DIR}/bin:${LD_LIBRARY_PATH}"
exec ./srcds_linux \
    -game insurgency \
    -console \
    -32bit \
    -port 27025 \
    -insecure \
    +sv_lan 0 \
    +sv_cheats 1 \
    +map "${START_MAP}" \
    +maxplayers "${MAX_PLAYERS}" \
    -tickrate "${TICKRATE}" \
    -sv_playlist "${PLAYLIST}" \
    +smartbots_ai_host "${AI_HOST}" \
    "$@"
