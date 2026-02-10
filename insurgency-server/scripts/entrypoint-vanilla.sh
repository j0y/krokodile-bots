#!/bin/bash
set -e

SERVER_DIR="/home/steam/insurgency-server"
GAME_DIR="${SERVER_DIR}/insurgency"

START_MAP="${START_MAP:-ministry_coop}"
MAX_PLAYERS="${MAX_PLAYERS:-32}"
TICKRATE="${TICKRATE:-64}"

echo "=============================================="
echo " Insurgency 2014 - VANILLA DEBUG SERVER"
echo " No MetaMod/SourceMod — original bot AI only"
echo "=============================================="

# Disable MetaMod/SourceMod by renaming the addons loader
if [ -f "${GAME_DIR}/addons/metamod.vdf" ]; then
    echo "[*] Disabling MetaMod for vanilla test..."
    mv "${GAME_DIR}/addons/metamod.vdf" "${GAME_DIR}/addons/metamod.vdf.disabled"
fi

# Copy custom configs if mounted
if [ -d "${GAME_DIR}/cfg/custom" ]; then
    echo "[*] Copying custom configs..."
    cp -f "${GAME_DIR}/cfg/custom/"*.cfg "${GAME_DIR}/cfg/" 2>/dev/null || true
fi

# server.cfg with cheats + debug
cat > "${GAME_DIR}/cfg/server.cfg" << 'EOF'
hostname "Vanilla Debug Server"
rcon_password "changeme"
sv_lan 0
sv_cheats 1
sv_pure 0

log on
sv_logecho 1
sv_logfile 1

mp_limitteams 0
mp_autoteambalance 0

mp_timer_pregame 3
mp_timer_preround 3
mp_timer_preround_first 3
mp_timer_postround 3

// Developer messages (1 = normal, avoids UTIL_GetListenServerHost spam)
developer 1

// NextBot debug — nb_debug is a COMMAND, not cvar
// Valid types: BEHAVIOR LOOK_AT PATH ANIMATION LOCOMOTION VISION HEARING EVENTS ERRORS *
// Must be sent after server fully loads, so we put it in a delayed exec
nb_debug_history 1
nb_update_debug 0

// NWI bot-specific debug
ins_bot_debug_combat_decisions 1
ins_bot_debug_combat_target 1
ins_bot_debug_movement_requests 0
ins_bot_debug_silhouette 0
ins_bot_debug_escort_formations 0
ins_bot_debug_visibility_blockers 0

// Small bot count for readable output
ins_bot_count_checkpoint_min 4
ins_bot_count_checkpoint_max 6
ins_bot_count_checkpoint_default 4
EOF

echo "[*] Starting vanilla debug server..."
echo "    Map: ${START_MAP}"
echo "    Max Players: ${MAX_PLAYERS}"

cd "${SERVER_DIR}"
export LD_LIBRARY_PATH="${SERVER_DIR}:${SERVER_DIR}/bin:${LD_LIBRARY_PATH}"
exec ./srcds_linux \
    -game insurgency \
    -console \
    -32bit \
    -port 27025 \
    +sv_lan 0 \
    +sv_cheats 1 \
    -insecure \
    +map "${START_MAP}" \
    +maxplayers "${MAX_PLAYERS}" \
    -tickrate "${TICKRATE}" \
    -sv_playlist coop \
    +nb_debug BEHAVIOR EVENTS ERRORS
