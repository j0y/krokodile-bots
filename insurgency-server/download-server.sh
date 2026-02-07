#!/bin/bash
set -e

# ============================================================
# Download Insurgency 2014 server + MetaMod + SourceMod
# to a local directory. Run this ONCE, then Docker builds
# will just COPY these files in (fast rebuilds).
#
# Uses a temporary Docker container for SteamCMD so you
# don't need SteamCMD installed on the host.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="${SCRIPT_DIR}/server-files"

MM_URL="https://mms.alliedmods.net/mmsdrop/1.12/mmsource-1.12.0-git1219-linux.tar.gz"
SM_URL="https://sm.alliedmods.net/smdrop/1.11/sourcemod-1.11.0-git6968-linux.tar.gz"

# ============================================================
# 1. Download Insurgency 2014 Dedicated Server via SteamCMD
# ============================================================
if [ -f "${SERVER_DIR}/srcds_linux" ]; then
    echo "[*] Server files already exist in ${SERVER_DIR}"
    echo "    Delete the directory to re-download."
else
    echo "[*] Downloading Insurgency 2014 Dedicated Server (App 237410)..."
    echo "    This will take a while on the first run."
    mkdir -p "${SERVER_DIR}"

    docker run --rm \
        -v "${SERVER_DIR}:/home/steam/insurgency-server" \
        steamcmd/steamcmd:latest \
        +force_install_dir /home/steam/insurgency-server \
        +login anonymous \
        +app_update 237410 validate \
        +quit

    # SteamCMD container runs as root, fix ownership
    echo "[*] Fixing file permissions..."
    sudo chown -R "$(id -u):$(id -g)" "${SERVER_DIR}"

    echo "[+] Server downloaded to ${SERVER_DIR}"
fi

# ============================================================
# 2. Download MetaMod:Source
# ============================================================
if [ -d "${SERVER_DIR}/insurgency/addons/metamod" ]; then
    echo "[*] MetaMod already installed, skipping."
else
    echo "[*] Downloading MetaMod:Source..."
    wget -q "${MM_URL}" -O /tmp/metamod.tar.gz
    tar xzf /tmp/metamod.tar.gz -C "${SERVER_DIR}/insurgency/"
    rm -f /tmp/metamod.tar.gz
    # Remove 64-bit files (server is 32-bit)
    rm -rf "${SERVER_DIR}/insurgency/addons/metamod/bin/linux64"
    rm -f "${SERVER_DIR}/insurgency/addons/metamod_x64.vdf"
    # Create server_srv.so stub (Insurgency loads the _srv variant)
    cp "${SERVER_DIR}/insurgency/addons/metamod/bin/server_i486.so" \
       "${SERVER_DIR}/insurgency/addons/metamod/bin/server_srv.so"
    # Remove extra stubs to prevent infinite recursion when the
    # stub tries to load "server_i486.so" from its own directory
    rm -f "${SERVER_DIR}/insurgency/addons/metamod/bin/server_i486.so"
    rm -f "${SERVER_DIR}/insurgency/addons/metamod/bin/server.so"
    echo "[+] MetaMod installed."
fi

# ============================================================
# 3. Download SourceMod
# ============================================================
if [ -d "${SERVER_DIR}/insurgency/addons/sourcemod" ]; then
    echo "[*] SourceMod already installed, skipping."
else
    echo "[*] Downloading SourceMod..."
    wget -q "${SM_URL}" -O /tmp/sourcemod.tar.gz
    tar xzf /tmp/sourcemod.tar.gz -C "${SERVER_DIR}/insurgency/"
    rm -f /tmp/sourcemod.tar.gz
    echo "[+] SourceMod installed."
fi

# ============================================================
# 4. Create MetaMod VDF (not used by Insurgency engine, but
#    kept for completeness)
# ============================================================
echo "[*] Writing metamod.vdf..."
cat > "${SERVER_DIR}/insurgency/addons/metamod.vdf" << 'EOF'
"Plugin"
{
    "file"  "addons/metamod/bin/server"
}
EOF

# ============================================================
# 5. Patch gameinfo.txt for MetaMod GameInfo loading
#    The engine loads server_srv.so from the first GameBin path.
#    By adding metamod/bin first, the MM stub is loaded instead
#    of the real server. The stub then finds the real server via
#    the server_i486.so symlink (see step 6).
# ============================================================
GAMEINFO="${SERVER_DIR}/insurgency/gameinfo.txt"
if grep -q "addons/metamod/bin" "${GAMEINFO}" 2>/dev/null; then
    echo "[*] gameinfo.txt already patched, skipping."
else
    echo "[*] Patching gameinfo.txt for MetaMod GameInfo loading..."
    sed -i '/SearchPaths/,/^[[:space:]]*{/{
        /^[[:space:]]*{/a\
\t\t\tGameBin\t\t\t\t|gameinfo_path|addons/metamod/bin
    }' "${GAMEINFO}"
    echo "[+] gameinfo.txt patched."
fi

# ============================================================
# 6. Create server_i486.so symlink in game bin directory
#    The MetaMod stub uses LIB_SUFFIX="_i486.so" internally,
#    so it searches for "server_i486.so" as the real server.
#    Insurgency's actual server binary is "server_srv.so".
#    This symlink lets the stub find the real server.
# ============================================================
GAMEBIN="${SERVER_DIR}/insurgency/bin"
if [ ! -e "${GAMEBIN}/server_i486.so" ]; then
    echo "[*] Creating server_i486.so symlink..."
    ln -sf server_srv.so "${GAMEBIN}/server_i486.so"
    echo "[+] server_i486.so -> server_srv.so"
else
    echo "[*] server_i486.so already exists, skipping."
fi

echo ""
echo "=============================================="
echo " All done! Server files are in:"
echo "   ${SERVER_DIR}"
echo ""
echo " You can now build the Docker image:"
echo "   docker compose build"
echo "=============================================="
