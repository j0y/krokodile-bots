# ============================================================
# Stage 1a: Build SmartBots C++ Metamod extension (32-bit)
# ============================================================
FROM debian:bullseye-slim AS ext-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        g++-multilib \
        cmake \
        make \
    && rm -rf /var/lib/apt/lists/*

COPY metamod-extension/ /build/metamod-extension/

RUN cd /build/metamod-extension && \
    cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build

# ============================================================
# Stage 1b: Compile SourcePawn plugins with spcomp
# ============================================================
FROM debian:bullseye-slim AS sp-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lib32stdc++6 \
        lib32z1 \
    && rm -rf /var/lib/apt/lists/*

# Download SourceMod 1.11 (stable) for spcomp + include files
RUN mkdir -p /opt/sourcemod && \
    curl -sqL "https://sm.alliedmods.net/smdrop/1.11/sourcemod-1.11.0-git6968-linux.tar.gz" \
    | tar xz -C /opt/sourcemod --strip-components=1

# Download DHooks extension (includes dhooks.inc)
RUN curl -sqL "https://github.com/peace-maker/DHooks2/releases/download/v2.2.0-detours17/dhooks-2.2.0-detours17-sm110.tar.gz" \
    | tar xz -C /opt/sourcemod

# Copy plugin sources
COPY insurgency-server/scripting/ /build/scripting/

# Compile SourceMod plugins (smartbots core stays as C++ extension)
RUN /opt/sourcemod/addons/sourcemod/scripting/spcomp \
        -i/opt/sourcemod/addons/sourcemod/scripting/include \
        -i/build/scripting \
        -o/build/smartbots_deathzones.smx \
        /build/scripting/smartbots_deathzones.sp && \
    /opt/sourcemod/addons/sourcemod/scripting/spcomp \
        -i/opt/sourcemod/addons/sourcemod/scripting/include \
        -i/build/scripting \
        -o/build/smartbots_navspawn.smx \
        /build/scripting/smartbots_navspawn.sp && \
    /opt/sourcemod/addons/sourcemod/scripting/spcomp \
        -i/opt/sourcemod/addons/sourcemod/scripting/include \
        -i/build/scripting \
        -o/build/smartbots_ammobox.smx \
        /build/scripting/smartbots_ammobox.sp && \
    /opt/sourcemod/addons/sourcemod/scripting/spcomp \
        -i/opt/sourcemod/addons/sourcemod/scripting/include \
        -i/build/scripting \
        -o/build/smartbots_healthbox.smx \
        /build/scripting/smartbots_healthbox.sp

# ============================================================
# Stage 2: Game server
# ============================================================
FROM debian:bullseye-slim

LABEL maintainer="insurgency-smart-bots"
LABEL description="Insurgency 2014 Dedicated Server with SmartBots (C++ extension + SourceMod plugins)"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# ============================================================
# 1. Install runtime dependencies
# ============================================================
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lib32gcc-s1 \
        lib32stdc++6 \
        lib32z1 \
        libncurses5:i386 \
        libtinfo5:i386 \
        libcurl4-gnutls-dev:i386 \
    && rm -rf /var/lib/apt/lists/*

# ============================================================
# 2. Create steam user (don't run server as root)
# ============================================================
RUN useradd -m -s /bin/bash steam
USER steam
WORKDIR /home/steam

# ============================================================
# 3. Install SteamCMD (small ~10MB, needed for Steam runtime)
# ============================================================
RUN mkdir -p /home/steam/steamcmd && \
    cd /home/steam/steamcmd && \
    curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz" | tar xz && \
    /home/steam/steamcmd/steamcmd.sh +quit

# Link steamclient.so where the engine expects it
RUN mkdir -p /home/steam/.steam/sdk32 && \
    ln -s /home/steam/steamcmd/linux32/steamclient.so /home/steam/.steam/sdk32/steamclient.so

# ============================================================
# 4. Copy pre-downloaded server files
#    Run ./download-server.sh first to populate server-files/
# ============================================================
COPY --chown=steam:steam insurgency-server/server-files/ /home/steam/insurgency-server/

# ============================================================
# 5. Copy configuration and startup scripts
# ============================================================
COPY --chown=steam:steam insurgency-server/cfg/ /home/steam/insurgency-server/insurgency/cfg/custom/
COPY --chown=steam:steam insurgency-server/scripts/server.cfg /home/steam/insurgency-server/insurgency/cfg/server.cfg
COPY --chown=steam:steam insurgency-server/scripts/betterbots.cfg /home/steam/insurgency-server/insurgency/cfg/betterbots.cfg
COPY --chown=steam:steam insurgency-server/scripts/hardbots.cfg /home/steam/insurgency-server/insurgency/cfg/hardbots.cfg
COPY --chown=steam:steam insurgency-server/scripts/entrypoint.sh /home/steam/entrypoint.sh
COPY --chown=steam:steam insurgency-server/scripts/entrypoint-vanilla.sh /home/steam/entrypoint-vanilla.sh

USER root
RUN chmod +x /home/steam/entrypoint.sh /home/steam/entrypoint-vanilla.sh
USER steam

# ============================================================
# 6. Install SmartBots Metamod extension (core bot AI)
# ============================================================
RUN mkdir -p /home/steam/insurgency-server/insurgency/addons/smartbots/bin/linux

COPY --from=ext-builder --chown=steam:steam \
    /build/metamod-extension/build/smartbots.so \
    /home/steam/insurgency-server/insurgency/addons/smartbots/bin/linux/smartbots.so
COPY --chown=steam:steam \
    metamod-extension/smartbots.vdf \
    /home/steam/insurgency-server/insurgency/addons/metamod/smartbots.vdf

# ============================================================
# 7. Install SourceMod plugins + gamedata
# ============================================================

# Compiled plugins
COPY --from=sp-builder --chown=steam:steam \
    /build/smartbots_deathzones.smx \
    /home/steam/insurgency-server/insurgency/addons/sourcemod/plugins/smartbots_deathzones.smx
COPY --from=sp-builder --chown=steam:steam \
    /build/smartbots_navspawn.smx \
    /home/steam/insurgency-server/insurgency/addons/sourcemod/plugins/smartbots_navspawn.smx
COPY --from=sp-builder --chown=steam:steam \
    /build/smartbots_ammobox.smx \
    /home/steam/insurgency-server/insurgency/addons/sourcemod/plugins/smartbots_ammobox.smx
COPY --from=sp-builder --chown=steam:steam \
    /build/smartbots_healthbox.smx \
    /home/steam/insurgency-server/insurgency/addons/sourcemod/plugins/smartbots_healthbox.smx

# Gamedata files (used by SourceMod plugins)
COPY --chown=steam:steam \
    insurgency-server/gamedata/ \
    /home/steam/insurgency-server/insurgency/addons/sourcemod/gamedata/

# ============================================================
# Ports
# ============================================================
EXPOSE 27025/udp 27025/tcp

ENTRYPOINT ["/home/steam/entrypoint.sh"]
