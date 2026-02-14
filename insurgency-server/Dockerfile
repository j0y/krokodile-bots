# ============================================================
# Stage 1: Build Metamod extension (32-bit)
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

COPY metamod-extension/ /build/
RUN cd /build && \
    cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build

# ============================================================
# Stage 2: Game server
# ============================================================
FROM debian:bullseye-slim

LABEL maintainer="insurgency-smart-bots"
LABEL description="Insurgency 2014 Dedicated Server with Metamod extension"

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
COPY --chown=steam:steam insurgency-server/scripts/server.cfg /home/steam/insurgency-server/insurgency/cfg/server.cfg
COPY --chown=steam:steam insurgency-server/scripts/betterbots.cfg /home/steam/insurgency-server/insurgency/cfg/betterbots.cfg
COPY --chown=steam:steam insurgency-server/scripts/hardbots.cfg /home/steam/insurgency-server/insurgency/cfg/hardbots.cfg
COPY --chown=steam:steam insurgency-server/scripts/entrypoint.sh /home/steam/entrypoint.sh
COPY --chown=steam:steam insurgency-server/scripts/entrypoint-vanilla.sh /home/steam/entrypoint-vanilla.sh

USER root
RUN chmod +x /home/steam/entrypoint.sh /home/steam/entrypoint-vanilla.sh
USER steam

# ============================================================
# 6. Install Metamod extension
# ============================================================
RUN mkdir -p /home/steam/insurgency-server/insurgency/addons/smartbots/bin/linux
COPY --from=ext-builder --chown=steam:steam \
    /build/build/smartbots.so \
    /home/steam/insurgency-server/insurgency/addons/smartbots/bin/linux/smartbots.so
COPY --chown=steam:steam \
    metamod-extension/smartbots.vdf \
    /home/steam/insurgency-server/insurgency/addons/metamod/smartbots.vdf

# ============================================================
# Ports
# ============================================================
EXPOSE 27025/udp 27025/tcp

ENTRYPOINT ["/home/steam/entrypoint.sh"]
