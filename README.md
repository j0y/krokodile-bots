# Insurgency 2014 Smart Bots

Python-driven AI for Insurgency 2014 game bots. A SourceMod plugin bridges the game engine to an external Python brain over UDP.

```
┌────────────────────┐  UDP :9000  ┌────────────────────┐
│  Insurgency Server │ ──────────► │  Python AI Brain   │
│  SourceMod plugin  │ ◄────────── │  asyncio UDP       │
│  (smartbots_bridge)│  commands   │  (smartbots)       │
└────────────────────┘             └────────────────────┘
```

## Quick Start

```bash
# 1. Download server files (one-time, ~10GB)
cd insurgency-server && ./download-server.sh && cd ..

# 2. Run game server + AI brain
docker compose --profile ai up --build

# 3. Connect in-game
# connect 192.168.1...:27025`
```

Game server only (no AI): `docker compose up insurgency --build`

## Project Structure

```
├── docker-compose.yml        # Orchestrates both services
├── insurgency-server/        # Game server + SM bridge plugin
│   ├── plugins/              # smartbots_bridge.sp/.smx
│   └── server-files/         # Pre-downloaded server (gitignored)
├── ai-brain/                 # Python AI brain (uv project)
│   └── src/smartbots/        # UDP server, movement controller
└── navMeshParser/            # Nav mesh parser (30/30 maps)
```

## How It Works

1. **SM plugin** (`smartbots_bridge.sp`) hooks `OnPlayerRunCmd` for game bots
2. Every ~125ms, plugin sends bot state (position, angles, health) as JSON over UDP
3. **Python AI** receives state, computes movement commands, sends them back
4. Plugin applies movement each tick: decomposes direction into forward/side via dot products

Both services run with `network_mode: host` so UDP over localhost works seamlessly.
