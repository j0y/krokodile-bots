# Insurgency 2014 Smart Bots

Python-driven AI for Insurgency 2014 game bots. A SourceMod plugin bridges the game engine to an external Python AI brain over UDP, using DHooks to control bot locomotion with proper running animations.

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

# 3. Connect in-game to port 27025
```

Game server only (no AI): `docker compose up insurgency --build`
Observer: `docker compose --profile record up --build`

## Project Structure

```
├── docker-compose.yml        # Orchestrates both services
├── insurgency-server/        # Game server + SM bridge plugin
│   ├── plugins/              # smartbots_bridge.sp/.smx
│   ├── gamedata/             # DHooks gamedata (vtable offsets)
│   └── server-files/         # Pre-downloaded server (gitignored)
├── ai-brain/                 # Python AI brain (uv project)
│   └── src/smartbots/        # UDP server, movement controller
└── navMeshParser/            # Nav mesh parser (30/30 maps)
```

## How It Works

1. **SM plugin** uses DHooks to detour `CINSBotLocomotion::Approach` — the engine function that converts a goal position into movement button presses
2. Every ~125ms, plugin sends bot state (position, angles, health) as JSON over UDP
3. **Python AI** receives state, decides where each bot should go, sends target positions back
4. When the bot's behavior tree calls `Approach(goal)`, the detour replaces `goal` with the Python-provided target
5. The bot's locomotion system naturally converts the new goal into button presses, producing proper running/walking animations

Both services run with `network_mode: host` so UDP over localhost works seamlessly.
