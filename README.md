# Insurgency 2014 Smart Bots

Custom AI for Insurgency (2014) cooperative mode. A C++ Metamod:Source extension that replaces default bot behavior with tactically competent defenders — no external services, no Python, everything runs in-process.

```
┌─────────────────────────────────────────────┐
│           Insurgency Server Process          │
│                                             │
│  Metamod extension (66 Hz GameFrame)        │
│  ├── Death zone tracking (nav mesh)         │
│  ├── Defender bots → fan around objective   │
│  └── Flanker bots  → death-zone-aware paths │
│                                             │
│  Engine handles: pathfinding, aim, firing   │
└─────────────────────────────────────────────┘
```

## How It Works

Each server tick (~66 Hz) the extension runs a game frame loop:

1. **Threat detection** — uses the engine's native `IVision` interface to check each bot for visible/known enemies. If a bot sees a threat, the engine's combat AI takes full control.

2. **Death zones** — player deaths are recorded on the nav mesh with a decaying intensity. Bots learn to avoid areas where teammates recently died.

3. **Role split** — bots are divided by proximity to the current objective:
   - **Defenders (~30%)** — positioned in a fan pattern around the objective (forward, flanks, rear). Slots are assigned greedily; forward positions fill first.
   - **Flankers (~70%)** — routed along paths that avoid death zones and approach from the enemy's direction.

4. **Command execution** — movement targets are written via `BotCommand_Set()` and picked up by a detour on `CINSBotActionCheckpoint::Update`, which suspends the default checkpoint action and issues an Approach or Investigate action instead.

## Quick Start

```bash
# Dev server (extension + game server, rebuilds extension image)
docker compose --profile dev up --build

# Vanilla server (unmodified AI, for comparison)
docker compose --profile vanilla up

# Connect in-game to port 27025
```

## Project Structure

```
├── docker-compose.yml         # Orchestrates game server
├── insurgency-server/         # Game server (Dockerfile w/ multi-stage ext build, configs)
├── metamod-extension/         # C++ Metamod:Source plugin — all AI logic
│   └── src/
│       ├── extension.cpp          # Main loop, plugin lifecycle
│       ├── bot_action_hook.cpp    # Detours: combat suppression + checkpoint override
│       ├── bot_tactics.cpp        # Defender fan positioning
│       ├── nav_flanking.cpp       # Flanker path selection
│       ├── bot_trace.cpp          # Visibility traces
│       ├── nav_objectives.cpp     # Objective nav data
│       ├── game_events.cpp        # Round/objective tracking
│       └── sig_resolve.cpp        # Symbol lookup
└── reverseEngineering/        # Decompiled server code, analysis docs
```

## Building

```bash
# Host build — generates compile_commands.json for IDE, 32-bit .so
cmake -B build metamod-extension/
# Requires g++-multilib (32-bit Linux target)

# Docker build bakes the .so into the image — must rebuild after C++ changes
docker compose --profile dev up --build
```
