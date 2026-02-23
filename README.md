# Insurgency 2014 Smart Bots

Custom AI for Insurgency (2014) cooperative mode. Hybrid architecture: a C++ Metamod:Source extension handles the performance-critical 66 Hz bot AI loop, while event-driven features (death zones, spawn relocation) run as SourceMod plugins for easy hot-reload tuning.

```
┌───────────────────────────────────────────────────┐
│              Insurgency Server Process             │
│                                                   │
│  C++ Metamod extension (66 Hz GameFrame)          │
│  └── smartbots.so     — core bot AI               │
│                                                   │
│  SourceMod plugins (event-driven)                 │
│  ├── smartbots_deathzones.smx — death zone track  │
│  └── smartbots_navspawn.smx   — spawn relocation  │
│                                                   │
│  Engine handles: pathfinding, aim, firing         │
└───────────────────────────────────────────────────┘
```

## How It Works

### smartbots.so — Core Bot AI (C++ Metamod extension)

Each server tick (~66 Hz) the extension runs a game frame loop with direct native function calls:

1. **Threat detection** — uses the engine's native `IVision` interface to check each bot for visible/known enemies. If a bot sees a threat, the engine's combat AI takes full control.

2. **Role split** — bots are divided by proximity to the current objective:
   - **Defenders (~30%)** — positioned in a fan pattern around the objective (forward, flanks, rear). Slots are assigned greedily; forward positions fill first.
   - **Flankers (~70%)** — routed along paths that avoid death zones and approach from the enemy's direction.

3. **Command execution** — movement targets are written via `BotCommand_Set()` and picked up by a detour on `CINSBotActionCheckpoint::Update`, which suspends the default checkpoint action and issues an Approach or Investigate action instead.

### smartbots_deathzones.smx — Death Zone Tracking (SourceMod plugin)

Player deaths are recorded on the nav mesh with decaying intensity via BFS. Bots learn to avoid areas where teammates recently died. Event-driven (fires on player_death), not per-tick. Hot-reloadable: `sm plugins reload smartbots_deathzones`.

### smartbots_navspawn.smx — Spawn Relocation (SourceMod plugin)

Post-hooks `CINSNextBot::Spawn` via DynamicDetour. Scores nav mesh areas using a multi-source BFS from attacker positions with distance bell curve, visibility penalty, and indoor bonus. Teleports spawning defender bots to high-scoring positions. Fires only on bot spawn events. Hot-reloadable: `sm plugins reload smartbots_navspawn`.

## Quick Start

```bash
# Dev server (extension + plugins, rebuilds on C++ changes)
docker compose --profile dev up --build

# Vanilla server (unmodified AI, for comparison)
docker compose --profile vanilla up

# Connect in-game to port 27025
```

## Project Structure

```
├── docker-compose.yml
├── metamod-extension/                    # C++ Metamod extension — core bot AI (66 Hz)
│   └── src/
│       ├── extension.cpp                     # Main loop, plugin lifecycle
│       ├── bot_action_hook.cpp               # Detours: combat + checkpoint override
│       ├── bot_tactics.cpp                   # Defender fan positioning
│       ├── nav_flanking.cpp                  # Flanker path selection
│       ├── bot_trace.cpp                     # Visibility traces
│       ├── nav_objectives.cpp                # Objective nav data
│       ├── game_events.cpp                   # Round/objective tracking
│       └── sig_resolve.cpp                   # Symbol lookup
├── insurgency-server/
│   ├── scripting/
│   │   ├── smartbots_deathzones.sp       # Death zone plugin (SourceMod)
│   │   ├── smartbots_deathzones/
│   │   │   └── navmesh.inc                   # Nav mesh access for deathzones
│   │   └── smartbots_navspawn.sp         # Spawn relocation plugin (SourceMod)
│   └── gamedata/
│       ├── smartbots_deathzones.txt      # Signatures + offsets for deathzones
│       └── smartbots_navspawn.txt        # Signatures + offsets for navspawn
└── reverseEngineering/                   # Decompiled server code, analysis docs
```

## Building

```bash
# Full build via Docker (C++ extension + SourcePawn plugins)
docker compose --profile dev up --build

# Host C++ build only (generates compile_commands.json for IDE)
cmake -B build metamod-extension/
# Requires g++-multilib (32-bit Linux target)

# SourceMod plugins can also be compiled standalone
spcomp insurgency-server/scripting/smartbots_deathzones.sp
spcomp insurgency-server/scripting/smartbots_navspawn.sp
# Deploy .smx to addons/sourcemod/plugins/, gamedata to addons/sourcemod/gamedata/
```
