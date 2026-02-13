# Insurgency 2014 Smart Bots

Three-layer AI for Insurgency 2014 bots: C++ Metamod extension controls bots via native action classes, Python tactical planner scores positions using precomputed visibility data, future LLM strategist for high-level decisions.

```
┌────────────────────┐  UDP :9000  ┌────────────────────┐
│  Insurgency Server │ ──────────► │  Tactical Brain    │
│  Metamod extension │ ◄────────── │  Python (asyncio)  │
│  (C++ bot control) │  commands   │  influence scoring  │
└────────────────────┘             └────────────────────┘
```

## Quick Start

```bash
# 1. Download server files (one-time, ~10GB)
cd insurgency-server && ./download-server.sh && cd ..

# 2. Precompute spatial data for a map
cd bspMeshExporter
uv run python -m bsp_mesh_exporter extract ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --output-dir ../data/
uv run python -m bsp_mesh_exporter vismatrix ministry_coop \
    --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
    --mesh-dir ../data/ --output-dir ../data/
uv run python -m bsp_mesh_exporter influence ministry_coop \
    --vismatrix-dir ../data/ --output-dir ../data/
cd ..

# 3. Run game server + tactical brain
docker compose --profile ai up --build

# 4. Connect in-game to port 27025
```

## Project Structure

```
├── docker-compose.yml        # Orchestrates services
├── insurgency-server/        # Game server + Metamod extension (multi-stage Docker build)
├── metamod-extension/        # C++ Metamod:Source plugin (bot control via native actions)
├── tactical-brain/           # Python tactical planner (influence map scoring)
├── bspMeshExporter/          # Offline spatial data pipeline (BSP mesh, vismatrix, influence)
├── navMeshParser/            # Nav mesh parser (30/30 maps)
├── ai-brain-old/             # Legacy Python AI (reference)
└── reverseEngineering/       # Analysis docs and design specs
```

## How It Works

1. **Metamod extension** hooks into bot behavior, sends bot state (position, health, team) over UDP each tick
2. **Tactical brain** loads precomputed visibility matrix (~21K grid points per map) and scores positions using weight profiles (defend, push, ambush, sniper, overrun)
3. Best positions are assigned to bots based on concealment, sightline to objective, threat from enemies, objective proximity, and team spread
4. Extension receives target positions and uses native bot action classes (approach, combat) — engine handles pathfinding, aim, firing

Docker profiles: `ai` (extension + tactical brain), `vanilla` (original AI), `record` (observer + recording).
