# Insurgency Server

Dockerized Insurgency 2014 dedicated server with a custom Metamod extension for bot control.

## Setup

1. Download server files: `./download-server.sh`
2. Build and run (from repo root): `docker compose --profile ai up --build`
3. Connect: `connect YOUR_IP:27025`

## Directory Structure

```
insurgency-server/
├── Dockerfile              # Multi-stage: builds Metamod extension + game server image
├── download-server.sh      # Downloads server + MM + SM to server-files/
├── server-files/           # Pre-downloaded game files (~10GB, gitignored)
├── scripts/
│   ├── entrypoint.sh       # Server startup, config generation, MM verification
│   ├── entrypoint-vanilla.sh
│   ├── server.cfg          # Template (overwritten at runtime)
│   └── betterbots.cfg      # Bot behavior CVars
└── cfg/                    # Custom .cfg files mounted into server
```

## Configuration

| Variable        | Default                          | Description             |
|-----------------|----------------------------------|-------------------------|
| SERVER_HOSTNAME | Insurgency Smart Bots Dev Server | Server name             |
| SERVER_PASSWORD | (empty)                          | Join password           |
| RCON_PASSWORD   | changeme                         | Remote console password |
| MAX_PLAYERS     | 32                               | Max player slots        |
| START_MAP       | ministry_coop                    | Starting map            |
| GAME_MODE       | coop                             | coop or pvp             |
| TICKRATE        | 64                               | Server tick rate        |
| NB_DEBUG        | 0                                | NextBot debug level     |
| CONTROLLED_TEAM | 3                                | Team controlled by AI (2=Security, 3=Insurgents) |

## How It Works

The Dockerfile uses a multi-stage build:
1. **Stage 1** — Compiles the Metamod extension (32-bit .so) from `metamod-extension/`
2. **Stage 2** — Copies pre-downloaded server files, configs, and the compiled extension into the final image

The extension is installed as a Metamod plugin at `addons/smartbots/` and communicates with the tactical brain over UDP.

## Version Compatibility

| Component      | Version              | Notes                           |
|----------------|----------------------|---------------------------------|
| Insurgency     | Steam AppID 237410   | Free anonymous download         |
| MetaMod:Source | 1.12.0-git1219       | Dev snapshots required          |
| SourceMod      | 1.11.0-git6968       | Dev snapshots required          |
| Server flags   | `-32bit`             | Required for Insurgency         |

## Troubleshooting

- **Extension not loading:** run `meta list` in console, check Metamod logs
- **Bots not spawning:** ensure coop map (e.g. `ministry_coop`), check `bot_quota`
- **Server crashes:** usually MM version mismatch, check server console output

## Useful RCON commands

```
meta list           # Verify MetaMod and extension
bot_add / bot_kick  # Manage bots
nb_debug 1          # Enable NextBot debug overlay
```
