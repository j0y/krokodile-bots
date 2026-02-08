# Insurgency Server

Dockerized Insurgency 2014 dedicated server with MetaMod + SourceMod.

## Setup

1. Download server files: `./download-server.sh`
2. Build and run (from repo root): `docker compose up insurgency --build`
3. Connect: `connect YOUR_IP:27025`

## Directory Structure

```
insurgency-server/
├── Dockerfile              # Game server image (debian:bullseye-slim)
├── download-server.sh      # Downloads server + MM + SM to server-files/
├── server-files/            # Pre-downloaded game files (~50GB, gitignored)
├── scripts/
│   ├── entrypoint.sh       # Server startup, config generation, MM/SM verification
│   ├── entrypoint-vanilla.sh
│   ├── server.cfg          # Template (overwritten at runtime)
│   └── betterbots.cfg      # Bot behavior CVars
├── cfg/                    # Mount custom .cfg files here
├── plugins/                # Custom SM plugins (.sp source + .smx compiled)
│   ├── smartbots_bridge.sp # SmartBots UDP bridge plugin source
│   └── smartbots_bridge.smx
└── .env
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

## Custom Plugins

Drop `.smx` files into `./plugins/` — they're copied into SM's plugins dir on container start.

### Compiling plugins

```bash
server-files/insurgency/addons/sourcemod/scripting/spcomp \
  plugins/smartbots_bridge.sp \
  -iserver-files/insurgency/addons/sourcemod/scripting/include \
  -oplugins/smartbots_bridge.smx
```

## Version Compatibility

Insurgency 2014 is picky about versions:

| Component      | Version              | Notes                           |
|----------------|----------------------|---------------------------------|
| Insurgency     | Steam AppID 237410   | Free anonymous download         |
| MetaMod:Source | 1.12.0-git1219       | Dev snapshots required          |
| SourceMod      | 1.11.0-git6968       | Dev snapshots required          |
| Server flags   | `-32bit`             | Required for Insurgency         |
| Socket ext     | 3.0.1                | UDP bridge, needs typedef fix   |

## Troubleshooting

- **SourceMod not loading:** check `-32bit` flag, run `meta list` in console
- **Bots not spawning:** ensure coop map (e.g. `ministry_coop`), check `bot_quota`
- **Server crashes:** usually MM/SM version mismatch, check `addons/sourcemod/logs/`

## Useful RCON commands

```
meta list           # Verify MetaMod
sm plugins list     # List SM plugins
bot_add / bot_kick  # Manage bots
```
