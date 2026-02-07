# Insurgency 2014 Smart Bots - Dev Server

Dockerized Insurgency 2014 dedicated server with SourceMod, MetaMod, and a Python AI brain for tactical bot behavior.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Docker Compose                             │
│                                             │
│  ┌───────────────────────┐    UDP :9000     │
│  │  insurgency-server    │◄────────────────►│
│  │                       │                  │
│  │  srcds_linux          │    ┌───────────┐ │
│  │  + MetaMod:Source     │    │ ai-brain  │ │
│  │  + SourceMod          │    │ (Python)  │ │
│  │  + Bridge Plugin (.sp)│    │           │ │
│  │  + NavBot (optional)  │    │ Tactical  │ │
│  └───────────────────────┘    │ AI Logic  │ │
│           │                   └───────────┘ │
│           │ :27015/udp                      │
└───────────┼─────────────────────────────────┘
            │
       Game Clients
```

## Quick Start

### 1. Build and start the game server only

```bash
docker compose build insurgency
docker compose up insurgency
```

This gives you a working Insurgency 2014 coop server with SourceMod.

### 2. (Optional) Start with the Python AI brain

```bash
docker compose --profile ai up --build
```

### 3. Connect to your server

Open Insurgency 2014, open console, type:
```
connect 192.168....:27025
```

Or from another machine:
`````
connect YOUR_SERVER_IP:27025
```

## Version Compatibility

This is critical — Insurgency 2014 is picky about versions:

| Component       | Version       | Notes                                    |
|----------------|---------------|------------------------------------------|
| Insurgency     | Steam 237410  | Free anonymous download                  |
| MetaMod:Source | 1.11.x dev    | Must use dev snapshots                   |
| SourceMod      | 1.11.x dev    | Must use dev snapshots, not stable       |
| Server flags   | `-32bit`      | Required for Insurgency                  |

### Updating MetaMod/SourceMod versions

The Dockerfile downloads specific snapshot builds. If they become unavailable:

1. Go to https://www.sourcemm.net/downloads.php?branch=dev
2. Go to https://www.sourcemod.net/downloads.php?branch=dev
3. Get the latest Linux `.tar.gz` URLs
4. Update the `wget` URLs in the Dockerfile

## Directory Structure

```
insurgency-server/
├── docker-compose.yml      # Orchestration
├── Dockerfile              # Game server image
├── scripts/
│   ├── entrypoint.sh       # Server startup script
│   ├── server.cfg          # Generated at runtime
│   └── betterbots.cfg      # Tuned bot CVars
├── cfg/                    # Mount custom .cfg files here
├── plugins/                # Mount custom .smx plugins here
├── ai-brain/
│   ├── Dockerfile          # Python AI service
│   ├── requirements.txt
│   └── src/
│       └── main.py         # Tactical AI scaffold
└── README.md
```

## Configuration

### Environment Variables

| Variable          | Default                          | Description              |
|-------------------|----------------------------------|--------------------------|
| SERVER_HOSTNAME   | Insurgency Smart Bots Dev Server | Server name              |
| SERVER_PASSWORD   | (empty)                          | Join password            |
| RCON_PASSWORD     | changeme                         | Remote console password  |
| MAX_PLAYERS       | 32                               | Max player slots         |
| START_MAP         | ministry_coop                    | Starting map             |
| GAME_MODE         | coop                             | coop or pvp              |
| TICKRATE          | 64                               | Server tick rate         |
| UPDATE_ON_START   | 1                                | Check for updates        |

### Custom Plugins

Drop compiled `.smx` files into `./plugins/` and they'll be copied into
the SourceMod plugins directory on container start.

### Custom Configs

Drop `.cfg` files into `./cfg/` and they'll be copied into the game's
cfg directory on container start.

## RCON Access

Connect to RCON for server management:

```bash
# From the host machine
docker exec -it insurgency-server bash
# Then in the container:
# Or use any RCON client pointed at localhost:27015

# Verify SourceMod is running:
# In server console: sm version
# In server console: meta list
```

## Development Workflow

### Working on bot AI (Python path)

1. Edit files in `ai-brain/src/`
2. The volume mount means changes are live
3. Restart the ai-brain service: `docker compose --profile ai restart ai-brain`

### Working on SourceMod plugins

1. Write your `.sp` file
2. Compile it with `spcomp` (included in SM's `scripting/` folder)
3. Drop the `.smx` into `./plugins/`
4. Restart: `docker compose restart insurgency`

### Useful RCON commands

```
meta list              # Verify MetaMod plugins
sm version             # Verify SourceMod
sm plugins list        # List loaded SM plugins
bot_add                # Add a bot
bot_kick               # Kick all bots
nav_generate           # Generate nav mesh (takes time)
nav_edit 1             # Enter nav mesh editor
```

## Next Steps

1. **Get the basic server running** with this Docker setup
2. **Install NavBot** extension for full bot movement control
   - Clone: https://github.com/caxanga334/NavBot
   - Build for Linux or grab a release
   - Place the .so in `insurgency/addons/sourcemod/extensions/`
3. **Write the SM bridge plugin** — a thin SourcePawn plugin that:
   - Reads bot positions, health, visibility each tick
   - Sends this state as JSON over UDP to the Python AI brain
   - Receives movement/action commands back
   - Translates them into engine calls (TeleportEntity, SetVelocity, etc.)
4. **Build out the Python tactical AI** with:
   - Nav mesh parsing (export nav mesh data to JSON)
   - Flanking route computation
   - Cover position analysis
   - Team coordination via shared blackboard

## Troubleshooting

**SourceMod not loading:**
- Check that `-32bit` is in launch flags
- Check `meta list` in console — MetaMod must load first
- Try different SM/MM version combinations (see community threads)

**Bots not spawning:**
- Make sure you're on a coop map (e.g. `ministry_coop`)
- Check `bot_quota` CVar

**Server crashes on start:**
- Usually a SM/MM version mismatch
- Check `insurgency/addons/sourcemod/logs/` for errors
