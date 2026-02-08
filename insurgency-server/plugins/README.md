# SmartBots Bridge Plugin

SourceMod plugin that bridges Insurgency 2014 game bots to an external Python AI brain over UDP.

## How It Works

### Movement Control

Insurgency 2014 bots use a NextBot-based AI system. The plugin takes full control by:

1. **Suppressing the behavior tree** — DHooks detour on `CINSNextBotIntention::Update` with `MRES_Supercede` kills the native AI (no Stop(), no hold position, no state changes).
2. **Clearing stuck detection** — DHooks detour on `CINSBotLocomotion::Update` calls `ILocomotion::ClearStuckStatus` each tick.
3. **Direct movement via OnPlayerRunCmd** — calculates yaw to target, sets forward velocity and IN_FORWARD button. The engine processes these into proper running animations.

### UDP Protocol

**State (SM -> Python, ~8 Hz):**
```json
{"tick":123,"bots":[{"id":3,"pos":[2200.0,-1100.0,32.0],"ang":[0.0,90.0,0.0],"hp":100,"alive":1,"team":3}]}
```

**Commands (Python -> SM):**
```
3 2200.0 -1100.0 32.0 1.00
5 1800.0 -900.0 32.0 0.50
```
One line per bot: `id x y z speed\n`

### Bot Mapping

On each bot spawn, the plugin calls `CINSNextBot::GetLocomotionInterface()` via SDKCall to get the bot's `ILocomotion*` pointer. This is stored in a lookup table so the Update detour can map `pThis` back to a client index.

## Gamedata

`gamedata/smartbots_bridge.txt` contains:

- **Signatures**: Linux symbol names for locomotion and behavior functions
- **Functions**: DHooks detour definitions with parameter types

### Key Vtable Offsets (Linux, from server_srv.so)

| Method | Offset | Used For |
|--------|--------|----------|
| `ILocomotion::Update` | 47 | Locomotion tick |
| `ILocomotion::Approach` | 50 | Movement goal (kept as fallback) |
| `ILocomotion::Run` | 59 | Run mode |
| `ILocomotion::Stop` | 61 | Stop movement |
| `ILocomotion::FaceTowards` | 77 | Look direction |

These offsets are specific to Insurgency 2014's `CINSBotLocomotion` class.

## ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `sm_smartbots_host` | `127.0.0.1` | AI brain host |
| `sm_smartbots_port` | `9000` | AI brain UDP port |
| `sm_smartbots_debug` | `1` | Debug logging |

## Commands

- `sm_smartbots_status` - Show bridge status, connected bots, and locomotion mappings

## Dependencies

- [DHooks](https://wiki.alliedmods.net/DHooks_(SourceMod_Scripting)) (bundled with SM 1.11+)
- [Socket extension](https://forums.alliedmods.net/showthread.php?t=67640) 3.0.1 (for UDP)

## Compiling

```bash
insurgency-server/server-files/insurgency/addons/sourcemod/scripting/spcomp \
  insurgency-server/plugins/smartbots_bridge.sp \
  -iinsurgency-server/server-files/insurgency/addons/sourcemod/scripting/include \
  -oinsurgency-server/plugins/smartbots_bridge.smx
```

The compiled `.smx` is volume-mounted into the container at runtime.
