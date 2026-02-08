# SmartBots Bridge Plugin

SourceMod plugin that bridges Insurgency 2014 game bots to an external Python AI brain over UDP. Uses DHooks to intercept the bot locomotion system, producing natural movement with proper running animations.

## How It Works

### Movement Control via DHooks

Insurgency 2014 bots use a NextBot-based AI system. The movement pipeline:

```
Behavior Tree
  -> PathFollower computes path via nav mesh
    -> CINSBotLocomotion::Approach(goalPos, weight)
      -> PlayerLocomotion converts goal into button presses (IN_FORWARD, etc.)
        -> Engine processes buttons -> proper running/walking animations
```

The plugin installs a **DynamicDetour** on `CINSBotLocomotion::Approach`. When the bot's behavior tree calls Approach with its computed waypoint, the detour replaces `goalPos` with the target position received from Python. The bot's locomotion system then naturally converts that into button presses, so animations work correctly.

### Why not OnPlayerRunCmd?

Insurgency's NextBot system constructs its own `CUserCmd` in `PhysicsSimulate`, overwriting any changes made in `OnPlayerRunCmd` each tick. Setting `vel[]` or `buttons` has no effect. Position teleportation works but produces sliding without animations.

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

On each bot spawn, the plugin calls `CINSNextBot::GetLocomotionInterface()` via SDKCall to get the bot's `ILocomotion*` pointer. This is stored in a lookup table so the Approach detour can map `pThis` back to a client index.

## Gamedata

`gamedata/smartbots_bridge.txt` contains:

- **Signatures**: Linux symbol names for `CINSBotLocomotion::Approach`, `FaceTowards`, and `GetLocomotionInterface`
- **Functions**: DHooks detour definitions with parameter types (vectorptr, float)

### Key Vtable Offsets (Linux, from server_srv.so)

| Method | Offset | Used For |
|--------|--------|----------|
| `ILocomotion::Update` | 47 | Locomotion tick |
| `ILocomotion::Approach` | 50 | **Movement goal redirection** |
| `ILocomotion::Run` | 59 | Run mode |
| `ILocomotion::Stop` | 61 | Stop movement |
| `ILocomotion::FaceTowards` | 77 | Look direction |

These offsets are specific to Insurgency 2014's `CINSBotLocomotion` class and differ from TF2/L4D2 due to extra virtual methods in `INextBotEventResponder`.

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
cd insurgency-server
./server-files/insurgency/addons/sourcemod/scripting/spcomp \
  plugins/smartbots_bridge.sp \
  -i./server-files/insurgency/addons/sourcemod/scripting/include \
  -o./plugins/smartbots_bridge.smx
```

## Limitations

- `Approach()` does straight-line movement only. For navigation around walls, the Python AI must send local waypoints along a nav mesh path (not distant targets).
- Speed control via the `speed` field in commands is not yet implemented (bots use their default run speed).
- `FaceTowards` is not hooked yet, so bots face wherever their native AI decides.
