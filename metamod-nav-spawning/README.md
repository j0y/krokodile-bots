# Nav Mesh Spawning Extension

Metamod:Source extension that overrides default spawn positions for defender bots (team Insurgents) in Insurgency 2014 co-op. When a bot spawns, it uses a multi-source BFS over the nav mesh seeded from attacker player positions, scoring candidates by distance from players (bell curve), visibility, and indoor/outdoor, then teleports the bot to the best position.

## How It Works

1. Detours `CINSNextBot::Spawn()` — the original spawn runs first (wave system, loadout, model)
2. Multi-source BFS expands outward from all attacker (human) player nav areas
3. Each candidate area is scored with a distance bell curve (peaking at `navspawn_ideal_dist`), visibility penalty, and indoor bonus
4. The bot is teleported to the highest-scoring area

During counter-attacks, the ideal distance shifts out by 1.5x to push bots farther from players.

## Console Variables

All variables can be changed at runtime via the server console or `rcon`.

| ConVar | Default | Description |
|---|---|---|
| `navspawn_enabled` | `0` | Master toggle. Set to `1` to enable nav-based spawning. When `0`, bots spawn at their default engine positions. |
| `navspawn_ideal_dist` | `2000` | Peak of the distance scoring curve (units from nearest player). Areas at this distance score highest. |
| `navspawn_dist_falloff` | `1500` | How quickly score drops from ideal distance. Score = `max(0.1, 1.0 - |dist - ideal| / falloff)`. |
| `navspawn_min_player_dist` | `800` | Hard minimum distance (units) from any human player. Areas closer are never considered. |
| `navspawn_max_player_dist` | `4000` | Hard maximum distance (units) from nearest human player. Areas farther are pruned from BFS. |
| `navspawn_debug` | `0` | Set to `1` to log spawn decisions to the server console (position, score, distance, candidate/visited/seed counts). |

## Scoring Details

- **Distance curve**: Bell curve peaking at `navspawn_ideal_dist`, falling off over `navspawn_dist_falloff`. During counter-attacks, ideal distance is multiplied by 1.5x.
- **Visibility**: Areas visible from a human player's nav area get a 90% score penalty (factor 0.1)
- **Indoor bonus**: Indoor areas (nav flag `0x80`) get a 1.5x multiplier
- **Random jitter**: 0.85x-1.15x random factor to prevent predictable patterns

## Usage

```
# Enable in server console
navspawn_enabled 1

# See what the extension is doing
navspawn_debug 1

# Move ideal spawn distance closer to players
navspawn_ideal_dist 1500

# Push bots farther from players
navspawn_min_player_dist 1200
```
