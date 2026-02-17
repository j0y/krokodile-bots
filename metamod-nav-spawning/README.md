# Nav Mesh Spawning Extension

Metamod:Source extension that overrides default spawn positions for defender bots (team Insurgents) in Insurgency 2014 co-op. When a bot spawns, it uses a BFS over the nav mesh to find a tactically scored position near the current objective, then teleports the bot there.

## How It Works

1. Detours `CINSNextBot::Spawn()` — the original spawn runs first (wave system, loadout, model)
2. BFS expands outward from the current objective through nav mesh areas
3. Each candidate area is scored based on distance to players, visibility, indoor/outdoor, and proximity to objective
4. The bot is teleported to the highest-scoring area

During counter-attacks, scoring shifts to push bots farther from the objective and away from players.

## Console Variables

All variables can be changed at runtime via the server console or `rcon`.

| ConVar | Default | Description |
|---|---|---|
| `navspawn_enabled` | `0` | Master toggle. Set to `1` to enable nav-based spawning. When `0`, bots spawn at their default engine positions. |
| `navspawn_radius` | `2500` | BFS search radius around the current objective (in Source units). Areas farther than this from the objective are ignored. |
| `navspawn_min_player_dist` | `800` | Minimum distance (units) a spawn candidate must be from any human player. Prevents bots from spawning on top of players. Automatically multiplied by 1.5x during counter-attacks. |
| `navspawn_max_player_dist` | `3000` | Maximum distance (units) from at least one human player. Ensures bots don't spawn in completely irrelevant parts of the map. |
| `navspawn_debug` | `0` | Set to `1` to log spawn decisions to the server console (chosen position, score, candidate/visited counts). |

## Scoring Details

- **Visibility**: Areas visible from a human player's nav area get a 90% score penalty (factor 0.1)
- **Indoor bonus**: Indoor areas (nav flag `0x80`) get a 1.5x multiplier
- **Objective proximity**: Closer to objective scores slightly higher (normal), farther scores higher (counter-attack)
- **Random jitter**: 0.85x-1.15x random factor to prevent predictable patterns

## Usage

```
# Enable in server console
navspawn_enabled 1

# See what the extension is doing
navspawn_debug 1

# Tighten the spawn zone around objectives
navspawn_radius 1500

# Push bots farther from players
navspawn_min_player_dist 1200
```
