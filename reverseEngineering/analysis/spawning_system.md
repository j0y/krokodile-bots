# Insurgency 2014 Bot Spawning System

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

Insurgency 2014 has **two distinct bot spawning systems** that serve different game modes.

---

## System 1: Traditional Spawn Zone System

**Used by:** Checkpoint (coop), Push, Invasion — the "linear" objective modes

**How it works:**
- Map authors place `ins_spawnzone` brush entities and `ins_spawnpoint` / `CTeamSpawnPoint` entities at fixed map locations
- Spawn zones are tied to control points and advance/deactivate as objectives are captured
- Bots spawn in **waves** controlled by the `mp_wave_*` family of cvars
- Wave system uses dead-player-ratio (`mp_wave_dpr_*`) to trigger reinforcement waves
- Spawn protection: 30 seconds (`mp_spawnprotectontime`)
- Counter-attacks are triggered after captures (`mp_checkpoint_counterattack_delay` = 12s)

**Key cvars:**

| CVar | Default | Description |
|------|---------|-------------|
| `mp_wave_count_attackers` | 10 | Total waves for attackers |
| `mp_wave_count_defenders` | 20 | Total waves for defenders |
| `mp_wave_max_wait_attackers` | 30 | Max wave trigger time (attackers) |
| `mp_wave_max_wait_defenders` | 30 | Max wave trigger time (defenders) |
| `mp_wave_dpr_attackers` | 0 | Dead ratio triggering attacker wave |
| `mp_wave_dpr_defenders` | 0 | Dead ratio triggering defender wave |
| `mp_wave_spawn_instant` | 0 | Force instant spawning |
| `mp_checkpoint_counterattack_delay` | 12 | Counter-attack wave delay after cap |
| `mp_checkpoint_counterattack_delay_finale` | 20 | Counter-attack wave delay (finale) |
| `mp_checkpoint_counterattack_duration` | 65 | How long a counter-attack lasts |
| `mp_checkpoint_counterattack_duration_finale` | 120 | How long finale counter-attack lasts |
| `mp_checkpoint_counterattack_disable` | 0 | 1 to disable all counter-attacks |
| `mp_checkpoint_counterattack_always` | 0 | Always counter-attack (value = min player count) |

Bot counts scale with player count between `ins_bot_count_checkpoint_min` (5) and `ins_bot_count_checkpoint_max` (16).

---

## System 2: Nav Mesh Dynamic Spawn System

**Used by:** Outpost (natively), Hunt/Survival/Conquer (experimental)

**How it works:**
- `CNavSpawn` / `CINSNavSpawn` classes dynamically select spawn positions from the nav mesh
- Each `CINSNavArea` has a `GetSpawnScore(teamID)` function (at `0x006E3730`) that evaluates spawn quality
- `CNavSpawnSearchSurroundingCollector` (implements `ISearchSurroundingAreasFunctor`) fans out from candidate areas to find valid positions

### Class Hierarchy

```
CNavSpawn
  └── CINSNavSpawn          (vtable at 0x00B84390)

ISearchSurroundingAreasFunctor
  └── CNavSpawnSearchSurroundingCollector
```

### CINSNavArea Spawn-Related Fields

```
+0x160  uint   m_insFlags
                 0x0080 = inside (has roof overhead)
                 0x0100 = has associated spawn zone
+0x19C  float  m_spawnScore[0]     — cached spawn score, team 0
+0x1A0  float  m_spawnScore[1]     — cached spawn score, team 1
+0x1A4  float  m_spawnScoreTime[0] — spawn score cache timestamp, team 0
+0x1A8  float  m_spawnScoreTime[1] — spawn score cache timestamp, team 1
+0x258  int    m_associatedSpawnZone (init -1)
+0x25C  int    m_associatedControlPoint
```

### GetSpawnScore Algorithm (0x006E3730)

Signature: `float __thiscall CINSNavArea::GetSpawnScore(int teamID)`

1. **Cache check**: reads cached score at `+0x19C + teamIdx*4`, returns cached value if `curtime < cacheTime + nav_spawn_rescore_time`
2. **Base score** from `nav_spawn_score_base` (default 1)
3. **Spawn zone check**:
   - Friendly zone: adds `nav_spawn_score_friendly_spawn_bonus` with distance falloff (max dist from `nav_spawn_score_friendly_spawn_bonus_max_distance`)
   - Enemy zone: immediately returns score = -1.0
4. **Indoor bonus**: if `m_insFlags & 0x80` set, multiply by `nav_spawn_score_inside`
5. **Objective proximity**: if area flags `0x2004` set and CP matches active objective:
   - Control point: `nav_spawn_score_controlpoint_bonus` (default 2)
   - Cache point: `nav_spawn_score_cachepoint_bonus` (default 1)
   - Skipped entirely in Outpost mode (`IsOutpost()`)
6. **Hiding spot count**: adds hiding spot count from CNavArea `+0xD0`
7. **Visibility penalty**: if area visible to enemy team, multiply by `nav_spawn_score_potentially_visible` (default 0)
8. **Random jitter**: multiply by `RandomFloat(0.8, 1.2)` to prevent spawn patterns
9. Caches final score at `+0x19C + teamIdx*4` with current timestamp

Related functions:
- `InvalidateSpawnScore(int)` at `0x006E2FA0` — clears cached score
- `AssociateWithSpawnZone(CINSSpawnZone*)` at `0x006E...` — links area to spawn zone
- `ClearAssociatedSpawnZone()` — unlinks area

### Per-Mode Distance Constraints

| Mode | Min Distance | Max Distance | Start Frac |
|------|-------------|-------------|------------|
| Hunt | 4000 | 20000 | 1x |
| Outpost | 500 | 6000 | 3x |
| Conquer | 800 | 5000 | 2x |
| Survival | 500 | 5000 | 4x |

**No distance parameters exist for Checkpoint, Push, or Invasion.**

Start fracs (`nav_spawn_enemy_minimum_distance_frac_{mode}_start`) multiply the minimum distance at round start, creating a larger initial buffer before allowing closer spawns as the round progresses.

### Nav Spawn Configuration CVars

| CVar | Default | Description |
|------|---------|-------------|
| `nav_spawn_rescore_time` | 15 | Cache TTL for spawn scores (seconds) |
| `nav_spawn_recollect_time` | 60 | Max time before discarding and recollecting spawn points |
| `nav_spawn_score_base` | 1 | Starting score for spawn evaluation |
| `nav_spawn_score_friendly_spawn_bonus` | 1 | Bonus for being in friendly spawn zone |
| `nav_spawn_score_friendly_spawn_bonus_max_distance` | 500 | Max distance for spawn zone bonus falloff |
| `nav_spawn_score_inside` | 1 | Multiplier for indoor areas |
| `nav_spawn_score_controlpoint_bonus` | 2 | Bonus for areas near active control point |
| `nav_spawn_score_controlpoint_proximity` | 1500 | Control point bonus falloff distance |
| `nav_spawn_score_cachepoint_bonus` | 1 | Bonus for areas near active cache point |
| `nav_spawn_score_potentially_visible` | 0 | Multiplier penalty for enemy-visible areas |
| `nav_spawn_score_hiding_bonus` | 1 | Bonus for nav spawns derived from hiding spots |
| `nav_spawn_score_spawn_point_bonus` | 1 | Bonus for nav spawns derived from spawn points |
| `nav_spawn_score_enemy_player_proximity_bonus` | 2 | Max bonus for ideal enemy distance |
| `nav_spawn_score_enemy_player_proximity_distance` | 2000 | Ideal distance from enemies |
| `nav_spawn_score_enemy_player_proximity_falloff` | 3000 | Range to apply the distance bonus |
| `nav_spawn_score_random_max` | 1 | Random modifier max (prevents patterns) |
| `nav_spawn_score_random_min` | 0 | Random modifier min |
| `nav_spawn_score_discard` | 0 | Minimum score to be considered |
| `nav_spawn_min_area_size` | 128 | Minimum nav area tile size |
| `nav_spawn_min_spacing_sq` | 1024 | Minimum spacing between spawn points (squared) |
| `nav_spawn_min_bot_spawn_frequency` | 0 | Minimum time between each bot spawn |
| `nav_spawn_min_human_spawn_frequency` | 0 | Minimum time between each human spawn |
| `nav_spawn_max_per_controlpoint` | 16 | Max spawns per control point |
| `nav_spawn_min_per_controlpoint` | 8 | Min spawns per control point |
| `nav_spawn_fill_empty_rate` | 250 | Rate to fill empty spawn slots |
| `nav_spawn_rescore_rate` | 5 | How often to rescore existing spawns |
| `nav_spawn_proximity_penalty` | 20 | Penalty for spawns too close together |
| `nav_spawn_verify_rate` | 1 | Rate to verify spawn validity |
| `nav_spawn_stored_spawn_expiration` | 1 | Expiration time for stored spawns |
| `mp_spawnprotectiontime_navspawn` | 15 | Spawn protection time for nav spawns (seconds) |
| `mp_spawns_per_frame` | 6 | Maximum players to spawn per frame |

### Debug CVars

| CVar | Default | Description |
|------|---------|-------------|
| `nav_spawn_debug` | 0 | Turn on debug messages for spawn system (CHEAT) |
| `nav_spawn_debug_show_discards` | 0 | Show discarded spawn candidates |
| `nav_spawn_debug_show_spawns` | 0 | Show active spawn points (CHEAT) |
| `nb_nav_show_valid_spawn_points` | 0 | Show points with score > 11 (1=team_one, 2=team_two) (CHEAT) |

---

## Per-Mode Nav Spawning Toggle

| CVar | Default | Description |
|------|---------|-------------|
| `mp_outpost_nav_spawning` | **1** | Standard for Outpost — always enabled |
| `mp_hunt_nav_spawning` | **0** | *"Enable experimental spawning system?"* |
| `mp_survival_nav_spawning` | **0** | Experimental for Survival |

There is **no** `mp_checkpoint_nav_spawning`, `mp_push_nav_spawning`, or `mp_invasion_nav_spawning` cvar.

---

## Can `mp_hunt_nav_spawning` Be Used on Coop Checkpoint Maps?

**No.** Here's why:

1. **Mode-gated at the rules level** — `mp_hunt_nav_spawning` is only checked when `CINSRules::IsHunt()` returns true. On a checkpoint map (`IsCheckpoint()` is true instead), the cvar is never read. Setting it to 1 on a checkpoint server does nothing.

2. **No distance parameters for Checkpoint** — The nav spawn system reads `nav_spawn_enemy_minimum_distance_{mode}` and `nav_spawn_enemy_maximum_distance_{mode}`. These only exist for `hunt`, `outpost`, `conquer`, and `survival`. There is no `_checkpoint` variant, so even if the code path were reachable, it would fall back to defaults (`nav_spawn_min_player_distance_default` = 1500, `nav_spawn_max_player_distance_default` = 7000) which aren't tuned for checkpoint gameplay.

3. **Fundamentally different spawning model** — Checkpoint uses wave-based spawning from fixed map entities. The spawn zone layout advancing with objectives IS the core gameplay mechanic. Nav spawning replaces fixed zones with dynamic scoring — these are architecturally incompatible concepts for Checkpoint's design.

4. **Separate gamemode code paths** — `CINSBotGamemodeMonitor::InitialContainedAction()` dispatches to `CINSBotActionCheckpoint` (0x40 bytes) for checkpoint and `CINSBotActionHunt` (0x64 bytes) for hunt. They are completely separate action classes with different behavior trees. The spawning system selection happens at the `CINSRules` level before bot actions come into play.

5. **Hunt's distances are wrong for checkpoint maps** — Hunt uses min 4000 / max 20000 unit distances because it's designed for large open maps where bots ambush from far away. Checkpoint maps are tight, linear corridors where 4000 units might span the entire playable area.

### What Would Be Needed

To get nav-based dynamic spawning on checkpoint maps, you would need to either:
- **Modify the game DLL** to add a `mp_checkpoint_nav_spawning` code path with appropriate distance tuning and integration with the wave/counter-attack system
- **Run checkpoint maps in Hunt mode** — which changes the entire game flow (no wave system, no advancing spawn zones, no counter-attacks)

---

## Reinforcement System (CINSNextBotManager)

The `CINSNextBotManager` singleton at GOT symbol `INSNextBotManager` manages team-level reinforcement:

- `CanCallForReinforcements(team)` at `0x007628F0` — checks cooldown timer
- `CallForReinforcements(team)` at `0x00762A90` — starts cooldown timer for team
- `GetCallForReinforcementCooldown()` at `0x007629F0`:
  - Non-Survival: fixed 10.0 seconds
  - Survival: `RandomFloat(40, 50) + (-10 - (waveCount - 1) * scalingFactor)` — progressively shorter cooldowns in later waves

Cooldown timers:
- Team 2 (Security): timer at offset `+0xC8`
- Team 3 (Insurgent): timer at offset `+0xD4`
