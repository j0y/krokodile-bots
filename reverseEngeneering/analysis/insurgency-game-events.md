# Insurgency 2014 Game Events Reference

Source: `resource/ModEvents.res` (v2.4.0.9), `gameevents.res`, `serverevents.res`
From: [jaredballou/insurgency-data](https://github.com/jaredballou/insurgency-data/tree/master/mods/insurgency/2.4.0.9/resource)

**IMPORTANT**: Events must be registered with deferred `AddListener()` — call from first GameFrame tick, NOT during plugin `Load()`. See [metamod-build-notes.md](metamod-build-notes.md).

---

## Round Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `round_start` | `priority` (short), `timelimit` (short), `lives` (short), `gametype` (short) | Fires at preround (freeze time) |
| `round_freeze_end` | *(none)* | Freeze time ended, round is playable. **Use this for "active" phase** (`round_begin` does not fire in coop) |
| `round_begin` | *(none)* | May not fire in all game modes |
| `round_end` | `reason` (byte), `winner` (byte), `message` (string), `message_string` (string) | |
| `round_restart` | *(none)* | |
| `round_timer_changed` | `delta` (float) | Timer modified |
| `round_level_advanced` | `level` (short) | Checkpoint/push: attackers advanced to next area |

## Objective Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `controlpoint_initialized` | *(none)* | CP system ready |
| `controlpoint_captured` | `priority` (short), `cp` (byte), `cappers` (string), `cpname` (string), `team` (byte), `oldteam` (byte) | |
| `controlpoint_neutralized` | `priority` (short), `cp` (byte), `cappers` (string), `cpname` (string), `team` (byte), `oldteam` (byte) | |
| `controlpoint_starttouch` | `area` (byte), `object` (short), `player` (short), `team` (short), `owner` (short), `type` (short) | Player enters cap zone. `area` = CP index |
| `controlpoint_endtouch` | `owner` (short), `player` (short), `team` (short), `area` (byte) | Player leaves cap zone |
| `controlpoint_regroup_available` | `cp` (byte), `team` (short) | |
| `controlpoint_regroup_triggered` | `cp` (byte), `team` (short), `player` (short) | |
| `object_destroyed` | `team` (byte), `attacker` (byte), `cp` (short), `index` (short), `type` (byte), `weapon` (string), `weaponid` (short), `assister` (byte), `attackerteam` (byte) | Cache destroyed |

## Player Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `player_death` | `deathflags` (short), `attacker` (short), `customkill` (short), `lives` (short), `attackerteam` (short), `damagebits` (long), `weapon` (string), `weaponid` (short), `userid` (short), `priority` (short), `team` (short), `x`/`y`/`z` (float), `assister` (short) | Has death position! |
| `player_hurt` | `priority` (short), `attacker` (short), `dmg_health` (short), `health` (byte), `damagebits` (long), `hitgroup` (short), `weapon` (string), `weaponid` (short), `userid` (short) | |
| `player_spawn` | `teamnum` (short), `userid` (short) | From gameevents.res |
| `player_suppressed` | `attacker` (short), `victim` (short) | |
| `player_avenged_teammate` | `avenger_id` (short), `avenged_player_id` (short) | |
| `player_first_spawn` | `userid` (short) | |
| `player_pick_squad` | `squad_slot` (byte), `squad` (byte), `userid` (short), `class_template` (string) | |
| `player_falldamage` | `userid` (short), `damage` (float) | |
| `player_blind` | `userid` (short) | Flashbang |
| `player_footstep` | `userid` (short) | |
| `player_jump` | `userid` (short) | |
| `player_drop` | `userid` (short), `entity` (short) | |
| `player_receive_supply` | `userid` (short), `ammount` (short) | Typo is in original |
| `player_team` | `userid` (short), `team` (byte), `oldteam` (byte), `disconnect` (bool), `silent` (bool), `isbot` (bool), `autoteam` (bool) | From gameevents.res |

## Weapon Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `weapon_fire` | `weaponid` (short), `userid` (short), `shots` (byte) | |
| `weapon_fire_on_empty` | `weapon` (string), `userid` (short) | |
| `weapon_outofammo` | `userid` (short) | |
| `weapon_reload` | `userid` (short) | |
| `weapon_pickup` | `weaponid` (short), `userid` (short) | |
| `weapon_deploy` | `weaponid` (short), `userid` (short) | |
| `weapon_holster` | `weaponid` (short), `userid` (short) | |
| `weapon_ironsight` | `weaponid` (short), `userid` (short) | ADS enter |
| `weapon_lower_sight` | `weaponid` (short), `userid` (short) | ADS exit |
| `weapon_firemode` | `weaponid` (short), `userid` (short), `firemode` (byte) | Semi/auto toggle |

## Grenade / Explosive Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `grenade_thrown` | `entityid` (long), `userid` (short), `id` (short) | |
| `grenade_detonate` | `userid` (short), `effectedEnemies` (short), `x`/`y`/`z` (float), `entityid` (long), `id` (short) | Has position + affected count |
| `missile_launched` | `entityid` (long), `userid` (short), `id` (short) | RPG |
| `missile_detonate` | `userid` (short), `x`/`y`/`z` (float), `entityid` (long), `id` (short) | |
| `smoke_grenade_expire` | `userid` (short), `x`/`y`/`z` (float), `entityid` (long), `id` (short) | Smoke cleared |

## Fire Support Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `artillery_requested` | `requesting_player` (short), `radio_player` (short), `team` (short), `type` (string), `lethal` (bool), `target_x`/`y`/`z` (float) | Has target coords! |
| `artillery_called` | *(same as requested)* | Confirmed incoming |
| `artillery_failed` | `requesting_player` (short), `radio_player` (short), `team` (short), `type` (string), `lethal` (bool), `reason` (string) | |

## Game Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `game_start` | `priority` (short) | |
| `game_end` | `team2_score` (short), `winner` (byte), `team1_score` (short) | |
| `game_newmap` | `mapname` (string) | |
| `game_teams_switched` | *(none)* | |

## Misc Events

| Event | Parameters | Notes |
|-------|-----------|-------|
| `nav_blocked` | `area` (long), `blocked` (bool) | Nav mesh area blocked |
| `enter_spawnzone` | `userid` (short) | |
| `exit_spawnzone` | `userid` (short) | |
| `door_moving` | `entindex` (long), `userid` (short) | |
| `flag_pickup/drop/captured/returned/reset` | various | Flag game mode |

## Server Events (serverevents.res)

| Event | Parameters | Notes |
|-------|-----------|-------|
| `player_connect` | `name`, `index`, `userid`, `networkid`, `address`, `bot` | |
| `player_disconnect` | `userid`, `reason`, `name`, `networkid`, `bot` | |
| `player_activate` | `userid` | |
| `server_spawn` | `hostname`, `address`, `port`, `game`, `mapname`, `maxplayers`, `os`, `dedicated`, `password` | |

## Events We Currently Hook (game_events.cpp)

```
round_start          → phase = "preround", reset objectives
round_freeze_end     → phase = "active"
round_begin          → phase = "active" (backup, may not fire)
round_end            → phase = "over"
controlpoint_captured    → objectives++, clear cap flag
controlpoint_starttouch  → set capping CP (if enemy team)
controlpoint_endtouch    → clear capping CP (if enemy team)
```

## Potentially Useful Events (not yet hooked)

- `player_death` — death position (x,y,z) for area-enriched kill tracking
- `round_level_advanced` — push mode progression
- `object_destroyed` — cache destruction in coop
- `artillery_called` — incoming fire support with target coords (bots could take cover)
- `grenade_detonate` — explosion position + affected enemies
- `nav_blocked` — dynamic pathfinding changes
