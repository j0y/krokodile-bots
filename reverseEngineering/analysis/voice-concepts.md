# Insurgency Voice Concept System

Bots trigger voice lines via `SpeakConceptIfAllowed(int conceptId, ...)` at vtable offset `0x800` (index 512) on `CINSPlayer`. The engine's response rules system handles cooldowns, team-specific voice selection, and audio playback.

## How It Works

```
Concept ID (integer)
    → CINSPlayer::SpeakConceptIfAllowed()     [vtable + 0x800]
    → Response Rules Engine (criteria matching)
    → Sound group lookup (team, squad role, odds, cooldown)
    → Pick random .wav from group → play to clients
```

You cannot pick a specific voice line — only a concept. The engine picks randomly from the matching sound group. The `odds` field in response rules means some concepts only produce audio a fraction of the time.

## Response Rules Files (in insurgency_misc VPK)

| File | Purpose |
|------|---------|
| `scripts/talker/response_criteria.txt` | Criteria definitions (team, squad, damage type, etc.) |
| `scripts/talker/response_rules.txt` | Base rules + syntax reference |
| `scripts/talker/bot_chatter.txt` | Bot-specific rules (coop mode) |
| `scripts/talker/team_security.txt` | Security team sound groups |
| `scripts/talker/team_insurgent.txt` | Insurgent team sound groups |
| `scripts/talker/radial_sec.txt` | Security radial menu voice lines |
| `scripts/talker/radial_ins.txt` | Insurgent radial menu voice lines |
| `scripts/ins_sounds_responses_security.txt` | Security sound definitions |
| `scripts/ins_sounds_responses_insurgent.txt` | Insurgent sound definitions |

## Team-Specific Behavior

Voice lines are **team-specific**. The response rules match on `OnSecurityTeam` (team 2) or `OnInsurgentTeam` (team 3). Security bots also distinguish **squad leader** (slot 0) from **subordinates**.

Many rules require `HasNearbyTeammates` — if no teammates are nearby, the bot stays silent.

### Example Rule (from bot_chatter.txt)

```
Response BotSecurityCoop_HeardSomething_Lead
{
    PermitRepeats
    speak "Bot.Security_Lead.HeardSomething" noscene predelay "1.5,3.0" respeakdelay "5.0,10.0" odds 40
}

Rule BotSecurityCoop_HeardSomething_Lead
{
    criteria ConceptHeardSomething OnSecurityTeam IsSquadLeader HasNearbyTeammates
    response BotSecurityCoop_HeardSomething_Lead
}
```

## Complete Concept ID Table

Extracted from `g_pszMPConcepts[]` array in `server_srv.so`. IDs 0–62 are base Source SDK, 63–104 are Insurgency-specific.

### Base Source SDK Concepts (0–62)

| ID | Hex | TLK Name | Notes |
|----|-----|----------|-------|
| 0 | 0x00 | TLK_FIREWEAPON | Firing weapon (Security bots use this for callouts) |
| 1 | 0x01 | TLK_HURT | Taking damage |
| 2 | 0x02 | TLK_PLAYER_EXPRESSION | Player expression |
| 3 | 0x03 | TLK_WINDMINIGUN | TF2 heritage, unused |
| 4 | 0x04 | TLK_FIREMINIGUN | TF2 heritage, unused |
| 5 | 0x05 | TLK_PLAYER_MEDIC | "Medic!" |
| 6 | 0x06 | TLK_DETONATED_OBJECT | Detonated object |
| 7 | 0x07 | TLK_KILLED_PLAYER | Killed an enemy |
| 8 | 0x08 | TLK_KILLED_OBJECT | Killed an object |
| 9 | 0x09 | TLK_PLAYER_PAIN | Pain vocalization |
| 10 | 0x0a | TLK_PLAYER_ATTACKER_PAIN | Attacker pain |
| 11 | 0x0b | TLK_PLAYER_TAUNT | Taunt |
| 12 | 0x0c | TLK_PLAYER_HELP | "Help!" |
| 13 | 0x0d | TLK_PLAYER_GO | "Go!" |
| 14 | 0x0e | TLK_PLAYER_MOVEUP | "Move up!" |
| 15 | 0x0f | TLK_PLAYER_LEFT | "Left!" |
| 16 | 0x10 | TLK_PLAYER_RIGHT | "Right!" |
| 17 | 0x11 | TLK_PLAYER_YES | "Yes" / affirmative |
| 18 | 0x12 | TLK_PLAYER_NO | "No" / negative |
| 19 | 0x13 | TLK_PLAYER_INCOMING | "Incoming!" |
| 20 | 0x14 | TLK_PLAYER_CLOAKEDSPY | TF2 heritage, unused |
| 21 | 0x15 | TLK_PLAYER_SENTRYAHEAD | TF2 heritage, unused |
| 22 | 0x16 | TLK_PLAYER_TELEPORTERHERE | TF2 heritage, unused |
| 23 | 0x17 | TLK_PLAYER_DISPENSERHERE | TF2 heritage, unused |
| 24 | 0x18 | TLK_PLAYER_SENTRYHERE | TF2 heritage, unused |
| 25 | 0x19 | TLK_PLAYER_ACTIVATECHARGE | TF2 heritage, unused |
| 26 | 0x1a | TLK_PLAYER_CHARGEREADY | TF2 heritage, unused |
| 27 | 0x1b | TLK_PLAYER_TAUNTS | Taunt variations |
| 28 | 0x1c | TLK_PLAYER_BATTLECRY | Battle cry |
| 29 | 0x1d | TLK_PLAYER_CHEERS | Cheer |
| 30 | 0x1e | TLK_PLAYER_JEERS | Jeer |
| 31 | 0x1f | TLK_PLAYER_POSITIVE | Positive reaction |
| 32 | 0x20 | TLK_PLAYER_NEGATIVE | Negative reaction |
| 33 | 0x21 | TLK_PLAYER_NICESHOT | "Nice shot!" |
| 34 | 0x22 | TLK_PLAYER_GOODJOB | "Good job!" |
| 35 | 0x23 | TLK_MEDIC_STARTEDHEALING | TF2 heritage, unused |
| 36 | 0x24 | TLK_MEDIC_CHARGEREADY | TF2 heritage, unused |
| 37 | 0x25 | TLK_MEDIC_STOPPEDHEALING | TF2 heritage, unused |
| 38 | 0x26 | TLK_MEDIC_CHARGEDEPLOYED | TF2 heritage, unused |
| 39 | 0x27 | TLK_FLAGPICKUP | Flag pickup |
| 40 | 0x28 | TLK_FLAGCAPTURED | Flag captured |
| 41 | 0x29 | TLK_ROUND_START | Round start |
| 42 | 0x2a | TLK_SUDDENDEATH_START | Last man standing |
| 43 | 0x2b | TLK_ONFIRE | On fire |
| 44 | 0x2c | TLK_STALEMATE | Stalemate |
| 45 | 0x2d | TLK_BUILDING_OBJECT | TF2 heritage, unused |
| 46 | 0x2e | TLK_LOST_OBJECT | Lost object |
| 47 | 0x2f | TLK_SPY_SAPPER | TF2 heritage, unused |
| 48 | 0x30 | TLK_TELEPORTED | TF2 heritage, unused |
| 49 | 0x31 | TLK_LOST_CONTROL_POINT | Lost control point |
| 50 | 0x32 | TLK_CAPTURED_POINT | Captured point |
| 51 | 0x33 | TLK_CAPTURE_BLOCKED | Capture blocked |
| 52 | 0x34 | TLK_HEALTARGET_STARTEDHEALING | TF2 heritage, unused |
| 53 | 0x35 | TLK_HEALTARGET_CHARGEREADY | TF2 heritage, unused |
| 54 | 0x36 | TLK_HEALTARGET_STOPPEDHEALING | TF2 heritage, unused |
| 55 | 0x37 | TLK_HEALTARGET_CHARGEDEPLOYED | TF2 heritage, unused |
| 56 | 0x38 | TLK_MINIGUN_FIREWEAPON | TF2 heritage, unused |
| 57 | 0x39 | TLK_DIED | Death vocalization |
| 58 | 0x3a | TLK_PLAYER_THANKS | "Thanks" |
| 59 | 0x3b | TLK_CART_MOVING_FORWARD | TF2 heritage, unused |
| 60 | 0x3c | TLK_CART_MOVING_BACKWARD | TF2 heritage, unused |
| 61 | 0x3d | TLK_CART_STOP | TF2 heritage, unused |
| 62 | 0x3e | TLK_ATE_FOOD | TF2 heritage, unused |

### Insurgency-Specific Concepts (63–104)

| ID | Hex | TLK Name | Voice Line | Bot Code Source |
|----|-----|----------|------------|-----------------|
| 63 | 0x3f | TLK_HEARD_SOMETHING | "I hear something" | CINSBotInvestigationMonitor |
| 64 | 0x40 | TLK_RELOADING | "Reloading!" | CINSBotReload |
| 65 | 0x41 | TLK_THROWING_GRENADE | "Frag out!" | — |
| 66 | 0x42 | TLK_PLANTING_EXPLOSIVE | Planting IED/C4 | — |
| 67 | 0x43 | TLK_DETONATING_EXPLOSIVE | Detonating | — |
| 68 | 0x44 | TLK_FIRING_PROJECTILE | RPG/GL launch | — |
| 69 | 0x45 | TLK_PLAYER_IDLE | Idle chatter | CINSBotPatrol |
| 70 | 0x46 | TLK_FIREWEAPON_SUPPRESSION | Suppressive fire callout | — |
| 71 | 0x47 | TLK_INVESTIGATE | Investigating area | CINSBotInvestigate (no threat) |
| 72 | 0x48 | TLK_FRIENDLY_FIRE | "Watch your fire!" | — |
| 73 | 0x49 | TLK_FRIENDLY_DOWN | "Man down!" | CINSBotInvestigationMonitor |
| 74 | 0x4a | TLK_BEING_SUPPRESSED | "I'm pinned down!" | — |
| 75 | 0x4b | TLK_FLASHED | "I can't see!" | CINSBotFlashed |
| 76 | 0x4c | TLK_SPOTTED_RPG | "RPG!" | CINSBotFireRPG |
| 77 | 0x4d | TLK_BOT_LOST_SIGHT | Lost visual on enemy | — |
| 78 | 0x4e | TLK_AOE_GRENADE_DETONATE | Grenade detonation nearby | — |
| 79 | 0x4f | TLK_RADIAL_AFFIRMATIVE | "Copy" / "Roger" | — |
| 80 | 0x50 | TLK_RADIAL_NEGATIVE | "Negative" | — |
| 81 | 0x51 | TLK_RADIAL_ENEMY | "Contact!" / "Enemy spotted" | — |
| 82 | 0x52 | TLK_RADIAL_MOVING | "Moving!" | — |
| 83 | 0x53 | TLK_RADIAL_AREA_HOSTILE | "Area is hostile" | — |
| 84 | 0x54 | TLK_RADIAL_NEED_BACKUP | "Need backup!" / "Need support" | — |
| 85 | 0x55 | TLK_RADIAL_ENEMY_DOWN | "Enemy down" / "Got him" | — |
| 86 | 0x56 | TLK_RADIAL_COVERING | "Covering!" | — |
| 87 | 0x57 | TLK_RADIAL_AREA_CLEAR | "Area clear" | — |
| 88 | 0x58 | TLK_RADIAL_ONTHEWAY | "On my way" | — |
| 89 | 0x59 | TLK_RADIAL_OBJECTIVE | "Hit the objective" | — |
| 90 | 0x5a | TLK_RADIAL_OPEN_FIRE | "Open fire!" | (commented out in rules) |
| 91 | 0x5b | TLK_RADIAL_MOVE_DIRECTION | Directional move callout | — |
| 92 | 0x5c | TLK_RADIAL_FLANK_LEFT | "Flank left!" | — |
| 93 | 0x5d | TLK_RADIAL_FLANK_RIGHT | "Flank right!" | — |
| 94 | 0x5e | TLK_RADIAL_GET_READY | "Get ready!" | — |
| 95 | 0x5f | TLK_RADIAL_CEASE_FIRE | "Cease fire!" | — |
| 96 | 0x60 | TLK_RADIAL_WATCH_AREA | "Watch that area" | — |
| 97 | 0x61 | TLK_RADIAL_GO | "Go go go!" | — |
| 98 | 0x62 | TLK_RADIAL_REPORT_STATUS | "Report in" | — |
| 99 | 0x63 | TLK_RADIAL_STICK_TOGETHER | "Stick together" | — |
| 100 | 0x64 | TLK_RADIAL_SPREAD_OUT | "Spread out" | — |
| 101 | 0x65 | TLK_RADIAL_HOLD_POSITION | "Hold position" | — |
| 102 | 0x66 | TLK_INVESTIGATE_AGGRESSIVE | Aggressive investigation (threat) | CINSBotInvestigate (threat visible) |
| 103 | 0x67 | TLK_FLASHLIGHT_SPOTTED | Spotted a flashlight | — |
| 104 | 0x68 | TLK_INCOMING_GRENADE | "Grenade!" | CINSBotRetreat, CINSBotRetreatToCover |

### Dangerous IDs

| ID | Hex | Effect |
|----|-----|--------|
| 125 | 0x7d | **Crashes the server** — out of bounds in concept array? |

## Concepts Used by Native Bot Actions

These are the concept IDs found in the decompiled bot action classes:

| Bot Action Class | Concept ID | TLK Name |
|-----------------|-----------|----------|
| CINSBotInvestigationMonitor | 63 (0x3f) | TLK_HEARD_SOMETHING |
| CINSBotReload | 64 (0x40) | TLK_RELOADING |
| CINSBotPatrol | 69 (0x45) | TLK_PLAYER_IDLE |
| CINSBotInvestigate (no threat) | 71 (0x47) | TLK_INVESTIGATE |
| CINSBotInvestigationMonitor | 73 (0x49) | TLK_FRIENDLY_DOWN |
| CINSBotFlashed | 75 (0x4b) | TLK_FLASHED |
| CINSBotFireRPG | 76 (0x4c) | TLK_SPOTTED_RPG |
| CINSBotInvestigate (threat) | 102 (0x66) | TLK_INVESTIGATE_AGGRESSIVE |
| CINSBotRetreat | 104 (0x68) | TLK_INCOMING_GRENADE |
| CINSBotRetreatToCover | 104 (0x68) | TLK_INCOMING_GRENADE |

## Tactical AI Usage (Phase 2)

Best concepts for smart bot callouts:

| Situation | Concept ID | What Players Hear |
|-----------|-----------|-------------------|
| Defending position | 101 (0x65) | "Hold position" |
| Moving to objective | 82 (0x52) | "Moving!" |
| Enemy contact | 81 (0x51) | "Contact!" |
| Enemy killed | 85 (0x55) | "Enemy down" |
| Need help | 84 (0x54) | "Need backup!" |
| Covering teammate | 86 (0x56) | "Covering!" |
| Area secured | 87 (0x57) | "Area clear" |
| Flanking | 92/93 | "Flank left/right!" |
| Preparing assault | 94 (0x5e) | "Get ready!" |
| Charge | 97 (0x61) | "Go go go!" |
| Retreat | 104 (0x68) | "Grenade!" (native retreat trigger) |
| Suppressed | 74 (0x4a) | "I'm pinned down!" |
| Spreading out | 100 (0x64) | "Spread out" |
| Regrouping | 99 (0x63) | "Stick together" |

## Console Commands

```
smartbots_voice_test       — Toggle cycling through all concept IDs (3s interval)
smartbots_voice <id>       — Fire a specific concept on all bots
smartbots_voice_reset      — Reset cycle counter to 0
```
