# Bot Senses System — CINSBotVision

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

CINSBotVision is the sole perception interface for bots. It handles visual
detection, threat ranking, silhouette recognition, line-of-sight / line-of-fire
checks, and flash-bang blindness. All senses feed into a single
`CKnownEntity` database inside the parent `IVision` class.

---

## Object Layout

Size: ~640 bytes (0x280). Inherits IVision.

```
+0x000  vtable pointer (CINSBotVision vtable)
...     IVision base (known-entity database, timers, etc.)
+0x144  (4 bytes)  unknown, zeroed in ctor
+0x148  (4 bytes)  unknown, zeroed in ctor
+0x14C  (4 bytes)  unknown, zeroed in ctor
+0x150  (4 bytes)  unknown, zeroed in ctor
+0x154  (4 bytes)  unknown, zeroed in ctor
+0x158  CountdownTimer  (silhouette update timer, 0.25s period)
+0x164  CountdownTimer  (threat recalculation timer, 0.25s period)
+0x170  CountdownTimer  (timer slot 3)
+0x17C  CountdownTimer  (timer slot 4)
+0x188  CountdownTimer  (timer slot 5)
+0x194  int[48]         silhouette-type cache per edict (indices 1..48)
                        values: -1=unknown, 0=dark, 1=fuzzy, 2=clear
+0x25C  CountdownTimer  (threat recalc cooldown, fires every 0.25s)
+0x268  EHANDLE         primary known threat (all senses)
+0x26C  EHANDLE         primary visible threat (visible only)
+0x270  float           last threat recalc time (gpGlobals->curtime + 2.0)
+0x274  float           highest threat score (from GetAssessmentScore)
+0x278  float           total threat score (sum of all assessments)
+0x27C  float           highest visible-only threat score
```

EHANDLE format: lower 16 bits = edict index, upper 16 bits = serial number.
Value 0xFFFFFFFF = invalid/no entity.

---

## Functions

### Core Update Loop

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0076ADB0 | Update | `void __thiscall (CINSBotVision*)` |

Called every bot tick by the NextBot framework. Flow:
1. Calls `IVision::Update()` (parent — maintains known-entity database)
2. If no valid cached primary threat → `CalculatePrimaryThreat()` immediately
3. Else if `CountdownTimer[0x25C]` expired (0.25s) → `CalculatePrimaryThreat()`
4. If debug cvar `ins_bot_debug_silhouette` active → renders debug overlays
5. `UpdateSilhouettes()` — refreshes silhouette type for all known entities

### Threat Assessment

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0076AAD0 | CalculatePrimaryThreat | `void __thiscall (CINSBotVision*)` |
| 0x0076A620 | GetAssessmentScore | `float __thiscall (CINSBotVision*, INSBotThreatAssessment*, int)` |
| 0x00769B60 | GetCombatIntensity | `float __thiscall (CINSBotVision*)` |

**CalculatePrimaryThreat** builds a `CINSThreatAssessment` (vtable at `+0x4329FD`
relative to GOT), iterates all known threats, scores each via
`GetAssessmentScore`, and stores:
- Best overall threat → EHANDLE at `+0x26C`
- Best visible-only threat → EHANDLE at `+0x268`
- Highest score → `+0x274`
- Total score → `+0x278`

Recalculation is gated to once per 0.25 seconds. If the cached primary threat
dies, it falls back to `IVision::GetPrimaryKnownThreat()`.

**GetAssessmentScore** computes a weighted sum from the `INSBotThreatAssessment`
entry (0x1C bytes per entry):

```
INSBotThreatAssessment entry layout:
+0x00  byte   isVisible (0 or 1)
+0x01  byte   isLookingAtMe
+0x02  byte   isFiring
+0x03  byte   isAimingAtMe
+0x04  byte   isCloseRange
+0x08  float  distanceToMe (score component)
+0x0C  float  distanceToDanger (score component)
+0x10  float  distanceToOther (score component)
+0x14  float  proximityWeight (base weight multiplied by modifiers)
+0x18  int    playerIndex (edict index of this threat)

Score formula:
  score = distanceToMe + distanceToDanger + distanceToOther + proximityWeight
  if isAimingAtMe:  score += 2 * proximityWeight
  if isCloseRange:  score += 1.25 * proximityWeight
  if isLookingAtMe: score += 1.25 * proximityWeight
  if isFiring:      score *= 5.0
```

**GetCombatIntensity** returns `clamp(totalThreatScore * 0.002, 0.0, 1.0)`.
A value of 1.0 means heavy firefight. Used by the arousal system and decision
timers throughout the behavior tree.

### Threat Retrieval

| Address | Function | Signature |
|---------|----------|-----------|
| 0x007691E0 | GetPrimaryKnownThreat | `CKnownEntity* __thiscall (CINSBotVision*, bool onlyVisible)` |
| 0x00769130 | GetPrimaryKnownThreatCached | `CKnownEntity* __thiscall (CINSBotVision*, bool onlyVisible)` |

`GetPrimaryKnownThreat` is a thin wrapper around `GetPrimaryKnownThreatCached`.

The cached version checks if the stored EHANDLE (`+0x26C` or `+0x268`) is still
valid via the entity list. If valid, resolves and returns the `CKnownEntity*`
from the `IVision` known-entity database. If stale, falls back to the parent
`IVision::GetPrimaryKnownThreat()`.

**IVision vtable offset for GetPrimaryKnownThreat: 0xD0** (used by extension).

### Vision Checks

| Address | Function | Signature |
|---------|----------|-----------|
| 0x007687A0 | IsAbleToSee (entity) | `bool __thiscall (CINSBotVision*, CBaseEntity*, int checkFOV, Vector* outVisibleSpot)` |
| 0x00767BE0 | IsAbleToSee (position) | `bool __thiscall (CINSBotVision*, const Vector&, int checkFOV)` |
| 0x00768D70 | IsLineOfSightClear | `bool __thiscall (CINSBotVision*, const Vector&)` |
| 0x00768520 | IsLineOfSightClearToEntity | `bool __thiscall (CINSBotVision*, CBaseEntity*, Vector* outVisibleSpot)` |
| 0x00769C60 | IsLineOfFireClear | `bool __thiscall (CINSBotVision*, const Vector&, Vector)` |

**IVision vtable offset for IsAbleToSee (entity): 260 (0x104)** (used by extension).

**IsAbleToSee (entity)** pipeline (profiled under "NextBotExpensive"):
1. Validate entity alive via `CBaseEntity::IsAlive` vtable call
2. Range check: `INextBot::IsRangeGreaterThan` using `GetMaxVisionRange()`
3. Fog check: `CBaseCombatCharacter::IsHiddenByFog`
4. If `checkFOV == 0` (USE_FOV): check `IsInFieldOfView` (vtable `+0x118`)
5. If target is a player: try `GetEntityViewPosition` first (head position)
6. Fallback: try `WorldSpaceCenter` (torso)
7. Final: `IsLineOfSightClear` raycast

Returns true if visible; if `outVisibleSpot != NULL`, writes the position
from which the entity is visible.

**IsLineOfFireClear** traces a bullet path accounting for world geometry and
other entities. Used by combat actions to decide whether to fire.

### Field of View

| Address | Function | Signature |
|---------|----------|-----------|
| 0x00767E50 | GetDefaultFieldOfView | `float __thiscall (CINSBotVision*)` |
| 0x00767B60 | GetMaxVisionRange | `float (void)` |

**GetMaxVisionRange** returns hardcoded **5000.0** units.

**GetDefaultFieldOfView** computes FOV from ConVars and difficulty:

```
Base FOV:
  if attacking: bot_fov_attack_base
  else:         bot_fov_idle_base

Difficulty multiplier (applied to base):
  easy (0):       bot_fov_frac_easy
  normal (1):     1.0 (no multiplier)
  hard (2):       bot_fov_frac_hard
  impossible (3): bot_fov_frac_impossible

Survival scaling (if survival mode):
  progress = clamp((survivalLevel - 1) * someConst, 0, 1)
  final = base * lerp(bot_fov_frac_survival_start, bot_fov_frac_survival_end, progress)
```

ConVars controlling FOV:

| ConVar | Description |
|--------|-------------|
| `bot_fov_idle_base` | Base FOV when not in combat |
| `bot_fov_attack_base` | Base FOV when attacking |
| `bot_fov_frac_easy` | FOV multiplier for easy difficulty |
| `bot_fov_frac_hard` | FOV multiplier for hard difficulty |
| `bot_fov_frac_impossible` | FOV multiplier for impossible difficulty |
| `bot_fov_frac_survival_start` | FOV multiplier at survival level 1 (default 0) |
| `bot_fov_frac_survival_end` | FOV multiplier at survival level 30 (default 1) |

### Recognition Time

| Address | Function | Signature |
|---------|----------|-----------|
| 0x007682E0 | GetMinRecognizeTime | `float __thiscall (CINSBotVision*)` |

Time in seconds before a visible entity becomes a "known" threat. Computed as:

```
base = bot_recognizetime_base

Difficulty multiplier:
  easy (0):       bot_recognizetime_frac_easy
  normal (1):     1.0
  hard (2):       bot_recognizetime_frac_hard
  impossible (3): bot_recognizetime_frac_impossible

Survival scaling (same lerp pattern as FOV):
  bot_recognizetime_frac_survival_start → bot_recognizetime_frac_survival_end

Arousal modifier:
  final = base * difficultyFrac * arousalFrac
  (arousalFrac from CINSBotBody::GetArousalFrac — higher arousal = faster recognition)
```

Solo mode (human team bots): recognition time = 0 (instant).

ConVars controlling recognition:

| ConVar | Description |
|--------|-------------|
| `bot_recognizetime_base` | Base recognition delay (seconds) |
| `bot_recognizetime_frac_easy` | Multiplier for easy |
| `bot_recognizetime_frac_hard` | Multiplier for hard |
| `bot_recognizetime_frac_impossible` | Multiplier for impossible |
| `bot_recognizetime_frac_survival_start` | Survival start multiplier (default 1) |
| `bot_recognizetime_frac_survival_end` | Survival end multiplier (default 0) |

### Silhouette System (Partial Visibility)

| Address | Function | Signature |
|---------|----------|-----------|
| 0x007691F0 | CanReadSilhouette | `bool __thiscall (CINSBotVision*, CKnownEntity*)` |
| 0x00769420 | GetSilhouetteType (mutable) | `int __thiscall (CINSBotVision*, CBaseEntity*)` |
| 0x00769A70 | GetSilhouetteType (const) | `int __thiscall (CINSBotVision*, CBaseEntity*) const` |
| 0x0076A230 | UpdateSilhouettes | `void __thiscall (CINSBotVision*)` |

NWI's custom system. A bot can partially see someone (shadow, limb sticking out)
without fully recognizing them. Stored per-edict in the `int[48]` array at
`+0x194`.

**Silhouette types** (enum values):

| Value | Name | Meaning |
|-------|------|---------|
| -1 | UNKNOWN | Not assessed yet |
| 0 | DARK | Can see shape but not identify (shadow/backlit) |
| 1 | FUZZY | Partially visible, partially identified |
| 2 | CLEAR | Fully visible and identified |

**CanReadSilhouette** checks whether the bot has "read" (identified) a partially
visible entity. Depends on:
- Silhouette system enabled (`TheINSNextBots() + 0x129`)
- `CKnownEntity` is valid and alive
- Entity's silhouette type in the per-edict cache
- Time spent observing vs required read time:
  - `bot_silhouette_readtime_clear` for type CLEAR
  - `bot_silhouette_readtime_dark` for type DARK
  - `bot_silhouette_readtime_fuzzy` for type FUZZY
- Difficulty modifier: hard = 0.75x time, impossible = 0.5x time

ConVars controlling silhouettes:

| ConVar | Description |
|--------|-------------|
| `bot_silhouette_range_close` | Distance for close silhouette detection |
| `bot_silhouette_range_far` | Max distance for silhouette detection |
| `bot_silhouette_range_movement` | Movement increases silhouette visibility |
| `bot_silhouette_readtime_clear` | Seconds to read clear silhouette |
| `bot_silhouette_readtime_dark` | Seconds to read dark silhouette |
| `bot_silhouette_readtime_fuzzy` | Seconds to read fuzzy silhouette |
| `bot_silhouette_light_threshold_low` | Light level for dark classification |
| `bot_silhouette_light_threshold_medium` | Light level for fuzzy classification |
| `bot_silhouette_discover_timer` | Interval between silhouette scans |
| `bot_silhouette_scan_frequency` | How often silhouette state updates |
| `ins_bot_debug_silhouette` | Debug overlay (renders "Sil: Dark/Fuzzy/Clear" per entity) |

### Blindness (Flash-bang)

| Address | Function | Signature |
|---------|----------|-----------|
| 0x00769BA0 | IsBlinded | `bool __thiscall (CINSBotVision*)` |
| 0x00768070 | OnBlinded | `void __thiscall (CINSBotVision*, CBaseEntity* attacker, bool)` |

**IsBlinded** checks two timer sources:
1. Player-level blind timer at entity offset `-0x840` from CINSNextBot base
2. Vision-level blind timer at `CINSBotVision + 0x16C` (offset `0x5B * 4`)

Returns true if `gpGlobals->curtime <= blindEndTime`.

ConVars:

| ConVar | Description |
|--------|-------------|
| `bot_hearing_flashbang_effect_max_distance` | Range for flash effect |
| `bot_hearing_flashbang_effect_max_time` | Max duration of blindness |

### Entity Filtering

| Address | Function | Signature |
|---------|----------|-----------|
| 0x00767D90 | IsIgnored | `bool __thiscall (CINSBotVision*, CBaseEntity*)` |
| 0x0076BB50 | CollectPotentiallyVisibleEntities | `void __thiscall (CINSBotVision*, CUtlVector<CBaseEntity*>*)` |
| 0x0076B8B0 | UpdatePotentiallyVisibleNPCVector | `void __thiscall (CINSBotVision*)` |
| 0x00768520 | IsVisibleEntityNoticed | `bool __thiscall (CINSBotVision*, CBaseEntity*) const` |

**CollectPotentiallyVisibleEntities** builds the list of entities that could
potentially be seen. Filters by team, alive state, and distance. This is the
first pass before expensive raycasts.

**IsIgnored** determines if an entity should be skipped entirely (teammates in
certain modes, non-combatants, etc.).

### Memory Management

| Address | Function | Signature |
|---------|----------|-----------|
| 0x00767D50 | ForgetAllKnownEntities | `void __thiscall (CINSBotVision*)` |
| 0x00767B80 | Reset | `void __thiscall (CINSBotVision*)` |

---

## VTable Offsets (used from extension code)

These are IVision vtable byte offsets used for dispatch from CINSNextBot:

| Vtable Offset | Function | Currently Used |
|---------------|----------|----------------|
| 0x0D0 | GetPrimaryKnownThreat(bool onlyVisible) | Yes |
| 0x104 (260) | IsAbleToSee(CBaseEntity*, int, Vector*) | Yes |
| 0x108 (264) | IsAbleToSee(const Vector&, int) | Declared, not used |
| 0x0C4 | GetBot() → INextBot* | Used internally |
| 0x0DC | GetNearestVisiblePlayer(team, flags, range) | Not used |
| 0x0E4 | GetKnown(CBaseEntity*) → CKnownEntity* | Not used |
| 0x0FC | GetMaxVisionRange() | Used in IsAbleToSee |
| 0x110 | IsLineOfSightClearToEntity | Used in IsAbleToSee |
| 0x114 | IsInFieldOfView(target) | Used in IsAbleToSee |
| 0x118 | IsInFieldOfView(entity) | Used in IsAbleToSee |
| 0x128 | IsLineOfSightClear(Vector) | Used in IsAbleToSee |

To get the IVision interface from a CINSNextBot entity pointer:
```c
void **vtable = *(void***)entityPtr;
GetVisionFn fn = (GetVisionFn)vtable[0x974 / 4];  // kVtableOff_GetVisionInterface
void *vision = fn(entityPtr);
```

---

## Hearing

Bot hearing is not part of CINSBotVision directly. It flows through the
`IVision` known-entity database: heard events create `CKnownEntity` entries
with `IsVisibleNow() == false`. The `GetPrimaryKnownThreat(onlyVisible=0)` call
used in the extension captures both seen and heard threats.

ConVars:

| ConVar | Description |
|--------|-------------|
| `bot_hearing_grenade_hearing_range` | Range bots can hear grenades |
| `bot_hearing_silenced_weapon_sound_reduction` | Silencer effect on hearing |
| `bot_hearing_flashbang_effect_max_distance` | Flash-bang hearing range |
| `bot_hearing_flashbang_effect_max_time` | Flash-bang blindness duration |

---

## Key Constants

| Value | Meaning |
|-------|---------|
| 5000.0 | Max vision range (units) |
| 0.25 | Threat recalculation interval (seconds) |
| 2.0 | Threat recalc time offset from curtime |
| 0.002 | Combat intensity scaling factor |
| 5.0 | Score multiplier when threat is firing |
| 1.25 | Score multiplier for close range / looking at me |
| 0.75 | Silhouette readtime multiplier (hard difficulty) |
| 0.5 | Silhouette readtime multiplier (impossible difficulty) |

---

## How the Extension Uses This

Currently in `extension.cpp`:

1. **ComputeVision()** (8Hz) — for each bot, calls `IsAbleToSee(target, 0, NULL)`
   for every other player. Populates `BotStateEntry.sees[]`.

2. **ComputeEnemyThreats()** (8Hz) — calls `GetPrimaryKnownThreat(0)` per bot.
   Sets `s_hasVisibleEnemy[]` flag. `onlyVisible=0` means all senses
   (seen + heard + reported).

3. **Checkpoint/Combat hooks** check `s_hasVisibleEnemy[]` to decide whether to
   let native combat AI run or override with custom movement.

### Not Yet Used

Functions that could improve decision-making:

| Function | What it gives | Use case |
|----------|---------------|----------|
| `GetCombatIntensity()` | 0-1 pressure level | Weight flanking urgency |
| `IsLineOfFireClear()` | Can this bot fire at position | Validate suppression targets |
| `IsBlinded()` | Bot is flash-banged | Don't assign tasks to blinded bots |
| `GetSilhouetteType()` | How well bot sees target | Priority targeting |
| `CanReadSilhouette()` | Has bot identified target | Delay engagement until identified |
| `GetPrimaryKnownThreat(1)` | Visible-only threat | Distinguish seen vs heard contacts |