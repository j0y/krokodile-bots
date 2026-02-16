# Bot Pathfinding System — CINSBotLocomotion, CINSNavArea, Path Cost Functors

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

CINSBotLocomotion is the movement interface for bots. It embeds a
CINSPathFollower that handles A* path computation and following, and
manages a priority queue of movement requests. The nav mesh (CINSNavArea)
stores per-area combat/death intensity and provides cover/hiding spot
scoring. Three path cost functors weight travel cost based on danger,
height changes, and tactical conditions.

---

## CINSBotLocomotion Object Layout

Size: ~0x498C bytes. Inherits PlayerLocomotion → ILocomotion.

Constructor: `0x00760920`

```
+0x000  vtable pointer (CINSBotLocomotion vtable, at 0x00B92C00+8)
...     PlayerLocomotion base (ILocomotion base)
+0x0AC  CINSPathFollower  (embedded sub-object — CINSPathFollower::CINSPathFollower)
...     CINSPathFollower internals (CNavPath, path segments, timers)
+0x491C CUtlVector<INSBotMovementRequest>  (m_pMemory pointer)
+0x4920 (4 bytes)  alloc count
+0x4924 (4 bytes)  grow size
+0x4928 int        movement request count
+0x492C (4 bytes)  unknown, zeroed in ctor
+0x4930 CountdownTimer  (movement update timer, 0.25s period)
+0x493C CountdownTimer  (posture hold timer, starts at -1.0)
+0x4948 CountdownTimer  (timer slot 3)
+0x4954 CountdownTimer  (timer slot 4)
+0x4960 CountdownTimer  (approach update timer, 0.5s period)
+0x496C CountdownTimer  (posture change timer, 4.0s duration)
+0x4978 CountdownTimer  (timer slot 7)
+0x4984 IntervalTimer   (still-duration tracker, -1.0 = moving)
```

Each CountdownTimer is 12 bytes: `{ vtable*, float duration, float endTime }`.
IntervalTimer is 8 bytes: `{ vtable*, float timestamp }`.

### INSBotMovementRequest (0x24 = 36 bytes)

```
+0x00  Vector     position (3 floats — x, y, z)
+0x0C  byte       isActive (1 = currently being followed)
+0x0D  byte       isCompleted
+0x0E  byte       isFailed
+0x10  float      startTime (gpGlobals->curtime when request created)
+0x14  float      expiryTime (curtime + duration parameter)
+0x18  int        INSBotMovementType
+0x1C  int        INSBotPriority
+0x20  int        failCount (incremented on ComputePath failure, max 2 retries)
```

---

## CINSBotLocomotion Functions

### Core Update Loop

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0075D8A0 | Update | `void __thiscall (CINSBotLocomotion*)` |
| 0x00760830 | Upkeep | `void __thiscall (CINSBotLocomotion*)` |

**Update** calls `PlayerLocomotion::Update()` (parent), then checks
`GetStillDuration()`. If still duration < 5.0s, records the still-start
timestamp. If >= 5.0s, resets to -1.0 (moving).

**Upkeep** checks game state (via `CINSRules::IsGameState`). If the
game is in active play, calls `UpdateMovement()`. During pre-round,
it checks if the bot has a valid player reference before allowing
movement.

### Movement Requests

| Address | Function | Signature |
|---------|----------|-----------|
| 0x00760DD0 | AddMovementRequest | `void __cdecl (CINSBotLocomotion*, Vector, INSBotMovementType, INSBotPriority, float duration)` |
| 0x0075FA10 | ClearMovementRequests | `void __thiscall (CINSBotLocomotion*, INSBotPriority)` |
| 0x0075EA70 | GetCurrentMovementRequest | `int __thiscall (CINSBotLocomotion*)` |
| 0x0075EC30 | ApplyMovementRequest | `void __thiscall (CINSBotLocomotion*, int index)` |
| 0x0075EC00 | OnMoveToSuccess | `void __thiscall (CINSBotLocomotion*, Path*)` |
| 0x0075EF00 | OnMoveToFailure | `void __thiscall (CINSBotLocomotion*, int failType)` |
| 0x0075EB10 | OnCompletedMovementRequest | `void __thiscall (CINSBotLocomotion*, int index)` |
| 0x0075EDA0 | OnFailedMovementRequest | `void __thiscall (CINSBotLocomotion*, int index)` |

**AddMovementRequest** appends to the CUtlVector at `+0x491C`. If an
identical position already exists, it extends the expiry time instead
of adding a duplicate. Debug cvar `ins_bot_debug_movement_requests`
renders spheres at request positions.

**GetCurrentMovementRequest** scans the request array for the first
entry with `isActive == 1`. Returns its index, or -1 if none active.
Special case: if exactly 1 request exists, returns index 0 directly.

**ClearMovementRequests** iterates requests from end to start. Removes
any with `priority <= param`. If the request was active, calls
`CINSPathFollower::Invalidate()` on the embedded path follower.

**OnCompletedMovementRequest** clears `isActive` (byte at +0x0C = 0)
and sets `isCompleted` (byte at +0x0D = 1).

**OnFailedMovementRequest** clears `isActive` (byte at +0x0C = 0)
and sets `isFailed` (byte at +0x0E = 1).

### Movement Execution

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0075FAA0 | UpdateMovement | `void __thiscall (CINSBotLocomotion*)` |
| 0x0075DA20 | Approach | `void __thiscall (CINSBotLocomotion*, const Vector&, float)` |
| 0x0075D6B0 | FaceTowards | `void __thiscall (CINSBotLocomotion*, const Vector&)` |
| 0x0075F7B0 | AdjustPosture | `void __thiscall (CINSBotLocomotion*, const Vector&)` |
| 0x0075F0D0 | GetMovementStance | `char __thiscall (CINSBotLocomotion*, const Vector&)` |
| 0x0075EF30 | GetDesiredPostureForRequest | `int __thiscall (CINSBotLocomotion*, int reqIndex)` |
| 0x0075F0C0 | UpdateMovementPosture | `void (void)` — stub, empty |

**UpdateMovement** is the main movement tick (called from Upkeep). Flow:

1. Validate bot alive. If dead → `ClearMovementRequests()` and return.
2. Debug overlay: shows request count/current via `NDebugOverlay::Text`.
3. **Request selection** (gated by CountdownTimer at +0x4930, 0.25s):
   - Iterate requests from highest to lowest index.
   - Remove expired/completed/failed requests.
   - Track the best candidate by priority and start time.
   - If the best differs from the currently active one → `ApplyMovementRequest`.
4. **Repath logic** (gated by CountdownTimer at +0x4954, 2.2s):
   - Repath interval: `2.2 / (numBots + 1)` — staggered across all bots.
   - Uses a static `s_fixedRepathCooldown` timer shared among all bots.
   - Checks: `CINSPathFollower::IsComputeExpired`, `IsOnGround`,
     `GetStillDuration` >= 1.0s (stuck → force repath).
5. **Path computation**: calls `CINSPathFollower::ComputePath` with:
   - Path cost functor (movement type dependent, see below)
   - Max path length from `CINSNextBot::MaxPathLength()`
   - Max lookahead: 30.0 units
   - On failure: increment failCount. If failCount > 2 → mark request failed.
   - On success: set `isActive = 1`, call `CINSPathFollower::Update`.
6. **Path following** (gated by CountdownTimer at +0x4948):
   - If path is valid and body is ready → `CINSPathFollower::Update`.
   - Update interval from ConVar `ins_bot_path_update_interval`.

**Approach** extends `ILocomotion::Approach`. Computes a 2D forward/strafe
vector from eye direction to goal. Delegates to `INextBotPlayerInput` for
actual button presses:
- Forward dot > 0.5 → press forward key
- Forward dot < -0.5 → press backward key
- Strafe dot > 0.5 → press right key
- Strafe dot < -0.5 → press left key

Also adjusts posture every 0.5s via timer at +0x4960.

**FaceTowards** calls `IBody::AimHeadTowards` (vtable offset `0xD4`)
with the target direction. Gets eye position from
`CINSNextBot::EyePosition` (vtable `0x20C`).

**GetMovementStance** does a hull trace (standing hull first, then
crouching) from the bot's position in the movement direction. Returns:
- `0x0C` = default/stand (12)
- `0x06` = crouch (6)
- `0x02` = prone (2)

Uses `PlayerBody::GetStandHullHeight`, `GetCrouchHullHeight`,
`GetHullWidth`, `GetSolidMask` via body interface vtable calls.

### Traversal & Stuck

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0075D7B0 | IsAreaTraversable | `bool __thiscall (CINSBotLocomotion*, const CINSNavArea*)` |
| 0x0075D840 | IsEntityTraversable | `bool __thiscall (CINSBotLocomotion*, CBaseEntity*, TraverseWhenType)` |
| 0x0075E500 | IsPotentiallyTraversable | `byte __thiscall (CINSBotLocomotion*, const Vector&, const Vector&, TraverseWhenType, float*)` |
| 0x0075D790 | IsClimbPossible | `bool __cdecl (INextBot*, CBaseEntity*)` — always returns 1 |
| 0x0075EE90 | OnStuck | `void __thiscall (CINSBotLocomotion*)` |
| 0x0075D7A0 | OnUnStuck | `void (void)` — empty stub |
| 0x0075E920 | AreAdjacentAreasOccupied | `bool __thiscall (CINSBotLocomotion*, const CINSNavArea*)` |

**IsAreaTraversable** checks:
1. `CNavArea::IsBlocked(teamID, false)` — if blocked → false
2. `(attributeFlags & 0x80) == 0` — underwater flag → false if set

**IsEntityTraversable** checks `CBaseEntity::IsBreakable` first (vtable
`+0x158`). Breakable entities are always traversable. Otherwise falls
back to `ILocomotion::IsEntityTraversable`.

**OnStuck** fires when the bot has been immobile for 5.0 seconds:
1. Gets current movement request
2. Marks it as failed
3. Invalidates the path follower

**AreAdjacentAreasOccupied** checks all 4 directions. For each adjacent
area, reads the player-count byte at `CNavArea+0x4C` (team 0) and
`+0x4D` (team 1). Returns true if any adjacent area has players of the
bot's team.

### Speed & Dimensions

| Address | Function | Signature |
|---------|----------|-----------|
| 0x0075D680 | GetRunSpeed | `float __thiscall (CINSBotLocomotion*)` |
| 0x0075D640 | GetDeathDropHeight | `float (void)` |
| 0x0075D660 | GetMaxJumpHeight | `float (void)` |
| 0x0075FA00 | GetBehaviorStance | `int (void)` — returns 0x0C (12) |
| 0x0075EA00 | GetStillDuration | `float __thiscall (CINSBotLocomotion*)` |

**GetRunSpeed** delegates to `CBasePlayer::GetPlayerMaxSpeed` (vtable
`0x7A4`) via the player entity (at CINSNextBot - 0x2060 offset).

**GetDeathDropHeight** returns **260.0** units.

**GetMaxJumpHeight** returns **48.0** units.

**GetStillDuration** reads IntervalTimer at `+0x4988`. If timestamp
<= 0 → returns -1.0 (never still). Otherwise returns
`IntervalTimer::Now() - timestamp`.

---

## CINSNavArea — Key Fields and Functions

CINSNavArea extends CNavArea with Insurgency-specific combat analytics,
spawn scoring, hiding spot evaluation, and per-team pathing data.

### Object Layout (partial, from decompiled code)

```
+0x00   vtable pointer (CINSNavArea vtable, at 0x00B8D710+8)
+0x04   CNavAreaCriticalData start
        Corner coords: NW(+0x04), NE(+0x10), SE(+0x10/+0x14), SW(+0x04/+0x14)
        Z coords: +0x0C (NW), +0x24 (NE), +0x18 (SE), +0x28 (SW)
+0x2C   Vector m_center (3 floats) — area center position
+0x48   int    m_dangerTimestamp — compared to global threshold, triggers 10× path cost
+0x4C   byte   m_playerCount[0] — team 0 player occupancy
+0x4D   byte   m_playerCount[1] — team 1 player occupancy
+0x54   float  m_costSoFar — accumulated path cost (used by path cost functors)
+0x68   uint   m_attributeFlags — CNavArea base flags (bit 0x80 = underwater/blocked, bit 0x1000 = special)
+0x6C   CUtlVectorUltraConservative<NavConnect> m_connect[4] — adjacency per direction
        (offset from object: 0x6C = 108)
        NavConnect = { CNavArea* area; float length; } = 8 bytes
        Direction: 0=North, 1=East, 2=South, 3=West
+0xD0   HidingSpot* m_hidingSpots (pointer to CUtlVector)
+0x160  uint   m_insFlags — INS-specific area classification bitmask:
        0x0020 = corridor/chokepoint
        0x0040 = partial sky exposure
        0x0080 = inside (has roof overhead) — used by GetSpawnScore, ScoreHidingSpot, IsDoorway
        0x0100 = has associated spawn zone
        0x0400 = is doorway (set by CustomAnalysis when IsDoorway() returns true)
        0x2000 = control point related
        0x4000 = is hallway/corridor
+0x164  struct[2] per-team PVS data (0x14 bytes each):
        +0x164 team 0 (Security): { CHandle* m_pData; int m_alloc; int m_grow; int m_count(+0x170); ... }
        +0x178 team 1 (Insurgents): { CHandle* m_pData; int m_alloc; int m_grow; int m_count(+0x184); ... }
+0x18C  float  m_combatTimestamp — IntervalTimer timestamp (when combat last occurred)
+0x190  8 bytes IntervalTimer (combat timer: vtable + timestamp)
+0x194  float  m_combatIntensity — accumulated combat value
+0x198  int    m_insMarkValue — static marker for flood-fill search algorithms
+0x19C  float  m_spawnScore[0] — cached spawn score, team 0
+0x1A0  float  m_spawnScore[1] — cached spawn score, team 1
+0x1A4  float  m_spawnScoreTime[0] — spawn score cache timestamp, team 0
+0x1A8  float  m_spawnScoreTime[1] — spawn score cache timestamp, team 1
+0x1AC  float[16] m_hidingSpotScores — per-spot scores (init -1.0), 64 bytes
+0x1EC  CountdownTimer m_coverUpdateTimer (12 bytes: vtable, duration, timestamp)
+0x1F8  float  m_lastCoverUpdateCurtime
+0x1FC  CountdownTimer m_perTeamTimer[0] (12 bytes)
+0x208  CountdownTimer m_perTeamTimer[1] (12 bytes)
+0x214  float  m_deathIntensity[0] — death intensity, team 0
+0x218  float  m_deathIntensity[1] — death intensity, team 1
+0x21C  IntervalTimer  m_deathTimer[0] — per-team death timer (8 bytes)
+0x224  IntervalTimer  m_deathTimer[1] — per-team death timer (8 bytes)
+0x22C  int    m_tickCounter — tick-based update throttle, compared to global threshold
        (also triggers 30× path cost when >= global death-danger threshold)
+0x230  CUtlVector<CINSPathingBotInfo> m_pathingBots[0] — team 0 (0x14 bytes)
+0x244  CUtlVector<CINSPathingBotInfo> m_pathingBots[1] — team 1 (0x14 bytes)
        Danger levels (0-3) accessed as: *(area + teamIndex * 0x14 + 0x23C)
+0x258  int    m_associatedSpawnZone (init -1)
+0x25C  int    m_associatedControlPoint (init -1)
```

### Functions

#### Combat & Death Tracking

| Address | Function | Signature |
|---------|----------|-----------|
| 0x006E3010 | GetCombatIntensity | `float __thiscall (CINSNavArea*)` |
| 0x006E3300 | IsInCombat | `bool (CINSNavArea*)` |
| 0x006E3220 | OnCombat | `void __thiscall (CINSNavArea*)` |
| 0x006E3450 | GetDeathIntensity | `float __thiscall (CINSNavArea*, int teamID)` |
| 0x006E3340 | OnDeath | `void __thiscall (CINSNavArea*)` |
| 0x006E4470 | GetNearbyDeathIntensity | `float __thiscall (CINSNavArea*, ...)` |

**GetCombatIntensity** reads `m_combatIntensity` at `+0x18C` with
time-based decay:
```
if m_combatTimestamp (+0x194) <= 0: return 0
value = m_combatIntensity - (now - m_combatTimestamp) * nb_nav_combat_decay_rate
return max(value, 0)
```

**IsInCombat** returns `GetCombatIntensity() > 0.01`.

**GetDeathIntensity** takes a team parameter. Uses per-team
IntervalTimer and intensity values with decay:
```
offset = 0x0C + ((teamID != 2) + 0x42) * 8  // selects per-team timer
value = deathIntensity - (now - deathTimestamp) * nb_nav_death_decay_rate
return max(value, 0)
```

**GetNearbyDeathIntensity** sums GetDeathIntensity across adjacent areas
weighted by proximity. Used by path cost functors.

ConVars:

| ConVar | Description |
|--------|-------------|
| `nb_nav_combat_decay_rate` | How fast combat intensity decays per second |
| `nb_nav_death_decay_rate` | How fast death intensity decays per second |
| `nav_spawn_rescore_time` | Cache TTL for spawn scores (seconds) |
| `nav_spawn_score_base` | Starting score for spawn evaluation |
| `nav_spawn_score_friendly_spawn_bonus` | Bonus for being in friendly spawn zone |
| `nav_spawn_score_friendly_spawn_bonus_max_distance` | Max distance for spawn zone bonus falloff |
| `nav_spawn_score_inside` | Multiplier for indoor areas (m_insFlags & 0x80) |
| `nav_spawn_score_controlpoint_bonus` | Bonus for areas near active control point |
| `nav_spawn_score_cachepoint_bonus` | Bonus for areas near active cache point |
| `nav_spawn_score_potentially_visible` | Multiplier penalty for enemy-visible areas |

#### Spawn & Cover Scoring

| Address | Function | Signature |
|---------|----------|-----------|
| 0x006E3730 | GetSpawnScore | `float __thiscall (CINSNavArea*, int teamID)` |
| 0x006E3BC0 | ScoreHidingSpot | `void __thiscall (CINSNavArea*, HidingSpot*)` |
| 0x006E40E0 | UpdateCover | `void __thiscall (CINSNavArea*, float* threshold)` |
| 0x006E2D60 | ResetHidingSpotScores | `void __thiscall (CINSNavArea*)` |
| 0x006E60B0 | CollectSpotsWithScoreAbove | `void __thiscall (CINSNavArea*, CUtlVector<...>*, float threshold)` |
| 0x006E2EF0 | GetDistanceToNearestHidingSpot | `float __cdecl (CINSNavArea*, Vector)` |

**GetSpawnScore** is a large function that scores this area for spawning:
1. **Cache check**: reads cached score at `+0x19C + teamIdx*4`, returns if
   `curtime < cacheTime + nav_spawn_rescore_time`.
2. **Base score** from `nav_spawn_score_base`.
3. **Spawn zone**: if friendly zone → `nav_spawn_score_friendly_spawn_bonus`
   with distance falloff (max dist from `nav_spawn_score_friendly_spawn_bonus_max_distance`).
   If enemy zone → score = -1.0 immediately.
4. **Inside bonus**: if `m_insFlags & 0x80` → multiply by `nav_spawn_score_inside`.
5. **Control point**: if flags `0x2004` set and CP matches active objective →
   `nav_spawn_score_controlpoint_bonus` or `nav_spawn_score_cachepoint_bonus`
   (depending on CP type). Skipped in Outpost mode (gamemode 3).
6. **Hiding spots**: adds hiding spot count from CNavArea `+0xD0`.
7. **Visibility**: if visible to enemy team → multiply by `nav_spawn_score_potentially_visible`.
8. **Random jitter**: multiply by `RandomFloat(0.8, 1.2)`.
9. Caches final score at `+0x19C + teamIdx*4` with timestamp.

**ScoreHidingSpot** evaluates hiding spots in the area. Iterates twice
(once per team, indices 2 and 3). For each team: checks control point
ownership via `g_pObjectiveResource`, applies spawn zone bonuses,
inside bonuses, and per-team PVS visibility. Enemy actors looking
towards the spot (cos 0.9 / ~25° threshold) and within 250 units
penalize the score. Results stored in HidingSpot per-team score fields.

**HidingSpot layout** (partial):
```
+0x04  float x
+0x08  float y
+0x0C  float z
+0x20  float score_team0 (Security)
+0x24  float score_team1 (Insurgents)
+0x28  float base_score
```

**UpdateCover** refreshes hiding spot scores periodically (5.0s ±
random jitter). Checks a CountdownTimer at float offset `+0x1EC`.
If the frame count has changed since last update, calls
`ScoreHidingSpot` for each hiding spot.

**CollectSpotsWithScoreAbove** populates a vector with hiding spots
whose per-team score (at HidingSpot `+0x20` for Security, `+0x24` for
Insurgents) exceeds a threshold. Team selection: `(team != 2) + 8` maps
to the correct score field offset.

#### Adjacency & Classification

| Address | Function | Signature |
|---------|----------|-----------|
| 0x006E4B70 | IsDoorway | `bool __thiscall (CINSNavArea*)` |
| 0x006E4920 | HasAdjacentInsideArea | `bool __thiscall (CINSNavArea*)` |
| 0x006E4800 | HasAdjacentOutsideArea | `bool __thiscall (CINSNavArea*)` |
| 0x006E4A40 | GetInOutAdjacentCount | `int __thiscall (CINSNavArea*)` |
| 0x006E65D0 | IsPotentiallyVisibleToTeam | `bool __thiscall (CINSNavArea*, int teamID)` |
| 0x006E5190 | IsValid | `bool __thiscall (CINSNavArea*)` |

**IsDoorway** returns true if the area has the inside flag (`m_insFlags & 0x80`)
and exactly one outside-facing adjacent area (transition zone). The result
is cached as `m_insFlags |= 0x0400` during `CustomAnalysis`.

**IsPotentiallyVisibleToTeam** reads the per-team actor count at
`+0x170 + (team-2) * 0x14` (Security at `+0x170`, Insurgents at `+0x184`).
Returns true if `count > 0`.

Note: `IsBlocked` is **not** overridden by CINSNavArea — it is inherited
directly from CNavArea at address `0x004ADC40`.

#### Lifecycle

| Address | Function | Signature |
|---------|----------|-----------|
| 0x006E5D40 | Constructor | `void __thiscall (CINSNavArea*)` |
| 0x006E5A00 | OnRoundRestart | `void __thiscall (CINSNavArea*)` |
| 0x006E2AC0 | OnRoundRestartPreEntity | `void __thiscall (CINSNavArea*)` |
| 0x006E2AE0 | OnServerActivate | `void __thiscall (CINSNavArea*)` |
| 0x006E2CC0 | Update | `void __thiscall (CINSNavArea*)` |
| 0x006E6830 | Destructor | `void __thiscall (CINSNavArea*)` |

**OnRoundRestart** resets pathing bot info, combat/death timers, and
spawn scores. Clears per-team actor visibility lists.

---

## Path Cost Functors

Three cost functors determine how expensive it is to traverse from one
CNavArea to another. They are used by `CINSPathFollower::ComputePath`.

### CINSNextBotPathCost — Primary Path Cost

Address: `0x006F4840`

The main functor used for standard movement. Has two completely different
code paths depending on `ins_nav_enable_pathfinding_updates`.

**Functor Object Layout** (the `this` pointer):

```
+0x04  INextBot*  bot entity pointer
+0x08  int        difficulty mode (0=coward/evasive, 1-2=intermediate, 3=aggressive)
+0x0C  Vector     CP target position (x, y, z)
+0x18  int        CP index (-1 = no CP)
+0x1C  float      step height (comfortable height change)
+0x20  float      jump height (max jumpable)
+0x24  float      death drop height (max survivable fall)
```

**CNavArea corner offsets** (used for closest-corner distance):

| Corner | X | Y | Z |
|--------|---|---|---|
| NW (0) | `+0x04` | `+0x08` | `+0x0C` |
| NE (1) | `+0x10` | `+0x08` | `+0x24` |
| SE (2) | `+0x10` | `+0x14` | `+0x18` |
| SW (3) | `+0x04` | `+0x14` | `+0x28` |

#### Branch A: Simple Mode (`ins_nav_enable_pathfinding_updates == 0`)

```
// 1. Ladder check — if bot can't use ladders, return -1

// 2. Height change
heightChange = ComputeAdjacentConnectionHeightChange(from, to)
if heightChange >= jumpHeight:  return -1
if heightChange <= -deathDrop:  return -1
if |heightChange| >= stepHeight:  heightPenalty = 4.0, else 1.0

// 3. Danger level (squared)
danger = clamp(area.danger[teamIdx], 0, 3)
cost += danger * danger  // level 3 = +9.0

// 4. Attribute flag 0x1000: cost += baseCost
// 5. Empty connections: for each of 4 dirs with no connections, cost += baseCost
// 6. Blocked (0x80): cost += 5.0
// 7. Danger timestamp (area+0x48 >= globalThreshold): cost += 5.0
// 8. Death timestamp (area+0x22C >= globalThreshold): cost += 5.0

// 9. CP distance (if ins_nav_enable_distancetocp_pathing && cpIndex != -1):
//    distance >= 1000: bias toward/away from CP
//    distance < 1000:  scale by Manhattan distance to CP
```

#### Branch B: Full Mode (`ins_nav_enable_pathfinding_updates != 0`)

```
// 1. Distance: Euclidean center-to-center, or elevator length
// 2. Short-circuit: if from.costSoFar < ins_bot_path_simplify_range → return dist + costSoFar (no penalties)

// 3. Danger penalty (mode-dependent):
danger = clamp(area.danger[teamIdx], 0, 3)
  Mode 0 (coward):  penalty = pow(dist, danger) * EXPONENTIAL_CONST
  Mode 1-2 (mid):   penalty = danger * dist * 0.5
  Mode 3 (aggro):   penalty = danger * dist

// 4. Height change: same thresholds, multiplier ~2-3x

// 5. Blocked (0x80):           dist *= 10.0
// 6. Danger timestamp (+0x48): dist *= 10.0
// 7. Death timestamp (+0x22C): dist *= 30.0

// 8. Randomness (mode 0 only): cosine-based noise from entity seed + gametime
randomFactor = 1.0 + (cos(noise) + 1.0) * SMALL_MULTIPLIER

// 9. Combat intensity (mode 2 only):
deathMultiplier = 6.5
if IsInCombat(): dist *= combatIntensity * ~2-3

// 10. Death intensity:
if deathIntensity > 0: dist *= deathIntensity * deathMultiplier

// 11. Player occupancy:
playerCount = area[+0x4C + team%2]  // or both teams if team==0
total = dangerPenalty + from.costSoFar + (dist * 5.0 * playerCount + dist) * randomFactor
```

ConVars:

| ConVar | Description |
|--------|-------------|
| `ins_nav_enable_pathfinding_updates` | Master switch: 0=simple cost, nonzero=full cost with danger/combat/death |
| `ins_bot_path_simplify_range` | Distance below which no danger penalties apply (early path simplification) |
| `ins_nav_enable_distancetocp_pathing` | Factor CP distance into path cost (simple mode only) |

### CINSNextBotChasePathCost — Chase Path Cost

Address: `0x006F5230`

Functor used when chasing a target. Minimizes distance from bot to
closest corner of each candidate area. Relatively light penalties.

**Functor Object Layout**:
```
+0x04  INextBot*  bot entity pointer
+0x0C  Vector     chase target position (x, y, z)
+0x18  float      step height
+0x1C  float      jump height
+0x20  float      death drop height
```

```
// 1. Minimum corner distance from target to any of 4 area corners
minDist = min(dist to NW, NE, SE, SW corners)

// 2. If center closer than minDist: cost = minDist - centerDist (benefit)
//    If center farther: cost = 1.0 + clamp((overshoot * 0.001), 0, 1) * -0.9

// 3. Height change: same thresholds, multiplier 3.0x

// 4. Danger: additive (not squared)
danger = clamp(area.danger[teamIdx], 0, 3)
cost += danger

// 5. Blocked (0x80): cost *= 10.0

total = cost + fromArea.GetTotalCost()
```

Designed to strongly prefer direct paths toward the target. The 0.001
overshoot scaling means only gentle penalties for slight detours.

### CINSNextBotCPDistancePathCost — Control Point Distance Cost

Address: `0x006ECB90`

The simplest functor. Pure geometric distance plus height change
penalty. No danger/combat/death/blocked considerations.

**Functor Object Layout**:
```
+0x04  Vector     target position (x, y, z)
+0x10  float      step height
+0x14  float      jump height
+0x18  float      death drop height
```

```
// 1. Find closest corner (iterates all 4 corners of the area)
base_cost = min distance to any corner

// 2. Elevator: use elevator.length (+0x18) instead

// 3. Height change
if heightChange > maxJump:  return -1
if heightChange < -deathDrop:  return -1
if |heightChange| > stepHeight:  base_cost *= 3.0

total = base_cost + fromArea.GetTotalCost() (+0x54)
```

### Functor Comparison

| Feature | PathCost | ChasePathCost | CPDistPathCost |
|---------|----------|---------------|----------------|
| **Use** | General nav | Chasing enemies | Rush to CP |
| **Distance** | Center-to-center | Min corner from target | Min corner from CP |
| **Danger** | Squared/exponential/linear (mode-dep) | Additive | None |
| **Combat intensity** | Yes (mode 2, ×6.5) | No | No |
| **Death intensity** | Yes (multiplied) | No | No |
| **Blocked** | 10× (full) or +5 (simple) | 10× | None |
| **Danger timestamp** | 10× | No | No |
| **Death timestamp** | 30× | No | No |
| **Player occupancy** | 5.0 per player | No | No |
| **Path randomization** | Yes (mode 0, cosine) | No | No |
| **Difficulty modes** | 4 (0-3) | None | None |

---

## CINSPathFollower

CINSPathFollower extends Valve's `PathFollower` (→ `Path`). It is not
separately decompiled (excluded from Ghidra script's `INCLUDE_PREFIXES`
— would need `"CINSPathFollower"` added to decompile). Reconstructed
from cross-referencing call sites, VPROF strings, vtable data, and SDK
references.

Vtable: `0x00B84480`

### Inheritance

`CINSPathFollower` → `PathFollower` → `Path`

The `Path` base class embeds `Segment m_path[256]` (~64 bytes each),
making path follower objects very large.

### Embedded Instances

CINSPathFollower appears in two places within the bot object hierarchy:

| Location | Offset | Purpose |
|----------|--------|---------|
| CINSBotLocomotion | `+0xAC` | Used by movement request system (AddMovementRequest/UpdateMovement) |
| CINSNextBot (as ChasePath base) | `+0x2298` | Chase path for pursuing entities |
| CINSNextBot (general PathFollower) | `+0x6B34` | General goal-based path following |

Related CINSNextBot offsets:

| Offset | Type | Description |
|--------|------|-------------|
| `+0x669C` | int | Chase path `m_segmentCount` |
| `+0x6A74` | float | Chase path `m_minLookAheadRange` |
| `+0x6B08` | CountdownTimer | Chase path compute throttle |
| `+0x6B14` | CountdownTimer | Chase path refresh throttle |
| `+0x6B20` | CountdownTimer | Chase path lifetime |
| `+0x6B2C` | int (-1) | Last path subject / CP index |
| `+0x6B30` | int (1) | Chase path type (DONT_LEAD_SUBJECT=1) |
| `+0xAF38` | int | General path follower `m_segmentCount` |
| `+0xB290` | float | General path `m_minLookAheadRange` |
| `+0xB324` | int | Consecutive path failure counter |

### Function Table (from VPROF strings + call sites)

| Function | VPROF String | Notes |
|----------|-------------|-------|
| `ComputePath(...)` | `"CINSPathFollower::ComputePath"` | A* path computation |
| `Update(INextBot*)` | `"CINSPathFollower::Update"` | Main movement tick |
| — (subsection) | `"CINSPathFollower::Update - Progress"` | AdjustSpeed + CheckProgress |
| — (subsection) | `"CINSPathFollower::Update - Climb check"` | Ledge detection |
| — (subsection) | `"CINSPathFollower::Update - Fall Check"` | Off-path detection |
| — (subsection) | `"CINSPathFollower::Update - Path Aim Ahead"` | INS-specific: weapon/ironsight look-ahead |
| `IsComputeExpired(INextBot*)` | — | Timer-based recomputation check |
| `Invalidate()` | — | Reset path state (from Path) |
| `Climbing(...)` | `"CINSPathFollower::Climbing"` | Ledge climb logic |
| `JumpOverGaps(...)` | `"CINSPathFollower::JumpOverGaps"` | Gap jump logic |
| `Avoid(...)` | `"CINSPathFollower::Avoid"` | Obstacle avoidance |
| `WaitToPass(INextBot*)` | `"CINSPathFollower::WaitToPass"` | INS-specific: congestion handling |
| `IsAtGoal(INextBot*)` | `"CINSPathFollower::IsAtGoal"` | Proximity check |
| `CheckProgress(INextBot*)` | `"CINSPathFollower: OnMoveToSuccess"` | Goal-reach detection |

### ComputePath Signature (reconstructed)

```cpp
bool CINSPathFollower::ComputePath(
    INextBot *bot,            // the bot
    Vector goal,              // destination position
    void *costContext,        // cost functor context
    int routeType,            // 0=default, 1=escort?, 2=investigate, 3=retreat
    float maxPathLength,      // from CINSNextBot::MaxPathLength()
    bool includeGoalIfFails,  // include goal on partial path
    float minLookAhead        // typically 30.0f
);
```

Route types affect the cost functor behavior (see CINSNextBotPathCost
difficulty modes). Movement-type bitmask at `+0x1D0` selects functor.

### Update Flow (10 steps)

1. `bot->SetCurrentPath(this)` — register as active path
2. **Validity check** — return early if path invalid or `m_goal == NULL`
3. **Wait timer** — if `m_waitTimer` active (congestion), skip movement
4. **Ladder update** — if `LadderUpdate(bot)` returns true, ladder in progress
5. **Progress** — `AdjustSpeed()` then `CheckProgress()`. If goal reached → `OnMoveToSuccess`
6. **Direction** — forward vector from feet to `m_goal->pos`, normalize 2D
7. **Climb check** — `Climbing()` for ledges, then `JumpOverGaps()`
8. **Fall check** — if fell off path → `OnMoveToFailure(FAIL_FELL_OFF)`
9. **Path Aim Ahead** (INS extension) — look ahead for weapon/ironsight coordination.
   Not present in base SDK PathFollower.
10. **Avoid + Approach** — `Avoid()` adjusts goal, then `FaceTowards()` + `Approach()`

### Invalidate

Resets all path state:
1. `Path::Invalidate()` — sets `m_segmentCount = 0`, clears cursor, nulls subject
2. `m_goal = NULL`, `m_avoidTimer.Invalidate()`, `m_waitTimer.Invalidate()`
3. `m_hindrance = NULL` (blocking entity)

### Wrapper Functions on CINSNextBot

**ComputeChasePath** (`0x0075C600`):
- Invalidates refresh/lifetime timers at `+0x6B1C` and `+0x6B28`
- Picks random route type (0-2), forced to 1 if escorting
- Uses `CINSNextBotChasePathCost` functor
- On failure: increments counter at `+0xB324`. After 5+ failures in
  Outpost/Entrenchment modes → `KillSelf()` with `"Chase path failed"`

**ComputePathFollower** (`0x0075C880`):
- Sets `bot_path_minlookahead` at `+0xB290`
- Uses `CINSNextBotPathCost` functor with CP index from goal area
- Same failure counter logic — suicides after 4+ failures in certain modes

**UpdateChasePath** (`0x0075C3A0`):
- Creates `CINSNextBotChasePathCost` on stack
- Calls `ChasePath::RefreshPath()` (recomputes if target moved enough)
- Calls `CINSPathFollower::Update()` to follow

### How to Decompile

Add `"CINSPathFollower"` to `INCLUDE_PREFIXES` in
`reverseEngineering/scripts/ghidra_decompile_bots.py` (line 23) and
re-run the Ghidra script.

---

## Key Constants

| Value | Meaning |
|-------|---------|
| 260.0 | Death drop height (units) — `GetDeathDropHeight()` |
| 48.0 | Max jump height (units) — `GetMaxJumpHeight()` |
| 5.0 | Stuck threshold (seconds) — triggers `OnStuck` |
| 0.25 | Movement request selection interval (seconds) |
| 2.2 | Base repath interval (seconds) — divided by `(numBots + 1)` |
| 30.0 | Path following max lookahead (units) |
| 3.0 | Height change cost multiplier |
| 10.0 | Underwater area cost multiplier |
| 10.0 | Blocked area cost multiplier (without nav blockers) |
| 30.0 | Blocked area cost multiplier (with nav blockers) |
| 0.5 | Approach update interval (seconds) |
| 4.0 | Posture change hold duration (seconds) |
| 5.0 | Cover update interval (seconds, ± random jitter) |
| 0.01 | IsInCombat threshold for combat intensity |
| 250.0 | Enemy proximity penalty distance in spawn scoring |
| 0x0C (12) | Default stance value (standing) |
| 0x06 (6) | Crouch stance value |
| 0x02 (2) | Prone stance value |

---

## Nav Mesh Globals

| Address | Symbol | Type |
|---------|--------|------|
| 0x00C99800 | TheNavMesh | `CNavMesh**` (global pointer) |

To access the nav mesh:
```c
CNavMesh **ppNavMesh = (CNavMesh**)(serverBase + 0x00C99800);
CNavMesh *navMesh = *ppNavMesh;
```

### Resolved Function Pointers (used by extension)

| Address | Function | Signature |
|---------|----------|-----------|
| 0x004F20D0 | CNavMesh::GetNearestNavArea | `CNavArea* (CNavMesh*, const Vector&, bool anyZ, float maxDist, bool checkLOS, bool checkGround, int team)` |
| 0x004AE260 | CNavArea::IsPotentiallyVisible | `bool (CNavArea*, const CNavArea*)` |
| 0x004ADC40 | CNavArea::IsBlocked | `bool (CNavArea*, int teamID, bool ignoreNavBlockers)` |

### CINSBotLocomotion::AddMovementRequest (used by extension)

| Address | Function |
|---------|----------|
| 0x00750DD0 | CINSBotLocomotion::AddMovementRequest |

Vtable byte offset to get the locomotion interface from CINSNextBot:
```c
void *loco = ((GetLocomotionFn)(*(void***)bot)[0x96C / 4])(bot);
```

---

## How the Extension Uses Pathfinding

Currently in `nav_flanking.cpp`:

1. **Custom A* Pathfinder** — the extension implements its own A*
   pathfinding on the nav mesh, bypassing the engine's CINSPathFollower
   entirely. This allows adding a visibility penalty
   (`smartbots_flank_vis_penalty`, default 2000) to areas visible from
   the threat position.

2. **GetNearestNavArea** — snaps world positions to nav areas for both
   bot and staging positions. Used for A* start/goal resolution.

3. **IsPotentiallyVisible** — checks if a nav area is visible from
   the threat area. Areas visible to the enemy get a cost penalty.

4. **IsBlocked** — skips blocked areas during A* expansion.

5. **AddMovementRequest** — injects the A* path waypoints as movement
   requests via the `BotCommandEntry` → `bot_action_hook.cpp` path.
   The engine's native path follower then executes each waypoint.

6. **NavArea field access** — reads `m_center` (+0x2C) for area positions
   and `m_connect` (+0x6C) for adjacency traversal, both using raw
   pointer arithmetic.

### Extension ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `smartbots_flank_enabled` | 1 | Enable flanking system |
| `smartbots_flank_vis_penalty` | 2000 | Extra cost for enemy-visible areas |
| `smartbots_flank_replan_seconds` | 3.0 | A* replan interval |
| `smartbots_flank_staging_dist` | 400 | Staging position distance from enemy |
| `smartbots_flank_assign_seconds` | 5.0 | Sector assignment interval |
| `smartbots_flank_defend_ratio` | 0.3 | Fraction of bots that defend (rest flank) |

### Not Yet Used

Engine pathfinding capabilities available but not leveraged:

| Function/Feature | What it gives | Use case |
|------------------|---------------|----------|
| `GetCombatIntensity()` per area | 0+ pressure level per area | Weight flanking routes away from active combat |
| `GetDeathIntensity()` per area | Per-team death hotspot data | Avoid areas where teammates died recently |
| `GetSpawnScore()` | Spawn quality rating | Choose better rally points |
| `ScoreHidingSpot()` / `CollectSpotsWithScoreAbove()` | Cover positions with scores | Select cover waypoints along flank routes |
| `IsPotentiallyVisibleToTeam()` | Team-based area visibility | More accurate than single-area vis checks |
| `GetNearbyDeathIntensity()` | Surrounding area danger level | Better danger avoidance radius |
| `AreAdjacentAreasOccupied()` | Teammate/enemy proximity | Avoid clustering or detect enemy concentration |
| `IsDoorway()` | Transition point detection | Identify choke points for ambush/avoidance |
| Native `CINSPathFollower::ComputePath` | Full engine pathfinding with proper ladders, elevators, cost functors | Replace custom A* with engine path for better nav mesh compatibility |
| `CINSNextBotPathCost` functor internals | Team danger at `+0x23C` per area | Read danger levels for intel without recomputing |
