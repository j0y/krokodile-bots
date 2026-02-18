# Bot Retreat & Cover System — Cover Selection, Retreat Actions & Combat Cover

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The retreat & cover system spans three layers: (1) **cover evaluation** on `CINSNextBot`
that discovers, caches, and ranks cover positions from the nav mesh; (2) **retreat actions**
(`CINSBotRetreat`, `CINSBotRetreatToCover`, `CINSBotRetreatToHidingSpot`) that move
the bot to safety when under fire; and (3) **combat cover actions**
(`CINSBotAttackFromCover`, `CINSBotAttackIntoCover`) that use cover positions
offensively during engagements.

Cover comes in two flavors: **attack cover** (positions between the bot and threat
that allow line-of-fire) and **hiding cover** (safe spots behind geometry, away from
all known threats). The choice depends on context — combat bots seek attack cover,
fleeing bots seek hiding cover.

---

## Cover Evaluation — CINSNextBot Methods

### UpdateCover (0x0074AC70)

Called every tick from the bot's main Update loop. Throttled to run at most once
per 1.0 second via timestamp at bot+0x2188.

```
if gpGlobals->curtime < bot.m_lastCoverUpdate + 1.0:
    return  // throttled

bot.m_lastCoverUpdate = curtime

if bot.IsInCombat():
    distance = GetPathDistance(bot.locomotion, bot.m_cachedCoverPos)
    if distance <= 500.0:
        // Close to existing cover — just update distances
        goto update_distances

    // In combat but far from cover — do BFS nav area search
    startArea = bot.GetLastKnownArea()
    SearchSurroundingAreas(startArea, bot.AbsOrigin, maxDist=2000.0)
    // Collects INSBotCoverContainer entries from adjacent areas

else:  // not in combat
    update_distances:
    // Iterate existing cover container, update distances
    for each entry in bot.m_coverContainer (CUtlVector at +0x2174):
        if entry.navArea == null:
            remove entry (shift array)
        else:
            entry.distance = GetPathDistance(bot.locomotion, entry.position)

    Sort(bot.m_coverContainer, SortBotCoverSpots)
```

**Key details:**
- Cover container at bot+0x2174 (CUtlVector of INSBotCoverContainer, 0xC bytes each)
- Container count at bot+0x2180
- BFS search max travel distance: 2000.0 units
- Update throttle: 1.0 second
- Combat distance threshold for full re-search: 500.0 units
- Sorted by distance (closest first) via SortBotCoverSpots functor (0x00733000)

### GetAttackCover (0x00745B70)

**VProf:** `CINSNextBot::GetForwardAttackCover`

Returns a cover position that allows the bot to fire at the threat while being
partially protected. Searches the cached cover container.

```
if coverContainer.count == 0:
    return vec3_origin  // no cover available

if cached attack cover is still valid (within time + 5.0s):
    return cached position

threat = GetPrimaryKnownThreat(includeHidden=false)

for each entry in coverContainer:
    if (filterCrouched && entry.isCrouched == false): skip

    hidingSpot = entry.navHidingSpot
    if threat != null:
        if !HidingSpot::HasAnyCoverToPoint(hidingSpot, threat.pos):
            continue  // no cover from this threat
        if entry.distance <= GetPathDistance(locomotion, threat.pos):
            continue  // too close to threat
        if !IsPointBetweenTargetAndSelf(spot, threat):
            continue  // not between us and threat
        if IsSpotOccupied(spot):
            continue  // another bot already there
        if !IsLineOfFireClear(spot + 69.0z, threat.EyePosition):
            continue  // can't shoot from here

    return entry.position  // found valid attack cover

return vec3_origin  // none found
```

**Key checks for attack cover:**
- Must have cover from the threat direction (HidingSpot::HasAnyCoverToPoint)
- Must be between the bot and threat (IsPointBetweenTargetAndSelf)
- Must not be already occupied by another bot
- Must have clear line of fire from position + 69.0 Z offset to threat's eyes
- Cached for performance; cache expires after 5.0 seconds

### GetHidingCover (0x00744790)

Returns a safe hiding position away from all known threats. Uses the
`INSBotSafeCoverTest` functor (vtable 0x458455) to validate positions.

```
if coverContainer.count == 0:
    return vec3_origin

if cached hiding cover still valid (within time + 5.0s):
    return cached position

threat = GetPrimaryKnownThreat(includeHidden=false)
firstSpot = coverContainer[0].navHidingSpot

// Get nearest nav area to the hiding spot for Z height
nearestArea = CNavMesh::GetNearestNavArea(TheNavMesh, spotPos, 10000.0)
if nearestArea overlaps spot:
    spot.z = nearestArea.GetZ(spot.xy) + 69.0  // standing height

// Validate with INSBotSafeCoverTest (safe from all threats)
// ... similar iteration through cover container
```

### GetAnyCover (0x007460F0)

Tries hiding cover first. If both hiding attempts return vec3_origin,
falls back to attack cover.

```
pos = GetHidingCover(false)
if pos == vec3_origin:
    pos = GetHidingCover(true)   // try with crouched filter
    if pos == vec3_origin:
        pos = GetAttackCover(true)
        if pos == vec3_origin:
            pos = GetAttackCover(false)
return pos
```

### IsInCover (0x00744DB0)

Checks if the bot is currently within 48 units of either cached cover position.

```
// Check hiding cover position (bot+0x2198)
if hidingCoverPos != vec3_origin:
    dist² = |bot.AbsOrigin - hidingCoverPos|²
    if dist² < 2304.0 (= 48²):
        return true

// Check attack cover position (bot+0x21A8)
if attackCoverPos != vec3_origin:
    dist² = |bot.AbsOrigin - attackCoverPos|²
    if dist² < 2304.0 (= 48²):
        return true

return false
```

**IsInCover radius: 48 units** (stored as 2304.0 = 48²)

### ShouldRushToCover (0x007446F0)

Returns true when the bot should sprint to cover rather than move cautiously.

```
teamID = bot.GetTeamID()
enemyTeam = (teamID == 2) ? 3 : 2
knownEnemies = vision.GetKnownCount(enemyTeam, allTypes, noMaxAge)

if knownEnemies >= 3:
    return true  // many enemies — always rush

combatIntensity = vision.GetCombatIntensity()
return combatIntensity > threshold  // high intensity — rush
```

### FindNearbyCoverPosition (0x00748B30)

Searches surrounding nav areas for retreat spots using `CollectRetreatSpotsFunctor`.

```
startArea = bot.GetLastKnownArea()
if startArea == null: return null

positions[] = {}  // up to 256 entries
SearchSurroundingAreas(startArea, bot.AbsOrigin, maxDist=param, functor)

if positions.count > 0:
    return positions[RandomInt(0, count-1)]  // random selection
return null
```

### FindNearbyRetreatArea (0x007451C0)

BFS search for a retreat nav area using `CINSSearchForCover` functor (vtable 0x457A5D).
Returns a CNavArea pointer suitable for retreating to.

---

## Retreat Action Hierarchy

```
Threat detected / damage taken / grenade spotted
  │
  ├── CINSBotRetreatToCover         (short retreat to nearby cover)
  │     └── Uses locomotion AddMovementRequest
  │     └── Can fire at threat while retreating
  │     └── Arrives → Done or → CINSBotReload
  │
  ├── CINSBotRetreatToHidingSpot    (longer retreat to hiding spot)
  │     └── Uses CINSPathFollower for nav mesh pathing
  │     └── No attacking during retreat
  │     └── Arrives → Done or → CINSBotReload
  │
  └── CINSBotRetreat                (generic retreat using CINSRetreatPath)
        └── Uses CINSRetreatPath for movement away from threat
        └── No attacking during retreat
        └── Timer-based or arrival → Done or → CINSBotReload
```

---

## CINSBotRetreatToCover — Short Cover Retreat

### Object Layout (0x58 bytes estimated)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard Action<CINSNextBot> fields |
| 0x38 | Vector | m_coverPosition | Target cover position (X, Y, Z) |
| 0x44 | CountdownTimer | m_assessTimer | Threat assessment interval (0.25s) |
| 0x50 | byte | m_doReloadOnArrival | If true, transitions to CINSBotReload |
| 0x54 | float | m_retreatDuration | Duration override from caller |
| 0x58 | CountdownTimer | m_durationTimer | Overall retreat duration timer |

### OnStart (0x0072E870)

```
1. if m_coverPosition == vec3_origin:
     coverPos = bot.GetAnyCover()
     if coverPos == vec3_origin → ChangeTo CINSBotRetreat ("Bailing on retreat to cover")

2. Get primary known threat
   if threat exists and alive:
     Check if threat is a detonator (grenade/explosive)
     if within GetDetonateDamageRadius() → speak alarm (concept 0x68)

3. Set m_durationTimer = Now() + retreatDuration
4. bot.ResetIdleStatus()
5. locomotion.ClearMovementRequests()
6. locomotion.AddMovementRequest(m_coverPosition, speed=5.0, priority=6, mode=7)
7. return Continue
```

### Update State Machine (0x0072F050)

```
┌─ Idle timeout ──────────────────────────────────────────┐
│  if bot.IsIdle() && idleDuration >= 5.0s                │
│    → Done("Idle in retreat to cover")                   │
└─────────────────────────────────────────────────────────┘
         │
┌─ Duration timer check ──────────────────────────────────┐
│  if m_durationTimer.IsElapsed():                        │
│    if !m_doReloadOnArrival → Done("Retreat timer elapsed")│
│    else → ChangeTo CINSBotReload                        │
└─────────────────────────────────────────────────────────┘
         │
┌─ Distance check ────────────────────────────────────────┐
│  dist = |bot.AbsOrigin - m_coverPosition|               │
│                                                         │
│  if dist < 48.0:  (arrived at cover)                    │
│    if !m_doReloadOnArrival → Done("In Cover")           │
│    else → ChangeTo CINSBotReload                        │
│                                                         │
│  if dist >= 48.0:  (still moving)                       │
│    if m_assessTimer.IsElapsed():                        │
│      threat = GetPrimaryKnownThreat()                   │
│      if threat alive AND has ammo:                      │
│        AimHeadTowards(threat, blend=1.0)                │
│        FireWeaponAtEnemy()                               │
│      else if not moving:                                │
│        AimHeadTowards(coverPos, blend=0.5)              │
│      m_assessTimer = Now() + 0.25s                      │
│    return Continue                                      │
└─────────────────────────────────────────────────────────┘
```

**Key behavior:** RetreatToCover **fires at enemies while retreating** if threat is
alive and bot has ammo. Assessment interval is 0.25s.

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 | Always hurries |
| ShouldAttack | 2 | Conditional attack (fires during retreat) |
| GetName | "Retreating to cover" | |

### Event Handlers

| Event | Response |
|-------|----------|
| OnMoveToSuccess | Done or → CINSBotReload |
| OnMoveToFailure | Done or → CINSBotReload |
| OnStuck | Done("Im Stuck, help!") |
| OnInjured | Sustain (code 4) — continue retreat |

---

## CINSBotRetreatToHidingSpot — Defensive Retreat

Longer-range retreat using `CINSPathFollower` for nav mesh path following.
No attacking during retreat.

### Object Layout (large, embeds CINSPathFollower)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x38–0x48A7 | CINSPathFollower | m_pathFollower | Full path follower (huge) |
| 0x48A8 | Vector | m_hidingSpotPos | Target hiding spot position |
| 0x48BC | float | m_recalcTime | Next path recalculation time |
| 0x48C4 | float | m_distToTarget | Distance to hiding spot |
| 0x48CC | byte | m_doReloadAfter | If true, transitions to reload |
| 0x48D8 | float | m_retreatTimerExpiry | Retreat duration expiration |
| 0x48DC | int | m_savedState | Previous AI state (restored in OnEnd) |

### OnStart (0x0072FC10)

```
1. range = ConVar(ins_bot_retreat_to_hidingspot_range)
2. coverPos = bot.FindNearbyCoverPosition(range)
3. if coverPos == null → Done("Failed finding cover nearby...")
4. m_hidingSpotPos = coverPos
5. Save previous AI state
6. ComputePath(bot, m_hidingSpotPos)
7. return Continue
```

### Update (0x007303C0)

```
1. threat = GetPrimaryKnownThreat()
   if no threat → Done("No longer need to retreat")

2. if m_retreatTimerExpiry > 0 AND elapsed:
     if !m_doReloadAfter → Done("Retreat timer elapsed.")
     else → ChangeTo CINSBotReload

3. Periodically re-search for closer hiding spots (random 2.5-5.0s interval)
   if AreBotsOnTeamInCombat():
     Recompute path to new/existing hiding spot

4. PathFollower.Update() — follow nav mesh path

5. return Continue
```

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 | Always hurries |
| ShouldAttack | 0 | **No attacking** while retreating to hiding spot |
| GetName | "Retreating to hiding spot" | |

### Event Handlers

| Event | Response |
|-------|----------|
| OnMoveToSuccess | Continue or → CINSBotReload |
| OnMoveToFailure | Done or → CINSBotReload |
| OnStuck | Invalidate path, recompute (maxDist=30.0); if fail → Done |
| OnInjured | Sustain (code 4) if under sustained fire |

---

## CINSBotRetreat — Generic Retreat

Base retreat action using `CINSRetreatPath` to move away from threats.
Three constructor variants for different callers. ShouldAttack returns 2
(attack permitted) but the Update loop never calls FireWeaponAtEnemy — so
the bot effectively does not shoot while in this action.

### Object Layout (0x48F8 bytes, embeds CINSPathFollower + CINSRetreatPath)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard Action\<CINSNextBot\> fields |
| 0x38 | CINSRetreatPath | m_retreatPath | Vtable for CINSRetreatPath at +0x38 |
| 0x3C–0x4813 | CINSPathFollower | m_pathFollower | Full path follower (embedded) |
| 0x4814 | float | m_desiredSpeed | Set to 69.0 in OnStart |
| 0x48A8 | CountdownTimer | timer_0 | Path update re-check |
| 0x48B4 | int | m_threatEntityHandle | EHANDLE to stored threat entity |
| 0x48C4 | CountdownTimer | timer_1 | Path update interval (ConVar-driven) |
| 0x48D0 | byte | m_mode | 0 = Done on end, 1 = ChangeTo CINSBotReload |
| 0x48D4 | float | m_retreatDuration | Duration param, capped to max 5.0s |
| 0x48D8 | CountdownTimer | timer_2 | Total retreat duration countdown |
| 0x48E4 | CountdownTimer | timer_3 | No-threat wait timeout |
| 0x48F0 | byte | m_noThreatFlag | Set to 1 when no threat found |
| 0x48F4 | int | m_storedEntityIndex | Entity index passed via constructor |

### Constructor Variants

| Signature | Address | Notes |
|-----------|---------|-------|
| `CINSBotRetreat(bool doReload, float duration)` | 0x0072C190 | Sets mode from bool, duration from float |
| `CINSBotRetreat(float duration)` | 0x0072C420 | Mode=0 (Done), duration from param, default 5.0s |
| `CINSBotRetreat(int entityIndex)` | 0x0072C6A0 | Mode=0, duration=5.0, stores entity index at +0x48F4 |

### Key Timers

| Timer | Purpose | Default |
|-------|---------|---------|
| timer_1 | Path update interval | ConVar `ins_bot_path_update_interval` |
| timer_2 | Total retreat duration | 5.0s |
| timer_3 | No-threat wait timeout | 0.5s (then 0.4-0.6s random) |

### OnStart (0x0072BBD0)

```
1. duration = min(m_retreatDuration, 5.0)   // capped to 5 seconds max
   timer_2.Start(duration)

2. locomotion.ClearMovementRequests()
   m_desiredSpeed = 69.0

3. Get stored threat entity (via EHANDLE) or GetPrimaryKnownThreat()
4. if no threat:
     Set m_noThreatFlag = 1
     timer_3.Start(0.5s)
     return Continue
5. if threat exists:
     CINSRetreatPath::RefreshPath(threat.position)
     PathFollower.Update()

6. ResetIdleStatus()

7. if threat is CBaseDetonator with damage > 0:
     if distance(bot, detonator) < GetDetonateDamageRadius():
       SpeakConceptIfAllowed(0x68)  // alarm callout

8. return Continue
```

### Update (0x0072B780)

```
1. if bot.IsIdle() >= 5.0s → Done("Idle in retreat")
2. if no-threat flag AND timer_3 elapsed → Done
3. if timer_2 (duration) elapsed:
     if mode==0 → Done("Retreat timer elapsed")
     if mode==1 → ChangeTo CINSBotReload
4. if timer_1 (path update) elapsed:
     Re-check threat
     if no threat: set no-threat flag, start timer_3(0.4-0.6s random)
     if threat: CINSRetreatPath::Update(), reschedule timer_1
5. return Continue
```

### Mode Flag (bot+0x48D0)

| Value | Mode | On Success/Failure/Stuck |
|-------|------|--------------------------|
| 0 | RetreatToCover mode | Done (end action) |
| 1 | RetreatToHidingSpot mode | → CINSBotReload |

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 | Always hurries |
| ShouldAttack | 2 | Attack permitted but Update never fires (effectively no shooting) |
| GetName | "Retreating!" | |

---

## CINSBotAttackFromCover — Peek/Fire Cycles

Holds position in cover and alternates between crouching (hidden) and
peeking/firing at the enemy. The most sophisticated cover combat action.

### Object Layout (0x50 bytes)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x40 | CountdownTimer | m_peekTimer | Peek cycle timer |
| 0x4C | float | m_fireDuration | Fire phase duration (1.5s initial) |
| 0x50 | CountdownTimer | m_fireTimer | Fire phase countdown |
| 0x54 | byte | m_peekFlag | 1=peeking, 0=crouched |
| 0x60 | byte | m_losRight | LOS clear from right lean |
| 0x61 | byte | m_losStraight | LOS clear from straight |
| 0x62 | byte | m_losLeft | LOS clear from left lean |

### OnStart (0x007087E0)

```
1. threat = GetPrimaryKnownThreat()
   if no threat → Done

2. SetPosture(CROUCH, intensity=1.0)
   "Crouching in fire from cover start"

3. AimHeadTowards(threat, intensity=1.0)
   "Aiming towards enemy in fire from cover start"

4. m_fireTimer = Now() + fireCycleDuration (from constant)
5. m_fireDuration = 1.5
6. return Continue
```

### Update — Two-Phase Cycle (0x00709720)

**Fire Phase** (m_fireTimer not elapsed):
```
- Validate threat exists, alive, ShouldAttack == true
- Generate random duration: 5.0 - 10.0 seconds for fire cycle
- If NOT crouched:
    Stand up, continue firing
- If crouched:
    Check for opportunistic reload → SuspendFor CINSBotReload
    Aim at enemy, manage lean states
- Set aiming direction with lean offsets:
    Straight: 69.0 units vertical
    Left lean: 37.0 units vertical
    Right lean: 12.0 units vertical
    Horizontal: 32.0 unit lean multiplier
- Call FireWeaponAtEnemy() with lean state debug string
```

**Peek Phase** (m_fireTimer elapsed, m_peekTimer check):
```
- Revalidate threat and attack permission
- if elapsed > 6.0s → transition to next action
- Check grenade opportunity:
    if CanIThrowGrenade() → SuspendFor CINSBotThrowGrenade
- Set m_peekFlag = 1
- Clear peek if suppressed or needs reload
- UpdateLOS() — check all 3 lean directions
- if ALL 3 LOS checks fail (straight, left, right):
    → ChangeTo CINSBotAttackInPlace ("we have shitty cover")
- Reset peek timer with interval + 0.5s
```

### UpdateLOS (0x00708B40)

Tests line of sight from three positions relative to the bot:

```
eyePos = bot.EyePosition()
threatPos = threat.GetPosition()

// Straight shot (standing)
straightLOS = TraceLine(eyePos + (0, 0, 69.0), threatPos)
m_losStraight = !straightLOS.blocked

// Left lean
leftLOS = TraceLine(eyePos + (-32.0 * right, 0, 37.0), threatPos)
m_losLeft = !leftLOS.blocked

// Right lean
rightLOS = TraceLine(eyePos + (32.0 * right, 0, 12.0), threatPos)
m_losRight = !rightLOS.blocked
```

If none of the three positions have LOS, the cover is considered useless and the
bot transitions to CINSBotAttackInPlace.

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 0 | Don't hurry (holding position) |
| ShouldRetreat | 0 | Don't retreat (staying in cover) |
| ShouldAttack | 2 | Attack approved |
| ShouldIronsight | 1 | Always ironsight |
| ShouldProne | 0 | Never prone |
| ShouldWalk | 0 | Don't walk |
| GetName | "AttackFromCover" | |

---

## CINSBotAttackIntoCover — Assault to Cover

Moves the bot toward a cover position while engaging enemies along the way.
Transitions to `CINSBotAttackFromCover` upon arrival.

### Object Layout (0x54 bytes)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x44 | Vector | m_coverTarget | Destination cover position |
| 0x50 | byte | m_needsReload | Reload on arrival flag |
| 0x51 | byte | m_flag2 | Secondary behavior flag |
| 0x0F | CountdownTimer | m_updateTimer | 0.25s assessment interval |

### OnStart (0x0070CB80)

```
1. locomotion = bot.GetLocomotionInterface()
2. locomotion.AddMovementRequest(m_coverTarget, mode=2, priority=7, speed=5.0)
3. return Continue
```

### Update (0x0070C400)

```
┌─ Threat validation ─────────────────────────────────────┐
│  threat = GetPrimaryKnownThreat()                       │
│  if no threat / dead / ShouldNotAttack → Done           │
└─────────────────────────────────────────────────────────┘
         │
┌─ Timer check (0.25s interval) ──────────────────────────┐
│  if m_updateTimer not elapsed → Continue                │
└─────────────────────────────────────────────────────────┘
         │
┌─ Distance to cover check ───────────────────────────────┐
│  dist = GetDistanceToThreat(m_coverTarget)              │
│                                                         │
│  if arrived at cover:                                   │
│    if m_needsReload → ChangeTo CINSBotReload            │
│    else → ChangeTo CINSBotAttackFromCover ("Made It!")  │
│                                                         │
│  if within attack range:                                │
│    if threat hidden:                                    │
│      if ShouldRushToCover() → posture=CROUCH, sprint    │
│      else → posture=SPRINT                              │
│    if threat visible:                                   │
│      AimHeadTowards(threat), posture=WALK               │
│      PressIronsightButton(0.6)                          │
│    if still > 2.0s → Done("Rethink, been still")        │
│    FireWeaponAtEnemy()                                   │
│                                                         │
│  if out of range:                                       │
│    posture=SPRINT ("sprinting to cover position")       │
│                                                         │
│  m_updateTimer = Now() + 0.25s                          │
│  return Continue                                        │
└─────────────────────────────────────────────────────────┘
```

### ShouldRetreat Decision (0x0070C1A0)

Probabilistic retreat evaluation:

```
score = 0.25
if bot.HasEverBeenInjured():    score += 0.25
if bot.IsSuppressed():          score += 0.25
if ammoRatio < 0.1 (10%):      score += 0.25
if combatIntensity >= threshold: score += 0.25

if score > RandomFloat(0.0, 1.0):
    return true  (retreat)
return false
```

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1-2 | 1 if hurt/suppressed, 2 otherwise |
| ShouldRetreat | 0-1 | Probabilistic (see above) |
| ShouldAttack | 2 | Attack approved |
| ShouldIronsight | 1 | Always ironsight |
| ShouldProne | 0 | Never prone |
| ShouldWalk | 2 | Normal movement |
| IsHindrance | 0 | Nothing blocks |
| GetName | "AttackIntoCover" | |

---

## Bot Entity Cover Fields

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x2060 | ILocomotion* | m_locomotion | Locomotion interface pointer |
| 0x2174 | CUtlVector | m_coverContainer | INSBotCoverContainer entries |
| 0x2180 | int | m_coverCount | Number of cached cover entries |
| 0x2188 | float | m_lastCoverUpdate | Timestamp of last UpdateCover |
| 0x218C | Vector | m_coverSearchOrigin | Position used for cover BFS |
| 0x2198 | Vector | m_hidingCoverPos | Cached hiding cover position |
| 0x21A4 | float | m_hidingCoverTime | Timestamp of hiding cover cache |
| 0x21A8 | Vector | m_attackCoverPos | Cached attack cover position |
| 0x21B4 | float | m_attackCoverTime | Timestamp of attack cover cache |

### INSBotCoverContainer (0x0C = 12 bytes)

| Offset | Type | Field |
|--------|------|-------|
| 0x00 | int | navHidingSpot pointer |
| 0x04 | float | distance (from bot) |
| 0x08 | float | position.z or flag |

---

## ConVar Reference

### Core Cover ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `ins_bot_cover_debug` | 0 | Cover evaluation debug visualization |
| `ins_bot_entrench_suppression_threshold` | 0 | Suppression level that prevents peeking |
| `ins_bot_retreat_to_cover_range` | — | Max range for cover search |
| `ins_bot_retreat_to_hidingspot_range` | — | Max range for hiding spot search |
| `bot_behav_retreat_to_hidingspot_range` | — | Hiding spot search radius (engine) |
| `bot_loco_path_max_retreat_length` | 420 | Max distance bot will run a retreat path |
| `ins_bot_path_max_retreat_length` | — | Insurgency variant of max retreat length |
| `ins_nav_hiding_spot_update_rate` | 100 | Hiding spot update interval (ms) |
| `ins_bot_min_setup_gate_defend_range` | 750 | Min distance from gate for cover ambush |
| `nb_nav_hiding_spot_show_cover` | 0 | Debug: show hiding spot cover |
| `ins_nav_debug_cover_entities` | 0 | Debug: show cover entities |
| `ins_bot_path_update_interval` | — | How often retreat paths are recalculated |

### Hardcoded Constants

| Constant | Value | Where Used |
|----------|-------|------------|
| IsInCover radius | 48.0 (2304.0 = 48²) | IsInCover distance check |
| Cover cache expiry | 5.0s | GetAttackCover, GetHidingCover |
| UpdateCover throttle | 1.0s | UpdateCover interval |
| Combat re-search threshold | 500.0 | UpdateCover: distance to trigger BFS |
| BFS search max distance | 2000.0 | UpdateCover: nav area search limit |
| Idle timeout | 5.0s | All retreat actions |
| RetreatToCover arrival | 48.0 | Update: distance to consider "at cover" |
| Threat assess interval | 0.25s | RetreatToCover and AttackIntoCover |
| Retreat speed | 69.0 | CINSBotRetreat: movement speed |
| MovementRequest speed | 5.0 | RetreatToCover, AttackIntoCover |
| AimHeadTowards blend (cover) | 0.5 | RetreatToCover: looking at cover |
| AimHeadTowards blend (threat) | 1.0 | RetreatToCover: looking at threat |
| Attack cover LOS height | 69.0 | GetAttackCover: Z offset for fire check |
| Lean straight offset | 69.0 | AttackFromCover: vertical offset |
| Lean left offset | 37.0 | AttackFromCover: vertical offset |
| Lean right offset | 12.0 | AttackFromCover: vertical offset |
| Lean horizontal | 32.0 | AttackFromCover: horizontal lean |
| Fire phase duration | 5.0-10.0s | AttackFromCover: random range |
| Initial fire duration | 1.5s | AttackFromCover: OnStart |
| Peek interval | 0.5s | AttackFromCover: cycle interval |
| Max engagement time | 6.0s | AttackFromCover: triggers transition |
| Ironsight pressure | 0.6 | AttackIntoCover: ironsight button |
| Still rethink threshold | 2.0s | AttackIntoCover: if still too long |
| Low ammo threshold | 0.1 (10%) | AttackIntoCover: retreat factor |
| Rush enemy count | 3 | ShouldRushToCover: max enemies |
| Path recalc interval | 2.5-5.0s | RetreatToHidingSpot: random range |
| Stuck recompute distance | 30.0 | RetreatToHidingSpot: OnStuck |
| No-threat timeout | 0.5s | CINSBotRetreat: initial wait |
| No-threat random range | 0.4-0.6s | CINSBotRetreat: rechecks |
| Retreat duration default | 5.0s | CINSBotRetreat: timer_2 |
| Reload suspension time | 10.0s | AttackFromCover: reload timer |

---

## Function Address Table

### Cover Evaluation (CINSNextBot)

| Address | Function | Notes |
|---------|----------|-------|
| 0x0074AC70 | UpdateCover | Periodic cover container refresh + sort |
| 0x00745B70 | GetAttackCover | Find offensive cover with LOS to threat |
| 0x00744790 | GetHidingCover | Find safe hiding spot from all threats |
| 0x007460F0 | GetAnyCover | Try hiding first, fallback to attack |
| 0x00744DB0 | IsInCover | Within 48u of cached cover position |
| 0x007446F0 | ShouldRushToCover | Enemies < 3 AND high combat intensity |
| 0x00748B30 | FindNearbyCoverPosition | BFS with CollectRetreatSpotsFunctor |
| 0x007451C0 | FindNearbyRetreatArea | BFS with CINSSearchForCover functor |
| 0x007453F0 | FindNearbyRetreatPosition | Wraps FindNearbyRetreatArea → center |
| 0x00733000 | SortBotCoverSpots | CUtlVector sort comparator |

### Retreat Actions

| Address | Function | Action |
|---------|----------|--------|
| 0x0072E870 | RetreatToCover::OnStart | Find cover, setup movement |
| 0x0072F050 | RetreatToCover::Update | Move + fire at threat |
| 0x0072FC10 | RetreatToHidingSpot::OnStart | Find hiding spot, compute path |
| 0x007303C0 | RetreatToHidingSpot::Update | Follow path, recompute periodically |
| 0x0072BBD0 | Retreat::OnStart | Setup retreat path from threat |
| 0x0072B780 | Retreat::Update | Follow retreat path, timer-based |

### Combat Cover Actions

| Address | Function | Action |
|---------|----------|--------|
| 0x007087E0 | AttackFromCover::OnStart | Crouch, aim at threat |
| 0x00709720 | AttackFromCover::Update | Peek/fire cycles, LOS check |
| 0x00708B40 | AttackFromCover::UpdateLOS | 3-position raycast check |
| 0x0070CB80 | AttackIntoCover::OnStart | Movement request to cover |
| 0x0070C400 | AttackIntoCover::Update | Move + fire, arrive → FromCover |
| 0x0070C1A0 | AttackIntoCover::ShouldRetreat | Probabilistic retreat score |
