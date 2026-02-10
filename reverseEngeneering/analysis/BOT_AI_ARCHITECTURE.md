# Insurgency (2014) Bot AI Architecture — Reverse Engineering Report

## Binary Info
- **Target:** `server_srv.so` (15.2 MB, ELF 32-bit, **not stripped**)
- **Engine:** Source Engine (Valve), INS branch by New World Interactive
- **Bot Framework:** NextBot (Valve) with NWI custom extensions
- **Engine bot management:** Minimal — `engine_srv.so` only has `CBaseServer::IsPlayingSoloAgainstBots()` and `sv_stressbots`. All real bot logic lives in `server_srv.so`.

---

## 1. Class Hierarchy

```
CBaseEntity
 └─ CBaseAnimating
     └─ CBaseAnimatingOverlay
         └─ CBaseFlex
             └─ CBaseCombatCharacter
                 └─ CBasePlayer
                     └─ CBaseMultiplayerPlayer
                         └─ CINSPlayer
                             └─ NextBotPlayer<CINSPlayer>   (+ INextBot, INextBotPlayerInput)
                                 └─ CINSNextBot             ← THE BOT ENTITY
```

`CINSNextBot` inherits from:
- **NextBotPlayer<CINSPlayer>** — Source Engine's NextBot player template
- **INextBot** (via NextBotPlayer) — core bot interface
- **INextBotPlayerInput** (via NextBotPlayer) — button input simulation

### Bot Subsystem Classes (Components)

| Component Class | Base Interface | Role |
|---|---|---|
| `CINSBotBody` | `IBody` | Posture (stand/crouch/prone), arousal state, head aiming |
| `CINSBotLocomotion` | `ILocomotion` (via `NextBotGroundLocomotion`) | Movement, pathfinding, stance during movement |
| `CINSBotVision` | `IVision` | Sight, threat detection, silhouette recognition, LOS |
| `CINSNextBot::CINSNextBotIntention` | `IIntention` | Behavior tree root, holds `Behavior<CINSNextBot>` |

### Manager

| Class | Role |
|---|---|
| `CINSNextBotManager` (extends `NextBotManager`) | Bot spawning, lifecycle, grenade coordination, objective assignment, reinforcement waves, team-level commands |

---

## 2. Behavior Tree Architecture

The bot uses Source Engine's **Action<> / Behavior<>** system — a hierarchical state machine with suspend/resume semantics.

### Action Lifecycle

```
Action::OnStart(bot, priorAction)     ← called once when action begins
Action::Update(bot, interval)         ← called every tick; returns Continue/ChangeTo/SuspendFor/Done
Action::OnEnd(bot, nextAction)        ← called when action is being replaced
Action::OnSuspend(bot, interrupter)   ← when a higher-priority action interrupts
Action::OnResume(bot, interrupted)    ← when the interrupting action completes
Action::InitialContainedAction(bot)   ← factory for child action (nesting)
```

### Transition Types
- **Continue()** — keep running this action
- **ChangeTo(newAction)** — replace this action with newAction (OnEnd → newAction.OnStart)
- **SuspendFor(newAction)** — push newAction on the stack (current is suspended, resumes later)
- **Done()** — pop this action, resume whatever was below it

### Action Tree Structure

```
CINSNextBot::CINSNextBotIntention
 └─ Behavior<CINSNextBot>
     └─ CINSBotMainAction                    ← ROOT ACTION
         ├─ CINSBotTacticalMonitor           ← CHILD (contained action)
         │   ├─ CINSBotGamemodeMonitor       ← CHILD (contained action)
         │   │   └─ [gamemode-specific action]  ← per-gamemode objective logic
         │   └─ CINSBotInvestigationMonitor  ← CHILD (contained action)
         │       └─ CINSBotPatrol            ← default roaming behavior
         │
         └─ [combat/behavior actions]         ← pushed via SuspendFor when events fire
             (CINSBotCombat, CINSBotRetreat, CINSBotDead, etc.)
```

---

## 3. All Action Classes

### Core Actions (Behavior States)

| Class | Purpose |
|---|---|
| `CINSBotMainAction` | Root action. Threat evaluation, target selection, stuck handling |
| `CINSBotTacticalMonitor` | Monitors tactical situation. Triggers combat/retreat. Checks posture. |
| `CINSBotGamemodeMonitor` | Selects gamemode-specific sub-action based on active game rules |
| `CINSBotInvestigationMonitor` | Reacts to sounds (footsteps, gunfire, kills) by creating investigations |
| `CINSBotPatrol` | Default movement — wander toward objective areas |

### Combat Actions

| Class | Purpose |
|---|---|
| `CINSBotCombat` | Main combat state. Selects weapon-specific sub-action. |
| `CINSBotAttack` | Base attack behavior |
| `CINSBotAttackRifle` | Rifle engagement (most common) |
| `CINSBotAttackSniper` | Long-range engagement |
| `CINSBotAttackLMG` | LMG sustained fire behavior |
| `CINSBotAttackPistol` | Pistol engagement |
| `CINSBotAttackMelee` | Melee/knife attack |
| `CINSBotAttackCQC` | Close quarters combat |
| `CINSBotAttackAdvance` | Advancing while attacking |
| `CINSBotAttackFromCover` | Shooting from cover position |
| `CINSBotAttackInPlace` | Stationary engagement |
| `CINSBotAttackIntoCover` | Moving to cover while engaging |
| `CINSBotFireRPG` | RPG/rocket engagement |
| `CINSBotSuppressTarget` | Suppressive fire at known/suspected position |

### Movement/Positioning Actions

| Class | Purpose |
|---|---|
| `CINSBotApproach` | Navigate toward a position |
| `CINSBotPursue` | Chase a specific enemy |
| `CINSBotRetreat` | Fall back from threat |
| `CINSBotRetreatToCover` | Move to nearest cover |
| `CINSBotRetreatToHidingSpot` | Move to a hiding spot |
| `CINSBotEscort` | Follow/escort a target entity |
| `CINSBotFollowCommand` | Follow player command |
| `CINSBotSweepArea` | Clear/sweep an area |
| `CINSBotInvestigate` | Investigate a position |
| `CINSBotInvestigateGunshot` | Investigate where gunfire was heard |

### Objective Actions

| Class | Purpose |
|---|---|
| `CINSBotCaptureCP` | Capture a control point |
| `CINSBotCaptureFlag` | Capture a flag |
| `CINSBotGuardCP` | Guard/defend a control point |
| `CINSBotGuardDefensive` | General defensive guard behavior |
| `CINSBotDestroyCache` | Destroy a weapon cache (coop) |

### Utility Actions

| Class | Purpose |
|---|---|
| `CINSBotReload` | Reload weapon |
| `CINSBotThrowGrenade` | Throw a grenade |
| `CINSBotDead` | Death/respawn state |
| `CINSBotFlashed` | Flashbang recovery |
| `CINSBotStuck` | Stuck recovery |
| `CINSBotSpecialAction` | Special contextual actions |

### Gamemode-Specific Actions

| Class | Game Mode |
|---|---|
| `CINSBotActionAmbush` | Ambush |
| `CINSBotActionCheckpoint` | Checkpoint (coop) |
| `CINSBotActionConquer` | Conquer |
| `CINSBotActionFirefight` | Firefight |
| `CINSBotActionFlashpoint` | Flashpoint |
| `CINSBotActionHunt` | Hunt |
| `CINSBotActionInfiltrate` | Infiltrate |
| `CINSBotActionOccupy` | Occupy |
| `CINSBotActionOutpost` | Outpost |
| `CINSBotActionPush` | Push |
| `CINSBotActionSkirmish` | Skirmish |
| `CINSBotActionStrike` | Strike |
| `CINSBotActionSurvival` | Survival |
| `CINSBotActionTraining` | Training |

---

## 4. Per-Tick Bot Update Flow

```
Engine tick
 └─ NextBotManager::Update()
     └─ CINSNextBotManager::Update()            ← updates grenades, targets, formations
         └─ For each CINSNextBot:
             ├─ INextBot::Update()
             │   ├─ CINSBotVision::Update()      ← scan for enemies, update known entities
             │   │   ├─ CollectPotentiallyVisibleEntities()
             │   │   ├─ UpdatePotentiallyVisibleNPCVector()
             │   │   ├─ UpdateSilhouettes()       ← silhouette recognition system
             │   │   └─ CalculatePrimaryThreat()   ← threat assessment
             │   ├─ CINSBotBody::Update()         ← update posture, arousal, head aim
             │   │   ├─ UpdatePosture()
             │   │   └─ UpdateArousal()
             │   ├─ CINSBotLocomotion::Update()   ← movement execution
             │   │   ├─ UpdateMovement()
             │   │   └─ UpdateMovementPosture()
             │   └─ CINSNextBot::CINSNextBotIntention::Update()
             │       └─ Behavior<CINSNextBot>::Update()
             │           └─ CINSBotMainAction::Update()      ← decision loop
             │               ├─ [evaluate threats]
             │               ├─ CINSBotTacticalMonitor::Update()
             │               │   ├─ CheckPosture()
             │               │   ├─ [check if should enter combat]
             │               │   ├─ CINSBotGamemodeMonitor::Update()
             │               │   │   └─ [gamemode action]::Update()
             │               │   └─ CINSBotInvestigationMonitor::Update()
             │               │       └─ [investigation/patrol]::Update()
             │               └─ [current behavior action]::Update()
             │
             ├─ CINSNextBot::Update()             ← NWI custom update
             │   ├─ UpdateCover()                 ← scan for cover positions
             │   ├─ UpdateIdleStatus()
             │   ├─ AdjustCombatState()
             │   ├─ SortAndRemoveInvestigations()
             │   ├─ SortAndRemoveOrders()
             │   └─ AvoidPlayers()
             │
             └─ CINSNextBot::Upkeep()            ← high-frequency update
                 └─ CINSBotLocomotion::Upkeep()   ← movement smoothing
```

---

## 5. Key Decision Systems

### 5.1 Threat Assessment (`CINSBotVision` + `CINSThreatAssessment`)

The vision system maintains a list of `CKnownEntity` objects. Each tick:

1. **CollectPotentiallyVisibleEntities()** — gathers nearby entities
2. **IsAbleToSee()** / **IsLineOfSightClear()** — LOS checks with FOV
3. **IsVisibleEntityNoticed()** — recognition delay based on difficulty
4. **CanReadSilhouette()** — silhouette detection (can detect partial visibility)
5. **CalculatePrimaryThreat()** — scores threats using `GetAssessmentScore()`
6. **GetPrimaryKnownThreat()** — returns the highest-priority threat

`CINSThreatAssessment::Inspect()` scores each known entity based on:
- Distance, visibility, time since last seen
- Whether the threat is actively shooting
- Suppression status

### 5.2 Arousal System (`CINSBotBody`)

NWI added an **arousal** system on top of the base `IBody`:

```
ArousalType: NEUTRAL → ALERT → INTENSE (presumably)
```

Arousal affects:
- Aim tracking speed (`ins_bot_arousal_frac_aimtracking_*`)
- Angular velocity (`ins_bot_arousal_frac_angularvelocity_*`)
- Attack delay (`ins_bot_arousal_frac_attackdelay_*`)
- Aim tolerance (`ins_bot_arousal_frac_aimtolerance_*`)
- Aim penalty (`ins_bot_arousal_frac_aimpenalty_*`)
- Recognition time (`ins_bot_arousal_frac_recognizetime_*`)

Arousal increments from:
- Combat encounters (`ins_bot_arousal_combat_max/falloff`)
- Firing weapons (`ins_bot_arousal_firing_max/falloff`)
- Being suppressed (`ins_bot_arousal_suppression_max/falloff`)

### 5.3 Cover System (`CINSNextBot`)

Key methods:
- `GetHidingCover(bool)` — find full cover from all threats
- `GetAttackCover(bool)` — find cover that allows firing
- `GetClosestPartialCover()` — partial concealment
- `GetAnyCover()` — any cover spot
- `IsInCover()` — check current position
- `FindNearbyCoverPosition(float)` — local cover search
- `FindNearbyRetreatArea(float)` / `FindNearbyRetreatPosition(float)` — retreat spots

Cover positions stored as `INSBotCoverContainer` structs, sorted by `SortBotCoverSpots()`.
Cover is evaluated via `CINSSearchForCover` and `CINSTestAreaAgainstThreats`.

### 5.4 Aim System (`CINSNextBot`)

**Aiming pipeline:**
1. `GetTargetPosition(target)` — get world position of target
2. `ComputePartPositions(player)` — compute visible body parts
3. `GetPartPosition(player, partType)` — select aim point (head, chest, etc.)
4. `ApplyAimPenalty(threat, aimVector)` — add difficulty-based error
5. `GetAimToleranceBloat(threat)` — tolerance before firing
6. `FireWeaponAtEnemy()` / `FireActiveWeapon()` — execute fire

**Targeting noise** (randomized aim offset):
- `bot_targeting_noise_{x,y,z}_base` — base noise at desired range
- Scaled by range fractions: `desiredrange`, `hipfirerange`, `maxrange`
- Solo variants (`_solo`) for when bot is alone

**Attack delay:**
- `bot_attackdelay_base` — minimum delay before firing
- Scaled by: range fraction, difficulty, FOV check, survival wave

### 5.5 Weapon Selection (`CINSNextBot`)

- `ChooseBestWeapon(CKnownEntity*)` — select based on threat range
- `ChooseBestWeapon(CINSWeapon*, float)` — select based on distance
- `GetMaxAttackRange(weapon)` / `GetDesiredAttackRange(weapon)` / `GetMaxHipFireAttackRange(weapon)`
- `ShouldReload()` / `ShouldOpportunisticReload()` — reload decisions
- `GetActiveWeaponAmmoRatio()` — ammo management
- `CheckAnyAmmo()` — empty weapon handling
- `GetPistolFireRate()` — pistol-specific fire rate

### 5.6 Movement System (`CINSBotLocomotion`)

Extended from `NextBotGroundLocomotion` with:
- **Movement requests** — queued movements with priorities (`INSBotPriority`)
- `AddMovementRequest(pos, type, priority, weight)` — add a request
- `ClearMovementRequests(priority)` — clear lower-priority requests
- `ApplyMovementRequest(id)` — execute specific request
- **Stance control** — `GetMovementStance()`, `AdjustPosture()`, `GetBehaviorStance()`
- **Posture** — `GetDesiredPostureForRequest()`, `UpdateMovementPosture()`
- **Path following** — `CINSPathFollower`, `CINSRetreatPath`

### 5.7 Silhouette Recognition (`CINSBotVision`)

A unique NWI system where bots detect enemies through partial visibility:
- `GetSilhouetteType(entity)` — classify what's visible
- `CanReadSilhouette(knownEntity)` — can bot identify the silhouette
- `UpdateSilhouettes()` — per-tick silhouette scan

ConVars:
- `bot_silhouette_range_close/far/movement` — detection ranges
- `bot_silhouette_readtime_clear/dark/fuzzy` — time to identify
- `bot_silhouette_light_threshold_low/medium` — lighting affects detection
- `bot_silhouette_discover_timer` / `bot_silhouette_scan_frequency`

---

## 6. Communication Systems

### BotMeme System
- `BotMeme::Transmit(CINSNextBot*)` — propagate information to other bots
- `BotEnemySpottedMeme` — notify team of spotted enemy
- `BotFragOut` — grenade warning

### Order System
- `CINSNextBot::AddOrder(radialCommand, ...)` — receive player commands
- `CINSNextBot::GetCurrentOrder()` / `GetCurrentOrderRadialCommand()`
- `CINSNextBotManager::IssueOrder(...)` — manager-level orders
- `CINSNextBotManager::CommandApproach()` / `CommandAttack()`

### Investigation System
- `CINSNextBot::AddInvestigation(area/vector/entity, priority)` — add investigation target
- `CINSBotInvestigationMonitor` reacts to:
  - `OnWeaponFired()` — gunfire
  - `OnHeardFootsteps()` — footsteps
  - `OnOtherKilled()` — teammate deaths
  - `OnSeeSomethingSuspicious()` — suspicious activity

### 6.1 NWI-Added Event Responder Methods

These four events are **NWI additions** to `INextBotEventResponder` (not present in the base Valve framework). They propagate through the entire action hierarchy like standard events:

| Event | Signature | Purpose |
|---|---|---|
| `OnHeardFootsteps` | `(CBaseCombatCharacter*, Vector const&)` | Footstep audio — triggers investigation |
| `OnSeeSomethingSuspicious` | `(CBaseCombatCharacter*, Vector const&)` | Pre-recognition awareness (movement/shape seen but not yet ID'd) |
| `OnBlinded` | `(CBaseEntity*)` | Flashbang effect — entity that caused it |
| `OnOrderReceived` | `()` | Squad leader voice command received |

---

## 7. Nav Mesh Extensions (`CINSNavArea` / `CINSNavMesh`)

The navigation mesh is heavily extended with spatial awareness data that drives bot decisions.

### 7.1 Combat Heat Mapping

Nav areas actively track combat state:
- `OnCombat()` / `IsInCombat()` / `GetCombatIntensity()` — per-area combat heat
- `OnDeath(int team)` / `GetDeathIntensity(int team)` / `GetNearbyDeathIntensity(int team)` — death tracking per team
- `ComputeDangerSpotData()` — precomputed danger zones

### 7.2 Spatial Awareness

- `HasAdjacentOutsideArea()` / `HasAdjacentInsideArea()` / `GetInOutAdjacentCount()` — indoor/outdoor detection
- `IsDoorway()` — doorway identification for tactical movement
- `IsPotentiallyVisibleToTeam(int)` / `AddPotentiallyVisibleActor()` — lightweight area-level PVS
- `CINSNavMesh::IsPotentiallyVisible()` — 4 overloads (area-area, area-vector, vector-area, vector-vector)
- `CINSNavMesh::GetLightIntensity(CBaseEntity*)` — lighting queries that feed the silhouette system

### 7.3 Hiding Spot Scoring

- `ScoreHidingSpot(HidingSpot*)` — score each hiding spot
- `ResetHidingSpotScores()` / `CollectSpotsWithScoreAbove(float, ...)` — filtered spot collection
- `GetDistanceToNearestHidingSpot(Vector)` — distance queries
- `UpdateCover(float*)` — cover data refresh per area

### 7.4 Control Point / Spawn Integration

- `AssociateWithControlPoint(int)` / `GetAssociatedControlPoint()` — areas linked to objectives
- `AssociateWithSpawnZone(CINSSpawnZone*)` / `GetAssociatedSpawnZone()` — areas linked to spawns
- `GetSpawnScore(int)` / `InvalidateSpawnScore(int)` — spawn scoring
- `CINSNavMesh::GetRandomControlPointArea()` / `GetRandomControlPointSurroundingArea()` / `GetControlPointHidingSpot()`
- `CINSNavMesh::CalculateDistancesToControlPoint(int)` — precomputed CP distances

### 7.5 Bot Traffic Management

- `AddPathingBot(CBaseCombatCharacter*, float)` / `RemovePathingBot()` / `CleanupPathingBots()` — tracks which bots are pathing through each area
- Used by `CINSPathFollower::WaitToPass()` and `GetHindrance()` for congestion handling

### 7.6 Mesh Decoration

- `CINSNavMesh::DecorateMesh()` / `CollectAreasOfType()` / `CollectControlPointAreas()` — annotates nav areas with game-specific data
- `GetAreasOfType(INSNavAreaTypes)` — query areas by type
- `ComputeBlockedAreas()` / `OnBlockedAreasChanged()` — dynamic area blocking

---

## 8. Pathfinding Extensions

### CINSPathFollower

Extends base `PathFollower` with:
- `ComputePath(INextBot*, Vector, RouteType, float, bool, float)` — adds `RouteType` parameter
- `CanCompute(INextBot*)` — gating check before pathfinding
- `IsComputeExpired(INextBot*)` / `GetTimeSinceLastCompute()` — path recomputation throttling
- `FindBlocker(INextBot*)` — identify path-blocking entities
- `WaitToPass(INextBot*)` — congestion handling (waits for area to clear)
- `GetHindrance()` — what's currently blocking
- `IsDiscontinuityAhead()` — gap/ledge detection
- `AdjustSpeed(INextBot*)` — dynamic speed adjustment on path

### CINSRetreatPath

Dedicated retreat pathing:
- `RefreshPath(INextBot*, CBaseEntity*)` — compute path away from a specific threat
- `GetMaxPathLength()` — capped retreat distance (see `ins_bot_path_max_retreat_length`)

---

## 9. Contextual Query Matrix

NWI extended `IContextualQuery` with `ShouldWalk`, `ShouldIronsight`, `ShouldProne`, and `ShouldPursue`. These bubble up through the action stack — the deepest action that overrides the query wins.

### Which Actions Override Which Queries

| Action | Walk | Ironsight | Prone | Pursue |
|---|---|---|---|---|
| `CINSBotMainAction` | | | | YES |
| `CINSBotTacticalMonitor` | YES | | | |
| `CINSBotCombat` | | | | YES |
| `CINSBotAttack` | YES | YES | | |
| `CINSBotAttackRifle` | YES | YES | YES | |
| `CINSBotAttackSniper` | YES | YES | YES | |
| `CINSBotAttackLMG` | YES | YES | YES | |
| `CINSBotAttackPistol` | YES | YES | YES | |
| `CINSBotAttackMelee` | YES | YES | YES | |
| `CINSBotAttackCQC` | YES | YES | YES | |
| `CINSBotAttackAdvance` | YES | YES | YES | |
| `CINSBotAttackFromCover` | YES | YES | YES | |
| `CINSBotAttackInPlace` | YES | YES | YES | |
| `CINSBotAttackIntoCover` | YES | YES | YES | |
| `CINSBotSuppressTarget` | | YES | | |
| `CINSBotApproach` | YES | | | |
| `CINSBotPursue` | YES | | | |
| `CINSBotPatrol` | YES | | | |
| `CINSBotEscort` | YES | | | |
| `CINSBotInvestigate` | YES | | | |
| `CINSBotInvestigateGunshot` | YES | | | |
| `CINSBotFireRPG` | YES | | | |
| `CINSBotThrowGrenade` | YES | | | |
| `CINSBotActionHunt` | YES | | | |
| `CINSBotActionOutpost` | YES | | | |

Key insight: weapon-specific attack actions control all three movement/posture queries (walk/ironsight/prone), giving each weapon type its own movement and stance behavior. `ShouldPursue` is gated by only `CINSBotCombat` and `CINSBotMainAction`.

---

## 10. Solo vs Group Behavior

Several ConVars have `_solo` variants, indicating bots behave differently when only one human is present:

| Standard | Solo Variant | Effect |
|---|---|---|
| `bot_targeting_noise_{x,y,z}_base` | `bot_targeting_noise_{x,y,z}_base_solo` | Wider/narrower aim noise |
| `bot_attack_burst_mintime/maxtime` | `bot_attack_burst_mintime/maxtime_solo` | Different burst durations |
| `bot_attack_aimtolerance_newthreat_amt` | `bot_attack_aimtolerance_newthreat_amt_solo` | Different tolerance on new threats |
| `bot_attack_aimtolerance_newthreat_time` | `bot_attack_aimtolerance_newthreat_time_solo` | Different reaction timing |

This suggests NWI tuned bots to be more/less forgiving based on player count.

---

## 11. Escort Formation System

A full formation system for bot escort behavior:

- `INSBotEscortFormation` — standalone class, `UpdatePositions()` computes formation slots
- `CINSBotEscort::AddToEscortFormation()` — assign bot to a formation
- `CINSBotEscort::UpdateEscortFormations()` / `UpdateFormationMovement()` — per-tick formation update
- `CINSBotEscort::GetEscortFormation(CBaseEntity*)` — get formation for a target
- `CINSNextBot::SetEscortFormation()` / `IsInFormation()` — bot-level formation state
- `CINSNextBot::GetHumanSquadmate()` / `UTIL_INSGetHumanSquadmate()` — bots know their human squadmate
- Static: `CINSBotEscort::m_escortFormations` — global formation registry

---

## 12. Outpost Mode Bot Smoke System

Outpost mode has a dedicated bot smoke grenade subsystem:

```
ins_outpost_bot_smoke_length_max/min       — smoke duration
ins_outpost_bot_smoke_amount_total/max/min — smoke count limits
ins_outpost_bot_smoke_variance             — timing randomization
ins_outpost_bot_smoke_interval_max/min     — time between smokes
ins_outpost_bot_smoke_scale_max/min        — smoke size
ins_outpost_bot_spawn_update_interval      — spawn wave timing
ins_outpost_bot_spawn_distance             — spawn distance from players
```

---

## 13. Notable Negative Findings

- **No VScript exposure** — zero VScript bindings for bot manipulation. Bots are entirely C++ driven.
- **No `engine_srv.so` bot logic** — only `CBaseServer::IsPlayingSoloAgainstBots()` and `sv_stressbots`. All real logic is in `server_srv.so`.

---

## 14. Difficulty System

`CINSNextBot::BotDifficulty_e` — per-bot difficulty level

Changed via: `CINSNextBot::ChangeDifficulty()` / `ins_bot_difficulty` / `ins_bot_change_difficulty`

Difficulty affects (via `_frac_easy`, `_frac_hard`, `_frac_impossible` suffixed ConVars):
- FOV (wider = easier to spot things)
- Aim tracking speed
- Angular velocity (turn speed)
- Attack delay
- Aim tolerance (accuracy)
- Aim penalty amount
- Recognition time

---

## 15. Gamemode Integration

`CINSBotGamemodeMonitor::InitialContainedAction()` selects one of these based on active game rules:

| Game Rules Class | Bot Action | Notes |
|---|---|---|
| `CINSRules_Ambush` | `CINSBotActionAmbush` | |
| `CINSRules_Checkpoint` | `CINSBotActionCheckpoint` | Main coop mode |
| `CINSRules_Conquer` | `CINSBotActionConquer` | |
| `CINSRules_Firefight` | `CINSBotActionFirefight` | |
| `CINSRules_Flashpoint` | `CINSBotActionFlashpoint` | |
| `CINSRules_Hunt` | `CINSBotActionHunt` | |
| `CINSRules_Infiltrate` | `CINSBotActionInfiltrate` | |
| `CINSRules_Occupy` | `CINSBotActionOccupy` | |
| `CINSRules_Outpost` | `CINSBotActionOutpost` | |
| `CINSRules_Push` | `CINSBotActionPush` | |
| `CINSRules_Skirmish` | `CINSBotActionSkirmish` | |
| `CINSRules_Strike` | `CINSBotActionStrike` | |
| `CINSRules_Survival` | `CINSBotActionSurvival` | |
| `CINSRules_Training` | `CINSBotActionTraining` | |

Manager provides objective selection per mode:
- `GetDesiredSkirmishObjective()`
- `GetDesiredBattleTypeObjective()`
- `GetDesiredPushTypeObjective()`
- `GetDesiredOccupyTypeObjective()`
- `GetDesiredHuntTypeObjective()`
- `GetDesiredStrongholdTypeObjective()`

---

## 16. CINSNextBotManager — Team-Level AI

The manager handles:

**Spawning:**
- `BotAddCommand()` — spawns bots
- `ins_bot_quota` — automatic bot count
- `ins_bot_count_{mode}` — per-mode bot counts
- `ins_bot_count_{mode}_max/min/default` — count bounds

**Coordination:**
- `OnPointContested()` / `OnPointCaptured()` — react to objective changes
- `CommandApproach()` / `CommandAttack()` — issue team-wide orders
- `IssueOrder()` — radial command-style orders to bots
- `AreBotsOnTeamInCombat()` — check team combat status

**Reinforcements:**
- `CanCallForReinforcements()` / `CallForReinforcements()` / `GetCallForReinforcementCooldown()`

**Grenade Coordination:**
- `UpdateGrenades()` / `UpdateGrenadeTargets()` — track active grenades
- `GenerateCPGrenadeTargets()` — compute grenade targets for control points
- `AddGrenadeTarget()` / `GetGrenadeTargets()`
- `OnGrenadeThrown()` / `OnGrenadeDetonate()`

---

## 17. Key Function Addresses

### CINSNextBot Core
| Address | Function |
|---|---|
| `0x00738c00` | `CINSNextBot::CINSNextBot()` — constructor |
| `0x0073a3c0` | `CINSNextBot::Spawn()` |
| `0x0073b440` | `CINSNextBot::Update()` — per-tick update |
| `0x00733380` | `CINSNextBot::Upkeep()` — high-frequency update |
| `0x00733e10` | `CINSNextBot::Event_Killed()` |
| `0x0073ac70` | `CINSNextBot::UpdateCover()` |
| `0x0074ae70` | `CINSNextBot::FireWeaponAtEnemy()` |
| `0x0075ee60` | `CINSNextBot::FireActiveWeapon()` |
| `0x0074b9d0` | `CINSNextBot::ApplyAimPenalty()` |
| `0x0075e540` | `CINSNextBot::ChooseBestWeapon(CKnownEntity*)` |
| `0x0075f3b0` | `CINSNextBot::CanIAttack()` |
| `0x0075f3f0` | `CINSNextBot::GetTargetNoise()` |
| `0x0074c600` | `CINSNextBot::ComputeChasePath()` |
| `0x0074ca70` | `CINSNextBot::ComputePathFollower()` |
| `0x0073bce0` | `CINSNextBot::AddInvestigation()` |
| `0x0073beb0` | `CINSNextBot::AddOrder()` |
| `0x0073beb0` | `CINSNextBot::AvoidPlayers()` |

### Behavior Actions
| Address | Function |
|---|---|
| `0x00743aa0` | `CINSBotMainAction::Update()` — root decision |
| `0x00743800` | `CINSBotMainAction::InitialContainedAction()` — spawns TacticalMonitor |
| `0x00744640` | `CINSBotMainAction::SelectMoreDangerousThreatInternal()` |
| `0x00744200` | `CINSBotMainAction::IsImmediateThreat()` |
| `0x00731bc0` | `CINSBotTacticalMonitor::Update()` |
| `0x007316a0` | `CINSBotTacticalMonitor::CheckPosture()` |
| `0x00706550` | `CINSBotCombat::Update()` |

### Vision
| Address | Function |
|---|---|
| `0x0075adb0` | `CINSBotVision::Update()` — main vision loop |
| `0x0075aad0` | `CINSBotVision::CalculatePrimaryThreat()` |
| `0x0075a620` | `CINSBotVision::GetAssessmentScore()` |
| `0x0075a230` | `CINSBotVision::UpdateSilhouettes()` |
| `0x007591f0` | `CINSBotVision::CanReadSilhouette()` |
| `0x00758d70` | `CINSBotVision::IsLineOfSightClear()` |

### Body
| Address | Function |
|---|---|
| `0x00748300` | `CINSBotBody::Update()` |
| `0x00747fa0` | `CINSBotBody::UpdateArousal()` |
| `0x00747820` | `CINSBotBody::UpdatePosture()` |
| `0x007466a0` | `CINSBotBody::IncrementArousal()` |

### Locomotion
| Address | Function |
|---|---|
| `0x0074d8a0` | `CINSBotLocomotion::Update()` |
| `0x00750830` | `CINSBotLocomotion::Upkeep()` |
| `0x0074da20` | `CINSBotLocomotion::Approach()` |
| `0x0074faa0` | `CINSBotLocomotion::UpdateMovement()` |
| `0x00750dd0` | `CINSBotLocomotion::AddMovementRequest()` |

### Manager
| Address | Function |
|---|---|
| `0x00756690` | `CINSNextBotManager::Update()` |
| `0x00756ef0` | `CINSNextBotManager::Init()` |
| `0x00754090` | `CINSNextBotManager::IssueOrder()` |
| `0x00754950` | `CINSNextBotManager::CommandApproach()` |
| `0x00755df0` | `CINSNextBotManager::GenerateCPGrenadeTargets()` |

---

## 18. Complete ConVar Reference

### Aiming
```
bot_aim_aimtracking_base                    bot_aim_aimtracking_frac_easy
bot_aim_aimtracking_frac_hard               bot_aim_aimtracking_frac_impossible
bot_aim_aimtracking_frac_sprinting_target   bot_aim_angularvelocity_base
bot_aim_angularvelocity_base_ooc            bot_aim_angularvelocity_frac_easy
bot_aim_angularvelocity_frac_hard           bot_aim_angularvelocity_frac_impossible
bot_aim_angularvelocity_frac_sprinting_target  bot_aim_angularvelocity_uber
bot_aim_attack_aimtolerance_frac_easy       bot_aim_attack_aimtolerance_frac_hard
bot_aim_attack_aimtolerance_frac_impossible bot_aim_attack_aimtolerance_frac_normal
```

### Attack
```
bot_attack_aimpenalty_amt_close             bot_attack_aimpenalty_amt_far
bot_attack_aimpenalty_amt_frac_dark         bot_attack_aimpenalty_amt_frac_easy
bot_attack_aimpenalty_amt_frac_hard         bot_attack_aimpenalty_amt_frac_impossible
bot_attack_aimpenalty_amt_frac_light        bot_attack_aimpenalty_debug
bot_attack_aimpenalty_time_close            bot_attack_aimpenalty_time_far
bot_attack_aimpenalty_time_frac_dark        bot_attack_aimpenalty_time_frac_light
bot_attack_aimtolerance_frac_easy           bot_attack_aimtolerance_frac_hard
bot_attack_aimtolerance_frac_impossible     bot_attack_aimtolerance_frac_normal
bot_attack_aimtolerance_newthreat_amt       bot_attack_aimtolerance_newthreat_amt_solo
bot_attack_aimtolerance_newthreat_time      bot_attack_aimtolerance_newthreat_time_solo
bot_attack_burst_maxtime                    bot_attack_burst_maxtime_solo
bot_attack_burst_mintime                    bot_attack_burst_mintime_solo
bot_attack_retarget_maxtime                 bot_attack_retarget_mintime
bot_attackdelay_base                        bot_attackdelay_frac_desiredrange
bot_attackdelay_frac_difficulty_easy        bot_attackdelay_frac_difficulty_hard
bot_attackdelay_frac_difficulty_impossible  bot_attackdelay_frac_hipfirerange
bot_attackdelay_frac_maxrange              bot_attackdelay_frac_outofrange
bot_attackdelay_frac_outsidefov            bot_attackdelay_frac_survival_end
bot_attackdelay_frac_survival_start
```

### Targeting Noise
```
bot_targeting_noise_x_base                  bot_targeting_noise_x_base_solo
bot_targeting_noise_x_frac_desiredrange     bot_targeting_noise_x_frac_hipfirerange
bot_targeting_noise_x_frac_maxrange         bot_targeting_noise_y_base
bot_targeting_noise_y_base_solo             bot_targeting_noise_y_frac_desiredrange
bot_targeting_noise_y_frac_hipfirerange     bot_targeting_noise_y_frac_maxrange
bot_targeting_noise_z_base                  bot_targeting_noise_z_base_solo
bot_targeting_noise_z_frac_desiredrange     bot_targeting_noise_z_frac_hipfirerange
bot_targeting_noise_z_frac_maxrange
```

### Vision
```
bot_vis_foliage_threshold                   bot_vis_fov_attack_base
bot_vis_fov_frac_easy                       bot_vis_fov_frac_hard
bot_vis_fov_frac_impossible                 bot_vis_fov_idle_base
bot_vis_recognizetime_base                  bot_vis_recognizetime_frac_easy
bot_vis_recognizetime_frac_hard             bot_vis_recognizetime_frac_impossible
bot_silhouette_discover_timer               bot_silhouette_light_threshold_low
bot_silhouette_light_threshold_medium       bot_silhouette_range_close
bot_silhouette_range_far                    bot_silhouette_range_movement
bot_silhouette_readtime_clear               bot_silhouette_readtime_dark
bot_silhouette_readtime_fuzzy               bot_silhouette_scan_frequency
```

### Arousal
```
ins_bot_arousal_combat_falloff              ins_bot_arousal_combat_max
ins_bot_arousal_default_falloff             ins_bot_arousal_firing_falloff
ins_bot_arousal_firing_max                  ins_bot_arousal_suppression_falloff
ins_bot_arousal_suppression_max
ins_bot_arousal_frac_aimpenalty_max/med/min
ins_bot_arousal_frac_aimtolerance_max/med/min
ins_bot_arousal_frac_aimtracking_max/med/min
ins_bot_arousal_frac_angularvelocity_max/med/min
ins_bot_arousal_frac_attackdelay_max/med/min
ins_bot_arousal_frac_recognizetime_max/med/min
```

### Locomotion / Pathing
```
ins_bot_path_compute_throttle_combat        ins_bot_path_compute_throttle_ooc
ins_bot_path_distance_conquer               ins_bot_path_distance_hunt
ins_bot_path_distance_max                   ins_bot_path_distance_outpost
ins_bot_path_distance_patrol                ins_bot_path_distance_survival
ins_bot_pathfollower_aimahead               ins_bot_path_max_retreat_length
ins_bot_path_simplify_range                 ins_bot_path_update_interval
bot_loco_hurry_sprinthold_max               bot_loco_hurry_sprinthold_min
bot_loco_path_max_retreat_length            bot_loco_path_minlookahead
bot_loco_pronehold_max                      bot_loco_pronehold_min
bot_loco_slowdown_walkhold_max              bot_loco_slowdown_walkhold_min
```

### Hearing / Senses
```
ins_bot_enemy_seen_notify_distance          ins_bot_flashbang_effect_max_distance
ins_bot_flashbang_effect_max_time           ins_bot_friendly_death_hearing_distance
ins_bot_grenade_hearing_range               ins_bot_grenade_think_time
ins_bot_silenced_weapon_sound_reduction
bot_hearing_flashbang_effect_max_distance   bot_hearing_flashbang_effect_max_time
bot_hearing_grenade_hearing_range           bot_hearing_silenced_weapon_sound_reduction
```

### Combat Behavior
```
ins_bot_attack_pistol_fire_rate             ins_bot_attack_reload_ratio
ins_bot_attack_slide_cooldown               ins_bot_debug_combat_decisions
ins_bot_debug_combat_target                 ins_bot_retreat_to_cover_range
ins_bot_retreat_to_hidingspot_range         ins_bot_suppressing_fire_duration
ins_bot_suppress_visible_requirement        bot_behav_retreat_to_hidingspot_range
bot_recoil_multiplier                       bot_range_frac_desiredrange
bot_range_frac_hipfirerange                 bot_range_frac_maxrange
bot_investigate_sneak_lightvalue
```

### RPG
```
ins_bot_rpg_grace_time                      ins_bot_rpg_minimum_firing_distance
ins_bot_rpg_minimum_player_cluster          ins_bot_rpg_player_cluster_bloat
ins_bot_rpg_player_cluster_radius           bot_rpg_spawn_attackdelay
```

### Spawning / Counts
```
ins_bot_quota                               ins_bot_count_checkpoint
ins_bot_count_checkpoint_default/max/min    ins_bot_count_conquer
ins_bot_count_conquer_default/max/min/solo  ins_bot_count_hunt
ins_bot_count_hunt_default/max/min/solo     ins_bot_count_outpost
ins_bot_count_outpost_default/max/start_max/start_min/level_multiplier
ins_bot_count_survival
ins_bot_count_survival_default/max/start_max/start_min/day_start_max/day_start_min/level_multiplier
```

### Debug
```
ins_bot_debug_combat_decisions              ins_bot_debug_combat_target
ins_bot_debug_escort_formations             ins_bot_debug_movement_requests
ins_bot_debug_silhouette                    ins_bot_debug_visibility_blockers
nb_debug                                    nb_debug_filter
nb_debug_known_entities                     nb_update_debug
```

---

## 19. Reference Source Coverage Analysis

How much of the binary's bot system is covered by available source code in `references/`.

### Available as Source (~35-40%)

The **base NextBot framework** (`references/NextBot/`) is complete with full `.h` + `.cpp`:

| Component | Files | Lines | Coverage |
|---|---|---|---|
| `INextBot` | header + cpp | ~1,700 | Full implementation |
| `ILocomotion` / `NextBotGroundLocomotion` | header + cpp | ~4,000 | Full physics/movement |
| `IBody` / `PlayerBody` | header + cpp | Full | Posture, head aiming, animation |
| `IVision` | header + cpp | Full | LOS, known entity tracking, FOV |
| `IIntention` | header + cpp | Full | Behavior execution, event routing |
| `Action<>` / `Behavior<>` | header (template) | Full | State machine engine, transitions |
| `NextBotManager` | header + cpp | Full | Global lifecycle |
| `Path` / `PathFollower` / `ChasePath` / `RetreatPath` | header + cpp | Full | A* pathfinding |
| `NextBotPlayer<>` | header + cpp | Full | Player-bot integration, button sim |
| `CKnownEntity` | header + cpp | Full | Entity awareness/tracking |

This means the **framework contract** is fully readable: vtable layouts, method call order, state machine lifecycle (`SuspendFor`/`ChangeTo`/`Done`), event propagation, vision update loop, locomotion physics.

### NWI-Proprietary — Binary Only (~60-65%)

**Zero** source exists for any of these. All must be reverse-engineered from `server_srv.so`:

| System | Key Classes | RE Difficulty |
|---|---|---|
| **Arousal system** | `CINSBotBody` extensions, `IncrementArousal`, `CalculateArousalFrac`, `GetArousalFalloff` | Medium |
| **Silhouette recognition** | `GetSilhouetteType`, `CanReadSilhouette`, `UpdateSilhouettes` | High |
| **Movement request queue** | `AddMovementRequest`, `ApplyMovementRequest`, `INSBotMovementType`, `INSBotPriority` | Medium |
| **Cover evaluation** | `INSBotSearchForCover`, `INSBotSafeCoverTest`, `CINSBotCoverContainer`, `SortBotCoverSpots` | High |
| **Threat assessment** | `CINSThreatAssessment::Inspect()`, `GetAssessmentScore()` | Medium |
| **All 40+ action classes** | Every `CINSBotAttack*`, `CINSBotRetreat*`, monitors, gamemode actions | Very high |
| **BotMeme communication** | `BotMeme::Transmit`, `BotEnemySpottedMeme`, `BotFragOut` | Low |
| **Manager coordination** | `CINSNextBotManager` — grenades, reinforcements, objectives | Medium |
| **Escort/formation** | `INSBotEscortFormation::UpdatePositions()` | Low |

### Other References (Limited Value)

| Reference | Approach | Usefulness |
|---|---|---|
| `sourcebots/` | Schedule-based AI (not NextBot) | Conceptual only — different architecture |
| `CS-EBOT/` | Waypoint navigation (not nav mesh) | Legacy, minimal overlap |
| `CSGOBetterBots/` | SourceMod plugin wrapping stock CSGO bots via offsets | Plugin pattern reference only |
| `NavBot/` | SourceMod extension for nav mesh access | Nav mesh API reference only |

### Summary

The references provide the **complete chassis** (framework, physics, pathfinding, vision tracking) but none of the **decision-making intelligence**. Every `Update()` body inside NWI action classes, the arousal/silhouette systems, cover scoring, and threat assessment are binary-only.

For replacement purposes this is actually favorable: the framework APIs are well-documented, so new AI logic can use the same interfaces without reverse-engineering the plumbing.

---

## 20. Runtime Observation Strategy — Reverse Engineering Without Disassembly

The NextBot framework has built-in debug infrastructure and a single-choke-point architecture that makes it possible to reconstruct nearly the entire decision graph through runtime observation.

### 13.1 Built-in Debug ConVars (zero code required)

The `Action<>::ApplyResult()` method already logs **every state transition** with reason strings when debugging is enabled. From the reference source (`NextBotBehavior.h`):

```cpp
// Inside ApplyResult() — CHANGE_TO case:
me->DebugConColorMsg( NEXTBOT_BEHAVIOR, Color(255,255,255,255), this->GetName() );
me->DebugConColorMsg( NEXTBOT_BEHAVIOR, Color(255,  0,  0,255), " CHANGE_TO " );
me->DebugConColorMsg( NEXTBOT_BEHAVIOR, Color(255,255,255,255), newAction->GetName() );
me->DebugConColorMsg( NEXTBOT_BEHAVIOR, Color(150,255,150,255), "  (%s)\n", result.m_reason );
```

Enable with:
```
nb_debug 1                              // full behavior tree debug overlay
nb_debug_filter <botname>               // filter to one bot
nb_debug_history 1                      // show action transition history
nb_debug_known_entities 1               // show what bot sees
ins_bot_debug_combat_decisions 1        // NWI combat decision logging
ins_bot_debug_combat_target 1           // target selection logging
ins_bot_debug_movement_requests 1       // movement queue logging
ins_bot_debug_silhouette 1              // silhouette recognition logging
ins_bot_debug_escort_formations 1       // formation logging
ins_bot_debug_visibility_blockers 1     // visibility logging
```

This produces output like:
```
12.50: Bot_Joe:Behavior: CINSBotPatrol CHANGE_TO CINSBotCombat  (Enemy spotted)
12.50: Bot_Joe:Behavior: CINSBotCombat caused CINSBotAttackRifle to SUSPEND_FOR CINSBotReload  (Low ammo)
14.20: Bot_Joe:Behavior: CINSBotReload DONE, RESUME CINSBotAttackRifle  (Reload complete)
```

Every transition across all 40+ actions, with the reason string explaining why.

### 13.2 Single Choke Point: `ApplyResult()` at `0x00742370`

The `Action<CINSNextBot>::ApplyResult()` function is the **only place** where state transitions execute. From the reference source:

```cpp
// Behavior<Actor>::Update() — the entire dispatch is one line:
m_action = m_action->ApplyResult( me, this, m_action->InvokeUpdate( me, this, interval ) );
```

Every `ChangeTo()`, `SuspendFor()`, and `Done()` returned by any action's `Update()` or event handler flows through `ApplyResult()`. Hooking this single function captures:

| Parameter | What it tells you |
|---|---|
| `this` (+ `GetName()`) | Which action is currently running |
| `result.m_type` | Transition type: `CONTINUE` / `CHANGE_TO` / `SUSPEND_FOR` / `DONE` |
| `result.m_action` (+ `GetName()`) | The new action being transitioned to |
| `result.m_reason` | Human-readable reason string |
| `me` | Which bot is making the decision |

### 13.3 Recommended Hook Set for Complete Observability

**Minimum (1 hook — captures all transitions):**

| Function | Address | Data captured |
|---|---|---|
| `Action<CINSNextBot>::ApplyResult()` | `0x00742370` | All state transitions + reason strings |

**Full observability (6 hooks):**

| Function | Address | Data captured |
|---|---|---|
| `Action<CINSNextBot>::ApplyResult()` | `0x00742370` | All state transitions + reasons |
| `Action<CINSNextBot>::StorePendingEventResult()` | `0x0071e630` | Event-driven decisions before execution |
| `Behavior<CINSNextBot>::Update()` | `0x007430b0` | Per-tick active action |
| `Behavior<CINSNextBot>::ShouldAttack()` | `0x0073cce0` | Attack query results (bubbles through action stack) |
| `Behavior<CINSNextBot>::ShouldRetreat()` | `0x0073cc50` | Retreat query results |
| `Behavior<CINSNextBot>::ShouldHurry()` | `0x0073cbc0` | Movement urgency results |

**Additional contextual queries (all bubble through the action stack):**

| Function | Address |
|---|---|
| `Behavior<CINSNextBot>::ShouldPursue()` | `0x0073d230` |
| `Behavior<CINSNextBot>::ShouldWalk()` | `0x0073d080` |
| `Behavior<CINSNextBot>::ShouldIronsight()` | `0x0073d110` |
| `Behavior<CINSNextBot>::ShouldProne()` | `0x0073d1a0` |
| `Behavior<CINSNextBot>::SelectTargetPoint()` | `0x0073ce00` |
| `Behavior<CINSNextBot>::SelectMoreDangerousThreat()` | `0x0073cff0` |
| `Behavior<CINSNextBot>::IsPositionAllowed()` | `0x0073cf60` |

### 13.4 What Runtime Observation Gives You

By running bots through various scenarios with these hooks/ConVars, you can reconstruct:

- **Complete state machine graph** — which actions transition to which, under what conditions
- **Trigger conditions** — what events cause combat/retreat/investigate/reload
- **Priority ordering** — which actions can suspend which (the action stack)
- **Gamemode-specific behavior** — how objectives drive action selection
- **Contextual query answers** — what the action stack says about attacking, retreating, hurrying

**Example reconstructed trace:**
```
CINSBotMainAction > CINSBotTacticalMonitor > CINSBotGamemodeMonitor > CINSBotActionCheckpoint
  → CINSBotActionCheckpoint SUSPEND_FOR CINSBotApproach  (Moving to objective)
    → CINSBotApproach SUSPEND_FOR CINSBotCombat  (Enemy spotted at range 450)
      → CINSBotCombat CHANGE_TO CINSBotAttackRifle  (Rifle selected for range)
        → CINSBotAttackRifle SUSPEND_FOR CINSBotReload  (Magazine empty)
        → CINSBotReload DONE, RESUME CINSBotAttackRifle  (Reload complete)
      → CINSBotAttackRifle DONE, RESUME CINSBotCombat  (Target eliminated)
    → CINSBotCombat DONE, RESUME CINSBotApproach  (No threats)
  → CINSBotApproach DONE  (Reached objective)
  → CINSBotActionCheckpoint CHANGE_TO CINSBotCaptureCP  (On point)
```

### 13.5 What Still Requires Disassembly

Runtime observation captures the **what** and **why** (via reason strings) but not the **how** (internal numeric logic):

- Exact distance/range thresholds for weapon selection
- Threat scoring weights in `CINSThreatAssessment::GetAssessmentScore()`
- Arousal increment/decay formulas in `CINSBotBody::CalculateArousalFrac()`
- Cover position scoring algorithm in `CINSSearchForCover`
- Silhouette detection state machine internals
- Specific ConVar value interactions (how fracs combine)

For these, targeted disassembly of individual functions at their known addresses is needed. But the runtime traces dramatically narrow which functions matter and in what order.

### 13.6 `GetName()` Addresses for All Actions

Every action class has a `GetName()` that returns its string identifier:

| Address | Action |
|---|---|
| `0x007447a0` | `CINSBotMainAction` |
| `0x00732c70` | `CINSBotTacticalMonitor` |
| `0x0072e960` | `CINSBotGamemodeMonitor` |
| `0x0072fbe0` | `CINSBotInvestigationMonitor` |
| `0x00718820` | `CINSBotPatrol` |
| `0x007078c0` | `CINSBotCombat` |
| `0x006e75c0` | `CINSBotApproach` |
| `0x0071a870` | `CINSBotPursue` |
| `0x0071c920` | `CINSBotRetreat` |
| `0x0071f980` | `CINSBotRetreatToCover` |
| `0x00720d60` | `CINSBotRetreatToHidingSpot` |
| `0x0070c830` | `CINSBotEscort` |
| `0x00710430` | `CINSBotFollowCommand` |
| `0x007242b0` | `CINSBotSweepArea` |
| `0x00714890` | `CINSBotInvestigate` |
| `0x00715690` | `CINSBotInvestigateGunshot` |
| `0x006f5790` | `CINSBotAttack` |
| `0x007017f0` | `CINSBotAttackRifle` |
| `0x00702930` | `CINSBotAttackSniper` |
| `0x006fe360` | `CINSBotAttackLMG` |
| `0x00700530` | `CINSBotAttackPistol` |
| `0x006ff360` | `CINSBotAttackMelee` |
| `0x006f81a0` | `CINSBotAttackCQC` |
| `0x006f6ff0` | `CINSBotAttackAdvance` |
| `0x006fa500` | `CINSBotAttackFromCover` |
| `0x006fb9c0` | `CINSBotAttackInPlace` |
| `0x006fd090` | `CINSBotAttackIntoCover` |
| `0x0070fd30` | `CINSBotFireRPG` |
| `0x00723310` | `CINSBotSuppressTarget` |
| `0x00704210` | `CINSBotCaptureCP` |
| `0x00704f10` | `CINSBotCaptureFlag` |
| `0x007115f0` | `CINSBotGuardCP` |
| `0x00712f30` | `CINSBotGuardDefensive` |
| `0x00708f00` | `CINSBotDestroyCache` |
| `0x0071afb0` | `CINSBotReload` |
| `0x00726110` | `CINSBotThrowGrenade` |
| `0x00707db0` | `CINSBotDead` |
| `0x00710030` | `CINSBotFlashed` |
| `0x00722500` | `CINSBotStuck` |
| `0x007214a0` | `CINSBotSpecialAction` |
| `0x00726840` | `CINSBotActionAmbush` |
| `0x00727300` | `CINSBotActionCheckpoint` |
| `0x00727ae0` | `CINSBotActionConquer` |
| `0x00728230` | `CINSBotActionFirefight` |
| `0x00728af0` | `CINSBotActionFlashpoint` |
| `0x007293a0` | `CINSBotActionHunt` |
| `0x00729b60` | `CINSBotActionInfiltrate` |
| `0x0072a2a0` | `CINSBotActionOccupy` |
| `0x0072ad90` | `CINSBotActionOutpost` |
| `0x0072b3e0` | `CINSBotActionPush` |
| `0x0072bdf0` | `CINSBotActionSkirmish` |
| `0x0072c500` | `CINSBotActionStrike` |
| `0x0072cde0` | `CINSBotActionSurvival` |
| `0x0072de90` | `CINSBotActionTraining` |

---

## 21. String Cross-References — Decision Logic Revealed

Full data in `analysis/string_xrefs_per_class.md` (626 meaningful strings across 66 classes, extracted via PIC GOT-relative `lea` resolution).

### 21.1 Gamemode Action Decision Strings

Each gamemode `Update()` branches on reason strings that reveal the decision tree:

| Gamemode | Key Decision Branches |
|---|---|
| **Checkpoint** | "Defending.", "Guarding CP.", "Escorting nearest Human", "Counter-attacking contested point", "Counter-attacking enemy directly", "Knifing a player" |
| **Conquer** | "Attacking visible threat", "Approach Command", "Escorting", "I have something to investigate", "My Job is to Patrol" |
| **Hunt** | "Escorting", "I have something to investigate", "Moving to recently lost cache", "My Job is to Patrol" |
| **Occupy** | "Attacking enemy directly", "Attacking point", "Defending point", "Escorting" |
| **Outpost** | "Capturing our target", "Escorting", "Bot is out of pathing range to point" |
| **Survival** | "Escorting the nearest human", "Patrolling the world" |
| **Firefight** | "Attacking enemy controlled point", "Defending our CP", "Escorting" |
| **Strike** | "Attacking a cache", "Defending a cache" |
| **Flashpoint/Skirmish** | "Capturing %i", "Destroying %i" |

Common pattern: `"Attacking nearby threats"` appears in ALL gamemode actions as a universal combat interrupt.

### 21.2 Combat System Internals

**CINSBotCombat** (34 strings) reveals detailed combat state machine:
- Target lifecycle: "First Threat of Combat" → "Aiming at a new target" → "Stale Primary Target" → "Bailing on Combat, no target"
- Weapon management: "Pistol Swap with primary empty for close target who is firing.", "Reloading In Cover", "Reloading in place because of escort/formation"
- Retreat decisions: "Retreating to Cover BC Scared", "Retreating to Reload", "Retreating From Non-Player Target", "Should Not Attack This Threat"
- Pursuit: "Pursuing a Lost Enemy", "Suppressing a recently lost threat"

**CINSBotAttack** sub-actions:
- **AttackFromCover**: "Standing to pop out", "I've been crouching here for too long", "we have shitty cover"
- **AttackIntoCover**: "Sprinting to Cover", "Walking to Cover", "staying prone while attacking"
- **AttackCQC/Pistol**: "Sprinting At Target", "Walking At Target", "Crouching From Suppression", "Crawling From Suppression"
- **AttackRifle/Sniper/LMG**: "CProne from aiming threat", "Crouch for stability", "Prone From Suppression"
- **AttackAdvance**: "Continue aim at threat", "Lost aim on our threat!", "Within good enough range"

### 21.3 Tactical Monitor — Posture by Silhouette

`CINSBotTacticalMonitor::CheckPosture()` uses silhouette-based posture selection:
- "Crouching in response to Clear/Dark/Fuzzy Silhouette"
- "Going Prone in response to dark silhouette"
- "Prone in response to Clear/Dark/Fuzzy Silhouette"
- Also handles: "Firing an RPG!", "Throwing a grenade!", "Opportunistic reload in-place"

### 21.4 Key System Strings

**CINSBotVision**: `"Assessment: bot:%s, target:%s, score:%3.2f, dtm:%3.2f, dtd:%3.2f, looking:%3.2f"` — reveals threat scoring factors (distance-to-me, distance-to-danger, looking direction).

**CINSBotBody**: `"Arousal: %3.2f,%3.2f,%3.2f,%3.2f"` — 4 arousal components tracked. `"Stance Request: %s, type:%i, prio:%i, len:%3.2f"` — priority-based posture system.

**CINSBotLocomotion**: Full movement request lifecycle: Add → Apply → Completed/Failed → Removed.

**CINSNextBot**: Weapon class checks for explosives: `weapon_at4`, `weapon_rpg7`, `weapon_c4_clicker`, `weapon_c4_ied`, `weapon_m67`, `weapon_rgd5`. Player config simulated: `cl_crouch_hold`, `cl_sprint_hold`, `cl_ironsight_hold`, `cl_walk_hold`, `cl_grenade_auto_switch`.

**CINSNextBotManager**: Grenade coordination: `"Generating grenade targets for CP %i"`, FLASH/SMOKE types, `"Grenade Target\nClear: %s\nUsed: %s\nTypes: %s %s %s %s"`.

### 21.5 TODO Markers Found

- `CINSNextBot::UpdateLookingAroundForIncomingPlayers`: `"TODO: UpdateLookingAroundForIncomingPlayers"` — **unfinished feature**

---

## 22. Action State Transition Graph

Full data + DOT graph in `analysis/action_transition_graph.md` (150 unique transitions, 33 action object sizes).

### 22.1 Complete Action Hierarchy

```
CINSNextBot
 └─ CINSBotMainAction (64B)               ← root, handles Dead/Flashed
     ├─ CINSBotTacticalMonitor (152B)      ← monitors combat, posture, RPG/grenades
     │   ├─ CINSBotInvestigationMonitor (96B)
     │   │   └─ CINSBotGamemodeMonitor (56B)  ← selects per-gamemode action:
     │   │       ├─ Checkpoint (64B) → CaptureCP, Combat, Escort, GuardCP, GuardDefensive, Investigate
     │   │       ├─ Push (60B)       → CaptureCP, Combat, Escort, Investigate
     │   │       ├─ Hunt (100B)      → Approach, Combat, Escort, Investigate, Patrol
     │   │       ├─ Conquer (72B)    → Approach, Combat, Escort, Investigate, Patrol
     │   │       ├─ Survival (72B)   → CaptureCP, Combat, Escort, Investigate, Patrol
     │   │       ├─ Outpost (92B)    → CaptureCP, Combat, DestroyCache, Escort, Investigate
     │   │       ├─ Flashpoint (60B) → CaptureCP, Combat, DestroyCache, Investigate
     │   │       ├─ Skirmish (60B)   → CaptureCP, Combat, DestroyCache, Escort, Investigate
     │   │       ├─ Strike (56B)     → Combat, DestroyCache, GuardCP, Investigate
     │   │       ├─ Occupy (60B)     → CaptureCP, Combat, Escort, Investigate
     │   │       ├─ Firefight (60B)  → CaptureCP, Combat, Escort, Investigate
     │   │       ├─ Infiltrate (60B) → CaptureFlag, Combat, Investigate
     │   │       ├─ Ambush (64B)     → CaptureCP, Combat, Investigate
     │   │       └─ Training (60B)   → Combat
     │   └─ CINSBotPatrol → (default roaming)
     └─ [suspended actions pushed by events/decisions]
```

### 22.2 Combat Sub-System Transitions

```
CINSBotCombat (136B)
 ├─ → CINSBotAttack (80B)           ← weapon selection:
 │    ├─ InitialContainedAction → AttackRifle (80B)
 │    ├─ InitialContainedAction → AttackSniper (80B)
 │    ├─ InitialContainedAction → AttackLMG (80B)
 │    ├─ InitialContainedAction → AttackPistol (80B)
 │    ├─ InitialContainedAction → AttackCQC (80B)
 │    ├─ InitialContainedAction → AttackMelee
 │    ├─ InitialContainedAction → FireRPG (112B)
 │    └─ InitialContainedAction → ThrowGrenade (108B)
 ├─ → CINSBotRetreat                ← fear/low health
 ├─ → CINSBotRetreatToCover (100B)  ← scared + cover available
 ├─ → CINSBotPursue (92B)           ← lost enemy
 ├─ → CINSBotReload (92B)           ← ammo low
 └─ → CINSBotSuppressTarget (120B)  ← recently lost threat

Weapon attack sub-actions (InitialContainedAction):
  Rifle/LMG/Pistol/CQC → AttackAdvance | AttackInPlace | AttackIntoCover
  Sniper               → AttackInPlace | AttackIntoCover
  AttackIntoCover      → AttackFromCover (pop-out shooting)
  AttackInPlace       ↔ AttackAdvance (bidirectional)
  AttackFromCover      → AttackInPlace | Reload | ThrowGrenade
```

### 22.3 Key Observations

- **Sniper** is the only weapon type that never creates AttackAdvance (stationary play)
- **Retreat actions always end with Reload** — all 3 retreat types (Retreat, RetreatToCover, RetreatToHidingSpot) transition to Reload on success/failure/stuck/timer
- **CINSBotDead::Update() → CINSBotMainAction** — death resets the entire behavior tree
- **OnStuck() → CINSBotStuck** is universal across Approach, Attack, Patrol, CaptureCP, Combat, Investigate
- **CINSBotTacticalMonitor** is the entry point for RPG/Grenade/Reload decisions (not Combat)

---

## 23. Class Data Layouts — Constructor Analysis

Extracted member initializations from 49 bot class constructors by scanning x86 instruction patterns (movl/movb to object offsets, vtable installations, sub-object constructor calls).

Full output: `analysis/class_data_layouts.md`

### 23.1 Action<CINSNextBot> Base Class (56 bytes = 0x38)

All Action-derived classes share this layout, confirmed from constructor disassembly and source-sdk-2013 reference:

| Offset | Type | Member |
|--------|------|--------|
| +0x00 | vtable* | Primary vtable (Action<CINSNextBot>) |
| +0x04 | vtable* | Secondary vtable (IContextualQuery, = primary + 0x1A0) |
| +0x08 | Behavior* | m_behavior — owning Behavior tree |
| +0x0C | Action* | m_parent — containing Action |
| +0x10 | Action* | m_child — active child (stack top) |
| +0x14 | Action* | m_buriedUnderMe |
| +0x18 | Action* | m_coveringMe |
| +0x1C | CINSNextBot* | m_actor — the bot entity |
| +0x20 | int | m_eventResult.type |
| +0x24 | Action* | m_eventResult.m_action |
| +0x28 | const char* | m_eventResult.m_reason |
| +0x2C | int | m_eventResult.m_priority |
| +0x30 | bool | m_isStarted |
| +0x31 | bool | m_isSuspended |
| +0x34 | int | (padding/secondary event) |

### 23.2 Key Class Layouts (Derived Members Only)

**CINSBotCombat** (136 bytes, 13 derived members):
- +0x38: float — initial value -1 (sentinel, likely cached distance)
- +0x3C–0x48: 4× int/ptr (target tracking, weapon refs)
- +0x4C–0x4E: 3× bool (combat state flags)
- +0x50: int/ptr
- +0x54, +0x60, +0x6C, +0x78: 4× CountdownTimer[12] (fire timing, reload check, weapon switch, etc.)

**CINSBotEscort** (156 bytes, 18 derived members):
- +0x38: float sentinel (-1)
- +0x48: bool
- +0x50–0x94: 6× CountdownTimer[12] (movement timing, regroup, etc.)
- +0x98: bool

**CINSBotAttack** (80 bytes, 2 derived members):
- +0x38: CountdownTimer[12] (attack timing)
- +0x48: float sentinel (0xFFFFFFFF)

**CINSBotBody** (376 bytes, component, 36 members):
- +0x00: vtable (PlayerBody)
- +0xD0–0xFC: 3× CountdownTimer[12] + state tracking
- +0x100–0x118: posture/animation state (int=7 appears 3×, likely PostureType enum)
- +0x120–0x150: 3× CountdownTimer[12] (arousal timers)
- +0x154–0x168: 6× float=1.0 (speed multipliers per stance)
- +0x170: float=-1.0 (cached value)

**CINSBotVision** (640 bytes, component, 28 members):
- +0x00: vtable (IVision)
- +0x144–0x154: 5× int/ptr (vision tracking state)
- +0x158–0x190: 5× CountdownTimer[12] (scan intervals, recognition timers)
- +0x194: float sentinel (silhouette threshold?)
- +0x258: ptr (threat list?)
- +0x25C: CountdownTimer[12]
- +0x268–0x26C: 2× float sentinels

### 23.3 Common Patterns

- **CountdownTimer**: 12 bytes (vtable 0xB181B8 + m_timestamp=0 + m_duration=-1.0f). Found 51 instances across all classes.
- **IntervalTimer**: 8 bytes (vtable 0xB28688 + m_timestamp). Found 5 instances.
- **Sentinel values**: 0xFFFFFFFF used for "invalid" CHandle/float, -1.0f for "not set" durations.
- **int(7)** in CINSBotBody: appears 3× at different offsets, likely a default PostureType enum value.

### 23.4 Statistics

- 49 constructors analyzed across 42 classes (37 Action-derived, 5 components)
- 878 total member slots found
- 51 CountdownTimer + 5 IntervalTimer sub-objects identified
- 5 sub-object constructor calls (CINSPathFollower, CINSRetreatPath)

---

## 24. Strategy for Replacement

### 24.1 Approach A: Server Plugin (Recommended for full control)

Write a Source Engine server plugin (`IServerPluginCallbacks`) that:
1. Hooks `CINSNextBot::Update()` and key decision functions via vtable patching
2. Replaces the behavior tree by hooking `CINSBotMainAction::Update()` or `CINSNextBot::CINSNextBotIntention::Update()`
3. Uses the existing subsystems (vision, locomotion, body) which are well-designed
4. Only replaces the decision-making layer

**Key hook targets:**
- `CINSBotMainAction::Update()` @ `0x00743aa0` — replace root decision logic
- `CINSBotTacticalMonitor::Update()` @ `0x00731bc0` — replace tactical awareness
- `CINSBotCombat::Update()` @ `0x00706550` — replace combat behavior
- `CINSNextBot::FireWeaponAtEnemy()` @ `0x0074ae70` — replace aim/fire logic
- `CINSNextBot::ChooseBestWeapon()` @ `0x0075e540` — replace weapon selection

### 24.2 Approach B: Binary Patching

Directly patch `server_srv.so`:
1. Replace function bodies at known addresses
2. Redirect vtable entries to custom implementations
3. More fragile but doesn't require plugin infrastructure

### 24.3 Approach C: SourceMod/Metamod

Use Metamod:Source to load a module that:
1. Uses `SH_ADD_HOOK` to intercept virtual functions
2. Can call original functions when needed
3. Community-standard approach, easier to maintain

### 24.4 What to Keep vs Replace

**Keep (well-implemented):**
- `CINSBotVision` — solid visibility/threat detection
- `CINSBotLocomotion` — good movement system with stance control
- `CINSBotBody` — arousal system is clever
- `CINSNextBotManager` — grenade coordination, spawning
- Navigation mesh integration

**Replace (decision-making):**
- `CINSBotMainAction::Update()` — threat prioritization
- `CINSBotTacticalMonitor` — tactical decisions (when to fight vs retreat)
- `CINSBotCombat` — combat engagement strategy
- Gamemode-specific actions — objective strategy
- `CINSBotInvestigationMonitor` — sound/event response logic
