# Bot Objective & Gamemode System — Checkpoint, Capture, Escort & Counter-Attack

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The objective system spans four layers: (1) a **gamemode monitor** that detects
the active mode and instantiates the appropriate action; (2) **gamemode actions**
(Checkpoint, Hunt, Push, etc.) that implement per-mode decision loops; (3)
**objective actions** (CaptureCP, CaptureFlag, GuardCP, GuardDefensive) that
execute specific objective tasks; and (4) a **support layer** (Escort,
Investigate, Combat) that handles adjacent behaviors like escorting humans and
responding to threats near objectives.

Team numbering: **Team 2 = Security (attackers)**, **Team 3 = Insurgents (defenders)**.

---

## Gamemode Detection — CINSBotGamemodeMonitor

Name string: `"Gamemode"`
Size: 0x38 bytes (base Action only)

The monitor sits at **layer 3** in the behavior tree. Its `Update` always returns
CONTINUE — all logic is in `InitialContainedAction`, which queries `CINSRules`
to determine the active mode and allocates the matching action class.

### Gamemode Dispatch Table (0x0073E000)

The monitor checks modes in this exact order:

| Priority | CINSRules Check | Action Class | Size | Notes |
|----------|-----------------|-------------|------|-------|
| 1 | `IsCheckpoint()` | CINSBotActionCheckpoint | 0x40 | Primary co-op mode |
| 2 | `IsHunt()` | CINSBotActionHunt | 0x64 (100) | 3 CountdownTimers |
| 3 | `IsOutpost()` | CINSBotActionOutpost | 0x5C | 1 CountdownTimer |
| 4 | `IsOccupy()` | CINSBotActionOccupy | 0x3C | Minimal state |
| 5 | `IsPush()` | CINSBotActionPush | 0x3C | Shared with Invasion |
| 5 | `IsInvasion()` | CINSBotActionPush | 0x3C | Same action as Push |
| 6 | `IsFireFight()` | CINSBotActionFirefight | 0x3C | |
| 7 | `IsInfiltrate()` | CINSBotActionInfiltrate | 0x3C | |
| 8 | `IsStrike()` | CINSBotActionStrike | 0x38 | |
| 9 | `IsSkirmish()` | CINSBotActionSkirmish | 0x3C | |
| 10 | `IsAmbush()` | CINSBotActionAmbush | 0x40 | |
| 11 | `IsFlashpoint()` | CINSBotActionFlashpoint | 0x3C | |
| 12 | `IsTraining()` | CINSBotActionTraining | 0x48C4 | Embeds CINSPathFollower |
| 13 | `IsSurvival()` | CINSBotActionSurvival | 0x48 | 1 CountdownTimer |
| 14 | `IsConquer()` | CINSBotActionConquer | 0x48 | |
| — | (none matched) | returns NULL | — | No gamemode action |

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x0073DFC0 | OnStart | Returns CONTINUE |
| 0x0073E000 | InitialContainedAction | Gamemode dispatch (see table above) |
| 0x0073DFE0 | Update | Returns CONTINUE (passthrough) |
| 0x0073E960 | GetName | Returns "Gamemode" |

---

## CINSBotActionCheckpoint — Primary Co-op Mode

Name string: `"Checkpoint"`
Size: **0x40 bytes**

The main decision-maker for Checkpoint mode. Runs as layer 4 in the behavior
tree. Its `Update` is a priority-ordered decision cascade — the first matching
condition wins and suspends/changes the current action.

### Object Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard Action\<CINSNextBot\> fields |
| 0x38 | byte | m_savedState | Saved from bot+0x228F on start, restored on end |
| 0x3C | float | m_counterAttackStartTime | Timestamp when counter-attack was first detected; -1.0 = not active |

### OnStart (0x00736920)

```
1. m_savedState = bot[0x228F]   // save previous AI state
2. bot[0x228F] = 0              // clear state
3. m_counterAttackStartTime = -1.0f
4. return Continue
```

### Update Decision Cascade (0x00736A50)

The Update runs each check in strict priority order. The **first** match exits:

```
┌─ Priority 1: COMBAT ───────────────────────────────────────────┐
│  threat = GetPrimaryKnownThreat(includeHidden=false)           │
│  if threat exists AND ShouldAttack(threat) == 1:               │
│    → SuspendFor CINSBotCombat ("Attacking nearby threats")     │
└────────────────────────────────────────────────────────────────┘
         │ (no threat or shouldn't attack)
┌─ Priority 2: ESCORT HUMANS ───────────────────────────────────┐
│  if bot.GetTeamNumber() != CINSRules::GetBotTeam():           │
│    → SuspendFor CINSBotEscort ("Escorting nearest Human")     │
│  // Bots NOT on the bot team → they escort human players      │
└────────────────────────────────────────────────────────────────┘
         │ (bot is on bot team)
┌─ Priority 3: INVESTIGATION QUEUE ─────────────────────────────┐
│  if NOT currently investigating AND HasInvestigations():       │
│    area = GetCurrentInvestigationArea()                        │
│    → SuspendFor CINSBotInvestigate ("I have an investigation!")│
└────────────────────────────────────────────────────────────────┘
         │ (no investigations)
┌─ Priority 3b: KNIVES-ONLY MODE ──────────────────────────────┐
│  if ConVar(ins_bot_knives_only) != 0:                         │
│    Find closest enemy player with GetLastKnownArea()          │
│    AddInvestigation(enemy.area, priority=7)                   │
│    → SuspendFor CINSBotInvestigate ("Knifing a player")      │
└────────────────────────────────────────────────────────────────┘
         │
┌─ OBJECTIVE QUERY ─────────────────────────────────────────────┐
│  cpIndex = GetDesiredPushTypeObjective()                      │
│  objRes = g_pObjectiveResource                                │
│  activeCPIndex = objRes[0x770]                                │
│  objType = objRes[0x450 + activeCPIndex * 4]                  │
│  if objType == 2:                                             │
│    contestedCount = objRes[0x590 + activeCPIndex * 4]         │
│  elif objType == 3:                                           │
│    contestedCount = objRes[0x550 + activeCPIndex * 4]         │
│  else: contestedCount = 0                                     │
└────────────────────────────────────────────────────────────────┘
         │
┌─ Priority 4: COUNTER-ATTACK ──────────────────────────────────┐
│  if g_pGameRules[0x3AC] != 0:  // counter-attack active       │
│    GenerateCPGrenadeTargets(cpIndex)                          │
│                                                               │
│    // Probability ramp (delayed aggression):                  │
│    if m_counterAttackStartTime < 0:                           │
│      m_counterAttackStartTime = gpGlobals->curtime            │
│    elapsed = curtime - m_counterAttackStartTime               │
│    p = clamp((elapsed - 20.0) * 0.025, 0.0, 1.0)            │
│    // p=0 for first 20s, ramps to 1.0 over next 40s          │
│                                                               │
│    if RandomFloat(0, 1) < p:                                  │
│      cpPos = objRes[0x5D0 + cpIndex * 0xC]  (Vector)         │
│      closestEnemy = GetClosestPlayer(cpPos, team=2)           │
│      if closestEnemy has nav area:                            │
│        → SuspendFor CINSBotInvestigate                        │
│          ("Counter-attacking enemy directly")                 │
│      else:                                                    │
│        → SuspendFor CINSBotCaptureCP(cpIndex)                │
│          ("It's a counter-attack and we're not hunting,       │
│           re-cap")                                            │
│                                                               │
│  else:                                                        │
│    m_counterAttackStartTime = -1.0  // reset                  │
└────────────────────────────────────────────────────────────────┘
         │ (not counter-attacking, or probability didn't trigger)
┌─ Priority 5: CONTESTED POINT ─────────────────────────────────┐
│  if contestedCount > 0 AND cpIndex < 16:                      │
│    playerArray = g_pGameRules[0x830 + cpIndex * 0x14]         │
│    if playerArray.count > 0:                                  │
│      randomPlayer = playerArray[RandomInt(0, count-1)]        │
│      AddInvestigation(randomPlayer.area, priority=0)          │
│      → SuspendFor CINSBotInvestigate                          │
│        ("Counter-attacking contested point")                  │
└────────────────────────────────────────────────────────────────┘
         │ (point not contested)
┌─ Priority 6: GUARD DEFENSIVE ─────────────────────────────────┐
│  if bot[0x8A5] & 0x04:  // defensive guard flag              │
│    → SuspendFor CINSBotGuardDefensive ("Defending.")          │
└────────────────────────────────────────────────────────────────┘
         │ (not flagged for defensive guard)
┌─ Priority 7: GUARD CP (probabilistic) ────────────────────────┐
│  r = TransientlyConsistentRandomValue(4.0s seed)              │
│  if r < 0.5:  // 50% chance                                  │
│    duration = RandomFloat(5.0, 15.0)                          │
│    → SuspendFor CINSBotGuardCP(cpIndex)                       │
│      ("Guarding CP.")                                         │
└────────────────────────────────────────────────────────────────┘
         │ (didn't guard)
         └─ return Continue  (idle, will re-evaluate next tick)
```

### Counter-Attack Probability Ramp

The counter-attack aggression is not instant. When defenders detect a counter-
attack state (`g_pGameRules[0x3AC] != 0`), a timer starts. For the first
**20 seconds**, probability is 0 (bots stay passive). Then it ramps linearly:

```
p = clamp((curtime - startTime - 20.0) * 0.025, 0.0, 1.0)

t=0s   → p=0.0   (wait)
t=20s  → p=0.0   (still waiting)
t=30s  → p=0.25  (25% chance per tick)
t=40s  → p=0.5   (50% chance)
t=60s  → p=1.0   (guaranteed push)
```

Each tick, the bot rolls `RandomFloat(0,1)` against `p`. On success, it either
investigates the closest enemy near the CP or pushes to recapture via
CINSBotCaptureCP.

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 or 2 | 1 if path distance to goal ≤ 1400 units; 2 otherwise |
| ShouldAttack | 1 | Always attack (ANSWER_YES) |
| GetName | "Checkpoint" | |

### OnEnd (0x00736970)

Restores `bot[0x228F]` from saved `m_savedState`.

---

## CINSBotCaptureCP — Control Point Capture

Name string: `"Capturing CP"`
Size: **0x88 bytes**

Moves the bot to a hiding spot near a control point and holds position until
the point is captured. Can transition to destroying weapon caches.

### Object Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x38 | int | m_currentGoalNavArea | Nav area ID of current movement goal |
| 0x3C | CountdownTimer | timer_0 | Hiding spot recalc (2.0s) |
| 0x48 | CountdownTimer | timer_1 | Assessment interval (0.25s) |
| 0x54 | int | m_cpIndex | Control point index to capture |
| 0x58 | Vector | m_hidingSpotPos | Target hiding spot at CP |
| 0x64 | byte | m_isCounterAttack | If true, suppresses combat response |
| 0x6C | byte | m_canSeeHidingSpot | Vision check result |
| 0x70 | IntervalTimer | m_arrivalTimer | Stamps time when bot arrives at CP |
| 0x78 | CountdownTimer | timer_2 | Lookaround interval at CP (1.0-5.0s random) |

### Constructor (0x00713010)

```
CINSBotCaptureCP(int cpIndex, bool isCounterAttack)
  m_cpIndex = cpIndex
  m_isCounterAttack = isCounterAttack
```

### OnStart (0x00712E80)

```
1. hidingSpot = CINSNavMesh::GetControlPointHidingSpot(m_cpIndex)
2. m_hidingSpotPos = hidingSpot
3. if hidingSpot is near origin (invalid):
     → Done("Unable to find hiding spots at this control point")
4. locomotion.AddMovementRequest(m_hidingSpotPos, priority=6, mode=3, speed=5.0)
5. return Continue
```

### Update State Machine (0x007131A0)

The update has two major phases depending on whether the bot has arrived at the CP.

**Phase 1 — Moving to CP** (timer_1 assessment loop, 0.25s):

```
1. Every 0.25s:
   a. If no path OR (idle > 3.0s AND still > 2.0s from last move):
      Recalculate hiding spot → AddMovementRequest
   b. Check for threats:
      if !m_isCounterAttack AND threat AND ShouldAttack == 1:
        → Done("Attacking nearby threats")
   c. Validate team:
      if bot not on team 2 or 3 → Done("Bot is not on a playteam")
   d. Check ownership:
      owner = objRes[0x490 + m_cpIndex * 4]
      if owner == bot.team → Done("Successfully captured.")
   e. Check contested:
      if CP contested or enemy on point:
        randomArea = GetRandomControlPointArea()
        → ChangeTo CINSBotInvestigate("CP Contested, trying to find threat")
   f. Check cache type:
      cpStatus = objRes[0x6F0 + m_cpIndex * 4]
      if distance < 200 AND can see spot AND (status == 0 or 8):
        → ChangeTo CINSBotDestroyCache("Point type is a Cache, blow it up!")
```

**Phase 2 — On the CP** (arrival timer running):

```
1. Check objective type for contested count
   if contested > 0:
     bot[0x2290] = 1  // mark as on point
     SetPosture(CROUCH)  "Crouching at CP"
2. Periodically (1.0-5.0s random interval):
   Collect visible nav areas from current + adjacent areas
   Pick random visible area → AimHeadTowards(randomPoint, blend=0.1)
   "Capture Aiming"
3. Probabilistic ironsight:
   if TransientlyConsistentRandomValue(8.0s) < 0.2:
     PressIronsightButton()
```

### ShouldHurry

```
if IsCheckpoint() AND !m_isCounterAttack:
  return 1  (always hurry in standard checkpoint)
if IsOutpost():
  return 2  (don't hurry in outpost)
else:
  if path distance to goal <= threshold:
    return 1
  return 2
```

### Event Handlers

| Event | Response |
|-------|----------|
| OnMoveToSuccess | If distance < 100: stamp arrival timer, set bot[0x2290]=1. Continue |
| OnStuck | → ChangeTo CINSBotStuck ("I'm Stuck") |
| OnEnd | If bot alive: clear bot[0x2290]=0 |
| OnResume | Re-issue AddMovementRequest to hiding spot |

---

## CINSBotCaptureFlag — Flag Objective Capture

Name string: `"Capturing Flag"`
Size: **0x4900 bytes** (embeds CINSPathFollower)

Handles flag-based objective capture. The bot paths toward the flag/objective,
and when close enough, aligns its aim to use/interact with the object.

### Object Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x38 | int | m_flagTeamIndex | Which team's flag (0 or 1) |
| 0x3C–0x4817 | CINSPathFollower | m_pathFollower | Nav mesh path following |
| 0x48AC | CountdownTimer | timer_0 | Path recalc interval (5.0-7.5s random) |
| 0x48B8 | Vector | m_targetPosition | Current desired position |
| 0x48C4 | byte | m_isCarryingFlag | True if this bot has the flag |
| 0x48C5 | byte | m_isNearFlag | True if close enough to interact |
| 0x48C8 | IntervalTimer | m_arrivalTimer | Stamps arrival time |
| 0x48D0-0x48F4 | CountdownTimer[4] | Various timers | Path, aim, use, etc. |

### Constructor (0x007145C0)

```
CINSBotCaptureFlag(CINSPlayer* owner, int flagTeamIndex)
  m_flagTeamIndex = flagTeamIndex
  m_pCapturer[flagTeamIndex] = owner.EHANDLE  // static array tracks who is capturing
  m_isCarryingFlag = false
  m_pathFollower.Invalidate()
```

### GetDesiredPosition (0x00714880)

Determines where the bot should move based on flag carrier state:

```
if m_isCarryingFlag:
  // Carrying flag → go to extraction point
  cpPos = objRes[0x5D0 + (m_flagTeamIndex==0 ? 1 : 0) * 0xC]  (Vector)
  return cpPos

else:
  // Not carrying → go to the flag object
  flagHandle = objRes[0x7CC + m_flagTeamIndex * 4]
  if flagHandle valid:
    entity = EntityFromHandle(flagHandle)
    assocObj = CPoint_ControlPoint::GetAssociatedObject()
    return assocObj.WorldSpaceCenter()
  return vec3_origin
```

### Update (0x00714960)

```
1. Validate bot on a play team (2 or 3)
2. Check if another bot grabbed the flag:
   currentCarrier = GetFlagCarrier(team)
   if carrier exists AND carrier != this bot:
     → Done("Flag carrier that wasn't us? Bailing.")
3. Update m_isCarryingFlag state
4. Recalculate target position via GetDesiredPosition()
5. Every 5.0-7.5s: if team in combat, recompute path
6. If carrying flag:
   PathFollower.Update() — follow path to extraction
7. If near flag AND not carrying:
   AimHeadTowards(flag, priority=5, blend=1.0, "Look at object to use")
   Compute dot product of eye-forward vs direction-to-flag
   if dot > 0.7 AND useTimer elapsed:
     PressUseButton(0.5s)  // interact with flag
     useTimer.Start(1.0s)
8. If not near flag:
   PathFollower.Update() — path toward flag
```

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 if not near flag, 2 if near | Slow down when approaching |
| GetName | "Capturing Flag" | |

### OnEnd (0x00714510)

Clears `m_pCapturer[flagTeamIndex]` static array (sets to -1/invalid).

---

## CINSBotEscort — Human Player Escort

Name string: `"Escort"`
Size: **0x9C bytes**

Bots that are **not on the bot team** (i.e., human-team bots in co-op) enter
Escort mode to follow and protect human players. Uses a formation system with
positions computed relative to the escort target.

### Object Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00–0x37 | | Action base | Standard fields |
| 0x38 | int | m_escortTargetIndex | Player index of escort target (-1 = none) |
| 0x3C | Vector | m_formationPos | Computed formation position |
| 0x48 | byte | m_canSeeTarget | Vision check to escort target |
| 0x4C | float | m_distToTarget | Distance to escort target |
| 0x50 | CountdownTimer | timer_0 | Assessment/update interval (0.15s) |
| 0x5C | CountdownTimer | timer_1 | Assessment timer |
| 0x68 | CountdownTimer | timer_2 | Lookaround interval (1.0s) |
| 0x74 | CountdownTimer | timer_3 | Lookaround timer |
| ... | | Various formation fields | |

### Escort Target Selection

Called in `OnStart` and `OnResume` via `SetEscortTarget()`. Finds the nearest
alive human player on the same team and stores their player index.

### Update (0x0071C350)

```
1. Check for threats:
   threat = GetPrimaryKnownThreat()
   if threat is a player AND IsAlive() AND ShouldAttack == 1:
     → SuspendFor CINSBotCombat ("Combat time!")

2. Every 0.15s (main assessment):
   a. Validate escort target exists and is alive
      if target dead → set index=-1, try SetEscortTarget() next tick
      if no target found → Done("Unable to get escort Target")
   b. Check if can see target (LOS test to EyePosition)
   c. Compute distance (travel distance or line-of-sight)
   d. UpdateEscortFormations()  — compute formation positions
   e. UpdateEscortPostures()    — set posture based on target movement
   f. Every 1.0s: UpdateEscortLookaround() — look around for threats

3. Get formation and update movement:
   formation = GetEscortFormation()
   UpdateFormationMovement(formation)

4. If path compute failures > 9:
   → Done("Path compute failed. Let's go back to Game Mode")

5. return Continue
```

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldHurry | 1 | If escort target is sprinting: match speed |
| ShouldHurry | 1 or 2 | If can't see target: 1 (hurry). If in formation: 2 (don't) |
| ShouldRetreat | 1 or 2 | If suppressed AND distance to formation > 256: return 1 (retreat); else 2 (no) |
| ShouldAttack | 1 | Always attack |
| GetName | "Escort" | |

### Event Handlers

| Event | Response |
|-------|----------|
| OnEnd | If bot alive: clear escort slot `[0xB32C]=-1`, clear `[0x2290]=0` |
| OnSuspend | Continue (formation maintained during suspension) |
| OnResume | Re-acquire escort target via SetEscortTarget(), set `[0x2290]=1` |

---

## g_pObjectiveResource — Objective State

The `CObjectiveResource` entity (pointed to by `g_pObjectiveResource`) stores
all objective state. Key offsets used by bot AI:

| Offset | Type | Field | Used By |
|--------|------|-------|---------|
| 0x450 + cp*4 | int | m_iCPTypes[cp] | Objective type: 2=capture zone, 3=destroy cache |
| 0x490 + cp*4 | int | m_iOwner[cp] | Team ID that owns this CP |
| 0x550 + cp*4 | int | m_iNumTeam3[cp] | Team 3 player count on/near point |
| 0x590 + cp*4 | int | m_iNumTeam2[cp] | Team 2 player count on/near point |
| 0x5D0 + cp*0xC | Vector | m_vCPPositions[cp] | Control point world position (x,y,z) |
| 0x6F0 + cp*4 | int | m_iCPStatus[cp] | CP status (0=active, 1=destroyed, 8=cache) |
| 0x770 | int | m_iActivePushCP | Currently active push objective index |
| 0x7CC + idx*4 | EHANDLE | m_hFlags[idx] | Entity handle for flag objects |

### g_pGameRules Objective Fields

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x3AC | byte | m_bIsCounterAttack | Non-zero during counter-attack phase |
| 0x3E0 | int | m_iLastCapturedCP | Index of most recently captured CP |
| 0x830 + cp*0x14 | CUtlVector | m_playersOnPoint[cp] | Players currently touching each CP's trigger |

---

## Objective Selection — CINSNextBotManager Functions

Six specialized functions select the target objective based on gamemode.
(Full documentation in `squad_team_coordination.md`)

| Address | Function | Used By | Logic Summary |
|---------|----------|---------|---------------|
| 0x00762450 | GetDesiredPushTypeObjective | Checkpoint, Push, Invasion, Conquer | Reads `objRes[0x770]` — the engine-tracked active push CP |
| 0x00761E40 | GetDesiredSkirmishObjective | Skirmish | Frontline analysis: counts friendly/enemy CPs, targets enemy-owned CP ahead |
| 0x007621A0 | GetDesiredBattleTypeObjective | Battle | 1 enemy CP → target it; contested + owned → target contested |
| 0x00762710 | GetDesiredHuntTypeObjective | Hunt | First CP where status ≠ 1 (not destroyed) |
| 0x007624F0 | GetDesiredOccupyTypeObjective | Occupy | Closest unowned CP, with random tiebreaker |
| 0x00765790 | GetDesiredStrongholdTypeObjective | Stronghold | Attackers: closest attackable CP. Defenders: build defend list |

---

## ConVar Reference

### Counter-Attack ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `mp_checkpoint_counterattack_disable` | 0 | Disable counter-attack phase (1=disabled) |
| `mp_checkpoint_counterattack_duration` | 65 | Counter-attack duration in seconds |
| `mp_checkpoint_counterattack_duration_finale` | 120 | Finale round counter-attack duration |

### Objective Bot ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `ins_bot_knives_only` | 0 | Forces bots to knife-hunt nearest enemy |
| `ins_bot_path_update_interval` | — | How often bots recalculate paths |

---

## Hardcoded Constants

| Constant | Value | Where Used |
|----------|-------|------------|
| Counter-attack delay | 20.0s | Time before counter-attack probability starts ramping |
| Counter-attack ramp rate | 0.025/s | Probability gain per second after delay |
| ShouldHurry distance | 1400.0 units | Checkpoint: hurry if path distance ≤ this |
| CP arrival distance | 100.0 units | CaptureCP: consider "arrived" at this range |
| Assessment interval | 0.25s | CaptureCP and Checkpoint update intervals |
| Hiding spot recalc | 2.0s | CaptureCP: time between hiding spot searches |
| Guard probability | 50% (0.5) | ActionCheckpoint: probability of GuardCP vs idle |
| Guard duration | 5.0–15.0s | Random guard duration range |
| Escort assessment | 0.15s | CINSBotEscort: main update rate |
| Escort lookaround | 1.0s | CINSBotEscort: look-around interval |
| Escort retreat range | 256.0 units | Distance from formation before retreating |
| Flag use dot threshold | 0.7 | Must face flag this accurately to interact |
| Flag use cooldown | 1.0s | Time between PressUseButton calls |
| Flag path recalc | 5.0–7.5s | Random path recompute interval |
| Flag near distance | 70.0 units | Distance to consider "near" the flag |
| Capture aiming blend | 0.1 | AimHeadTowards blend for looking around on CP |
| Ironsight probability | 20% (0.2) | Probabilistic ironsight while on CP |
| Path compute fail limit | 9 | Escort: bail after this many failures |
| Crouching at CP | Always | Bots crouch when on contested point |

---

## Function Address Table

### Gamemode Monitor

| Address | Function | Notes |
|---------|----------|-------|
| 0x0073DFC0 | GamemodeMonitor::OnStart | Returns Continue |
| 0x0073E000 | GamemodeMonitor::InitialContainedAction | Gamemode dispatch |
| 0x0073DFE0 | GamemodeMonitor::Update | Returns Continue |
| 0x0073E960 | GamemodeMonitor::GetName | "Gamemode" |

### ActionCheckpoint

| Address | Function | Notes |
|---------|----------|-------|
| 0x00736920 | ActionCheckpoint::OnStart | Save state, init timer |
| 0x00736A50 | ActionCheckpoint::Update | Priority decision cascade |
| 0x00736970 | ActionCheckpoint::OnEnd | Restore state |
| 0x007369C0 | ActionCheckpoint::ShouldHurry | Distance-based 1 or 2 |
| 0x007369A0 | ActionCheckpoint::ShouldAttack | Always 1 |
| 0x00737300 | ActionCheckpoint::GetName | "Checkpoint" |

### CaptureCP

| Address | Function | Notes |
|---------|----------|-------|
| 0x00713010 | CaptureCP::Constructor | (cpIndex, isCounterAttack) |
| 0x00712E80 | CaptureCP::OnStart | Find hiding spot, move |
| 0x007131A0 | CaptureCP::Update | Move/cap/cache state machine |
| 0x00712A10 | CaptureCP::OnEnd | Clear bot[0x2290] |
| 0x00712C60 | CaptureCP::OnResume | Re-issue movement request |
| 0x00712B80 | CaptureCP::OnMoveToSuccess | Stamp arrival, mark on point |
| 0x00712A40 | CaptureCP::OnStuck | ChangeTo CINSBotStuck |
| 0x00712D00 | CaptureCP::ShouldHurry | Mode-dependent |
| 0x00714210 | CaptureCP::GetName | "Capturing CP" |

### CaptureFlag

| Address | Function | Notes |
|---------|----------|-------|
| 0x007145C0 | CaptureFlag::Constructor | (owner, flagTeamIndex) |
| 0x007143C0 | CaptureFlag::OnStart | Compute path to flag |
| 0x00714960 | CaptureFlag::Update | Path/carry/use state machine |
| 0x00714510 | CaptureFlag::OnEnd | Clear capturer static |
| 0x00714880 | CaptureFlag::GetDesiredPosition | Flag or extraction point |
| 0x00714320 | CaptureFlag::OnMoveToSuccess | Stamp arrival timer |
| 0x00714300 | CaptureFlag::ShouldHurry | 1 if far, 2 if near |
| 0x00714F10 | CaptureFlag::GetName | "Capturing Flag" |

### Escort

| Address | Function | Notes |
|---------|----------|-------|
| 0x0071A3E0 | Escort::Constructor | Init 6 CountdownTimers |
| 0x0071C7F0 | Escort::OnStart | SetEscortTarget, set state |
| 0x0071C350 | Escort::Update | Combat/formation/movement loop |
| 0x00719050 | Escort::OnEnd | Clear escort slot |
| 0x0071C7B0 | Escort::OnResume | Re-acquire target |
| 0x0071B790 | Escort::SetEscortTarget | Find nearest human |
| 0x0071A700 | Escort::HasEscortTarget | Validate target exists |
| 0x0071C830 | Escort::GetName | "Escort" |
| 0x007192B0 | Escort::ShouldHurry | Sprint/formation-based |
| 0x007196D0 | Escort::ShouldRetreat | Suppressed + far from formation |
