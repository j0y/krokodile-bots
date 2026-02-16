# Bot Behavior / Action System

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The bot AI is built on a Source Engine `Behavior<CINSNextBot>` template that
manages a stack of `Action<CINSNextBot>` objects. Each action returns a result
every tick (CONTINUE, CHANGE_TO, SUSPEND_FOR, DONE) that drives transitions.
Nested `InitialContainedAction` calls form a layered hierarchy from top-level
state management down to individual combat/navigation actions.

---

## Action Base Class — `Action<CINSNextBot>`

Size: **56 bytes (0x38)**

```
+0x00  void*       vtable (Action<CINSNextBot> primary)
+0x04  void*       vtable (IContextualQuery secondary, at vtable+0x19C)
+0x08  Behavior*   m_behavior           (owning Behavior object)
+0x0C  Action*     m_parent             (parent action in hierarchy)
+0x10  Action*     m_child              (active contained action)
+0x14  Action*     m_buriedUnderMe      (action suspended below this one)
+0x18  Action*     m_coveringMe         (action currently suspending this one)
+0x1C  CINSNextBot* m_actor             (owning bot entity)
+0x20  EventResultPriorityType  m_eventResult  (16 bytes, see below)
+0x30  bool        m_isStarted
+0x31  bool        m_isSuspended
+0x34  (4 bytes)   padding / debug name
```

### ActionResult (12 bytes) — returned by Update/OnStart/event handlers

```
+0x00  int         type     (0=CONTINUE, 1=CHANGE_TO, 2=SUSPEND_FOR, 3=DONE)
+0x04  Action*     action   (new action for CHANGE_TO / SUSPEND_FOR, else NULL)
+0x08  const char* reason   (debug string, or NULL)
```

**x86-32 sret ABI:** All Action methods that "return" an ActionResult actually
receive a hidden first parameter (the sret pointer) where the 12-byte struct
is written. In Ghidra decompilation this appears as `param_1` being the return
buffer and the actual `this` as `in_stack_0000000c`.

### EventResultPriorityType (16 bytes)

Same as ActionResult plus a priority field at `+0x0C` (int). Used by event
handlers (`OnInjured`, `OnSight`, etc.) so the framework can compare priorities
when multiple events fire in the same tick.

---

## Behavior Tree Hierarchy

When a bot spawns, the framework calls `InitialContainedAction` down the chain:

```
Behavior<CINSNextBot>
  └─ CINSBotMainAction              (layer 0 — death, flash, idle suicide)
       └─ CINSBotTacticalMonitor    (layer 1 — posture, grenades, RPG, reload)
            └─ CINSBotInvestigationMonitor  (layer 2 — event→investigation queue)
                 └─ CINSBotGamemodeMonitor  (layer 3 — gamemode dispatch)
                      └─ <gamemode action>  (layer 4 — e.g. CINSBotActionCheckpoint)
```

Each layer's `Update` runs every tick. A `SUSPEND_FOR` from any layer pushes
a new action onto the stack (e.g. CINSBotCombat, CINSBotInvestigate) that
takes over until it returns `DONE`, at which point the suspended action's
`OnResume` is called.

---

## CINSBotMainAction — Layer 0

Name string: `"Behavior"`

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x00753730 | OnStart | Returns CONTINUE |
| 0x00753800 | InitialContainedAction | Allocates CINSBotTacticalMonitor (0x98 bytes) |
| 0x00753AA0 | Update | Death/flash/idle checks |
| 0x007547A0 | GetName | Returns "Behavior" |
| 0x00754200 | IsImmediateThreat | Detonator radius or firing-at-me |
| 0x007543B0 | SelectCloserThreat | Distance with weapon FOV modifiers |
| 0x00754640 | SelectMoreDangerousThreatInternal | Armed → immediate → closer |
| 0x00754760 | SelectMoreDangerousThreat | Wrapper, null-checks then delegates |
| 0x007537B0 | SelectTargetPoint | Delegates to CINSNextBot::GetTargetPosition |
| 0x00753790 | ShouldPursue | Always returns 1 (true) |
| 0x007540E0 | OnInjured | Adds attacker to known entities via IVision::AddKnownEntity (+0xE8) |
| 0x00754050 | OnContact | Opens "prop_door*" entities via PressUseButton (vtable 0x8D8, 0.1f) |
| 0x00753E10 | OnStuck | Logs detailed stuck info, returns CONTINUE |

### Update Decision Flow (0x00753AA0)

1. **Death check** — `IsAlive()` (vtable +0x118)
   - If dead → **CHANGE_TO** `CINSBotDead`
2. **Flash check** — entity offset `+0x608` (flash end time)
   - If `gpGlobals->curtime < flash_end_time` → **SUSPEND_FOR** `CINSBotFlashed`
3. **Idle suicide** — if idle duration exceeds ConVar threshold and bot stuck
   - Calls `CINSPlayer::CommitSuicide()`, sets flag at entity +0x4A5
4. Otherwise → **CONTINUE**

### Threat Evaluation

**IsImmediateThreat** (0x00754200):
- Requires: entity visible (vtable +0xF0) AND not same team AND entity alive AND armed
- For `CBaseDetonator` (dynamic_cast check): immediate if distance < `GetDetonateDamageRadius() × 1.5`
- For players: calls `CINSPlayer::IsThreatFiringAtMe()`

**SelectCloserThreat** (0x007543B0):
- Gets raw distance to each threat via entity distance function (vtable +0x130)
- **Weapon FOV modifier** — if threat entity has flashlight on (vtable +0x620):
  - If weapon scope FOV ≥ 20.0 AND player flag bit 0 set (scoped): distance × 0.75
  - If weapon scope FOV < 20.0 (unscoped): distance × 0.25
- Returns threat with smaller adjusted distance

**SelectMoreDangerousThreatInternal** (0x00754640):
1. Compare armed status (vtable +0x158) — prefer armed threat
2. Compare IsImmediateThreat — prefer immediate threat
3. Fall back to SelectCloserThreat

---

## CINSBotTacticalMonitor — Layer 1

Name string: `"Tactics"`
Object size: **0x98 bytes (152)**

### Object Layout (derived fields, after 0x38 base)

```
+0x38  CountdownTimer   (next-bot update timing)
+0x74  CountdownTimer   (10.0s trigger)
+0x88  CountdownTimer   (weapon switch, 0.5s interval)
+0x94  int              silhouette type cache (-1 = unknown, 0/1/2)
```

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x0073FE70 | OnStart | Initializes timers, returns CONTINUE |
| 0x0073FD40 | InitialContainedAction | Allocates CINSBotInvestigationMonitor (0x60 bytes) |
| 0x00741BC0 | Update | Tactical decision loop |
| 0x007416A0 | CheckPosture | Silhouette-based posture selection |
| 0x00740A40 | OnSight | Grenade detection / retreat |
| 0x00740BF0 | OnInjured | Retreat on heavy damage |
| 0x00740730 | OnWeaponFired | Look at weapon fire source |
| 0x007402A0 | OnHeardFootsteps | Investigation type 6 or look-at |
| 0x00740060 | OnSeeSomethingSuspicious | Investigation type 5 |
| 0x0073FFC0 | ShouldAttack | True if distance ≤ GetMaxAttackRange |
| 0x0073FCD0 | ShouldWalk | Always returns 2 |
| 0x00742C70 | GetName | Returns "Tactics" |

### Update Decision Flow (0x00741BC0)

Priorities checked in order each tick:

1. **RPG fire** — visible threat at distance > 1200 units AND `CINSBotFireRPG::HasRPGTarget()`:
   - **SUSPEND_FOR** `CINSBotFireRPG` (0x70 bytes) — "Firing an RPG!"
2. **Grenade throw** — no visible threat AND `CINSBotThrowGrenade::CanIThrowGrenade()`:
   - **SUSPEND_FOR** `CINSBotThrowGrenade` (0x6C bytes) — "Throwing a grenade!"
3. **Reload** — not in combat AND `ShouldReload()` or `ShouldOpportunisticReload()`:
   - **SUSPEND_FOR** `CINSBotReload` (0x5C bytes) — "Opportunistic reload in-place"
4. **Weapon switch** — every 0.5s, calls `CINSNextBot::ChooseBestWeapon()`
5. **Posture update** — if silhouette type changed or timer expired:
   - Calls `CheckPosture()` (see below)
6. **CONTINUE**

### CheckPosture (0x007416A0)

Uses `CINSNextBot::TransientlyConsistentRandomValue` for deterministic
per-bot decisions. Reads `bot_silhouette_range_close` and
`bot_silhouette_range_far` ConVars to determine close/far thresholds.

**Silhouette type 0 (standing threat):**
- Close range: 80% → crouch (5-10s), 20% → prone (5-8s)
- Far range: 30% → stand (8-12s), 70% → crouch (8-12s)

**Silhouette type 1 (crouched threat):**
- Close range: 75% → no change (return), 25% → crouch or stand (3-6s / 4-8s)
- Far range: 60% → crouch (3-6s), 35% if beyond far → crouch, else stand (4-8s)

**Silhouette type 2 (prone threat):**
- Close range: 50% → no change, 50% → crouch (3-6s)
- Far range: 50% if beyond far → no change, else crouch (3-6s)

All posture changes call `CINSBotBody::SetPosture()` via
`GetBodyInterface()` (vtable 0x970).

### Event Handlers

**OnSight** (0x00740A40):
- `dynamic_cast<CBaseDetonator*>` on seen entity
- If detonation damage > 0 AND distance < detonation radius:
  - **SUSPEND_FOR** `CINSBotRetreatToCover` (100 bytes) — "Fleeing from nade"

**OnInjured** (0x00740BF0):
- Validates attacker alive and enemy team
- If damage info has ABSOLUTE flag (bit at +0x3C of CTakeDamageInfo):
  - **SUSPEND_FOR** `CINSBotRetreatToCover` (100 bytes) — "We're in fire, get out of here!"

**OnHeardFootsteps** (0x007402A0):
- Requires: enemy team AND not firing
- If no primary threat AND can see source AND not in combat:
  - `AimHeadTowards` — "Looking at footsteps"
- Else if no primary threat:
  - `AddInvestigation(position, type=6)` (footstep investigation)
- Else if has threat:
  - `IVision::AddKnownEntity` (update threat tracking)

**OnSeeSomethingSuspicious** (0x00740060):
- Requires: not firing
- If can't see source:
  - `AddInvestigation(position, type=5)` (suspicious investigation)
- Else if no primary threat and not in combat:
  - `AimHeadTowards` — "Looking at footsteps in Tac Monitor"

---

## CINSBotInvestigationMonitor — Layer 2

Object size: **0x60 bytes (96)**
Objective entity handle at `+0x5C`.

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x0073ED50 | OnStart | Initializes objective entity handle |
| 0x0073EA40 | InitialContainedAction | Allocates CINSBotGamemodeMonitor (0x38 bytes) |
| 0x0073EF60 | Update | Monitors checkpoint investigations (5s interval) |
| 0x0073F120 | OnOtherKilled | 80% → kill location, 20% → attacker position, type 2 |
| 0x0073F700 | OnWeaponFired | 10% visible / 25% heard / 33% distant, type 2 |
| 0x0073F3C0 | OnHeardFootsteps | Type 6, 4-7s delay, 128u distance threshold |
| 0x0073EAD0 | OnSeeSomethingSuspicious | Type 5, 4-7s delay |

### Investigation Queue

Bots maintain a queue of investigations fed by the event handlers above. Each
investigation entry contains:

```
+0x0C  float  position.x
+0x10  float  position.y
+0x14  float  position.z
+0x20  int    type (2=combat, 5=suspicious, 6=footsteps)
```

**OnOtherKilled** (0x0073F120):
- Checks: victim not visible (IVision::IsAbleToSee vtable +0x104), within
  hearing distance
- 80% chance: `AddInvestigation(kill_position, type=2)`
- 20% chance: `AddInvestigation(attacker_position, type=2)`

**OnWeaponFired** (0x0073F700):
- Visible fire: 10% chance, 5s cooldown
- Heard fire (unseen): 25% chance, 5s cooldown
- Distant fire (>1000 units): 33% chance, 10s cooldown
- All produce type 2 investigations

**OnHeardFootsteps** (0x0073F3C0):
- Distance threshold: 128 units
- Requires: not firing, enemy team
- `AddInvestigation(position, type=6)` with 4-7s random delay

**OnSeeSomethingSuspicious** (0x0073EAD0):
- Requires: not firing, no primary threat, no active enemy target
- `AddInvestigation(position, type=5)` with 4-7s random delay

---

## CINSBotGamemodeMonitor — Layer 3

Object size: **0x38 bytes (56)** — pure base Action, no derived fields.

### Gamemode Dispatch Table

`InitialContainedAction` queries `CINSRules` to determine the active gamemode
and allocates the corresponding action:

| Query | Action Class | Size |
|-------|-------------|------|
| IsCheckpoint() | CINSBotActionCheckpoint | 0x40 |
| IsHunt() | CINSBotActionHunt | 0x64 |
| IsOutpost() | CINSBotActionOutpost | 0x5C |
| IsOccupy() | CINSBotActionOccupy | 0x3C |
| IsPush() | CINSBotActionOccupy | 0x3C |
| IsInvasion() | CINSBotActionOccupy | 0x3C |
| IsFireFight() | CINSBotActionFirefight | 0x3C |
| IsInfiltrate() | CINSBotActionInfiltrate | 0x3C |
| IsStrike() | CINSBotActionStrike | 0x38 |
| IsSkirmish() | CINSBotActionSkirmish | 0x3C |
| IsAmbush() | CINSBotActionAmbush | 0x40 |
| IsFlashpoint() | CINSBotActionFlashpoint | 0x3C |
| IsTraining() | CINSBotActionTraining | 0x48C4 |
| IsSurvival() | CINSBotActionSurvival | 0x48 |
| IsConquer() | CINSBotActionConquer | 0x48 |

If no gamemode matches, returns NULL (no contained action).

---

## CINSBotActionCheckpoint — Layer 4 (Checkpoint Gamemode)

Name string: `"Checkpoint"`
Object size: **0x40 bytes (64)**

### Object Layout (derived fields)

```
+0x38  Action*   saved action reference (from bot entity +0x228F)
+0x3C  float     counter-attack throttle timestamp (init -1.0)
```

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x00736920 | OnStart | Saves entity action ref at +0x38, throttle = -1.0 |
| 0x00736A50 | Update | Main strategic decision chain |
| 0x00736970 | OnEnd | Restores entity action ref |
| 0x007369A0 | ShouldAttack | Always returns 1 |
| 0x007369C0 | ShouldHurry | True if distance ≤ 1400 units |
| 0x00737300 | GetName | Returns "Checkpoint" |

### Update Decision Priority Chain (0x00736A50)

The most important function for understanding bot strategic behavior. Checked
in order every tick:

**1. Combat** — visible primary threat + ShouldAttack returns true:
- **SUSPEND_FOR** `CINSBotCombat` (0x88 bytes) — "Attacking nearby threats"

**2. Escort** — nearby entity not on bot's team (`GetTeamNumber != GetBotTeam`):
- **SUSPEND_FOR** `CINSBotEscort` (0x9C bytes) — "Escorting nearest Human"

**3. Investigation** — `!IsInvestigating() && HasInvestigations()`:
- Gets current investigation area via `GetCurrentInvestigationArea()`
- **SUSPEND_FOR** `CINSBotInvestigate` (0x4900 bytes) — "I have an investigation!"

**4. Knife investigation** — `ins_bot_knives_only` ConVar enabled:
- Finds closest player via `UTIL_INSGetClosestPlayer`
- Validates: IsPlayer (vtable +0x158) AND has nav area (vtable +0x548)
- Adds investigation type 7 to player's last known area
- **SUSPEND_FOR** `CINSBotInvestigate` (0x4900 bytes) — "Knifing a player"

**5. Counter-attack** — `g_pGameRules` offset `+0x3AC` is non-zero:
- Gets objective info from `g_pObjectiveResource`:
  - `[0x770]` = current objective index
  - `[0x450 + idx*4]` = objective type (2 or 3)
  - `[0x590 + idx*4]` or `[0x550 + idx*4]` = extraction point (type-dependent)
  - `[idx*0xC + 0x5D0..0x5D8]` = CP position vector
- Generates grenade targets via `CINSNextBotManager::GenerateCPGrenadeTargets`
- **Probability ramp:** `p = clamp((curtime - cached_time - 20.0) × 0.025, 0, 1)`
  - Probability increases linearly over 20 seconds to 100%
  - Throttle timestamp cached at `+0x3C` (reset to -1.0 each cycle)
- If random < p AND closest player found at CP:
  - **SUSPEND_FOR** `CINSBotInvestigate` — "Counter-attacking enemy directly"
- Else:
  - **SUSPEND_FOR** `CINSBotCaptureCP` (0x88 bytes) — "It's a counter-attack and we're not hunting, re-cap"

**6. Contested point** — objective has contested player count > 0 AND index < 16:
- Picks random player from contested list
- **SUSPEND_FOR** `CINSBotInvestigate` — "Counter-attacking contested point"

**7. Guard defensive** — entity byte at `+0x8A5` bit 2 set:
- **SUSPEND_FOR** `CINSBotGuardDefensive` (0x48F4 bytes) — "Defending."

**8. Guard CP** — `TransientlyConsistentRandomValue(entity, 4.0) < 0.5`:
- Duration: RandomFloat(5.0, 15.0)
- **SUSPEND_FOR** `CINSBotGuardCP` (0x48FC bytes) — "Guarding CP."

**9. Default** — **CONTINUE** (do nothing, wait for next tick)

---

## CINSBotCombat

Name string: `"Combat"`
Object size: **0x88 bytes (136)**
Constructor: `0x00715390`

### Object Layout (derived fields)

```
+0x38  int              target entity index (-1 = none)
+0x3C  (4 bytes)        reserved
+0x40  float            combat timeout (curtime + 30.0 at start)
+0x44  (4 bytes)        reserved
+0x48  float            distance to target
+0x4C  byte             has line of sight
+0x4D  byte             can see target
+0x4E  byte             target firing at me
+0x50  float            difficulty scale (2.0 / 3.0 / 5.0)
+0x54  CountdownTimer   frame throttle (0.2s normal, 0.05s solo vs human)
+0x60  CountdownTimer   attack delay
+0x6C  CountdownTimer   lost-target pursuit
+0x78  CountdownTimer   info update (1.0s period)
```

### Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x00715390 | Constructor | Initializes 4 timers, target = -1 |
| 0x00716200 | OnStart | Sets difficulty scale, timeout = curtime + 30s |
| 0x00716550 | Update | Full combat decision tree |
| 0x007151C0 | OnEnd | Clears combat state on exit |
| 0x00716350 | OnResume | Re-validates target after sub-action |
| 0x00716040 | UpdateInternalInfo | Target visibility/distance refresh (1.0s) |
| 0x00716090 | OnSight | Sets visible flag if target matched |
| 0x00716100 | OnLostSight | Clears visible flag; ends combat if escort target |
| 0x00715080 | OnStuck | CHANGE_TO CINSBotStuck (0x6C bytes) |
| 0x00715070 | ShouldHurry | Always returns 2 |
| 0x00715050 | ShouldPursue | Always returns 2 |
| 0x007178C0 | GetName | Returns "Combat" |

### OnStart — Difficulty Scaling (0x00716200)

| Difficulty | Scale Factor |
|-----------|-------------|
| 3 (hard) | 2.0 |
| 2 (medium) | 3.0 |
| default | 5.0 |

Lower scale = faster reaction. Stored at `+0x50`.

### Update Decision Tree (0x00716550)

Runs every tick. Calls `UpdateInternalInfo()` periodically (1.0s).

**Early termination:**
- Target index == -1 → **DONE** ("Combat no longer has a target")
- Timeout elapsed (`curtime >= +0x40`) → **DONE** ("Combat has timed out")
- Target dead/invalid → **DONE** ("Unable to retrieve primary target")
- Target not a player → **SUSPEND_FOR** `CINSBotRetreat` ("Retreating From Non-Player Target")
- Target not known entity → **DONE** ("Target ent is not a Known Entity")
- ShouldAttack == false → **DONE** ("Should Not Attack This Threat")

**Scared retreat** — `IsMinArousal() && !IsEscorting()`:
- Has cover → **SUSPEND_FOR** `CINSBotRetreatToCover` ("Retreating to Cover BC Scared")
- No cover → **SUSPEND_FOR** `CINSBotRetreat` ("Retreating without Cover BC Scared")

**Main decision (ammo ≥ 0.1):**

| Condition | Result | Message |
|-----------|--------|---------|
| Has LOS | SUSPEND_FOR CINSBotAttack | "Attacking a visible/HasLOS threat" |
| Lost target + ShouldPursue + !ShouldRetreat | SUSPEND_FOR CINSBotPursue | "Pursuing a new target that I just lost" |
| Lost target + ShouldRetreat | SUSPEND_FOR CINSBotRetreat | "Retreating BC behavior said to" |
| Weapon supports suppression (bitmask 0x1600) | SUSPEND_FOR CINSBotSuppressTarget | "Suppressing a recently lost threat" |
| Lost-target timer elapsed + ShouldPursue | SUSPEND_FOR CINSBotPursue | "Pursuing a Lost Enemy" |

**Low ammo (< 0.1):**

| Condition | Result | Message |
|-----------|--------|---------|
| In cover | SUSPEND_FOR CINSBotReload | "Reloading In Cover" |
| Escorting | SUSPEND_FOR CINSBotReload | "Reloading in place because of escort/formation" |
| Has attack cover position | Move to cover, CONTINUE | — |
| No cover | SUSPEND_FOR CINSBotRetreat | "Retreating to Reload" |

**Secondary weapon switch:** if primary empty AND distance < 300 units, tries
`GetWeaponInSlot()` for pistol swap.

### Weapon Suppression Bitmask

The expression `(1 << (weapon_type & 0x1F)) & 0x1600` identifies weapon types
that can suppress. Bits 9, 10, 12 → weapon types supporting suppressive fire.

### UpdateInternalInfo (0x00715600)

Runs every 1.0s (gated by timer at +0x78). Updates:
- Target entity index from vision's primary known threat
- Distance to target (pathfinding or direct)
- LOS, visibility, and firing-at-me flags
- Attack and pursuit timers

---

## CINSBotInvestigate

Object size: **0x4900 bytes (18688)** — embeds full `CINSPathFollower`.

### Constructors

| Address | Variant | Notes |
|---------|---------|-------|
| 0x00723FA0 | CNavArea* | Initialize from nav area |
| 0x00724290 | Vector | Initialize from position, resolves nearest nav area |
| 0x007245B0 | Default | Zero-init, origin position |

### Object Layout (key fields past base + embedded path follower)

```
+0x0E   CNavArea*        investigation area
+0x0F   Vector           investigation position (3 floats at +0x0F, +0x10, +0x11)
+0x38   CNavArea*        current investigation area
+0x3C   float            target position X
+0x40   float            target position Y
+0x44   float            target position Z
...     CINSPathFollower (embedded, several KB)
+0x48B8 CountdownTimer   patience timer (5.0s period)
+0x48C4 CountdownTimer   idle check timer
+0x48D0 CountdownTimer   area change timer
+0x48DC float            last-checked position X
+0x48E0 float            last-checked position Y
+0x48E4 float            last-checked position Z
+0x48E8 CountdownTimer   timer 3
+0x48F9 byte             saved investigating state
+0x48FA byte             state flag
+0x48FC int              investigation type (from queue entry +0x20)
```

### OnStart (0x00723540)

1. Gets current investigation via `CINSNextBot::GetCurrentInvestigation()`
   - If NULL → **DONE** ("Invalid investigation?")
2. Resolves investigation area via `CNavMesh::GetNearestNavArea()`
   - If NULL → **DONE** ("No Place to investigate")
3. Extracts position from investigation entry at `+0x0C/+0x10/+0x14`
4. Extracts type from `+0x20`, stores at `+0x48FC`
5. 60% chance: bot speaks (concept 0x66 if threat alive, 0x47 otherwise)
6. Starts 5.0s patience timer at `+0x48B8`

### Update (0x00723960)

**Done conditions:**
- Investigation area is NULL → "Invalid investigation area?"
- No investigations remain → "No move investigations to worry about"
- Visible threat + ShouldAttack returns true → exits investigation
- **Stuck detection:** if `GetFeet()` position moved < 16 units in 5 seconds:
  - "Gave up investigating, took too long."

**Area change handling:**
- Compares current area from `GetCurrentInvestigationArea()` with stored area
- If changed: gets random point in new area, updates target position, resets
  idle timer

---

## Extension Hook Points

The extension (`bot_action_hook.cpp`) installs two inline detours:

### Hook 1: CINSBotCombat::Update (0x00706550)

Offset in `sig_resolve.h`: `ServerOffsets::CINSBotCombat_Update = 0x00706550`

When the extension has an active goto command for a bot AND the bot has no
visible enemies, the hook returns **DONE** with reason "goto override",
causing the bot to exit combat and resume the parent behavior chain where the
extension's movement request takes effect.

### Hook 2: CINSBotActionCheckpoint::Update (0x00726A50)

Offset in `sig_resolve.h`: `ServerOffsets::CINSBotActionCheckpoint_Update = 0x00726A50`

When the extension has a Python-issued command for a bot, the hook intercepts
the Checkpoint layer's Update and returns **SUSPEND_FOR** one of:
- `CINSBotApproach` (0x80 bytes, ctor at `ServerOffsets::CINSBotApproach_ctor = 0x006E7490`)
  — for movement commands
- `CINSBotInvestigate` (0x4900 bytes, vector ctor at `ServerOffsets::CINSBotInvestigate_ctor_vec = 0x00714290`)
  — for investigate commands

Both hooks use the sret calling convention: the 12-byte ActionResult is
written to the hidden first parameter. The original function pointer is saved
and called for the default path.

### Movement and Look Commands

After suspending the native behavior, the extension directly issues:
- `CINSBotLocomotion::AddMovementRequest` (vtable 0x96C → locomotion, then direct call)
  with `MOVE_TYPE_APPROACH=6`, `MOVE_PRIORITY_NORMAL=8`, `MOVE_SPEED_DEFAULT=5.0`
- `IBody::AimHeadTowards` (vtable 0x970 → body, then vtable +0xD4 for aim)

### Relevant Extension Types

From `bot_action_types.h`:

```cpp
struct ActionResult { int type; void* action; const char* reason; };
enum ActionResultType { CONTINUE=0, CHANGE_TO=1, SUSPEND_FOR=2, DONE=3 };

// Size constants for heap allocation before calling placement constructors:
static constexpr size_t CINSBOT_APPROACH_SIZE     = 128;   // 0x80
static constexpr size_t CINSBOT_COMBAT_SIZE       = 136;   // 0x88
static constexpr size_t CINSBOT_INVESTIGATE_SIZE   = 0x4900;
```

---

## ConVars Referenced

| ConVar | Used By | Purpose |
|--------|---------|---------|
| `bot_silhouette_range_close` | TacticalMonitor::CheckPosture | Close range threshold for posture decisions |
| `bot_silhouette_range_far` | TacticalMonitor::CheckPosture | Far range threshold for posture decisions |
| `ins_bot_debug_combat_decisions` | Combat::Update | Debug logging |
| `ins_bot_knives_only` | ActionCheckpoint::Update | Knife-only investigation mode |
| `bot_rpg_spawn_attackdelay` | TacticalMonitor::Update | RPG deployment timing |

---

## Key Entity Offsets

These are byte offsets from the CINSNextBot / CBaseEntity base, accessed
throughout the behavior system:

| Offset | Field | Used By |
|--------|-------|---------|
| +0x118 | `IsAlive()` vtable offset | MainAction death check |
| +0x158 | `IsPlayer()` / `IsArmed()` | Threat evaluation, ActionCheckpoint |
| +0x208..0x210 | Absolute position (X, Y, Z) | Multiple — threat distance/direction |
| +0x260 | `WorldSpaceCenter()` vtable offset | TacticalMonitor posture |
| +0x548 | `GetLastKnownArea()` vtable offset | Investigation, ActionCheckpoint |
| +0x608 | Flash end time (float) | MainAction flash check |
| +0x620 | `FlashlightIsOn()` vtable offset | SelectCloserThreat weapon check |
| +0x8A5 | Defend flag byte (bit 2) | ActionCheckpoint guard decision |
| +0x8A8 | `IsFiringWeapon()` vtable offset | TacticalMonitor event handlers |
| +0x8AC | `IsInCombat()` vtable offset | Event handlers |
| +0x8D8 | `PressUseButton()` vtable offset | MainAction door opening |
| +0x96C | `GetLocomotionInterface()` vtable offset | Extension movement |
| +0x970 | `GetBodyInterface()` vtable offset | Posture, aim-at |
| +0x974 | `GetVisionInterface()` vtable offset | Threat queries |
| +0x97C | `GetIntentionInterface()` vtable offset | ShouldAttack queries |
| +0xB338 | Last enemy target index | InvestigationMonitor |
| +0xD1 | Entity flags byte (bit 3 = needs CalcAbsolutePosition) | Multiple |

---

## Global Addresses

| Address (BSS) | Symbol | Used By |
|---------------|--------|---------|
| 0x00C0C3D8 | `g_pGameRules` | Counter-attack check (+0x3AC) |
| `g_pObjectiveResource` | (via pointer) | CP positions, types, contested state |
| `g_pEntityList` | (via pointer) | EHANDLE → entity resolution |
| `gpGlobals` | (via pointer) | `curtime` (+0x0C), frame info |
