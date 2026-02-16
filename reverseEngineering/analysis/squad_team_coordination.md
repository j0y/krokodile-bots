# Bot Squad & Team Coordination — Intel Sharing, Formations, Orders & Objectives

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The bot team coordination system spans six interconnected subsystems: (1) a **central
manager** (`CINSNextBotManager`) that tracks team combat state, issues orders, selects
objectives, and propagates weapon fire events; (2) an **escort formation system**
(`CINSBotEscort`) where bots group around human players in capacity-limited squads;
(3) an **order/command pipeline** where radial commands from players are stored per-bot
in priority-sorted queues; (4) a **chatter system** (`CINSBotChatter`) that shares
enemy positions across same-team bots via `BotStatement` objects; (5) an **investigation
monitor** (`CINSBotInvestigationMonitor`) that converts gunfire, deaths, and footsteps
into investigation points; and (6) **guard actions** (`CINSBotGuardCP`,
`CINSBotGuardDefensive`) that assign bots to defend objectives using nav mesh hiding spots.

Team numbering: **Team 2 = Security**, **Team 3 = Insurgents**.

---

## System Architecture Overview

```
CINSNextBotManager (singleton)
  ├── Update()  ─── team combat counting (0.5s)
  │                  idle chatter dispatch (1-8s)
  │                  survival cache tracking (0.25s)
  │                  grenade target management
  │
  ├── OnWeaponFired()  ─── propagate gunfire to nearby bots (hearing distance by weapon type)
  ├── OnEnemySight()   ─── alert same-team bots to orient toward spotted enemy
  ├── IssueOrder()     ─── distribute radial commands to all team bots
  ├── CommandApproach() / CommandAttack()  ─── direct team bot movement/engagement
  ├── CallForReinforcements()  ─── per-team cooldown timers
  └── GetDesired*Objective()   ─── 6 functions for different game mode objective selection

Per-Bot Systems:
  CINSBotEscort           ─── formation-based squad movement around human players
  CINSBotFollowCommand    ─── lightweight radial "follow" command handler
  CINSBotChatter          ─── enemy callouts, idle chatter, statement coordination
  CINSBotInvestigationMonitor  ─── gunfire/death/footstep → investigation points
  CINSBotGuardCP          ─── guard capture point with hiding spot selection
  CINSBotGuardDefensive   ─── defensive guard with objective tracking
  CINSBotSpecialAction    ─── reinforcement calls on action end
```

---

## CINSNextBotManager — Central Coordinator

**File:** `reverseEngineering/decompiled/CINSNextBotManager.c` (43 functions)

The manager is a singleton (global pointer `INSNextBotManager`) that extends
`NextBotManager`. It owns all team-level state: combat counters, reinforcement
cooldowns, grenade tracking, objective selection, and event propagation.

### Object Layout

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x5C-0x6C | CUtlVector | Active grenades | Count at 0x68 |
| 0x70-0x80 | CUtlVector | Thrown grenades | Count at 0x7C |
| 0x98-0xA0 | CountdownTimer | timer_0 | Grenade think interval |
| 0xA4-0xAC | CountdownTimer | timer_1 | Survival cache check (0.25s) |
| 0xB0-0xB8 | CountdownTimer | timer_2 | Team combat count (0.5s) |
| 0xBC | int | lastCPIndex | Last known active CP index |
| 0xC0 | int | securityCombatCount | Team 2 bots in combat |
| 0xC4 | int | insurgentCombatCount | Team 3 bots in combat |
| 0xC8-0xD0 | CountdownTimer | timer_3 | Team 2 reinforcement cooldown |
| 0xD4-0xDC | CountdownTimer | timer_4 | Team 3 reinforcement cooldown |
| 0xE0-0xFC | CUtlVector[2] | Grenade targets | 0x14 bytes per team |
| 0x110-0x118 | CountdownTimer | timer_5 | Grenade target update (0.25s) |
| 0x11C-0x124 | CountdownTimer | timer_6 | Idle chatter (1-8s) |
| 0x120+ | CountdownTimer[] | Per-CP timers | 17 CPs x 4 timers |
| 0x128 | bool | navForceLoadFlag | Prevents repeated NavMesh force loads |
| 0x129 | bool | useLightVision | Map supports light-based vision |

### Constructor

| Address | Function | Notes |
|---------|----------|-------|
| 0x00764EE0 | CINSNextBotManager() | Calls parent `NextBotManager()`, inits all 7 timers to -1.0f, inits per-CP timer array (17 CPs x 4 timers), sets `[0x15]=0x2A`, `[0x38]=1.0f`, `[0x39]=1`, `[0x4a]=0` |

### Update Loop

| Address | Function | Notes |
|---------|----------|-------|
| 0x00766690 | Update() | Central per-tick think, 4 subsystems below |

**Update subsystems** (each gated by its own `CountdownTimer`):

1. **Grenade think** (timer_0, interval from `ins_bot_grenade_think_time` ConVar):
   - Calls `UpdateGrenades()` and `UpdateGrenadeTargets()`

2. **Idle chatter** (timer_6, random 1.0-8.0s interval):
   - Skips in Survival mode
   - Iterates all players, filters for alive co-op bots (`CINSRules::IsCoopBot`)
   - Checks `nb_blind` ConVar and flags at `+0xb448` (has enemy knowledge) and `+0x2290`
   - Picks a random eligible bot, calls `CINSBotChatter::IdleChatter()`

3. **Survival cache tracking** (timer_1, 0.25s interval):
   - Monitors active objective via `g_pObjectiveResource->+0x770`
   - On CP change: records position (offsets `0x5D0 + cp*0xC`), calls `GenerateCPGrenadeTargets`,
     notifies all bots via `CINSNextBotSurvivalCacheNotify::operator()`

4. **Team combat counting** (timer_2, 0.5s interval):
   - Collects all bots via `NextBotManager::CollectAllBots`
   - Counts alive bots per team → offsets 0xC0 (Security) and 0xC4 (Insurgents)
   - Used by `AreBotsOnTeamInCombat()` and reinforcement eligibility checks

---

## Team Intel Sharing — Weapon Fire Propagation

### OnWeaponFired

| Address | Function | Notes |
|---------|----------|-------|
| 0x00764230 | OnWeaponFired() | Notifies nearby bots when any weapon fires |

When any weapon fires, the manager computes a **hearing distance** from a lookup table
indexed by weapon type (`CSWTCH.989`, 7 entries for weapon classes 8-14). Silenced
weapons multiply the distance by `ins_bot_silenced_weapon_sound_reduction` ConVar.

For each alive bot:
1. Raycasts from firer's position along fire direction (16384.0 units max)
2. Computes distance from the trace hit point to the bot's eye position
3. **Notification conditions** (any of):
   - Bot has **line of sight** (`IsLineOfSightClear`) AND is in **field of view** (`IsInFieldOfView`) → notified
   - Bot is within **250 units** AND in FoV → notified
   - Bot is within **100 units** → notified regardless of LoS/FoV
4. If firer is on a different team → calls bot virtual at offset `+0x5C` (weapon fire notification)
5. Also checks if firer's world center is within computed hearing distance

**Trace mask:** `0x600400B`

### OnEnemySight

| Address | Function | Notes |
|---------|----------|-------|
| 0x007617E0 | OnEnemySight() | Propagates enemy sighting to same-team bots |

When a bot spots an enemy, this iterates all registered bots on the same team:
1. Computes distance from each friendly bot to the spotted enemy (virtual `+0x134`)
2. Compares against `ins_bot_enemy_seen_notify_distance` (default: 300 units)
3. Close enough → calls the bot's body interface (`+0xDC` → `+0xE8`) to orient toward the enemy

This creates a "heads-up" effect: when one bot spots an enemy, nearby teammates turn
to look at the threat.

---

## Escort Formation System

**File:** `reverseEngineering/decompiled/CINSBotEscort.c` (42 functions)

The escort system is the **most sophisticated squad coordination** in the codebase.
Bots form groups around human players using `INSBotEscortFormation` structs stored
in a shared static vector. Nearly every game mode uses this system.

### INSBotEscortFormation Object Layout (0x40 = 64 bytes)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00 | bool | alive | Formation still valid |
| 0x04 | int | teamNum | Team this formation belongs to |
| 0x08 | int | leaderIndex | Player index of the escort target |
| 0x14-0x1C | Vector | position | Current position of the leader |
| 0x20-0x30 | CUtlVector | members | Member bot list |
| 0x34+ | CountdownTimer | timer | Formation update timer |

**Capacity limits:**
- **3 bots** for a human-led formation
- **5 bots** for a bot-led formation

**Global data:** `CINSBotEscort::m_escortFormations` — static `CUtlVector<INSBotEscortFormation*>`
at BSS offsets `0x5d0f70`/`0x5d0f7c`

### Escort Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x0071A3E0 | Constructor | Inits 6 timers, escort target = -1 |
| 0x0071C7F0 | OnStart | Calls SetEscortTarget(), sets bot flag +0x2290=1 |
| 0x0071C350 | Update | Threat check → CINSBotCombat, re-validate target, UpdateEscortFormations(), UpdateFormationMovement() |
| 0x0071B790 | SetEscortTarget | Resolves target via GetEscortTarget or UTIL_INSGetHumanTeammate, creates/joins formations, debug via `ins_bot_debug_escort_formations` |
| 0x0071A700 | HasEscortTarget | Checks human team, searches formations, validates capacity (3 human / 5 bot) |
| 0x0071B5C0 | AddToEscortFormation | Adds bot to formation with capacity check |
| 0x0071A620 | GetEscortFormation | Looks up formation by entity index |
| — | UpdateEscortFormations | Static: removes dead formations, reassigns orphaned bots, recomputes slot positions |
| — | UpdateFormationMovement | Moves bot toward assigned formation slot |
| 0x007191F0 | OnCommandAttack | Adds target to bot's vision known entities |
| 0x00719BE0 | OnSight | Shares enemy sightings with manager via `TheINSNextBots()->VFunc(+0x38)` |
| 0x00719DC0 | OnWeaponFired | If friendly fires: raycasts to their aim point, aims head there. If enemy fires: aims toward shooter |
| 0x007192B0 | ShouldHurry | Matches escort target's sprint state |
| 0x007196D0 | ShouldRetreat | Retreats if suppressed and >256u from formation center |
| 0x00719050 | OnEnd | Clears escort data: +0xb32c=-1, +0x2290=0 |

### CINSNextBot Escort Offsets

| Offset | Type | Field |
|--------|------|-------|
| 0x2290 | bool | isEscorting |
| 0xB32C | int | escortTargetIndex (-1 = none) |
| 0xB330 | ptr | escortTargetPtr |
| 0xB334 | ptr | escortFormationPtr → INSBotEscortFormation |

### Escort Usage Across Game Modes

| Game Mode Action | Escort Usage |
|-----------------|-------------|
| CINSBotActionCheckpoint | "Escorting nearest Human" |
| CINSBotActionPush | "Escorting " |
| CINSBotActionConquer | "Escorting " |
| CINSBotActionFirefight | "Escorting " |
| CINSBotActionHunt | Creates escort |
| CINSBotActionOutpost | "Escorting " |
| CINSBotActionSurvival | "Escorting the nearest human" |

---

## Order / Command System

Orders flow from human players (via radial menu) through the manager to individual bots.
Each bot stores up to 5 active orders in a priority-sorted vector.

### OrderData_t Layout (inferred from accessor offsets)

| Offset | Type | Field |
|--------|------|-------|
| 0x00 | CountdownTimer | expiry timer |
| 0x0C | int | radialCommand (eRadialCommands enum) |
| 0x10 | int | issuerIndex (player who issued) |
| 0x14-0x1C | Vector | targetPosition |
| 0x20 | int | markedObjective |
| 0x24 | int | priority (OrderPriority) |

### Manager Order Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x00764090 | IssueOrder(team, cmd, ...) | Collects all bots, filters by team + alive, calls AddOrder on each, calls virtual +0xB4 (acknowledge) |
| 0x00764950 | CommandApproach(team, pos, radius) | Orders bots within radius to approach position (virtual +0x78) |
| 0x00764B00 | CommandAttack(team, entity) | Orders all team bots to attack entity (virtual +0x74) |

### Per-Bot Order Functions (CINSNextBot)

| Address | Function | Notes |
|---------|----------|-------|
| 0x0074BD60 | AddOrder(cmd, target, pos, priority, issuer, duration) | Creates OrderData_t with CountdownTimer, inserts into CUtlVector at +0xb470, calls SortAndRemoveOrders() |
| 0x0074A2D0 | SortAndRemoveOrders() | Removes expired orders, sorts by priority, trims to max 5 |
| 0x00747EF0 | GetCurrentOrder() | Returns first (highest-priority) order, or 0 |
| 0x00747F40 | GetCurrentOrderIssuer() | Returns issuer player index, or -1 |
| 0x00747F10 | GetCurrentOrderRadialCommand() | Returns eRadialCommands value, or -1 |
| 0x00747F70 | GetCurrentOrderTarget() | Returns 3D target position vector |
| 0x00747FD0 | GetCurrentOrderMarkedObjective() | Returns objective ID, or -1 |
| 0x00748000 | GetCurrentOrderPriority() | Returns OrderPriority, or -1 |
| 0x00748030 | HasOrders() | True if order count (0xb47c) > 0 |
| 0x00747EC0 | IsFollowingOrder() | Reads flag at +0x2293 |
| 0x00747ED0 | SetFollowingOrder(bool) | Writes flag at +0x2293 |

### CINSBotFollowCommand — Radial Follow Stub

**File:** `reverseEngineering/decompiled/CINSBotFollowCommand.c` (11 functions)

| Address | Function | Notes |
|---------|----------|-------|
| 0x00720350 | Constructor(eRadialCommands) | Stores command ID at +0xe |
| 0x007201D0 | OnStart | If radial command is -1 → Done("No radial command!"); else Continue |
| 0x00720170 | Update | Calls CountdownTimer::Now(), always returns Continue |
| 0x00720430 | GetName | Returns "FollowCommand" |

A lightweight stub — validates the radial command then ticks indefinitely.
The actual follow behavior is handled by the escort system.

---

## Chatter / Communication System

**File:** `reverseEngineering/decompiled/CINSBotChatter.c` (9 functions)

Bots share enemy knowledge through `BotStatement` objects in a priority-sorted
linked list. The system coordinates callouts across the entire team to prevent overlap.

| Address | Function | Notes |
|---------|----------|-------|
| 0x00759670 | Update() | Calls ReportEnemies(), processes BotStatement::Update(), removes expired/redundant statements. Debug: `ins_debug_chatter` |
| 0x00759240 | ReportEnemies() | **Core intel sharing.** Iterates all players (1-50), filters alive + same team. For each teammate CINSNextBot, checks vision for known enemies on different team seen within **5.0 seconds**. Creates BotStatement with report concept. Only in co-op modes. |
| 0x007590D0 | GetActiveStatement() | Scans all same-team bots, returns highest-priority active BotStatement across the team. Prevents overlapping callouts. |
| 0x00759950 | IdleChatter() | Creates statement (priority 2, concept 1, 5.0s expiry) when alive and not suppressed. Cooldown gated by timer at +0x1818. |
| 0x00758EE0 | AddStatement() | Inserts BotStatement into priority-sorted list, rejects redundant duplicates. |
| 0x00759000 | RemoveStatement() | Removes from linked list, cleans up voice interface, frees memory. |
| 0x00759070 | Reset() | Clears all statements. |

---

## Investigation Monitor — Gunfire, Death & Footstep Intel

**File:** `reverseEngineering/decompiled/CINSBotInvestigationMonitor.c` (14 functions)

Converts environmental stimuli into investigation points that drive bot movement.
These are per-bot but create team-level coordination because multiple bots react
to the same shared events.

| Address | Function | Notes |
|---------|----------|-------|
| 0x0073ED50 | OnStart | Inits objective tracking (Hunt: scans 3 points; Checkpoint: active CP handle stored at +0x5c) |
| 0x0073EF60 | Update | Every 5s when not in combat, checks objective change and updates tracked entity |
| 0x0073F120 | OnOtherKilled | **Death intel.** If killer visible or within `ins_bot_friendly_death_hearing_distance` (default 100u): 50% chance speak concept 0x49 (death callout); **80% chance** investigate dead teammate's position; **20% chance** investigate killer's position |
| 0x0073F700 | OnWeaponFired | **Gunfire intel.** Enemy fires + bot not in combat: if enemy visible → **90% chance** investigate (5s cooldown); if enemy audible (silhouette) + not hurrying → **75% chance** investigate; if enemy <1000u → **67% chance** investigate (10s cooldown) |
| 0x0073F3C0 | OnHeardFootsteps | **Footstep intel.** Enemy footsteps >128u, no current threat, not hurrying: speaks concept 0x3F (footsteps callout), adds investigation at footstep location (priority 6, 4-7s cooldown) |
| 0x0073EAD0 | OnSeeSomethingSuspicious | Not firing, no current investigation, not hurrying: adds investigation (priority 5), aims toward suspicious location |

### Investigation Priority Levels (inferred)

| Priority | Source |
|----------|--------|
| 2 | Enemy position (from gunfire/combat) |
| 5 | Suspicious sighting |
| 6 | Footsteps heard |

---

## Guard / Defend Systems

### CINSBotGuardCP — Guard Capture Point

**File:** `reverseEngineering/decompiled/CINSBotGuardCP.c` (15 functions)

| Address | Function | Notes |
|---------|----------|-------|
| 0x007208D0 | Constructor(pointIndex, duration) | Takes CP index and guard time (float) |
| 0x00721550 | OnStart | Gets hiding spot via GetRandomHidingSpotForPoint(), sets +0x2290=1 |
| 0x00720F80 | Update | Checks threat LoS → Done "LoS to an enemy." Monitors CP capture state. Enemy entering CP → random 0-8s timer then exit "Exiting guard state, enemy entering CP". At guard spot: aims periodically ("Guard Aiming"), random ironsights, re-paths to new spots every 1.5s |
| 0x00720B40 | GetRandomHidingSpotForPoint | Uses static `m_HidingSpotsAtPoint` array (16 CPs). Finds spawn zones via FindEntityByClassname("ins_spawnzone"), Fisher-Yates shuffle, round-robin `m_iSelectedHidingSpot` counter for distribution |
| 0x00720590 | OnCommandApproach | Returns Done — aborts guard when receiving approach command |

### CINSBotGuardDefensive — Defensive Guard

**File:** `reverseEngineering/decompiled/CINSBotGuardDefensive.c` (14 functions)

| Address | Function | Notes |
|---------|----------|-------|
| 0x007224A0 | Update | Like GuardCP but also checks `GetDesiredPushTypeObjective()` — if objective changed: Done "Point we were guarding is inactive, relocating to new point." Sets crouching posture ("Crouching at CP"). Reacts to gunshots: aims toward fire source ("Heard some gunshots.") |
| 0x00721FE0 | GetRandomHidingSpotForPoint | Uses objective CP nav area connections. **Prioritizes exposed hiding spots** (flag bit 8), falls back to non-exposed if fewer than 30 found |

---

## Reinforcement System

The reinforcement pipeline flows:
`CINSBotSpecialAction::OnEnd (type==1)` → `CINSNextBotManager::CallForReinforcements()` → per-team cooldown timer

| Address | Function | Notes |
|---------|----------|-------|
| 0x00762A90 | CallForReinforcements(team) | Starts timer_3 (team 2) or timer_4 (team 3) with duration from GetCallForReinforcementCooldown() |
| 0x007628F0 | CanCallForReinforcements(team) | Returns false if timer hasn't elapsed. In Survival: also false if team combat count > 0 |
| 0x007629F0 | GetCallForReinforcementCooldown() | Non-Survival: **10.0s**. Survival: **RandomFloat(40.0, 50.0) + wave_scaling** — later waves get shorter cooldowns |
| 0x007628B0 | AreBotsOnTeamInCombat(team) | Reads combat counters at 0xC0 (team 2) / 0xC4 (team 3) |

### CINSBotSpecialAction (trigger)

**File:** `reverseEngineering/decompiled/CINSBotSpecialAction.c` (12 functions)

| Address | Function | Notes |
|---------|----------|-------|
| 0x007310D0 | OnStart | Type 1: 5s timer, 3s damage abort delay. Other types: random 1-5s timer |
| 0x00730ED0 | OnEnd | **Type 1 → calls `CINSNextBotManager::CallForReinforcements()`** |

---

## Objective Selection System

Six specialized functions determine which control point bots should target,
based on game mode category.

| Address | Function | Mode | Logic |
|---------|----------|------|-------|
| 0x00762450 | GetDesiredPushTypeObjective | Push/Checkpoint/Invasion/Conquer | Reads `g_pObjectiveResource->+0x770` (active push CP index) |
| 0x00761E40 | GetDesiredSkirmishObjective | Skirmish | Complex frontline analysis: counts friendly/enemy-owned CPs, searches forward (Security) or backward (Insurgents) for enemy-owned CP. Uses `HasExplosive()` check. RandomInt(0,1) tiebreaker |
| 0x007621A0 | GetDesiredBattleTypeObjective | Battle-type | Ownership analysis: counts owned/enemy/neutral/contested CPs. 1 enemy CP → target it. 1 contested + 1 owned → target contested. Fallback: direction-based offset |
| 0x00762710 | GetDesiredHuntTypeObjective | Hunt | Returns first CP where status (offset `0x6F0 + cp*4`) is not 1 (not destroyed) |
| 0x007624F0 | GetDesiredOccupyTypeObjective | Occupy | Closest unowned CP to bot, with RandomInt(0,1) to sometimes pick second-closest |
| 0x00765790 | GetDesiredStrongholdTypeObjective | Stronghold | For attackers: closest attackable CP. For defenders: builds defend list via CUtlVector<int>. Uses FLT_MAX as initial distance sentinel |

---

## Event Handling

| Address | Function | Notes |
|---------|----------|-------|
| 0x00761AC0 | FireGameEvent() | Dispatches game events by ID |
| 0x00764D70 | OnPointCaptured() | Notifies all alive bots (virtual +0x9C), capturing team bots get extra callback (+0xA0) |
| 0x00764C40 | OnPointContested() | If contesting team != current owner (from `g_pObjectiveResource->+0x490 + point*4`), notifies all alive bots (virtual +0x98) |
| 0x00761630 | OnRoundRestart() | Full state reset: clears grenades, targets, resets all per-CP timers to -1.0f |
| 0x00761920 | OnMapLoaded() | Resets timers, clears guard hiding spots, checks map light data for vision flag at +0x129 |

### FireGameEvent ID Table

| Event ID | Decimal | Likely Event | Handler |
|----------|---------|-------------|---------|
| 0x45 | 69 | player_shoot | Virtual +0x28 with player + weapon |
| 0x6D | 109 | grenade_pickup | Virtual +0x30 with entity |
| 0x6E | 110 | grenade_throw | Virtual +0x34 with entity |
| 0x79 | 121 | point_captured | Virtual +0x3C with CP data |
| 0x7C | 124 | objective_event | Virtual +0x40 |

---

## Utility Functions

| Address | Function | Notes |
|---------|----------|-------|
| 0x00762CF0 | GetAverageDirectionToPlayersOnTeam(origin, team) | Iterates players 1-48, filters alive + team, computes normalized average direction |
| 0x00762C30 | IsAllBotTeam(team) | Returns true if no human players on team |
| 0x00762790 | BotAddCommand() | Validates NavMesh exists before allowing bot addition; can force-load NavMesh |
| 0x00765DF0 | GenerateCPGrenadeTargets(cpIndex) | Generates grenade targets around CP (attack: type=2, r=250; defend: type=9, r=220; 40s cooldown per CP). Uses nav areas at NavMesh offsets 0x974 and 0x834 |

---

## AI Teammate System (mp_coop_ai_teammates)

A global flag checked throughout the codebase to modify bot behavior when acting as
friendly AI teammates for a solo human player.

**Pattern** (found in CINSNextBot.c, CINSBotBody.c, CINSBotTacticalMonitor.c,
CINSBotVision.c, CINSBotCombat.c):

```c
if (mp_coop_ai_teammates->GetInt() != 0 && CINSRules::IsSoloMode()) {
    teamNum = GetTeamNumber(this);
    humanTeam = CINSRules::GetHumanTeam();
    if (teamNum == humanTeam) {
        // Apply AI teammate behavior adjustments
    }
}
```

**Effects when active:**
- **Difficulty scaling** — AI teammates get "impossible" difficulty aim adjustments
- **Knowledge sharing** — when injured or hearing gunfire, shares enemy knowledge with team
- **Vision adjustments** — modified vision parameters
- **Combat modifications** — altered combat decision thresholds

---

## Hardcoded Constants

| Value | Context | Used In |
|-------|---------|---------|
| 16384.0 | Max weapon fire trace distance | OnWeaponFired |
| 250.0 | Close range auto-notification (in FoV) | OnWeaponFired |
| 100.0 | Very close range auto-notification (any angle) | OnWeaponFired |
| 5.0s | Enemy "recently seen" threshold for callouts | CINSBotChatter::ReportEnemies |
| 256.0 | Max distance from formation center before retreat | CINSBotEscort::ShouldRetreat |
| 3 | Max bots per human-led escort formation | HasEscortTarget |
| 5 | Max bots per bot-led escort formation | HasEscortTarget |
| 5 | Max orders per bot | SortAndRemoveOrders |
| 10.0s | Non-survival reinforcement cooldown | GetCallForReinforcementCooldown |
| 40.0-50.0s | Survival base reinforcement cooldown | GetCallForReinforcementCooldown |
| 0.5s | Team combat count update interval | Update timer_2 |
| 1.0-8.0s | Random idle chatter interval | Update timer_6 |
| 0.25s | Survival cache tracking interval | Update timer_1 |
| 40.0s | Grenade target regeneration cooldown per CP | GenerateCPGrenadeTargets |
| 250.0 | Attack grenade target radius | GenerateCPGrenadeTargets |
| 220.0 | Defend grenade target radius | GenerateCPGrenadeTargets |
| 180.0 | Grenade danger awareness radius | OnGrenadeDetonate |
| 48 | Max player index for team iteration | GetAverageDirectionToPlayersOnTeam |
| 128.0 | Min footstep distance for investigation | OnHeardFootsteps |
| 1000.0 | Close gunfire investigation threshold | OnWeaponFired (Investigation) |

---

## Key ConVars

### Bot Inter-Bot Communication

| ConVar | Default | Description |
|--------|---------|-------------|
| ins_bot_radio_range | 2000 | Hearing range for radio commands |
| ins_bot_radio_range_blocked_fraction | 0 | Range reduction without LoS |
| ins_bot_enemy_seen_notify_distance | 300 | Hearing range for enemy sighting alerts |
| ins_bot_friendly_death_hearing_distance | 100 | Hearing range for friendly death events |

### AI Teammates

| ConVar | Default | Description |
|--------|---------|-------------|
| mp_coop_ai_teammates | 0 | Enable AI teammate system |
| mp_coop_ai_teammate_count | 0 | Number of teammates (0 = fill lobby) |
| mp_coop_ai_teammate_handicap | 0 | Impact on enemy bot counts |

### Gate Defense

| ConVar | Default | Description |
|--------|---------|-------------|
| ins_bot_max_setup_gate_defend_range | 2000 | Max distance from gate for defense positions |
| ins_bot_min_setup_gate_defend_range | 750 | Min distance (closer = ambush cover) |
| ins_bot_min_setup_gate_sniper_defend_range | 1500 | Min sniper defense distance from gate |

### Radial Commands

| ConVar | Default | Description |
|--------|---------|-------------|
| sv_radial_marker_duration | 15 | Radial marker world persistence (seconds) |
| sv_radial_marker_duration_attack | 10 | Attack marker persistence (seconds) |
| sv_radial_spam_cooldown | 2 | Spam counter reset time |

### Survival Coordination

| ConVar | Default | Description |
|--------|---------|-------------|
| ins_survival_coordinated_attack_time_min | 12 | Min seconds bots attack recently captured point |
| ins_survival_coordinated_attack_time_max | 24 | Max seconds bots attack recently captured point |

### Conquer Mode Response Distances

| ConVar | Default | Description |
|--------|---------|-------------|
| mp_conquer_capture_start_response_distance_high_strength | 20000 | Bot response range (high strength) |
| mp_conquer_capture_start_response_distance_low_strength | 9000 | Bot response range (low strength) |
| mp_conquer_capture_finished_response_distance_high_strength | 5000 | Post-capture response range (high) |
| mp_conquer_capture_finished_response_distance_low_strength | 3000 | Post-capture response range (low) |
| mp_conquer_hostile_objective_response_distance_high_strength | 5000 | Hostile objective response (high) |
| mp_conquer_hostile_objective_response_distance_low_strength | 3500 | Hostile objective response (low) |
| mp_conquer_losing_objective_response_distance_high_strength | 9000 | Losing objective response (high) |
| mp_conquer_losing_objective_response_distance_low_strength | 6000 | Losing objective response (low) |

---

## Function Address Table

| Address | Class | Function |
|---------|-------|----------|
| 0x00764EE0 | CINSNextBotManager | Constructor |
| 0x00766690 | CINSNextBotManager | Update |
| 0x00764230 | CINSNextBotManager | OnWeaponFired |
| 0x007617E0 | CINSNextBotManager | OnEnemySight |
| 0x00764090 | CINSNextBotManager | IssueOrder |
| 0x00764950 | CINSNextBotManager | CommandApproach |
| 0x00764B00 | CINSNextBotManager | CommandAttack |
| 0x00762A90 | CINSNextBotManager | CallForReinforcements |
| 0x007628F0 | CINSNextBotManager | CanCallForReinforcements |
| 0x007629F0 | CINSNextBotManager | GetCallForReinforcementCooldown |
| 0x007628B0 | CINSNextBotManager | AreBotsOnTeamInCombat |
| 0x00762450 | CINSNextBotManager | GetDesiredPushTypeObjective |
| 0x00761E40 | CINSNextBotManager | GetDesiredSkirmishObjective |
| 0x007621A0 | CINSNextBotManager | GetDesiredBattleTypeObjective |
| 0x00762710 | CINSNextBotManager | GetDesiredHuntTypeObjective |
| 0x007624F0 | CINSNextBotManager | GetDesiredOccupyTypeObjective |
| 0x00765790 | CINSNextBotManager | GetDesiredStrongholdTypeObjective |
| 0x00762CF0 | CINSNextBotManager | GetAverageDirectionToPlayersOnTeam |
| 0x00762C30 | CINSNextBotManager | IsAllBotTeam |
| 0x00765DF0 | CINSNextBotManager | GenerateCPGrenadeTargets |
| 0x00764D70 | CINSNextBotManager | OnPointCaptured |
| 0x00764C40 | CINSNextBotManager | OnPointContested |
| 0x00761630 | CINSNextBotManager | OnRoundRestart |
| 0x00761920 | CINSNextBotManager | OnMapLoaded |
| 0x00761AC0 | CINSNextBotManager | FireGameEvent |
| 0x00762790 | CINSNextBotManager | BotAddCommand |
| 0x0071A3E0 | CINSBotEscort | Constructor |
| 0x0071C7F0 | CINSBotEscort | OnStart |
| 0x0071C350 | CINSBotEscort | Update |
| 0x0071B790 | CINSBotEscort | SetEscortTarget |
| 0x0071A700 | CINSBotEscort | HasEscortTarget |
| 0x0071B5C0 | CINSBotEscort | AddToEscortFormation |
| 0x0071A620 | CINSBotEscort | GetEscortFormation |
| 0x00719DC0 | CINSBotEscort | OnWeaponFired |
| 0x00719BE0 | CINSBotEscort | OnSight |
| 0x007191F0 | CINSBotEscort | OnCommandAttack |
| 0x00719050 | CINSBotEscort | OnEnd |
| 0x00720350 | CINSBotFollowCommand | Constructor |
| 0x007201D0 | CINSBotFollowCommand | OnStart |
| 0x00720170 | CINSBotFollowCommand | Update |
| 0x00759670 | CINSBotChatter | Update |
| 0x00759240 | CINSBotChatter | ReportEnemies |
| 0x007590D0 | CINSBotChatter | GetActiveStatement |
| 0x00759950 | CINSBotChatter | IdleChatter |
| 0x00758EE0 | CINSBotChatter | AddStatement |
| 0x0073ED50 | CINSBotInvestigationMonitor | OnStart |
| 0x0073EF60 | CINSBotInvestigationMonitor | Update |
| 0x0073F120 | CINSBotInvestigationMonitor | OnOtherKilled |
| 0x0073F700 | CINSBotInvestigationMonitor | OnWeaponFired |
| 0x0073F3C0 | CINSBotInvestigationMonitor | OnHeardFootsteps |
| 0x0073EAD0 | CINSBotInvestigationMonitor | OnSeeSomethingSuspicious |
| 0x007208D0 | CINSBotGuardCP | Constructor |
| 0x00721550 | CINSBotGuardCP | OnStart |
| 0x00720F80 | CINSBotGuardCP | Update |
| 0x00720B40 | CINSBotGuardCP | GetRandomHidingSpotForPoint |
| 0x007224A0 | CINSBotGuardDefensive | Update |
| 0x00721FE0 | CINSBotGuardDefensive | GetRandomHidingSpotForPoint |
| 0x007310D0 | CINSBotSpecialAction | OnStart |
| 0x00730ED0 | CINSBotSpecialAction | OnEnd |
| 0x0074BD60 | CINSNextBot | AddOrder |
| 0x0074A2D0 | CINSNextBot | SortAndRemoveOrders |
| 0x00747EF0 | CINSNextBot | GetCurrentOrder |
| 0x00747EC0 | CINSNextBot | IsFollowingOrder |
| 0x00747ED0 | CINSNextBot | SetFollowingOrder |
| 0x00747C10 | CINSNextBot | GetEscortTarget |
| 0x00747BA0 | CINSNextBot | IsEscorting |
| 0x0075A0D0 | CINSNextBot | GetHumanSquadmate |
