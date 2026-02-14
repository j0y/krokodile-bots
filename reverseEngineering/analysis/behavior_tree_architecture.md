# Insurgency 2014 Bot Behavior Tree — Complete Architecture

Reverse-engineered from `server_srv.so` via Ghidra decompilation + binary analysis.

## Full Action Tree (Checkpoint/Coop)

```
CINSNextBotIntention::Update()                      @ 0x0074c1e0
  └─ Behavior<CINSNextBot>::Update()
       └─ CINSBotMainAction                         (0x40 bytes)  @ 0x00753aa0
            │  Handles: death → CINSBotDead, flash → CINSBotFlashed, idle suicide
            │
            └─ CINSBotTacticalMonitor                (0x98 bytes)  @ 0x00731bc0
                 │  Handles (SUSPEND_FOR):
                 │    - Visible threat >1200u + RPG  → CINSBotFireRPG
                 │    - No threat + grenade ready    → CINSBotThrowGrenade
                 │    - No threat + low ammo         → CINSBotReload
                 │    - Sees live grenade nearby      → CINSBotRetreatToCover
                 │    - Takes heavy damage            → CINSBotRetreatToCover
                 │  Does directly:
                 │    - Posture adjustment (stand/crouch/prone) based on silhouette
                 │    - ChooseBestWeapon() every 0.5s
                 │    - SnapEyeAngles toward gunfire/footsteps
                 │
                 └─ CINSBotInvestigationMonitor      (0x60 bytes)
                      │  NEVER changes action — only feeds investigation queue:
                      │    - OnOtherKilled: 80% investigate kill location, 20% attacker
                      │    - OnWeaponFired: 10-33% investigate (tiered by range/LOS)
                      │    - OnHeardFootsteps: investigate 4-7s or look-at
                      │    - OnSeeSomethingSuspicious: priority-5 investigation
                      │
                      └─ CINSBotGamemodeMonitor      (0x38 bytes)
                           │  Pure dispatcher — picks gamemode action, then Continue forever
                           │
                           └─ CINSBotActionCheckpoint  (0x40 bytes)  @ Update TBD
                                │  THE DECISION MAKER for Checkpoint/Coop:
                                │
                                ├─ Enemy visible?        → SUSPEND_FOR CINSBotCombat
                                ├─ Human nearby?         → SUSPEND_FOR CINSBotEscort
                                ├─ Has investigation?    → SUSPEND_FOR CINSBotInvestigate
                                ├─ Counter-attack phase? → SUSPEND_FOR CINSBotCaptureCP
                                ├─ Objective to guard?
                                │    ├─ 50%              → SUSPEND_FOR CINSBotGuardCP
                                │    └─ 50%              → SUSPEND_FOR CINSBotGuardDefensive
                                └─ Nothing               → Continue (idle)
```

## Action Lifecycle

Actions have 3 key methods:
- `OnStart(actor, prevAction)` — initialization
- `Update(actor, interval)` — per-tick logic, returns ActionResult
- `OnEnd(actor, nextAction)` — cleanup

### ActionResult (12 bytes, sret return)

```cpp
struct ActionResult {
    ActionResultType type;   // +0x00: 0=CONTINUE, 1=CHANGE_TO, 2=SUSPEND_FOR, 3=DONE
    void *action;            // +0x04: new Action* (for CHANGE_TO/SUSPEND_FOR) or nullptr
    const char *reason;      // +0x08: debug string
};
```

Event handlers (OnSight, OnInjured, etc.) return a 16-byte variant with an extra field at +0x0c (priority/flags).

### x86-32 Linux/GCC Calling Convention

Structs > 8 bytes returned via hidden sret pointer:
```
void Update(ActionResult *sret, void *thisptr, void *actor, float interval)
```

### SUSPEND_FOR Pattern (from decompiled CINSBotActionCheckpoint)

```c
void *newAction = operator_new(0x88);              // allocate
CINSBotCombat::CINSBotCombat(newAction);           // construct
sret->type   = 2;                                  // SUSPEND_FOR
sret->action = newAction;                           // ownership transfers to tree
sret->reason = "Attacking nearby threats";          // debug string
// Zero out actor+0x20..+0x2c (clears some action state)
```

When the suspended action returns DONE, control resumes at the suspender's Update().

## Combat Sub-Tree

When CINSBotCombat is active, it manages weapon-specific attack actions:

```
CINSBotCombat                      (0x88 bytes)  ctor @ 0x00705390
  └─ Picks weapon-appropriate attack:
       ├─ CINSBotAttackRifle       (43 functions)
       ├─ CINSBotAttackSniper      (43 functions)
       ├─ CINSBotAttackLMG         (43 functions)
       ├─ CINSBotAttackPistol      (43 functions)
       ├─ CINSBotAttackCQC         (43 functions)
       ├─ CINSBotAttackMelee       (42 functions)
       ├─ CINSBotAttackAdvance     (44 functions) — advancing while attacking
       ├─ CINSBotAttackFromCover   (43 functions)
       ├─ CINSBotAttackInPlace     (42 functions)
       └─ CINSBotAttackIntoCover   (44 functions)
```

Attack actions handle:
- `IBody::AimHeadTowards(enemyPos)` — engine-quality aim smoothing
- Burst fire timing (weapon-specific)
- ADS management
- Arousal-based accuracy (ConVars: `bot_targeting_noise_*`, `bot_attack_burst_*`)
- Suppression awareness
- Posture during combat

## Gamemode Dispatch Table

`CINSBotGamemodeMonitor::InitialContainedAction()` dispatches based on `CINSRules`:

| Gamemode | Action Class | Size |
|----------|-------------|------|
| Checkpoint | CINSBotActionCheckpoint | 0x40 |
| Hunt | CINSBotActionHunt | 0x64 |
| Outpost | CINSBotActionOutpost | 0x5c |
| Occupy | CINSBotActionOccupy | 0x3c |
| Push | CINSBotActionPush | 0x3c |
| Firefight | CINSBotActionFirefight | 0x3c |
| Infiltrate | CINSBotActionInfiltrate | 0x3c |
| Strike | CINSBotActionStrike | 0x38 |
| Skirmish | CINSBotActionSkirmish | 0x3c |
| Ambush | CINSBotActionAmbush | 0x40 |
| Flashpoint | CINSBotActionFlashpoint | 0x3c |
| Training | CINSBotActionTraining | 0x48c4 |
| Survival | CINSBotActionSurvival | 0x48 |
| Conquer | CINSBotActionConquer | 0x48 |

## Tactical Sub-Actions (used by gamemode actions)

### Lightweight (no CINSPathFollower)

| Action | Size | Constructor Args | Purpose |
|--------|------|-----------------|---------|
| CINSBotCombat | 0x88 | none | Full combat: aim, fire, weapon selection |
| CINSBotApproach | 0x64 | float x, y, z | Move to position via AddMovementRequest |
| CINSBotEscort | 0x9c | none (finds nearest) | Follow human player |
| CINSBotCaptureCP | ~0x40 | int objIdx | Capture/defuse objective |

### Heavy (embed CINSPathFollower ~18k bytes)

| Action | Size | Constructor Args | Purpose |
|--------|------|-----------------|---------|
| CINSBotPatrol | 0x4934 | none | Patrol random areas |
| CINSBotRetreat | 0x4938+ | bool, float / float / int | Retreat to safety |
| CINSBotGuardCP | 0x48f8 | int objIdx, float duration | Guard checkpoint position |
| CINSBotGuardDefensive | 0x48f8 | none | Guard general position |
| CINSBotInvestigate | 0x48fa+ | CNavArea* / Vector / none | Check area |
| CINSBotRetreatToCover | ~0x4900 | varies | Retreat to nearest cover |

## Key Binary Offsets (server_srv.so)

### Already Resolved (in sig_resolve.h)

```
CINSBotApproach::ctor              0x006e7490
CINSBotCombat::Update              0x00706550
CINSBotCombat::ctor                0x00705390
CINSBotLocomotion::AddMovementReq  0x00750dd0
CINSNextBotIntention::Update       0x0073c1e0
CINSBotLocomotion::Update          0x0074d8a0
CINSBotBody::Update                0x00748300
CINSNextBot::PressWalkButton       0x00733c90
```

### Needed for Replacement

```
CINSBotActionCheckpoint::ctor      TBD (find from decompiled header)
CINSBotActionCheckpoint::Update    TBD
CINSBotGuardCP::ctor               TBD
CINSBotGuardDefensive::ctor        TBD
CINSBotRetreat::ctor               TBD
CINSBotRetreatToCover::ctor        TBD
CINSBotInvestigate::ctor           TBD
CINSBotPatrol::ctor                TBD
```

## Investigation System

Investigations are a queue on `CINSNextBot`:
- `AddInvestigation(Vector pos, int priority)` — enqueue
- Consumed by gamemode actions (e.g., Checkpoint checks `HasInvestigation()`)
- Priority: 2=gunfire, 5=suspicious, 6=footsteps

## Engine Subsystems (IVision, IBody, ILocomotion)

These run as `INextBotComponent::Update()` calls, separate from the behavior tree:

| Subsystem | Vtable Offset | What It Does |
|-----------|--------------|--------------|
| IVision | 0x974 | Line-of-sight, threat tracking, CKnownEntity management |
| IBody | 0x970 | Posture state machine, arousal, AimHeadTowards |
| ILocomotion | 0x96c | Pathfinding, AddMovementRequest processing |

Currently all three update functions are detoured to no-op. Vision data is still queryable via vtable dispatch even with Update disabled (vision state is populated by the main IVision::Update which we'd re-enable).

## Detour Infrastructure

- `InlineDetour` class: 5-byte JMP rel32 patch
- Supports trampolines via `GetTrampoline()` (copies original 5 bytes + JMP back)
- Can install/remove at runtime, no limit on count
- Currently 4 detours active (Intention, Locomotion, Body, CombatUpdate)

## What Each Layer Controls

| Layer | Controls | We Want |
|-------|----------|---------|
| Intention::Update | Drives entire tree | Re-enable (let tree run) |
| MainAction | Death/flash handling | Keep (engine handles) |
| TacticalMonitor | Grenades, RPG, reload, posture, weapon switch | Keep (engine handles) |
| InvestigationMonitor | Sound reactions → investigation queue | Keep (engine handles) |
| GamemodeMonitor | Dispatches to gamemode action | Keep (engine handles) |
| **ActionCheckpoint** | **Strategic decisions: fight/guard/investigate/retreat** | **REPLACE with our detour** |
| CINSBotCombat | Aim, fire, recoil, burst, weapon handling | Keep (engine handles) |
| Body::Update | Posture, arousal, aim tracking | Re-enable |
| Locomotion::Update | Pathfinding, movement requests | Re-enable |
