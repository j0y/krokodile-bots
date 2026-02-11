# Team Coordination via Metamod Extension — Design Reference

## Architecture Overview

The original Insurgency bots have **zero inter-bot coordination**. Each bot runs its own
independent behavior tree. The `CINSBotCombat::Update()` action is the sole decision point
where a bot chooses between Attack, Pursue, Retreat, RetreatToCover, or SuppressTarget —
all based on individual assessment only.

Team coordination is implemented as a **Metamod C++ extension** that:

1. Adds a `TeamCoordinator` singleton with shared tactical state
2. Hooks a minimal set of existing action `Update()` methods
3. Forces bots into **existing native action classes** based on assigned roles
4. Lets the engine handle all low-level execution (aiming, firing, locomotion, cover)
5. Receives high-level orders from Python via UDP bridge

```
Python (strategic)                         Metamod Extension (tick-rate)
──────────────────                         ─────────────────────────────
"execute tactic T                          TeamCoordinator singleton
 with bots [A,B,C]                                │
 at target X"                              ┌──────┴───────┐
       │                                   │              │
       └── UDP ──────────────────── Hooked Actions    Native Actions
                                   (role dispatch)   (unmodified execution)
```

### Core Hook Points

| Hook Target | Symbol | Why |
|---|---|---|
| `CINSBotCombat::Update` | `_ZN13CINSBotCombat6UpdateEP11CINSNextBotf` | Combat decision dispatch — forces role-based action selection |
| `CINSBotSuppressTarget::Update` | `_ZN20CINSBotSuppressTarget6UpdateEP11CINSNextBotf` | Extend/modify exit conditions for coordinated suppression |
| `CINSBotAttackAdvance::Update` | `_ZN18CINSBotAttackAdvance6UpdateEP11CINSNextBotf` | Signal coordinator on advance completion |
| `CINSBotApproach::Update` | `_ZN15CINSBotApproach6UpdateEP11CINSNextBotf` | Signal coordinator on position reached |

All hooks follow the same pattern: check coordinator for a role, if none → `CALL_ORIGINAL()`.

### Shared State

```cpp
struct TacticSlot {
    int         id;
    int         type;              // SUPPRESS_ADVANCE, BOUNDING, BREACH, CROSSFIRE
    int         participants[4];   // entity indices, -1 = unused
    int         roles[4];          // per-participant role enum
    Vector      positions[4];      // target positions per role
    CBaseEntity* target_entity;

    enum Phase { SETUP, PHASE_1, PHASE_2, PHASE_3, DONE };
    Phase       phase;
    float       phase_start_time;
    float       timeout;           // auto-cancel if exceeded
};
```

---

## Tactic 1: Suppress and Advance

**Situation**: Two bots spot the same enemy behind cover. One lays suppressive fire
while the other pushes to a flanking or closer position.

### Roles

| Role | Bot Action | Native Class Used |
|---|---|---|
| SUPPRESSOR | Fire at enemy position with spread, keep firing until advancer signals done | `CINSBotSuppressTarget` |
| ADVANCER | Wait for suppression, then push toward enemy | `CINSBotAttack` → `CINSBotAttackAdvance` |

### Phase State Machine

```
SETUP ──────────── Coordinator assigns roles
  │
  ▼
PHASE_1 (SUPPRESSING)
  │  Suppressor: ChangeTo → SuppressTarget(target_pos, target_entity)
  │  Advancer:   Continue() — hold position, wait
  │  Transition: suppressor fires first burst → PHASE_2
  │
  ▼
PHASE_2 (ADVANCING)
  │  Suppressor: keep suppressing (timer reset on each expiry)
  │  Advancer:   ChangeTo → Attack() (native picks weapon sub-action)
  │  Transition: advancer reaches engagement range or kills target → DONE
  │              advancer dies or retreats → DONE (abort)
  │              timeout (15s) → DONE
  │
  ▼
DONE ──────────── Both bots return to native solo behavior
```

### Hook Logic

**CINSBotCombat::Update hook**:
- SUPPRESSOR + SETUP/PHASE_1: `ChangeTo(new CINSBotSuppressTarget(pos, entity))`
- ADVANCER + PHASE_1: `Continue()` (wait in current state)
- ADVANCER + PHASE_2: `ChangeTo(new CINSBotAttack())` (native attack with advance)
- Any role + DONE: `CALL_ORIGINAL()` (resume solo behavior)

**CINSBotSuppressTarget::Update hook**:
- If coordinated and phase != DONE: reset expiry timer, don't exit on "spotted threat"
- If DONE: `return Done("advance complete")`

### Relevant Symbols

```
_ZN20CINSBotSuppressTargetC1E6VectorP11CBaseEntity   # constructor(Vector, CBaseEntity*)
_ZN13CINSBotAttackC1Ev                                 # constructor()
```

### Key Constants from Decompiled Code

- SuppressTarget fires for 3-6s by default (timer_0, randomized in OnStart)
- SuppressTarget aim spread: sin/cos wobble at 3.5 * curtime, ±5.0 random offset
- SuppressTarget exits if target within 114u ("too close") or ammo empty
- SuppressTarget checks `IsSuppressed` threshold — set by cvar `ins_bot_entrench_suppression_threshold`

---

## Tactic 2: Bounding Overwatch

**Situation**: Two bots need to move through a dangerous area. They leapfrog: one
overwatches (stationary, covering) while the other bounds forward, then they swap.

### Roles

| Role | Phase 1 | Phase 2 | Phase 3 ... |
|---|---|---|---|
| BOT_ALPHA | OVERWATCH (stationary, covering) | BOUND (move to next waypoint) | OVERWATCH |
| BOT_BETA | BOUND (move to next waypoint) | OVERWATCH (stationary, covering) | BOUND |

### Phase State Machine

```
SETUP ──────── Coordinator assigns Alpha=OVERWATCH, Beta=BOUND, generates waypoints
  │
  ▼
PHASE_1
  │  Alpha: ChangeTo → AttackInPlace (stationary, covers sector)
  │  Beta:  ChangeTo → Approach(waypoint_1)
  │  Transition: Beta reaches waypoint_1 → PHASE_2
  │
  ▼
PHASE_2 (roles swap)
  │  Alpha: ChangeTo → Approach(waypoint_2)
  │  Beta:  ChangeTo → AttackInPlace (covers sector)
  │  Transition: Alpha reaches waypoint_2 → PHASE_3
  │
  ▼
PHASE_3 ... (repeat until destination reached or contact)
  │
  ▼
DONE ──── destination reached, or either bot enters CINSBotCombat (contact)
```

### Hook Logic

**CINSBotCombat::Update hook** (same hook, different tactic type):
- OVERWATCH: `ChangeTo(new CINSBotAttackInPlace())` — stationary firing position
- BOUND: `ChangeTo(new CINSBotApproach(next_waypoint))` — move to next position

**CINSBotApproach::Update hook** (or OnEnd/OnMoveToSuccess):
- On arrival at waypoint: signal coordinator → phase advances, roles swap

**Cancellation**:
- Either bot enters native CINSBotCombat (spotted close threat) → coordinator cancels tactic
- Both bots revert to solo behavior, handle contact individually

### Relevant Symbols

```
_ZN15CINSBotApproachC1E6Vector               # constructor(Vector)
_ZN18CINSBotAttackInPlaceC1Ev                 # constructor()
_ZN15CINSBotApproach15OnMoveToSuccessEP11CINSNextBotPK4Path  # arrival signal
```

### Waypoint Generation

Python computes the waypoint chain from navmesh A* path. Coordinator stores them:

```cpp
struct BoundingData {
    Vector waypoints[8];   // max 8 bounds
    int    num_waypoints;
    int    current_wp;     // index of next waypoint to reach
};
```

Each bound covers ~100-200u. Total distance typically 400-800u (a street crossing, a
corridor, an open area).

---

## Tactic 3: Room Breach (Frag and Clear)

**Situation**: Bots need to enter a room/building with a known or suspected enemy inside.
One bot throws a grenade through the door, the others rush in after detonation.

### Roles

| Role | Action |
|---|---|
| GRENADIER | Move to throw position, throw grenade, then enter |
| POINTMAN | Stack at entry, rush in after detonation |
| COVERMAN | Cover the entry from outside, enter last |

### Phase State Machine

```
SETUP ──────── Python identifies room, assigns roles, picks entry point + throw arc
  │
  ▼
PHASE_1 (STACK)
  │  All bots: Approach(stack_position) — move to positions near entry
  │  Transition: all participants at their stack positions → PHASE_2
  │
  ▼
PHASE_2 (GRENADE)
  │  Grenadier: ChangeTo → ThrowGrenade(target_pos)
  │  Others: AttackInPlace — hold at stack, cover entry
  │  Transition: grenade detonation event (OnSound/OnBlinded) or 3s timeout → PHASE_3
  │
  ▼
PHASE_3 (ENTRY)
  │  Pointman: ChangeTo → Approach(room_center) then Attack
  │  Grenadier: ChangeTo → Approach(room_center) (follows pointman in)
  │  Coverman: AttackInPlace at door for 2s, then Approach(room_center)
  │  Transition: all inside or 8s timeout → DONE
  │
  ▼
DONE ──────── all bots inside, revert to solo CINSBotCombat / sweep
```

### Hook Logic

**CINSBotCombat::Update hook**:
- PHASE_1: all roles → `ChangeTo(new CINSBotApproach(stack_pos))`
- PHASE_2 + GRENADIER: `ChangeTo(new CINSBotThrowGrenade(target_pos, arc))`
- PHASE_2 + others: `ChangeTo(new CINSBotAttackInPlace())`
- PHASE_3: `ChangeTo(new CINSBotApproach(room_center))` → native combat on contact

**Grenade detonation detection**:
Hook `CINSBotTacticalMonitor::OnInjured` or `OnBlinded`, or simply use a fixed timer
(grenade fuse is ~3s). The coordinator watches `gpGlobals->curtime - phase_start_time`.

### Relevant Symbols

```
_ZN19CINSBotThrowGrenadeC1E6VectorS0_       # constructor(Vector target, Vector arc)
_ZN15CINSBotApproachC1E6Vector               # constructor(Vector)
_ZN18CINSBotAttackInPlaceC1Ev                 # constructor()
```

### Key Constants from Decompiled Code

- ThrowGrenade object size: 108 bytes (0x6c)
- ThrowGrenade checks `CanIThrowGrenade()` on CINSNextBot — validates ammo + throw arc
- CINSBotAttackFromCover already does `CanIThrowGrenade` + `SuspendFor(ThrowGrenade)` — same pattern
- Grenade fuse time: typically ~3-4s in Insurgency

---

## Tactic 4: Crossfire Setup

**Situation**: Two bots set up at different angles on a known enemy position, creating a
crossfire that's hard to defend against. Effective for holding chokepoints or ambushing.

### Roles

| Role | Action |
|---|---|
| ANCHOR | Move to anchor position (primary firing angle), engage on signal |
| FLANKER | Move to flanking position (secondary angle), signal ready, engage |

### Phase State Machine

```
SETUP ──────── Python picks two positions with different angles to target, assigns roles
  │
  ▼
PHASE_1 (POSITIONING)
  │  Anchor: Approach(anchor_pos)
  │  Flanker: Approach(flank_pos)
  │  Transition: both in position → PHASE_2
  │
  ▼
PHASE_2 (ENGAGE)
  │  Both: ChangeTo → Attack (native weapon action, both fire simultaneously)
  │  Transition: target killed, both retreat, or timeout (20s) → DONE
  │
  ▼
DONE
```

### Hook Logic

**CINSBotCombat::Update hook**:
- PHASE_1: `ChangeTo(new CINSBotApproach(assigned_pos))`
- PHASE_2: `ChangeTo(new CINSBotAttack())` — both engage simultaneously
- Neither bot engages prematurely. If one arrives first, it holds with AttackInPlace until
  the other is ready.

### Position Selection (Python side)

Python picks positions satisfying:
- Both have line-of-sight to target area
- Angular separation > 45 degrees (ideally 60-90)
- Both have nearby cover (navmesh hiding spots)
- Neither position is behind the other's line of fire

---

## Implementation Notes

### Constructing Native Action Objects

Your Metamod extension needs to call the original constructors to create action objects.
Since symbols are local (`t` not `T`), resolve addresses at plugin load:

```cpp
// Resolve from symbol table at init
typedef void (*SuppressTargetCtor)(void* this_ptr, Vector pos, CBaseEntity* target);
SuppressTargetCtor g_pfnSuppressTargetCtor = nullptr;

void ResolveSymbols(void* server_handle) {
    g_pfnSuppressTargetCtor = (SuppressTargetCtor)
        dlsym(server_handle, "_ZN20CINSBotSuppressTargetC1E6VectorP11CBaseEntity");
}

// Usage: allocate + construct
CINSBotSuppressTarget* CreateSuppressTarget(Vector pos, CBaseEntity* ent) {
    void* mem = operator new(120);  // object size from class_data_layouts.md
    g_pfnSuppressTargetCtor(mem, pos, ent);
    return (CINSBotSuppressTarget*)mem;
}
```

### Object Sizes (from class_data_layouts.md)

| Class | Size | Use |
|---|---|---|
| CINSBotSuppressTarget | 120 (0x78) | Suppressive fire at position |
| CINSBotAttack | 80 (0x50) | Weapon-specific attack dispatcher |
| CINSBotAttackAdvance | 92 (0x5c) | Move toward enemy while firing |
| CINSBotAttackInPlace | 80 (0x50) | Stationary firing |
| CINSBotAttackFromCover | 104 (0x68) | Lean + fire from cover |
| CINSBotAttackIntoCover | 84 (0x54) | Move to cover while engaging |
| CINSBotApproach | 100 (0x64) | Navigate to position |
| CINSBotThrowGrenade | 108 (0x6c) | Throw grenade at target |
| CINSBotRetreatToCover | 100 (0x64) | Fall back to cover |
| CINSBotCombat | 136 (0x88) | Combat decision dispatcher |

### Action Result Types

From `Action<CINSNextBot>` base class:
```
0 = Continue     — keep running this action
1 = ChangeTo     — replace with new action (+ reason string)
2 = SuspendFor   — push new action, resume this one when it ends
3 = Done         — action complete, pop from stack
```

### Cancellation and Failure

Every tactic needs a timeout and abort conditions:
- **Timeout**: `gpGlobals->curtime - phase_start_time > timeout` → DONE, revert all to solo
- **Participant death**: coordinator watches entity validity each tick
- **Participant retreats**: if a hooked bot returns `Retreat` from native logic, honor it — survival > tactics
- **Contact break**: if target dies or escapes, tactic succeeds/cancels naturally

### Python Bridge Protocol Extension

Add a new message type for tactic assignment:

```
Current:  "id mx my mz lx ly lz flags\n"
New:      "TACTIC type bot1 bot2 [bot3 bot4] tx ty tz [tx2 ty2 tz2]\n"

Examples:
  "TACTIC SUPPRESS_ADVANCE 3 5 1024.0 -512.0 64.0\n"
  "TACTIC BOUNDING 3 5 1024.0 -512.0 64.0 1200.0 -512.0 64.0\n"
  "TACTIC BREACH 3 5 7 800.0 -300.0 64.0\n"
  "TACTIC CANCEL 3 5\n"
```

### Symbol Reference

All symbols present in `server_srv.so` (local text, 46721 total symbols):

```
# Constructors
_ZN20CINSBotSuppressTargetC1E6VectorP11CBaseEntity
_ZN13CINSBotAttackC1Ev
_ZN18CINSBotAttackAdvanceC1Ev
_ZN18CINSBotAttackInPlaceC1Ev
_ZN22CINSBotAttackFromCoverC1Ev
_ZN21CINSBotAttackIntoCoverC1E6Vectorbb
_ZN15CINSBotApproachC1E6Vector
_ZN19CINSBotThrowGrenadeC1E6VectorS0_
_ZN22CINSBotRetreatToCoverC1Ebf

# Update methods (hook targets)
_ZN13CINSBotCombat6UpdateEP11CINSNextBotf
_ZN20CINSBotSuppressTarget6UpdateEP11CINSNextBotf
_ZN18CINSBotAttackAdvance6UpdateEP11CINSNextBotf
_ZN15CINSBotApproach6UpdateEP11CINSNextBotf

# Completion signals
_ZN15CINSBotApproach15OnMoveToSuccessEP11CINSNextBotPK4Path
_ZN15CINSBotApproach15OnMoveToFailureEP11CINSNextBotPK4Path17MoveToFailureType

# Lean support (call via vtable offset or symbol)
_ZN11CINSNextBot19PressLeanLeftButtonEf
_ZN11CINSNextBot20PressLeanRightButtonEf
_ZN11CINSNextBot21ReleaseLeanLeftButtonEv
_ZN11CINSNextBot22ReleaseLeanRightButtonEv

# Bot entity methods
_ZNK11CINSNextBot22GetLocomotionInterfaceEv
_ZNK11CINSNextBot17GetVisionInterfaceEv
_ZNK11CINSNextBot20GetIntentionInterfaceEv
```
