# Bot Grenade System — Targeting, Trajectory & Throw Execution

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The bot grenade system spans four subsystems: (1) a **grenade target registry** managed
by `CINSNextBotManager` that tracks enemy positions as potential grenade destinations;
(2) an **eligibility checker** `CanIThrowGrenade()` that validates range, weapon type,
and finds a viable throw angle; (3) a **ballistic solver** (`AimForGrenadeToss` /
`TraceTrajectory`) that computes physics-accurate parabolic arcs; and (4) a **throw
execution action** (`CINSBotThrowGrenade`) that switches weapons, aims, and fires.

The system also includes reactive **grenade avoidance** — bots flee from visible
grenades via the TacticalMonitor's `OnSight` handler.

---

## Trigger Points — Who Initiates a Grenade Throw?

```
CINSBotTacticalMonitor::Update()       (layer 1 monitor, every tick)
  │
  ├─ Has visible threat at distance >= 240?
  │   └─ Threat NOT aiming at bot → CanIThrowGrenade() check
  │
  ├─ No visible threat (or threat conditions not met)
  │   └─ CanIThrowGrenade() check directly
  │
  └─ Success → SuspendFor → CINSBotThrowGrenade("Throwing a grenade!")

CINSBotAttackFromCover::Update()       (tactical sub-action)
  │
  └─ Bot is crouched in cover
      └─ CanIThrowGrenade() check
          └─ Success → SuspendFor → CINSBotThrowGrenade
```

**TacticalMonitor** is the primary trigger. When the bot has a visible threat
at >= 240 units that is NOT aiming toward the bot, it attempts a grenade throw
before considering other actions. It also attempts grenades when no visible threat
is present (e.g., known-but-hidden enemies). The RPG check (>= 1200 units) takes
priority over grenade checks when both apply.

**AttackFromCover** provides a secondary trigger: if the bot is crouched behind cover,
it tries to lob a grenade over/around the cover.

---

## Grenade Target Registry

Enemy positions are registered as `CINSGrenadeTarget` objects by combat and
cover actions, then consumed by `CanIThrowGrenade()`.

### CINSGrenadeTarget Object Layout (0x24 = 36 bytes)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00 | uint32 | m_typeBitmask | Which grenade types can target this (0xD typical) |
| 0x04 | CountdownTimer | m_timer | Expiration timer (vtable + duration + timestamp) |
| 0x08 | float | m_timer.duration | 10.0s |
| 0x0C | float | m_timer.timestamp | Now() + 10.0s |
| 0x10 | Vector | m_position | Enemy last-known position |
| 0x1C | byte | m_isActive | 1 = valid target, checked as `!= 0` |
| 0x1D | byte | m_isUsed | Set to 1 when consumed by a successful throw |
| 0x20 | float | m_radius | 100.0 units |

### Type Bitmask

The `m_typeBitmask` field (default 0xD = binary 1101) controls which grenade
weapon classes are allowed to target this entry:

| Bit | Weapon Class | Type |
|-----|-------------|------|
| 0 (1) | 2 — Grenade (frag) | Frag grenades (RGD-5, M67) |
| 1 (2) | 3 — Smoke | Smoke grenades |
| 2 (4) | 4 — Flash | Flashbang grenades |
| 3 (8) | 5 — Incendiary | Incendiary/molotov |

The default bitmask 0xD (bits 0, 2, 3) allows frag, flash, and incendiary but
**excludes smoke**. Smoke targets use separate Outpost-mode ConVars.

### Target Registration

`CINSBotCombat::Update()` and `CINSBotAttackFromCover::Update()` create grenade
targets when engaging enemies under specific conditions (higher difficulty bots,
or easy bots after 3+ seconds in combat):

```
// Pseudocode — CINSBotCombat creating a grenade target
CINSGrenadeTarget *target = new CINSGrenadeTarget();  // 0x24 bytes
target->m_typeBitmask = 0xD;             // frag + flash + incendiary
target->m_position = threat->GetPosition();
target->m_radius = 100.0f;
target->m_timer.Start(10.0f);            // expires in 10 seconds
target->m_isActive = true;
target->m_isUsed = false;

int team = bot->GetTeamNumber();
TheINSNextBots()->AddGrenadeTarget(team, target);
```

### CINSNextBotManager::AddGrenadeTarget (0x00765CC0)

Manages per-team target vectors (team 2 at offset 0xE0, team 3 at offset 0xF4):
- Validates team number (2 or 3)
- Checks for nearby duplicates: rejects if new target is within `2 × existing.radius`
  of any existing target
- Inserts into the team's `CUtlVector<CINSGrenadeTarget*>`

### CINSNextBotManager::GetGrenadeTargets (0x007636C0)

Returns pointer to the team-specific grenade target vector:
- Team 2: `manager + 0xE8`
- Team 3: `manager + 0xFC`

---

## CanIThrowGrenade — Eligibility & Target Selection

**Address:** 0x00735830 | **Signature:** `bool CanIThrowGrenade(CINSNextBot*, Vector& outAimTarget)`

This static-like function checks whether a bot can throw a grenade and, if so,
populates the output aim vector for the throw direction.

### Gate Checks (early-out conditions)

```
1. Bot is null                         → return 0
2. Grenade cooldown timer not elapsed  → return 0
   (bot + 0xB378 timestamp, set to Now() + 3.0s after each throw)
3. No weapon in slot 3                 → return 0
4. Weapon not usable (vtable+0x410)    → return 0
5. Weapon class not in {2,3,4,5}       → return 0
   (vtable+0x5F0 = GetWeaponClass, same slot as shooting system)
6. Game is in training mode            → return 0
7. No grenade targets for bot's team   → return 0
```

### Target Search Algorithm

For each registered `CINSGrenadeTarget` in the bot's team list:

```
for each target in GetGrenadeTargets(team):
    if target == null                    → skip
    if (target.bitmask & weapon_bitmask) != weapon_bitmask → skip
    if target.m_isUsed                   → skip
    if !target.m_isActive                → skip

    distance = |bot.EyePosition - target.position|
    if distance > ins_bot_max_grenade_range + target.radius → skip

    // Adjust target height: add 12.0 to Z for lob clearance
    testZ = target.position.z + 12.0

    // Test 12 angles × 3 distances = 36 positions
    for angle = 0° to 330° step 30°:       // 0x1E = 30, up to 0x168 = 360
        for frac = 0.0, 0.5, 1.0:          // fraction of target radius
            testPoint.x = cos(angle) * frac * radius + target.x
            testPoint.y = sin(angle) * frac * radius + target.y
            testPoint.z = testZ

            // LOS trace from target origin to test point
            TraceLine(target.origin, testPoint, MASK_SOLID)
            if hit world → break inner loop (obstructed)

            // Try ballistic throw to test point
            if AimForGrenadeToss(bot, testPoint, outAimTarget):
                target.m_isUsed = 1   // consume target
                return 1              // success!

    // All 36 positions failed → try next target

return 0  // no viable throw
```

**Key details:**
- The 12 radial positions (30° increments) test around the target to find
  unobstructed throw angles
- 3 distance fractions (0.0, 0.5, 1.0 × radius) test from center outward
- A TraceLine (mask `0x42006089` = MASK_SOLID) checks if the test point is
  reachable from the target origin (no wall between them)
- If the trace hits world geometry, that angle is abandoned
- Once `AimForGrenadeToss` succeeds, the target is consumed immediately

---

## AimForGrenadeToss — Ballistic Arc Solver

**Address:** 0x007352E0 | **VProf:** `CINSBotThrowGrenade::AimVectorForGrenade`

Computes the launch velocity vector for a parabolic grenade trajectory from
the bot's eye position to a target point.

### Algorithm

```
1. Get bot eye position (EyePosition)
2. delta = target - eyePos
3. horizontalDist = sqrt(delta.x² + delta.y²)
4. if horizontalDist == 0 → return 0  (target directly above/below)

5. gravity = -sv_gravity * 0.85
   (scaled by 0.85 to account for grenade physics, then negated)

6. Solve quadratic for launch angles:
   discriminant = speed² - gravity * (gravity * horizontalDist² + 2 * deltaZ * speed²)
   if discriminant <= 0 → return 0  (target unreachable)

   angle_low  = atan((sqrt(discriminant) - speed) / (gravity * horizontalDist))
   angle_high = atan((sqrt(discriminant) + speed) / (gravity * horizontalDist))

7. Normalize horizontal direction (XY only)

8. For the LOW arc:
   velocity.x = cos(angle_low) * speed * dirX
   velocity.y = cos(angle_low) * speed * dirY
   velocity.z = sin(angle_low) * speed

   success = TraceTrajectory(bot, eyePos, target, velocity, gravity)
   if success → output velocity, return 1

9. For the HIGH arc (fallback):
   velocity.x = cos(angle_high) * speed * dirX
   velocity.y = cos(angle_high) * speed * dirY
   velocity.z = sin(angle_high) * speed

   success = TraceTrajectory(bot, eyePos, target, velocity, gravity)
   if success → output velocity, return 1

10. return 0  (both arcs failed)
```

The low arc is tried first (flatter trajectory, faster arrival). If it's
obstructed, the high arc (lobbed trajectory) is attempted as fallback.

---

## TraceTrajectory — Flight Path Simulation

**Address:** 0x00734E50 | **VProf:** `CINSBotThrowGrenade::TraceTrajectory`

Simulates the grenade's parabolic flight path through discrete time steps
and checks for collisions.

### Physics Loop

```
dt = 0.2s per step
maxSteps = 20  (total flight time: 4.0 seconds)

prevPos = startPos
for step = 1..20:
    t = step * 0.2
    nextPos.x = velocity.x * t + startPos.x
    nextPos.y = velocity.y * t + startPos.y
    nextPos.z = 0.5 * gravity * t² + velocity.z * t + startPos.z

    TraceLine(prevPos → nextPos, MASK_SOLID, filter=NoNPCsOrPlayer)

    if r_visualizetraces:
        DebugDrawLine(hit, end, yellow)

    if trace.fraction < 1.0:    // hit something
        impactDist = |traceEndPos - targetPos|
        return (impactDist < 45.0)  // within 45-unit tolerance

    prevPos = nextPos

return false  // flew for 4 seconds without landing near target
```

**Key constants:**
- Time step: 0.2s
- Max steps: 20 (4.0s total flight)
- Trace hull: 3.0 × 3.0 × 3.0 (cube extents for collision)
- Impact tolerance: 45.0 units (grenade lands within 45u of target = success)
- Trace mask: `0x42006089` (MASK_SOLID)
- Filter: `CTraceFilterNoNPCsOrPlayer` (ignores bots and players)

---

## CINSBotThrowGrenade — Throw Execution Action

### Object Layout (0x6C = 108 bytes)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00 | int | vtable_0 | `Action<CINSNextBot>` vtable |
| 0x04 | int | vtable_1 | Alt vtable |
| 0x08–0x37 | | Action base | Standard `Action<CINSNextBot>` fields |
| 0x38 | Vector | m_aimDirection | Aim velocity vector from AimForGrenadeToss |
| 0x44 | Vector | m_eyePosition | Bot eye position at throw initiation |
| 0x50 | CountdownTimer | m_timeoutTimer | 5.0s overall timeout |
| 0x5C | CountdownTimer | m_releaseTimer | Post-throw release tracking |
| 0x68 | int | m_startTick | gpGlobals->tickcount at OnStart |

### Constructors

**Parameterized** (0x00734D10) — used by TacticalMonitor:
```
CINSBotThrowGrenade(Vector eyePos, Vector aimDir)
    m_eyePosition = eyePos     // bot's eye position from AbsOrigin
    m_aimDirection = aimDir     // aim target from CanIThrowGrenade
    Both timers initialized to -1.0 (not running)
```

**Default** (0x00735F70) — used by AttackFromCover:
```
CINSBotThrowGrenade()
    If bot has a visible threat:
        Call CanIThrowGrenade(bot, &aimDir)
        If success: populate m_eyePosition and m_aimDirection
        If failure: set bot grenade state to 3 (failed)
```

### OnStart (0x00734540)

```
1. if bot.grenadeState == 3 → Done("Nothing to throw at")
2. weapon = GetWeaponInSlot(3)  // grenade slot
3. if weapon == null → Done("No grenade...")
4. bot.grenadeState = 1  (preparing)
5. Set grenade cooldown: bot+0xB378 = Now() + 3.0s
6. Set aim timer: bot+0xB37C = Now() + 3.0s
7. ChooseBestWeapon(weapon)  — switch to grenade
8. AimHeadTowards(m_aimDirection * 1024 + m_eyePosition,
                  priority=IMPORTANT, duration=5.0s,
                  reply=grenadeThrowReply)
9. Set bot timeout: bot+0xB388 = Now() + 5.0s
10. bot.m_attackDelay = 10.0  (prevent shooting during throw)
11. Start m_timeoutTimer(5.0s)
12. m_releaseTimer.timestamp = -1.0  (not started)
13. m_startTick = gpGlobals->tickcount
14. return Continue
```

### Update State Machine (0x007348F0)

```
┌─ Check weapon availability ─────────────────────────────┐
│  weapon = GetWeaponInSlot(3)                            │
│  active = GetActiveINSWeapon()                          │
│  if either null → Done("No grenade...")                 │
└─────────────────────────────────────────────────────────┘
         │
┌─ Check overall timeout ─────────────────────────────────┐
│  if m_timeoutTimer.IsElapsed() → Done("Timeout")       │
└─────────────────────────────────────────────────────────┘
         │
┌─ Check idle state ──────────────────────────────────────┐
│  if bot.IsIdle() && idleDuration >= threshold           │
│    → Done("Idle in throw grenade")                      │
└─────────────────────────────────────────────────────────┘
         │
┌─ Check error state ─────────────────────────────────────┐
│  if bot.grenadeState == 3                               │
│    → Done("Error aiming grenade.")                      │
└─────────────────────────────────────────────────────────┘
         │
┌─ Pre-throw phase (m_releaseTimer not started) ──────────┐
│  if grenade weapon != active weapon:                    │
│    ChooseBestWeapon(grenade)  — keep switching          │
│                                                         │
│  Get locomotion interface position                      │
│  if |position - m_eyePos| < 40.0:                     │
│    Face toward aim target (locomotion)                  │
│                                                         │
│  if bot.grenadeState == 2     // ready (aim settled)    │
│     && !weapon.IsDeploying()  // animation done         │
│     && weapon.CanAttack():    // weapon ready           │
│    PressFireButton(0.85)  — throw grenade               │
│    Start m_releaseTimer                                 │
│    Start bot timeout timer                              │
│    bot.m_attackDelay = 10.0                             │
│    return Continue                                      │
└─────────────────────────────────────────────────────────┘
         │
┌─ Post-throw phase (m_releaseTimer started) ─────────────┐
│  projectile = active.GetProjectile()                    │
│  if projectile == null → Done (error)                   │
│                                                         │
│  Wait for:                                              │
│    - grenade not being held                             │
│    - weapon activity idle                               │
│    - m_releaseTimer elapsed                             │
│    - weapon CanAttack()                                 │
│  When all true:                                         │
│    ForceLookAtExpire()                                  │
│    → Done("Finished throw.")                            │
└─────────────────────────────────────────────────────────┘
         │
         └─ Continue (waiting for conditions)
```

### OnEnd (0x007343E0)

```
if bot != null:
    body = bot.GetBodyInterface()
    body.ForceLookAtExpire()  // release forced head aim
```

### Behavioral Flags

| Virtual | Return | Effect |
|---------|--------|--------|
| ShouldAttack | 0 | Suppresses combat actions during throw |
| ShouldWalk | 1 | Forces walking speed during throw |
| GetName | "Throwing Grenade" | Debug name |

---

## Bot Entity Grenade Fields

Fields on `CINSNextBot` used by the grenade system:

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x2280 | int | m_grenadeState | 0=idle, 1=preparing, 2=ready, 3=failed |
| 0xB344 | float | m_attackDelay | Set to 10.0 during throw (prevents shooting) |
| 0xB370 | CountdownTimer | m_grenadeCooldownTimer | Prevents rapid re-throws |
| 0xB378 | float | m_grenadeCooldown.timestamp | Now() + 3.0s (cooldown) |
| 0xB37C | CountdownTimer | m_grenadeAimTimer | Aim settle timer |
| 0xB384 | float | m_grenadeAim.timestamp | Now() + 3.0s |
| 0xB388 | CountdownTimer | m_grenadeTimeoutTimer | Overall throw timeout |
| 0xB390 | float | m_grenadeTimeout.timestamp | Now() + 5.0s |

**Grenade state transitions:**
```
0 (idle) ─→ 1 (preparing)    [OnStart: weapon switch & aim]
1 (preparing) ─→ 2 (ready)   [grenadeThrowReply callback: aim settled]
2 (ready) ─→ 0 (idle)        [OnEnd: throw complete or action ended]
        ──→ 3 (failed)       [CanIThrowGrenade: no valid target found]
3 (failed) ─→ 0 (idle)       [OnEnd or next action]
```

---

## Grenade Avoidance — TacticalMonitor::OnSight

**Address:** 0x0073FE10

When a bot sees a non-player entity, the TacticalMonitor checks if it's a
grenade and flees:

```
1. Entity is not a player (IsPlayer() == false)
2. dynamic_cast to CBaseDetonator succeeds
3. CBaseDetonator::GetDetonateDamage() > 0
4. distance = |bot.AbsOrigin - grenade.AbsOrigin|
5. if distance < CBaseDetonator::GetDetonateDamageRadius():
     SuspendFor → CINSBotRetreatToCover(0.0)
     "Fleeing from nade"
```

The bot retreats to cover with urgency 0.0 (immediate). This applies to both
enemy grenades and any detonatable entity (C4, RPG rockets, etc.).

---

## HasExplosive — Explosive Weapon Check

**Address:** 0x0076F920

Checks if the bot has an explosive weapon in slot 3. Not directly used by the
grenade throw system (which uses `GetWeaponInSlot(3)` + `GetWeaponClass()`),
but used elsewhere for explosive-related decisions.

```
Checks weapon classname against (in order):
  "weapon_rpg7"        — RPG-7
  "weapon_at4"         — AT4 launcher
  "weapon_c4_clicker"  — C4 detonator
  "weapon_c4_ied"      — IED
  "weapon_rgd5"        — RGD-5 frag grenade
  "weapon_m67"         — M67 frag grenade

Returns: weapon ammo count if found, 0 otherwise
```

---

## ConVar Reference

### Core Grenade ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `ins_bot_max_grenade_range` | 900 | Max distance (units) bots will try to throw grenades from |
| `dod_grenadegravity` | -420 | Gravity applied to grenade projectiles (unit/s²) |
| `bot_grenade_think_time` | 0 | Think interval for grenade AI (0 = every tick) |
| `bot_hearing_grenade_hearing_range` | 3000 | Distance bots can hear grenade explosions |
| `sv_gravity` | 800 | Server gravity (scaled by 0.85 for grenade physics) |

### Outpost Mode Smoke ConVars

| ConVar | Default | Description |
|--------|---------|-------------|
| `ins_outpost_bot_smoke_amount_min` | 1 | Min smoke grenade targets per interval |
| `ins_outpost_bot_smoke_amount_max` | 1 | Max smoke grenade targets per interval |
| `ins_outpost_bot_smoke_amount_total` | 3 | Absolute max smoke targets generated |
| `ins_outpost_bot_smoke_interval_min` | 35 | Min delay between smoke target generation |
| `ins_outpost_bot_smoke_interval_max` | 15 | Max delay between smoke target generation |
| `ins_outpost_bot_smoke_length_min` | 35 | Min duration of smoke targets |
| `ins_outpost_bot_smoke_length_max` | 15 | Max duration of smoke targets |
| `ins_outpost_bot_smoke_scale_min` | 0 | Min level for smoke scaling |
| `ins_outpost_bot_smoke_scale_max` | 20 | Max level for smoke scaling |
| `ins_outpost_bot_smoke_variance` | 5 | Random variance added to interval |

### Hardcoded Constants

| Constant | Value | Where Used |
|----------|-------|------------|
| Grenade cooldown | 3.0s | CanIThrowGrenade gate, OnStart timer |
| Throw timeout | 5.0s | OnStart timer_0, bot+0xB388 |
| Attack delay during throw | 10.0 | bot.m_attackDelay, prevents shooting |
| Fire button strength | 0.85 | PressFireButton in Update |
| Aim priority | 5 (IMPORTANT) | AimHeadTowards in OnStart |
| Aim look-at distance | 1024.0 | Direction × 1024 + eye position |
| Trajectory time step | 0.2s | TraceTrajectory |
| Max trajectory steps | 20 | 4.0s total flight simulation |
| Impact tolerance | 45.0 | TraceTrajectory: landing distance threshold |
| Gravity scale | 0.85 | AimForGrenadeToss: sv_gravity × 0.85 |
| Height adjustment | 12.0 | CanIThrowGrenade: added to target Z |
| Target search angles | 12 | 360° / 30° = 12 radial positions |
| Target search distances | 3 | 0.0, 0.5, 1.0 × radius |
| Grenade target radius | 100.0 | CINSGrenadeTarget.m_radius default |
| Grenade target expiry | 10.0s | CINSGrenadeTarget timer duration |
| Nearby duplicate threshold | 2 × radius | AddGrenadeTarget rejection |
| Locomotion approach | 40.0 | Update: face target when within 40u |

---

## Function Address Table

| Address | Function | Notes |
|---------|----------|-------|
| 0x00734D10 | CINSBotThrowGrenade(Vector, Vector) | Parameterized constructor |
| 0x00735F70 | CINSBotThrowGrenade() | Default constructor (self-validates) |
| 0x00734540 | OnStart | Weapon switch, aim setup, timers |
| 0x007348F0 | Update | State machine: switch → aim → throw → wait |
| 0x007343E0 | OnEnd | ForceLookAtExpire cleanup |
| 0x007352E0 | AimForGrenadeToss | Ballistic arc solver (two-arc) |
| 0x00734E50 | TraceTrajectory | 20-step physics simulation |
| 0x00735830 | CanIThrowGrenade | Eligibility + target search (36 positions) |
| 0x00736110 | GetName | Returns "Throwing Grenade" |
| 0x00736140 | ShouldAttack | Returns 0 (suppress combat) |
| 0x00736160 | ShouldWalk | Returns 1 (force walk) |
| 0x00765CC0 | AddGrenadeTarget | Manager: per-team target registration |
| 0x007636C0 | GetGrenadeTargets | Manager: returns team target vector |
| 0x00763010 | GetThrownGrenade | Manager: get specific thrown grenade |
| 0x00762FB0 | GetTotalActiveGrenades | Manager: active grenade count |
| 0x00763000 | GetTotalThrownGrenades | Manager: thrown grenade count |
| 0x0076F920 | HasExplosive | Bot: check for explosive in slot 3 |
| 0x0073FE10 | TacticalMonitor::OnSight | Grenade avoidance handler |
