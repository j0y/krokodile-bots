# Bot Shooting System — Fire Control, Aiming & Recoil

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)

The bot shooting system spans three layers: (1) weapon-type **posture coordinators**
that select stance, bipod, and ironsight behavior; (2) **tactical sub-actions** that
decide *when* to call `FireWeaponAtEnemy`; and (3) the core **fire control pipeline**
inside `CINSNextBot` that handles head-steady gating, attack delay, aim tolerance,
burst timing, targeting noise, suppression offsets, and the actual trigger press.

Recoil itself is handled engine-side via a single `bot_recoil_multiplier` ConVar —
there is no per-shot recoil compensation logic in the bot AI code.

---

## Attack Action Hierarchy

```
CINSBotCombat::Update()                   (sees engageable threat)
  └─ SUSPEND_FOR → CINSBotAttack (0x50)   (base dispatcher)
       │
       ├─ InitialContainedAction()         ← WEAPON DISPATCH
       │   │
       │   ├── ins_bot_knives_only?  → CINSBotAttackMelee  (0x48C0, embeds CINSPathFollower)
       │   ├── ins_bot_pistols_only? → CINSBotAttackPistol  (0x50)
       │   └── GetWeaponClass() jump table:
       │        0  Invalid    → CINSBotAttackCQC (fallback)
       │        1  Melee      → CINSBotAttackMelee
       │        2–5 Grenades  → (jump table, likely CQC/special)
       │        6  Pistol     → CINSBotAttackPistol
       │        7  RPG        → (jump table, CINSBotFireRPG via combat)
       │        8  Shotgun    → CINSBotAttackCQC
       │        9  SMG        → CINSBotAttackRifle
       │       10  Rifle      → CINSBotAttackRifle
       │       11  Carbine    → CINSBotAttackRifle
       │       12  LMG        → CINSBotAttackLMG
       │       13  Sniper     → CINSBotAttackSniper
       │       14  DMR        → CINSBotAttackSniper or Rifle
       │       ≥15            → CINSBotAttackCQC (fallback)
       │
       └─ Each weapon-type action → InitialContainedAction():
            ├── CINSBotAttackInPlace   (0x50, hold position and fire)
            ├── CINSBotAttackAdvance   (0x5C, move toward enemy and fire)
            ├── CINSBotAttackFromCover (0x50, peek from cover and fire)
            └── CINSBotAttackIntoCover (0x54, retreat to cover while firing)
```

**Key insight:** weapon-type classes (Rifle, LMG, Sniper, Pistol, CQC) contain
**zero fire control logic**. They manage posture (prone/crouch/stand), bipod
deploy/retract, and ironsight timing. All actual shooting is delegated to the
four tactical sub-actions, which call `CINSNextBot::FireWeaponAtEnemy()`.

---

## CINSBotAttack — Base Dispatcher

| Address | Function | Notes |
|---------|----------|-------|
| 0x007056A0 | Constructor | 80 bytes (0x50) |
| 0x00704DE0 | OnStart | Validates threat, weapon, intention |
| 0x007049C0 | InitialContainedAction | **Weapon dispatch** (jump table) |
| 0x00705050 | Update | Target tracking, aim direction, posture |
| 0x007045C0 | OnEnd | Empty |
| 0x00704CB0 | OnOtherKilled | Done if our target was killed |

### Update (0x00705050) — Per-Tick Logic

1. Idle timeout: `IsIdle() && GetIdleDuration() >= 5.0` → DONE
2. Should retreat: `IIntention::ShouldRetreat()` → DONE
3. Target validation via `bot+0xB338` or vision primary threat
4. Visibility lost: `!IsVisibleInFOVNow() && timeSinceLastSeen >= 0.5` → DONE
5. Low ammo: `GetActiveWeaponAmmoRatio() < 0.1` → DONE
6. **Aim direction:**
   - Target visible: `AimHeadTowards(entity, priority=4, duration=0.3, "Aiming at active enemy")`
   - Target not visible: `AimTowards(lastKnownPos, priority=3, duration=0.3)`
7. Prone posture adjustment when in combat

---

## Weapon-Type Posture Coordinators

### CINSBotAttackRifle / CINSBotAttackLMG (near-identical)

| Address | Function | Notes |
|---------|----------|-------|
| 0x00711680 / 0x006FE1F0 | Constructor | 80 bytes, 2 CountdownTimers at +0x38, +0x44 |
| 0x00710E60 / 0x006FD9C0 | OnStart | Sets posture based on range/suppression |
| 0x00710CA0 / 0x006FD800 | InitialContainedAction | Routes to InPlace / Advance / IntoCover |
| 0x00711130 / 0x006FDCA0 | Update | 0.5s throttle, posture/bipod/ironsight management |

- **Bipod logic:** Deploy when prone AND distance > desiredRange × 0.75; retract otherwise
- **Ironsight:** `PressIronsightButton(0.55f)` — distance-based (no at sprint, yes at long range)
- **InitialContainedAction dispatch:**
  - Has cover AND distance > desired range → `CINSBotAttackIntoCover`
  - Has cover → `CINSBotAttackInPlace`
  - No cover → `CINSBotAttackAdvance`

### CINSBotAttackSniper

Same posture pattern. Key differences:
- **InitialContainedAction:** Only `AttackInPlace` or `AttackIntoCover` (never Advance)
- **ShouldIronsight:** Always returns 2 (always scope)
- Snipers are more passive — they hold position rather than push

### CINSBotAttackPistol

- No bipod, no prone. Postures: walk/sprint/crouch/crawl
- `ins_bot_pistols_only` ConVar forces weapon switch
- **ShouldHurry:** distance < 360u → NO (careful aim when close)

### CINSBotAttackCQC

- Most nuanced `ShouldIronsight`: hipfire at <50% desired range, ironsight at
  mid-range, conditional at long range
- No weapon switching logic

### CINSBotAttackMelee

**Unique — self-contained with own CINSPathFollower (size 0x48C0 = 18,624 bytes)**

- Calls `FireWeaponAtEnemy()` directly from Update (no sub-actions)
- Slide mechanic: `ins_bot_knives_only_enable_slide` + sprint range + 64u + 0.9 cosine facing check
- Two-tier movement: jog close, sprint far
- ShouldRetreat: 0 (never), ShouldAttack: 1 (always)

---

## Tactical Sub-Actions (Where Firing Happens)

### CINSBotAttackInPlace — Hold & Shoot

| Address | Function |
|---------|----------|
| 0x006FB000 | Constructor (0x50 bytes) |
| 0x006FAC50 | OnStart |
| 0x006FB140 | Update |

- **Timer_1:** 8–12s random timeout (engagement window)
- **Timer_0:** 0.5s LOS recheck
- **Side-step logic:** `EyeVectors()` right vector × hull width to find LOS laterally
- **Transitions:** lost target → AttackAdvance; no LOS → AttackAdvance; timeout → Done
- **ShouldRetreat:** health < 0.5 AND ≥2 enemies → YES; suppressed AND enemies → probabilistic
- Fires via `FireWeaponAtEnemy()` every tick while in LOS

### CINSBotAttackAdvance — Move & Shoot

| Address | Function |
|---------|----------|
| 0x006F5EF0 | Constructor (0x5C bytes) |
| 0x006F5D30 | OnStart |
| 0x006F6730 | Update |
| 0x006F61B0 | GetAdvancePosition |

- Fires `FireWeaponAtEnemy()` every tick while advancing
- **Timer_0 (1.0s):** repath; **Timer_1 (0.5s):** posture/weapon checks
- **GetAdvancePosition:** ratio-based (desiredRange/currentRange), scope backing
- **Range thresholds:** <180u with primary → ChangeTo InPlace; sniper within 0.5× max → Done
- ShouldHurry: 0, ShouldRetreat: 0, ShouldIronsight: 1

### CINSBotAttackFromCover — Peek & Shoot

| Address | Function |
|---------|----------|
| 0x006F89F0 | Constructor (0x50 bytes) |
| 0x006F87E0 | OnStart |
| 0x006F9720 | Update |
| 0x006F8B40 | UpdateLOS |

**Most sophisticated — 5-ray LOS system:**

```
UpdateLOS() traces 5 rays from bot to threat:
  Ray 1: standing height  (69u eye offset)
  Ray 2: crouch height    (37u eye offset)
  Ray 3: prone height     (12u eye offset)
  Ray 4: lean left         (standing + hull_width × 32 lateral offset)
  Ray 5: lean right        (standing − hull_width × 32 lateral offset)
```

- **Engagement cycle:** Timer_1 5–10s random, Timer_0 0.5s cover assessment
- **canFire flag:** set 1 normally, set 0 if suppressed or needs reload
- **Crouch timeout:** 6.0s max crouching → Done
- **Grenade opportunism:** checks `CanIThrowGrenade` during cover assessment
- **Bad cover detection:** all LOS rays blocked → ChangeTo AttackInPlace ("shitty cover")

### CINSBotAttackIntoCover — Retreat While Shooting

| Address | Function |
|---------|----------|
| 0x006FCF60 | Constructor (0x54 bytes, takes Vector + 2 bools) |
| 0x006FCB80 | OnStart |
| 0x006FC400 | Update |

- **Movement + shooting:** walks when enemy visible (PressIronsight 0.6s, CanShoot 0.9 threshold), sprints when not visible
- **Arrival:** shouldReload → ChangeTo CINSBotReload; else → ChangeTo AttackFromCover
- **Still-detection failsafe:** 2.0s still → Done ("Rethink")
- **ShouldRetreat — probabilistic risk accumulator:**
  Each factor adds 0.25 probability: injury, suppression, low ammo, high combat intensity

---

## Core Fire Control — `CINSNextBot::FireWeaponAtEnemy()`

**Address: 0x0075AE70**

This is the central function called by all tactical sub-actions. It gates every
single shot through a multi-stage pipeline:

### Stage 1: Pre-Conditions (Early Returns)

```
if (!IsAlive())                    return;
if (player_flags & 0x02)           return;  // some disable flag
if (no target entity AND no primary known threat)  return;
if (IsSprinting())                 return;
if (IsInAir())                     return;
if (HasPlayerFlag(flag))  {                  // posture change flag
    CountdownTimer::Start(bot+0xB3B8);       // delay fire during transition
    return;
}
if (timer at bot+0xB3C0 not elapsed)  return; // general fire cooldown
if (target entity dead)            return;
if (!CanAttackTarget(known))       return;
```

### Stage 2: Weapon Selection

```
if (weapon_reselect_timer elapsed) {
    ChooseBestWeapon(known_threat);
    restart timer at bot+0xB3A0;
}
if (!CanIAttack())                 return;
if (GetActiveINSWeapon() == NULL)  return;
```

### Stage 3: Attack Delay

```
timeSinceLastSeen = known->GetTimeSinceLastSeen();
isVisible = known->IsVisibleInFOVNow();
distance = Distance3D(bot, target);

attackDelay = GetAttackDelay(distance, weapon, isVisible);
if (timeSinceLastSeen <= attackDelay)  return;  // not ready yet
```

### Stage 4: Suppression Fire Probability

When the bot is suppressed (`GetSuppressionFrac() > threshold`):

```
// Suppression fire probability scaled by difficulty
// CSWTCH.663 table: 4 floats indexed by difficulty (0=easy..3=impossible)
probability = base_suppression_prob × difficulty_multiplier;

// Survival mode wave scaling
if (IsSurvival()) {
    wave = g_pGameRules->survivalWave;  // at offset +1000
    probability *= RemapValClamped(wave, 1, 13, 1.0, 1.5);
}

// Difficulty remaps the probability band [low, high]
// easy=RemapVal(0, 0..3, low, high)
// hard=RemapVal(2, 0..3, low, high)
// impossible=RemapVal(3, 0..3, low, high)

if (RandomFloat() > probability)  return;  // suppressed, skip firing
```

### Stage 5: Target Position & Aim Direction

```
if (target visible) {
    targetPos = GetEntityViewPosition(target);
} else {
    // Suppression mode: aim at last known position + random offset
    suppressOffset = GetSuppressingOffset(known);
    lastKnownPos = known->GetLastKnownPosition();
    targetPos = lastKnownPos + suppressOffset;
}
aimDir = Normalize(targetPos − EyePosition());
distToTarget = Length(targetPos − EyePosition());

if (distToTarget > GetMaxAttackRange(weapon))  return;
```

### Stage 6: Ironsight Decision

```
if (ins_bot_knives_only)  goto fire;  // skip ironsight for melee

isADS = GetPlayerFlags() & 1;

if (distToTarget > GetMaxHipFireAttackRange(weapon)) {
    // Beyond hipfire range
    if (target visible && aim on target)
        PressIronsightButton();
    // If ratio dist/maxRange >= 1.0 and not ADS → return (too far for hipfire)
} else if (!isADS && aim on target) {
    // Within hipfire range but could benefit from ADS
    if (ShouldIronsight() == YES)
        PressIronsightButton();
}
```

### Stage 7: Head-Steady Check

```
if (distToTarget < 150.0) {
    // Close range: skip head-steady if in FOV
    if (!IsInFieldOfView(target))  goto steadyCheck;
    // else proceed to fire (no steady requirement at close range)
} else {
steadyCheck:
    if (!IsHeadSteady())  return;

    // Distance-scaled steady duration threshold:
    //   dist < 500u  → threshold = 0.3s
    //   dist > 3000u → threshold = 0.75s
    //   between: linear interpolation
    steadyThreshold = Lerp(dist, 500, 3000, 0.3, 0.75);

    if (GetHeadSteadyDuration() < steadyThreshold)  return;
}
```

### Stage 8: Silhouette Check (optional)

```
if (TheINSNextBots()->silhouetteRequired) {
    if (!CINSBotVision::CanReadSilhouette(threat))  return;
}
```

### Stage 9: Aim Tolerance Check

```
// Use the larger of bot/target bounding box widths
targetWidth = max(target.WorldAlignSize().x, target.WorldAlignSize().y);

aimBloat = GetAimToleranceBloat(known);
aimCone = atan(aimBloat × targetWidth × 0.5 / distToTarget);
cosTolerance = cos(aimCone);

viewDir = GetBodyInterface()->GetViewVector();
dotProduct = Dot(aimDir, viewDir);

if (!closeRange && dotProduct < cosTolerance)  return;  // not aiming close enough
```

### Stage 10: Fire!

```
FireActiveWeapon(bot, known);
```

---

## `FireActiveWeapon()` — Burst Timing & Trigger Press

**Address: 0x0075EE60**

Called at the end of `FireWeaponAtEnemy()` when all gates pass.

### Pre-Conditions

1. Known entity is alive
2. Target entity from known entity is alive
3. Active weapon exists
4. **Line of fire clear:** `CINSBotVision::IsLineOfFireClear()` → if blocked, `ReleaseFireButton()`

### Weapon Class Special Cases

```
weaponClass = weapon->GetWeaponClass();  // vtable+0x5F0

if (weaponClass == 0x0B || weaponClass == 0x0E) {
    // Carbine or DMR: require ADS before firing
    if (!(GetPlayerFlags() & 1)) {
        PressIronsightButton(1.0f);
        return;  // wait for ADS
    }
}
if (weaponClass == 7) {
    return;  // RPG handled separately by CINSBotFireRPG
}
```

### Burst Timing

```
// Solo mode check (human team gets different timing)
isSolo = IsSoloMode() && GetTeamNumber() == GetHumanTeam();

if (weaponClass < 0x0F) {
    // Jump table dispatch per weapon class for specific burst patterns
    // (Ghidra could not recover — "Too many branches")
}

// Fallback / generic burst timing:
if (isSolo) {
    burstMax = ConVar("bot_attack_burst_maxtime_solo");
    burstMin = ConVar("bot_attack_burst_mintime_solo");
} else {
    burstMax = ConVar("bot_attack_burst_maxtime");
    burstMin = ConVar("bot_attack_burst_mintime");
}

burstDuration = RandomFloat(burstMin, burstMax);
PressFireButton(burstDuration);  // vtable+0x8C0
```

---

## `GetAttackDelay()` — Reaction Time

**Address: 0x0076EA60**

Computes the delay before the bot will fire after seeing a target. Returns
a float in seconds.

### Formula

```
delay = bot_attackdelay_base × rangeFraction × outsideFovFraction × survivalFraction × difficultyFraction
```

### Range Fraction Tiers

```
distance vs weapon ranges:
  > MaxAttackRange        → bot_attackdelay_frac_outofrange
  > DesiredAttackRange    → bot_attackdelay_frac_maxrange
  > MaxHipFireAttackRange → bot_attackdelay_frac_desiredrange
  ≤ MaxHipFireAttackRange → bot_attackdelay_frac_hipfirerange
```

### Outside-FOV Multiplier

```
if (target outside FOV when first spotted) {
    delay *= bot_attackdelay_frac_outsidefov;
}
```

### Survival Wave Scaling

```
if (IsSurvival()) {
    survivalStart = bot_attackdelay_frac_survival_start;
    survivalEnd   = bot_attackdelay_frac_survival_end;
    wave = g_pGameRules->survivalWave;
    // waveFrac = (wave − 1) / 12, clamped [0, 1]
    // via: (wave + (-1.0)) * 0.08333f  [≈ 1/12]
    delay *= Lerp(waveFrac, survivalStart, survivalEnd);
}
```

### Difficulty Multiplier

```
difficulty = GetDifficulty();
if (difficulty == NORMAL)     → no multiplier (skip)
if (difficulty == EASY)       → delay *= bot_attackdelay_frac_difficulty_easy
if (difficulty == HARD)       → delay *= bot_attackdelay_frac_difficulty_hard
if (difficulty == IMPOSSIBLE) → delay *= bot_attackdelay_frac_difficulty_impossible
```

### Solo Mode Override

```
if (IsSoloMode() && onHumanTeam)  return 0.0;  // instant reaction
```

---

## `GetAimToleranceBloat()` — Aim Cone Scaling

**Address: 0x0075AA50**

Returns a multiplier that expands or shrinks the angular cone within which the
bot considers itself "aimed at" the target.

### Difficulty-Based Base Value

```
EASY       → bot_attack_aimtolerance_frac_easy
NORMAL     → bot_attack_aimtolerance_frac_normal
HARD       → bot_attack_aimtolerance_frac_hard
IMPOSSIBLE → bot_attack_aimtolerance_frac_impossible
```

### Special Overrides

- If `player_flags & 0x10` (prone/bipod deployed): bloat = 1.0 (perfect accuracy)
- If solo mode + human team + coop AI teammates enabled: force `impossible` tier bloat

### New Threat Time Ramp

When a new threat is first spotted, accuracy ramps up over time:

```
timeSinceFirstSeen = known->GetTimeSinceFirstSeen();
newThreatTime = bot_attack_aimtolerance_newthreat_time;
newThreatTimeSolo = bot_attack_aimtolerance_newthreat_time_solo;

if (timeSinceFirstSeen <= newThreatTime) {
    startBloat = some_start_fraction;  // from ConVar
    // Ramp from startBloat to 1.0 over newThreatTime
    frac = clamp(timeSinceFirstSeen / newThreatTime, 0, 1);
    bloat = Lerp(frac, startBloat, 1.0);

    // Also factor in head steady duration
    steadyDuration = GetHeadSteadyDuration();
    steadyFrac = clamp(steadyDuration × someMultiplier, 0, 1);
    steadyBloat = Lerp(steadyFrac, startBloat, 1.0);

    // Use the better (higher) of the two
    finalBloat = max(bloat, steadyBloat);
    result *= clamp(finalBloat, 0, 1);
}
```

---

## `GetTargetNoise()` — Per-Axis Aim Jitter

**Address: 0x0076F3F0**

Adds random noise to the aimed position. Returns a Vector with per-axis
random offsets in `[-noise, +noise]` range.

### Base Noise Values

```
noiseX = bot_targeting_noise_x_base
noiseY = bot_targeting_noise_y_base
noiseZ = bot_targeting_noise_z_base
```

Solo mode (human team) uses separate ConVars:
```
noiseX = bot_targeting_noise_x_base_solo
noiseY = bot_targeting_noise_y_base_solo  (same ConVar, all axes equal)
noiseZ = bot_targeting_noise_z_base_solo
```

### Range-Tier Multipliers

Distance is compared against three weapon range thresholds:

```
if (dist > MaxAttackRange) {
    noiseX *= bot_targeting_noise_x_frac_maxrange
    noiseY *= bot_targeting_noise_y_frac_maxrange
    noiseZ *= bot_targeting_noise_z_frac_maxrange
}
else if (dist > DesiredAttackRange) {
    noiseX *= bot_targeting_noise_x_frac_desiredrange
    noiseY *= bot_targeting_noise_y_frac_desiredrange
    noiseZ *= bot_targeting_noise_z_frac_desiredrange
}
else if (dist > MaxHipFireAttackRange) {
    noiseX *= bot_targeting_noise_x_frac_hipfirerange
    noiseY *= bot_targeting_noise_y_frac_hipfirerange
    noiseZ *= bot_targeting_noise_z_frac_hipfirerange
}
else {
    // Within hipfire range: no multiplier (base noise only)
}
```

### Final Randomization

```
result.x = RandomFloat(-noiseX, +noiseX)
result.y = RandomFloat(-noiseY, +noiseY)
result.z = RandomFloat(-noiseZ, +noiseZ)
```

---

## `ApplyAimPenalty()` — Sustained-Fire & Lighting Drift

**Address: 0x0075B9D0**

Applies an aim offset based on distance, difficulty, and lighting conditions.
Uses ray-plane intersection to project the aim offset onto the target plane.

### Distance-Based Penalty

```
// Penalty amount and duration interpolated by distance fraction
penaltyFar   = bot_attack_aimpenalty_amt_far
penaltyClose = bot_attack_aimpenalty_amt_close  (from unresolved ConVar)
penalty = Lerp(distanceFraction, penaltyClose, penaltyFar)

timeFar   = bot_attack_aimpenalty_time_far
timeClose = bot_attack_aimpenalty_time_close
penaltyTime = Lerp(distanceFraction, timeClose, timeFar)
```

### Difficulty Scaling

```
EASY       → penalty *= bot_attack_aimpenalty_amt_frac_easy
HARD       → penalty *= bot_attack_aimpenalty_amt_frac_hard
IMPOSSIBLE → penalty *= bot_attack_aimpenalty_amt_frac_impossible
NORMAL     → no scaling
```

Solo mode (human team) always uses `impossible` tier.

### Lighting Conditions

Reads lighting data from the target entity (4 floats at entity offsets
+0xE0, +0xE4, +0xE8, +0xEC, averaged):

```
avgLight = (light[0] + light[1] + light[2] + light[3]) × 0.25
avgLight = clamp(avgLight, 0, 1)

lightPenalty = Lerp(avgLight, bot_attack_aimpenalty_amt_frac_dark, bot_attack_aimpenalty_amt_frac_light)
penalty *= lightPenalty

lightTime = Lerp(avgLight, bot_attack_aimpenalty_time_frac_dark, bot_attack_aimpenalty_time_frac_light)
penaltyTime *= lightTime
```

### Application

The penalty is applied as a displacement perpendicular to the aim direction,
projected onto the target plane. The displacement fades based on
`known->GetTimeSinceLastSeen()` vs the computed penalty time.

---

## `GetSuppressingOffset()` — Blind-Fire Offset

**Address: 0x0075A510**

When the bot fires at a non-visible target (suppression mode), this function
computes a pseudo-random offset around the target's last known position.

### Offset Components

1. **Height bias:** Adds a fixed vertical offset to the target center (from CSWTCH.663+0x14)
2. **Sinusoidal sweep:** Uses `sin(4.0 × curtime)` and `cos(0.75 × curtime)` for
   oscillating horizontal/vertical offsets, scaled by constants from CSWTCH.663+0x44
3. **Transient random:** `TransientlyConsistentRandomValue()` called twice with
   `(bot_entity, 0.5f)` for two random scalars × 10.0, applied along the right
   and up vectors
4. **Distance attenuation:** All offsets scaled by `clamp((distance + offset) × scale, 0, 1)`
   — suppression fire becomes more accurate at close range

### Result

```
offset.x = (rightVec × rand1 + upVec × rand2 + sinSweep + cosSweep) × distFrac
offset.y = ...
offset.z = ... + heightBias
```

---

## `ShouldSuppressThreat()` — Suppression Decision

**Address: 0x0074A800**

Returns `true` if the bot should fire at a non-visible but recently-seen target.

### Conditions (all must pass)

1. `known->GetTimeSinceLastSeen() <= ins_bot_suppress_visible_requirement`
2. Has active weapon (not null)
3. Weapon class ≠ 1 (not melee)
4. `ins_bot_knives_only` is NOT set
5. Target is NOT currently visible (`!IsVisibleNow()`) but WAS recently visible (`IsVisibleRecently()`)
6. Distance to target > `GetMaxHipFireAttackRange()` (no suppression at close range)
7. Weapon ammo check: `currentAmmo / maxAmmo` ratio is acceptable (not zero, and weapon can still fire)
8. Time since last seen < `ins_bot_suppressing_fire_duration`

---

## Recoil Handling

There is **no per-shot recoil compensation** in the bot AI code. Instead:

- **`bot_recoil_multiplier`** (ConVar, default "0", REPLICATED): Multiplier applied
  engine-side to weapon recoil when the shooter is a bot. At 0 or near-0, bots
  experience negligible recoil. This is a global scalar, not per-weapon.
- All `OnWeaponFired()` handlers in attack actions are **trivial** — they return
  `CONTINUE` with no side effects. There is no recoil tracking, no viewangle
  adjustment, and no burst interruption based on accumulated recoil.

The bot's accuracy over sustained fire is controlled entirely by:
1. `GetTargetNoise()` — random per-axis noise per firing decision
2. `ApplyAimPenalty()` — sustained fire drift based on time and lighting
3. `GetAimToleranceBloat()` — expanding aim cone for new threats
4. `bot_recoil_multiplier` — engine-side recoil scaling

---

## Scope Range Bonus

In the weapon-type coordinators, scoped weapons get extended effective range:

```
// In AttackRifle/LMG/Sniper Update():
scopeFOV = weapon->GetScopeFOV();  // vtable call

if (scopeFOV < 20) {
    // High-power scope (e.g., 4x, 7x)
    desiredRange *= 1.75;
} else if (scopeFOV < 90) {
    // Low-power scope (e.g., 2x, red dot)
    desiredRange *= 1.15;
}
```

---

## OnWeaponFired Event Handlers

All attack action `OnWeaponFired()` handlers are identical trivial stubs:

```c
void CINSBotAttack*::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*)
{
    result.type = CONTINUE;  // 0
    result.action = NULL;
    result.reason = NULL;
    result.priority = 1;
}
```

This confirms that no action-level logic responds to individual shot events.
The `CINSNextBot::OnWeaponFired()` at 0x007342A0 (the entity-level handler)
propagates the event up the behavior tree but no action acts on it for
fire control purposes.

---

## Complete ConVar Reference

### Attack Delay

| ConVar | Purpose |
|--------|---------|
| `bot_attackdelay_base` | Base delay in seconds |
| `bot_attackdelay_frac_hipfirerange` | Multiplier when within hipfire range |
| `bot_attackdelay_frac_desiredrange` | Multiplier when within desired range |
| `bot_attackdelay_frac_maxrange` | Multiplier when within max range |
| `bot_attackdelay_frac_outofrange` | Multiplier when beyond max range |
| `bot_attackdelay_frac_outsidefov` | Multiplier when target was outside FOV |
| `bot_attackdelay_frac_difficulty_easy` | Difficulty multiplier (easy) |
| `bot_attackdelay_frac_difficulty_hard` | Difficulty multiplier (hard) |
| `bot_attackdelay_frac_difficulty_impossible` | Difficulty multiplier (impossible) |
| `bot_attackdelay_frac_survival_start` | Survival wave 1 multiplier |
| `bot_attackdelay_frac_survival_end` | Survival wave 13 multiplier |

### Burst Timing

| ConVar | Purpose |
|--------|---------|
| `bot_attack_burst_mintime` | Minimum burst duration (seconds) |
| `bot_attack_burst_maxtime` | Maximum burst duration (seconds) |
| `bot_attack_burst_mintime_solo` | Solo mode minimum burst |
| `bot_attack_burst_maxtime_solo` | Solo mode maximum burst |

### Targeting Noise (per-axis base + 3 range tier fractions)

| ConVar | Purpose |
|--------|---------|
| `bot_targeting_noise_x_base` | Base X noise |
| `bot_targeting_noise_y_base` | Base Y noise |
| `bot_targeting_noise_z_base` | Base Z noise |
| `bot_targeting_noise_x_base_solo` | Solo mode X base |
| `bot_targeting_noise_y_base_solo` | Solo mode Y base (appears same ConVar) |
| `bot_targeting_noise_z_base_solo` | Solo mode Z base (appears same ConVar) |
| `bot_targeting_noise_x_frac_hipfirerange` | X multiplier at hipfire range |
| `bot_targeting_noise_y_frac_hipfirerange` | Y multiplier at hipfire range |
| `bot_targeting_noise_z_frac_hipfirerange` | Z multiplier at hipfire range |
| `bot_targeting_noise_x_frac_desiredrange` | X multiplier at desired range |
| `bot_targeting_noise_y_frac_desiredrange` | Y multiplier at desired range |
| `bot_targeting_noise_z_frac_desiredrange` | Z multiplier at desired range |
| `bot_targeting_noise_x_frac_maxrange` | X multiplier at max range |
| `bot_targeting_noise_y_frac_maxrange` | Y multiplier at max range |
| `bot_targeting_noise_z_frac_maxrange` | Z multiplier at max range |

### Aim Tolerance

| ConVar | Purpose |
|--------|---------|
| `bot_attack_aimtolerance_frac_easy` | Aim cone bloat (easy) |
| `bot_attack_aimtolerance_frac_normal` | Aim cone bloat (normal) |
| `bot_attack_aimtolerance_frac_hard` | Aim cone bloat (hard) |
| `bot_attack_aimtolerance_frac_impossible` | Aim cone bloat (impossible) |
| `bot_attack_aimtolerance_newthreat_time` | New threat ramp-up time |
| `bot_attack_aimtolerance_newthreat_time_solo` | Solo mode new threat time |

### Aim Penalty

| ConVar | Purpose |
|--------|---------|
| `bot_attack_aimpenalty_amt_far` | Penalty amount at far range |
| `bot_attack_aimpenalty_amt_close` | Penalty amount at close range |
| `bot_attack_aimpenalty_time_far` | Penalty duration at far range |
| `bot_attack_aimpenalty_time_close` | Penalty duration at close range |
| `bot_attack_aimpenalty_amt_frac_easy` | Difficulty scaling (easy) |
| `bot_attack_aimpenalty_amt_frac_hard` | Difficulty scaling (hard) |
| `bot_attack_aimpenalty_amt_frac_impossible` | Difficulty scaling (impossible) |
| `bot_attack_aimpenalty_amt_frac_light` | Lighting: well-lit fraction |
| `bot_attack_aimpenalty_amt_frac_dark` | Lighting: dark fraction |
| `bot_attack_aimpenalty_time_frac_light` | Lighting time: well-lit |
| `bot_attack_aimpenalty_time_frac_dark` | Lighting time: dark |

### Suppression

| ConVar | Purpose |
|--------|---------|
| `ins_bot_suppress_visible_requirement` | Max time-since-seen to suppress |
| `ins_bot_suppressing_fire_duration` | Max suppression fire duration |

### Recoil & Misc

| ConVar | Purpose |
|--------|---------|
| `bot_recoil_multiplier` | Engine-side recoil scaling for bots (default "0") |
| `ins_bot_knives_only` | Force melee weapons |
| `ins_bot_pistols_only` | Force pistol weapons |
| `mp_coop_ai_teammates` | Enable AI teammates in coop |

---

## Key Function Address Table

| Address | Function | Role |
|---------|----------|------|
| 0x0075AE70 | `FireWeaponAtEnemy` | Master fire control gate |
| 0x0075EE60 | `FireActiveWeapon` | Burst timing + trigger press |
| 0x0076EA60 | `GetAttackDelay` | Reaction time computation |
| 0x0075AA50 | `GetAimToleranceBloat` | Aim cone scaling |
| 0x0076F3F0 | `GetTargetNoise` | Per-axis aim jitter |
| 0x0075B9D0 | `ApplyAimPenalty` | Sustained-fire drift |
| 0x0075A510 | `GetSuppressingOffset` | Blind-fire offset |
| 0x0074A800 | `ShouldSuppressThreat` | Suppression decision |
| 0x0075F330 | `CanIAttack` | Generic attack precondition |
| 0x00734560 | `CanActiveWeaponFire` | Weapon-specific fire check |
| 0x0075E150 | `GetMaxAttackRange` | Max effective range |
| 0x0075E310 | `GetDesiredAttackRange` | Preferred engagement range |
| 0x0075E920 | `GetMaxHipFireAttackRange` | Max hipfire range |
| 0x007049C0 | `CINSBotAttack::InitialContainedAction` | Weapon class dispatch |
| 0x007342A0 | `CINSNextBot::OnWeaponFired` | Entity-level fire event |
