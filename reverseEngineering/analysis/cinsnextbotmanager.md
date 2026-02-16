# CINSNextBotManager — Complete Deep-Dive Analysis

Source: `server_srv.so` (Insurgency 2014, x86-32, unstripped)
File: `reverseEngineering/decompiled/CINSNextBotManager.c` — 3443 lines, 43 functions

CINSNextBotManager extends `NextBotManager` and serves as the global singleton
coordinator for all bot AI. It owns team combat state, reinforcement cooldowns,
grenade tracking, objective selection, weapon-fire intel propagation, order
distribution, and per-control-point tactical timers. The singleton pointer
is stored at GOT symbol `INSNextBotManager`.

---

## Class Hierarchy & Interfaces

```
NextBotManager              (Source Engine base — bot collection, iteration, Update)
  └── CINSNextBotManager    (Insurgency-specific coordination)
        implements IGameEventListener2  (vtable at +0x50)
```

The class has two vtable pointers:
- `+0x00`: CINSNextBotManager vtable (main)
- `+0x50`: IGameEventListener2 vtable (for FireGameEvent)

---

## Object Layout (verified from constructor + all accessors)

### Inherited / Base Fields

| Offset | Type | Field | Source |
|--------|------|-------|--------|
| 0x00 | ptr | vtable (main) | Constructor |
| 0x04 | ptr | m_registeredBots.data | NextBotManager linked list storage |
| 0x10 | uint16 | m_registeredBots.head | Linked list head index (0xFFFF = empty) |
| 0x50 | ptr | vtable (IGameEventListener2) | Constructor |
| 0x54 | int | m_eventListenerPad | Set to 0xD in destructor |
| 0x58 | bool | m_bListenerActive | Set to 1 in Init(), 0 in destructor |

### Grenade Tracking

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x5C | 4 | ptr | m_activeGrenades.data | CUtlVector<CINSActiveGrenade*> |
| 0x60 | 4 | int | m_activeGrenades.alloc | Allocation count |
| 0x64 | 4 | int | m_activeGrenades.capacity | Allocated capacity |
| 0x68 | 4 | int | m_activeGrenades.count | Active grenade count |
| 0x6C | 4 | int | m_activeGrenades.tail | CUtlVector tail |
| 0x70 | 4 | ptr | m_thrownGrenades.data | CUtlVector<CHandle<CBaseEntity>> |
| 0x74 | 4 | int | m_thrownGrenades.alloc | |
| 0x78 | 4 | int | m_thrownGrenades.capacity | |
| 0x7C | 4 | int | m_thrownGrenades.count | Thrown grenade count |
| 0x80 | 4 | int | m_thrownGrenades.tail | |

### CINSActiveGrenade Object (0x1C = 28 bytes, heap-allocated)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00 | float | pos.x | From entity +0x208 (abs origin) |
| 0x04 | float | pos.y | |
| 0x08 | float | pos.z | |
| 0x0C | float | fuseEndTime | Entity +0x4AC + gpGlobals->curtime |
| 0x10 | float | _unused | Hardcoded 180.0f |
| 0x14 | float | effectEndTime | Entity +0x4B0 + gpGlobals->curtime |
| 0x18 | float | damageRadius | From CBaseDetonator::GetDetonateDamageRadius() |

Cleanup in `UpdateGrenades()`: removed when both `+0x14` and `+0x0C` have elapsed
relative to `gpGlobals->curtime`.

### Timers (CountdownTimer = 12 bytes: vtable ptr + duration float + timestamp float)

| Offset | Timer | Interval | Purpose |
|--------|-------|----------|---------|
| 0x98-0xA0 | timer_0 | `ins_bot_grenade_think_time` ConVar | Grenade think (UpdateGrenades + UpdateGrenadeTargets) |
| 0xA4-0xAC | timer_1 | 0.25s | Survival cache/CP tracking |
| 0xB0-0xB8 | timer_2 | 0.5s | Team combat bot counting |
| 0xC8-0xD0 | timer_3 | GetCallForReinforcementCooldown() | Team 2 (Security) reinforcement cooldown |
| 0xD4-0xDC | timer_4 | GetCallForReinforcementCooldown() | Team 3 (Insurgent) reinforcement cooldown |
| 0x110-0x118 | timer_5 | 0.25s | Grenade target proximity update |
| 0x11C-0x124 | timer_6 | RandomFloat(1.0, 8.0) | Idle chatter dispatch |

### Combat State

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0xBC | int | m_lastCPIndex | Last known active CP index for Survival tracking |
| 0xC0 | int | m_securityCombatCount | Team 2 bots currently in combat (updated every 0.5s) |
| 0xC4 | int | m_insurgentCombatCount | Team 3 bots currently in combat (updated every 0.5s) |

### Grenade Targets (2 teams × CUtlVector<CINSGrenadeTarget*>)

| Offset | Type | Field |
|--------|------|-------|
| 0xE0-0xF3 | CUtlVector | Grenade targets — computed from `param_1 + 0xE0 + (team!=2)*0x14` |
| 0xE8 | ptr | Team 2 (Security) grenade target vector data |
| 0xFC | ptr | Team 3 (Insurgent) grenade target vector data |

`GetGrenadeTargets(team)` returns: `this + 0xE8 + (team!=2)*0x14`

### Per-CP Timers

| Offset | Formula | Notes |
|--------|---------|-------|
| 0x120 + cp*0x30 + side*0xC | `cp * 0x30 + 0x120 + side * 0xC + this` | 17 CPs × 4 timers each (2 sides × 2 timers) |

Each timer is a 12-byte CountdownTimer. The constructor loop runs from index
`0x4B` through `0x117` (int indices), initializing 4 timers per iteration in
nested loops: outer loop counts CPs, inner loop counts 4 timers per CP.

Total: 17 × 4 = 68 per-CP timers. Used by `GenerateCPGrenadeTargets()` with
a 40-second cooldown per CP per team.

### Flags

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x128 | bool | m_bNavForceLoaded | Prevents repeated NavMesh force-load attempts |
| 0x129 | bool | m_bUseLightVision | Map supports light-based vision calculations |

### Unknown Constructor Fields

| Offset | Value | Notes |
|--------|-------|-------|
| [0x15] = 0x54 | 0x2A (42) | Possibly max bot count or ID constant |
| [0x38] = 0xE0 | 1.0f | Possibly defend/attack ratio weight |
| [0x39] = 0xE4 | 1 | Unknown flag |
| [0x4A] = 0x128 | 0 → bool | m_bNavForceLoaded (confirmed) |

---

## VTable Virtuals Used on Individual Bots

The manager calls these virtual offsets on `CINSNextBot` instances:

| VTable Offset | Likely Function | Called From |
|---------------|----------------|-------------|
| +0x5C | OnWeaponFired(firer, weapon) | OnWeaponFired — notify bot of enemy gunfire |
| +0x74 | CommandAttack(entity) | CommandAttack — order bot to attack target |
| +0x78 | CommandApproach(pos, radius) | CommandApproach — order bot to move to position |
| +0x98 | OnPointContested(cpIndex) | OnPointContested — defensive alert |
| +0x9C | OnObjectiveChanged(cpIndex) | OnPointCaptured — general notification to all bots |
| +0xA0 | OnPointCaptured(cpIndex) | OnPointCaptured — team-specific celebration/advance |
| +0xB4 | AcknowledgeOrder() | IssueOrder — confirm receipt of radial command |
| +0xC8 | GetEntity() | Various — resolve bot's CBaseEntity |
| +0xD0 | GetGroundEntity() | Combat counting — check if entity is valid ground entity |
| +0xDC | GetBodyInterface() | OnEnemySight — access body for aim control |
| +0x118 | IsAlive() | All iteration loops — filter dead bots |
| +0x134 | GetRangeTo(position) | OnEnemySight — distance check to enemy |
| +0x158 | IsPlayer() | IsAllBotTeam, idle chatter — player type check |
| +0x170 | IsWeapon() | OnWeaponFired — validate weapon entity |
| +0x200 | virtual (200) | Combat counting — resolve entity |
| +0x20C | EyePosition(out) | OnWeaponFired — get eye position for trace |
| +0x260 | WorldSpaceCenter() | OnWeaponFired — get world center for distance check |
| +0x444 | IsLineOfSightClear(pos) | OnWeaponFired — LoS check for notification |
| +0x43C | IsInFieldOfView(pos) | OnWeaponFired — FoV check for notification |
| +0x5F0 | GetWeaponType() | OnWeaponFired — weapon class for hearing distance |
| +0x760 | HasSilencer() | OnWeaponFired — silencer check for distance reduction |
| +0x7B0 | IsBot() | IsAllBotTeam, idle chatter — distinguish bots from humans |
| +0x978 | GetChatter() | Idle chatter — access CINSBotChatter |

---

## Function-by-Function Analysis

### 1. Constructor (0x00764EE0)

```
CINSNextBotManager::CINSNextBotManager()
```

1. Calls `NextBotManager::NextBotManager()` (parent)
2. Sets both vtable pointers (main at +0x00, event listener at +0x14 = +0x50)
3. Zeroes out grenade vectors and all intermediate fields ([0x16]-[0x25])
4. Initializes 7 named timers (timer_0 through timer_6) to -1.0f (not running)
5. Initializes 68 per-CP timers in a nested loop (17 CPs × 4 timers)
6. Stores singleton pointer: `INSNextBotManager = this`
7. Explicitly resets timer_0, timer_1, timer_5 to -1.0f (redundant safety)
8. Sets `[0x4a] = 0` (m_bNavForceLoaded), `[0x129] = 0` (m_bUseLightVision)
9. Sets `[0x38] = 1.0f`, `[0x39] = 1`

### 2. Update (0x00766690)

The main per-tick think function. Returns immediately if `CINSRules::IsGameState()`
is false (game not in active state).

**Subsystem 1 — Grenade think** (timer_0):
```
if timer_0.IsElapsed():
    UpdateGrenades()           // clean up expired grenade tracking
    UpdateGrenadeTargets()     // update proximity checks, debug viz
    timer_0.Start(ins_bot_grenade_think_time->GetFloat())
```

**Subsystem 2 — Idle chatter** (timer_6, skipped in Survival):
```
if timer_6.IsElapsed() AND NOT IsSurvival():
    for each player index 1..maxClients:
        if IsBot() AND IsAlive() AND IsCoopBot():
            cast to CINSNextBot
            if (+0xb448 != 0 OR nb_blind != 0) AND +0x2290 != 0:
                add to eligible list
    if eligible.count > 0:
        pick = RandomInt(0, eligible.count - 1)
        eligible[pick]->GetChatter()->IdleChatter()
    timer_6.Start(RandomFloat(1.0, 8.0))
```

The `+0xb448` check is "has enemy knowledge" and `+0x2290` is the "is escorting/active" flag.

**Subsystem 3 — Survival cache tracking** (timer_1, 0.25s):
```
if timer_1.IsElapsed() AND IsSurvival():
    cpIndex = g_pObjectiveResource->+0x770    // active push CP
    if cpIndex != -1 AND cpIndex != m_lastCPIndex:
        position = g_pObjectiveResource->+0x5D0 + cp * 0xC
        m_lastCPIndex = cpIndex
        CINSRules::GetBotTeam()
        GenerateCPGrenadeTargets(cpIndex)
        for each registered bot (linked list iteration):
            CINSNextBotSurvivalCacheNotify::operator()(bot)
    timer_1.Start(0.25)
```

The linked list iteration uses `ushort` indices at `+0x10` (head) and
`bot_data + 6 + index * 8` (next), terminating at `0xFFFF`.

**Subsystem 4 — Team combat counting** (timer_2, 0.5s):
```
if timer_2.IsElapsed():
    m_securityCombatCount = 0    // +0xC0
    m_insurgentCombatCount = 0   // +0xC4
    CollectAllBots(botList)
    for each bot in botList:
        entity = bot->GetEntity()
        if entity AND entity->IsAlive():
            ground = entity->GetGroundEntity()   // vfunc +0xD0
            if ground AND ground->vfunc_0x3C():  // some validity check
                team = GetTeamNumber()
                if team == 2: m_securityCombatCount++
                if team == 3: m_insurgentCombatCount++
    timer_2.Start(0.5)
```

The combat check chain `+0xDC` → `+0xD0` → `+0x3C` likely resolves through
`GetBaseAnimating()` → `GetGroundEntity()` → some validity predicate. This
determines if bots are actively engaged (not just alive).

Finally calls `NextBotManager::Update()` (parent).

### 3. OnKilled (0x007615F0)

Pure delegation: `NextBotManager::OnKilled(combatCharacter, damageInfo)`.
No INS-specific logic.

### 4. OnWeaponFired (0x00764230)

**The weapon fire intel propagation system.** This is the most complex function
in the manager (232 lines of decompilation).

```
OnWeaponFired(CBaseCombatCharacter* firer, CBaseCombatWeapon* weapon):
    CollectAllBots(botList)

    // Validate weapon
    insWeapon = weapon->IsWeapon() ? weapon : NULL
    if insWeapon == NULL OR firer == NULL: return

    // Compute hearing distance by weapon type
    weaponType = insWeapon->GetWeaponType()    // vfunc +0x5F0
    if (weaponType - 8) < 7:
        hearingDistance = CSWTCH.989[weaponType - 8]    // lookup table
    else: return

    // Silencer reduction
    if insWeapon->HasSilencer():    // vfunc +0x760
        hearingDistance *= ins_bot_silenced_weapon_sound_reduction->GetFloat()

    // Get fire direction from firer's eye vectors
    firer->EyeVectors(&fireDir, NULL, NULL)

    for each bot in botList:
        if bot == NULL OR bot->GetEntity() == NULL OR !IsAlive(): continue

        // Compute trace from firer's eye along fire direction (16384 units)
        firerEye = firer->EyePosition()
        traceEnd = firerEye + fireDir * 16384.0

        // Ray trace with mask 0x600400B
        CTraceFilterSimple filter(firer)
        enginetrace->TraceRay(ray, 0x600400B, &filter, &result)

        // Distance from trace hit to bot's eye
        botEye = bot->EyePosition()
        hitToBotDist = Distance(result.endpos, botEye)

        // Distance from firer's center to bot's eye
        firerCenter = firer->WorldSpaceCenter()
        firerToBotDist = Distance(firerCenter, botEye)

        // Notification logic
        if bot->IsLineOfSightClear(result.endpos):
            if bot->IsInFieldOfView(result.endpos) OR hitToBotDist < 250.0:
                // Bot can see the impact point
                if GetTeamNumber(bot) != GetTeamNumber(firer):
                    bot->vfunc_0x5C(firer, weapon)    // notify
                continue

        if hitToBotDist < 100.0:
            // Very close to impact — always notify regardless of LoS
            if GetTeamNumber(bot) != GetTeamNumber(firer):
                bot->vfunc_0x5C(firer, weapon)
            continue

        if firerToBotDist <= hearingDistance:
            // Within hearing distance of the firer
            if GetTeamNumber(bot) != GetTeamNumber(firer):
                bot->vfunc_0x5C(firer, weapon)

    // Debug output
    if developer flag set:
        DevMsg("%3.2f: OnWeaponFired( %s, %s )")
```

**CSWTCH.989 weapon hearing distance table** (7 entries for weapon types 8-14):

| Index | Weapon Type | Likely Class |
|-------|------------|-------------|
| 0 | 8 | Shotgun |
| 1 | 9 | SMG |
| 2 | 10 | Rifle |
| 3 | 11 | Carbine |
| 4 | 12 | LMG |
| 5 | 13 | Sniper |
| 6 | 14 | DMR |

The actual distance values are in the rodata section at `CSWTCH.989`. Each is a float
multiplied by the silencer reduction if applicable.

**Trace mask `0x600400B`:**
- `CONTENTS_SOLID` (0x1)
- `CONTENTS_WINDOW` (0x2)
- `CONTENTS_MOVEABLE` (0x8)
- `CONTENTS_HITBOX` (0x4000000)
- `CONTENTS_OPAQUE` (0x40)
- Plus engine-specific bits

### 5. OnEnemySight (0x007617E0)

```
OnEnemySight(CINSNextBot* spotter, CBaseEntity* enemy):
    for each registered bot (linked list, head at spotter+0x10):
        entity = bot->GetEntity()
        if !entity->IsAlive(): continue

        spotterTeam = GetTeamNumber(spotter's entity)
        botTeam = GetTeamNumber(bot's entity)
        if spotterTeam != botTeam: continue    // same team only

        dist = bot->GetRangeTo(enemy->GetAbsOrigin())    // vfunc +0x134

        threshold = ConVar_at_0x45969->GetFloat()    // ins_bot_enemy_seen_notify_distance
        if dist < threshold:
            bodyInterface = bot->GetBodyInterface()    // vfunc +0xDC
            bodyInterface->AimHeadToward(enemy->position)    // vfunc +0xE8
```

This uses the manager's linked list (not CollectAllBots), iterating via
`ushort` indices stored in the bot storage array.

### 6. AddGrenadeTarget (0x00765CC0)

```
AddGrenadeTarget(int team, CINSGrenadeTarget* target):
    if target == NULL: return 0
    if (team - 2) > 1:
        Warning("Tried adding grenade target for invalid team %i")
        delete target
        return 0

    vectorOffset = this + 0xE0 + (team != 2) * 0x14

    // Duplicate check: reject if within 2× existing target's radius
    for each existing in vector:
        if existing != NULL:
            dist = Distance(target->pos, existing->pos)
            if dist < existing->radius * 2:
                delete target
                return 0

    vector.InsertBefore(vector.Count(), target)
    return 1
```

### 7. AreBotsOnTeamInCombat (0x007628B0)

```
AreBotsOnTeamInCombat(int team):
    if team == 2: return m_securityCombatCount > 0     // +0xC0
    if team == 3: return m_insurgentCombatCount > 0    // +0xC4
    return 0
```

### 8. BotAddCommand (0x00762790)

Validates NavMesh before allowing bot addition:
```
BotAddCommand():
    if NavMeshExists():
        navData = TheNavMesh->data
        if navData->+0x38 == 0:    // not loaded
            Warning("NavMesh exists but not currently loaded")
            if !m_bNavForceLoaded:
                m_bNavForceLoaded = true
                Warning("Forcing a load...")
                result = navData->vfunc_0x28()    // Load()
                if result == 4 OR result == 0:
                    Msg("Successfully loaded NavMesh on demand, restarting game")
                    mp_restartgame->SetValue(1)    // trigger restart
                    return false
                else:
                    Warning("Failed loading navmesh!")
                    return false
            return false
        else:
            return navData->+0x514 == 0    // not in edit mode
    else:
        Warning("NavMesh does not exist")
        return false
```

### 9. CallForReinforcements (0x00762A90)

```
CallForReinforcements(int team):
    if g_pGameRules == NULL: return
    cooldown = GetCallForReinforcementCooldown()
    if team == 2:
        timer_3.Start(cooldown)    // +0xC8
    elif team == 3:
        timer_4.Start(cooldown)    // +0xD4
```

### 10. CanCallForReinforcements (0x007628F0)

```
CanCallForReinforcements(int team):
    if g_pGameRules == NULL: return false

    // Check cooldown timer
    if team == 2 AND !timer_3.IsElapsed(): return false
    if team == 3 AND !timer_4.IsElapsed(): return false

    // In Survival: also blocked if team is in combat
    if IsSurvival():
        if team == 2: return m_securityCombatCount < 1
        if team == 3: return m_insurgentCombatCount < 1

    return true
```

### 11. CommandApproach (0x00764950)

```
CommandApproach(int team, float x, float y, float z, ?, float radius):
    CollectAllBots(botList)
    for each bot:
        entity = bot->GetEntity()
        if !IsAlive(): continue
        if GetTeamNumber() != team: continue
        botPos = entity->GetAbsOrigin()    // vfunc +0xE4
        if Distance(botPos, {x,y,z}) <= radius:
            bot->CommandApproach({x,y,z}, radius)    // vfunc +0x78
```

### 12. CommandAttack (0x00764B00)

```
CommandAttack(int team, CBaseEntity* target):
    CollectAllBots(botList)
    for each bot:
        if !IsAlive(): continue
        if GetTeamNumber() != team: continue
        bot->CommandAttack(target)    // vfunc +0x74
```

### 13-14. FireGameEvent (0x00761AB0 thunk, 0x00761AC0 real)

The thunk adjusts `this` by `-0x50` (from IGameEventListener2 interface to main object).

```
FireGameEvent(IGameEvent* event):
    eventID = event->GetID()    // vfunc +0x1C
    if eventID == -1: return

    player = UTIL_PlayerByUserId(event->GetInt("userid"))
    if player == NULL OR !player->IsPlayer(): player = NULL

    switch eventID:
        case 0x45 (69):    // player_shoot / weapon_fire
            weapon = CINSPlayer::GetActiveINSWeapon(player)
            this->vfunc_0x28(player, weapon)    // → OnWeaponFired

        case 0x6D (109):   // grenade_pickup
            entityID = event->GetInt("entityid")
            entity = LookupEntity(entityID)
            if entity: this->vfunc_0x30(entity)    // → OnGrenadePickup

        case 0x6E (110):   // grenade_throw
            entityID = event->GetInt("entityid")
            entity = LookupEntity(entityID)
            if entity: this->vfunc_0x34(entity)    // → OnGrenadeThrown

        case 0x79 (121):   // controlpoint_captured
            cpIndex = event->GetInt(?)
            currentOwner = g_pObjectiveResource->+0x490 + cp*4
            team1 = event->GetInt(?)
            team2 = event->GetInt(?)
            this->vfunc_0x3C(team2, team1, currentOwner)    // → OnPointCaptured

        case 0x7C (124):   // objective_event
            val1 = event->GetInt(?)
            val2 = event->GetInt(?)
            this->vfunc_0x40(val2, val1)
```

Entity lookup uses `gpGlobals->pEdicts` array: validates serial number bits
and non-null entity pointer at `edict + 0xC`.

### 15. GenerateCPGrenadeTargets (0x00765DF0)

```
GenerateCPGrenadeTargets(int cpIndex):
    if cpIndex < 0:
        DevWarning("invalid control point index")
        return

    // Per-CP cooldown check (formula: cp*0x30 + 0x120 + side*0xC + this)
    timerOffset = cpIndex * 0x30 + 0x120 + side * 0xC + this
    if !timer_at(timerOffset).IsElapsed(): return
    timer_at(timerOffset).Start(40.0)    // 40-second cooldown

    // ATTACK nav areas (NavMesh offset 0x974 + cp * 0x14)
    attackAreas = TheNavMesh->data + 0x974 + cpIndex * 0x14
    if attackAreas:
        localCopy = copy_to_vector(attackAreas)
        Fisher-Yates shuffle(localCopy)
        for each area in localCopy:
            if area != NULL:
                repeat 4 times:
                    point = area->GetRandomPoint()
                    target = new CINSGrenadeTarget(0x24 bytes)
                    target->type = 2        // attack type
                    target->radius = 250.0
                    target->timer.Start(40.0)
                    target->clear = false
                    target->used = false
                    target->pos = point
                    AddGrenadeTarget(team, target)

    // DEFEND nav areas (NavMesh offset 0x834 + cp * 0x14)
    defendAreas = TheNavMesh->data + 0x834 + cpIndex * 0x14
    if defendAreas:
        localCopy = copy_to_vector(defendAreas)
        Fisher-Yates shuffle(localCopy)
        for each area in localCopy:
            if area != NULL:
                repeat 4 times:
                    point = area->GetRandomPoint()
                    target = new CINSGrenadeTarget(0x24 bytes)
                    target->type = 9        // defend type
                    target->radius = 220.0
                    target->timer.Start(40.0)
                    target->clear = false
                    target->used = false
                    target->pos = point
                    AddGrenadeTarget(team, target)
```

### 16-17. GetActiveGrenade (0x00762FC0) / GetTotalActiveGrenades (0x00762FB0)

Bounds-checked array accessor: `m_activeGrenades[index]` if valid, else 0.
Count accessor: returns `*(this + 0x68)`.

### 18. GetAverageDirectionToPlayersOnTeam (0x00762CF0)

```
GetAverageDirectionToPlayersOnTeam(Vector origin, int team) → Vector:
    sumPos = {0, 0, 0}
    count = 0
    for playerIndex = 1 to 48 (0x31):    // max 48 players
        player = UTIL_PlayerByIndex(playerIndex)
        if player == NULL OR !IsPlayer() OR !IsAlive(): continue
        if player->GetTeamID() != team: continue
        player->CalcAbsolutePosition()
        sumPos += player->absOrigin    // at +0x208, +0x20C, +0x210
        count++

    avg = sumPos / count
    result = avg - origin
    VectorNormalize(result)
    return result
```

### 19. GetCallForReinforcementCooldown (0x007629F0)

```
GetCallForReinforcementCooldown() → float:
    if g_pGameRules == NULL: return 0.0
    if !IsSurvival():
        return 10.0
    else:
        base = RandomFloat(40.0, 50.0)
        waveCount = g_pGameRules->+0x3E8 (offset 1000)    // survival wave count
        scaling = CSWTCH.989[0x24/4]    // scaling factor from same lookup table area
        return base + (-10.0 - (waveCount - 1.0) * scaling)
```

Later survival waves get progressively shorter cooldowns.

### 20-25. Objective Selection Functions

**GetDesiredPushTypeObjective** (0x00762450):
Simple: validates Push/Invasion/Checkpoint/Conquer mode, returns `g_pObjectiveResource->+0x770`.

**GetDesiredSkirmishObjective** (0x00761E40):
Complex frontline analysis. For Security (team 2): searches forward for enemy-owned CP.
For Insurgents (team 3): searches backward. Uses `HasExplosive()` to adjust default
objective (4 for Security, 0 for Insurgents). When losing, picks frontline. Uses
`RandomInt(0,1)` for tiebreaking. Fallback for 5 CPs returns 2, for 3 CPs returns 1 or 2.

**GetDesiredBattleTypeObjective** (0x007621A0):
Counts owned/enemy/neutral/contested CPs. If 1 enemy-owned and no contested/neutral,
returns that CP. If 1 contested + 1 owned, returns contested. Falls back to
direction-based offset (+1 or -1 based on team).

**GetDesiredHuntTypeObjective** (0x00762710):
Returns first CP where status (`+0x6F0 + cp*4`) is not 1 (not destroyed).
Falls back to -1 with "Failed to load active Hunt objective" warning.

**GetDesiredOccupyTypeObjective** (0x007624F0):
Finds closest unowned CP to bot. Uses `RandomInt(0,1)` to sometimes pick second-closest
instead. CP positions from `g_pObjectiveResource->+0x5D0 + cp*0xC`.

**GetDesiredStrongholdTypeObjective** (0x00765790):
For attackers: finds closest CP where attacking team has access but defending team owns it.
For defenders: builds a defend list of CPs where the bot's team is defending.
Uses `FLT_MAX` as initial distance sentinel. Queries `GetAttackingTeam()` and
`GetDefendingTeam()` from game rules.

### 26. GetGrenadeTargets (0x007636C0)

```
GetGrenadeTargets(int team) → CUtlVector*:
    if (team - 2) < 2:
        return this + 0xE8 + (team != 2) * 0x14
    return NULL
```

### 27-28. GetThrownGrenade (0x00763010) / GetTotalThrownGrenades (0x00763000)

Thrown grenade handle accessor. Returns `0xFFFFFFFF` (invalid handle) if out of bounds.
Count accessor: returns `*(this + 0x7C)`.

### 29. Init (0x00766EF0)

Registers for 7 game events via `gameeventmanager->AddListener()`:

| Event ID | Decimal | Likely Event |
|----------|---------|-------------|
| 0x45 | 69 | weapon_fire / player_shoot |
| 0x79 | 121 | controlpoint_captured |
| 0x7C | 124 | objective_event |
| 0x6D | 109 | grenade_pickup |
| 0x6E | 110 | grenade_throw |
| 0x6F | 111 | grenade_detonate |
| 0x70 | 112 | grenade_explode |

Sets `+0x58 = 1` (listener active) before each registration.

### 30. IsAllBotTeam (0x00762C30)

```
IsAllBotTeam(int team) → bool:
    teamObj = GetGlobalTeam(team)
    if teamObj == NULL: return false
    memberCount = teamObj->GetNumPlayers()    // vfunc +0x348
    for i = 0 to memberCount-1:
        member = teamObj->GetPlayer(i)    // vfunc +0x34C
        if member AND member->IsPlayer():
            if !member->IsBot():
                return false    // found a human
    return memberCount != 0    // true only if team has members
```

### 31. IssueOrder (0x00764090)

```
IssueOrder(int team, eRadialCommands cmd, int ?, Vector pos, OrderPriority priority, int ?, float ?):
    CollectAllBots(botList)
    for each bot:
        if !IsAlive(): continue
        entity = bot->GetEntity()
        if GetTeamNumber() != team: continue
        if entity == NULL: continue
        insBot = entity - 0x2060    // cast offset to CINSNextBot from CBaseEntity
        if insBot == NULL: continue
        insBot->AddOrder(cmd, ?, pos, priority, ?, ?)
        bot->vfunc_0xB4()    // AcknowledgeOrder
```

The `- 0x2060` offset is the reverse of the CINSNextBot→CBaseEntity inheritance
offset, converting from entity pointer back to bot pointer.

### 32. OnGrenadeDetonate (0x00765BB0)

```
OnGrenadeDetonate(CBaseDetonator* grenade):
    if grenade == NULL:
        Warning("grenade == NULL")
        return
    active = new CINSActiveGrenade(0x1C bytes)
    active->pos = grenade->GetAbsOrigin()    // +0x208
    active->fuseEndTime = grenade->+0x4AC + gpGlobals->curtime
    active->const180 = 180.0f
    active->effectEndTime = grenade->+0x4B0 + gpGlobals->curtime
    active->damageRadius = grenade->GetDetonateDamageRadius()
    m_activeGrenades.InsertBefore(count, active)
```

### 33. OnGrenadeThrown (0x00765B30)

```
OnGrenadeThrown(CBaseDetonator* grenade):
    if grenade == NULL:
        Warning("NULL grenade thrown?")
        return
    handle = grenade->GetRefEHandle()    // vfunc +0xC
    m_thrownGrenades.InsertBefore(count, handle)
```

### 34. OnMapLoaded (0x00761920)

```
OnMapLoaded():
    NextBotManager::OnMapLoaded()    // parent
    timer_0.Start(ins_bot_grenade_think_time)
    timer_5.Reset(-1.0)    // not running
    CINSBotGuardCP::ResetHidingSpots()    // clear cached guard positions
    m_bNavForceLoaded = false

    mapName = gpGlobals->+0x3C    // map name string
    mapRef = CMapDatabase::GetMapDatabaseReference(mapName)
    mapItem = CMapDatabase::GetMapDatabaseItem(mapRef)
    if mapItem:
        if mapItem->+0xBA0:    // has light data
            m_bUseLightVision = true
            DevMsg("Using light calculation for NextBot vision.")
        else:
            m_bUseLightVision = false
            DevMsg("Not using light calculation for NextBot vision.")
```

### 35. OnPointCaptured (0x00764D70)

```
OnPointCaptured(int cpIndex, int ?, int capturingTeam):
    CollectAllBots(botList)
    for each bot:
        if !IsAlive(): continue
        bot->vfunc_0x9C(cpIndex)    // OnObjectiveChanged — all alive bots

        if GetTeamNumber(bot) == capturingTeam:
            bot->vfunc_0xA0(cpIndex)    // OnPointCaptured — capturing team only
```

### 36. OnPointContested (0x00764C40)

```
OnPointContested(int cpIndex, int contestingTeam):
    currentOwner = g_pObjectiveResource->+0x490 + cpIndex * 4
    if contestingTeam == currentOwner: return    // own team contesting = no alert

    CollectAllBots(botList)
    for each bot:
        if !IsAlive(): continue
        bot->vfunc_0x98(cpIndex)    // OnPointContested — defensive alert
```

### 37. OnRoundRestart (0x00761630)

```
OnRoundRestart():
    NextBotManager::OnRoundRestart()

    // Free all active grenades
    for i = 0 to m_activeGrenades.count - 1:
        delete m_activeGrenades[i]
    m_activeGrenades.RemoveAll()

    // Clear thrown grenades
    m_thrownGrenades.count = 0

    // Clear grenade targets for both teams
    for team = 0 to 1:
        vector = this + 0xE0 + team * 0x14
        for i = 0 to vector.count - 1:
            delete vector[i]
        vector.RemoveAll()

    // Reset all per-CP timers (17 CPs × 4 timers)
    for cp = 0 to 16:
        for timer = 0 to 3:
            offset = cp * 0x30 + 0x120 + timer * 0xC + this
            timer_at(offset).Reset(-1.0)
```

### 38. UpdateGrenadeTargets (0x00763050)

Two phases:

**Phase 1 — Debug visualization** (if `ins_debug_grenade_targets` != 0):
For each target in both team vectors, displays:
- Text overlay with type flags (FRAG/FLASH/SMOKE/INCENDIARY), clear/used status
- Circle overlay at target position with target radius
- Color: green (0,255,0) if unused, red (255,0,0) if used

**Phase 2 — Target maintenance** (timer_5, 0.25s):
```
for team = 0 to 1:
    vector = team grenade targets
    // Remove expired/null targets (iterate in reverse)
    for i = count-1 downto 0:
        target = vector[i]
        if target == NULL: remove(i)
        elif target->timer.IsElapsed():
            delete target
            remove(i)

    // Update "clear" flag for surviving unused targets
    for each target where target->used == false:
        isClear = true
        for playerIndex = 1 to maxClients:
            player = UTIL_PlayerByIndex(playerIndex)
            if player AND IsAlive():
                enemyTeam = 3 - (team == 0)    // opposite team
                if GetTeamNumber() == enemyTeam:
                    dist = Distance(player->EyePosition(), target->pos)
                    if dist <= target->radius + 32.0:
                        isClear = false
                        break
        target->clear = isClear
```

### 39. UpdateGrenades (0x00762E30)

```
UpdateGrenades():
    // Clean active grenades (reverse iteration)
    for i = count-1 downto 0:
        grenade = m_activeGrenades[i]
        if grenade != NULL:
            curtime = gpGlobals->curtime
            if grenade->effectEndTime <= curtime AND grenade->fuseEndTime <= curtime:
                delete grenade
                remove(i)

    // Clean thrown grenades (reverse iteration, handle validation)
    for i = count-1 downto 0:
        handle = m_thrownGrenades[i]
        if handle == 0xFFFFFFFF: remove(i); continue

        // Validate entity handle via g_pEntityList
        slot = (handle & 0xFFFF) * 0x18 + g_pEntityList->data
        if slot->serialNumber != (handle >> 16): remove(i); continue
        if slot->entityPtr == NULL: remove(i); continue
```

### 40-43. Destructors

Four variants: two non-virtual thunks, one non-deleting, one deleting.

The real destructor (0x00765440):
1. Resets vtable pointers to base class versions
2. Clears `INSNextBotManager` and `NextBotManager::sInstance` to NULL
3. Frees both teams' grenade target vectors (2 iterations, freeing each target + vector memory)
4. Frees active grenades vector
5. Frees thrown grenades vector
6. Unregisters from `gameeventmanager` if `+0x58` (listener active) is set
7. Resets IGameEventListener2 vtable
8. Calls `NextBotManager::~NextBotManager()`

The deleting destructor (0x00765750) also calls `operator_delete(this)`.

---

## Global References

| Symbol | GOT Offset | Purpose |
|--------|-----------|---------|
| INSNextBotManager | 0x58cad1 (rel EBX) | Singleton pointer, set in constructor |
| g_pGameRules | 0x44025d (rel EBX) | CINSRules singleton |
| g_pObjectiveResource | 0x440681 (rel EBX) | Objective state (CP ownership, positions, active CP) |
| TheNavMesh | 0x443f1a (rel EBX) | Navigation mesh |
| gpGlobals | varies | Server globals (curtime, maxClients, map name) |
| enginetrace | 0x442537 (rel EBX) | Ray tracing interface |
| gameeventmanager | 0x43ffd5 (rel EBX) | Game event registration |
| g_pEntityList | 0x44399d (rel EBX) | Entity handle validation |
| ins_bot_grenade_think_time | 0x440921 (rel EBX) | ConVar for grenade think interval |
| ins_bot_silenced_weapon_sound_reduction | 0x44281f (rel EBX) | ConVar for silencer hearing reduction |
| ins_debug_grenade_targets | 0x443a8d (rel EBX) | ConVar for grenade target debug viz |
| nb_blind | 0x440195 (rel EBX) | ConVar for blind bots |
| r_visualizetraces | 0x4427ff (rel EBX) | ConVar for trace debug viz |
| NextBotManager::sInstance | 0x441401 (rel EBX) | Parent class singleton |

---

## g_pObjectiveResource Layout (used by this class)

| Offset | Type | Field | Used In |
|--------|------|-------|---------|
| +0x37C | int | m_numControlPoints | All objective functions |
| +0x450 + cp*4 | int | m_attackingTeam[cp] | Skirmish, Stronghold |
| +0x490 + cp*4 | int | m_ownerTeam[cp] | Battle, Skirmish, Stronghold, OnPointContested |
| +0x5D0 + cp*0xC | Vector | m_cpPosition[cp] | Occupy, Stronghold, Survival tracking |
| +0x690 + cp | byte | m_securityFlags[cp] | Stronghold (Security access) |
| +0x6A0 + cp | byte | m_insurgentFlags[cp] | Stronghold (Insurgent access) |
| +0x6F0 + cp*4 | int | m_cpStatus[cp] | Hunt (1 = destroyed) |
| +0x770 | int | m_activePushCP | Push/Checkpoint/Invasion/Conquer objective |

---

## Function Address Table

| Address | Function | Lines |
|---------|----------|-------|
| 0x00764EE0 | Constructor | 15-131 |
| 0x00766690 | Update | 143-406 |
| 0x007615F0 | OnKilled | 417-425 |
| 0x00764230 | OnWeaponFired | 437-671 |
| 0x00765CC0 | AddGrenadeTarget | 682-731 |
| 0x007628B0 | AreBotsOnTeamInCombat | 742-755 |
| 0x00762790 | BotAddCommand | 766-814 |
| 0x00762A90 | CallForReinforcements | 825-864 |
| 0x007628F0 | CanCallForReinforcements | 875-911 |
| 0x00764950 | CommandApproach | 922-985 |
| 0x00764B00 | CommandAttack | 996-1050 |
| 0x00761AB0 | FireGameEvent (thunk) | 1061-1066 |
| 0x00761AC0 | FireGameEvent | 1077-1159 |
| 0x00765DF0 | GenerateCPGrenadeTargets | 1171-1489 |
| 0x00762FC0 | GetActiveGrenade | 1500-1510 |
| 0x00762CF0 | GetAverageDirectionToPlayersOnTeam | 1521-1568 |
| 0x007629F0 | GetCallForReinforcementCooldown | 1579-1603 |
| 0x007621A0 | GetDesiredBattleTypeObjective | 1614-1759 |
| 0x00762710 | GetDesiredHuntTypeObjective | 1770-1803 |
| 0x007624F0 | GetDesiredOccupyTypeObjective | 1814-1903 |
| 0x00762450 | GetDesiredPushTypeObjective | 1914-1942 |
| 0x00761E40 | GetDesiredSkirmishObjective | 1953-2112 |
| 0x00765790 | GetDesiredStrongholdTypeObjective | 2124-2252 |
| 0x007636C0 | GetGrenadeTargets | 2263-2274 |
| 0x00763010 | GetThrownGrenade | 2285-2299 |
| 0x00762FB0 | GetTotalActiveGrenades | 2310-2316 |
| 0x00763000 | GetTotalThrownGrenades | 2327-2333 |
| 0x00766EF0 | Init | 2344-2393 |
| 0x00762C30 | IsAllBotTeam | 2404-2440 |
| 0x00764090 | IssueOrder | 2451-2509 |
| 0x007617E0 | OnEnemySight | 2520-2578 |
| 0x00765BB0 | OnGrenadeDetonate | 2589-2628 |
| 0x00765B30 | OnGrenadeThrown | 2639-2657 |
| 0x00761920 | OnMapLoaded | 2668-2729 |
| 0x00764D70 | OnPointCaptured | 2740-2796 |
| 0x00764C40 | OnPointContested | 2807-2856 |
| 0x00761630 | OnRoundRestart | 2867-2945 |
| 0x00763050 | UpdateGrenadeTargets | 2956-3188 |
| 0x00762E30 | UpdateGrenades | 3199-3271 |
| 0x00765430 | ~Destructor (thunk 1) | 3282-3287 |
| 0x00765440 | ~Destructor (real) | 3298-3403 |
| 0x00765740 | ~Destructor (thunk 2) | 3414-3419 |
| 0x00765750 | ~Destructor (deleting) | 3430-3441 |
