# Verified Bot Behavior — Live Server Observations

Captured from `nb_debug BEHAVIOR EVENTS ERRORS` on a vanilla Insurgency 2014 server
(no SourceMod/MetaMod — original bot AI only).

- **Map**: ministry_coop (Checkpoint mode, full playthrough)
- **Server**: `developer 1`, `sv_cheats 1`
- **Date**: 2026-02-10
- **Duration**: ~1470 seconds (~24 minutes)
- **Total transitions logged**: 1767
- **Bots**: defending team (12) + attacking/security team (15+), ~30 bot entities total

---

## 1. Boot Sequence

All bots initialize identically:
```
START Behavior → START Tactics → START Investigations → START Gamemode → START Checkpoint
```
Full stack: `Behavior( Tactics( Investigations( Gamemode( Checkpoint ) ) ) )`

The four wrapper actions (Behavior, Tactics, Investigations, Gamemode) never change —
all decision-making happens as children/suspensions of `Checkpoint`.

---

## 2. Action Hierarchy (Verified)

```
Behavior                                       [root — never changes]
 │
 │  ┌─ Throwing Grenade                        [SuspendFor Tactics — interrupts everything]
 │  ├─ Firing RPG                              [SuspendFor Tactics — same level as grenade]
 │  ├─ Reloading                               [SuspendFor Tactics — opportunistic reload]
 │  ├─ Retreating to cover                     [SuspendFor Tactics — flee from nade/injury]
 │  └─ Retreating!                             [ChangeTo from failed Retreating to cover]
 │
 └─ Tactics                                    [child — never changes]
     └─ Investigations                         [child — never changes]
         └─ Gamemode                           [child — never changes]
             └─ Checkpoint                     [gamemode root — always present as base]
                 │
                 │  DEFENDING TEAM:
                 ├── Guarding CP               [SuspendFor] hold a position
                 ├── Defensive Guard            [SuspendFor] positional defense
                 ├── Capturing CP               [SuspendFor] counter-attack recapture
                 │
                 │  ATTACKING TEAM:
                 ├── Escort                     [SuspendFor] follow nearest human
                 │
                 │  SHARED:
                 ├── Investigating              [SuspendFor] check disturbance / counter-attack
                 ├── Stuck                      [ChangeTo via OnStuck event]
                 │
                 └── Combat                     [SuspendFor from any above]
                     ├── Attacking              [SuspendFor] has LOS to target
                     │   ├── CINSBotAttackRifle    [child] → AttackInPlace / AttackAdvance
                     │   ├── CINSBotAttackLMG      [child] → AttackInPlace / AttackAdvance
                     │   ├── CINSBotAttackCQC      [child] → AttackAdvance (starts aggressive)
                     │   ├── CINSBotAttackPistol   [child] → AttackAdvance (starts aggressive)
                     │   └── Throwing Grenade      [child] combat grenade (rare, different from Tactics-level)
                     │
                     ├── Pursue Threat          [SuspendFor] chase lost enemy
                     ├── Suppressing            [SuspendFor] suppress recently lost target
                     ├── Retreating!            [SuspendFor] retreat to reload
                     ├── Retreating to cover    [SuspendFor] retreat to cover to reload (rare, combat-level)
                     └── Reloading              [SuspendFor] in-place reload
```

### Key structural findings

**Two levels of Retreating to cover:**
1. **Tactics-level** (most common): triggered by OnInjured ("We're in fire, get out of here!") or
   OnSight ("Fleeing from nade"). Interrupts the entire gamemode stack.
2. **Combat-level** (rare, 1 instance): "Retreating to Cover to Reload" — stays within combat.

**Two levels of Throwing Grenade:**
1. **Tactics-level** (most common): `Tactics → SuspendFor Throwing Grenade` — interrupts everything.
2. **Attacking child** (rare, 2 instances): grenade as the weapon-action child of Attacking.

**Two levels of Reloading:**
1. **Tactics-level**: "Opportunistic reload in-place" — safe moment, no combat.
2. **Combat-level**: "Reloading in place because of escorting or formation" / "Exiting attack to Reload".

**Retreating to cover can nest:**
`Retreating to cover << Retreating to cover << Tactics` — double flee observed when
a second grenade arrives mid-retreat.

### Not yet observed (expected from RE):
- `CINSBotAttackSniper`, `CINSBotAttackMelee`
- `AttackIntoCover`, `AttackFromCover`
- `Flank`, `Hunt`, `Search`
- `Shuttle`, `Assault` (other attacking-team strategies)
- `Use Explosive`

---

## 3. Verified Transitions

### 3.1 Checkpoint (gamemode root)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Checkpoint | SuspendFor | Escort | "Escorting nearest Human" | 689 |
| Checkpoint | SuspendFor | Guarding CP | "Guarding CP." | 240 |
| Checkpoint | SuspendFor | Combat | "Attacking nearby threats" | 181 |
| Checkpoint | SuspendFor | Investigating | "I have an investigation!" | 45 |
| Checkpoint | SuspendFor | Defensive Guard | "Defending." | 14 |
| Checkpoint | SuspendFor | Capturing CP | "It's a counter-attack and we're not hunting, re-cap" | 12 |
| Checkpoint | SuspendFor | Investigating | "Counter-attacking enemy directly" | 3 |

### 3.2 Escort (attacking team)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Escort | SuspendFor | Combat | "Combat time!" | 307 |
| Escort | Done → Resume Checkpoint | — | "Unable to get escort Target" | 610 |

### 3.3 Guarding CP (defending team)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Guarding CP | Done → Resume Checkpoint | — | "Finished guarding spot." | 122 |
| Guarding CP | Done → Resume Checkpoint | — | "LoS to an enemy." | 96 |
| Guarding CP | Done → Resume Checkpoint | — | "Point we were guarding is inactive, relocating to new point." | 3 |
| Guarding CP | Done → Resume Checkpoint | — | "Failed move-to." | 3 |

### 3.4 Capturing CP (defending team — counter-attack)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Capturing CP | Done → Resume Checkpoint | — | "Attacking nearby threats" | (transitions to combat) |
| Capturing CP | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 6 |

Triggered during counter-attacks — defending bots rush to recapture a lost point.
Multiple bots get stuck while rushing to the same point.

### 3.5 Defensive Guard

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Defensive Guard | Done → Resume Checkpoint | — | "LoS to an enemy." | (observed) |

### 3.6 Investigating

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Investigating | Done → Resume Checkpoint | — | "Found a threat!" | 28 |
| Investigating | Done → Resume Checkpoint | — | "No move investigations to worry about" | 1 |
| Investigating | Done → Resume Checkpoint | — | "Gave up investigating, took too long." | 1 |
| Investigating | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 3 |

### 3.7 Combat

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Combat | SuspendFor | Attacking | "Attacking a visible/HasLOS threat" | 264 |
| Combat | SuspendFor | Attacking | "Attacking in place in escort" | 158 |
| Combat | SuspendFor | Pursue Threat | "Pursuing a Lost Enemy" | 123 |
| Combat | SuspendFor | Pursue Threat | "Pursuing a new target that I just lost" | 82 |
| Combat | SuspendFor | Suppressing | "Suppressing a recently lost threat" | 27 |
| Combat | SuspendFor | Retreating! | "Retreating to Reload" | 2 |
| Combat | SuspendFor | Reloading | "Reloading in place because of escorting or formation" | 4 |
| Combat | SuspendFor | Reloading | "Exiting attack to Reload" | 4 |
| Combat | SuspendFor | Retreating to cover | "Retreating to Cover to Reload" | 1 |
| Combat | Done | — | "Our threat is gone" | 73 |
| Combat | Done | — | "Should Not Attack This Threat" | 72 |
| Combat | Done | — | "Ending Combat in Update, Unable to retrieve primary target" | 70 |
| Combat | Done | — | "Lost sight of my Escort Target" | 103 |
| Combat | Done | — | "Primary target is no longer known" | 22 |
| Combat | Done | — | "Ending Combat in Update, Target ent is not a Known Entity" | 13 |
| Combat | Done | — | "Unable to determine initial threat." | 1 |
| Combat | Done | — | "Combat has timed out" | 1 |
| Combat | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 25 |

### 3.8 Attacking

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Attacking | Done → Resume Combat | — | "Retreating to cover" | 82 |
| Attacking | Done → Resume Combat | — | "Our Active target has been killed!" | 57 |
| Attacking | Done → Resume Combat | — | "Lost sight of my threat" | 54 |
| Attacking | Done → Resume Combat | — | "I should not attack this threat" | 10 |
| Attacking | Done → Resume Combat | — | "Out of scope" | 2 |

### 3.9 Attack Positioning (child of weapon-specific action)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| AttackInPlace | ChangeTo | AttackAdvance | "Advancing because of no LOS" | 128 |
| AttackInPlace | ChangeTo | AttackAdvance | "Advancing towards a lost target" | 24 |
| AttackAdvance | ChangeTo | AttackInPlace | "Closing in too close with primary" | 3 |

### 3.10 Pursue Threat

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Pursue Threat | Done → Resume Combat | — | "Arrived at investigation target." | 47 |
| Pursue Threat | Done → Resume Combat | — | "My Primary Target has changed" | 43 |
| Pursue Threat | Done → Resume Combat | — | "Out of scope" | 26 |
| Pursue Threat | Done → Resume Combat | — | "No Known Threats" | 24 |
| Pursue Threat | Done → Resume Combat | — | "I saw an enemy, attack!" | 20 |
| Pursue Threat | Done → Resume Combat | — | "No Known Threat" | 14 |
| Pursue Threat | Done → Resume Combat | — | "Idle in pursue" | 5 |

### 3.11 Suppressing

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Suppressing | Done → Resume Combat | — | "We're done suppressing." | 12 |
| Suppressing | Done → Resume Combat | — | "Spotted a threat while suppressing." | 11 |
| Suppressing | Done → Resume Combat | — | "Failed to init weapon entity" | 1 |
| Suppressing | Done → Resume Combat | — | "Our weapon is out of ammo." | 1 |

### 3.12 Retreating! (Combat-level retreat)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Retreating! | Done → Resume | — | "Retreat timer elapsed." | 6 |
| Retreating! | Done (via OnMoveToSuccess) | — | (empty — reached retreat position) | 2 |
| Retreating! | Done → Resume | — | "Unable to find a retreat area" | 2 |
| Retreating! | ChangeTo | Reloading | "Retreat timer elapsed, changing to reload" | 1 |

### 3.13 Reloading

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Reloading | Done → Resume | — | "Finished reloading!" | 8 |
| Reloading | Done → Resume | — | "No weapon." | 2 |

### 3.14 Throwing Grenade (Tactics-level)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Tactics → SuspendFor | Throwing Grenade | — | "Throwing a grenade!" | 21 |
| Throwing Grenade | Done → Resume Tactics | — | "Finished throw." | 17 |
| Throwing Grenade | Done → Resume Tactics | — | "No grenade..." | 4 |
| Throwing Grenade | Done → Resume Tactics | — | "Idle in throw grenade" | 1 |

### 3.15 Firing RPG (Tactics-level)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Tactics → SuspendFor | Firing RPG | — | "Firing an RPG!" | 1 |
| Firing RPG | Done → Resume Tactics | — | "Finished throw." | 1 |

Same "Finished throw." reason string as grenades — shared base class likely.

### 3.16 Retreating to cover (Tactics-level)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Tactics → SuspendFor | Retreating to cover | — | "We're in fire, get out of here!" | 30 |
| Tactics → SuspendFor | Retreating to cover | — | "Fleeing from nade" | 5 |
| Retreating to cover | Done → Resume Tactics | — | "In Cover" | 16 |
| Retreating to cover | Done → Resume | — | "Idle in retreat to cover" | 2 |
| Retreating to cover | ChangeTo | Retreating! | "Bailing on retreat to cover, no pos or threat is invalid" | 10 |
| Retreating to cover | SuspendFor | Retreating to cover | "Fleeing from nade" (nested) | 1 |

Fallback: when Retreating to cover can't find a position, it degrades to Retreating! (generic retreat).

### 3.17 Stuck / Unstuck

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| (any) | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 39 |
| Stuck | Done (via OnUnStuck) → Resume | — | "moved from our stuck position" | 22 |
| Retreating to cover | (via OnStuck) | — | "Im Stuck, help!" | 5 |

Stuck occurs in: Combat (25), Capturing CP (6), Investigating (3), Retreating to cover (5).

### 3.18 Dead

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Behavior | ChangeTo | Dead | "Dead" | 211 |

---

## 4. Events (OnEvent handlers)

| Event | Handler Action | Response | Reason | Count |
|-------|---------------|----------|--------|-------|
| OnLostSight | Combat (escort) | Done | "Lost sight of my Escort Target" | 103 |
| OnOtherKilled | Attacking | Done | "Our Active target has been killed!" | 58 |
| OnMoveToSuccess | Pursue Threat | Done | "Arrived at investigation target." | 47 |
| OnStuck | any | ChangeTo Stuck | "I'm Stuck" | 39 |
| OnInjured | Tactics | SuspendFor Retreating to cover | "We're in fire, get out of here!" | 30 |
| OnUnStuck | Stuck | Done | "Successful unstuck" | 22 |
| OnSight | Tactics | SuspendFor Retreating to cover | "Fleeing from nade" | 5 |
| OnStuck | Retreating to cover | Done | "Im Stuck, help!" | 5 |
| OnMoveToFailure | various | Done | "Failed move-to." / "Failed pathing..." | 3 |
| OnMoveToSuccess | Retreating! | Done | (empty — reached retreat position) | 2 |

---

## 5. Weapon-Specific Attack Classes

| Class | Weapon Type | Initial Child | Count |
|-------|------------|---------------|-------|
| CINSBotAttackCQC | Shotgun / SMG | AttackAdvance | 112 |
| CINSBotAttackRifle | Assault rifles | AttackInPlace | 113 |
| CINSBotAttackLMG | Light machine guns | AttackInPlace | 26 |
| CINSBotAttackPistol | Pistols / sidearms | AttackAdvance | 12 |
| Throwing Grenade | Grenade (as Attacking child) | — | 2 |

- CQC and Pistol start with AttackAdvance (aggressive close-in)
- Rifle and LMG start with AttackInPlace (hold position, fire)
- Grenade can appear as the weapon-action child of Attacking (rare)

---

## 6. Observed Behavior Patterns

### 6.1 Defending Team — Guard Rotation
Bots cycle: Checkpoint → Guarding CP (15-20s) → "Finished guarding spot" → Checkpoint → new Guarding CP.
They pick different guard positions each time. "LoS to an enemy" breaks the guard immediately.

### 6.2 Defending Team — Counter-Attack Recapture
When attackers capture a point, defending bots switch to `Capturing CP`:
```
Checkpoint → SuspendFor Capturing CP("It's a counter-attack and we're not hunting, re-cap")
```
Multiple bots rush simultaneously. Many get stuck (6 OnStuck events during Capturing CP) —
likely due to pathfinding congestion at the capture point.

### 6.3 Attacking Team — Escort Loop
Attacking-team bots primarily Escort the human player. The dominant cycle is:
```
Checkpoint → Escort("Escorting nearest Human") → Done("Unable to get escort Target") → Checkpoint → Escort
```
"Unable to get escort Target" fires 610 times — the single most common transition.
Bots constantly lose and reacquire their escort target.

### 6.4 Escort Combat
```
Escort → SuspendFor Combat("Combat time!") → Attacking → ...
  → Combat Done("Lost sight of my Escort Target") → Resume Escort
```
Escort bots have unique combat exit: OnLostSight fires "Lost sight of my Escort Target" (103 times) —
they break off combat to stay with their human. Also "Should Not Attack This Threat" (72 times)
filters targets that don't match escort engagement rules.

### 6.5 Combat Engagement Sequence
```
[idle action] → Checkpoint → SuspendFor Combat("Attacking nearby threats" / "Combat time!")
  → SuspendFor Attacking("visible/HasLOS threat") → weapon class → positioning
  → [lost LOS] ChangeTo AttackAdvance("Advancing because of no LOS")   ← most common
  → [too close] ChangeTo AttackInPlace("Closing in too close with primary")
  → Done("Retreating to cover" / "Lost sight" / "killed") → Resume Combat
  → SuspendFor Pursue Threat / Suppressing / Retreating!
  → ... → Done("Our threat is gone") → Resume [Escort/Checkpoint]
```

### 6.6 Retreating to Cover — Dominant Combat Exit
"Retreating to cover" is the #1 reason Attacking ends (82 times), ahead of kills (57)
and lost sight (54). Bots actively seek cover during firefights.

### 6.7 OnInjured → Flee
When shot, OnInjured triggers Tactics-level retreat: "We're in fire, get out of here!" (30 times).
This interrupts the entire gamemode stack — the bot drops everything to flee.
If no valid cover position exists, degrades to generic Retreating! ("Bailing on retreat to cover,
no pos or threat is invalid" — 10 times).

### 6.8 Grenade Flee
OnSight detects incoming grenade → Tactics-level "Fleeing from nade" (5 times).
Can nest: bot already fleeing from one grenade sees another, creating double retreat:
`Retreating to cover << Retreating to cover << Tactics`

### 6.9 Suppression → Re-engage
```
Combat → SuspendFor Suppressing("Suppressing a recently lost threat")
  → Done("We're done suppressing." / "Spotted a threat while suppressing.")
  → Resume Combat → re-engage or pursue
```
Suppression can end early if the target reappears ("Spotted a threat while suppressing." — 11 times).

### 6.10 Retreat → Reload Chain
```
Combat → SuspendFor Retreating!("Retreating to Reload")
  → [Tactics-level Reloading may suspend over retreat]
  → Retreating! ChangeTo Reloading("Retreat timer elapsed, changing to reload")
  → Reloading Done("Finished reloading!") → Resume Combat
```

### 6.11 RPG Firing
`Firing RPG` works like Throwing Grenade at Tactics level — same "Finished throw." reason.
Observed once. Likely shares a base class with Throwing Grenade.

### 6.12 Kill Notification Cascade
OnOtherKilled propagates to all bots attacking that target simultaneously (58 total events).

### 6.13 Post-Combat Investigation
After combat ends, bots often enter Investigating("Found a threat!" — 28 times,
"Counter-attacking enemy directly" — 3 times during counter-attacks).

### 6.14 Stuck Patterns
- Most common during Combat (25 times) — bots stuck mid-pursuit
- Capturing CP rush causes congestion (6 stuck events)
- Average unstuck time: ~2-3 seconds
- One bot (player #3) got stuck 8+ times throughout the map

---

## 7. Action Frequency Summary

| Action | Observations | Notes |
|--------|-------------|-------|
| Checkpoint | 1209 | gamemode root, always cycling back |
| Escort | 981 | attacking team dominant action |
| Combat | 878 | |
| AttackInPlace | 354 | |
| Attacking | 264 | |
| Guarding CP | 250 | defending team dominant action |
| Pursue Threat | 230 | |
| AttackAdvance | 222 | |
| Dead | 211 | ~24 min, many deaths |
| CINSBotAttackRifle | 113 | |
| CINSBotAttackCQC | 112 | |
| Investigating | 50 | |
| Stuck | 39 | |
| Retreating to cover | 37 | Tactics-level |
| Suppressing | 30 | |
| CINSBotAttackLMG | 26 | |
| Throwing Grenade | 22 | Tactics-level |
| Capturing CP | 17 | defending counter-attack |
| Defensive Guard | 14 | |
| Retreating! | 12 | |
| CINSBotAttackPistol | 12 | |
| Reloading | 10 | |
| Firing RPG | 1 | |

---

## 8. Collection Notes

Good coverage of both teams across a full map playthrough:
- Defending: Guarding CP, Defensive Guard, Capturing CP (counter-attack), Combat
- Attacking: Escort (dominant), Combat while escorting
- Weapons: Rifle, CQC, LMG, Pistol, Grenade, RPG
- Reactions: OnInjured flee, OnSight grenade dodge, OnStuck recovery
- Progression: multiple checkpoint captures, counter-attacks, round resets

Still not observed (may require different maps/modes/loadouts):
- `CINSBotAttackSniper`, `CINSBotAttackMelee`
- `AttackIntoCover`, `AttackFromCover`
- `Flank`, `Hunt`, `Search`
- `Shuttle`, `Assault` (other attacking-team strategies)
- `Use Explosive`
