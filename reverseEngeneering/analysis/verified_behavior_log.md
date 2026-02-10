# Verified Bot Behavior — Live Server Observations

Captured from `nb_debug BEHAVIOR EVENTS ERRORS` on a vanilla Insurgency 2014 server
(no SourceMod/MetaMod — original bot AI only).

- **Map**: ministry_coop (Checkpoint mode)
- **Server**: `developer 1`, `sv_cheats 1`
- **Date**: 2026-02-10
- **Duration**: ~210 seconds of gameplay (t=22s to t=232s), multiple rounds
- **Total transitions logged**: 1663
- **Bots**: defending team (12) + attacking/security team (15+)

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
Behavior                                [root — never changes]
 ├─ Throwing Grenade                    [SuspendFor on Tactics — interrupts everything]
 ├─ Reloading                          [SuspendFor on Tactics — opportunistic reload]
 ├─ Retreating to cover                [SuspendFor on Tactics — flee from grenade]
 │
 └─ Tactics                            [child — never changes]
     └─ Investigations                 [child — never changes]
         └─ Gamemode                   [child — never changes]
             └─ Checkpoint             [gamemode root — always present as base]
                 │
                 ├── Guarding CP       [SuspendFor] defend a position (defending team)
                 ├── Defensive Guard   [SuspendFor] positional defense (defending team)
                 ├── Investigating     [SuspendFor] heard/saw something
                 ├── Escort            [SuspendFor] follow nearest human (attacking team)
                 ├── Stuck             [ChangeTo via OnStuck event]
                 │
                 └── Combat            [SuspendFor] threat detected
                     ├── Attacking     [SuspendFor] has LOS to target
                     │   ├── CINSBotAttackRifle   [child] → AttackInPlace / AttackAdvance
                     │   ├── CINSBotAttackLMG     [child] → AttackInPlace / AttackAdvance
                     │   ├── CINSBotAttackCQC     [child] → AttackAdvance (starts advancing)
                     │   └── CINSBotAttackPistol  [child] → AttackAdvance (starts advancing)
                     │
                     ├── Pursue Threat [SuspendFor] lost sight of enemy
                     ├── Suppressing   [SuspendFor] suppressive fire on lost target
                     ├── Retreating!   [SuspendFor] fall back to reload
                     └── Reloading     [SuspendFor] reload in combat
```

### Key structural finding: Tactics-level actions
`Throwing Grenade`, `Reloading` (opportunistic), and `Retreating to cover` suspend **Tactics**,
not Checkpoint. This means they interrupt the ENTIRE gamemode stack — they take priority
over any combat/escort/guard action. The Behavior stack shows:
```
Behavior( Throwing Grenade<<Tactics( Investigations( Gamemode( ... ) ) ) )
Behavior( Reloading<<Tactics( Investigations( Gamemode( ... ) ) ) )
Behavior( Retreating to cover<<Tactics( Investigations( Gamemode( ... ) ) ) )
```

### Not yet observed (expected from RE):
- `CINSBotAttackSniper`, `CINSBotAttackMelee`
- `AttackIntoCover`, `AttackFromCover`
- `Flank`, `Hunt`, `Search`
- `Shuttle`, `Assault` (attacking-team Checkpoint actions)
- `Use Explosive`

---

## 3. Verified Transitions

### 3.1 Checkpoint (gamemode root)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Checkpoint | SuspendFor | Escort | "Escorting nearest Human" | 239 |
| Checkpoint | SuspendFor | Guarding CP | "Guarding CP." | 67 |
| Checkpoint | SuspendFor | Combat | "Attacking nearby threats" | 39 |
| Checkpoint | SuspendFor | Investigating | "I have an investigation!" | 10 |
| Checkpoint | SuspendFor | Defensive Guard | "Defending." | 4 |

### 3.2 Escort (attacking team — follow player)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Escort | SuspendFor | Combat | "Combat time!" | 43 |
| Escort | Done → Resume Checkpoint | — | "Unable to get escort Target" | 213 |
| Escort | (implicit via Combat Done) | Resume Escort | various | — |

Note: Escort frequently loses and re-acquires its target. "Unable to get escort Target" is
the most common single transition in the log — bots constantly cycle Escort → Checkpoint → Escort.

### 3.3 Guarding CP (defending team)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Guarding CP | Done → Resume Checkpoint | — | "Finished guarding spot." | 30 |
| Guarding CP | Done → Resume Checkpoint | — | "LoS to an enemy." | 22 |
| Guarding CP | Done → Resume Checkpoint | — | "Failed move-to." | 1 |
| Guarding CP | Done → Resume Checkpoint | — | "Point we were guarding is inactive, relocating to new point." | 1 |

### 3.4 Defensive Guard

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Defensive Guard | Done → Resume Checkpoint | — | "LoS to an enemy." | 1 |

### 3.5 Investigating

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Investigating | Done → Resume Checkpoint | — | "Found a threat!" | 5 |
| Investigating | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 2 |

### 3.6 Combat

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Combat | SuspendFor | Attacking | "Attacking a visible/HasLOS threat" | 92 |
| Combat | SuspendFor | Attacking | "Attacking in place in escort" | 42 |
| Combat | SuspendFor | Pursue Threat | "Pursuing a Lost Enemy" | 11 |
| Combat | SuspendFor | Pursue Threat | "Pursuing a new target that I just lost" | 18 |
| Combat | SuspendFor | Suppressing | "Suppressing a recently lost threat" | 1 |
| Combat | SuspendFor | Retreating! | "Retreating to Reload" | 2 |
| Combat | SuspendFor | Reloading | "Reloading in place because of escorting or formation" | 1 |
| Combat | SuspendFor | Reloading | "Exiting attack to Reload" | 2 |
| Combat | Done → Resume Escort | — | "Our threat is gone" | 20 |
| Combat | Done → Resume Escort | — | "Should Not Attack This Threat" | 9 |
| Combat | Done → Resume Escort | — | "Ending Combat in Update, Unable to retrieve primary target" | 8 |
| Combat | Done → Resume Escort | — | "Lost sight of my Escort Target" | 8 |
| Combat | Done → Resume Escort | — | "Ending Combat in Update , Target ent is not a Known Entity" | 2 |
| Combat | Done → Resume Checkpoint | — | "Our threat is gone" | (included above) |
| Combat | Done → Resume Checkpoint | — | "Combat has timed out" | 1 |
| Combat | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 6 |

### 3.7 Attacking

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Attacking | Done → Resume Combat | — | "Retreating to cover" | 51 |
| Attacking | Done → Resume Combat | — | "Our Active target has been killed!" | 19 |
| Attacking | Done → Resume Combat | — | "Lost sight of my threat" | 4 |
| Attacking | Done → Resume Combat | — | "I should not attack this threat" | 3 |
| Attacking | Done → Resume Combat | — | "Out of scope" | 2 |

### 3.8 Attack Positioning (child of weapon-specific action)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| AttackInPlace | ChangeTo | AttackAdvance | "Advancing because of no LOS" | 25 |
| AttackInPlace | ChangeTo | AttackAdvance | "Advancing towards a lost target" | 3 |
| AttackAdvance | ChangeTo | AttackInPlace | "Closing in too close with primary" | 5 |

### 3.9 Pursue Threat

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Pursue Threat | Done → Resume Combat | — | "Arrived at investigation target." | 6 |
| Pursue Threat | Done → Resume Combat | — | "I saw an enemy, attack!" | 3 |
| Pursue Threat | Done → Resume Combat | — | "No Known Threats" | 4 |
| Pursue Threat | Done → Resume Combat | — | "No Known Threat" | 3 |
| Pursue Threat | Done → Resume Combat | — | "Out of scope" | 5 |
| Pursue Threat | Done → Resume Combat | — | "My Primary Target has changed" | 4 |

### 3.10 Suppressing

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Suppressing | Done → Resume Combat | — | "We're done suppressing." | 1 |

### 3.11 Retreating!

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Retreating! | ChangeTo | Reloading | "Retreat timer elapsed, changing to reload" | 1 |

During retreat, Tactics-level Reloading can suspend over it:
```
Behavior( Reloading<<Tactics( Investigations( Gamemode( Retreating!<<Combat<<Checkpoint ) ) ) )
```

### 3.12 Reloading

Two distinct contexts:
1. **Combat-level**: `Combat → SuspendFor Reloading` ("Reloading in place because of escorting or formation", "Exiting attack to Reload")
2. **Tactics-level**: `Tactics → SuspendFor Reloading` ("Opportunistic reload in-place") — interrupts entire gamemode stack

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Reloading | Done → Resume Combat | — | "Finished reloading!" | 3 |
| Reloading | Done → Resume Tactics | — | "Finished reloading!" | (opportunistic) |
| Reloading | Done → Resume Combat | — | "No weapon." | 1 |

### 3.13 Throwing Grenade (Tactics-level)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Tactics → SuspendFor | Throwing Grenade | — | "Throwing a grenade!" | 5 |
| Throwing Grenade | Done → Resume Tactics | — | "Finished throw." | 4 |
| Throwing Grenade | Done → Resume Tactics | — | "No grenade..." | 1 |

### 3.14 Retreating to cover (Tactics-level)

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Tactics → SuspendFor | Retreating to cover | — | "Fleeing from nade" | 1 |

Triggered by `OnSight` event (seeing an incoming grenade).

### 3.15 Stuck / Unstuck

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| (any) | ChangeTo (via OnStuck) | Stuck | "I'm Stuck" | 8 |
| Stuck | Done (via OnUnStuck) → Resume Checkpoint | — | "moved from our stuck position" | 5 |

Note: player(#3) got stuck 4 separate times — always during Combat or Investigating.

### 3.16 Dead

| From | Mechanism | To | Reason String | Count |
|------|-----------|-----|---------------|-------|
| Behavior | ChangeTo | Dead | "Dead" | 56 |

Replaces entire behavior stack. Bot respawns with fresh boot sequence.

---

## 4. Events (OnEvent handlers)

| Event | Handler Action | Response | Reason | Count |
|-------|---------------|----------|--------|-------|
| OnOtherKilled | Attacking | Done | "Our Active target has been killed!" | 19 |
| OnStuck | Combat / Investigating | ChangeTo Stuck | "I'm Stuck" | 8 |
| OnLostSight | Combat (in Escort) | Done | "Lost sight of my Escort Target" | 8 |
| OnMoveToSuccess | Pursue Threat | Done | "Arrived at investigation target." | 6 |
| OnUnStuck | Stuck | Done | "Successful unstuck" | 5 |
| OnSight | Tactics | SuspendFor Retreating to cover | "Fleeing from nade" | 1 |
| OnMoveToFailure | Guarding CP | Done | "Failed move-to." | 1 |
| OnMoveToFailure | Pursue Threat | Done | "Failed pathing to investigation target." | 1 |

---

## 5. Weapon-Specific Attack Classes (Verified)

| Class | Weapon Type | Initial Child | Count |
|-------|------------|---------------|-------|
| CINSBotAttackRifle | Assault rifles | AttackInPlace | 30 |
| CINSBotAttackCQC | Close quarters (shotgun/SMG) | AttackAdvance | 54 |
| CINSBotAttackPistol | Pistols / sidearms | AttackAdvance | 3 |
| CINSBotAttackLMG | Light machine guns | AttackInPlace | 5 |

- CQC and Pistol start with AttackAdvance (aggressive close-in)
- Rifle and LMG start with AttackInPlace (hold position, fire)
- Pistol bots were escorting (attacking team) — switched to pistol likely after primary ran dry

---

## 6. Observed Behavior Patterns

### 6.1 Defending Team — Guard Rotation
Bots cycle: Checkpoint → Guarding CP (15-20s) → "Finished guarding spot" → Checkpoint → new Guarding CP.
They pick different guard positions each time.

### 6.2 Attacking Team — Escort Loop
Attacking-team bots primarily Escort the human player. The dominant cycle is:
```
Checkpoint → Escort("Escorting nearest Human") → ... → Done("Unable to get escort Target") → Checkpoint → Escort
```
"Unable to get escort Target" fires 213 times — bots constantly lose and reacquire their escort target.
This is the single most common transition in the entire log.

### 6.3 Escort Combat
When escorting bots spot enemies:
```
Escort → SuspendFor Combat("Combat time!") → Attacking → ...
  → Combat Done("Our threat is gone" / "Should Not Attack This Threat" / "Lost sight of my Escort Target")
  → Resume Escort
```
Escort bots have a unique combat exit: "Lost sight of my Escort Target" — they break off combat
to stay with their human, triggered by the OnLostSight event.

### 6.4 Combat Engagement Sequence (general)
```
[guard/escort] → Checkpoint → SuspendFor Combat("Attacking nearby threats" / "Combat time!")
  → SuspendFor Attacking("visible/HasLOS threat") → weapon class → positioning
  → [if lost LOS] ChangeTo AttackAdvance("Advancing because of no LOS")
  → [if too close] ChangeTo AttackInPlace("Closing in too close with primary")
  → Done("Lost sight" / "Retreating to cover" / "killed") → Resume Combat
  → SuspendFor Pursue Threat / Suppressing / Retreating!
  → ... → Done("Our threat is gone") → Resume [Escort/Checkpoint]
```

### 6.5 Retreating to Cover (new)
"Retreating to cover" is now the MOST common reason for Attacking to end (51 times).
This suggests bots actively seek cover during firefights rather than just losing LOS passively.

### 6.6 Retreat → Reload Sequence
```
Combat → SuspendFor Retreating!("Retreating to Reload")
  → [Tactics-level Reloading suspends over retreat]
  → [reload done] → Resume Retreating!
  → ChangeTo Reloading("Retreat timer elapsed, changing to reload")
  → Done("Finished reloading!" / "No weapon.") → Resume Combat
```
The retreat has a timer; after it expires, the bot transitions from retreating to in-place reload.

### 6.7 Grenade Usage
Grenade throwing happens at the Tactics level — it interrupts everything:
```
Tactics → SuspendFor Throwing Grenade("Throwing a grenade!")
  → [1.5-2s later] Done("Finished throw." / "No grenade...")
  → Resume Tactics (whatever was happening continues)
```
One bot (player #7) threw a grenade then immediately fled from another grenade (OnSight → Retreating to cover).

### 6.8 Stuck Detection
The engine's OnStuck event fires on any action via ChangeTo, replacing it with Stuck.
OnUnStuck then fires Done, resuming Checkpoint. player(#3) got stuck 4 times in Combat/Investigating —
always successfully unstuck after ~2-3s.

### 6.9 AttackInPlace ↔ AttackAdvance Oscillation
Still observed — bots rapidly flip between positioning states at weapon boundary distances.

### 6.10 Kill Notification Cascade
OnOtherKilled propagates to all bots attacking that target simultaneously.

### 6.11 "Should Not Attack This Threat"
Escort bots sometimes exit combat with this reason (9 times). Likely means the threat is
out of the bot's engagement rules while escorting (too far, wrong direction, friendly fire risk).

---

## 7. Action Frequency Summary

| Action | Total Observations |
|--------|--------------------|
| Checkpoint | 367 |
| Escort | 278 |
| Combat | 184 |
| AttackInPlace | 111 |
| Attacking | 92 |
| Guarding CP | 69 |
| Dead | 56 |
| CINSBotAttackCQC | 54 |
| AttackAdvance | 51 |
| CINSBotAttackRifle | 30 |
| Pursue Threat | 29 |
| Investigating | 10 |
| Stuck | 8 |
| CINSBotAttackLMG | 5 |
| Throwing Grenade | 5 |
| Defensive Guard | 4 |
| Reloading | 4 |
| CINSBotAttackPistol | 3 |
| Retreating! | 2 |
| Suppressing | 1 |
| Retreating to cover | 1 |

---

## 8. Collection Notes

Coverage now includes both teams:
- Defending: Guarding CP, Defensive Guard, Combat (defending)
- Attacking: Escort (dominant), Combat while escorting
- Weapons: Rifle, CQC, LMG, Pistol
- New mechanics: Grenade throw/flee, Retreat→Reload, Stuck/Unstuck, Escort combat

Still missing (need more gameplay / different maps):
- `CINSBotAttackSniper`, `CINSBotAttackMelee`
- `AttackIntoCover`, `AttackFromCover`
- `Flank`, `Hunt`, `Search`
- `Shuttle`, `Assault` (other attacking-team strategies)
- `Use Explosive`
- Behavior on different game modes (Push, Firefight, etc.)
