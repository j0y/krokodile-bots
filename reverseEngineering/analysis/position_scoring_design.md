# Position Scoring AI — Design & Implementation Plan

## The Problem

Current bot movement uses a centralized coordinator (`nav_flanking.cpp`) that:
- Assigns sector angles and staging distances per bot
- Computes A* paths with visibility penalty
- Manages wave ordering and holding states
- Requires ~600 lines of coordination logic

Result: bots cluster at the same staging distance, queue behind each other,
freeze when they arrive, and don't adapt to changing situations. The system
is fragile and produces predictable, robotic behavior.

## The Solution: Tactical Position Evaluation

Replace the coordinator with **per-bot position scoring**. Each bot independently
evaluates nearby positions and moves to the best one. Squad-level tactics
(flanking, spreading, cover usage) emerge from individual decisions.

This is the proven pattern from Killzone, F.E.A.R., and virtually every
shipped FPS with competent bot AI.

### Core Loop (per bot, every ~1s)

```
1. Gather candidate positions (nav areas within BFS radius)
2. Score each candidate:
     cover_from_threat  * 40   (highest priority)
     line_of_fire       * 20   (can I shoot from here?)
     distance_to_threat * 15   (not too far, not too close)
     spread_from_allies * 15   (not near other bots)
     indoor_bonus       * 10   (Insurgency-specific: indoor = safer)
3. Pick highest-scoring position
4. Move there via engine pathfinding
5. Re-evaluate when: timer expires, threat moves, bot takes damage
```

### Why Emergent Behavior Falls Out

- **Flanking**: bots choose different high-scoring positions around the
  threat because already-occupied spots score lower
- **Spreading**: "distance from allies" penalty naturally distributes bots
- **Retreat**: when a position loses cover (threat moved), score drops,
  bot finds a better position (usually rearward)
- **Advance**: when threat is eliminated, all positions near the old
  threat score poorly (no line-of-fire needed), bots explore forward
- **No coordination code needed**: each bot is self-sufficient

## What We Already Have in the Engine

The decompiled `server_srv.so` reveals the engine already implements most of
the building blocks we need:

### Nav Mesh Hiding Spots (pre-scored)

Each `CINSNavArea` has hiding spots with per-team scores:

```
HidingSpot layout:
  +0x04  float x, y, z          — position
  +0x20  float score_team0       — Security score
  +0x24  float score_team1       — Insurgents score
  +0x28  float base_score

CINSNavArea methods (already resolved):
  ScoreHidingSpot(0x006E3BC0)           — evaluates spots per team
  CollectSpotsWithScoreAbove(...)       — get spots above threshold
  ResetHidingSpotScores(0x006E2D60)     — reset for recomputation
```

Scores factor in: control point ownership, spawn zone bonuses, PVS visibility,
enemy actors looking toward the spot (cos 0.9 / ~25° cone, within 250u).

### Cover Evaluation (already in CINSNextBot)

```
UpdateCover(0x0074AC70)       — BFS search, 2000u radius, 1s throttle
GetAttackCover(0x00745B70)    — cover with line-of-fire to threat
GetHidingCover(0x00744790)    — safe hiding from all threats
IsInCover(0x00744DB0)         — within 48u of cached cover
IsSpotOccupied(...)           — checks if another bot is using a spot
```

Attack cover checks:
- `HasAnyCoverToPoint(hidingSpot, threat.pos)` — geometry cover check
- `IsPointBetweenTargetAndSelf(spot, threat)` — positional validation
- `IsLineOfFireClear(spot + 69z, threat.eyes)` — can shoot from here
- `IsSpotOccupied(spot)` — no friendly overlap

### Visibility

```
IsPotentiallyVisible(area, otherArea)   — pre-computed PVS check
```

Already resolved and used in our current A* pathfinder.

### What We Use Now (in our extension)

```
GetNearestNavArea(pos)      — resolve position to nav area
NavArea_GetCenter(area)     — get area center position
NavArea_GetAdjacentCount()  — BFS expansion
NavArea_GetAdjacentArea()   — BFS expansion
IsBlocked(area)             — skip blocked areas
IsPotentiallyVisible()      — visibility checks
```

## Architecture Decision: Hook Engine Functions vs. Reimplement

Two approaches:

### Option A: Hook the engine's existing cover system

Call `UpdateCover`, `GetAttackCover`, etc. on the bot entity to use the
engine's own cover evaluation. Pros: battle-tested code, uses real hiding
spots, handles edge cases. Cons: need to resolve more function pointers,
covers may be optimized for the native AI's movement patterns.

### Option B: Reimplement position scoring in our extension

Use our existing nav mesh access (BFS over areas, `IsPotentiallyVisible`)
to score positions ourselves. Pros: full control over weights, no new
function resolution needed, can tune for our movement patterns. Cons:
won't use the engine's pre-scored hiding spots (unless we also resolve
those offsets).

**Recommendation: Option B (reimplement), with Option A data where easy.**
We already have nav BFS and visibility checks. Adding our own scoring
function on top is straightforward. If we can cheaply resolve the hiding
spot list per area (+0xD0 offset), we get pre-scored positions for free
as bonus candidates.

---

## Implementation TODO

### Phase 1: Position Scoring Core

Replace the centralized coordinator with per-bot scoring. This is the
minimum viable change that should immediately produce better bot behavior.

- [ ] **1.1 Create `bot_positioning.cpp/.h`**
  New source files for the position scoring system. Public API:
  `BotPositioning_Init()`, `BotPositioning_Update()`,
  `BotPositioning_GetTarget(edictIndex, &x, &y, &z)`,
  `BotPositioning_IsActive(edictIndex)`, `BotPositioning_Reset()`.
  Mirror the current `NavFlanking_*` API so extension.cpp can swap
  with minimal changes.

- [ ] **1.2 Implement BFS candidate collector**
  Given a bot position and threat position, BFS outward from the bot's
  nav area collecting candidate areas. Cap at ~200 areas or 2000u travel
  distance (matching the engine's cover search radius). Store centers as
  candidate positions.

- [ ] **1.3 Implement scoring function**
  For each candidate position, compute weighted score:
  - `cover_from_threat`: 1.0 if not `IsPotentiallyVisible` from threat
    area, 0.2 if visible. Weight: 40.
  - `line_of_fire`: 1.0 if `IsPotentiallyVisible` to threat from an
    adjacent area (can peek), 0.3 otherwise. Weight: 20.
  - `distance_to_threat`: bell curve peaking at ideal distance (ConVar,
    default ~800u). Use gaussian: `exp(-(d - ideal)^2 / (2 * sigma^2))`.
    Weight: 15.
  - `spread_from_allies`: minimum distance to any friendly bot position,
    normalized. 1.0 if >300u from nearest ally, drops linearly to 0.0
    at 0u. Weight: 15.
  - `indoor_bonus`: 1.5x if area has indoor flag (offset 0x160, bit 7).
    Weight: 10.

- [ ] **1.4 Implement per-bot state and decision timer**
  Each bot stores: current target position, last evaluation time, current
  score. Re-evaluate every 2-3 seconds, or immediately on: threat death,
  new threat detected, bot took damage, reached current target.

- [ ] **1.5 Wire into extension.cpp**
  Replace `NavFlanking_Update`/`NavFlanking_GetTarget` calls with
  `BotPositioning_Update`/`BotPositioning_GetTarget`. Keep the same
  defend/flank split logic — defenders still use BotTactics, flankers
  use positioning. Pass all known enemy positions + all friendly bot
  positions into the update.

- [ ] **1.6 Add ConVars for weight tuning**
  `smartbots_pos_cover_weight` (40), `smartbots_pos_lof_weight` (20),
  `smartbots_pos_dist_weight` (15), `smartbots_pos_spread_weight` (15),
  `smartbots_pos_ideal_dist` (800), `smartbots_pos_eval_interval` (2.0).
  All tunable live in-game for rapid iteration.

### Phase 2: Movement Improvements

Once scoring works, improve how bots move to their chosen positions.

- [ ] **2.1 Use engine pathfinding instead of A* waypoints**
  Currently we run our own A* and feed waypoints one at a time. Instead,
  just issue a single `IssueMovementRequest` to the scored position and
  let the engine handle pathfinding + obstacle avoidance. Removes our
  entire A* pathfinder (~130 lines) and waypoint advancement code.

- [ ] **2.2 Add "position reached" detection**
  When bot is within ~100u of target position, mark as "positioned".
  Bot stays and fights until re-evaluation triggers. No "holding" state
  needed — just a longer re-eval timer when positioned (5s vs 2s).

- [ ] **2.3 Continuous re-evaluation under fire**
  If bot takes damage (detectable via health change between ticks), force
  immediate re-evaluation. This produces natural retreat behavior: current
  position scores poorly (under fire = bad cover), bot moves to better spot.

### Phase 3: Refinements

Polish and edge cases.

- [ ] **3.1 Resolve hiding spot data from nav areas**
  Access `CINSNavArea::m_hidingSpots` at offset +0xD0. Use pre-scored
  hiding spots as additional candidate positions (in addition to area
  centers). These are higher-resolution tactical positions that the
  engine's level designers validated.

- [ ] **3.2 Add occupied-position penalty**
  Track which positions bots have claimed. Score penalty for positions
  within 200u of another bot's target. This prevents two bots from
  choosing the same spot in the same evaluation cycle.

- [ ] **3.3 Add threat-direction weighting**
  Prefer positions that are laterally offset from the threat-to-objective
  line (flanking positions). This is a soft bias, not a hard assignment:
  `lateral_offset = cross(threat_to_pos, threat_to_objective)`.
  Normalized and weighted low (~5). Creates a mild flanking preference
  without forcing it.

- [ ] **3.4 Add "advance when safe" behavior**
  When no threats are known for >10 seconds, gradually increase the
  ideal distance factor to push bots forward toward the attacker spawn.
  This prevents bots from camping forever when all enemies are dead.
  Resets when a new threat is detected.

- [ ] **3.5 Vocal callouts (the F.E.A.R. lesson)**
  When a bot picks a position that is laterally offset from the threat,
  trigger a voice command ("Flanking!" / "Moving!"). The engine has
  voice concepts (`voice-concepts.md`). This dramatically increases
  perceived intelligence even if the bot's decision was trivially simple.

### Cleanup

- [ ] **4.1 Remove nav_flanking.cpp**
  Once position scoring is validated, delete `nav_flanking.cpp/.h` and
  all references. Remove: FlankAssignment struct, wave ordering, sector
  computation, A* pathfinder, holding state, staging positions. This
  removes ~600 lines of coordinator code.

- [ ] **4.2 Simplify extension.cpp dispatch**
  With no wave ordering or holding states, the dispatch in GameFrame
  simplifies to: collect bots → split defend/position → call update →
  issue movement. Remove staleness tracking, reassignment triggers, etc.

---

## Risk Assessment

**Low risk**: Position scoring is a well-understood technique used in every
major FPS. The approach is simpler than what we have now.

**Main risk**: Tuning weights to produce good behavior on Insurgency's maps.
Mitigated by making all weights ConVars for live tuning.

**Fallback**: If position scoring produces worse results than current flanking
on specific maps, we can add map-specific weight overrides via ConVars.

## References

- Killzone AI: Dynamic Procedural Tactics (Guerrilla Games, GDC 2005)
- F.E.A.R. AI: Three States and a Plan (Jeff Orkin, GDC 2006)
- Game AI Pro Ch. 26: Tactical Position Selection
- Game AI Pro Ch. 9: Introduction to Utility Theory (Dave Mark)
- Insurgency engine analysis: `retreat_cover_system.md`, `pathfinding_system.md`
