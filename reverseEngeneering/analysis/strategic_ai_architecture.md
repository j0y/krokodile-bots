# Strategic AI Architecture — Three-Layer Design

## Overview

Bot decision-making is split into three layers, each running at a different frequency.
The LLM handles strategy, Python handles squad tactics, C++ handles tick-rate execution.

```
┌─────────────────────────────────────────────────────┐
│  LLM Strategist            (event-driven, ~2-5/min) │  "Squad A flank left, Squad B suppress"
├─────────────────────────────────────────────────────┤
│  Python Tactical Planner   (every 1-2s / on events) │  translates strategy → roles + positions
├─────────────────────────────────────────────────────┤
│  C++ Metamod Extension     (every tick, 66Hz)        │  executes roles via native action classes
└─────────────────────────────────────────────────────┘
```

Key principle: each layer only communicates with its neighbors. LLM never sees
coordinates, C++ never makes strategic choices.

---

## Layer 1: LLM Strategist

### What It Sees

Not raw positions. A compressed situation report built from zone-level summaries:

```
MAP: ministry (12 zones)

ZONES:
- security_spawn: indoor, good cover, ground level
  → connects to: main_hallway, back_corridor
- main_hallway: corridor, CHOKE POINT, low cover
  → connects to: security_spawn, courtyard
- courtyard: open, exposed, ground level, has OBJECTIVE B
  → connects to: main_hallway, east_building, west_alley
  → visible from: east_balcony
- east_balcony: indoor, good cover, ELEVATED, overlooks courtyard
  → connects to: east_building

CHOKE POINTS:
- main_hallway (between security_spawn and courtyard)

FLANKING ROUTES:
- security_spawn → courtyard via back_corridor, west_alley (avoids main_hallway)

CURRENT STATE:
- Squad A (LMG+2 rifles) at east_building, healthy
- Squad B (3 rifles) at security_spawn, full ammo
- Enemies: 4 at courtyard near obj B, 2 at west_alley
- Objective B: enemy controlled
```

### What It Outputs

Structured JSON, not prose:

```json
{
  "squad_alpha": {
    "objective": "suppress_obj_B_from_warehouse",
    "tactic": "crossfire_setup",
    "priority": "high"
  },
  "squad_bravo": {
    "objective": "flank_east_to_obj_B",
    "tactic": "bounding_overwatch",
    "priority": "high"
  }
}
```

### When It Fires (Event-Driven, NOT Periodic)

| Event | Example |
|-------|---------|
| Objective captured/lost | Point B taken by enemy |
| Squad wiped or heavily damaged | Squad A lost 3 of 4 members |
| New major enemy contact | Large enemy group spotted in new zone |
| Stalemate detected | No progress for 30s |
| Round start | Initial strategy assignment |

Expected frequency: 2-5 calls per minute. Feasible with any model including Haiku.

### Map Context

The LLM receives a static map tactical profile (loaded once per map) plus dynamic
state updates. It reasons about named zones, not coordinates.

---

## Layer 2: Python Tactical Planner

Rule-based code, no LLM. Runs every 1-2 seconds or on events.

### Squad Formation

Groups bots into squads of 3-5 based on proximity and weapon composition.
Runs on spawn, death, or regroup events.

```python
def form_squads(bots):
    # Group by proximity + weapon composition
    # Each squad wants: 1 support weapon + 2-3 rifles + optional specialist
    # Squad size: 3-5 bots
    # Rebalance when squad drops below 2
```

### Tactic Translation

Converts LLM strategy orders into per-bot role assignments with exact positions.

```python
def plan_tactic(squad, strategy_order, world_state):
    if strategy_order.tactic == "suppress_and_advance":
        suppressor = squad.best_support_weapon()
        advancers = squad.rifles()[:2]
        suppress_pos = resolve_overwatch_position(
            squad.current_zone,
            strategy_order.target_zone
        )
        advance_waypoints = resolve_approach_route(
            squad.current_zone,
            strategy_order.target_zone
        )
        return TacticAssignment(
            roles={
                suppressor.id: ("SUPPRESS", suppress_pos, target_pos),
                advancers[0].id: ("ADVANCE", advance_waypoints),
                advancers[1].id: ("ADVANCE", advance_waypoints),
            }
        )
```

### What Python Tracks

- Squad membership, health, ammo status
- Squad positions (zone-level, from state updates already in the bridge)
- Active tactic per squad + current phase
- Enemy cluster positions (aggregated from bot vision reports)

### Position Resolution — Zone Names to Coordinates

This is where "the warehouse" becomes exact coordinates. It's lookups on
precomputed data, not runtime computation.

#### Resolution Chain

```
LLM:     "Squad A → warehouse, suppress courtyard"
              │
              ▼
Python:  zone "warehouse" → area_ids [234, 235, 236, 237]
         zone "courtyard" → area_ids [301, 302, 303]
              │
              ▼
         visibility NPZ → which warehouse areas see courtyard?
         (234,301)✓  (234,302)✓  (235,301)✓  (236,*)✗  (237,*)✗
              │
              ▼
         areas 234, 235 have LOS to courtyard
         area 234 hiding_spots: [(450,200,64), (455,195,64)]
         area 235 hiding_spots: [(460,210,64), (468,205,64)]
              │
              ▼
         assign bot_3 → (450,200,64), aim toward area 301 center
         assign bot_5 → (460,210,64), aim toward area 302 center
              │
              ▼
C++:     SuppressTarget(area_301_center, NULL) for bot_3
         SuppressTarget(area_302_center, NULL) for bot_5
```

#### Position Resolver

```python
def resolve_positions(zone_id, target_zone_id, num_bots):
    """Turn 'go to warehouse, watch courtyard' into exact positions."""

    zone_areas = tactical_data["zones"][zone_id]["area_ids"]
    target_areas = tactical_data["zones"][target_zone_id]["area_ids"]

    # Step 1: which areas in our zone can see the target zone?
    overwatch_areas = [
        a for a in zone_areas
        if any((a, t) in visible_pairs or (t, a) in visible_pairs
               for t in target_areas)
    ]

    # Step 2: grab hiding spots in those areas (already in nav JSON)
    candidate_spots = []
    for area_id in overwatch_areas:
        spots = nav_data["areas"][area_id]["hiding_spots"]
        visible_targets = [t for t in target_areas
                          if (area_id, t) in visible_pairs]
        for spot in spots:
            candidate_spots.append((spot, visible_targets))

    # Step 3: pick spots that are spread out (avoid clustering)
    selected = pick_spread_positions(candidate_spots, num_bots)

    return selected  # [(pos, aim_toward), ...]
```

#### Crossfire Resolution

For crossfire tactics, find two positions that both see the target but from
different angles (so the enemy can't hide from both behind the same cover):

```python
def find_crossfire_positions(target_zone, available_zones, min_angle=60):
    target_center = zone_center(target_zone)

    for zone_a, zone_b in combinations(available_zones, 2):
        pos_a = best_overwatch_spot(zone_a, target_zone)
        pos_b = best_overwatch_spot(zone_b, target_zone)

        if pos_a and pos_b:
            angle = angle_between(
                pos_a - target_center,
                pos_b - target_center
            )
            if angle > min_angle:
                return (zone_a, pos_a), (zone_b, pos_b)
```

#### Data Sources for Position Resolution

| Question | Answered by | Precomputed? |
|----------|-------------|:---:|
| Which areas can see the target zone? | Visibility NPZ | Yes |
| Where to stand with cover? | Nav mesh hiding spots | Yes |
| Is the position too exposed? | Clearance NPZ (min clearance) | Yes |
| How spread out are the positions? | Hiding spot coordinates | Yes |
| What angle is the crossfire? | Vector math on positions | Trivial |
| Can bot physically path there? | Nav mesh connectivity | Yes |

#### Runtime-Only Decisions (NOT Precomputed)

- Which spots are already occupied (Python tracks squad assignments)
- Which spots are near known enemies (from bot vision state updates)
- Spacing between assigned bots (filter spots > N units apart)
- Priority when spots are limited (LMG gets best overwatch, rifles get the rest)

These are simple filters on the candidate list, not heavy computation.

---

## Layer 3: C++ Metamod Extension

Detailed in [team_coordination_design.md](team_coordination_design.md).

Receives tactic assignments from Python, maps roles to native action classes:

| Role | Native Action | Behavior |
|------|---------------|----------|
| SUPPRESS | `CINSBotSuppressTarget(pos, entity)` | Fire at position with wobble |
| ADVANCE | `CINSBotApproach(pos)` + `CINSBotAttack` on contact | Move forward |
| OVERWATCH | `CINSBotAttackFromCover()` | Pop-out shooting with lean |
| HOLD | `CINSBotGuardDefensive(area_id)` | Defend position |
| BREACH | `CINSBotThrowGrenade(pos)` → `CINSBotAttackCQC` | Frag + enter |
| FLANK | `CINSBotApproach(pos)` via specific route | Move to side position |
| RETREAT | `CINSBotRetreatToCover(bool, float)` | Fall back to cover |

Phase transitions (e.g., suppressor fires → advance signal → advancer moves) happen
at tick-rate in C++. Python just sets up the plan.

### Protocol Extension

Python→SM message format for tactic assignments:

```
TACTIC squad_id tactic_type phase bot_assignments...
```

Example:
```
TACTIC 1 suppress_advance 0 bot3:SUPPRESS:450,200,0 bot5:ADVANCE:500,180,0 bot7:OVERWATCH
```

C++ reads this once, then runs autonomously until the tactic completes, fails,
or Python sends a new assignment.

---

## Precomputed Map Data Pipeline

### Available Data (Already Produced)

| Data | Format | File Pattern | Content |
|------|--------|-------------|---------|
| 3D mesh | GLB | `ai-brain/data/{map}.glb` | World geometry (Blender/Three.js compatible) |
| Nav mesh | JSON | `navMeshParser --json` | Areas, connections, hiding spots, flags |
| Visibility | NPZ | `ai-brain/data/{map}_visibility.npz` | Pairwise area visibility (317K pairs for ministry) |
| Clearance | NPZ | `ai-brain/data/{map}_clearance.npz` | 72-azimuth radial clearance per sample |

### Zone Builder Pipeline

```
BSP + NAV ──→ bspMeshExporter (GLB + clearance + visibility)
                    │
                    ▼
              zone_builder.py (auto-cluster + tactical scoring)
                    │
                    ▼
              {map}_tactical.json (draft)
                    │
                    ▼
              web editor (Three.js + nav mesh overlay)
                    │
                    ▼
              {map}_tactical.json (reviewed, final)
```

30 maps, review each once, done forever.

### Zone Builder — Auto-Derivable Properties

| Property | Source | Method |
|----------|--------|--------|
| Zone boundaries | Nav graph | Connected-component clustering, split on doorways/clearance drops/indoor-outdoor transitions/elevation |
| Choke points | Nav graph | High betweenness centrality + low clearance flanked by high clearance |
| Cover quality | Nav mesh + clearance | Hiding spot density + varied clearance = good cover |
| Exposure | Clearance NPZ | High min-clearance everywhere = open/exposed |
| Corridor vs room vs open | Clearance + area shape | Narrow in one axis = corridor, enclosed = room |
| Elevation tier | Nav area Z coords | Relative to neighbors — ground/elevated/rooftop |
| Sight lines | Visibility NPZ | Filter to inter-zone pairs |
| Flanking routes | Nav graph | A* with choke-point penalty |
| Objective proximity | Nav area CP associations | CINSNavArea data |

### Zone Builder — Needs Visual Review

| Property | Why |
|----------|-----|
| Zone boundary placement | Wide archway: one room or two? |
| Space "feel" | Courtyard with cars: data says "open", plays as "decent cover" |
| Semantic naming | Data says "indoor, ground, high cover" — you know it's "the kitchen" |
| Flanking route quality | Path may exist geometrically but be impractical tactically |

### Tactical Profile Format

```json
{
  "map": "ministry",
  "zones": [
    {
      "id": "z1",
      "label": "security_spawn",
      "type": "indoor",
      "cover": "high",
      "elevation": "ground",
      "is_choke": false,
      "area_ids": [101, 102, 103, 104],
      "center": [450, 200, 0],
      "connects_to": ["z2", "z5"],
      "sight_lines_to": [],
      "objectives": []
    },
    {
      "id": "z4",
      "label": "courtyard",
      "type": "open",
      "cover": "low",
      "elevation": "ground",
      "is_choke": false,
      "connects_to": ["z3", "z5", "z6"],
      "sight_lines_to": ["z8"],
      "objectives": ["B"]
    },
    {
      "id": "z8",
      "label": "east_balcony",
      "type": "indoor",
      "cover": "high",
      "elevation": "elevated",
      "is_choke": false,
      "connects_to": ["z7"],
      "sight_lines_to": ["z4", "z3"],
      "objectives": []
    }
  ],
  "choke_points": [
    {"between": ["z2", "z4"], "zone": "z3", "width": "narrow"}
  ],
  "flanking_routes": [
    {"from": "z1", "to": "z4", "via": ["z5", "z6"], "avoids": ["z3"]}
  ]
}
```

### Web-Based Tactical Editor

Single-page app for reviewing and tweaking auto-generated zones:

**Layer 1 — Base map:** GLB mesh projected top-down (walls/rooms visible) +
nav area polygons from JSON.

**Layer 2 — Zones:** Color-coded zone clusters. Click areas to reassign
between zones. Click zones to see/edit properties.

**Layer 3 — Annotations:** Sight lines, choke point markers, flanking routes,
objective locations. Add manual notes ("sniper nest", "ambush corner").

**Tech:** Three.js (loads GLB natively), nav mesh JSON overlay, saves to
tactical JSON.

---

## Scaling to Many Bots

With 20-30 bots across 5-7 squads:

| Layer | Work per cycle | Scale factor |
|-------|---------------|-------------|
| LLM | 5-7 squad summaries in prompt | O(squads), not O(bots) |
| Python | Loop over 5-7 squads | Negligible CPU |
| C++ | Per-bot tick-rate execution | Already handled natively |

Squad-level decisions compress the problem from O(n_bots) to O(n_squads).

---

## Bot Senses — Reading Vision and Events

The native bot subsystems (vision, body, locomotion) continue running untouched.
The C++ Metamod extension **reads their output** through public INextBot interfaces
and aggregates it into zone-level intelligence for Python.

### Reading Vision (No Hooks Required)

The reference NextBot headers (`references/NextBot/`) expose the full IVision API
as public virtual methods. The Metamod extension calls these directly:

```cpp
IVision *vision = bot->GetVisionInterface();

// Primary threat
CKnownEntity *threat = vision->GetPrimaryKnownThreat();
if (threat) {
    Vector pos       = threat->GetLastKnownPosition();
    bool   visible   = threat->IsVisibleNow();
    float  lastSeen  = threat->GetTimeSinceLastSeen();
}

// All known entities
int count = vision->GetKnownCount();
for (int i = 0; i < count; i++) {
    CKnownEntity *known = vision->GetKnown(i);
    if (!known->IsObsolete()) {
        // entity, position, visibility, freshness
    }
}
```

The native vision system does all the hard work — FOV, LOS, silhouette recognition,
threat scoring, recognition delay. We just read the results.

### Other Readable Bot State

| Data | Interface | Method |
|------|-----------|--------|
| Primary threat | `IVision` | `GetPrimaryKnownThreat()` |
| All known enemies | `IVision` | `GetKnownCount()`, `GetKnown(i)` |
| Enemy last known position | `CKnownEntity` | `GetLastKnownPosition()` |
| Enemy currently visible? | `CKnownEntity` | `IsVisibleNow()` |
| Time since last seen | `CKnownEntity` | `GetTimeSinceLastSeen()` |
| Stale/obsolete? | `CKnownEntity` | `IsObsolete()` |
| Arousal level | `IBody` (CINSBotBody) | `GetArousalLevel()` / arousal float |
| Is in cover? | `CINSNextBot` | `IsInCover()` |
| Current posture | `IBody` | `GetPosture()` |
| Active weapon | `CBaseCombatCharacter` | `GetActiveWeapon()` |
| Ammo ratio | `CINSNextBot` | `GetActiveWeaponAmmoRatio()` |

None of these require hooks — they're standard interface calls on the bot entity.

### Event Hooks (Only 2 Needed)

For events that polling doesn't catch, hook at the Intention level to intercept
NWI event responders as they propagate through the action hierarchy:

| Event | Signature | What it tells us |
|-------|-----------|-----------------|
| `OnOtherKilled` | `(CBaseCombatCharacter*)` | Teammate/enemy died, who and where |
| `OnInjured` | `(CBaseEntity*, CGameTrace*)` | Bot took damage, from which direction |

Other events are less critical for strategic decisions:
- `OnWeaponFired` / `OnHeardFootsteps` — vision system already tracks resulting threats
- `OnBlinded` — can be polled via body state
- `player_death`, `point_captured` — standard SM game events, no hook needed

### Intelligence Aggregation (C++ → Python)

The C++ extension does NOT send per-tick per-bot vision data. It aggregates into
zone-level summaries and sends only when things change:

```cpp
void TeamCoordinator::UpdateIntelligence() {
    for (auto& squad : squads) {
        ZoneEnemyMap current_contacts;

        for (auto bot_id : squad.members) {
            INextBot *bot = GetBot(bot_id);
            IVision *vision = bot->GetVisionInterface();

            for (int i = 0; i < vision->GetKnownCount(); i++) {
                CKnownEntity *known = vision->GetKnown(i);
                if (known->IsObsolete()) continue;

                Vector pos = known->GetLastKnownPosition();
                int zone = PosToZone(pos);  // lookup from tactical profile
                current_contacts[zone]++;
            }
        }

        // Only send when contacts change
        if (current_contacts != squad.last_contacts) {
            SendIntelUpdate(squad.id, current_contacts);
            squad.last_contacts = current_contacts;
        }
    }
}
```

### INTEL Message Format (C++ → Python)

```
INTEL squad_id event_type zone_id details
```

Examples:
```
INTEL 1 CONTACT z4 3_enemies
INTEL 1 LOST_CONTACT z4
INTEL 2 TAKING_FIRE z3 from_z6
INTEL 2 CASUALTY z3 bot7_killed
INTEL 0 OBJECTIVE_LOST B
```

Python sees "Squad A reports 3 enemies in courtyard" — not raw CKnownEntity data.

### Full Sense Data Flow

```
Engine (per tick)
 └─ CINSBotVision::Update()          ← runs natively, no hook
     └─ updates CKnownEntity list    ← we READ this

C++ TeamCoordinator (per tick)
 ├─ polls each bot's IVision         ← direct interface call
 ├─ maps enemy positions → zones     ← PosToZone() lookup
 ├─ aggregates per squad             ← zone-level summary
 ├─ diffs against last report        ← only send changes
 └─ sends INTEL messages → Python    ← via UDP bridge

Python Tactical Planner
 ├─ maintains world_state.enemies    ← zone → count + freshness
 ├─ triggers LLM on significant change  ← "new contact cluster in zone X"
 └─ adjusts tactic assignments       ← react to threats
```

### What Each Layer Knows

| | Bot positions | Enemy positions | Zone names | Tactics | Strategy |
|---|:---:|:---:|:---:|:---:|:---:|
| **C++** | exact coords | exact coords (from IVision) | zone lookup table | active roles | - |
| **Python** | zone-level | zone-level (from INTEL) | full tactical profile | assigns roles | receives from LLM |
| **LLM** | - | zone-level (from SITREP) | map context | - | decides strategy |

---

## Tactic Evaluation — Positional Success, Not Kills

### The Problem

If the LLM evaluates tactics by kill count or K/D ratio, it will misinterpret
difficulty-tuned misses as bad strategy. A suppressor who misses every shot but
keeps enemies pinned while the flankers take the point executed a GOOD tactic.

### Evaluation Criteria

The LLM only sees **positional and objective outcomes**, never kill/damage stats:

| Feed to LLM (good metrics) | Hide from LLM (execution details) |
|---|---|
| Did the squad reach the overwatch position? | How many kills did they get? |
| Did suppressive fire pin enemies in cover? | Did the suppressor hit anyone? |
| Did the flanking squad reach the objective? | What was the K/D ratio? |
| Was the objective captured/held? | How much damage was dealt? |
| Did the squad survive the advance? | Individual aim accuracy |

### Tactic Outcome Recording

```sql
CREATE TABLE tactic_outcomes (
    map              TEXT,
    round            INT,
    tactic_type      TEXT,      -- suppress_advance, bounding_overwatch, etc.
    target_zone      TEXT,      -- what we were trying to hold/take
    squad_weapons    TEXT,      -- "LMG,rifle,rifle"
    approach_zones   TEXT,      -- route taken (JSON array)

    -- Positional outcomes (fed to LLM)
    objective_held   BOOL,      -- did we hold/take the goal?
    position_reached BOOL,      -- did squads get where they needed to be?
    enemy_pinned     BOOL,      -- did suppression keep enemies in cover?
    squad_survived   BOOL,      -- did the squad make it through?
    duration_sec     FLOAT,     -- how long the tactic ran

    -- Execution details (NOT fed to LLM, used for ConVar tuning only)
    friendly_killed  INT,
    enemy_killed     INT,
    shots_fired      INT,
    shots_hit        INT,

    timestamp        TIMESTAMP
);
```

### Engagement Recording (For Zone Learning)

```sql
CREATE TABLE engagements (
    map         TEXT,
    round       INT,
    killer_zone TEXT,
    victim_zone TEXT,
    weapon      TEXT,
    headshot    BOOL,
    timestamp   TIMESTAMP
);
```

Aggregated into zone ratings: "attackers pushing through main_hallway die 70% of
the time" tells the LLM the zone is dangerous to push through, without revealing
per-engagement accuracy details.

### Persistent Storage

| Data | Storage | Lifetime |
|------|---------|----------|
| Per-tick telemetry | tmpfs PostgreSQL (current) | Disposable per session |
| Engagement records | Persistent SQLite/DuckDB per map | Accumulates forever |
| Tactic outcomes | Same persistent DB | Accumulates forever |
| Zone ratings | Baked into `{map}_tactical.json` | Re-exported periodically |

### What the LLM Sees After Learning

```
ZONES (ministry):
- courtyard: open, exposed
  EXPERIENCE: dangerous for attackers (30% survive pushing through)
  strong for defenders holding east_balcony overwatch
- main_hallway: corridor, choke point
  EXPERIENCE: squad pushes succeed only 15% — flanking routes preferred
- back_alley: narrow, moderate cover
  EXPERIENCE: 72% success rate as flanking approach to courtyard

TACTIC HISTORY:
- suppress_advance via main_hallway: 2/13 success (AVOID)
- suppress_advance via back_alley:   8/11 success (PREFERRED)
- crossfire from balcony+rooftop:    9/10 success (STRONG)
```

### Difficulty Separation

Difficulty is controlled entirely by existing ConVars, invisible to the LLM:

```
bot_targeting_noise_*          ← how much bots miss
bot_attackdelay_*              ← reaction time before firing
bot_aim_aimtracking_*          ← how well they track moving targets
bot_vis_recognizetime_*        ← how fast they spot you
ins_bot_arousal_*              ← stress-based performance degradation
```

The LLM plans smart tactics. ConVars make bots miss. The LLM never knows they
missed — it only sees whether the tactic worked positionally.

```
LLM:     "crossfire on courtyard from balcony + rooftop"    ← smart
Python:  assigns positions + roles                           ← correct positions
C++:     bots take positions, start firing                   ← native actions
ConVars: bots miss 60% of shots                              ← fun for players
LLM:     sees "enemy pinned, objective held"                 ← tactic worked
```

---

## Game Design — Fun Over Winning

### No Adaptive Difficulty

Insurgency coop already has built-in catch-up mechanics:
- Players get 6 rounds per objective
- More reinforcement waves on failed attempts
- Supply points accumulate

Adjusting bot strategy based on win rate would fight against this existing design.
Skilled players joining and breezing through is fine — that's the game working
as intended.

### LLM Objective: Be Varied, Not Optimal

The LLM is a **game director**, not an optimizer. Its goal is interesting rounds,
not maximum win rate.

```
SYSTEM PROMPT:
You command bot squads defending against human attackers in Insurgency coop.

Rules:
- NEVER stack all squads on the capture point
- Always keep at least one squad on a forward position or flank
- Vary defensive positions between rounds — don't repeat the same setup
- If you lose a round, don't just add more bots to the point —
  try a different approach (ambush, counter-attack, forward defense)
- Use the map: choke points, flanking routes, elevated positions
```

No win-rate tracking, no scaling. Just "be varied and use the whole map."

### What Makes Bot Tactics Fun

**Telegraphing** — give players time to react:
- Suppressive fire starts 1-2s before the advance begins
- Bots call out before breaching (CINSBotChatter system exists)
- Grenade warning delay gives time to move

**Commitment** — bots commit to plans, creating counter-play windows:
- Once a squad starts advancing, they don't instantly retreat when spotted
- A flanking squad follows the route even if the player relocates
- Players who read the tactic can outplay it

**Imperfect information** — bots aren't omniscient:
- Squads only know what their own members see (native IVision behavior)
- Intel has delay before reaching other squads
- Lost contact means genuinely lost

**Exploitable patterns** — players learn and adapt:
- If bots flank from back_alley twice, players start watching it
- LLM naturally varies because it's told to, creating an evolving meta
- Experienced players feel rewarded for reading the bots

### The Variation Problem

The real enemy of fun is predictability. With 3-4 viable defensive setups per
objective and an LLM that's told to vary, each round plays differently:

```
Round 1: Forward defense at main_hallway choke + ambush in back_alley
Round 2: Crossfire from balcony + rooftop, light presence at point
Round 3: Counter-attack squad hidden behind point, springs after capture starts
Round 4: Spread defense, one squad per approach route
```

Players can't memorize a single strategy. Each attempt at an objective is a
fresh tactical puzzle.

---

## Voice Callouts — Tactical Telegraphing

Bots use Insurgency's concept-based voice system to call out tactical actions.
This serves as **telegraphing** — players hear coordination happening and get
time to react, which is key to making smart tactics feel fair.

### How the Voice System Works

```
Concept ID (integer)
    → CINSPlayer::SpeakConceptIfAllowed()    [vtable + 0x800]
    → Response Rules Engine
    → botchatter.db lookup
    → Select wav file + play to clients
    → Fire OnSpokeConcept event to all bots
```

The engine handles everything: file selection, playback, replication to clients.
The C++ extension just calls one function with a concept ID.

### Triggering Voice From the Metamod Extension

Direct virtual call, no hooks:

```cpp
void TeamCoordinator::AssignTactic(Squad& squad, Tactic& tactic) {
    for (auto& assignment : tactic.roles) {
        INextBot *bot = GetBot(assignment.bot_id);

        switch (assignment.role) {
        case ROLE_SUPPRESS:
            bot->BotSpeakConceptIfAllowed(CONCEPT_COVERING, NULL, 0, NULL);
            break;
        case ROLE_ADVANCE:
            bot->BotSpeakConceptIfAllowed(CONCEPT_ON_MY_WAY, NULL, 0, NULL);
            break;
        case ROLE_RETREAT:
            bot->BotSpeakConceptIfAllowed(CONCEPT_PINNED_DOWN, NULL, 0, NULL);
            break;
        case ROLE_BREACH:
            bot->BotSpeakConceptIfAllowed(CONCEPT_FRAG_OUT, NULL, 0, NULL);
            break;
        }
    }
}
```

### Existing Callouts in botchatter.db

The game already has 50+ voice concepts. Many map directly to tactical roles:

| Tactic Role | Existing Concept | What the player hears |
|-------------|-----------------|----------------------|
| Suppress | `CoveringFriend` / `CoverMe` | "Covering!" / "Cover me!" |
| Advance | `OnMyWay` | "Moving up!" |
| Hold position | `WaitingHere` | "Holding here!" |
| Retreat | `PinnedDown` / `Help` | "Pinned down!" / "Taking fire!" |
| Enemy spotted | `EnemySpotted` | "Contact!" |
| Area clear | `ClearedArea` / `Clear` | "Clear!" |
| Man down | `KilledFriend` (event-driven) | "Man down!" |
| Reinforcing | `FollowingSir` | "On my way!" |
| Sniper call | `SniperWarning` | "Sniper!" |

**Place names** are also in botchatter.db: Bridge, Market, Courtyard, Kitchen,
Tower, Tunnel, etc. These can be appended to callouts for location context.

### Custom Voice Lines

For callouts that don't exist yet (e.g., "flank him", "sweep the area"):

**Option A: Remap existing wav files (easiest, no client downloads)**

Insurgency has hundreds of recorded voice lines in the VPK archives — "Go go go!",
"Fall back!", "Push up!", "Move move move!" — many are underused. Remap them
to new concept entries in `botchatter.db`:

```
Chatter FlankOrder
    Radio RADIO_AFFIRMATIVE
    go_around.wav
    push_up.wav
    move_move.wav
End

Chatter SweepOrder
    clear_the_room.wav
    move_in.wav
End
```

`botchatter.db` is **server-side only** — editing it works immediately for all
clients. Clients already have the wav files from the base game.

**Option B: Custom wav files**

Record or source new lines. Clients need the files via `sv_downloadurl` or a
custom VPK. More work, but allows purpose-built callouts.

**Option C: Hybrid**

Use existing wav files for most callouts, add a few custom files for
tactic-specific lines that have no good existing match.

### Voice Integration in the Tactic Flow

```
LLM:     "Squad A suppress courtyard, Squad B flank via back_alley"
              │
Python:  assigns roles, sends TACTIC message to C++
              │
C++ TeamCoordinator:
  ├─ Bot_3 (LMG):   BotSpeak("Covering!")     → takes balcony position
  ├─ Bot_5 (Rifle):  BotSpeak("Moving up!")    → starts flanking
  └─ Bot_7 (Rifle):  BotSpeak("Moving up!")    → follows Bot_5
              │
Players hear: coordinated callouts → know something's coming
              │
  Bot_5 reaches flank:  BotSpeak("Contact!")   → engages
  Bot_3 on balcony:     [suppressive fire]     → pins players
              │
  Bot_5 killed:
  Bot_7:                BotSpeak("Man down!")
  C++ sends INTEL → Python reassigns Bot_9
  Bot_9:                BotSpeak("On my way!") → reinforces
```

Players experience a squad that **sounds** coordinated. The callouts give
tactical information the player can act on — hear "Moving up!" from the
flank, turn to face it, counter the maneuver. This is the telegraphing
that makes smart tactics fun instead of oppressive.

### Voice Spam Prevention

The native `SpeakConceptIfAllowed()` already has built-in cooldowns — it
won't play the same concept twice in rapid succession. The TeamCoordinator
should also throttle:

- Max 1 callout per bot per tactic assignment
- Stagger callouts by 0.5-1s between squad members
- Don't call out routine movements, only tactic-relevant actions
- Event callouts (contact, man down) use the native chatter system

---

## Changes vs Current Architecture

| Component | Current | New |
|-----------|---------|-----|
| Python AI | Per-bot pathfinding + movement | Squad strategy + tactic planning |
| SM Bridge | Velocity injection per bot | Tactic assignments per squad |
| C++ | Nothing (native AI killed via Intention hook) | TeamCoordinator + role→action mapping |
| LLM | Not used | Event-driven strategist |
| Map data | Clearance for steering only | Tactical profiles for LLM context |

---

## Related Documents

- [team_coordination_design.md](team_coordination_design.md) — C++ Metamod extension details, native action inventory, constructor signatures, symbol reference
- [BOT_AI_ARCHITECTURE.md](BOT_AI_ARCHITECTURE.md) — Full reverse engineering report of original bot AI
- [action_transition_graph.md](action_transition_graph.md) — Complete state transition diagram
- [class_data_layouts.md](class_data_layouts.md) — Memory layouts for all bot action classes
