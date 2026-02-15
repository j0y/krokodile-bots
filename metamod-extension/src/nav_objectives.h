#ifndef _SMARTBOTS_NAV_OBJECTIVES_H_
#define _SMARTBOTS_NAV_OBJECTIVES_H_

// Runtime objective scanner: discovers capture points, weapon caches, and
// spawn zones from engine entities.  No external data files needed.

struct ObjectiveInfo {
    float pos[3];
    int   order;       // 1-based sequence index
    bool  isCapture;   // true = capture, false = destroy (weapon cache)
    char  name[64];    // targetname from entity
};

struct SpawnZoneInfo {
    float pos[3];
    int   team;        // 2 = Security (attacker), 3 = Insurgent (defender)
    int   phase;       // phase number (1-based)
};

static const int MAX_OBJECTIVES = 16;
static const int MAX_SPAWNZONES = 32;

// Initialize with IServerTools interface pointer (resolved by caller).
// Call once during plugin Load().  Returns false if serverTools is null.
bool NavObjectives_Init(void *serverTools);

// Scan world entities for objectives and spawns.
// Call once after the map has fully loaded (e.g. first GameFrame tick).
// Safe to call multiple times — rescans each time.
void NavObjectives_Scan();

// True after a successful Scan found at least one objective.
bool NavObjectives_IsReady();

// Number of objectives discovered (ordered by sequence).
int NavObjectives_Count();

// Get objective by 0-based index (ordered by sequence).  Returns nullptr if out of range.
const ObjectiveInfo *NavObjectives_Get(int index);

// Current "active" objective index (0-based), derived from objectives-lost count.
// In coop checkpoint: defenders protect this one next.
int NavObjectives_CurrentIndex();

// Get the Security (attacker) spawn centroid for the first phase.
// Returns false if no spawn data found.
bool NavObjectives_GetAttackerSpawn(float &x, float &y, float &z);

// Get the approach point (midpoint between attacker spawn and first objective).
// Returns false if either is missing.
bool NavObjectives_GetApproachPoint(float &x, float &y, float &z);

// Clear all scanned data (map change).
void NavObjectives_Reset();

#endif // _SMARTBOTS_NAV_OBJECTIVES_H_
