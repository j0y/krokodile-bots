#include "extension.h"
#include "nav_flanking.h"
#include "sig_resolve.h"

#include <cstring>
#include <cmath>
#include <queue>
#include <unordered_map>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro in extension.cpp

// Forward declarations from Source engine (we use as opaque pointers)
class CNavArea;
class CNavMesh;

// ---- Resolved function pointers ----

// CNavMesh::GetNearestNavArea(Vector const&, bool anyZ, float maxDist, bool checkLOS, bool checkGround, int team)
typedef CNavArea *(*GetNearestNavAreaFn)(void *thisNavMesh, const float *pos,
                                         bool anyZ, float maxDist,
                                         bool checkLOS, bool checkGround, int team);

// CNavArea::IsPotentiallyVisible(CNavArea const*) const
typedef bool (*IsPotentiallyVisibleFn)(void *thisArea, const void *otherArea);

// CNavArea::IsBlocked(int teamID, bool ignoreNavBlockers) const
typedef bool (*IsBlockedFn)(void *thisArea, int teamID, bool ignoreNavBlockers);

static void          **s_ppTheNavMesh = nullptr;
static GetNearestNavAreaFn s_fnGetNearestNavArea = nullptr;
static IsPotentiallyVisibleFn s_fnIsPotentiallyVisible = nullptr;
static IsBlockedFn    s_fnIsBlocked = nullptr;

static bool s_navReady = false;
static bool s_navInitialized = false;
static bool s_hasVisData = false;  // true if IsPotentiallyVisible returns meaningful results
static bool s_visDataChecked = false;

// ---- CNavArea opaque field access (offset-based) ----
// CNavArea layout on 32-bit Linux: vtable at +0, CNavAreaCriticalData starts at +4
// CNavAreaCriticalData: m_center at +40 from struct start = +44 from object
// m_attributeFlags: +80 from struct start = +84 from object
// m_connect[4]: +84 from struct start = +88 from object
// m_id: after CNavAreaCriticalData

static const int kOff_Center     = 44;   // Vector (3 floats)
static const int kOff_AttrFlags  = 84;   // int
static const int kOff_Connect    = 88;   // 4x NavConnectVector (one per direction)
static const int kOff_ID         = 136;  // unsigned int

// NavConnectVector is CUtlVectorUltraConservative<NavConnect>
// Single pointer to Data_t { int m_Size; NavConnect m_Elements[]; }
// NavConnect = { CNavArea *area; float length; } = 8 bytes on 32-bit
static const int kSizeofNavConnectVec = 4;  // single pointer
static const int kSizeofNavConnect    = 8;  // area ptr + float length

inline const float *NavArea_GetCenter(const void *area)
{
    return reinterpret_cast<const float *>(
        reinterpret_cast<const char *>(area) + kOff_Center);
}

inline unsigned int NavArea_GetID(const void *area)
{
    return *reinterpret_cast<const unsigned int *>(
        reinterpret_cast<const char *>(area) + kOff_ID);
}

inline int NavArea_GetAdjacentCount(const void *area, int dir)
{
    // m_connect[dir] is a CUtlVectorUltraConservative: pointer to Data_t
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data)
        return 0;
    // Data_t starts with int m_Size
    return *reinterpret_cast<const int *>(data);
}

inline void *NavArea_GetAdjacentArea(const void *area, int dir, int index)
{
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data)
        return nullptr;
    // Data_t: { int m_Size; NavConnect m_Elements[]; }
    // NavConnect[index] at offset 4 + index * 8
    const char *elements = reinterpret_cast<const char *>(data) + 4;
    return *reinterpret_cast<void *const *>(elements + index * kSizeofNavConnect);
}

// ---- Per-bot flanking path state ----

static const int MAX_WAYPOINTS = 32;
static const int MAX_EDICT = 33;  // edicts 1..32

struct FlankPath {
    float waypoints[MAX_WAYPOINTS][3];
    int waypointCount;
    int currentWaypoint;
    float enemyPos[3];     // enemy position that generated this path
    float replanTime;      // gpGlobals->curtime when last computed
    bool active;
};

static FlankPath s_paths[MAX_EDICT];

// ---- ConVars ----

#include <convar.h>

static ConVar s_cvarFlankEnabled("smartbots_flank_enabled", "1", 0,
    "Enable nav mesh flanking for bots without visible enemies");
static ConVar s_cvarFlankVisPenalty("smartbots_flank_vis_penalty", "2000", 0,
    "Extra cost (units) added to nav areas visible to the threat");
static ConVar s_cvarFlankReplan("smartbots_flank_replan_seconds", "3.0", 0,
    "Seconds between flanking path replans");

// ---- Nav readiness check ----

static void *GetNavMesh()
{
    if (!s_ppTheNavMesh)
        return nullptr;
    return *s_ppTheNavMesh;
}

static bool EnsureNavReady()
{
    if (s_navReady)
        return true;

    void *navMesh = GetNavMesh();
    if (!navMesh)
        return false;

    // Try to resolve a nav area to confirm the mesh is loaded
    float testPos[3] = {0.0f, 0.0f, 0.0f};
    CNavArea *testArea = s_fnGetNearestNavArea(navMesh, testPos, true, 10000.0f, false, false, 0);
    if (!testArea)
        return false;

    s_navReady = true;
    META_CONPRINTF("[SmartBots] NavFlanking: nav mesh ready (test area ID %u)\n",
                   NavArea_GetID(testArea));

    return true;
}

// Check if vis data is loaded by testing IsPotentiallyVisible on adjacent areas.
// If all pairs return false, vis data is missing.
static void CheckVisData()
{
    if (s_visDataChecked)
        return;
    s_visDataChecked = true;

    void *navMesh = GetNavMesh();
    if (!navMesh || !s_fnIsPotentiallyVisible)
    {
        s_hasVisData = false;
        return;
    }

    // Find a nav area and check visibility against its neighbors
    float testPos[3] = {0.0f, 0.0f, 0.0f};
    CNavArea *area = s_fnGetNearestNavArea(navMesh, testPos, true, 10000.0f, false, false, 0);
    if (!area)
    {
        s_hasVisData = false;
        return;
    }

    int tested = 0;
    int visibleCount = 0;
    for (int dir = 0; dir < 4 && tested < 8; dir++)
    {
        int count = NavArea_GetAdjacentCount(area, dir);
        for (int i = 0; i < count && tested < 8; i++)
        {
            void *neighbor = NavArea_GetAdjacentArea(area, dir, i);
            if (!neighbor)
                continue;
            tested++;
            if (s_fnIsPotentiallyVisible(area, neighbor))
                visibleCount++;
        }
    }

    // Adjacent areas should almost always be visible to each other.
    // If none are, vis data is missing.
    s_hasVisData = (visibleCount > 0);
    META_CONPRINTF("[SmartBots] NavFlanking: vis data %s (tested %d pairs, %d visible)\n",
                   s_hasVisData ? "AVAILABLE" : "MISSING (penalty disabled)",
                   tested, visibleCount);
}

// ---- Custom A* pathfinder ----

static const int MAX_ITERATIONS = 4096;

struct AStarNode {
    void *area;
    float gCost;
    float fCost;

    bool operator>(const AStarNode &other) const { return fCost > other.fCost; }
};

static float VecDist(const float *a, const float *b)
{
    float dx = a[0] - b[0];
    float dy = a[1] - b[1];
    float dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

// Find a flanking path from startArea to goalArea, avoiding areas visible to threatArea.
// Returns number of waypoints written (0 = no path found).
static int FindFlankPath(void *startArea, void *goalArea, void *threatArea,
                         float waypoints[][3], int maxWaypoints)
{
    if (!startArea || !goalArea)
        return 0;

    float visPenalty = s_cvarFlankVisPenalty.GetFloat();
    bool useVisCheck = s_hasVisData && s_fnIsPotentiallyVisible && threatArea;

    const float *goalCenter = NavArea_GetCenter(goalArea);

    // A* open list (min-heap by fCost)
    std::priority_queue<AStarNode, std::vector<AStarNode>, std::greater<AStarNode>> openList;

    // Best g-cost per area
    std::unordered_map<void *, float> gCosts;
    gCosts.reserve(256);

    // Parent tracking for path reconstruction
    std::unordered_map<void *, void *> parents;
    parents.reserve(256);

    // Seed start
    const float *startCenter = NavArea_GetCenter(startArea);
    float hStart = VecDist(startCenter, goalCenter);
    openList.push({startArea, 0.0f, hStart});
    gCosts[startArea] = 0.0f;

    int iterations = 0;
    bool found = false;

    while (!openList.empty() && iterations < MAX_ITERATIONS)
    {
        iterations++;
        AStarNode current = openList.top();
        openList.pop();

        if (current.area == goalArea)
        {
            found = true;
            break;
        }

        // Skip if we've already found a better path to this node
        auto it = gCosts.find(current.area);
        if (it != gCosts.end() && current.gCost > it->second)
            continue;

        const float *curCenter = NavArea_GetCenter(current.area);

        // Expand neighbors (4 directions: N, E, S, W)
        for (int dir = 0; dir < 4; dir++)
        {
            int adjCount = NavArea_GetAdjacentCount(current.area, dir);
            for (int i = 0; i < adjCount; i++)
            {
                void *neighbor = NavArea_GetAdjacentArea(current.area, dir, i);
                if (!neighbor)
                    continue;

                // Skip blocked areas
                if (s_fnIsBlocked && s_fnIsBlocked(neighbor, 0, false))
                    continue;

                const float *neighborCenter = NavArea_GetCenter(neighbor);
                float edgeCost = VecDist(curCenter, neighborCenter);

                // Visibility penalty: penalize areas visible to threat
                if (useVisCheck && s_fnIsPotentiallyVisible(threatArea, neighbor))
                    edgeCost += visPenalty;

                float tentativeG = current.gCost + edgeCost;

                auto existingIt = gCosts.find(neighbor);
                if (existingIt != gCosts.end() && tentativeG >= existingIt->second)
                    continue;

                gCosts[neighbor] = tentativeG;
                parents[neighbor] = current.area;

                float h = VecDist(neighborCenter, goalCenter);
                openList.push({neighbor, tentativeG, tentativeG + h});
            }
        }
    }

    if (!found)
        return 0;

    // Reconstruct path (goal → start), then reverse
    void *path[MAX_WAYPOINTS + 1];
    int pathLen = 0;
    void *node = goalArea;
    while (node && pathLen <= MAX_WAYPOINTS)
    {
        path[pathLen++] = node;
        if (node == startArea)
            break;
        auto it = parents.find(node);
        if (it == parents.end())
            break;
        node = it->second;
    }

    // Reverse into output (skip startArea — bot is already there)
    int wpCount = 0;
    for (int i = pathLen - 2; i >= 0 && wpCount < maxWaypoints; i--)
    {
        const float *c = NavArea_GetCenter(path[i]);
        waypoints[wpCount][0] = c[0];
        waypoints[wpCount][1] = c[1];
        waypoints[wpCount][2] = c[2];
        wpCount++;
    }

    return wpCount;
}

// ---- Status ConCommand ----

static void CC_FlankStatus(const CCommand &args)
{
    META_CONPRINTF("[SmartBots] NavFlanking status:\n");
    META_CONPRINTF("  Initialized: %s\n", s_navInitialized ? "yes" : "no");
    META_CONPRINTF("  Nav ready: %s\n", s_navReady ? "yes" : "no");
    META_CONPRINTF("  Vis data: %s\n", s_visDataChecked ? (s_hasVisData ? "yes" : "missing") : "not checked");
    META_CONPRINTF("  Enabled: %s\n", s_cvarFlankEnabled.GetBool() ? "yes" : "no");
    META_CONPRINTF("  Vis penalty: %.0f\n", s_cvarFlankVisPenalty.GetFloat());
    META_CONPRINTF("  Replan interval: %.1fs\n", s_cvarFlankReplan.GetFloat());

    int activePaths = 0;
    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (s_paths[i].active)
            activePaths++;
    }
    META_CONPRINTF("  Active paths: %d\n", activePaths);

    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (s_paths[i].active)
        {
            FlankPath &p = s_paths[i];
            META_CONPRINTF("  Bot %d: wp %d/%d, enemy (%.0f,%.0f,%.0f)\n",
                           i, p.currentWaypoint, p.waypointCount,
                           p.enemyPos[0], p.enemyPos[1], p.enemyPos[2]);
        }
    }
}

static ConCommand s_cmdFlankStatus("smartbots_flank_status", CC_FlankStatus,
    "Show nav mesh flanking system status");

// ---- Public API ----

bool NavFlanking_Init(uintptr_t serverBase)
{
    // Resolve TheNavMesh pointer
    s_ppTheNavMesh = reinterpret_cast<void **>(
        serverBase + ServerOffsets::TheNavMesh);

    // Resolve function pointers
    s_fnGetNearestNavArea = reinterpret_cast<GetNearestNavAreaFn>(
        serverBase + ServerOffsets::CNavMesh_GetNearestNavArea);

    s_fnIsPotentiallyVisible = reinterpret_cast<IsPotentiallyVisibleFn>(
        serverBase + ServerOffsets::CNavArea_IsPotentiallyVisible);

    s_fnIsBlocked = reinterpret_cast<IsBlockedFn>(
        serverBase + ServerOffsets::CNavArea_IsBlocked);

    // Clear all paths
    memset(s_paths, 0, sizeof(s_paths));

    s_navInitialized = true;
    s_navReady = false;
    s_visDataChecked = false;
    s_hasVisData = false;

    META_CONPRINTF("[SmartBots] NavFlanking: initialized (TheNavMesh=%p, GetNearestNavArea=%p)\n",
                   (void *)s_ppTheNavMesh, (void *)s_fnGetNearestNavArea);

    return true;
}

void NavFlanking_Update(const int *botEdicts, void *const *botEntities,
                        const float (*botPositions)[3], int botCount,
                        const float (*enemyPositions)[3], int enemyCount)
{
    if (!s_navInitialized || !s_cvarFlankEnabled.GetBool())
        return;

    if (!EnsureNavReady())
        return;

    if (!s_visDataChecked)
        CheckVisData();

    void *navMesh = GetNavMesh();
    if (!navMesh)
        return;

    float curtime = gpGlobals->curtime;
    float replanInterval = s_cvarFlankReplan.GetFloat();

    for (int b = 0; b < botCount; b++)
    {
        int edictIdx = botEdicts[b];
        if (edictIdx < 1 || edictIdx >= MAX_EDICT)
            continue;

        FlankPath &path = s_paths[edictIdx];

        // No enemies known — deactivate path
        if (enemyCount == 0)
        {
            path.active = false;
            continue;
        }

        // Find nearest enemy to this bot
        float bestDist2 = 1e18f;
        int bestEnemy = -1;
        for (int e = 0; e < enemyCount; e++)
        {
            float dx = enemyPositions[e][0] - botPositions[b][0];
            float dy = enemyPositions[e][1] - botPositions[b][1];
            float d2 = dx * dx + dy * dy;
            if (d2 < bestDist2)
            {
                bestDist2 = d2;
                bestEnemy = e;
            }
        }
        if (bestEnemy < 0)
            continue;

        // Check if replan needed
        bool needReplan = false;
        if (!path.active)
        {
            needReplan = true;
        }
        else if (curtime - path.replanTime >= replanInterval)
        {
            needReplan = true;
        }
        else
        {
            // Enemy moved significantly?
            float dx = enemyPositions[bestEnemy][0] - path.enemyPos[0];
            float dy = enemyPositions[bestEnemy][1] - path.enemyPos[1];
            if (dx * dx + dy * dy > 200.0f * 200.0f)
                needReplan = true;
        }

        if (!needReplan)
            continue;

        // Resolve nav areas for bot and enemy
        CNavArea *botArea = s_fnGetNearestNavArea(
            navMesh, botPositions[b], true, 300.0f, false, false, 0);
        CNavArea *enemyArea = s_fnGetNearestNavArea(
            navMesh, enemyPositions[bestEnemy], true, 300.0f, false, false, 0);

        if (!botArea || !enemyArea)
        {
            path.active = false;
            continue;
        }

        // If bot is already at the enemy area, no flanking needed
        if (botArea == enemyArea)
        {
            path.active = false;
            continue;
        }

        // Run A* with visibility penalty
        float waypoints[MAX_WAYPOINTS][3];
        int wpCount = FindFlankPath(botArea, enemyArea, enemyArea, waypoints, MAX_WAYPOINTS);

        if (wpCount == 0)
        {
            path.active = false;
            continue;
        }

        // Store path
        memcpy(path.waypoints, waypoints, wpCount * sizeof(float[3]));
        path.waypointCount = wpCount;
        path.currentWaypoint = 0;
        path.enemyPos[0] = enemyPositions[bestEnemy][0];
        path.enemyPos[1] = enemyPositions[bestEnemy][1];
        path.enemyPos[2] = enemyPositions[bestEnemy][2];
        path.replanTime = curtime;
        path.active = true;
    }

    // Advance waypoints for all active paths
    for (int b = 0; b < botCount; b++)
    {
        int edictIdx = botEdicts[b];
        if (edictIdx < 1 || edictIdx >= MAX_EDICT)
            continue;

        FlankPath &path = s_paths[edictIdx];
        if (!path.active || path.currentWaypoint >= path.waypointCount)
            continue;

        // Check if bot is close enough to current waypoint to advance
        float dx = botPositions[b][0] - path.waypoints[path.currentWaypoint][0];
        float dy = botPositions[b][1] - path.waypoints[path.currentWaypoint][1];
        float dist2 = dx * dx + dy * dy;

        if (dist2 < 64.0f * 64.0f)
        {
            path.currentWaypoint++;
            if (path.currentWaypoint >= path.waypointCount)
                path.active = false;
        }
    }
}

bool NavFlanking_GetTarget(int edictIndex, float &x, float &y, float &z)
{
    if (edictIndex < 1 || edictIndex >= MAX_EDICT)
        return false;

    FlankPath &path = s_paths[edictIndex];
    if (!path.active || path.currentWaypoint >= path.waypointCount)
        return false;

    x = path.waypoints[path.currentWaypoint][0];
    y = path.waypoints[path.currentWaypoint][1];
    z = path.waypoints[path.currentWaypoint][2];
    return true;
}

bool NavFlanking_IsActive(int edictIndex)
{
    if (edictIndex < 1 || edictIndex >= MAX_EDICT)
        return false;
    return s_paths[edictIndex].active;
}

void NavFlanking_Reset()
{
    memset(s_paths, 0, sizeof(s_paths));
    s_navReady = false;
    s_visDataChecked = false;
    s_hasVisData = false;
    META_CONPRINTF("[SmartBots] NavFlanking: reset\n");
}
