#include "extension.h"
#include "nav_flanking.h"
#include "sig_resolve.h"
#include "nav_objectives.h"

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

static const int kOff_Center     = 44;   // Vector (3 floats) — verified from binary (movss 0x2c)
static const int kOff_Connect    = 108;  // 4x NavConnectVector (one per direction) — verified from ConnectTo disasm

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

// Validate that a raw pointer value looks like a plausible heap/data address.
// On 32-bit Linux, valid pointers are typically > 0x10000 and < 0xF0000000.
inline bool IsPlausiblePtr(const void *p)
{
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    return addr > 0x10000 && addr < 0xF0000000;
}

inline int NavArea_GetAdjacentCount(const void *area, int dir)
{
    // m_connect[dir] is a CUtlVectorUltraConservative: pointer to Data_t
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data || !IsPlausiblePtr(data))
        return 0;
    // Data_t starts with int m_Size
    int count = *reinterpret_cast<const int *>(data);
    if (count < 0 || count > 256)
        return 0;  // sanity cap
    return count;
}

inline void *NavArea_GetAdjacentArea(const void *area, int dir, int index)
{
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data || !IsPlausiblePtr(data))
        return nullptr;
    // Data_t: { int m_Size; NavConnect m_Elements[]; }
    // NavConnect[index] at offset 4 + index * 8
    const char *elements = reinterpret_cast<const char *>(data) + 4;
    void *areaPtr = *reinterpret_cast<void *const *>(elements + index * kSizeofNavConnect);
    if (!IsPlausiblePtr(areaPtr))
        return nullptr;
    return areaPtr;
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

// ---- Per-bot flank assignment (team-level coordination) ----

struct FlankAssignment {
    int   targetEnemyIdx;   // index into enemy position array
    int   sectorIndex;      // which sector around that enemy
    int   totalSectors;     // total sectors for this enemy
    float stagingPos[3];    // A* goal position (~stagingDist from enemy)
    int   waveOrder;        // 0 = deploy now, 1+ = queued, -1 = holding (arrived)
    bool  assigned;
};

static FlankAssignment s_assignments[MAX_EDICT];
static bool s_holding[MAX_EDICT];  // true = reached staging position, holding

// Staleness tracking for reassignment
static float s_lastAssignTime = 0.0f;
static float s_lastAssignEnemyPos[32][3];
static int   s_lastAssignEnemyCount = 0;

// ---- ConVars ----

#include <convar.h>

static ConVar s_cvarFlankEnabled("smartbots_flank_enabled", "1", 0,
    "Enable nav mesh flanking for bots without visible enemies");
static ConVar s_cvarFlankVisPenalty("smartbots_flank_vis_penalty", "2000", 0,
    "Extra cost (units) added to nav areas visible to the threat");
static ConVar s_cvarFlankReplan("smartbots_flank_replan_seconds", "3.0", 0,
    "Seconds between flanking path replans");
static ConVar s_cvarFlankStagingDist("smartbots_flank_staging_dist", "400", 0,
    "Distance from enemy for flanking staging positions (units)");
static ConVar s_cvarFlankAssignSeconds("smartbots_flank_assign_seconds", "5.0", 0,
    "Interval between flank assignment recomputation (seconds)");
static ConVar s_cvarFlankLayerSpacing("smartbots_layer_spacing", "300", 0,
    "Distance between each bot's layered staging position (units)");
static ConVar s_cvarFlankDefendRatio("smartbots_flank_defend_ratio", "0.15", 0,
    "Fraction of bots that defend objective (rest flank)");

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
    const float *tc = NavArea_GetCenter(testArea);
    META_CONPRINTF("[SmartBots] NavFlanking: nav mesh ready (test area at %.0f,%.0f,%.0f)\n",
                   tc[0], tc[1], tc[2]);

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
    void *finalArea = nullptr;  // area we actually reached (may differ from goalArea)

    while (!openList.empty() && iterations < MAX_ITERATIONS)
    {
        iterations++;
        AStarNode current = openList.top();
        openList.pop();

        if (current.area == goalArea)
        {
            finalArea = goalArea;
            found = true;
            break;
        }

        // Early termination: if within ~200u of goal, accept as reached
        {
            const float *cc = NavArea_GetCenter(current.area);
            if (VecDist(cc, goalCenter) < 200.0f)
            {
                finalArea = current.area;
                found = true;
                break;
            }
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

    // Reconstruct path (reached area → start), then reverse
    void *path[MAX_WAYPOINTS + 1];
    int pathLen = 0;
    void *node = finalArea;
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

// ---- Team-level flank assignment ----

// Distribute bots across enemies with layered staging distances.
// All bots move simultaneously — each gets a unique sector angle AND distance.
static void AssignFlankTargets(const int *botEdicts, const float (*botPositions)[3],
                               int botCount,
                               const float (*enemyPositions)[3], int enemyCount)
{
    memset(s_assignments, 0, sizeof(s_assignments));

    if (botCount == 0 || enemyCount == 0)
        return;

    float stagingDist = s_cvarFlankStagingDist.GetFloat();

    // Get objective position for sector orientation (sector 0 faces objective)
    float objPos[3] = {0, 0, 0};
    if (NavObjectives_IsReady())
    {
        const ObjectiveInfo *obj = NavObjectives_Get(NavObjectives_CurrentIndex());
        if (obj)
        {
            objPos[0] = obj->pos[0];
            objPos[1] = obj->pos[1];
            objPos[2] = obj->pos[2];
        }
    }

    // All bots are available for assignment (including previously holding bots)
    int availIdx[32];
    int availCount = 0;

    for (int b = 0; b < botCount && b < 32; b++)
    {
        int edict = botEdicts[b];
        if (edict < 1 || edict >= MAX_EDICT)
            continue;
        availIdx[availCount++] = b;
    }

    if (availCount == 0)
        return;

    // Sort available bots by distance to nearest enemy (closest first)
    struct BotDist { int botIdx; float dist2; };
    BotDist sorted[32];
    for (int i = 0; i < availCount; i++)
    {
        int b = availIdx[i];
        sorted[i].botIdx = b;
        float best = 1e18f;
        for (int e = 0; e < enemyCount; e++)
        {
            float dx = enemyPositions[e][0] - botPositions[b][0];
            float dy = enemyPositions[e][1] - botPositions[b][1];
            float d2 = dx * dx + dy * dy;
            if (d2 < best) best = d2;
        }
        sorted[i].dist2 = best;
    }
    // Insertion sort (small array)
    for (int i = 1; i < availCount; i++)
    {
        BotDist tmp = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j].dist2 > tmp.dist2)
        {
            sorted[j + 1] = sorted[j];
            j--;
        }
        sorted[j + 1] = tmp;
    }

    // Round-robin available bots across enemies
    int botsPerEnemy[32] = {};
    int botEnemyMap[32];  // sorted index → enemy index
    for (int i = 0; i < availCount; i++)
    {
        int enemyIdx = i % enemyCount;
        botEnemyMap[i] = enemyIdx;
        botsPerEnemy[enemyIdx]++;
    }

    // Assign sectors and compute staging positions
    int sectorCounter[32] = {};

    for (int i = 0; i < availCount; i++)
    {
        int b = sorted[i].botIdx;
        int edict = botEdicts[b];
        if (edict < 1 || edict >= MAX_EDICT)
            continue;

        int enemyIdx = botEnemyMap[i];
        int K = botsPerEnemy[enemyIdx];
        int sector = sectorCounter[enemyIdx]++;

        FlankAssignment &a = s_assignments[edict];
        a.targetEnemyIdx = enemyIdx;
        a.sectorIndex = sector;
        a.totalSectors = K;
        a.assigned = true;

        // Compute sector angle: sector 0 oriented from enemy toward objective
        float baseDirX = objPos[0] - enemyPositions[enemyIdx][0];
        float baseDirY = objPos[1] - enemyPositions[enemyIdx][1];
        float baseLen = sqrtf(baseDirX * baseDirX + baseDirY * baseDirY);
        if (baseLen > 0.001f)
        {
            baseDirX /= baseLen;
            baseDirY /= baseLen;
        }
        else
        {
            baseDirX = 1.0f;
            baseDirY = 0.0f;
        }

        float sectorAngle = (2.0f * 3.14159f * sector) / K;
        float cosA = cosf(sectorAngle);
        float sinA = sinf(sectorAngle);
        float dirX = baseDirX * cosA - baseDirY * sinA;
        float dirY = baseDirX * sinA + baseDirY * cosA;

        // Layered staging: each bot stops at a different distance from enemy
        float layerSpacing = s_cvarFlankLayerSpacing.GetFloat();
        float botStagingDist = stagingDist + sector * layerSpacing;
        float candidate[3] = {
            enemyPositions[enemyIdx][0] + dirX * botStagingDist,
            enemyPositions[enemyIdx][1] + dirY * botStagingDist,
            enemyPositions[enemyIdx][2]
        };

        // Snap to nav mesh
        void *navMesh = GetNavMesh();
        if (navMesh && s_fnGetNearestNavArea)
        {
            CNavArea *area = s_fnGetNearestNavArea(navMesh, candidate,
                                                    true, 500.0f, false, false, 0);
            if (area)
            {
                const float *c = NavArea_GetCenter(area);
                a.stagingPos[0] = c[0];
                a.stagingPos[1] = c[1];
                a.stagingPos[2] = c[2];
            }
            else
            {
                a.stagingPos[0] = candidate[0];
                a.stagingPos[1] = candidate[1];
                a.stagingPos[2] = candidate[2];
            }
        }
        else
        {
            a.stagingPos[0] = candidate[0];
            a.stagingPos[1] = candidate[1];
            a.stagingPos[2] = candidate[2];
        }
    }

    // All bots move simultaneously — no queueing
    for (int b = 0; b < botCount; b++)
    {
        int edict = botEdicts[b];
        if (edict < 1 || edict >= MAX_EDICT) continue;
        FlankAssignment &a = s_assignments[edict];
        if (!a.assigned) continue;

        // Check if already at staging position
        float dx = botPositions[b][0] - a.stagingPos[0];
        float dy = botPositions[b][1] - a.stagingPos[1];
        if (dx * dx + dy * dy < 200.0f * 200.0f)
        {
            s_holding[edict] = true;
            a.waveOrder = -1;
        }
        else
        {
            a.waveOrder = 0;  // ACTIVE — all bots move
        }
    }

    s_lastAssignTime = gpGlobals->curtime;
    s_lastAssignEnemyCount = enemyCount;
    for (int e = 0; e < enemyCount && e < 32; e++)
    {
        s_lastAssignEnemyPos[e][0] = enemyPositions[e][0];
        s_lastAssignEnemyPos[e][1] = enemyPositions[e][1];
        s_lastAssignEnemyPos[e][2] = enemyPositions[e][2];
    }

    // Log assignment summary
    int activeCount = 0, holdCount = 0;
    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (!s_assignments[i].assigned) continue;
        if (s_assignments[i].waveOrder == 0) activeCount++;
        else if (s_assignments[i].waveOrder == -1) holdCount++;
    }
    META_CONPRINTF("[SmartBots] FlankAssign: %d enemies, %d active, %d holding (layer spacing %.0f)\n",
                   enemyCount, activeCount, holdCount, s_cvarFlankLayerSpacing.GetFloat());
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
    META_CONPRINTF("  Staging dist: %.0f (layer spacing: %.0f)\n",
                   s_cvarFlankStagingDist.GetFloat(), s_cvarFlankLayerSpacing.GetFloat());
    META_CONPRINTF("  Assign interval: %.1fs\n", s_cvarFlankAssignSeconds.GetFloat());
    META_CONPRINTF("  Defend ratio: %.0f%%\n", s_cvarFlankDefendRatio.GetFloat() * 100.0f);
    META_CONPRINTF("  Last assign: %.1fs ago\n",
                   s_lastAssignTime > 0 ? gpGlobals->curtime - s_lastAssignTime : -1.0f);

    int activePaths = 0, assigned = 0, holdingCount = 0;
    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (s_paths[i].active) activePaths++;
        if (s_assignments[i].assigned) assigned++;
        if (s_holding[i]) holdingCount++;
    }
    META_CONPRINTF("  Assigned: %d, Active paths: %d, Holding: %d\n",
                   assigned, activePaths, holdingCount);

    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (!s_assignments[i].assigned)
            continue;
        FlankAssignment &a = s_assignments[i];
        const char *state = s_holding[i] ? "HOLDING" :
                            (a.waveOrder == 0 ? "ACTIVE" : "QUEUED");
        float effectiveDist = s_cvarFlankStagingDist.GetFloat() +
                              a.sectorIndex * s_cvarFlankLayerSpacing.GetFloat();
        META_CONPRINTF("  Bot %d: enemy=%d sector=%d/%d dist=%.0f staging=(%.0f,%.0f,%.0f) %s\n",
                       i, a.targetEnemyIdx, a.sectorIndex, a.totalSectors,
                       effectiveDist, a.stagingPos[0], a.stagingPos[1], a.stagingPos[2],
                       state);
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
    float assignInterval = s_cvarFlankAssignSeconds.GetFloat();
    float replanInterval = s_cvarFlankReplan.GetFloat();

    // --- Check staleness: do we need to reassign sectors? ---
    bool needReassign = false;

    // First time or no previous assignment
    if (s_lastAssignTime == 0.0f)
        needReassign = true;

    // Timer expired
    if (!needReassign && curtime - s_lastAssignTime >= assignInterval)
        needReassign = true;

    // Enemy count changed
    if (!needReassign && enemyCount != s_lastAssignEnemyCount)
    {
        needReassign = true;
        memset(s_holding, 0, sizeof(s_holding));  // positions invalid
    }

    // Enemy moved >300u
    if (!needReassign)
    {
        for (int e = 0; e < enemyCount && e < s_lastAssignEnemyCount; e++)
        {
            float dx = enemyPositions[e][0] - s_lastAssignEnemyPos[e][0];
            float dy = enemyPositions[e][1] - s_lastAssignEnemyPos[e][1];
            if (dx * dx + dy * dy > 300.0f * 300.0f)
            {
                needReassign = true;
                memset(s_holding, 0, sizeof(s_holding));
                break;
            }
        }
    }

    // Check if a flanking bot died (was assigned but not in current bot list)
    if (!needReassign)
    {
        for (int e = 1; e < MAX_EDICT; e++)
        {
            if (!s_assignments[e].assigned)
                continue;
            bool found = false;
            for (int b = 0; b < botCount; b++)
            {
                if (botEdicts[b] == e) { found = true; break; }
            }
            if (!found)
            {
                needReassign = true;
                s_assignments[e].assigned = false;
                s_holding[e] = false;
                break;
            }
        }
    }

    // Mark active bots that reached staging as holding (no reassignment needed)
    for (int b = 0; b < botCount; b++)
    {
        int edict = botEdicts[b];
        if (edict < 1 || edict >= MAX_EDICT) continue;
        FlankAssignment &a = s_assignments[edict];
        if (!a.assigned || a.waveOrder != 0 || s_holding[edict])
            continue;

        float dx = botPositions[b][0] - a.stagingPos[0];
        float dy = botPositions[b][1] - a.stagingPos[1];
        if (dx * dx + dy * dy < 200.0f * 200.0f)
        {
            s_holding[edict] = true;
            a.waveOrder = -1;
            s_paths[edict].active = false;
        }
    }

    if (needReassign)
    {
        AssignFlankTargets(botEdicts, botPositions, botCount,
                           enemyPositions, enemyCount);
    }

    // --- Compute A* paths for active bots (waveOrder == 0, not holding) ---
    for (int b = 0; b < botCount; b++)
    {
        int edictIdx = botEdicts[b];
        if (edictIdx < 1 || edictIdx >= MAX_EDICT)
            continue;

        FlankAssignment &asgn = s_assignments[edictIdx];
        if (!asgn.assigned || asgn.waveOrder != 0 || s_holding[edictIdx])
        {
            // Deactivate path for non-active bots
            s_paths[edictIdx].active = false;
            continue;
        }

        FlankPath &path = s_paths[edictIdx];

        // Check if A* replan needed
        bool needReplan = false;
        if (!path.active)
            needReplan = true;
        else if (curtime - path.replanTime >= replanInterval)
            needReplan = true;

        if (needReplan)
        {
            // Resolve nav areas
            CNavArea *botArea = s_fnGetNearestNavArea(
                navMesh, botPositions[b], true, 300.0f, false, false, 0);
            CNavArea *stagingArea = s_fnGetNearestNavArea(
                navMesh, asgn.stagingPos, true, 500.0f, false, false, 0);

            // Threat area for vis penalty (enemy's actual position)
            CNavArea *threatArea = nullptr;
            int enemyIdx = asgn.targetEnemyIdx;
            if (enemyIdx >= 0 && enemyIdx < enemyCount)
            {
                threatArea = s_fnGetNearestNavArea(
                    navMesh, enemyPositions[enemyIdx], true, 300.0f, false, false, 0);
            }

            if (!botArea || !stagingArea)
            {
                path.active = false;
                continue;
            }

            if (botArea == stagingArea)
            {
                // Already at staging area
                s_holding[edictIdx] = true;
                path.active = false;
                continue;
            }

            // Run A* with visibility penalty on enemy area
            float waypoints[MAX_WAYPOINTS][3];
            int wpCount = FindFlankPath(botArea, stagingArea, threatArea,
                                         waypoints, MAX_WAYPOINTS);

            if (wpCount == 0)
            {
                path.active = false;
                continue;
            }

            memcpy(path.waypoints, waypoints, wpCount * sizeof(float[3]));
            path.waypointCount = wpCount;
            path.currentWaypoint = 0;
            path.enemyPos[0] = asgn.stagingPos[0];
            path.enemyPos[1] = asgn.stagingPos[1];
            path.enemyPos[2] = asgn.stagingPos[2];
            path.replanTime = curtime;
            path.active = true;
        }
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
    memset(s_assignments, 0, sizeof(s_assignments));
    memset(s_holding, 0, sizeof(s_holding));
    s_lastAssignTime = 0.0f;
    s_lastAssignEnemyCount = 0;
    s_navReady = false;
    s_visDataChecked = false;
    s_hasVisData = false;
    META_CONPRINTF("[SmartBots] NavFlanking: reset\n");
}

float NavFlanking_GetDefendRatio()
{
    return s_cvarFlankDefendRatio.GetFloat();
}
