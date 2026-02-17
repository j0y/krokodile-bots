#include "extension.h"
#include "nav_flanking.h"
#include "bot_voice.h"
#include "sig_resolve.h"
#include "nav_objectives.h"
#include "game_events.h"

#include <cstring>
#include <cmath>

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
static const int kOff_InsFlags   = 0x160; // CINSNavArea m_insFlags (uint32)

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

inline bool NavArea_IsIndoor(const void *area)
{
    uint32_t flags = *reinterpret_cast<const uint32_t *>(
        reinterpret_cast<const char *>(area) + kOff_InsFlags);
    return (flags & 0x80) != 0;
}

// ---- Hiding spot access (CINSNavArea +0xD0) ----
// CUtlVectorUltraConservative<HidingSpot*>: pointer to Data_t { int count; HidingSpot* spots[]; }
// HidingSpot: +0x04 float x, +0x08 float y, +0x0C float z

static const int kOff_HidingSpots = 0xD0;

struct HidingSpotPos {
    float pos[3];
    void *parentArea;
};

static int GetHidingSpotsFromArea(const void *area, HidingSpotPos *out, int maxSpots)
{
    const char *areaPtr = reinterpret_cast<const char *>(area);
    void *vecData = *reinterpret_cast<void *const *>(areaPtr + kOff_HidingSpots);
    if (!vecData || !IsPlausiblePtr(vecData))
        return 0;

    int count = *reinterpret_cast<const int *>(vecData);
    if (count <= 0 || count > 64)
        return 0;

    int written = 0;
    for (int i = 0; i < count && written < maxSpots; i++)
    {
        // spots[i] is a pointer at offset 4 + i*4
        void *spot = *reinterpret_cast<void *const *>(
            reinterpret_cast<const char *>(vecData) + 4 + i * 4);
        if (!spot || !IsPlausiblePtr(spot))
            continue;

        const char *sp = reinterpret_cast<const char *>(spot);
        out[written].pos[0] = *reinterpret_cast<const float *>(sp + 0x04);
        out[written].pos[1] = *reinterpret_cast<const float *>(sp + 0x08);
        out[written].pos[2] = *reinterpret_cast<const float *>(sp + 0x0C);
        out[written].parentArea = const_cast<void *>(area);
        written++;
    }
    return written;
}

// ---- Per-bot position target state ----

static const int MAX_EDICT = 33;  // edicts 1..32

struct BotTarget {
    float pos[3];       // best scored position
    float score;        // score of current target
    float evalTime;     // gpGlobals->curtime when last evaluated
    int   lastEnemyCount; // enemy count at last eval (force re-eval on change)
    float lastEnemyPos[3]; // closest enemy pos at last eval
    int   lastHealth;   // health at last eval (force re-eval on damage)
    float lastVoiceTime; // cooldown for vocal callouts
    bool  valid;        // has a target?
    bool  reached;      // within arrival radius of target
};

static BotTarget s_targets[MAX_EDICT];

// Track time since enemies were last known (for advance-when-safe)
static float s_lastEnemySeenTime = 0.0f;

// Death zone data (refreshed each NavFlanking_Update cycle)
static float s_dzPos[16][3];
static float s_dzTimes[16];
static int   s_dzHeat[16];    // how many deaths clustered near this one (grows radius)
static int   s_dzCount = 0;
static bool  s_dzFresh = false; // any death zone < 15s old (active combat)

// ---- ConVars ----

#include <convar.h>

static ConVar s_cvarFlankEnabled("smartbots_flank_enabled", "1", 0,
    "Enable position scoring for bots without visible enemies");
static ConVar s_cvarFlankDefendRatio("smartbots_flank_defend_ratio", "0.15", 0,
    "Fraction of bots that defend objective (rest flank)");

static ConVar s_cvarEvalInterval("smartbots_pos_eval_interval", "2.0", 0,
    "Seconds between position re-evaluation per bot");
static ConVar s_cvarIdealDist("smartbots_pos_ideal_dist", "800", 0,
    "Peak of distance bell curve from threat (units)");
static ConVar s_cvarCoverWeight("smartbots_pos_cover_weight", "40", 0,
    "Weight for cover from threat (0-100)");
static ConVar s_cvarLofWeight("smartbots_pos_lof_weight", "20", 0,
    "Weight for line-of-fire peek ability (0-100)");
static ConVar s_cvarDistWeight("smartbots_pos_dist_weight", "15", 0,
    "Weight for distance bell curve (0-100)");
static ConVar s_cvarSpreadWeight("smartbots_pos_spread_weight", "15", 0,
    "Weight for spreading from allies (0-100)");
static ConVar s_cvarIndoorWeight("smartbots_pos_indoor_weight", "10", 0,
    "Weight for indoor area bonus (0-100)");
static ConVar s_cvarFlankWeight("smartbots_pos_flank_weight", "5", 0,
    "Weight for lateral flanking offset from threat-to-objective line (0-100)");

static ConVar s_cvarReachedDist("smartbots_pos_reached_dist", "100", 0,
    "Distance to consider position reached (units)");
static ConVar s_cvarReachedEvalInterval("smartbots_pos_reached_eval", "5.0", 0,
    "Eval interval when positioned at target (seconds)");
static ConVar s_cvarAdvanceSafeTime("smartbots_pos_advance_safe_time", "10.0", 0,
    "Seconds with no enemies before bots start advancing");
static ConVar s_cvarAdvanceDistMin("smartbots_pos_advance_dist_min", "200", 0,
    "Minimum ideal distance when advancing (units)");
static ConVar s_cvarHidingSpots("smartbots_pos_hiding_spots", "1", 0,
    "Use nav mesh hiding spots as additional candidate positions");
static ConVar s_cvarVoiceCallouts("smartbots_pos_voice_callouts", "1", 0,
    "Enable vocal callouts when bots pick flanking positions");
static ConVar s_cvarVoiceCooldown("smartbots_pos_voice_cooldown", "8.0", 0,
    "Minimum seconds between voice callouts per bot");
static ConVar s_cvarDeathZoneWeight("smartbots_pos_deathzone_weight", "60", 0,
    "Weight for death zone avoidance — avoid positions where teammates died (0-100)");
static ConVar s_cvarDeathZoneRadius("smartbots_pos_deathzone_radius", "600", 0,
    "Radius of death zone penalty (units)");
static ConVar s_cvarDeathZoneMaxAge("smartbots_pos_deathzone_age", "45.0", 0,
    "How long death zones remain active (seconds)");

// ---- Helpers ----

static float VecDist(const float *a, const float *b)
{
    float dx = a[0] - b[0];
    float dy = a[1] - b[1];
    float dz = a[2] - b[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

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
                   s_hasVisData ? "AVAILABLE" : "MISSING (cover scoring disabled)",
                   tested, visibleCount);
}

// ---- BFS candidate area collector ----

static const int MAX_BFS_AREAS = 256;
static const float MAX_BFS_DIST = 2000.0f;

static int CollectCandidateAreas(void *startArea, float maxDist,
                                  void *outAreas[], int maxAreas)
{
    if (!startArea || maxAreas <= 0)
        return 0;

    void *queue[MAX_BFS_AREAS];
    int head = 0, tail = 0, count = 0;
    const float *startCenter = NavArea_GetCenter(startArea);

    queue[tail++] = startArea;
    outAreas[count++] = startArea;

    while (head < tail && count < maxAreas)
    {
        void *current = queue[head++];

        for (int dir = 0; dir < 4; dir++)
        {
            int adjCount = NavArea_GetAdjacentCount(current, dir);
            for (int i = 0; i < adjCount; i++)
            {
                void *neighbor = NavArea_GetAdjacentArea(current, dir, i);
                if (!neighbor)
                    continue;

                // Check if already visited (linear scan — small array)
                bool alreadyVisited = false;
                for (int v = 0; v < count; v++)
                {
                    if (outAreas[v] == neighbor)
                    {
                        alreadyVisited = true;
                        break;
                    }
                }
                if (alreadyVisited)
                    continue;

                // Skip blocked areas
                if (s_fnIsBlocked && s_fnIsBlocked(neighbor, 0, false))
                    continue;

                // Distance check from start
                const float *nc = NavArea_GetCenter(neighbor);
                if (VecDist(startCenter, nc) > maxDist)
                    continue;

                if (count >= maxAreas || tail >= MAX_BFS_AREAS)
                    break;

                outAreas[count++] = neighbor;
                queue[tail++] = neighbor;
            }
        }
    }

    return count;
}

// ---- Position scoring ----

static float ScorePosition(const float *pos, void *area,
                            void *threatArea, const float *threatPos,
                            const float *objPos,
                            const float (*allyPositions)[3], int allyCount,
                            float idealDistOverride)
{
    bool useVis = s_hasVisData && s_fnIsPotentiallyVisible && threatArea;

    float wCover  = s_cvarCoverWeight.GetFloat();
    float wLof    = s_cvarLofWeight.GetFloat();
    float wDist   = s_cvarDistWeight.GetFloat();
    float wSpread = s_cvarSpreadWeight.GetFloat();
    float wIndoor = s_cvarIndoorWeight.GetFloat();
    float wFlank  = s_cvarFlankWeight.GetFloat();

    // 1. Cover factor: not visible from threat = 1.0, visible = 0.2
    float coverFactor = 0.5f; // default if no vis data
    if (useVis)
        coverFactor = s_fnIsPotentiallyVisible(threatArea, area) ? 0.2f : 1.0f;

    // 2. Line-of-fire factor: can peek from adjacent area = 1.0, else 0.3
    float lofFactor = 0.3f;
    if (useVis)
    {
        for (int dir = 0; dir < 4; dir++)
        {
            int adjCount = NavArea_GetAdjacentCount(area, dir);
            for (int i = 0; i < adjCount; i++)
            {
                void *adj = NavArea_GetAdjacentArea(area, dir, i);
                if (adj && s_fnIsPotentiallyVisible(threatArea, adj))
                {
                    lofFactor = 1.0f;
                    goto lof_done;
                }
            }
        }
    }
lof_done:

    // 3. Distance factor: gaussian bell curve peaking at ideal_dist
    float idealDist = idealDistOverride;
    float dist = VecDist(pos, threatPos);
    float distDelta = (dist - idealDist) / (idealDist * 0.5f);
    float distFactor = expf(-0.5f * distDelta * distDelta);

    // 4. Spread factor: distance to nearest ally target/position
    //    Hard penalty for very close (<100u) — prevents stacking on same spot
    float spreadFactor = 1.0f;
    if (allyCount > 0)
    {
        float nearestAllyDist = 1e18f;
        for (int a = 0; a < allyCount; a++)
        {
            float d = VecDist(pos, allyPositions[a]);
            if (d < nearestAllyDist)
                nearestAllyDist = d;
        }
        if (nearestAllyDist < 100.0f)
            spreadFactor = nearestAllyDist / 300.0f * 0.5f; // harsh penalty for overlap
        else
            spreadFactor = nearestAllyDist / 300.0f;
        if (spreadFactor > 1.0f)
            spreadFactor = 1.0f;
    }

    // 5. Indoor factor
    float indoorFactor = NavArea_IsIndoor(area) ? 1.5f : 1.0f;

    // 6. Flanking factor: lateral offset from threat-to-objective line
    float flankFactor = 0.5f; // default neutral
    if (objPos)
    {
        // threat→objective direction
        float toObjX = objPos[0] - threatPos[0];
        float toObjY = objPos[1] - threatPos[1];
        float toObjLen = sqrtf(toObjX * toObjX + toObjY * toObjY);

        if (toObjLen > 1.0f)
        {
            // threat→candidate direction
            float toCandX = pos[0] - threatPos[0];
            float toCandY = pos[1] - threatPos[1];
            float toCandLen = sqrtf(toCandX * toCandX + toCandY * toCandY);

            if (toCandLen > 1.0f)
            {
                // 2D cross product magnitude = lateral offset
                float cross = (toObjX * toCandY - toObjY * toCandX) / (toObjLen * toCandLen);
                flankFactor = fabsf(cross); // 0 = inline, 1 = perpendicular
            }
        }
    }

    // 7. Death zone penalty: avoid positions where teammates recently died
    //    Radius grows with clustered kills — 2 deaths = 1.5x radius, 3 = 2x, etc.
    float wDeathZone = s_cvarDeathZoneWeight.GetFloat();
    float dzBaseRadius = s_cvarDeathZoneRadius.GetFloat();
    float dzMaxAge = s_cvarDeathZoneMaxAge.GetFloat();
    float deathZoneFactor = 1.0f;
    if (wDeathZone > 0.0f && s_dzCount > 0)
    {
        float curtime = gpGlobals->curtime;
        float totalPenalty = 0.0f;
        for (int d = 0; d < s_dzCount; d++)
        {
            float effectiveRadius = dzBaseRadius * (1.0f + 0.5f * (s_dzHeat[d] - 1));
            float dist = VecDist(pos, s_dzPos[d]);
            if (dist < effectiveRadius)
            {
                float distPenalty = 1.0f - dist / effectiveRadius;    // 1.0 at center, 0.0 at edge
                float age = curtime - s_dzTimes[d];
                float ageFade = 1.0f - age / dzMaxAge;               // 1.0 when fresh, 0.0 when old
                if (ageFade < 0.0f) ageFade = 0.0f;
                totalPenalty += distPenalty * ageFade;                 // stacks per death
            }
        }
        deathZoneFactor = 1.0f - totalPenalty;
        if (deathZoneFactor < 0.0f) deathZoneFactor = 0.0f;
    }

    float score = coverFactor      * wCover
                + lofFactor        * wLof
                + distFactor       * wDist
                + spreadFactor     * wSpread
                + indoorFactor     * wIndoor
                + flankFactor      * wFlank
                + deathZoneFactor  * wDeathZone;

    return score;
}

// ---- Status ConCommand ----

static void CC_FlankStatus(const CCommand &args)
{
    META_CONPRINTF("[SmartBots] Position Scoring status:\n");
    META_CONPRINTF("  Initialized: %s\n", s_navInitialized ? "yes" : "no");
    META_CONPRINTF("  Nav ready: %s\n", s_navReady ? "yes" : "no");
    META_CONPRINTF("  Vis data: %s\n", s_visDataChecked ? (s_hasVisData ? "yes" : "missing") : "not checked");
    META_CONPRINTF("  Enabled: %s\n", s_cvarFlankEnabled.GetBool() ? "yes" : "no");
    META_CONPRINTF("  Weights: cover=%.0f lof=%.0f dist=%.0f spread=%.0f indoor=%.0f flank=%.0f dz=%.0f\n",
                   s_cvarCoverWeight.GetFloat(), s_cvarLofWeight.GetFloat(),
                   s_cvarDistWeight.GetFloat(), s_cvarSpreadWeight.GetFloat(),
                   s_cvarIndoorWeight.GetFloat(), s_cvarFlankWeight.GetFloat(),
                   s_cvarDeathZoneWeight.GetFloat());
    META_CONPRINTF("  Death zones: %d active (radius=%.0f, age=%.0fs) %s\n",
                   s_dzCount, s_cvarDeathZoneRadius.GetFloat(),
                   s_cvarDeathZoneMaxAge.GetFloat(),
                   s_dzFresh ? "COMBAT ACTIVE" : "");
    for (int d = 0; d < s_dzCount; d++)
    {
        float age = gpGlobals->curtime - s_dzTimes[d];
        float effR = s_cvarDeathZoneRadius.GetFloat() * (1.0f + 0.5f * (s_dzHeat[d] - 1));
        META_CONPRINTF("    DZ%d: (%.0f,%.0f,%.0f) age=%.0fs heat=%d radius=%.0f\n",
                       d, s_dzPos[d][0], s_dzPos[d][1], s_dzPos[d][2],
                       age, s_dzHeat[d], effR);
    }
    META_CONPRINTF("  Ideal dist: %.0f  Eval: %.1fs (reached: %.1fs)\n",
                   s_cvarIdealDist.GetFloat(), s_cvarEvalInterval.GetFloat(),
                   s_cvarReachedEvalInterval.GetFloat());
    META_CONPRINTF("  Defend ratio: %.0f%%\n", s_cvarFlankDefendRatio.GetFloat() * 100.0f);

    float timeSinceEnemy = gpGlobals->curtime - s_lastEnemySeenTime;
    if (s_lastEnemySeenTime > 0.0f && timeSinceEnemy > s_cvarAdvanceSafeTime.GetFloat())
        META_CONPRINTF("  ADVANCING: %.1fs since enemies (ideal dist shrinking)\n", timeSinceEnemy);

    int activeCount = 0, reachedCount = 0;
    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (s_targets[i].valid) activeCount++;
        if (s_targets[i].reached) reachedCount++;
    }
    META_CONPRINTF("  Active: %d  Reached: %d\n", activeCount, reachedCount);

    for (int i = 1; i < MAX_EDICT; i++)
    {
        if (!s_targets[i].valid)
            continue;
        BotTarget &t = s_targets[i];
        float age = gpGlobals->curtime - t.evalTime;
        META_CONPRINTF("  Bot %d: target=(%.0f,%.0f,%.0f) score=%.1f age=%.1fs hp=%d %s\n",
                       i, t.pos[0], t.pos[1], t.pos[2], t.score, age,
                       t.lastHealth, t.reached ? "REACHED" : "moving");
    }
}

static ConCommand s_cmdFlankStatus("smartbots_flank_status", CC_FlankStatus,
    "Show position scoring system status");

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

    memset(s_targets, 0, sizeof(s_targets));

    s_navInitialized = true;
    s_navReady = false;
    s_visDataChecked = false;
    s_hasVisData = false;

    META_CONPRINTF("[SmartBots] NavFlanking: initialized (TheNavMesh=%p, GetNearestNavArea=%p)\n",
                   (void *)s_ppTheNavMesh, (void *)s_fnGetNearestNavArea);

    return true;
}

void NavFlanking_Update(const int *botEdicts, void *const *botEntities,
                        const float (*botPositions)[3], const int *botHealths,
                        int botCount,
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
    float evalInterval = s_cvarEvalInterval.GetFloat();
    float reachedEvalInterval = s_cvarReachedEvalInterval.GetFloat();
    float reachedDist = s_cvarReachedDist.GetFloat();

    // Refresh death zone cache for this update cycle
    float dzMaxAge = s_cvarDeathZoneMaxAge.GetFloat();
    float dzBaseRadius = s_cvarDeathZoneRadius.GetFloat();
    s_dzCount = GameEvents_GetDeathZones(dzMaxAge, s_dzPos, s_dzTimes, 16);

    // Compute heat per death zone: how many other deaths are clustered nearby
    // More deaths in same area → larger effective radius
    s_dzFresh = false;
    for (int d = 0; d < s_dzCount; d++)
    {
        s_dzHeat[d] = 1; // count self
        for (int d2 = 0; d2 < s_dzCount; d2++)
        {
            if (d2 != d && VecDist(s_dzPos[d], s_dzPos[d2]) < dzBaseRadius)
                s_dzHeat[d]++;
        }
        if (curtime - s_dzTimes[d] < 15.0f)
            s_dzFresh = true;
    }

    // Phase 3.4: Advance when safe — adjust ideal distance based on time without enemies
    if (enemyCount > 0)
        s_lastEnemySeenTime = curtime;

    float idealDist = s_cvarIdealDist.GetFloat();
    float safeTime = s_cvarAdvanceSafeTime.GetFloat();
    float timeSinceEnemy = curtime - s_lastEnemySeenTime;
    if (s_lastEnemySeenTime > 0.0f && timeSinceEnemy > safeTime)
    {
        // Linearly reduce ideal distance: full dist → min over 20 seconds past safe threshold
        float advanceProgress = (timeSinceEnemy - safeTime) / 20.0f;
        if (advanceProgress > 1.0f) advanceProgress = 1.0f;
        float minDist = s_cvarAdvanceDistMin.GetFloat();
        idealDist = idealDist + (minDist - idealDist) * advanceProgress;
    }

    // Get objective position for flanking bias
    float objPos[3] = {0, 0, 0};
    bool hasObj = false;
    if (NavObjectives_IsReady())
    {
        const ObjectiveInfo *obj = NavObjectives_Get(NavObjectives_CurrentIndex());
        if (obj)
        {
            objPos[0] = obj->pos[0];
            objPos[1] = obj->pos[1];
            objPos[2] = obj->pos[2];
            hasObj = true;
        }
    }

    for (int b = 0; b < botCount; b++)
    {
        int edict = botEdicts[b];
        if (edict < 1 || edict >= MAX_EDICT)
            continue;

        BotTarget &target = s_targets[edict];

        // Phase 2.2: Check if bot reached its target position
        if (target.valid)
            target.reached = (VecDist(botPositions[b], target.pos) < reachedDist);

        // Find closest enemy to this bot
        float closestEnemyDist = 1e18f;
        int closestEnemyIdx = -1;
        for (int e = 0; e < enemyCount; e++)
        {
            float d = VecDist(botPositions[b], enemyPositions[e]);
            if (d < closestEnemyDist)
            {
                closestEnemyDist = d;
                closestEnemyIdx = e;
            }
        }

        if (closestEnemyIdx < 0)
        {
            target.valid = false;
            continue;
        }

        const float *threatPos = enemyPositions[closestEnemyIdx];

        // Check if re-evaluation needed
        float activeInterval = target.reached ? reachedEvalInterval : evalInterval;
        bool needEval = false;
        if (!target.valid)
            needEval = true;
        else if (curtime - target.evalTime >= activeInterval)
            needEval = true;
        else if (enemyCount != target.lastEnemyCount)
            needEval = true;
        else if (VecDist(threatPos, target.lastEnemyPos) > 400.0f)
            needEval = true;
        // Force re-eval if bot took damage (even during hold)
        else if (botHealths && botHealths[b] < target.lastHealth)
            needEval = true;
        // Force re-eval if a fresh death zone appeared near the bot's current target
        if (!needEval && target.valid && s_dzCount > 0)
        {
            float dzCheckRadius = s_cvarDeathZoneRadius.GetFloat();
            for (int d = 0; d < s_dzCount; d++)
            {
                // Death zone is newer than bot's last eval and near target
                if (s_dzTimes[d] > target.evalTime &&
                    VecDist(target.pos, s_dzPos[d]) < dzCheckRadius)
                {
                    needEval = true;
                    break;
                }
            }
        }

        if (!needEval)
            continue;

        // Resolve bot and threat nav areas
        CNavArea *botArea = s_fnGetNearestNavArea(
            navMesh, botPositions[b], true, 300.0f, false, false, 0);
        CNavArea *threatArea = s_fnGetNearestNavArea(
            navMesh, threatPos, true, 500.0f, false, false, 0);

        if (!botArea)
        {
            target.valid = false;
            continue;
        }

        // Collect candidate areas via BFS
        void *candidates[MAX_BFS_AREAS];
        int candidateCount = CollectCandidateAreas(botArea, MAX_BFS_DIST,
                                                    candidates, MAX_BFS_AREAS);

        if (candidateCount == 0)
        {
            target.valid = false;
            continue;
        }

        // Build ally position array (all bots except this one)
        float allyPos[32][3];
        int allyCount = 0;
        for (int a = 0; a < botCount && allyCount < 32; a++)
        {
            if (a == b)
                continue;
            int allyEdict = botEdicts[a];
            // Use current targets for allies that have them, else use their position
            if (allyEdict >= 1 && allyEdict < MAX_EDICT && s_targets[allyEdict].valid)
            {
                allyPos[allyCount][0] = s_targets[allyEdict].pos[0];
                allyPos[allyCount][1] = s_targets[allyEdict].pos[1];
                allyPos[allyCount][2] = s_targets[allyEdict].pos[2];
            }
            else
            {
                allyPos[allyCount][0] = botPositions[a][0];
                allyPos[allyCount][1] = botPositions[a][1];
                allyPos[allyCount][2] = botPositions[a][2];
            }
            allyCount++;
        }

        // Score all area center candidates, pick highest
        float bestScore = -1.0f;
        float bestPos[3] = {0, 0, 0};
        bool foundBest = false;

        for (int c = 0; c < candidateCount; c++)
        {
            const float *cpos = NavArea_GetCenter(candidates[c]);
            float s = ScorePosition(cpos, candidates[c],
                                     threatArea, threatPos,
                                     hasObj ? objPos : nullptr,
                                     allyPos, allyCount,
                                     idealDist);
            if (s > bestScore)
            {
                bestScore = s;
                bestPos[0] = cpos[0];
                bestPos[1] = cpos[1];
                bestPos[2] = cpos[2];
                foundBest = true;
            }
        }

        // Phase 3.1: Also score hiding spots from candidate areas
        if (s_cvarHidingSpots.GetBool())
        {
            HidingSpotPos hspots[8];
            for (int c = 0; c < candidateCount; c++)
            {
                int hcount = GetHidingSpotsFromArea(candidates[c], hspots, 8);
                for (int h = 0; h < hcount; h++)
                {
                    float s = ScorePosition(hspots[h].pos, hspots[h].parentArea,
                                             threatArea, threatPos,
                                             hasObj ? objPos : nullptr,
                                             allyPos, allyCount,
                                             idealDist);
                    if (s > bestScore)
                    {
                        bestScore = s;
                        bestPos[0] = hspots[h].pos[0];
                        bestPos[1] = hspots[h].pos[1];
                        bestPos[2] = hspots[h].pos[2];
                        foundBest = true;
                    }
                }
            }
        }

        if (foundBest)
        {
            // Check if position actually changed (>50u from old target)
            bool posChanged = !target.valid ||
                VecDist(bestPos, target.pos) > 50.0f;

            target.pos[0] = bestPos[0];
            target.pos[1] = bestPos[1];
            target.pos[2] = bestPos[2];
            target.score = bestScore;
            target.evalTime = curtime;
            target.lastEnemyCount = enemyCount;
            target.lastEnemyPos[0] = threatPos[0];
            target.lastEnemyPos[1] = threatPos[1];
            target.lastEnemyPos[2] = threatPos[2];
            target.lastHealth = botHealths ? botHealths[b] : 100;
            target.valid = true;
            target.reached = false;

            // Phase 3.5: Vocal callouts only when picking a new position
            if (posChanged && s_cvarVoiceCallouts.GetBool() && hasObj &&
                curtime - target.lastVoiceTime >= s_cvarVoiceCooldown.GetFloat())
            {
                // Compute flanking offset to decide which callout
                float toObjX = objPos[0] - threatPos[0];
                float toObjY = objPos[1] - threatPos[1];
                float toObjLen = sqrtf(toObjX * toObjX + toObjY * toObjY);
                float toCandX = bestPos[0] - threatPos[0];
                float toCandY = bestPos[1] - threatPos[1];
                float toCandLen = sqrtf(toCandX * toCandX + toCandY * toCandY);

                if (toObjLen > 1.0f && toCandLen > 1.0f)
                {
                    float cross = (toObjX * toCandY - toObjY * toCandX)
                                  / (toObjLen * toCandLen);
                    float absCross = fabsf(cross);

                    if (absCross > 0.5f && botEntities[b])
                    {
                        // Laterally offset > 30 degrees — flanking callout
                        // 92 = "Flank left!", 93 = "Flank right!"
                        int voiceId = (cross > 0.0f) ? 92 : 93;
                        BotVoice_Speak(botEntities[b], voiceId);
                        target.lastVoiceTime = curtime;
                    }
                    else if (absCross <= 0.3f && botEntities[b])
                    {
                        // Inline with threat-objective axis — "Moving!"
                        BotVoice_Speak(botEntities[b], 82);
                        target.lastVoiceTime = curtime;
                    }
                }
            }
        }
        else
        {
            target.valid = false;
        }
    }
}

bool NavFlanking_GetTarget(int edictIndex, float &x, float &y, float &z)
{
    if (edictIndex < 1 || edictIndex >= MAX_EDICT)
        return false;

    BotTarget &t = s_targets[edictIndex];
    if (!t.valid)
        return false;

    x = t.pos[0];
    y = t.pos[1];
    z = t.pos[2];
    return true;
}

bool NavFlanking_IsActive(int edictIndex)
{
    if (edictIndex < 1 || edictIndex >= MAX_EDICT)
        return false;
    return s_targets[edictIndex].valid;
}

void NavFlanking_Reset()
{
    memset(s_targets, 0, sizeof(s_targets));
    s_lastEnemySeenTime = 0.0f;
    s_navReady = false;
    s_visDataChecked = false;
    s_hasVisData = false;
    META_CONPRINTF("[SmartBots] NavFlanking: reset\n");
}

float NavFlanking_GetDefendRatio()
{
    return s_cvarFlankDefendRatio.GetFloat();
}

bool NavFlanking_IsCombatActive()
{
    return s_dzFresh;
}
