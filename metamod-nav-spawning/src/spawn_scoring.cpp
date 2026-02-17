#include "spawn_scoring.h"
#include "extension.h"
#include "sig_resolve.h"
#include "detour.h"

#include <convar.h>
#include <dlfcn.h>
#include <cstring>
#include <cmath>
#include <cstdlib>

extern ISmmAPI *g_SMAPI;

// ---- Forward declarations ----
class CNavArea;
class CNavMesh;

// ---- Function pointer types ----

// CINSNextBot::Spawn() -- thiscall on Linux: this as first stack arg
typedef void (*SpawnFn)(void *thisBot);

// CNavMesh::GetNearestNavArea(Vector const&, bool anyZ, float maxDist, bool checkLOS, bool checkGround, int team)
typedef CNavArea *(*GetNearestNavAreaFn)(void *thisNavMesh, const float *pos,
                                         bool anyZ, float maxDist,
                                         bool checkLOS, bool checkGround, int team);

// CNavArea::IsPotentiallyVisible(CNavArea const*) const
typedef bool (*IsPotentiallyVisibleFn)(void *thisArea, const void *otherArea);

// CNavArea::IsBlocked(int teamID, bool ignoreNavBlockers) const
typedef bool (*IsBlockedFn)(void *thisArea, int teamID, bool ignoreNavBlockers);

// CBaseEntity::Teleport(Vector const*, QAngle const*, Vector const*) -- vtable dispatch
typedef void (*TeleportFn)(void *thisEnt, const float *origin, const float *angles, const float *velocity);

// CBaseEntity::GetTeamNumber() const -- resolved via dlsym at init
// x86-32 Linux/GCC thiscall: `this` is first stack argument
typedef int (*GetTeamNumberFn)(void *thisEntity);
static GetTeamNumberFn s_fnGetTeamNumber = nullptr;

// ---- Resolved pointers ----

static void          **s_ppTheNavMesh = nullptr;
static GetNearestNavAreaFn s_fnGetNearestNavArea = nullptr;
static IsPotentiallyVisibleFn s_fnIsPotentiallyVisible = nullptr;
static IsBlockedFn    s_fnIsBlocked = nullptr;

// Spawn detour
static InlineDetour s_spawnDetour;
static SpawnFn s_originalSpawn = nullptr;

// ---- CNavArea opaque field access (same offsets as nav_flanking.cpp) ----

static const int kOff_Center     = 44;   // Vector (3 floats)
static const int kOff_Connect    = 108;  // 4x NavConnectVector (one per direction)
static const int kOff_InsFlags   = 0x160; // CINSNavArea m_insFlags (uint32)

static const int kSizeofNavConnectVec = 4;  // single pointer
static const int kSizeofNavConnect    = 8;  // area ptr + float length

inline const float *NavArea_GetCenter(const void *area)
{
    return reinterpret_cast<const float *>(
        reinterpret_cast<const char *>(area) + kOff_Center);
}

inline bool IsPlausiblePtr(const void *p)
{
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    return addr > 0x10000 && addr < 0xF0000000;
}

inline int NavArea_GetAdjacentCount(const void *area, int dir)
{
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data || !IsPlausiblePtr(data))
        return 0;
    int count = *reinterpret_cast<const int *>(data);
    if (count < 0 || count > 256)
        return 0;
    return count;
}

inline void *NavArea_GetAdjacentArea(const void *area, int dir, int index)
{
    const char *base = reinterpret_cast<const char *>(area) + kOff_Connect;
    const char *vecPtr = base + dir * kSizeofNavConnectVec;
    void *data = *reinterpret_cast<void *const *>(vecPtr);
    if (!data || !IsPlausiblePtr(data))
        return nullptr;
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

// ---- ConVars ----

static ConVar s_cvarEnabled("navspawn_enabled", "0", 0,
    "Enable nav mesh spawning for defender bots");
static ConVar s_cvarIdealDist("navspawn_ideal_dist", "2000", 0,
    "Ideal distance from players (peak of scoring curve)");
static ConVar s_cvarDistFalloff("navspawn_dist_falloff", "1500", 0,
    "How quickly score drops from ideal distance");
static ConVar s_cvarMinPlayerDist("navspawn_min_player_dist", "800", 0,
    "Minimum distance from human players");
static ConVar s_cvarMaxPlayerDist("navspawn_max_player_dist", "4000", 0,
    "Maximum distance from human players");
static ConVar s_cvarDebug("navspawn_debug", "0", 0,
    "Log spawn decisions to console");

// ---- Player cache (updated from GameFrame) ----

static const int MAX_PLAYERS = 32;

struct CachedPlayer {
    float pos[3];
    int team;
    void *navArea;  // CNavArea* for this player's position
};

static CachedPlayer s_players[MAX_PLAYERS];
static int s_playerCount = 0;

// ---- Objective cache ----

static float s_objectivePos[3] = {0, 0, 0};
static bool s_hasObjective = false;

// ---- Controlled team (read from CONTROLLED_TEAM env, default 3) ----

static int s_controlledTeam = 3;  // team whose bots get relocated

// ---- Counter-attack state ----

static bool s_isCounterAttack = false;

// ---- BFS + scoring ----

static const int MAX_BFS_AREAS = 2048;

struct ScoredArea {
    void *area;
    float score;
};

// Simple xorshift PRNG (avoid pulling in <random>)
static uint32_t s_rngState = 0x12345678;
static float RandomFloat(float lo, float hi)
{
    s_rngState ^= s_rngState << 13;
    s_rngState ^= s_rngState >> 17;
    s_rngState ^= s_rngState << 5;
    float t = (float)(s_rngState & 0xFFFF) / 65535.0f;
    return lo + t * (hi - lo);
}

static float VecDist2D(const float *a, const float *b)
{
    float dx = a[0] - b[0];
    float dy = a[1] - b[1];
    return sqrtf(dx * dx + dy * dy);
}

// Multi-source BFS from attacker player positions, score by enemy distance bell curve
static bool PickSpawnPosition(float outPos[3])
{
    if (s_playerCount == 0)
        return false;

    void *navMesh = s_ppTheNavMesh ? *s_ppTheNavMesh : nullptr;
    if (!navMesh || !s_fnGetNearestNavArea)
        return false;

    float idealDist = s_cvarIdealDist.GetFloat();
    float distFalloff = s_cvarDistFalloff.GetFloat();
    float minPlayerDist = s_cvarMinPlayerDist.GetFloat();
    float maxPlayerDist = s_cvarMaxPlayerDist.GetFloat();

    // During counter-attack: shift ideal distance out by 1.5x
    if (s_isCounterAttack)
        idealDist *= 1.5f;

    // Collect attacker player nav areas as BFS seeds
    int attackerTeam = (s_controlledTeam == 3) ? 2 : 3;

    void *bfsQueue[MAX_BFS_AREAS];
    void *visitedAreas[MAX_BFS_AREAS];
    int visitedCount = 0;
    int queueHead = 0, queueTail = 0;

    auto isVisited = [&](void *area) -> bool {
        for (int i = 0; i < visitedCount; i++)
            if (visitedAreas[i] == area) return true;
        return false;
    };

    // Seed BFS from all attacker players' nav areas (multi-source)
    int seedCount = 0;
    for (int p = 0; p < s_playerCount; p++)
    {
        if (s_players[p].team != attackerTeam)
            continue;
        void *playerNav = s_players[p].navArea;
        if (!playerNav || isVisited(playerNav))
            continue;
        if (queueTail >= MAX_BFS_AREAS)
            break;

        visitedAreas[visitedCount++] = playerNav;
        bfsQueue[queueTail++] = playerNav;
        seedCount++;
    }

    if (seedCount == 0)
        return false;

    ScoredArea candidates[MAX_BFS_AREAS];
    int candidateCount = 0;

    while (queueHead < queueTail && visitedCount < MAX_BFS_AREAS)
    {
        void *current = bfsQueue[queueHead++];
        const float *center = NavArea_GetCenter(current);

        // Compute minimum distance to any attacker player
        float minDist = 1e9f;
        for (int p = 0; p < s_playerCount; p++)
        {
            if (s_players[p].team != attackerTeam)
                continue;
            float dist = VecDist2D(center, s_players[p].pos);
            if (dist < minDist)
                minDist = dist;
        }

        // Prune expansion past maxPlayerDist
        if (minDist > maxPlayerDist)
            continue;

        // Skip blocked areas (but still expand through them)
        if (s_fnIsBlocked && s_fnIsBlocked(current, 0, false))
            goto expand;

        // Only score areas within [minPlayerDist, maxPlayerDist]
        if (minDist < minPlayerDist)
            goto expand;

        // Score this area
        {
            // Distance bell curve: peak at idealDist, falloff over distFalloff
            float distDelta = fabsf(minDist - idealDist);
            float distFactor = 1.0f - distDelta / distFalloff;
            if (distFactor < 0.1f)
                distFactor = 0.1f;

            float score = 100.0f * distFactor;

            // Visibility penalty: 0.1x if visible from any player's nav area
            if (s_fnIsPotentiallyVisible)
            {
                for (int p = 0; p < s_playerCount; p++)
                {
                    if (!s_players[p].navArea)
                        continue;
                    if (s_fnIsPotentiallyVisible(s_players[p].navArea, current))
                    {
                        score *= 0.1f;
                        break;
                    }
                }
            }

            // Indoor bonus: 1.5x
            if (NavArea_IsIndoor(current))
                score *= 1.5f;

            // Random jitter: 0.85x-1.15x
            score *= RandomFloat(0.85f, 1.15f);

            candidates[candidateCount].area = current;
            candidates[candidateCount].score = score;
            candidateCount++;
        }

expand:
        // Expand neighbors
        for (int dir = 0; dir < 4; dir++)
        {
            int adjCount = NavArea_GetAdjacentCount(current, dir);
            for (int i = 0; i < adjCount; i++)
            {
                void *neighbor = NavArea_GetAdjacentArea(current, dir, i);
                if (!neighbor || isVisited(neighbor))
                    continue;

                if (visitedCount < MAX_BFS_AREAS && queueTail < MAX_BFS_AREAS)
                {
                    visitedAreas[visitedCount++] = neighbor;
                    bfsQueue[queueTail++] = neighbor;
                }
            }
        }
    }

    if (candidateCount == 0)
        return false;

    // Find highest scoring area
    int bestIdx = 0;
    for (int i = 1; i < candidateCount; i++)
    {
        if (candidates[i].score > candidates[bestIdx].score)
            bestIdx = i;
    }

    const float *bestCenter = NavArea_GetCenter(candidates[bestIdx].area);
    outPos[0] = bestCenter[0];
    outPos[1] = bestCenter[1];
    outPos[2] = bestCenter[2];

    if (s_cvarDebug.GetBool())
    {
        // Compute distance from best spawn to nearest player for logging
        float bestMinDist = 1e9f;
        for (int p = 0; p < s_playerCount; p++)
        {
            if (s_players[p].team != attackerTeam)
                continue;
            float d = VecDist2D(outPos, s_players[p].pos);
            if (d < bestMinDist)
                bestMinDist = d;
        }

        META_CONPRINTF("[NavSpawn] Picked spawn: (%.0f, %.0f, %.0f) score=%.1f "
                       "dist=%.0f (%d candidates, %d visited, %d seeds)\n",
                       outPos[0], outPos[1], outPos[2],
                       candidates[bestIdx].score,
                       bestMinDist,
                       candidateCount, visitedCount, seedCount);
    }

    return true;
}

// ---- Teleport via vtable dispatch ----

static void TeleportEntity(void *entity, const float *pos)
{
    void **vtable = *reinterpret_cast<void ***>(entity);
    auto fnTeleport = reinterpret_cast<TeleportFn>(
        vtable[kVtableOff_Teleport / 4]);
    fnTeleport(entity, pos, nullptr, nullptr);
}

// ---- GetTeamNumber via dlsym-resolved function pointer ----

static int GetTeamNumber(void *entity)
{
    if (!s_fnGetTeamNumber)
        return 0;
    return s_fnGetTeamNumber(entity);
}

// ---- Spawn hook ----

static void __attribute__((cdecl)) Hook_CINSNextBot_Spawn(void *thisBot)
{
    // Call original Spawn — handles wave system, loadout, model, position
    s_originalSpawn(thisBot);

    // Check if enabled
    if (!s_cvarEnabled.GetBool())
        return;

    // Only affect bots on the controlled (defender) team
    int team = GetTeamNumber(thisBot);
    if (team != s_controlledTeam)
        return;

    // Pick a spawn position
    float pos[3];
    if (!PickSpawnPosition(pos))
        return;

    // Teleport the bot
    TeleportEntity(thisBot, pos);

    if (s_cvarDebug.GetBool())
    {
        META_CONPRINTF("[NavSpawn] Teleported bot (team %d) to (%.0f, %.0f, %.0f)\n",
                       team, pos[0], pos[1], pos[2]);
    }
}

// ---- Public API ----

bool SpawnScoring_Init(uintptr_t serverBase, int controlledTeam)
{
    s_controlledTeam = controlledTeam;

    // Resolve TheNavMesh pointer
    s_ppTheNavMesh = reinterpret_cast<void **>(
        serverBase + ServerOffsets::TheNavMesh);

    // Resolve nav function pointers
    s_fnGetNearestNavArea = reinterpret_cast<GetNearestNavAreaFn>(
        serverBase + ServerOffsets::CNavMesh_GetNearestNavArea);
    s_fnIsPotentiallyVisible = reinterpret_cast<IsPotentiallyVisibleFn>(
        serverBase + ServerOffsets::CNavArea_IsPotentiallyVisible);
    s_fnIsBlocked = reinterpret_cast<IsBlockedFn>(
        serverBase + ServerOffsets::CNavArea_IsBlocked);

    // Resolve GetTeamNumber via offset (symbol is local 't', not exported — dlsym won't find it)
    s_fnGetTeamNumber = reinterpret_cast<GetTeamNumberFn>(
        serverBase + ServerOffsets::CBaseEntity_GetTeamNumber);
    META_CONPRINTF("[NavSpawn] GetTeamNumber resolved at %p\n", (void *)s_fnGetTeamNumber);

    META_CONPRINTF("[NavSpawn] SpawnScoring: initialized (TheNavMesh=%p, Spawn=%p)\n",
                   (void *)s_ppTheNavMesh,
                   ResolveOffset(serverBase, ServerOffsets::CINSNextBot_Spawn));

    return true;
}

bool SpawnScoring_InstallDetour(uintptr_t serverBase)
{
    void *spawnAddr = ResolveOffset(serverBase, ServerOffsets::CINSNextBot_Spawn);

    if (!s_spawnDetour.Install(spawnAddr, (void *)Hook_CINSNextBot_Spawn))
    {
        META_CONPRINTF("[NavSpawn] ERROR: Failed to install Spawn detour at %p\n", spawnAddr);
        return false;
    }

    s_originalSpawn = reinterpret_cast<SpawnFn>(s_spawnDetour.GetTrampoline());

    META_CONPRINTF("[NavSpawn] Spawn detour installed at %p (trampoline=%p)\n",
                   spawnAddr, (void *)s_originalSpawn);

    return true;
}

void SpawnScoring_RemoveDetour()
{
    s_spawnDetour.Remove();
    s_originalSpawn = nullptr;
    META_CONPRINTF("[NavSpawn] Spawn detour removed\n");
}

void SpawnScoring_UpdatePlayers(const float (*positions)[3], const int *teams, int count)
{
    s_playerCount = (count > MAX_PLAYERS) ? MAX_PLAYERS : count;
    for (int i = 0; i < s_playerCount; i++)
    {
        s_players[i].pos[0] = positions[i][0];
        s_players[i].pos[1] = positions[i][1];
        s_players[i].pos[2] = positions[i][2];
        s_players[i].team = teams[i];
        s_players[i].navArea = nullptr;  // resolved separately
    }
}

void SpawnScoring_UpdatePlayerNavAreas()
{
    void *navMesh = s_ppTheNavMesh ? *s_ppTheNavMesh : nullptr;
    if (!navMesh || !s_fnGetNearestNavArea)
        return;

    int attackerTeam = (s_controlledTeam == 3) ? 2 : 3;
    for (int i = 0; i < s_playerCount; i++)
    {
        // Only resolve nav areas for human players on the attacker team
        if (s_players[i].team == attackerTeam)
        {
            s_players[i].navArea = s_fnGetNearestNavArea(
                navMesh, s_players[i].pos, true, 300.0f, false, false, 0);
        }
    }
}

void SpawnScoring_SetObjective(float x, float y, float z)
{
    s_objectivePos[0] = x;
    s_objectivePos[1] = y;
    s_objectivePos[2] = z;
    s_hasObjective = true;
}

void SpawnScoring_SetCounterAttack(bool active)
{
    s_isCounterAttack = active;
}
