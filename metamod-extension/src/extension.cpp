#include "extension.h"
#include "sig_resolve.h"
#include "bot_action_hook.h"
#include "bot_state.h"
#include "bot_command.h"
#include "game_events.h"
#include "bot_voice.h"
#include "nav_flanking.h"
#include "nav_objectives.h"
#include "bot_tactics.h"
#include "bot_trace.h"

#include <toolframework/itoolentity.h>
#include <dlfcn.h>
#include <cstdlib>

SmartBotsExtension g_Extension;
PLUGIN_EXPOSE(SmartBotsExtension, g_Extension);

// SourceHook: GameFrame hook declaration
SH_DECL_HOOK1_void(IServerGameDLL, GameFrame, SH_NOATTRIB, 0, bool);

// Engine interfaces
IServerGameDLL *g_pServerGameDLL = nullptr;
IVEngineServer *g_pEngineServer = nullptr;
IServerGameClients *g_pServerGameClients = nullptr;
IPlayerInfoManager *g_pPlayerInfoManager = nullptr;
ICvar *g_pCVar = nullptr;
CGlobalVars *gpGlobals = nullptr;

// Server module handle
void *g_pServerHandle = nullptr;

// Server module base address (for offset resolution)
static uintptr_t s_serverBase = 0;

// Tick counter for throttled logging
static int s_tickCount = 0;

// Trace enabled (env DEV_MODE=1)
static bool s_traceEnabled = false;

// GameFrame movement request counters
static int s_gfMoveReqCount = 0;
static int s_gfMoveReqLogThrottle = 0;

static BotStateEntry s_stateArray[32];
static CBaseEntity *s_playerEntities[32];  // parallel to s_stateArray — entity ptrs for vision checks

// Per-bot resolved data — refreshed at 8Hz, reused every tick
struct ResolvedBot {
    int edictIndex;
    CBaseEntity *entity;
};
static ResolvedBot s_resolvedBots[32];
static int s_resolvedBotCount = 0;
static int s_lastResolveTick = 0;

// Last-issued movement target per bot — avoids redundant AddMovementRequest calls.
// The game engine logs every call, so repeating the same target floods the console.
static float s_lastTarget[33][3];  // [edictIndex][x/y/z]
static bool  s_lastTargetValid[33];

// Last-issued look target per bot — avoids redundant AimHeadTowards calls.
static float s_lastLookTarget[33][3];
static bool  s_lastLookTargetValid[33];

static bool TargetChanged(int edictIndex, float x, float y, float z)
{
    if (edictIndex < 1 || edictIndex > 32)
        return true;
    if (!s_lastTargetValid[edictIndex])
        return true;

    float dx = s_lastTarget[edictIndex][0] - x;
    float dy = s_lastTarget[edictIndex][1] - y;
    float dz = s_lastTarget[edictIndex][2] - z;
    // Only re-issue if target moved more than 1 unit
    return (dx * dx + dy * dy + dz * dz) > 1.0f;
}

static void RecordTarget(int edictIndex, float x, float y, float z)
{
    if (edictIndex >= 1 && edictIndex <= 32)
    {
        s_lastTarget[edictIndex][0] = x;
        s_lastTarget[edictIndex][1] = y;
        s_lastTarget[edictIndex][2] = z;
        s_lastTargetValid[edictIndex] = true;
    }
}

static bool LookTargetChanged(int edictIndex, float x, float y, float z)
{
    if (edictIndex < 1 || edictIndex > 32)
        return true;
    if (!s_lastLookTargetValid[edictIndex])
        return true;

    float dx = s_lastLookTarget[edictIndex][0] - x;
    float dy = s_lastLookTarget[edictIndex][1] - y;
    float dz = s_lastLookTarget[edictIndex][2] - z;
    return (dx * dx + dy * dy + dz * dz) > 1.0f;
}

static void RecordLookTarget(int edictIndex, float x, float y, float z)
{
    if (edictIndex >= 1 && edictIndex <= 32)
    {
        s_lastLookTarget[edictIndex][0] = x;
        s_lastLookTarget[edictIndex][1] = y;
        s_lastLookTarget[edictIndex][2] = z;
        s_lastLookTargetValid[edictIndex] = true;
    }
}

// Cheap validation: check that a cached entity pointer is still valid.
// Only reads edict struct fields — no IPlayerInfo calls, no UTIL_GetListenServerHost.
static bool ValidateBot(int edictIndex, CBaseEntity *cachedEntity)
{
    edict_t *edict = PEntityOfEntIndex(edictIndex);
    if (!edict || edict->IsFree())
        return false;

    IServerUnknown *pUnknown = edict->GetUnknown();
    if (!pUnknown)
        return false;

    // Entity pointer must still match what we cached
    return pUnknown->GetBaseEntity() == cachedEntity;
}

// ---- ConVars ----

static ConVar s_cvarTeam("smartbots_team", "3", 0,
    "Controlled team index (3=insurgents for coop)");

// ---- ConCommand registration (required by Source engine) ----

class BaseAccessor : public IConCommandBaseAccessor
{
public:
    bool RegisterConCommandBase(ConCommandBase *pCommandBase)
    {
        return META_REGCVAR(pCommandBase);
    }
} s_BaseAccessor;

// ---- ConCommand: smartbots_goto <x> <y> <z> ----

static void CC_SmartBotsGoto(const CCommand &args)
{
    if (args.ArgC() < 4)
    {
        META_CONPRINTF("[SmartBots] Usage: smartbots_goto <x> <y> <z>\n");
        return;
    }

    float x = atof(args.Arg(1));
    float y = atof(args.Arg(2));
    float z = atof(args.Arg(3));

    BotActionHook_SetGotoTarget(x, y, z);
    s_gfMoveReqCount = 0;
    s_gfMoveReqLogThrottle = 0;
    META_CONPRINTF("[SmartBots] Goto target set: %.1f %.1f %.1f (active on ALL bots via GameFrame)\n", x, y, z);
}

static ConCommand s_cmdGoto("smartbots_goto", CC_SmartBotsGoto,
    "Redirect combat bots to approach a position: smartbots_goto <x> <y> <z>");

// ---- ConCommand: smartbots_stop ----

static void CC_SmartBotsStop(const CCommand &args)
{
    BotActionHook_ClearGotoTarget();
    memset(s_lastTargetValid, 0, sizeof(s_lastTargetValid));
    memset(s_lastLookTargetValid, 0, sizeof(s_lastLookTargetValid));
}

static ConCommand s_cmdStop("smartbots_stop", CC_SmartBotsStop,
    "Clear the goto target and let bots resume normal combat AI");

// ---- ConCommand: smartbots_status ----

static void CC_SmartBotsStatus(const CCommand &args)
{
    if (!gpGlobals || !g_pEngineServer || !g_pPlayerInfoManager)
    {
        META_CONPRINTF("[SmartBots] Engine not ready\n");
        return;
    }

    META_CONPRINTF("[SmartBots] Bots: %d active (tick %d)\n", s_resolvedBotCount, s_tickCount);

    if (BotActionHook_HasGotoTarget())
        META_CONPRINTF("[SmartBots] Goto target: ACTIVE\n");
}

static ConCommand s_cmdStatus("smartbots_status", CC_SmartBotsStatus,
    "Show all bot positions and extension status");

// ---- ConCommand: smartbots_objectives ----

static void CC_SmartBotsObjectives(const CCommand &args)
{
    if (!NavObjectives_IsReady())
    {
        META_CONPRINTF("[SmartBots] Objectives: not scanned yet\n");
        return;
    }

    int count = NavObjectives_Count();
    int current = NavObjectives_CurrentIndex();
    META_CONPRINTF("[SmartBots] Objectives: %d total, current=#%d (lost=%d)\n",
                   count, current, GameEvents_GetObjectivesLost());

    for (int i = 0; i < count; i++)
    {
        const ObjectiveInfo *obj = NavObjectives_Get(i);
        if (!obj) continue;
        META_CONPRINTF("  %s[%d] '%s' %s at (%.0f, %.0f, %.0f)\n",
                       (i == current) ? ">> " : "   ",
                       obj->order, obj->name,
                       obj->isCapture ? "capture" : "destroy",
                       obj->pos[0], obj->pos[1], obj->pos[2]);
    }

    float ax, ay, az;
    if (NavObjectives_GetAttackerSpawn(ax, ay, az))
        META_CONPRINTF("  Attacker spawn: (%.0f, %.0f, %.0f)\n", ax, ay, az);

    float px, py, pz;
    if (NavObjectives_GetApproachPoint(px, py, pz))
        META_CONPRINTF("  Approach point: (%.0f, %.0f, %.0f)\n", px, py, pz);
}

static ConCommand s_cmdObjectives("smartbots_objectives", CC_SmartBotsObjectives,
    "Show discovered map objectives and current active objective");

// ---- ConCommand: smartbots_voice <concept_id> ----

static void CC_SmartBotsVoice(const CCommand &args)
{
    if (args.ArgC() < 2)
    {
        META_CONPRINTF("[SmartBots] Usage: smartbots_voice <concept_id>\n");
        return;
    }

    int conceptId = atoi(args.Arg(1));

    int spoken = 0;
    for (int i = 0; i < s_resolvedBotCount; i++)
    {
        int idx = s_resolvedBots[i].edictIndex;
        if (!ValidateBot(idx, s_resolvedBots[i].entity))
            continue;

        if (BotVoice_Speak((void *)s_resolvedBots[i].entity, conceptId))
            spoken++;
    }

    META_CONPRINTF("[SmartBots] Voice: concept %d (0x%02x) sent to %d bots\n",
                   conceptId, conceptId, spoken);
}

static ConCommand s_cmdVoice("smartbots_voice", CC_SmartBotsVoice,
    "Trigger a specific voice concept on all bots: smartbots_voice <concept_id>");

// ---- Edict scan: resolve all bots + collect state (called at 8Hz) ----

static int s_stateCount = 0;  // how many entries in s_stateArray from last scan

static void ResolveBots()
{
    s_resolvedBotCount = 0;
    s_stateCount = 0;
    BotActionHook_ClearEntityMap();

    int maxClients = gpGlobals->maxClients;
    for (int i = 1; i <= maxClients; i++)
    {
        edict_t *edict = PEntityOfEntIndex(i);
        if (!edict || edict->IsFree())
            continue;

        IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
        if (!info || !info->IsConnected())
            continue;

        bool isBot = info->IsFakeClient();

        // Bot resolution: fake clients only (for movement/combat hooks)
        if (isBot && s_resolvedBotCount < 32)
        {
            IServerUnknown *pUnknown = edict->GetUnknown();
            if (pUnknown)
            {
                CBaseEntity *pEntity = pUnknown->GetBaseEntity();
                if (pEntity)
                {
                    s_resolvedBots[s_resolvedBotCount].edictIndex = i;
                    s_resolvedBots[s_resolvedBotCount].entity = pEntity;
                    s_resolvedBotCount++;

                    BotActionHook_RegisterEntity((void *)pEntity, i);
                }
            }
        }

        // State collection: ALL connected players (for Python brain)
        if (s_stateCount < 32)
        {
            Vector pos = info->GetAbsOrigin();
            QAngle ang = info->GetAbsAngles();

            BotStateEntry &entry = s_stateArray[s_stateCount];
            entry.id = i;
            entry.pos[0] = pos.x;
            entry.pos[1] = pos.y;
            entry.pos[2] = pos.z;
            entry.ang[0] = ang.x;
            entry.ang[1] = ang.y;
            entry.ang[2] = ang.z;
            entry.health = info->GetHealth();
            entry.alive = info->IsDead() ? 0 : 1;
            entry.team = info->GetTeamIndex();
            entry.is_bot = isBot ? 1 : 0;
            entry.sees_count = 0;

            // Cache entity pointer for vision checks
            IServerUnknown *pUnk = edict->GetUnknown();
            s_playerEntities[s_stateCount] = pUnk ? pUnk->GetBaseEntity() : nullptr;

            s_stateCount++;
        }
    }

    s_lastResolveTick = s_tickCount;
}

// ---- Vision: per-bot visibility via IVision::IsAbleToSee ----

// x86-32 Linux/GCC thiscall: this as first stack argument
typedef void *(*GetVisionInterfaceFn)(void *thisNextBot);
typedef bool  (*IsAbleToSeeEntityFn)(void *thisVision, void *entity, int checkFOV, void *visibleSpot);

static int s_visionLogThrottle = 0;

static void ComputeVision()
{
    // For each bot in s_stateArray, compute which other players it can see.
    // Uses vtable dispatch: entity → GetVisionInterface() → IsAbleToSee(target).
    for (int i = 0; i < s_stateCount; i++)
    {
        BotStateEntry &entry = s_stateArray[i];
        entry.sees_count = 0;

        // Only compute vision for alive bots (fake clients)
        if (!entry.is_bot || !entry.alive)
            continue;

        CBaseEntity *botEntity = s_playerEntities[i];
        if (!botEntity)
            continue;

        // vtable dispatch: GetVisionInterface
        void **vtable = *reinterpret_cast<void ***>(botEntity);
        auto fnGetVision = reinterpret_cast<GetVisionInterfaceFn>(
            vtable[kVtableOff_GetVisionInterface / 4]);
        void *vision = fnGetVision(botEntity);
        if (!vision)
            continue;

        // Get IsAbleToSee(entity) from IVision vtable
        void **visionVtable = *reinterpret_cast<void ***>(vision);
        auto fnIsAbleToSee = reinterpret_cast<IsAbleToSeeEntityFn>(
            visionVtable[kVtableOff_IVision_IsAbleToSee_Entity / 4]);

        for (int j = 0; j < s_stateCount; j++)
        {
            if (i == j)
                continue;

            CBaseEntity *targetEntity = s_playerEntities[j];
            if (!targetEntity)
                continue;

            // checkFOV=0 (USE_FOV), visibleSpot=NULL
            if (fnIsAbleToSee(vision, targetEntity, 0, nullptr))
            {
                if (entry.sees_count < 32)
                {
                    entry.sees[entry.sees_count++] = s_stateArray[j].id;
                }
            }
        }
    }

    if (s_visionLogThrottle++ % 240 == 0)
    {
        int totalSeen = 0;
        for (int i = 0; i < s_stateCount; i++)
            totalSeen += s_stateArray[i].sees_count;
        META_CONPRINTF("[SmartBots] Vision: %d bots, %d total visibility entries\n",
                       s_stateCount, totalSeen);
    }
}

// ---- Enemy threat detection (uses engine's own threat assessment: vision + hearing + reports) ----

// IVision::GetPrimaryKnownThreat(int onlyVisible) → CKnownEntity*
// onlyVisible=0: all senses (seen + heard + reported)
// onlyVisible=1: only currently visible
typedef void *(*GetPrimaryKnownThreatFn)(void *thisVision, int onlyVisible);

static void ComputeEnemyThreats()
{
    BotActionHook_ClearVisibleEnemies();

    for (int i = 0; i < s_stateCount; i++)
    {
        BotStateEntry &entry = s_stateArray[i];
        if (!entry.is_bot || !entry.alive)
            continue;

        CBaseEntity *botEntity = s_playerEntities[i];
        if (!botEntity)
            continue;

        // vtable dispatch: GetVisionInterface
        void **vtable = *reinterpret_cast<void ***>(botEntity);
        auto fnGetVision = reinterpret_cast<GetVisionInterfaceFn>(
            vtable[kVtableOff_GetVisionInterface / 4]);
        void *vision = fnGetVision(botEntity);
        if (!vision)
            continue;

        // GetPrimaryKnownThreat(onlyVisible=0) — covers all senses
        void **visionVtable = *reinterpret_cast<void ***>(vision);
        auto fnGetThreat = reinterpret_cast<GetPrimaryKnownThreatFn>(
            visionVtable[kVtableOff_IVision_GetPrimaryKnownThreat / 4]);
        void *threat = fnGetThreat(vision, 0);

        BotActionHook_SetVisibleEnemy(entry.id, threat != nullptr);
    }
}

// ---- Team intel: enemy positions seen by any friendly bot ----

static float s_intelPos[32][3];   // enemy positions from team intel
static int   s_intelCount = 0;
static int   s_intelLogThrottle = 0;

// Collect enemy positions visible to any bot on the controlled team.
// Called after ComputeVision so sees[] is populated.
static void ComputeTeamIntel()
{
    s_intelCount = 0;
    int team = s_cvarTeam.GetInt();

    bool recorded[33] = {};  // avoid duplicates by edict index

    for (int i = 0; i < s_stateCount; i++)
    {
        BotStateEntry &entry = s_stateArray[i];
        if (!entry.alive || entry.team != team)
            continue;

        for (int s = 0; s < entry.sees_count; s++)
        {
            int enemyId = entry.sees[s];
            if (enemyId < 1 || enemyId > 32 || recorded[enemyId])
                continue;

            // Find this enemy in state array
            for (int j = 0; j < s_stateCount; j++)
            {
                if (s_stateArray[j].id == enemyId && s_stateArray[j].alive
                    && s_stateArray[j].team != team)
                {
                    s_intelPos[s_intelCount][0] = s_stateArray[j].pos[0];
                    s_intelPos[s_intelCount][1] = s_stateArray[j].pos[1];
                    s_intelPos[s_intelCount][2] = s_stateArray[j].pos[2];
                    s_intelCount++;
                    recorded[enemyId] = true;
                    break;
                }
            }
            if (s_intelCount >= 32)
                break;
        }
        if (s_intelCount >= 32)
            break;
    }
}

// For uncontrolled bots with no visible enemy, look at nearest team intel enemy.
static void ApplyTeamIntelLook()
{
    if (s_intelCount == 0)
        return;

    int team = s_cvarTeam.GetInt();
    int applied = 0;

    for (int i = 0; i < s_resolvedBotCount; i++)
    {
        int idx = s_resolvedBots[i].edictIndex;
        if (!ValidateBot(idx, s_resolvedBots[i].entity))
            continue;

        // Skip bots with Python commands — they already have look targets
        BotCommandEntry cmd;
        if (BotCommand_Get(idx, cmd))
            continue;

        // Skip bots that already see enemies — native combat handles aim
        if (BotActionHook_HasVisibleEnemy(idx))
            continue;

        // Find this bot's team and position from state array
        float botPos[3] = {};
        int botTeam = 0;
        for (int j = 0; j < s_stateCount; j++)
        {
            if (s_stateArray[j].id == idx)
            {
                botPos[0] = s_stateArray[j].pos[0];
                botPos[1] = s_stateArray[j].pos[1];
                botPos[2] = s_stateArray[j].pos[2];
                botTeam = s_stateArray[j].team;
                break;
            }
        }
        if (botTeam != team)
            continue;

        // Find nearest enemy from team intel
        float bestDist2 = 1e18f;
        int bestIdx = -1;
        for (int e = 0; e < s_intelCount; e++)
        {
            float dx = s_intelPos[e][0] - botPos[0];
            float dy = s_intelPos[e][1] - botPos[1];
            float d2 = dx * dx + dy * dy;
            if (d2 < bestDist2)
            {
                bestDist2 = d2;
                bestIdx = e;
            }
        }

        if (bestIdx >= 0)
        {
            // Horizontal aim: use bot's own Z
            float lx = s_intelPos[bestIdx][0];
            float ly = s_intelPos[bestIdx][1];
            float lz = botPos[2];

            if (LookTargetChanged(idx, lx, ly, lz))
            {
                BotActionHook_IssueLookAt(
                    (void *)s_resolvedBots[i].entity, lx, ly, lz);
                RecordLookTarget(idx, lx, ly, lz);
                applied++;
            }
        }
    }

    if (applied > 0 && s_intelLogThrottle++ % 120 == 0)
    {
        META_CONPRINTF("[SmartBots] TeamIntel: %d enemies known, look applied to %d bots\n",
                       s_intelCount, applied);
    }
}

// ---- GameFrame hook ----

void SmartBotsExtension::Hook_GameFrame(bool simulating)
{
    if (!simulating)
    {
        RETURN_META(MRES_IGNORED);
    }

    s_tickCount++;

    // Deferred event registration — events may not exist during Load()
    if (s_tickCount == 1)
    {
        GameEvents_RegisterListeners();
        NavObjectives_Scan();
    }

    // Detect round start → reset flanking paths
    {
        static const char *s_lastPhase = nullptr;
        const char *phase = GameEvents_GetPhase();
        if (phase != s_lastPhase)
        {
            if (phase && strcmp(phase, "preround") == 0)
            {
                NavFlanking_Reset();
                BotTactics_Reset();
                NavObjectives_Scan();
                if (s_traceEnabled)
                    BotTrace_Open();  // fresh trace each round
            }
            s_lastPhase = phase;
        }
    }

    // Refresh bot list + state at 8Hz (every 8 ticks).
    // IPlayerInfo calls are expensive (trigger UTIL_GetListenServerHost),
    // so we avoid doing this every tick.
    bool freshScan = false;
    if (s_tickCount % 8 == 0)
    {
        ResolveBots();
        ComputeVision();
        ComputeEnemyThreats();
        ComputeTeamIntel();
        freshScan = true;
    }

    // --- All heavy work gated to 8Hz (every 8 ticks) ---
    // AddMovementRequest triggers the game's pathfinder internally.
    // Calling it 66x/sec per bot overloads the server. 8Hz is plenty —
    // the locomotion system continues executing the last path between updates.
    if (freshScan)
    {
        // ---- Role assignment: defenders (BotTactics) vs flankers (NavFlanking) ----
        {
            int allEdicts[32];
            void *allEntities[32];
            float allPositions[32][3];
            int allCount = 0;
            int team = s_cvarTeam.GetInt();

            // Collect all alive team bots
            for (int i = 0; i < s_resolvedBotCount && allCount < 32; i++)
            {
                int idx = s_resolvedBots[i].edictIndex;
                if (!ValidateBot(idx, s_resolvedBots[i].entity))
                    continue;

                for (int j = 0; j < s_stateCount; j++)
                {
                    if (s_stateArray[j].id == idx && s_stateArray[j].alive
                        && s_stateArray[j].team == team)
                    {
                        allEdicts[allCount] = idx;
                        allEntities[allCount] = (void *)s_resolvedBots[i].entity;
                        allPositions[allCount][0] = s_stateArray[j].pos[0];
                        allPositions[allCount][1] = s_stateArray[j].pos[1];
                        allPositions[allCount][2] = s_stateArray[j].pos[2];
                        allCount++;
                        break;
                    }
                }
            }

            if (allCount > 0)
            {
                // Build intel target list: real enemies if available,
                // otherwise use attacker spawn as a synthetic threat
                // so flankers proactively advance toward the approach.
                float intelPos[33][3];
                int intelCount = 0;

                if (s_intelCount > 0)
                {
                    intelCount = s_intelCount;
                    memcpy(intelPos, s_intelPos, s_intelCount * sizeof(float[3]));
                }
                else
                {
                    // No enemies visible — use attacker spawn as synthetic target
                    float ax, ay, az;
                    if (NavObjectives_GetAttackerSpawn(ax, ay, az))
                    {
                        intelPos[0][0] = ax;
                        intelPos[0][1] = ay;
                        intelPos[0][2] = az;
                        intelCount = 1;
                    }
                }

                int defCount = allCount;    // default: all defend
                int flankStart = allCount;  // default: no flankers

                if (intelCount > 0)
                {
                    // Sort by distance to current objective (closest = defenders)
                    float objX = 0, objY = 0;
                    if (NavObjectives_IsReady())
                    {
                        const ObjectiveInfo *obj = NavObjectives_Get(NavObjectives_CurrentIndex());
                        if (obj) { objX = obj->pos[0]; objY = obj->pos[1]; }
                    }

                    // Compute distances and sort indices
                    float dist2[32];
                    int indices[32];
                    for (int i = 0; i < allCount; i++)
                    {
                        float dx = allPositions[i][0] - objX;
                        float dy = allPositions[i][1] - objY;
                        dist2[i] = dx * dx + dy * dy;
                        indices[i] = i;
                    }
                    // Insertion sort by distance (closest first)
                    for (int i = 1; i < allCount; i++)
                    {
                        int tmp = indices[i];
                        float tmpD = dist2[tmp];
                        int j = i - 1;
                        while (j >= 0 && dist2[indices[j]] > tmpD)
                        {
                            indices[j + 1] = indices[j];
                            j--;
                        }
                        indices[j + 1] = tmp;
                    }

                    // Split: ~30% defenders (closest to obj), rest flankers
                    float ratio = NavFlanking_GetDefendRatio();
                    defCount = (int)(allCount * ratio + 0.5f);
                    if (defCount < 1) defCount = 1;
                    if (defCount > allCount) defCount = allCount;
                    flankStart = defCount;

                    // Reorder arrays by sorted indices
                    int tmpEdicts[32];
                    void *tmpEntities[32];
                    float tmpPositions[32][3];
                    for (int i = 0; i < allCount; i++)
                    {
                        int src = indices[i];
                        tmpEdicts[i] = allEdicts[src];
                        tmpEntities[i] = allEntities[src];
                        tmpPositions[i][0] = allPositions[src][0];
                        tmpPositions[i][1] = allPositions[src][1];
                        tmpPositions[i][2] = allPositions[src][2];
                    }
                    memcpy(allEdicts, tmpEdicts, allCount * sizeof(int));
                    memcpy(allEntities, tmpEntities, allCount * sizeof(void *));
                    memcpy(allPositions, tmpPositions, allCount * sizeof(float[3]));
                }

                // Defenders → BotTactics (spread around objective)
                if (defCount > 0)
                    BotTactics_Update(allEdicts, allPositions, defCount, s_tickCount);

                // Flankers → NavFlanking (only those without visible enemy)
                if (flankStart < allCount && intelCount > 0)
                {
                    int flankEdicts[32];
                    void *flankEntities[32];
                    float flankPositions[32][3];
                    int flankCount = 0;

                    for (int i = flankStart; i < allCount && flankCount < 32; i++)
                    {
                        if (BotActionHook_HasVisibleEnemy(allEdicts[i]))
                            continue;

                        flankEdicts[flankCount] = allEdicts[i];
                        flankEntities[flankCount] = allEntities[i];
                        flankPositions[flankCount][0] = allPositions[i][0];
                        flankPositions[flankCount][1] = allPositions[i][1];
                        flankPositions[flankCount][2] = allPositions[i][2];
                        flankCount++;
                    }

                    if (flankCount > 0)
                    {
                        NavFlanking_Update(flankEdicts, flankEntities, flankPositions,
                                           flankCount,
                                           reinterpret_cast<const float(*)[3]>(intelPos),
                                           intelCount);

                        // Issue movement requests for bots with active flanking paths
                        for (int i = 0; i < flankCount; i++)
                        {
                            float fx, fy, fz;
                            if (NavFlanking_GetTarget(flankEdicts[i], fx, fy, fz))
                            {
                                if (TargetChanged(flankEdicts[i], fx, fy, fz))
                                {
                                    if (BotActionHook_IssueMovementRequest(
                                            flankEntities[i], fx, fy, fz))
                                    {
                                        RecordTarget(flankEdicts[i], fx, fy, fz);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        float gotoX, gotoY, gotoZ;
        bool hasGoto = BotActionHook_GetGotoTarget(gotoX, gotoY, gotoZ);

        if (hasGoto)
        {
            for (int i = 0; i < s_resolvedBotCount; i++)
            {
                int idx = s_resolvedBots[i].edictIndex;
                if (!ValidateBot(idx, s_resolvedBots[i].entity))
                    continue;
                // Bot in combat — let native AI control movement and aim
                if (BotActionHook_HasVisibleEnemy(idx))
                {
                    s_lastTargetValid[idx] = false;
                    s_lastLookTargetValid[idx] = false;
                    continue;
                }
                if (!TargetChanged(idx, gotoX, gotoY, gotoZ))
                    continue;

                if (BotActionHook_IssueMovementRequest(
                        (void *)s_resolvedBots[i].entity, gotoX, gotoY, gotoZ))
                {
                    RecordTarget(idx, gotoX, gotoY, gotoZ);
                    s_gfMoveReqCount++;
                }
            }

            if (s_gfMoveReqLogThrottle++ % 40 == 0)
            {
                META_CONPRINTF("[SmartBots] GameFrame MovReq: %d total (tick %d)\n",
                               s_gfMoveReqCount, s_tickCount);
            }
        }

        // Share enemy intel with uncontrolled bots (look-at only, no movement)
        // Trace bot positions at ~1Hz (every 64 ticks)
        if (s_traceEnabled && s_tickCount % 64 == 0 && s_stateCount > 0)
            BotTrace_Write(s_stateArray, s_stateCount, s_tickCount);

        ApplyTeamIntelLook();
    }

    // Log bot count periodically (~50 seconds)
    if (s_tickCount % 3300 == 0)
    {
        if (s_resolvedBotCount > 0)
        {
            META_CONPRINTF("[SmartBots] GameFrame: %d bots active (tick %d)\n",
                           s_resolvedBotCount, s_tickCount);
        }
    }

    RETURN_META(MRES_IGNORED);
}

// ---- Plugin lifecycle ----

bool SmartBotsExtension::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
    PLUGIN_SAVEVARS();

    GET_V_IFACE_CURRENT(GetEngineFactory, g_pEngineServer, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
    GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
    GET_V_IFACE_ANY(GetServerFactory, g_pServerGameDLL, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
    GET_V_IFACE_ANY(GetServerFactory, g_pServerGameClients, IServerGameClients, INTERFACEVERSION_SERVERGAMECLIENTS);
    GET_V_IFACE_ANY(GetServerFactory, g_pPlayerInfoManager, IPlayerInfoManager, INTERFACEVERSION_PLAYERINFOMANAGER);

    gpGlobals = ismm->GetCGlobals();

    // Resolve server module for symbol lookups
    g_pServerHandle = dlopen("insurgency/bin/server_srv.so", RTLD_NOW | RTLD_NOLOAD);
    if (!g_pServerHandle)
    {
        snprintf(error, maxlen, "Failed to get server_srv.so handle: %s", dlerror());
        return false;
    }

    // Get module base address via dlinfo (link_map)
    s_serverBase = GetServerModuleBaseFromHandle(g_pServerHandle);

    if (s_serverBase == 0)
    {
        snprintf(error, maxlen, "Failed to resolve server_srv.so base address");
        return false;
    }

    // Initialize bot action hook (resolve offsets, verify signatures)
    if (!BotActionHook_Init(s_serverBase))
    {
        snprintf(error, maxlen, "Bot action hook init failed (signature mismatch?)");
        return false;
    }

    // Install the CINSBotCombat::Update detour
    if (!BotActionHook_InstallDetour())
    {
        snprintf(error, maxlen, "Failed to install combat detour");
        return false;
    }

    // Hook GameFrame via SourceHook
    SH_ADD_HOOK_MEMFUNC(IServerGameDLL, GameFrame, g_pServerGameDLL, this,
                        &SmartBotsExtension::Hook_GameFrame, true);

    // Register console commands and ConVars
    ConVar_Register(0, &s_BaseAccessor);

    // Initialize bot command buffer
    BotCommand_Init();

    // Initialize game event listener (objective tracking)
    {
        IGameEventManager2 *pGameEventMgr = nullptr;
        GET_V_IFACE_CURRENT(GetEngineFactory, pGameEventMgr,
                             IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
        const char *teamEnv = std::getenv("CONTROLLED_TEAM");
        int controlledTeam = teamEnv ? std::atoi(teamEnv) : 3;
        GameEvents_Init(pGameEventMgr, controlledTeam);
    }

    // Resolve game rules for live counter-attack detection
    GameEvents_InitGameRules(s_serverBase);

    // Initialize nav mesh flanking (non-fatal — continues if resolution fails)
    if (!NavFlanking_Init(s_serverBase))
    {
        META_CONPRINTF("[SmartBots] WARNING: NavFlanking init failed — flanking disabled\n");
    }

    // Initialize objective scanner via IServerTools (non-fatal)
    {
        IServerTools *pServerTools = nullptr;
        // GET_V_IFACE_ANY would abort on failure, so query manually
        CreateInterfaceFn serverFactory = ismm->GetServerFactory(false);
        if (serverFactory)
        {
            int ret = 0;
            pServerTools = static_cast<IServerTools *>(
                serverFactory(VSERVERTOOLS_INTERFACE_VERSION, &ret));
        }
        if (!NavObjectives_Init(pServerTools))
        {
            META_CONPRINTF("[SmartBots] WARNING: NavObjectives init failed — no objective data\n");
        }
    }

    // Initialize tactical deployment (non-fatal)
    if (!BotTactics_Init(s_serverBase))
    {
        META_CONPRINTF("[SmartBots] WARNING: BotTactics init failed — tactical deployment disabled\n");
    }

    // Open trace file for position logging (env DEV_MODE=1)
    {
        const char *devEnv = std::getenv("DEV_MODE");
        s_traceEnabled = (devEnv && devEnv[0] == '1');
        if (s_traceEnabled)
            BotTrace_Open();
    }

    META_CONPRINTF("[SmartBots] Extension loaded (v0.2.0) — Phase 2 active\n");

    if (late)
    {
        META_CONPRINTF("[SmartBots] Late load — server already running\n");
    }

    return true;
}

void SmartBotsExtension::AllPluginsLoaded()
{
    META_CONPRINTF("[SmartBots] All plugins loaded\n");
}

bool SmartBotsExtension::Unload(char *error, size_t maxlen)
{
    // Close trace file
    BotTrace_Close();

    // Unregister game event listener
    GameEvents_Shutdown();

    // Remove detour first (restore original code)
    BotActionHook_RemoveDetour();

    // Remove SourceHook hooks
    SH_REMOVE_HOOK_MEMFUNC(IServerGameDLL, GameFrame, g_pServerGameDLL, this,
                           &SmartBotsExtension::Hook_GameFrame, true);

    if (g_pServerHandle)
    {
        dlclose(g_pServerHandle);
        g_pServerHandle = nullptr;
    }

    META_CONPRINTF("[SmartBots] Extension unloaded\n");
    return true;
}
