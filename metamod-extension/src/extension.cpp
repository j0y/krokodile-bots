#include "extension.h"
#include "sig_resolve.h"
#include "bot_action_hook.h"
#include "udp_bridge.h"
#include "bot_state.h"
#include "bot_command.h"
#include "game_events.h"

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

// GameFrame movement request counters
static int s_gfMoveReqCount = 0;
static int s_gfMoveReqLogThrottle = 0;

// UDP bridge send/recv buffers
static char s_sendBuf[8192];
static char s_recvBuf[4096];
static BotStateEntry s_stateArray[32];
static CBaseEntity *s_playerEntities[32];  // parallel to s_stateArray — entity ptrs for vision checks

// Bridge logging throttle
static int s_bridgeSendCount = 0;
static int s_bridgeRecvCount = 0;
static int s_bridgeCmdExecCount = 0;

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

static ConVar s_cvarAiHost("smartbots_ai_host", "127.0.0.1", 0,
    "Python AI brain address");
static ConVar s_cvarAiPort("smartbots_ai_port", "9000", 0,
    "Python AI brain port");
static ConVar s_cvarAiEnabled("smartbots_ai_enabled", "1", 0,
    "Enable/disable UDP bridge to Python AI brain");

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

    META_CONPRINTF("[SmartBots] Bridge: %s (sent=%d recv=%d exec=%d)\n",
                   s_cvarAiEnabled.GetBool() ? "enabled" : "disabled",
                   s_bridgeSendCount, s_bridgeRecvCount, s_bridgeCmdExecCount);
}

static ConCommand s_cmdStatus("smartbots_status", CC_SmartBotsStatus,
    "Show all bot positions and extension status");

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
        GameEvents_RegisterListeners();

    // Refresh bot list + state at 8Hz (every 8 ticks).
    // IPlayerInfo calls are expensive (trigger UTIL_GetListenServerHost),
    // so we avoid doing this every tick.
    bool freshScan = false;
    if (s_tickCount % 8 == 0)
    {
        ResolveBots();
        ComputeVision();
        ComputeEnemyThreats();
        freshScan = true;
    }

    // --- UDP bridge: receive commands every tick (non-blocking, cheap) ---
    if (s_cvarAiEnabled.GetBool())
    {
        int bytesRead = UdpBridge_Recv(s_recvBuf, sizeof(s_recvBuf) - 1);
        if (bytesRead > 0)
        {
            s_recvBuf[bytesRead] = '\0';
            BotCommand_Parse(s_recvBuf, bytesRead, s_tickCount);
            s_bridgeRecvCount++;

            if (s_bridgeRecvCount == 1 || s_bridgeRecvCount % 240 == 0)
            {
                META_CONPRINTF("[SmartBots] Bridge: recv commands #%d (%d bytes)\n",
                               s_bridgeRecvCount, bytesRead);
            }
        }
    }

    // --- All heavy work gated to 8Hz (every 8 ticks) ---
    // AddMovementRequest triggers the game's pathfinder internally.
    // Calling it 66x/sec per bot overloads the server. 8Hz is plenty —
    // the locomotion system continues executing the last path between updates.
    if (freshScan)
    {
        float gotoX, gotoY, gotoZ;
        bool hasGoto = BotActionHook_GetGotoTarget(gotoX, gotoY, gotoZ);

        if (hasGoto)
        {
            for (int i = 0; i < s_resolvedBotCount; i++)
            {
                int idx = s_resolvedBots[i].edictIndex;
                if (!ValidateBot(idx, s_resolvedBots[i].entity))
                    continue;
                // Bot in combat — let native AI control movement
                if (BotActionHook_HasVisibleEnemy(idx))
                {
                    s_lastTargetValid[idx] = false;
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

        // Send state to Python brain
        if (s_cvarAiEnabled.GetBool() && s_stateCount > 0)
        {
            int len = BotState_Serialize(s_stateArray, s_stateCount, s_tickCount,
                                         s_sendBuf, sizeof(s_sendBuf));
            if (UdpBridge_Send(s_sendBuf, len))
            {
                s_bridgeSendCount++;

                if (s_bridgeSendCount == 1 || s_bridgeSendCount % 240 == 0)
                {
                    META_CONPRINTF("[SmartBots] Bridge: sent state #%d (%d bots, %d bytes)\n",
                                   s_bridgeSendCount, s_stateCount, len);
                }
            }
        }

        // Execute Python commands (skip if manual goto is active)
        if (s_cvarAiEnabled.GetBool() && !hasGoto)
        {
            BotCommand_ClearStale(s_tickCount, 66);

            for (int i = 0; i < s_resolvedBotCount; i++)
            {
                int idx = s_resolvedBots[i].edictIndex;
                if (!ValidateBot(idx, s_resolvedBots[i].entity))
                    continue;

                BotCommandEntry cmd;
                if (!BotCommand_Get(idx, cmd))
                    continue;

                // Bot in combat — let native AI control movement
                if (BotActionHook_HasVisibleEnemy(idx))
                {
                    s_lastTargetValid[idx] = false;
                    continue;
                }

                if (!TargetChanged(idx, cmd.moveTarget[0], cmd.moveTarget[1], cmd.moveTarget[2]))
                    continue;

                if (BotActionHook_IssueMovementRequest(
                        (void *)s_resolvedBots[i].entity,
                        cmd.moveTarget[0], cmd.moveTarget[1], cmd.moveTarget[2]))
                {
                    RecordTarget(idx, cmd.moveTarget[0], cmd.moveTarget[1], cmd.moveTarget[2]);
                    s_bridgeCmdExecCount++;
                }
            }
        }
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

    // Initialize UDP bridge to Python brain
    if (s_cvarAiEnabled.GetBool())
    {
        const char *host = s_cvarAiHost.GetString();
        int port = s_cvarAiPort.GetInt();
        if (!UdpBridge_Init(host, port))
        {
            META_CONPRINTF("[SmartBots] WARNING: UDP bridge init failed — AI brain will not be connected\n");
        }
    }

    // Initialize game event listener (objective tracking)
    {
        IGameEventManager2 *pGameEventMgr = nullptr;
        GET_V_IFACE_CURRENT(GetEngineFactory, pGameEventMgr,
                             IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
        GameEvents_Init(pGameEventMgr, /*controlledTeam=*/2);
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
    // Unregister game event listener
    GameEvents_Shutdown();

    // Close UDP bridge
    UdpBridge_Close();

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
