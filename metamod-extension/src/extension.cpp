#include "extension.h"
#include "sig_resolve.h"
#include "bot_action_hook.h"
#include "udp_bridge.h"
#include "bot_state.h"
#include "bot_command.h"

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

// Bridge logging throttle
static int s_bridgeSendCount = 0;
static int s_bridgeRecvCount = 0;
static int s_bridgeCmdExecCount = 0;

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

    int botCount = 0;
    int maxClients = gpGlobals->maxClients;

    for (int i = 1; i <= maxClients; i++)
    {
        edict_t *edict = PEntityOfEntIndex(i);
        if (!edict || edict->IsFree())
            continue;

        IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
        if (!info || !info->IsConnected() || !info->IsFakeClient())
            continue;

        Vector pos = info->GetAbsOrigin();
        META_CONPRINTF("[SmartBots] Bot #%d \"%s\" @ (%.1f, %.1f, %.1f)\n",
                       i, info->GetName(), pos.x, pos.y, pos.z);
        botCount++;
    }

    META_CONPRINTF("[SmartBots] Total bots: %d\n", botCount);

    if (BotActionHook_HasGotoTarget())
        META_CONPRINTF("[SmartBots] Goto target: ACTIVE\n");

    META_CONPRINTF("[SmartBots] Bridge: %s (sent=%d recv=%d exec=%d)\n",
                   s_cvarAiEnabled.GetBool() ? "enabled" : "disabled",
                   s_bridgeSendCount, s_bridgeRecvCount, s_bridgeCmdExecCount);
}

static ConCommand s_cmdStatus("smartbots_status", CC_SmartBotsStatus,
    "Show all bot positions and extension status");

// ---- GameFrame hook ----

void SmartBotsExtension::Hook_GameFrame(bool simulating)
{
    if (!simulating)
    {
        RETURN_META(MRES_IGNORED);
    }

    s_tickCount++;

    // Build entity pointer → edict index map for the combat detour
    BotActionHook_ClearEntityMap();
    {
        int maxClients = gpGlobals->maxClients;
        for (int i = 1; i <= maxClients; i++)
        {
            edict_t *edict = PEntityOfEntIndex(i);
            if (!edict || edict->IsFree())
                continue;

            IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
            if (!info || !info->IsConnected() || !info->IsFakeClient())
                continue;

            IServerUnknown *pUnknown = edict->GetUnknown();
            if (!pUnknown)
                continue;

            CBaseEntity *pEntity = pUnknown->GetBaseEntity();
            if (!pEntity)
                continue;

            BotActionHook_RegisterEntity((void *)pEntity, i);
        }
    }

    // --- Manual goto target (takes priority over Python commands) ---
    float gotoX, gotoY, gotoZ;
    bool hasGoto = BotActionHook_GetGotoTarget(gotoX, gotoY, gotoZ);

    if (hasGoto)
    {
        int maxClients = gpGlobals->maxClients;

        for (int i = 1; i <= maxClients; i++)
        {
            edict_t *edict = PEntityOfEntIndex(i);
            if (!edict || edict->IsFree())
                continue;

            IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
            if (!info || !info->IsConnected() || !info->IsFakeClient())
                continue;

            IServerUnknown *pUnknown = edict->GetUnknown();
            if (!pUnknown)
                continue;

            CBaseEntity *pEntity = pUnknown->GetBaseEntity();
            if (!pEntity)
                continue;

            if (BotActionHook_IssueMovementRequest(
                    (void *)pEntity, gotoX, gotoY, gotoZ))
            {
                s_gfMoveReqCount++;
            }
        }

        // Log every ~5 seconds
        if (s_gfMoveReqLogThrottle++ % 330 == 0)
        {
            META_CONPRINTF("[SmartBots] GameFrame MovReq: %d total requests issued (tick %d)\n",
                           s_gfMoveReqCount, s_tickCount);
        }
    }

    // --- UDP bridge to Python brain ---
    if (s_cvarAiEnabled.GetBool())
    {
        // Send state at ~8Hz (every 8 ticks at 66 tick/s)
        if (s_tickCount % 8 == 0)
        {
            int count = BotState_Collect(s_stateArray, 32);
            if (count > 0)
            {
                int len = BotState_Serialize(s_stateArray, count, s_tickCount,
                                             s_sendBuf, sizeof(s_sendBuf));
                if (UdpBridge_Send(s_sendBuf, len))
                {
                    s_bridgeSendCount++;

                    // Log first send and then every ~30 seconds
                    if (s_bridgeSendCount == 1 || s_bridgeSendCount % 240 == 0)
                    {
                        META_CONPRINTF("[SmartBots] Bridge: sent state #%d (%d bots, %d bytes)\n",
                                       s_bridgeSendCount, count, len);
                    }
                }
            }
        }

        // Receive commands every tick (non-blocking)
        int bytesRead = UdpBridge_Recv(s_recvBuf, sizeof(s_recvBuf) - 1);
        if (bytesRead > 0)
        {
            s_recvBuf[bytesRead] = '\0';
            BotCommand_Parse(s_recvBuf, bytesRead, s_tickCount);
            s_bridgeRecvCount++;

            // Log first recv and then every ~30 seconds
            if (s_bridgeRecvCount == 1 || s_bridgeRecvCount % 240 == 0)
            {
                META_CONPRINTF("[SmartBots] Bridge: recv commands #%d (%d bytes)\n",
                               s_bridgeRecvCount, bytesRead);
            }
        }

        // Clear stale commands (older than ~1 second = 66 ticks)
        BotCommand_ClearStale(s_tickCount, 66);

        // Execute Python commands for bots (skip if manual goto is active)
        if (!hasGoto)
        {
            int maxClients = gpGlobals->maxClients;

            for (int i = 1; i <= maxClients; i++)
            {
                BotCommandEntry cmd;
                if (!BotCommand_Get(i, cmd))
                    continue;

                edict_t *edict = PEntityOfEntIndex(i);
                if (!edict || edict->IsFree())
                    continue;

                IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
                if (!info || !info->IsConnected() || !info->IsFakeClient())
                    continue;

                IServerUnknown *pUnknown = edict->GetUnknown();
                if (!pUnknown)
                    continue;

                CBaseEntity *pEntity = pUnknown->GetBaseEntity();
                if (!pEntity)
                    continue;

                if (BotActionHook_IssueMovementRequest(
                        (void *)pEntity, cmd.moveTarget[0], cmd.moveTarget[1], cmd.moveTarget[2]))
                {
                    s_bridgeCmdExecCount++;
                }
            }
        }
    }

    // Log bot count periodically (~50 seconds)
    if (s_tickCount % 3300 == 0)
    {
        int botCount = 0;
        int maxClients = gpGlobals->maxClients;

        for (int i = 1; i <= maxClients; i++)
        {
            edict_t *edict = PEntityOfEntIndex(i);
            if (!edict || edict->IsFree())
                continue;

            IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
            if (!info || !info->IsConnected() || !info->IsFakeClient())
                continue;

            botCount++;
        }

        if (botCount > 0)
        {
            META_CONPRINTF("[SmartBots] GameFrame: %d bots active (tick %d)\n",
                           botCount, s_tickCount);
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
