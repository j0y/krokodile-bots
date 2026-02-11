#include "extension.h"
#include "sig_resolve.h"
#include "bot_action_hook.h"

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
    META_CONPRINTF("[SmartBots] Goto target set: %.1f %.1f %.1f (will activate on next combat tick)\n", x, y, z);
}

static ConCommand s_cmdGoto("smartbots_goto", CC_SmartBotsGoto,
    "Send the next combat bot to approach a position: smartbots_goto <x> <y> <z>");

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
        META_CONPRINTF("[SmartBots] Goto target: PENDING\n");
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

    // Log bot count every ~5 seconds (66 ticks/sec * 5 = 330)
    if (s_tickCount % 330 == 0)
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

        if (botCount > 0 && s_tickCount % 3300 == 0) // every ~50 seconds
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

    // Get module base address via dlinfo (link_map) — most reliable
    // Note: dl_iterate_phdr matches MetaMod's stub server_srv.so, not the real game binary.
    // dlinfo on our RTLD_NOLOAD handle resolves to the actual server_i486.so.
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

    // Register console commands
    ConVar_Register(0, &s_BaseAccessor);

    META_CONPRINTF("[SmartBots] Extension loaded (v0.1.0) — Phase 1 active\n");

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
