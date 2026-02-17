#include "extension.h"
#include "sig_resolve.h"
#include "spawn_scoring.h"

#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cmath>

NavSpawningExtension g_Extension;
PLUGIN_EXPOSE(NavSpawningExtension, g_Extension);

// SourceHook: GameFrame hook declaration
SH_DECL_HOOK1_void(IServerGameDLL, GameFrame, SH_NOATTRIB, 0, bool);

// Engine interfaces
IServerGameDLL *g_pServerGameDLL = nullptr;
IVEngineServer *g_pEngineServer = nullptr;
IPlayerInfoManager *g_pPlayerInfoManager = nullptr;
ICvar *g_pCVar = nullptr;
CGlobalVars *gpGlobals = nullptr;

// Server module handle
void *g_pServerHandle = nullptr;

// Server module base address
static uintptr_t s_serverBase = 0;

// Tick counter
static int s_tickCount = 0;

// ---- Counter-attack state ----

// x86-32 Linux/GCC thiscall: `this` is first stack argument
typedef bool (*IsCounterAttackFn)(void *thisRules);

static void **s_pGameRules = nullptr;
static IsCounterAttackFn s_fnIsCounterAttack = nullptr;

static bool IsCounterAttack()
{
    if (!s_pGameRules || !s_fnIsCounterAttack)
        return false;
    void *rules = *s_pGameRules;
    if (!rules)
        return false;
    return s_fnIsCounterAttack(rules);
}

// ---- ConVar registration ----

class BaseAccessor : public IConCommandBaseAccessor
{
public:
    bool RegisterConCommandBase(ConCommandBase *pCommandBase)
    {
        return META_REGCVAR(pCommandBase);
    }
} s_BaseAccessor;

// ---- GameFrame hook ----

void NavSpawningExtension::Hook_GameFrame(bool simulating)
{
    if (!simulating)
    {
        RETURN_META(MRES_IGNORED);
    }

    s_tickCount++;

    // Update player positions at 8Hz
    if (s_tickCount % 8 == 0 && g_pPlayerInfoManager && gpGlobals)
    {
        float positions[32][3];
        int teams[32];
        int count = 0;

        int maxClients = gpGlobals->maxClients;
        for (int i = 1; i <= maxClients && count < 32; i++)
        {
            edict_t *edict = PEntityOfEntIndex(i);
            if (!edict || edict->IsFree())
                continue;

            IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
            if (!info || !info->IsConnected())
                continue;

            // Only cache human players for distance/visibility checks
            if (info->IsFakeClient())
                continue;

            if (info->IsDead())
                continue;

            Vector pos = info->GetAbsOrigin();
            positions[count][0] = pos.x;
            positions[count][1] = pos.y;
            positions[count][2] = pos.z;
            teams[count] = info->GetTeamIndex();
            count++;
        }

        SpawnScoring_UpdatePlayers(
            reinterpret_cast<const float(*)[3]>(positions), teams, count);
        SpawnScoring_UpdatePlayerNavAreas();

        // Update counter-attack state
        SpawnScoring_SetCounterAttack(IsCounterAttack());
    }

    RETURN_META(MRES_IGNORED);
}

// ---- Plugin lifecycle ----

bool NavSpawningExtension::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
    PLUGIN_SAVEVARS();

    GET_V_IFACE_CURRENT(GetEngineFactory, g_pEngineServer, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
    GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
    GET_V_IFACE_ANY(GetServerFactory, g_pServerGameDLL, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
    GET_V_IFACE_ANY(GetServerFactory, g_pPlayerInfoManager, IPlayerInfoManager, INTERFACEVERSION_PLAYERINFOMANAGER);

    gpGlobals = ismm->GetCGlobals();

    // Resolve server module
    g_pServerHandle = dlopen("insurgency/bin/server_srv.so", RTLD_NOW | RTLD_NOLOAD);
    if (!g_pServerHandle)
    {
        snprintf(error, maxlen, "Failed to get server_srv.so handle: %s", dlerror());
        return false;
    }

    s_serverBase = GetServerModuleBaseFromHandle(g_pServerHandle);
    if (s_serverBase == 0)
    {
        snprintf(error, maxlen, "Failed to resolve server_srv.so base address");
        return false;
    }

    // Read controlled team from environment (matches smartbots extension convention)
    const char *teamEnv = std::getenv("CONTROLLED_TEAM");
    int controlledTeam = teamEnv ? std::atoi(teamEnv) : 3;
    META_CONPRINTF("[NavSpawn] Controlled team: %d\n", controlledTeam);

    // Initialize spawn scoring (nav mesh + game rules pointers)
    if (!SpawnScoring_Init(s_serverBase, controlledTeam))
    {
        snprintf(error, maxlen, "SpawnScoring init failed");
        return false;
    }

    // Install Spawn detour
    if (!SpawnScoring_InstallDetour(s_serverBase))
    {
        snprintf(error, maxlen, "Failed to install Spawn detour");
        return false;
    }

    // Hook GameFrame via SourceHook
    SH_ADD_HOOK_MEMFUNC(IServerGameDLL, GameFrame, g_pServerGameDLL, this,
                        &NavSpawningExtension::Hook_GameFrame, true);

    // Register ConVars
    ConVar_Register(0, &s_BaseAccessor);

    // Resolve game rules for counter-attack detection
    s_pGameRules = reinterpret_cast<void **>(
        s_serverBase + ServerOffsets::g_pGameRules);
    s_fnIsCounterAttack = reinterpret_cast<IsCounterAttackFn>(
        s_serverBase + ServerOffsets::CINSRules_IsCounterAttack);

    META_CONPRINTF("[NavSpawn] Extension loaded (v0.1.0)\n");

    if (late)
        META_CONPRINTF("[NavSpawn] Late load - server already running\n");

    return true;
}

void NavSpawningExtension::AllPluginsLoaded()
{
    META_CONPRINTF("[NavSpawn] All plugins loaded\n");
}

bool NavSpawningExtension::Unload(char *error, size_t maxlen)
{
    // Remove Spawn detour
    SpawnScoring_RemoveDetour();

    // Remove SourceHook hooks
    SH_REMOVE_HOOK_MEMFUNC(IServerGameDLL, GameFrame, g_pServerGameDLL, this,
                           &NavSpawningExtension::Hook_GameFrame, true);

    if (g_pServerHandle)
    {
        dlclose(g_pServerHandle);
        g_pServerHandle = nullptr;
    }

    META_CONPRINTF("[NavSpawn] Extension unloaded\n");
    return true;
}
