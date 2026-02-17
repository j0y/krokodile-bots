#include "extension.h"
#include "sig_resolve.h"
#include "spawn_scoring.h"

#include <toolframework/itoolentity.h>
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>

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

// ---- Objective scanning (via IServerTools) ----

static IServerTools *s_pServerTools = nullptr;
static bool s_objectivesScanned = false;

struct ObjectiveInfo {
    float pos[3];
    int   order;
    char  name[64];
};

static const int MAX_OBJECTIVES = 16;
static ObjectiveInfo s_objectives[MAX_OBJECTIVES];
static int s_objectiveCount = 0;

// Parse "x y z" string to float[3]
static bool ParseOrigin(const char *str, float out[3])
{
    if (!str || !str[0])
        return false;
    char buf[128];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = nullptr;
    char *tok = strtok_r(buf, " ", &saveptr);
    if (!tok) return false;
    out[0] = strtof(tok, nullptr);

    tok = strtok_r(nullptr, " ", &saveptr);
    if (!tok) return false;
    out[1] = strtof(tok, nullptr);

    tok = strtok_r(nullptr, " ", &saveptr);
    if (!tok) return false;
    out[2] = strtof(tok, nullptr);

    return true;
}

// Extract order from control point targetname
static int ParseOrder(const char *targetname)
{
    if (!targetname || !targetname[0])
        return 0;

    int len = (int)strlen(targetname);
    const char *p = targetname + len - 1;
    while (p > targetname && *(p - 1) >= '0' && *(p - 1) <= '9')
        p--;
    if (*p >= '0' && *p <= '9')
        return atoi(p);

    if (len >= 2)
    {
        char c = targetname[len - 1];
        if (c >= 'a' && c <= 'z')
            return (c - 'a') + 1;
        if (c >= 'A' && c <= 'Z')
            return (c - 'A') + 1;
    }
    return 0;
}

static void ScanObjectives()
{
    s_objectiveCount = 0;
    s_objectivesScanned = false;

    if (!s_pServerTools)
        return;

    // Pass 1: find trigger_capture_zone to identify capture-type CPs
    char captureNames[MAX_OBJECTIVES][64];
    int captureNameCount = 0;

    void *ent = s_pServerTools->FirstEntity();
    while (ent)
    {
        char classname[128] = {};
        s_pServerTools->GetKeyValue(ent, "classname", classname, sizeof(classname));

        if (strcmp(classname, "trigger_capture_zone") == 0)
        {
            char cpName[64] = {};
            s_pServerTools->GetKeyValue(ent, "controlpoint", cpName, sizeof(cpName));
            if (cpName[0] && captureNameCount < MAX_OBJECTIVES)
            {
                strncpy(captureNames[captureNameCount], cpName, sizeof(captureNames[0]) - 1);
                captureNames[captureNameCount][sizeof(captureNames[0]) - 1] = '\0';
                captureNameCount++;
            }
        }
        ent = s_pServerTools->NextEntity(ent);
    }

    // Pass 2: collect point_controlpoint, obj_weapon_cache
    ent = s_pServerTools->FirstEntity();
    while (ent)
    {
        char classname[128] = {};
        s_pServerTools->GetKeyValue(ent, "classname", classname, sizeof(classname));

        if (strcmp(classname, "point_controlpoint") == 0)
        {
            if (s_objectiveCount >= MAX_OBJECTIVES)
                goto next;

            char originStr[128] = {};
            char targetname[64] = {};
            s_pServerTools->GetKeyValue(ent, "origin", originStr, sizeof(originStr));
            s_pServerTools->GetKeyValue(ent, "targetname", targetname, sizeof(targetname));

            ObjectiveInfo &obj = s_objectives[s_objectiveCount];
            if (!ParseOrigin(originStr, obj.pos))
                goto next;

            strncpy(obj.name, targetname, sizeof(obj.name) - 1);
            obj.name[sizeof(obj.name) - 1] = '\0';
            obj.order = ParseOrder(targetname);

            // Skip names with non-printable bytes
            {
                bool valid = (targetname[0] != '\0');
                for (const char *p = targetname; *p && valid; p++)
                    if (*p < 32 || *p > 126) valid = false;
                if (!valid) goto next;
            }

            s_objectiveCount++;
        }
        else if (strcmp(classname, "obj_weapon_cache") == 0)
        {
            if (s_objectiveCount >= MAX_OBJECTIVES)
                goto next;

            char originStr[128] = {};
            char targetname[64] = {};
            char cpRef[64] = {};
            s_pServerTools->GetKeyValue(ent, "origin", originStr, sizeof(originStr));
            s_pServerTools->GetKeyValue(ent, "targetname", targetname, sizeof(targetname));
            s_pServerTools->GetKeyValue(ent, "ControlPoint", cpRef, sizeof(cpRef));

            float pos[3];
            if (!ParseOrigin(originStr, pos))
                goto next;

            // Merge with existing CP if referenced
            bool merged = false;
            for (int i = 0; i < s_objectiveCount; i++)
            {
                if (cpRef[0] && strcmp(s_objectives[i].name, cpRef) == 0)
                {
                    s_objectives[i].pos[0] = pos[0];
                    s_objectives[i].pos[1] = pos[1];
                    s_objectives[i].pos[2] = pos[2];
                    merged = true;
                    break;
                }
            }

            if (!merged)
            {
                ObjectiveInfo &obj = s_objectives[s_objectiveCount];
                obj.pos[0] = pos[0];
                obj.pos[1] = pos[1];
                obj.pos[2] = pos[2];
                strncpy(obj.name, cpRef[0] ? cpRef : targetname, sizeof(obj.name) - 1);
                obj.name[sizeof(obj.name) - 1] = '\0';
                obj.order = ParseOrder(obj.name);
                s_objectiveCount++;
            }
        }

next:
        ent = s_pServerTools->NextEntity(ent);
    }

    // Sort objectives by order
    std::sort(s_objectives, s_objectives + s_objectiveCount,
              [](const ObjectiveInfo &a, const ObjectiveInfo &b) {
                  return a.order < b.order;
              });

    s_objectivesScanned = (s_objectiveCount > 0);

    META_CONPRINTF("[NavSpawn] Scanned %d objectives\n", s_objectiveCount);
    for (int i = 0; i < s_objectiveCount; i++)
    {
        META_CONPRINTF("  [%d] '%s' order=%d at (%.0f, %.0f, %.0f)\n",
                       i, s_objectives[i].name, s_objectives[i].order,
                       s_objectives[i].pos[0], s_objectives[i].pos[1],
                       s_objectives[i].pos[2]);
    }
}

// ---- Game event listener (objective tracking) ----

static IGameEventManager2 *s_pGameEventMgr = nullptr;

class NavSpawnEventListener : public IGameEventListener2
{
public:
    void Init(IGameEventManager2 *mgr, int controlledTeam)
    {
        m_pEventMgr = mgr;
        m_controlledTeam = controlledTeam;
        m_objectivesLost = 0;
        m_registered = false;
    }

    void RegisterListeners()
    {
        if (m_registered || !m_pEventMgr)
            return;
        m_registered = true;

        const char *events[] = {
            "round_start", "controlpoint_captured",
            "object_destroyed", "round_level_advanced",
        };

        for (const char *ev : events)
        {
            if (!m_pEventMgr->AddListener(this, ev, true))
                META_CONPRINTF("[NavSpawn] Event '%s' failed to register\n", ev);
        }

        META_CONPRINTF("[NavSpawn] Event listeners registered\n");
    }

    void Shutdown()
    {
        if (m_pEventMgr && m_registered)
        {
            m_pEventMgr->RemoveListener(this);
            m_pEventMgr = nullptr;
        }
    }

    int GetObjectivesLost() const { return m_objectivesLost; }

    // Current active objective index (clamped)
    int GetCurrentObjectiveIndex() const
    {
        if (m_objectivesLost >= s_objectiveCount && s_objectiveCount > 0)
            return s_objectiveCount - 1;
        return m_objectivesLost;
    }

    void FireGameEvent(IGameEvent *event) override
    {
        const char *name = event->GetName();

        if (strcmp(name, "round_start") == 0)
        {
            m_objectivesLost = 0;
            META_CONPRINTF("[NavSpawn] Round start - objectives reset\n");

            // Rescan objectives on round start
            ScanObjectives();
        }
        else if (strcmp(name, "controlpoint_captured") == 0)
        {
            int team = event->GetInt("team");
            // Attackers capturing = defenders lose an objective
            if (team != m_controlledTeam)
            {
                m_objectivesLost++;
                META_CONPRINTF("[NavSpawn] Objective lost (total: %d)\n", m_objectivesLost);
            }
        }
        else if (strcmp(name, "object_destroyed") == 0)
        {
            m_objectivesLost++;
            META_CONPRINTF("[NavSpawn] Object destroyed (total lost: %d)\n", m_objectivesLost);
        }
        else if (strcmp(name, "round_level_advanced") == 0)
        {
            m_objectivesLost++;
            META_CONPRINTF("[NavSpawn] Level advanced (total lost: %d)\n", m_objectivesLost);
        }
    }

    int GetEventDebugID() override { return 43; }

private:
    IGameEventManager2 *m_pEventMgr = nullptr;
    int m_controlledTeam = 3;
    int m_objectivesLost = 0;
    bool m_registered = false;
};

static NavSpawnEventListener s_eventListener;

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

    // Deferred initialization on first tick
    if (s_tickCount == 1)
    {
        s_eventListener.RegisterListeners();
        ScanObjectives();
    }

    // Update player positions + objective at 8Hz
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

        // Update current objective
        int objIdx = s_eventListener.GetCurrentObjectiveIndex();
        if (s_objectivesScanned && objIdx >= 0 && objIdx < s_objectiveCount)
        {
            SpawnScoring_SetObjective(
                s_objectives[objIdx].pos[0],
                s_objectives[objIdx].pos[1],
                s_objectives[objIdx].pos[2]);
        }

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

    // Initialize game event listener
    {
        IGameEventManager2 *pGameEventMgr = nullptr;
        GET_V_IFACE_CURRENT(GetEngineFactory, pGameEventMgr,
                             IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
        s_eventListener.Init(pGameEventMgr, controlledTeam);
    }

    // Resolve game rules for counter-attack detection
    s_pGameRules = reinterpret_cast<void **>(
        s_serverBase + ServerOffsets::g_pGameRules);
    s_fnIsCounterAttack = reinterpret_cast<IsCounterAttackFn>(
        s_serverBase + ServerOffsets::CINSRules_IsCounterAttack);

    // Initialize IServerTools for objective scanning
    {
        CreateInterfaceFn serverFactory = ismm->GetServerFactory(false);
        if (serverFactory)
        {
            int ret = 0;
            s_pServerTools = static_cast<IServerTools *>(
                serverFactory(VSERVERTOOLS_INTERFACE_VERSION, &ret));
        }
        if (!s_pServerTools)
            META_CONPRINTF("[NavSpawn] WARNING: IServerTools not available - no objective scanning\n");
    }

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
    // Unregister game event listener
    s_eventListener.Shutdown();

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
