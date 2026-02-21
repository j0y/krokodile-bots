#include "game_events.h"
#include "extension.h"
#include "sig_resolve.h"
#include <convar.h>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro

// ---- Death zone tracking ----

static const int MAX_DEATH_ZONES = 16;

struct DeathZoneEntry {
    float pos[3];
    float time;
    bool  active;
};

static DeathZoneEntry s_deathZones[MAX_DEATH_ZONES];
static int s_deathZoneHead = 0;  // ring buffer write index

// Pending deaths — queued in event handler, processed in GameFrame
static float s_pendingDeaths[MAX_DEATH_ZONES][3];
static int   s_pendingDeathCount = 0;

class SmartBotsEventListener : public IGameEventListener2
{
public:
    void Init(IGameEventManager2 *mgr, int controlledTeam)
    {
        m_pEventMgr = mgr;
        m_controlledTeam = controlledTeam;
        m_objectivesLost = 0;
        // Default to "active" so strategist works even if events never fire
        m_phase = "active";
        m_cappingCP = -1;
        m_registered = false;

        META_CONPRINTF("[SmartBots] Game events: init (controlled team: %d, registration deferred)\n",
                       controlledTeam);
    }

    void RegisterListeners()
    {
        if (m_registered || !m_pEventMgr)
            return;

        m_registered = true;

        const char *events[] = {
            "round_start", "round_begin", "round_end",
            "round_freeze_end",
            "controlpoint_captured", "controlpoint_starttouch",
            "controlpoint_endtouch",
            "object_destroyed",
            "round_level_advanced",
            "game_end",
            "player_death",
        };

        for (const char *ev : events)
        {
            if (!m_pEventMgr->AddListener(this, ev, true))
            {
                META_CONPRINTF("[SmartBots] Game events: '%s' failed to register\n", ev);
            }
        }

        META_CONPRINTF("[SmartBots] Game events: listeners registered (deferred)\n");
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
    const char *GetPhase() const { return m_phase; }
    int GetCappingCP() const { return m_cappingCP; }

    void RecordObjectiveLost(const char *source)
    {
        if (strcmp(m_phase, "over") == 0)
        {
            META_CONPRINTF("[SmartBots] Ignoring objective event [%s] — round is over\n", source);
            return;
        }
        m_objectivesLost++;
        memset(s_deathZones, 0, sizeof(s_deathZones));
        s_deathZoneHead = 0;
        META_CONPRINTF("[SmartBots] Objective lost [%s] (total lost: %d, death zones cleared)\n",
                       source, m_objectivesLost);
    }

    // IGameEventListener2
    void FireGameEvent(IGameEvent *event) override
    {
        const char *name = event->GetName();

        if (strcmp(name, "round_start") == 0)
        {
            // In coop checkpoint, round_start fires once at game start and
            // again when Security fails and the map restarts.
            // No round_start fires between objectives within a round.
            m_objectivesLost = 0;
            m_phase = "preround";
            m_cappingCP = -1;
            memset(s_deathZones, 0, sizeof(s_deathZones));
            s_deathZoneHead = 0;
            META_CONPRINTF("[SmartBots] Round start — preround\n");
        }
        else if (strcmp(name, "game_end") == 0)
        {
            META_CONPRINTF("[SmartBots] Game ended — resetting objectives (was %d)\n",
                           m_objectivesLost);
            m_objectivesLost = 0;
        }
        else if (strcmp(name, "round_begin") == 0 || strcmp(name, "round_freeze_end") == 0)
        {
            m_phase = "active";
            META_CONPRINTF("[SmartBots] Round active\n");
        }
        else if (strcmp(name, "round_end") == 0)
        {
            int winner = event->GetInt("winner");
            m_phase = "over";
            m_cappingCP = -1;

            META_CONPRINTF("[SmartBots] Round over (winner: team %d, objectives lost: %d)\n",
                           winner, m_objectivesLost);
        }
        else if (strcmp(name, "controlpoint_captured") == 0)
        {
            int cp = event->GetInt("cp");
            int team = event->GetInt("team");
            m_cappingCP = -1;

            if (team != m_controlledTeam)
            {
                char src[64];
                snprintf(src, sizeof(src), "controlpoint_captured cp=%d team=%d", cp, team);
                RecordObjectiveLost(src);
            }
        }
        else if (strcmp(name, "object_destroyed") == 0)
        {
            RecordObjectiveLost("object_destroyed");
        }
        else if (strcmp(name, "round_level_advanced") == 0)
        {
            int level = event->GetInt("level");
            m_cappingCP = -1;
            char src[64];
            snprintf(src, sizeof(src), "round_level_advanced level=%d", level);
            RecordObjectiveLost(src);
        }
        else if (strcmp(name, "controlpoint_starttouch") == 0)
        {
            int area = event->GetInt("area");
            int team = event->GetInt("team");

            // Enemy stepping on capture point
            if (team != m_controlledTeam)
            {
                m_cappingCP = area;
                META_CONPRINTF("[SmartBots] Capture started (cp=%d, by team %d)\n", area, team);
            }
        }
        else if (strcmp(name, "player_death") == 0)
        {
            // player_death 'team' field uses 0-based indexing (0=Security, 1=Insurgent)
            // while engine teams are 2-based (2=Security, 3=Insurgent)
            int team = event->GetInt("team");
            if (team == m_controlledTeam - 2)
            {
                float x = event->GetFloat("x");
                float y = event->GetFloat("y");
                float z = event->GetFloat("z");

                DeathZoneEntry &dz = s_deathZones[s_deathZoneHead];
                dz.pos[0] = x;
                dz.pos[1] = y;
                dz.pos[2] = z;
                dz.time = gpGlobals->curtime;
                dz.active = true;
                s_deathZoneHead = (s_deathZoneHead + 1) % MAX_DEATH_ZONES;

                META_CONPRINTF("[SmartBots] Death zone recorded at (%.0f, %.0f, %.0f)\n", x, y, z);

                // Queue for deferred nav mesh spreading (unsafe to write nav areas
                // from inside event handler — engine may be iterating nav areas)
                if (s_pendingDeathCount < MAX_DEATH_ZONES)
                {
                    s_pendingDeaths[s_pendingDeathCount][0] = x;
                    s_pendingDeaths[s_pendingDeathCount][1] = y;
                    s_pendingDeaths[s_pendingDeathCount][2] = z;
                    s_pendingDeathCount++;
                }
            }
        }
        else if (strcmp(name, "controlpoint_endtouch") == 0)
        {
            int team = event->GetInt("team");

            // Enemy left the capture point — clear capping flag
            if (team != m_controlledTeam && m_cappingCP >= 0)
            {
                META_CONPRINTF("[SmartBots] Capture ended (cp=%d, team %d left)\n", m_cappingCP, team);
                m_cappingCP = -1;
            }
        }
    }

    int GetEventDebugID() override { return 42; }

private:
    IGameEventManager2 *m_pEventMgr = nullptr;
    int m_controlledTeam = 2;
    int m_objectivesLost = 0;
    const char *m_phase = "active";
    int m_cappingCP = -1;
    bool m_registered = false;
};

static SmartBotsEventListener s_listener;

bool GameEvents_Init(IGameEventManager2 *eventMgr, int controlledTeam)
{
    if (!eventMgr)
        return false;

    s_listener.Init(eventMgr, controlledTeam);
    return true;
}

void GameEvents_RegisterListeners()
{
    s_listener.RegisterListeners();
}

void GameEvents_Shutdown()
{
    s_listener.Shutdown();
}

int GameEvents_GetObjectivesLost()
{
    return s_listener.GetObjectivesLost();
}

const char *GameEvents_GetPhase()
{
    return s_listener.GetPhase();
}

int GameEvents_GetCappingCP()
{
    return s_listener.GetCappingCP();
}

// --- Counter-attack ConVar accessors (lazy-cached) ---

static ConVar *s_cvCADisable = nullptr;
static ConVar *s_cvCADuration = nullptr;
static ConVar *s_cvCADurationFinale = nullptr;
static bool s_cvCACached = false;

static void CacheCounterAttackCVars()
{
    if (s_cvCACached)
        return;
    s_cvCACached = true;
    s_cvCADisable = g_pCVar->FindVar("mp_checkpoint_counterattack_disable");
    s_cvCADuration = g_pCVar->FindVar("mp_checkpoint_counterattack_duration");
    s_cvCADurationFinale = g_pCVar->FindVar("mp_checkpoint_counterattack_duration_finale");
}

bool GameEvents_CounterAttackDisabled()
{
    CacheCounterAttackCVars();
    return s_cvCADisable ? s_cvCADisable->GetBool() : false;
}

int GameEvents_CounterAttackDuration()
{
    CacheCounterAttackCVars();
    return s_cvCADuration ? s_cvCADuration->GetInt() : 65;
}

int GameEvents_CounterAttackDurationFinale()
{
    CacheCounterAttackCVars();
    return s_cvCADurationFinale ? s_cvCADurationFinale->GetInt() : 120;
}

// --- Live counter-attack state via CINSRules::IsCounterAttack() ---

// x86-32 Linux/GCC thiscall: `this` is first stack argument (not ECX)
typedef bool (*IsCounterAttackFn)(void *thisRules);

static void **s_pGameRules = nullptr;       // &g_pGameRules (pointer to pointer)
static IsCounterAttackFn s_fnIsCA = nullptr;

void GameEvents_InitGameRules(uintptr_t serverBase)
{
    s_pGameRules = reinterpret_cast<void **>(
        serverBase + ServerOffsets::g_pGameRules);
    s_fnIsCA = reinterpret_cast<IsCounterAttackFn>(
        serverBase + ServerOffsets::CINSRules_IsCounterAttack);
    META_CONPRINTF("[SmartBots] GameRules: resolved g_pGameRules=%p, IsCounterAttack=%p\n",
                   (void *)s_pGameRules, (void *)s_fnIsCA);
}

bool GameEvents_IsCounterAttack()
{
    if (!s_pGameRules || !s_fnIsCA)
        return false;
    void *rules = *s_pGameRules;
    if (!rules)
        return false;
    return s_fnIsCA(rules);
}

// ---- Pending death drain (called from GameFrame) ----

int GameEvents_DrainPendingDeaths(float (*outPositions)[3], int maxCount)
{
    int count = s_pendingDeathCount;
    if (count > maxCount)
        count = maxCount;
    for (int i = 0; i < count; i++)
    {
        outPositions[i][0] = s_pendingDeaths[i][0];
        outPositions[i][1] = s_pendingDeaths[i][1];
        outPositions[i][2] = s_pendingDeaths[i][2];
    }
    s_pendingDeathCount = 0;
    return count;
}

// ---- Death zone API ----

int GameEvents_GetDeathZones(float maxAge, float (*outPositions)[3], float *outTimes, int maxCount)
{
    float curtime = gpGlobals->curtime;
    int count = 0;
    for (int i = 0; i < MAX_DEATH_ZONES && count < maxCount; i++)
    {
        if (!s_deathZones[i].active)
            continue;
        float age = curtime - s_deathZones[i].time;
        if (age > maxAge || age < 0.0f)
            continue;
        outPositions[count][0] = s_deathZones[i].pos[0];
        outPositions[count][1] = s_deathZones[i].pos[1];
        outPositions[count][2] = s_deathZones[i].pos[2];
        outTimes[count] = s_deathZones[i].time;
        count++;
    }
    return count;
}
