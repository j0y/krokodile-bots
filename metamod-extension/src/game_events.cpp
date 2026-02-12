#include "game_events.h"
#include "extension.h"

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro

class SmartBotsEventListener : public IGameEventListener2
{
public:
    void Init(IGameEventManager2 *mgr, int controlledTeam)
    {
        m_pEventMgr = mgr;
        m_controlledTeam = controlledTeam;
        m_objectivesCaptured = 0;
        m_phase = "over";
        m_cappingCP = -1;

        mgr->AddListener(this, "round_start", true);
        mgr->AddListener(this, "teamplay_round_active", true);
        mgr->AddListener(this, "teamplay_round_win", true);
        mgr->AddListener(this, "teamplay_point_captured", true);
        mgr->AddListener(this, "teamplay_point_startcapture", true);

        META_CONPRINTF("[SmartBots] Game event listener registered (controlled team: %d)\n",
                       controlledTeam);
    }

    void Shutdown()
    {
        if (m_pEventMgr)
        {
            m_pEventMgr->RemoveListener(this);
            m_pEventMgr = nullptr;
        }
    }

    int GetObjectivesCaptured() const { return m_objectivesCaptured; }
    const char *GetPhase() const { return m_phase; }
    int GetCappingCP() const { return m_cappingCP; }

    // IGameEventListener2
    void FireGameEvent(IGameEvent *event) override
    {
        const char *name = event->GetName();

        if (strcmp(name, "round_start") == 0)
        {
            m_objectivesCaptured = 0;
            m_phase = "preround";
            m_cappingCP = -1;
            META_CONPRINTF("[SmartBots] Round start — preround (objectives reset)\n");
        }
        else if (strcmp(name, "teamplay_round_active") == 0)
        {
            m_phase = "active";
            META_CONPRINTF("[SmartBots] Round active\n");
        }
        else if (strcmp(name, "teamplay_round_win") == 0)
        {
            int winner = event->GetInt("team");
            m_phase = "over";
            m_cappingCP = -1;
            META_CONPRINTF("[SmartBots] Round over (winner: team %d)\n", winner);
        }
        else if (strcmp(name, "teamplay_point_captured") == 0)
        {
            int cp = event->GetInt("cp");
            int team = event->GetInt("team");
            m_cappingCP = -1;

            // If the capturing team is NOT our controlled team, we lost an objective
            if (team != m_controlledTeam)
            {
                m_objectivesCaptured++;
                META_CONPRINTF("[SmartBots] Objective captured (cp=%d, by team %d, total lost: %d)\n",
                               cp, team, m_objectivesCaptured);
            }
        }
        else if (strcmp(name, "teamplay_point_startcapture") == 0)
        {
            int cp = event->GetInt("cp");
            int capteam = event->GetInt("capteam");

            // Only track if enemy is capping (not our team recapping)
            if (capteam != m_controlledTeam)
            {
                m_cappingCP = cp;
                META_CONPRINTF("[SmartBots] Capture started (cp=%d, by team %d)\n", cp, capteam);
            }
        }
    }

    int GetEventDebugID() override { return 42; }

private:
    IGameEventManager2 *m_pEventMgr = nullptr;
    int m_controlledTeam = 2;
    int m_objectivesCaptured = 0;
    const char *m_phase = "over";
    int m_cappingCP = -1;
};

static SmartBotsEventListener s_listener;

bool GameEvents_Init(IGameEventManager2 *eventMgr, int controlledTeam)
{
    if (!eventMgr)
        return false;

    s_listener.Init(eventMgr, controlledTeam);
    return true;
}

void GameEvents_Shutdown()
{
    s_listener.Shutdown();
}

int GameEvents_GetObjectivesCaptured()
{
    return s_listener.GetObjectivesCaptured();
}

const char *GameEvents_GetPhase()
{
    return s_listener.GetPhase();
}

int GameEvents_GetCappingCP()
{
    return s_listener.GetCappingCP();
}
