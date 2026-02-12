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

        mgr->AddListener(this, "teamplay_point_captured", true);
        mgr->AddListener(this, "round_start", true);

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

    // IGameEventListener2
    void FireGameEvent(IGameEvent *event) override
    {
        const char *name = event->GetName();

        if (strcmp(name, "teamplay_point_captured") == 0)
        {
            int cp = event->GetInt("cp");
            int team = event->GetInt("team");

            // If the capturing team is NOT our controlled team, we lost an objective
            if (team != m_controlledTeam)
            {
                m_objectivesCaptured++;
                META_CONPRINTF("[SmartBots] Objective captured (cp=%d, by team %d, total lost: %d)\n",
                               cp, team, m_objectivesCaptured);
            }
        }
        else if (strcmp(name, "round_start") == 0)
        {
            m_objectivesCaptured = 0;
            META_CONPRINTF("[SmartBots] Round start — objectives reset\n");
        }
    }

    int GetEventDebugID() override { return 42; }

private:
    IGameEventManager2 *m_pEventMgr = nullptr;
    int m_controlledTeam = 2;
    int m_objectivesCaptured = 0;
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
