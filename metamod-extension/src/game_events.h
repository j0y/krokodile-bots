#ifndef _SMARTBOTS_GAME_EVENTS_H_
#define _SMARTBOTS_GAME_EVENTS_H_

#include <igameevents.h>

// Initialize: get IGameEventManager2, register listener.
// controlledTeam: team index we're defending (2 = Security).
// When the *other* team captures a point, we increment the counter.
bool GameEvents_Init(IGameEventManager2 *eventMgr, int controlledTeam);

// Unregister listener. Call on plugin unload.
void GameEvents_Shutdown();

// Number of objectives captured by the attacking team since last round_start.
int GameEvents_GetObjectivesCaptured();

#endif // _SMARTBOTS_GAME_EVENTS_H_
