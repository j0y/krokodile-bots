#ifndef _SMARTBOTS_GAME_EVENTS_H_
#define _SMARTBOTS_GAME_EVENTS_H_

#include <cstdint>
#include <igameevents.h>

// Store references for deferred event registration.
// Events must be registered after map load, not during plugin Load().
bool GameEvents_Init(IGameEventManager2 *eventMgr, int controlledTeam);

// Actually register event listeners. Call from GameFrame on first tick.
void GameEvents_RegisterListeners();

// Unregister listener. Call on plugin unload.
void GameEvents_Shutdown();

// Number of objectives captured by the attacking team since last round_start.
int GameEvents_GetObjectivesCaptured();

// Round phase: "preround", "active", "over"
const char *GameEvents_GetPhase();

// Control point currently being captured by enemy (-1 if none).
int GameEvents_GetCappingCP();

// Counter-attack ConVar accessors (cached on first call).
// mp_checkpoint_counterattack_disable (0 = enabled, 1 = disabled)
bool GameEvents_CounterAttackDisabled();
// mp_checkpoint_counterattack_duration (default 65)
int GameEvents_CounterAttackDuration();
// mp_checkpoint_counterattack_duration_finale (default 120)
int GameEvents_CounterAttackDurationFinale();

// Live counter-attack state from CINSRules::IsCounterAttack().
// Must be initialized with the server module base via GameEvents_InitGameRules().
void GameEvents_InitGameRules(uintptr_t serverBase);
bool GameEvents_IsCounterAttack();

#endif // _SMARTBOTS_GAME_EVENTS_H_
