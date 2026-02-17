#ifndef _NAVSPAWNING_SPAWN_SCORING_H_
#define _NAVSPAWNING_SPAWN_SCORING_H_

#include <cstdint>

// Initialize: resolve nav mesh pointers and game rules from server base.
// controlledTeam: the team the bots defend (3 = Insurgents by default).
bool SpawnScoring_Init(uintptr_t serverBase, int controlledTeam);

// Install the CINSNextBot::Spawn detour.
bool SpawnScoring_InstallDetour(uintptr_t serverBase);

// Remove the Spawn detour, restore original bytes.
void SpawnScoring_RemoveDetour();

// Update cached player positions (called from GameFrame).
// positions: array of [x,y,z], teams: parallel team indices, count: number of players.
void SpawnScoring_UpdatePlayers(const float (*positions)[3], const int *teams, int count);

// Update cached player nav areas (called from GameFrame after UpdatePlayers).
void SpawnScoring_UpdatePlayerNavAreas();

// Set counter-attack state (changes scoring bias).
void SpawnScoring_SetCounterAttack(bool active);

#endif // _NAVSPAWNING_SPAWN_SCORING_H_
