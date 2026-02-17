#ifndef _SMARTBOTS_NAV_FLANKING_H_
#define _SMARTBOTS_NAV_FLANKING_H_

#include <cstdint>

// Initialize nav flanking system: resolve TheNavMesh, function pointers.
// Non-fatal — returns false if resolution fails but extension continues.
bool NavFlanking_Init(uintptr_t serverBase);

// Update position scoring for eligible bots.
// botEdicts: array of edict indices for flanking-eligible bots (alive, no visible enemy).
// botEntities: parallel array of entity pointers (void* to CINSNextBot).
// botPositions: parallel array of [x,y,z] positions.
// botHealths: parallel array of current health values (for damage-triggered re-eval).
// botCount: number of entries.
// enemyPositions: array of [x,y,z] enemy positions from team intel.
// enemyCount: number of enemies.
void NavFlanking_Update(const int *botEdicts, void *const *botEntities,
                        const float (*botPositions)[3], const int *botHealths,
                        int botCount,
                        const float (*enemyPositions)[3], int enemyCount);

// Get the next movement waypoint for a bot. Returns false if no active path.
bool NavFlanking_GetTarget(int edictIndex, float &x, float &y, float &z);

// Check if a bot has an active flanking path.
bool NavFlanking_IsActive(int edictIndex);

// Clear all flanking state (round start / map change).
void NavFlanking_Reset();

// Get the defend ratio ConVar value (fraction of bots that defend objective).
float NavFlanking_GetDefendRatio();

#endif // _SMARTBOTS_NAV_FLANKING_H_
