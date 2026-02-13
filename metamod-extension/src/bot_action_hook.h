#ifndef _SMARTBOTS_BOT_ACTION_HOOK_H_
#define _SMARTBOTS_BOT_ACTION_HOOK_H_

#include <cstdint>

// Initialize: resolve offsets and verify signatures.
// Returns true if all signatures match.
bool BotActionHook_Init(uintptr_t serverBase);

// Install the CINSBotCombat::Update detour.
// Must call BotActionHook_Init first.
bool BotActionHook_InstallDetour();

// Remove the detour, restore original bytes.
void BotActionHook_RemoveDetour();

// Set a goto target for all bots
void BotActionHook_SetGotoTarget(float x, float y, float z);

// Clear the goto target
void BotActionHook_ClearGotoTarget();

// Check if a goto command is pending
bool BotActionHook_HasGotoTarget();

// Get the current goto target coordinates. Returns false if no target.
bool BotActionHook_GetGotoTarget(float &x, float &y, float &z);

// Issue a look-at request via IBody::AimHeadTowards vtable dispatch.
// entityPtr must be a CINSNextBot*. Priority INTERESTING (2), duration 1.0s.
// Returns true if the call was dispatched.
bool BotActionHook_IssueLookAt(void *entityPtr, float x, float y, float z);

// Issue a movement request directly to a bot entity via vtable dispatch.
// entityPtr must be a CINSNextBot* (the bot's CBaseEntity pointer).
// Returns true if the request was successfully issued.
bool BotActionHook_IssueMovementRequest(void *entityPtr, float x, float y, float z);

// Register an entity pointer → edict index mapping for the detour to use.
// Called from GameFrame after resolving bot edicts.
void BotActionHook_RegisterEntity(void *entityPtr, int edictIndex);

// Clear all entity → edict mappings. Called at the start of each GameFrame.
void BotActionHook_ClearEntityMap();

// Set whether a bot currently sees enemies (called from GameFrame after vision scan).
void BotActionHook_SetVisibleEnemy(int edictIndex, bool hasEnemy);

// Check if a bot currently sees enemies (used in combat hook).
bool BotActionHook_HasVisibleEnemy(int edictIndex);

// Clear all visibility flags (called at start of each vision scan).
void BotActionHook_ClearVisibleEnemies();

#endif // _SMARTBOTS_BOT_ACTION_HOOK_H_
