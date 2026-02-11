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

// Set a goto target. Next time any bot's CINSBotCombat::Update fires,
// it will be redirected to CINSBotApproach(target).
void BotActionHook_SetGotoTarget(float x, float y, float z);

// Check if a goto command is pending
bool BotActionHook_HasGotoTarget();

#endif // _SMARTBOTS_BOT_ACTION_HOOK_H_
