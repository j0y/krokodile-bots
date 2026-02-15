#ifndef _SMARTBOTS_BOT_TACTICS_H_
#define _SMARTBOTS_BOT_TACTICS_H_

#include <cstdint>

// Tactical deployment: spreads bots around the current objective from
// multiple directions with staggered timing.
//
// Each 8Hz tick, writes BotCommand entries for bots that are "activated"
// (their deploy delay has elapsed).  The checkpoint hook consumes these
// the same way it consumed Python commands.

// Initialize: resolve nav mesh pointers for position snapping.
bool BotTactics_Init(uintptr_t serverBase);

// Main update — call at 8Hz from GameFrame.
// botEdicts/botEntities/botPositions: parallel arrays of alive friendly bots.
// currentTick: for BotCommand timestamps.
void BotTactics_Update(const int *botEdicts, const float (*botPositions)[3],
                       int botCount, int currentTick);

// Reset all tactical state (round start, map change).
void BotTactics_Reset();

#endif // _SMARTBOTS_BOT_TACTICS_H_
