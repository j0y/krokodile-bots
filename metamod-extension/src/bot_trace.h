#ifndef _SMARTBOTS_BOT_TRACE_H_
#define _SMARTBOTS_BOT_TRACE_H_

#include "bot_state.h"

// CSV position logger — writes bot state to /dev/shm/ for debug.
// Copy from container: docker cp insurgency-server:/dev/shm/smartbots_trace.csv .

// Open/create the trace file.  Safe to call multiple times (reopens on round start).
void BotTrace_Open();

// Write one snapshot of all bots.  Call at ~1Hz from GameFrame.
// stateArray/stateCount: same arrays used for the UDP bridge.
// tick: current game tick.
void BotTrace_Write(const BotStateEntry *stateArray, int stateCount, int tick);

// Close the file (plugin unload).
void BotTrace_Close();

#endif // _SMARTBOTS_BOT_TRACE_H_
