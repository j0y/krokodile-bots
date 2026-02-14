#ifndef _SMARTBOTS_BOT_COMMAND_H_
#define _SMARTBOTS_BOT_COMMAND_H_

// Parse movement commands from Python brain, maintain per-bot command buffer.
// Command format (line-based text): "<id> <mx> <my> <mz> <lx> <ly> <lz> <flags>\n"

static const int MAX_BOT_SLOTS = 33;  // edicts 1..32

struct BotCommandEntry {
    float moveTarget[3];
    float lookTarget[3];
    int flags;
    int voice;        // concept ID to speak (0 = silent)
    int tick;         // game tick when received (for age tracking)
    bool valid;       // has a command been received for this bot?
};

// Initialize command buffer (clear all entries).
void BotCommand_Init();

// Parse a received data buffer containing one or more command lines.
// Each line: "<id> <mx> <my> <mz> <lx> <ly> <lz> <flags>\n"
void BotCommand_Parse(const char *data, int len, int currentTick);

// Get the command for a specific bot. Returns true if a valid command exists.
bool BotCommand_Get(int botId, BotCommandEntry &cmd);

// Clear the voice field for a bot (fire-once: called after speaking).
void BotCommand_ClearVoice(int botId);

// Invalidate commands older than maxAge ticks.
void BotCommand_ClearStale(int currentTick, int maxAge);

#endif // _SMARTBOTS_BOT_COMMAND_H_
