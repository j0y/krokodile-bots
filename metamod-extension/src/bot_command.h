#ifndef _SMARTBOTS_BOT_COMMAND_H_
#define _SMARTBOTS_BOT_COMMAND_H_

// Per-bot command buffer for movement targets and look directions.

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

// Get the command for a specific bot. Returns true if a valid command exists.
bool BotCommand_Get(int botId, BotCommandEntry &cmd);

// Clear the voice field for a bot (fire-once: called after speaking).
void BotCommand_ClearVoice(int botId);

// Set a command for a given bot.
void BotCommand_Set(int botId, float mx, float my, float mz,
                    float lx, float ly, float lz,
                    int flags, int currentTick);

// Clear the command for a specific bot.
void BotCommand_Clear(int botId);

#endif // _SMARTBOTS_BOT_COMMAND_H_
