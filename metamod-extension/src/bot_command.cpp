#include "bot_command.h"

#include <cstring>

static BotCommandEntry s_commands[MAX_BOT_SLOTS];

void BotCommand_Init()
{
    memset(s_commands, 0, sizeof(s_commands));
}

bool BotCommand_Get(int botId, BotCommandEntry &cmd)
{
    if (botId < 1 || botId >= MAX_BOT_SLOTS)
        return false;

    if (!s_commands[botId].valid)
        return false;

    cmd = s_commands[botId];
    return true;
}

void BotCommand_ClearVoice(int botId)
{
    if (botId >= 1 && botId < MAX_BOT_SLOTS)
        s_commands[botId].voice = 0;
}

void BotCommand_Set(int botId, float mx, float my, float mz,
                    float lx, float ly, float lz,
                    int flags, int currentTick)
{
    if (botId < 1 || botId >= MAX_BOT_SLOTS)
        return;

    BotCommandEntry &cmd = s_commands[botId];
    cmd.moveTarget[0] = mx;
    cmd.moveTarget[1] = my;
    cmd.moveTarget[2] = mz;
    cmd.lookTarget[0] = lx;
    cmd.lookTarget[1] = ly;
    cmd.lookTarget[2] = lz;
    cmd.flags = flags;
    cmd.voice = 0;
    cmd.tick = currentTick;
    cmd.valid = true;
}

void BotCommand_Clear(int botId)
{
    if (botId >= 1 && botId < MAX_BOT_SLOTS)
        s_commands[botId].valid = false;
}
