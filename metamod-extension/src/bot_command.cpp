#include "bot_command.h"

#include <cstring>
#include <cstdio>

static BotCommandEntry s_commands[MAX_BOT_SLOTS];

void BotCommand_Init()
{
    memset(s_commands, 0, sizeof(s_commands));
}

void BotCommand_Parse(const char *data, int len, int currentTick)
{
    // Work on a null-terminated copy
    char buf[4096];
    int copyLen = (len < (int)sizeof(buf) - 1) ? len : (int)sizeof(buf) - 1;
    memcpy(buf, data, copyLen);
    buf[copyLen] = '\0';

    // Tokenize by newlines
    char *line = buf;
    while (line && *line)
    {
        // Find end of line
        char *eol = strchr(line, '\n');
        if (eol)
            *eol = '\0';

        // Skip empty lines
        if (*line == '\0')
        {
            if (eol)
                line = eol + 1;
            else
                break;
            continue;
        }

        // Parse: "<id> <mx> <my> <mz> <lx> <ly> <lz> <flags> <voice>"
        int id = 0;
        float mx, my, mz, lx, ly, lz;
        int flags = 0;
        int voice = 0;

        int parsed = sscanf(line, "%d %f %f %f %f %f %f %d %d",
                            &id, &mx, &my, &mz, &lx, &ly, &lz, &flags, &voice);

        if (parsed >= 7 && id >= 1 && id < MAX_BOT_SLOTS)
        {
            BotCommandEntry &cmd = s_commands[id];
            cmd.moveTarget[0] = mx;
            cmd.moveTarget[1] = my;
            cmd.moveTarget[2] = mz;
            cmd.lookTarget[0] = lx;
            cmd.lookTarget[1] = ly;
            cmd.lookTarget[2] = lz;
            cmd.flags = (parsed >= 8) ? flags : 0;
            cmd.voice = (parsed >= 9) ? voice : 0;
            cmd.tick = currentTick;
            cmd.valid = true;
        }

        if (eol)
            line = eol + 1;
        else
            break;
    }
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

void BotCommand_ClearStale(int currentTick, int maxAge)
{
    for (int i = 0; i < MAX_BOT_SLOTS; i++)
    {
        if (s_commands[i].valid && (currentTick - s_commands[i].tick) > maxAge)
        {
            s_commands[i].valid = false;
        }
    }
}
