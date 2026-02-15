#include "extension.h"
#include "bot_trace.h"
#include "bot_command.h"
#include "bot_action_hook.h"
#include "nav_objectives.h"

#include <cstdio>

extern ISmmAPI *g_SMAPI;

static FILE *s_file = nullptr;
static const char *TRACE_PATH = "/dev/shm/smartbots_trace.csv";

static void WriteHeader()
{
    if (!s_file)
        return;
    fprintf(s_file,
            "tick,time,bot_id,x,y,z,yaw,alive,health,team,"
            "has_enemy,sees_count,target_x,target_y,target_z,objective_idx\n");
    fflush(s_file);
}

void BotTrace_Open()
{
    if (s_file)
        fclose(s_file);

    s_file = fopen(TRACE_PATH, "w");
    if (!s_file)
    {
        META_CONPRINTF("[SmartBots] BotTrace: failed to open %s\n", TRACE_PATH);
        return;
    }

    WriteHeader();
    META_CONPRINTF("[SmartBots] BotTrace: writing to %s\n", TRACE_PATH);
}

void BotTrace_Write(const BotStateEntry *stateArray, int stateCount, int tick)
{
    if (!s_file)
        return;

    float curtime = gpGlobals ? gpGlobals->curtime : 0.0f;
    int objIdx = NavObjectives_IsReady() ? NavObjectives_CurrentIndex() : -1;

    for (int i = 0; i < stateCount; i++)
    {
        const BotStateEntry &e = stateArray[i];

        // Target position from BotCommand (if any)
        float tx = 0, ty = 0, tz = 0;
        BotCommandEntry cmd;
        bool hasCmd = BotCommand_Get(e.id, cmd);
        if (hasCmd)
        {
            tx = cmd.moveTarget[0];
            ty = cmd.moveTarget[1];
            tz = cmd.moveTarget[2];
        }

        bool hasEnemy = BotActionHook_HasVisibleEnemy(e.id);

        fprintf(s_file,
                "%d,%.2f,%d,%.1f,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d\n",
                tick, curtime, e.id,
                e.pos[0], e.pos[1], e.pos[2], e.ang[1],
                e.alive, e.health, e.team,
                hasEnemy ? 1 : 0, e.sees_count,
                tx, ty, tz, objIdx);
    }

    fflush(s_file);
}

void BotTrace_Close()
{
    if (s_file)
    {
        fclose(s_file);
        s_file = nullptr;
        META_CONPRINTF("[SmartBots] BotTrace: closed\n");
    }
}
