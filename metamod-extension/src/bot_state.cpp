#include "bot_state.h"
#include "extension.h"

#include <cstdio>

int BotState_Collect(BotStateEntry *out, int maxBots)
{
    if (!gpGlobals || !g_pEngineServer || !g_pPlayerInfoManager)
        return 0;

    int count = 0;
    int maxClients = gpGlobals->maxClients;

    for (int i = 1; i <= maxClients && count < maxBots; i++)
    {
        edict_t *edict = PEntityOfEntIndex(i);
        if (!edict || edict->IsFree())
            continue;

        IPlayerInfo *info = g_pPlayerInfoManager->GetPlayerInfo(edict);
        if (!info || !info->IsConnected() || !info->IsFakeClient())
            continue;

        Vector pos = info->GetAbsOrigin();
        QAngle ang = info->GetAbsAngles();

        BotStateEntry &entry = out[count];
        entry.id = i;
        entry.pos[0] = pos.x;
        entry.pos[1] = pos.y;
        entry.pos[2] = pos.z;
        entry.ang[0] = ang.x;
        entry.ang[1] = ang.y;
        entry.ang[2] = ang.z;
        entry.health = info->GetHealth();
        entry.alive = info->IsAlive() ? 1 : 0;
        entry.team = info->GetTeamIndex();

        count++;
    }

    return count;
}

int BotState_Serialize(const BotStateEntry *bots, int count, int tick, char *buf, int bufSize)
{
    // Build JSON manually — format is simple and fixed, no library needed.
    int offset = 0;

    offset += snprintf(buf + offset, bufSize - offset, "{\"tick\":%d,\"bots\":[", tick);
    if (offset >= bufSize) return bufSize - 1;

    for (int i = 0; i < count; i++)
    {
        const BotStateEntry &b = bots[i];

        if (i > 0)
        {
            offset += snprintf(buf + offset, bufSize - offset, ",");
            if (offset >= bufSize) return bufSize - 1;
        }

        offset += snprintf(buf + offset, bufSize - offset,
            "{\"id\":%d,"
            "\"pos\":[%.1f,%.1f,%.1f],"
            "\"ang\":[%.1f,%.1f,%.1f],"
            "\"hp\":%d,"
            "\"alive\":%d,"
            "\"team\":%d}",
            b.id,
            b.pos[0], b.pos[1], b.pos[2],
            b.ang[0], b.ang[1], b.ang[2],
            b.health,
            b.alive,
            b.team);

        if (offset >= bufSize) return bufSize - 1;
    }

    offset += snprintf(buf + offset, bufSize - offset, "]}");
    if (offset >= bufSize) return bufSize - 1;

    return offset;
}
