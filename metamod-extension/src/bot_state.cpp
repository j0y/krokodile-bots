#include "bot_state.h"
#include "extension.h"

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
        entry.alive = info->IsDead() ? 0 : 1;
        entry.team = info->GetTeamIndex();

        count++;
    }

    return count;
}
