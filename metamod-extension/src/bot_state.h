#ifndef _SMARTBOTS_BOT_STATE_H_
#define _SMARTBOTS_BOT_STATE_H_

// Collect bot state from edicts into a flat array for internal use.

struct BotStateEntry {
    int id;           // edict index
    float pos[3];     // x, y, z
    float ang[3];     // pitch, yaw, roll
    int health;
    int alive;        // 1 if alive, 0 if dead
    int team;
    int is_bot;       // 1 = fake client (bot), 0 = human player
    int sees[32];     // edict indices of players this bot can see
    int sees_count;   // number of entries in sees[]
};

// Iterate edicts and fill bot state array. Returns number of bots found.
int BotState_Collect(BotStateEntry *out, int maxBots);

#endif // _SMARTBOTS_BOT_STATE_H_
