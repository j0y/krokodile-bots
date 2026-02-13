#ifndef _SMARTBOTS_BOT_STATE_H_
#define _SMARTBOTS_BOT_STATE_H_

// Collect bot state from edicts and serialize to JSON for the Python brain.
// JSON format matches protocol.py exactly:
//   {"tick":123,"bots":[{"id":3,"pos":[1.0,2.0,3.0],"ang":[0.0,90.0,0.0],"hp":100,"alive":1,"team":2,"bot":1}]}

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

// Serialize bot state array to JSON string. Returns bytes written (excluding null terminator).
int BotState_Serialize(const BotStateEntry *bots, int count, int tick, const char *mapName, char *buf, int bufSize);

#endif // _SMARTBOTS_BOT_STATE_H_
