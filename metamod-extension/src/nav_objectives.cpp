#include "extension.h"
#include "nav_objectives.h"
#include "game_events.h"

#include <toolframework/itoolentity.h>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <algorithm>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro in extension.cpp

// ---- State ----

static IServerTools *s_pServerTools = nullptr;

static ObjectiveInfo  s_objectives[MAX_OBJECTIVES];
static int            s_objectiveCount = 0;

static SpawnZoneInfo  s_spawnZones[MAX_SPAWNZONES];
static int            s_spawnZoneCount = 0;

static float s_attackerSpawn[3] = {};
static bool  s_hasAttackerSpawn = false;

static bool s_ready = false;

// ---- Helpers ----

static bool ParseOrigin(const char *str, float out[3])
{
    if (!str || !str[0])
        return false;
    // Format: "x y z"
    char buf[128];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = nullptr;
    char *tok = strtok_r(buf, " ", &saveptr);
    if (!tok) return false;
    out[0] = strtof(tok, nullptr);

    tok = strtok_r(nullptr, " ", &saveptr);
    if (!tok) return false;
    out[1] = strtof(tok, nullptr);

    tok = strtok_r(nullptr, " ", &saveptr);
    if (!tok) return false;
    out[2] = strtof(tok, nullptr);

    return true;
}

// Extract phase number from a spawnzone targetname like "sz_1", "phase_2", "sz_a"
static int ParsePhase(const char *targetname)
{
    if (!targetname || !targetname[0])
        return 0;

    // Try to find a digit
    const char *p = targetname;
    while (*p)
    {
        if (*p >= '0' && *p <= '9')
            return atoi(p);
        p++;
    }

    // Try single letter: "sz_a" → 1, "sz_b" → 2, etc.
    int len = (int)strlen(targetname);
    if (len >= 2 && targetname[len - 2] == '_')
    {
        char c = targetname[len - 1];
        if (c >= 'a' && c <= 'z')
            return (c - 'a') + 1;
        if (c >= 'A' && c <= 'Z')
            return (c - 'A') + 1;
    }

    return 0;
}

// Extract order from a control point targetname like "cp_1", "cap_a", "cachepoint_b"
static int ParseOrder(const char *targetname)
{
    if (!targetname || !targetname[0])
        return 0;

    // Try trailing number: "cp_1" → 1
    int len = (int)strlen(targetname);
    const char *p = targetname + len - 1;
    while (p > targetname && *(p - 1) >= '0' && *(p - 1) <= '9')
        p--;
    if (*p >= '0' && *p <= '9')
        return atoi(p);

    // Try trailing letter: "cp_a" → 1, "cap_b" → 2
    if (len >= 2)
    {
        char c = targetname[len - 1];
        if (c >= 'a' && c <= 'z')
            return (c - 'a') + 1;
        if (c >= 'A' && c <= 'Z')
            return (c - 'A') + 1;
    }

    return 0;
}

// ---- Public API ----

bool NavObjectives_Init(void *serverTools)
{
    s_pServerTools = static_cast<IServerTools *>(serverTools);

    if (!s_pServerTools)
    {
        META_CONPRINTF("[SmartBots] NavObjectives: IServerTools not available\n");
        return false;
    }

    META_CONPRINTF("[SmartBots] NavObjectives: initialized (IServerTools=%p)\n",
                   (void *)s_pServerTools);
    return true;
}

void NavObjectives_Scan()
{
    s_objectiveCount = 0;
    s_spawnZoneCount = 0;
    s_hasAttackerSpawn = false;
    s_ready = false;

    if (!s_pServerTools)
        return;

    // Track which CP names have trigger_capture_zone references (= capture type)
    char captureNames[MAX_OBJECTIVES][64];
    int captureNameCount = 0;

    // --- Pass 1: find trigger_capture_zone to identify capture-type CPs ---
    void *ent = s_pServerTools->FirstEntity();
    while (ent)
    {
        // Get classname via edict
        // IServerTools iterates CBaseEntity*, we need edict for classname
        // But we can use GetKeyValue for classname too
        char classname[128] = {};
        s_pServerTools->GetKeyValue(ent, "classname", classname, sizeof(classname));

        if (strcmp(classname, "trigger_capture_zone") == 0)
        {
            char cpName[64] = {};
            s_pServerTools->GetKeyValue(ent, "controlpoint", cpName, sizeof(cpName));
            if (cpName[0] && captureNameCount < MAX_OBJECTIVES)
            {
                strncpy(captureNames[captureNameCount], cpName, sizeof(captureNames[0]) - 1);
                captureNames[captureNameCount][sizeof(captureNames[0]) - 1] = '\0';
                captureNameCount++;
            }
        }

        ent = s_pServerTools->NextEntity(ent);
    }

    // --- Pass 2: collect point_controlpoint, obj_weapon_cache, ins_spawnzone ---
    ent = s_pServerTools->FirstEntity();
    while (ent)
    {
        char classname[128] = {};
        s_pServerTools->GetKeyValue(ent, "classname", classname, sizeof(classname));

        if (strcmp(classname, "point_controlpoint") == 0)
        {
            if (s_objectiveCount >= MAX_OBJECTIVES)
                goto next;

            char originStr[128] = {};
            char targetname[64] = {};
            s_pServerTools->GetKeyValue(ent, "origin", originStr, sizeof(originStr));
            s_pServerTools->GetKeyValue(ent, "targetname", targetname, sizeof(targetname));

            ObjectiveInfo &obj = s_objectives[s_objectiveCount];
            if (!ParseOrigin(originStr, obj.pos))
                goto next;

            strncpy(obj.name, targetname, sizeof(obj.name) - 1);
            obj.name[sizeof(obj.name) - 1] = '\0';

            obj.order = ParseOrder(targetname);

            // Check if this CP has a trigger_capture_zone → capture type
            obj.isCapture = false;
            for (int i = 0; i < captureNameCount; i++)
            {
                if (strcmp(captureNames[i], targetname) == 0)
                {
                    obj.isCapture = true;
                    break;
                }
            }

            // Heuristic: if name doesn't contain "cache" and no capture zone,
            // it might still be a capture point (some maps lack trigger_capture_zone)
            if (!obj.isCapture && strstr(targetname, "cache") == nullptr
                && strstr(targetname, "Cache") == nullptr)
            {
                // Default to capture if no "cache" in name
                obj.isCapture = true;
            }

            s_objectiveCount++;
        }
        else if (strcmp(classname, "obj_weapon_cache") == 0)
        {
            // Weapon caches are destroy objectives — often paired with a point_controlpoint
            // that may not have a position in the BSP.  Record their position as supplementary.
            if (s_objectiveCount >= MAX_OBJECTIVES)
                goto next;

            char originStr[128] = {};
            char targetname[64] = {};
            char cpRef[64] = {};
            s_pServerTools->GetKeyValue(ent, "origin", originStr, sizeof(originStr));
            s_pServerTools->GetKeyValue(ent, "targetname", targetname, sizeof(targetname));
            s_pServerTools->GetKeyValue(ent, "ControlPoint", cpRef, sizeof(cpRef));

            float pos[3];
            if (!ParseOrigin(originStr, pos))
                goto next;

            // Check if we already have a point_controlpoint with this CP name
            // If so, update its position to the cache location (more accurate)
            bool merged = false;
            for (int i = 0; i < s_objectiveCount; i++)
            {
                if (cpRef[0] && strcmp(s_objectives[i].name, cpRef) == 0)
                {
                    s_objectives[i].pos[0] = pos[0];
                    s_objectives[i].pos[1] = pos[1];
                    s_objectives[i].pos[2] = pos[2];
                    s_objectives[i].isCapture = false;  // confirmed destroy
                    merged = true;
                    break;
                }
            }

            if (!merged)
            {
                ObjectiveInfo &obj = s_objectives[s_objectiveCount];
                obj.pos[0] = pos[0];
                obj.pos[1] = pos[1];
                obj.pos[2] = pos[2];
                strncpy(obj.name, cpRef[0] ? cpRef : targetname, sizeof(obj.name) - 1);
                obj.name[sizeof(obj.name) - 1] = '\0';
                obj.order = ParseOrder(obj.name);
                obj.isCapture = false;
                s_objectiveCount++;
            }
        }
        else if (strcmp(classname, "ins_spawnzone") == 0)
        {
            if (s_spawnZoneCount >= MAX_SPAWNZONES)
                goto next;

            char originStr[128] = {};
            char targetname[64] = {};
            char teamStr[16] = {};
            s_pServerTools->GetKeyValue(ent, "origin", originStr, sizeof(originStr));
            s_pServerTools->GetKeyValue(ent, "targetname", targetname, sizeof(targetname));
            s_pServerTools->GetKeyValue(ent, "TeamNum", teamStr, sizeof(teamStr));

            SpawnZoneInfo &sz = s_spawnZones[s_spawnZoneCount];
            if (!ParseOrigin(originStr, sz.pos))
                goto next;

            sz.team = atoi(teamStr);
            sz.phase = ParsePhase(targetname);
            s_spawnZoneCount++;
        }

next:
        ent = s_pServerTools->NextEntity(ent);
    }

    // --- Sort objectives by order ---
    std::sort(s_objectives, s_objectives + s_objectiveCount,
              [](const ObjectiveInfo &a, const ObjectiveInfo &b) {
                  return a.order < b.order;
              });

    // --- Compute attacker spawn centroid (Security team, first phase) ---
    if (s_spawnZoneCount > 0)
    {
        int minPhase = 999;
        for (int i = 0; i < s_spawnZoneCount; i++)
        {
            if (s_spawnZones[i].team == 2 && s_spawnZones[i].phase > 0
                && s_spawnZones[i].phase < minPhase)
                minPhase = s_spawnZones[i].phase;
        }

        float sumX = 0, sumY = 0, sumZ = 0;
        int count = 0;
        for (int i = 0; i < s_spawnZoneCount; i++)
        {
            if (s_spawnZones[i].team == 2 && s_spawnZones[i].phase == minPhase)
            {
                sumX += s_spawnZones[i].pos[0];
                sumY += s_spawnZones[i].pos[1];
                sumZ += s_spawnZones[i].pos[2];
                count++;
            }
        }

        if (count > 0)
        {
            s_attackerSpawn[0] = sumX / count;
            s_attackerSpawn[1] = sumY / count;
            s_attackerSpawn[2] = sumZ / count;
            s_hasAttackerSpawn = true;
        }
    }

    s_ready = (s_objectiveCount > 0);

    META_CONPRINTF("[SmartBots] NavObjectives: scanned %d objectives, %d spawn zones\n",
                   s_objectiveCount, s_spawnZoneCount);
    for (int i = 0; i < s_objectiveCount; i++)
    {
        META_CONPRINTF("  [%d] '%s' order=%d %s at (%.0f, %.0f, %.0f)\n",
                       i, s_objectives[i].name, s_objectives[i].order,
                       s_objectives[i].isCapture ? "capture" : "destroy",
                       s_objectives[i].pos[0], s_objectives[i].pos[1],
                       s_objectives[i].pos[2]);
    }
    if (s_hasAttackerSpawn)
    {
        META_CONPRINTF("  Attacker spawn: (%.0f, %.0f, %.0f)\n",
                       s_attackerSpawn[0], s_attackerSpawn[1], s_attackerSpawn[2]);
    }
}

bool NavObjectives_IsReady()
{
    return s_ready;
}

int NavObjectives_Count()
{
    return s_objectiveCount;
}

const ObjectiveInfo *NavObjectives_Get(int index)
{
    if (index < 0 || index >= s_objectiveCount)
        return nullptr;
    return &s_objectives[index];
}

int NavObjectives_CurrentIndex()
{
    int lost = GameEvents_GetObjectivesLost();
    if (lost >= s_objectiveCount)
        return s_objectiveCount - 1;  // clamp to last
    return lost;
}

bool NavObjectives_GetAttackerSpawn(float &x, float &y, float &z)
{
    if (!s_hasAttackerSpawn)
        return false;
    x = s_attackerSpawn[0];
    y = s_attackerSpawn[1];
    z = s_attackerSpawn[2];
    return true;
}

bool NavObjectives_GetApproachPoint(float &x, float &y, float &z)
{
    if (!s_hasAttackerSpawn || s_objectiveCount == 0)
        return false;

    x = (s_attackerSpawn[0] + s_objectives[0].pos[0]) / 2.0f;
    y = (s_attackerSpawn[1] + s_objectives[0].pos[1]) / 2.0f;
    z = (s_attackerSpawn[2] + s_objectives[0].pos[2]) / 2.0f;
    return true;
}

void NavObjectives_Reset()
{
    s_objectiveCount = 0;
    s_spawnZoneCount = 0;
    s_hasAttackerSpawn = false;
    s_ready = false;
    META_CONPRINTF("[SmartBots] NavObjectives: reset\n");
}
