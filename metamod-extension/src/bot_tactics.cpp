#include "extension.h"
#include "bot_tactics.h"
#include "bot_command.h"
#include "nav_objectives.h"
#include "game_events.h"
#include "sig_resolve.h"

#include <cstring>
#include <cmath>
#include <cstdlib>

extern ISmmAPI *g_SMAPI;

// ---- Nav mesh access (same resolution as nav_flanking) ----

class CNavArea;

typedef CNavArea *(*GetNearestNavAreaFn)(void *thisNavMesh, const float *pos,
                                         bool anyZ, float maxDist,
                                         bool checkLOS, bool checkGround, int team);

static void **s_ppTheNavMesh = nullptr;
static GetNearestNavAreaFn s_fnGetNearestNavArea = nullptr;

static const int kOff_Center = 44;  // CNavArea m_center offset (vtable + CNavAreaCriticalData)

inline const float *NavArea_GetCenter(const void *area)
{
    return reinterpret_cast<const float *>(
        reinterpret_cast<const char *>(area) + kOff_Center);
}

// Snap a world position to the nearest navigable area center.
// Returns false if no nav area is nearby.
static bool SnapToNav(const float in[3], float out[3], float maxDist = 500.0f)
{
    if (!s_ppTheNavMesh || !*s_ppTheNavMesh || !s_fnGetNearestNavArea)
        return false;

    CNavArea *area = s_fnGetNearestNavArea(*s_ppTheNavMesh, in, true, maxDist, false, false, 0);
    if (!area)
        return false;

    const float *c = NavArea_GetCenter(area);
    out[0] = c[0];
    out[1] = c[1];
    out[2] = c[2];
    return true;
}

// ---- Tactical slot assignment ----

static const int MAX_SLOTS = 32;
static const int MAX_EDICT = 33;

struct TacSlot {
    float pos[3];       // target position (nav-snapped)
    float lookAt[3];    // direction to face (toward approach)
    float deployTime;   // gpGlobals->curtime when this bot should start moving
    int   edictIndex;   // assigned bot (-1 = unassigned)
    bool  active;
};

static TacSlot s_slots[MAX_SLOTS];
static int s_slotCount = 0;

// Which objective index the current deployment is for (-1 = none)
static int s_deployedForObjective = -1;

// curtime when deployment was computed
static float s_deployTime = 0.0f;

static bool s_initialized = false;

// ---- ConVars ----

#include <convar.h>

static ConVar s_cvarTacticsEnabled("smartbots_tactics_enabled", "1", 0,
    "Enable tactical deployment around objectives");
static ConVar s_cvarSpreadRadius("smartbots_tactics_radius", "600", 0,
    "Base spread radius around objective (units)");
static ConVar s_cvarStaggerMax("smartbots_tactics_stagger", "8.0", 0,
    "Max stagger delay (seconds) for bot deployment");
static ConVar s_cvarForwardDist("smartbots_tactics_forward", "500", 0,
    "Forward picket distance toward enemy approach (units)");

// ---- Helpers ----

static float RandFloat(float lo, float hi)
{
    return lo + (float)rand() / (float)RAND_MAX * (hi - lo);
}

static void Vec2D_Normalize(float &x, float &y)
{
    float len = sqrtf(x * x + y * y);
    if (len > 0.001f)
    {
        x /= len;
        y /= len;
    }
}

// ---- Deployment computation ----

// Build tactical slots around the current objective.
// approachDir: 2D direction FROM which enemies approach (normalized).
static void ComputeDeployment(const float objPos[3], const float approachDir[2],
                              int botCount, float curtime)
{
    s_slotCount = 0;
    s_deployTime = curtime;

    if (botCount <= 0)
        return;

    float radius = s_cvarSpreadRadius.GetFloat();
    float forwardDist = s_cvarForwardDist.GetFloat();
    float staggerMax = s_cvarStaggerMax.GetFloat();

    // Strategy: distribute bots into roles
    // - Forward: toward the enemy approach, to provide early warning / ambush
    // - Flanks: left and right of approach axis, for crossfire
    // - Objective: on/near the point, direct defense
    //
    // We generate one slot per bot, arranged in a fan pattern biased
    // toward the enemy approach.  Each slot gets a stagger delay:
    // forward bots deploy first, flankers next, rear last.

    // Generate positions in a fan:
    // Angle 0 = directly toward enemy approach
    // Spread bots across roughly 270 degrees (leaving the "rear" sparser)
    for (int i = 0; i < botCount && s_slotCount < MAX_SLOTS; i++)
    {
        TacSlot &slot = s_slots[s_slotCount];

        // Distribute angles: bias toward front
        // Map bot index to an angle.  First bots = forward, last = rear flanks.
        float t = (float)i / (float)botCount;  // 0..1

        // Angle from approach direction:
        // t=0 → 0° (forward), t=0.5 → ±90° (flanks), t=1 → ±150° (rear)
        // Alternate left/right
        float angleDeg;
        if (i == 0)
        {
            // First bot: directly forward
            angleDeg = 0.0f;
        }
        else
        {
            // Spread: alternate left/right, increasing angle
            float spread = t * 150.0f;  // up to 150° from forward
            // Add some jitter to avoid perfect symmetry
            spread += RandFloat(-15.0f, 15.0f);
            angleDeg = (i % 2 == 1) ? spread : -spread;
        }

        float angleRad = angleDeg * 3.14159f / 180.0f;

        // Compute direction for this slot (rotate approach dir by angle)
        float cosA = cosf(angleRad);
        float sinA = sinf(angleRad);
        float dirX = approachDir[0] * cosA - approachDir[1] * sinA;
        float dirY = approachDir[0] * sinA + approachDir[1] * cosA;

        // Distance: forward bots are further out, rear bots closer to objective
        float dist;
        float absDeg = fabsf(angleDeg);
        if (absDeg < 30.0f)
            dist = forwardDist + RandFloat(-50.0f, 100.0f);  // forward picket
        else if (absDeg < 90.0f)
            dist = radius + RandFloat(-100.0f, 100.0f);       // flanks
        else
            dist = radius * 0.6f + RandFloat(-50.0f, 50.0f);  // rear / objective

        // Candidate world position
        float candidate[3] = {
            objPos[0] + dirX * dist,
            objPos[1] + dirY * dist,
            objPos[2]
        };

        // Snap to nav mesh
        if (!SnapToNav(candidate, slot.pos, 600.0f))
        {
            // Fallback: try closer
            candidate[0] = objPos[0] + dirX * (dist * 0.5f);
            candidate[1] = objPos[1] + dirY * (dist * 0.5f);
            if (!SnapToNav(candidate, slot.pos, 600.0f))
            {
                // Last resort: objective center
                if (!SnapToNav(objPos, slot.pos, 1000.0f))
                    continue;  // skip this slot entirely
            }
        }

        // Look toward the enemy approach direction
        slot.lookAt[0] = slot.pos[0] + approachDir[0] * 500.0f;
        slot.lookAt[1] = slot.pos[1] + approachDir[1] * 500.0f;
        slot.lookAt[2] = slot.pos[2];

        // Stagger: forward bots go first, rear last
        // Map angle to delay: 0° = immediate, 150° = full stagger
        float delayFraction = absDeg / 150.0f;
        if (delayFraction > 1.0f) delayFraction = 1.0f;
        slot.deployTime = curtime + delayFraction * staggerMax + RandFloat(0.0f, 1.0f);

        slot.edictIndex = -1;
        slot.active = true;
        s_slotCount++;
    }

    META_CONPRINTF("[SmartBots] Tactics: computed %d slots (radius=%.0f, stagger=%.1fs)\n",
                   s_slotCount, radius, staggerMax);
}

// Assign bots to slots by proximity (greedy nearest-neighbor).
// Only assigns bots that don't already have a slot.
static void AssignBotsToSlots(const int *botEdicts, const float (*botPositions)[3],
                              int botCount)
{
    // Clear stale assignments (bots that died or disconnected)
    for (int s = 0; s < s_slotCount; s++)
    {
        if (s_slots[s].edictIndex < 0)
            continue;
        bool found = false;
        for (int b = 0; b < botCount; b++)
        {
            if (botEdicts[b] == s_slots[s].edictIndex)
            {
                found = true;
                break;
            }
        }
        if (!found)
            s_slots[s].edictIndex = -1;
    }

    // Assign unassigned bots to nearest unassigned slot
    for (int b = 0; b < botCount; b++)
    {
        int edict = botEdicts[b];

        // Already assigned?
        bool hasSlot = false;
        for (int s = 0; s < s_slotCount; s++)
        {
            if (s_slots[s].edictIndex == edict)
            {
                hasSlot = true;
                break;
            }
        }
        if (hasSlot)
            continue;

        // Find nearest unassigned slot
        float bestDist2 = 1e18f;
        int bestSlot = -1;
        for (int s = 0; s < s_slotCount; s++)
        {
            if (!s_slots[s].active || s_slots[s].edictIndex >= 0)
                continue;

            float dx = s_slots[s].pos[0] - botPositions[b][0];
            float dy = s_slots[s].pos[1] - botPositions[b][1];
            float d2 = dx * dx + dy * dy;
            if (d2 < bestDist2)
            {
                bestDist2 = d2;
                bestSlot = s;
            }
        }

        if (bestSlot >= 0)
            s_slots[bestSlot].edictIndex = edict;
    }
}

// ---- Status ConCommand ----

static void CC_TacticsStatus(const CCommand &args)
{
    META_CONPRINTF("[SmartBots] Tactics status:\n");
    META_CONPRINTF("  Initialized: %s\n", s_initialized ? "yes" : "no");
    META_CONPRINTF("  Enabled: %s\n", s_cvarTacticsEnabled.GetBool() ? "yes" : "no");
    META_CONPRINTF("  Deployed for objective: %d\n", s_deployedForObjective);
    META_CONPRINTF("  Slots: %d\n", s_slotCount);

    float curtime = gpGlobals ? gpGlobals->curtime : 0.0f;
    for (int i = 0; i < s_slotCount; i++)
    {
        TacSlot &s = s_slots[i];
        if (!s.active) continue;
        float dt = s.deployTime - curtime;
        META_CONPRINTF("  [%d] bot=%d pos=(%.0f,%.0f,%.0f) %s\n",
                       i, s.edictIndex,
                       s.pos[0], s.pos[1], s.pos[2],
                       dt > 0 ? "waiting" : "deployed");
    }
}

static ConCommand s_cmdTacticsStatus("smartbots_tactics_status", CC_TacticsStatus,
    "Show tactical deployment status");

// ---- Public API ----

bool BotTactics_Init(uintptr_t serverBase)
{
    s_ppTheNavMesh = reinterpret_cast<void **>(
        serverBase + ServerOffsets::TheNavMesh);
    s_fnGetNearestNavArea = reinterpret_cast<GetNearestNavAreaFn>(
        serverBase + ServerOffsets::CNavMesh_GetNearestNavArea);

    memset(s_slots, 0, sizeof(s_slots));
    s_slotCount = 0;
    s_deployedForObjective = -1;
    s_initialized = true;

    META_CONPRINTF("[SmartBots] BotTactics: initialized\n");
    return true;
}

void BotTactics_Update(const int *botEdicts, const float (*botPositions)[3],
                       int botCount, int currentTick)
{
    if (!s_initialized || !s_cvarTacticsEnabled.GetBool())
        return;

    if (!NavObjectives_IsReady())
        return;

    float curtime = gpGlobals->curtime;
    int currentObj = NavObjectives_CurrentIndex();

    // Check if we need a new deployment (objective changed or first time)
    if (currentObj != s_deployedForObjective)
    {
        const ObjectiveInfo *obj = NavObjectives_Get(currentObj);
        if (!obj)
            return;

        // Compute approach direction: from attacker spawn toward objective
        float approachDir[2] = {0.0f, 1.0f};  // default: north
        float ax, ay, az;
        if (NavObjectives_GetAttackerSpawn(ax, ay, az))
        {
            approachDir[0] = obj->pos[0] - ax;
            approachDir[1] = obj->pos[1] - ay;
            Vec2D_Normalize(approachDir[0], approachDir[1]);
        }
        else
        {
            // No attacker spawn — use direction from previous objective
            const ObjectiveInfo *prev = NavObjectives_Get(currentObj - 1);
            if (prev)
            {
                approachDir[0] = obj->pos[0] - prev->pos[0];
                approachDir[1] = obj->pos[1] - prev->pos[1];
                Vec2D_Normalize(approachDir[0], approachDir[1]);
            }
        }

        ComputeDeployment(obj->pos, approachDir, botCount, curtime);
        s_deployedForObjective = currentObj;

        META_CONPRINTF("[SmartBots] Tactics: deploying for objective %d '%s' (%s) at (%.0f,%.0f,%.0f)\n",
                       currentObj, obj->name, obj->isCapture ? "capture" : "destroy",
                       obj->pos[0], obj->pos[1], obj->pos[2]);
    }

    if (s_slotCount == 0)
        return;

    // Assign bots to slots
    AssignBotsToSlots(botEdicts, botPositions, botCount);

    // Write BotCommand for each assigned, activated slot
    for (int s = 0; s < s_slotCount; s++)
    {
        TacSlot &slot = s_slots[s];
        if (!slot.active || slot.edictIndex < 0)
            continue;

        // Stagger: don't issue command until deploy time
        if (curtime < slot.deployTime)
            continue;

        // Write the command — checkpoint hook will SUSPEND_FOR approach
        BotCommand_Set(slot.edictIndex,
                       slot.pos[0], slot.pos[1], slot.pos[2],
                       slot.lookAt[0], slot.lookAt[1], slot.lookAt[2],
                       0,  // flags: 0 = approach (not investigate)
                       currentTick);
    }
}

void BotTactics_Reset()
{
    memset(s_slots, 0, sizeof(s_slots));
    s_slotCount = 0;
    s_deployedForObjective = -1;
    s_deployTime = 0.0f;
    META_CONPRINTF("[SmartBots] Tactics: reset\n");
}
