#include "bot_action_hook.h"
#include "bot_action_types.h"
#include "bot_command.h"
#include "sig_resolve.h"
#include "detour.h"

#include <ISmmPlugin.h>
#include <cstdlib>
#include <cstring>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro

// Resolved function pointers
static CINSBotApproach_Ctor_t  s_ApproachCtor  = nullptr;
static CINSBotCombat_Update_t  s_CombatUpdateOriginal = nullptr;
static AddMovementRequest_t    s_AddMovementRequest = nullptr;

// Detour instance
static InlineDetour s_CombatUpdateDetour;

// Cached server base (set during Init)
static uintptr_t s_serverBase = 0;

// Goto target state
static bool  s_hasGotoTarget = false;
static float s_gotoX = 0.0f;
static float s_gotoY = 0.0f;
static float s_gotoZ = 0.0f;

// Entity pointer → edict index lookup table (built each GameFrame)
static const int MAX_ENTITY_MAP = 33;
static void *s_entityPtrs[MAX_ENTITY_MAP];     // entityPtrs[edictIndex] = entityPtr

// Per-edict flag: bot can see at least one enemy (set from GameFrame after vision scan)
static bool s_hasVisibleEnemy[MAX_ENTITY_MAP];

// Diagnostic state
static int  s_hookCallCount = 0;
static int  s_moveRequestCount = 0;
static int  s_logThrottle = 0;

// Expected function prologues for signature verification
// push ebp; mov ebp,esp; push edi; push esi; push ebx
static const unsigned char kCombatUpdatePrologue[] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53 };
static const unsigned char kApproachCtorPrologue[] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53 };
// AddMovementRequest: push ebp; mov ebp,esp (minimum 3-byte check)
static const unsigned char kAddMovementRequestPrologue[] = { 0x55, 0x89, 0xE5 };

// Resolve actor pointer → edict index using the entity map.
static int LookupEdictIndex(void *actor)
{
    for (int i = 1; i < MAX_ENTITY_MAP; i++)
    {
        if (s_entityPtrs[i] == actor)
            return i;
    }
    return -1;
}

// The hook function — called instead of CINSBotCombat::Update.
// x86-32 sret ABI: void Hook(ActionResult *sret, void *this, void *actor, float interval)
//
// This detour only SUPPRESSES combat for bots that have a movement override
// (goto target or Python command). It does NOT issue AddMovementRequest —
// GameFrame handles all movement requests to avoid double-calling the pathfinder.
static void Hook_CINSBotCombat_Update(ActionResult *sret, void *thisptr, void *actor, float interval)
{
    s_hookCallCount++;

    // If the bot can see enemies, let native combat AI handle it (shoot, take cover, etc.)
    if (actor)
    {
        int edictIndex = LookupEdictIndex(actor);
        if (edictIndex > 0 && s_hasVisibleEnemy[edictIndex])
        {
            s_CombatUpdateOriginal(sret, thisptr, actor, interval);
            return;
        }
    }

    // No visible enemies — suppress combat if we have a movement override
    bool shouldSuppress = false;

    if (s_hasGotoTarget && actor)
    {
        shouldSuppress = true;
    }
    else if (actor)
    {
        int edictIndex = LookupEdictIndex(actor);
        if (edictIndex > 0)
        {
            BotCommandEntry cmd;
            if (BotCommand_Get(edictIndex, cmd))
            {
                shouldSuppress = true;
            }
        }
    }

    if (shouldSuppress)
    {
        // Skip original combat Update — bot doesn't fight, just moves.
        // Movement is issued from GameFrame via IssueMovementRequest.
        sret->type   = ACTION_RESULT_CONTINUE;
        sret->action = nullptr;
        sret->reason = nullptr;
        return;
    }

    // No override active — run original combat logic
    s_CombatUpdateOriginal(sret, thisptr, actor, interval);
}

bool BotActionHook_Init(uintptr_t serverBase)
{
    if (serverBase == 0)
    {
        META_CONPRINTF("[SmartBots] ERROR: server module base is 0\n");
        return false;
    }

    // Resolve addresses
    void *combatUpdate = ResolveOffset(serverBase, ServerOffsets::CINSBotCombat_Update);
    void *approachCtor = ResolveOffset(serverBase, ServerOffsets::CINSBotApproach_ctor);
    void *addMoveReq   = ResolveOffset(serverBase, ServerOffsets::CINSBotLocomotion_AddMovementRequest);

    // Verify signatures
    bool combatOk   = VerifySignature(combatUpdate, kCombatUpdatePrologue, sizeof(kCombatUpdatePrologue));
    bool approachOk = VerifySignature(approachCtor, kApproachCtorPrologue, sizeof(kApproachCtorPrologue));
    bool moveReqOk  = VerifySignature(addMoveReq, kAddMovementRequestPrologue, sizeof(kAddMovementRequestPrologue));

    META_CONPRINTF("[SmartBots] CINSBotCombat::Update   @ %p — sig %s\n",
                   combatUpdate, combatOk ? "PASS" : "FAIL");
    META_CONPRINTF("[SmartBots] CINSBotApproach::ctor    @ %p — sig %s\n",
                   approachCtor, approachOk ? "PASS" : "FAIL");
    META_CONPRINTF("[SmartBots] AddMovementRequest       @ %p — sig %s\n",
                   addMoveReq, moveReqOk ? "PASS" : "FAIL");

    if (!combatOk || !approachOk || !moveReqOk)
    {
        META_CONPRINTF("[SmartBots] ERROR: Signature verification failed. Wrong binary?\n");
        return false;
    }

    s_ApproachCtor = reinterpret_cast<CINSBotApproach_Ctor_t>(approachCtor);
    s_AddMovementRequest = reinterpret_cast<AddMovementRequest_t>(addMoveReq);
    s_serverBase = serverBase;

    return true;
}

bool BotActionHook_InstallDetour()
{
    if (s_serverBase == 0)
        return false;

    void *combatUpdate = ResolveOffset(s_serverBase, ServerOffsets::CINSBotCombat_Update);

    if (!s_CombatUpdateDetour.Install(combatUpdate, (void *)Hook_CINSBotCombat_Update))
    {
        META_CONPRINTF("[SmartBots] ERROR: Failed to install CINSBotCombat::Update detour\n");
        return false;
    }

    // Store trampoline as the "original" function pointer
    s_CombatUpdateOriginal = reinterpret_cast<CINSBotCombat_Update_t>(
        s_CombatUpdateDetour.GetTrampoline());

    META_CONPRINTF("[SmartBots] CINSBotCombat::Update detour installed\n");
    return true;
}

void BotActionHook_RemoveDetour()
{
    s_CombatUpdateDetour.Remove();
    s_CombatUpdateOriginal = nullptr;
    META_CONPRINTF("[SmartBots] CINSBotCombat::Update detour removed\n");
}

void BotActionHook_SetGotoTarget(float x, float y, float z)
{
    s_gotoX = x;
    s_gotoY = y;
    s_gotoZ = z;
    s_hasGotoTarget = true;
    s_moveRequestCount = 0;
    s_hookCallCount = 0;
    s_logThrottle = 0;
}

void BotActionHook_ClearGotoTarget()
{
    s_hasGotoTarget = false;
    META_CONPRINTF("[SmartBots] Goto cleared. Stats: %d move requests over %d hook calls\n",
                   s_moveRequestCount, s_hookCallCount);
}

bool BotActionHook_HasGotoTarget()
{
    return s_hasGotoTarget;
}

bool BotActionHook_GetGotoTarget(float &x, float &y, float &z)
{
    if (!s_hasGotoTarget)
        return false;
    x = s_gotoX;
    y = s_gotoY;
    z = s_gotoZ;
    return true;
}

bool BotActionHook_IssueMovementRequest(void *entityPtr, float x, float y, float z)
{
    if (!entityPtr || !s_AddMovementRequest)
        return false;

    // Get locomotion interface via vtable dispatch:
    // entity->vtable[0x96c / 4](entity)
    void **vtable = *reinterpret_cast<void ***>(entityPtr);
    if (!vtable)
        return false;

    typedef void *(*GetLocoFn_t)(void *);
    GetLocoFn_t getLocoFn = reinterpret_cast<GetLocoFn_t>(
        vtable[kVtableOff_GetLocomotionInterface / 4]);
    if (!getLocoFn)
        return false;

    void *loco = getLocoFn(entityPtr);
    if (!loco)
        return false;

    s_AddMovementRequest(loco, x, y, z,
                         MOVE_TYPE_APPROACH, MOVE_PRIORITY_NORMAL,
                         MOVE_SPEED_DEFAULT);
    return true;
}

void BotActionHook_RegisterEntity(void *entityPtr, int edictIndex)
{
    if (edictIndex >= 1 && edictIndex < MAX_ENTITY_MAP)
    {
        s_entityPtrs[edictIndex] = entityPtr;
    }
}

void BotActionHook_ClearEntityMap()
{
    memset(s_entityPtrs, 0, sizeof(s_entityPtrs));
}

void BotActionHook_SetVisibleEnemy(int edictIndex, bool hasEnemy)
{
    if (edictIndex >= 1 && edictIndex < MAX_ENTITY_MAP)
        s_hasVisibleEnemy[edictIndex] = hasEnemy;
}

bool BotActionHook_HasVisibleEnemy(int edictIndex)
{
    if (edictIndex >= 1 && edictIndex < MAX_ENTITY_MAP)
        return s_hasVisibleEnemy[edictIndex];
    return false;
}

void BotActionHook_ClearVisibleEnemies()
{
    memset(s_hasVisibleEnemy, 0, sizeof(s_hasVisibleEnemy));
}
