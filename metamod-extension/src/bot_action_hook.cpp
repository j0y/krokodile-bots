#include "bot_action_hook.h"
#include "bot_action_types.h"
#include "sig_resolve.h"
#include "detour.h"

#include <ISmmPlugin.h>
#include <cstdlib>
#include <cstring>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro

// Resolved function pointers
static CINSBotApproach_Ctor_t  s_ApproachCtor  = nullptr;
static CINSBotCombat_Update_t  s_CombatUpdateOriginal = nullptr;

// Detour instance
static InlineDetour s_CombatUpdateDetour;

// Goto target state
static bool  s_hasGotoTarget = false;
static float s_gotoX = 0.0f;
static float s_gotoY = 0.0f;
static float s_gotoZ = 0.0f;

// Expected function prologues for signature verification
// push ebp; mov ebp,esp; push edi; push esi; push ebx
static const unsigned char kCombatUpdatePrologue[] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53 };
static const unsigned char kApproachCtorPrologue[] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53 };

// The hook function — called instead of CINSBotCombat::Update.
// x86-32 sret ABI: void Hook(ActionResult *sret, void *this, void *actor, float interval)
static void Hook_CINSBotCombat_Update(ActionResult *sret, void *thisptr, void *actor, float interval)
{
    if (s_hasGotoTarget && s_ApproachCtor)
    {
        // Allocate memory for a new CINSBotApproach action
        void *approach = calloc(1, CINSBOT_APPROACH_SIZE);
        if (approach)
        {
            // Call CINSBotApproach constructor with target position
            // x86-32 passes Vector by value as 3 floats on stack
            s_ApproachCtor(approach, s_gotoX, s_gotoY, s_gotoZ);

            // Fill ActionResult to tell the behavior tree to CHANGE_TO this new action
            sret->type   = ACTION_RESULT_CHANGE_TO;
            sret->action = approach;
            sret->reason = "SmartBots goto command";

            s_hasGotoTarget = false;

            META_CONPRINTF("[SmartBots] Redirected bot combat to Approach(%.1f, %.1f, %.1f)\n",
                           s_gotoX, s_gotoY, s_gotoZ);
            return;
        }
    }

    // Call original CINSBotCombat::Update via trampoline
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

    // Verify signatures
    bool combatOk = VerifySignature(combatUpdate, kCombatUpdatePrologue, sizeof(kCombatUpdatePrologue));
    bool approachOk = VerifySignature(approachCtor, kApproachCtorPrologue, sizeof(kApproachCtorPrologue));

    META_CONPRINTF("[SmartBots] CINSBotCombat::Update   @ %p — sig %s\n",
                   combatUpdate, combatOk ? "PASS" : "FAIL");
    META_CONPRINTF("[SmartBots] CINSBotApproach::ctor    @ %p — sig %s\n",
                   approachCtor, approachOk ? "PASS" : "FAIL");

    if (!combatOk || !approachOk)
    {
        META_CONPRINTF("[SmartBots] ERROR: Signature verification failed. Wrong binary?\n");
        return false;
    }

    s_ApproachCtor = reinterpret_cast<CINSBotApproach_Ctor_t>(approachCtor);

    return true;
}

bool BotActionHook_InstallDetour()
{
    uintptr_t serverBase = GetServerModuleBase();
    if (serverBase == 0)
        return false;

    void *combatUpdate = ResolveOffset(serverBase, ServerOffsets::CINSBotCombat_Update);

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
}

bool BotActionHook_HasGotoTarget()
{
    return s_hasGotoTarget;
}
