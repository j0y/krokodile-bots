/**
 * dhooks.inc — DHook detour setup for SmartBots
 *
 * Installs DynamicDetour on CINSBotCombat::Update and
 * CINSBotActionCheckpoint::Update. Uses the "Block and Drive" pattern:
 *
 * When a bot has no visible enemies and has a movement command:
 *   - Supercede Update with ACTION_RESULT_CONTINUE (12 zero bytes at sret)
 *   - OnGameFrame drives movement via Approach() SDKCall
 *
 * When a bot has visible enemies:
 *   - Let native AI run unmodified (MRES_Ignored)
 *
 * Depends on: sdkcalls.inc (not directly, but botstate.inc uses it)
 *             botstate.inc (for entity address → client lookup, hasVisibleEnemy)
 *
 * sret ABI (x86-32 GCC Linux):
 *   Stack: [sret_ptr] [this_ptr] [actor_ptr] [interval]
 *   Gamedata declares cdecl with all 4 as explicit params.
 */

#if defined _smartbots_dhooks_included
#endinput
#endif
#define _smartbots_dhooks_included

#include <dhooks>

// ---------------------------------------------------------------------------
// Detour handles
// ---------------------------------------------------------------------------

static DynamicDetour g_hDetour_CombatUpdate;
static DynamicDetour g_hDetour_CheckpointUpdate;

// ===========================================================================
// DHook callbacks
// ===========================================================================

/**
 * Pre-hook for CINSBotCombat::Update.
 *
 * If the bot has no visible enemies and has a movement command,
 * write CONTINUE to sret and supercede (skip native combat AI).
 * Otherwise, let the original run.
 */
static MRESReturn DHook_CombatUpdate_Pre(DHookParam hParams)
{
	// Param 3 = actor (CINSNextBot* as int)
	Address actorAddr = view_as<Address>(hParams.Get(3));
	if (actorAddr == Address_Null)
		return MRES_Ignored;

	int client = BotState_LookupClient(actorAddr);
	if (client < 1)
		return MRES_Ignored;

	// Bot can see enemies → let native combat handle it
	if (BotState_HasVisibleEnemy(client))
		return MRES_Ignored;

	// Bot has a movement command → suppress combat, drive movement from GameFrame
	if (!BotState_HasMoveCommand(client))
		return MRES_Ignored;

	// Write ACTION_RESULT_CONTINUE to sret:
	// { int type = 0 (CONTINUE), void* action = NULL, const char* reason = NULL }
	Address sret = view_as<Address>(hParams.Get(1));
	StoreToAddress(sret, 0, NumberType_Int32);                         // type = 0
	StoreToAddress(sret + view_as<Address>(4), 0, NumberType_Int32);   // action = NULL
	StoreToAddress(sret + view_as<Address>(8), 0, NumberType_Int32);   // reason = NULL

	return MRES_Supercede;
}

/**
 * Pre-hook for CINSBotActionCheckpoint::Update.
 *
 * Same logic as combat hook — blocks the checkpoint action when
 * we're driving the bot ourselves.
 */
static MRESReturn DHook_CheckpointUpdate_Pre(DHookParam hParams)
{
	Address actorAddr = view_as<Address>(hParams.Get(3));
	if (actorAddr == Address_Null)
		return MRES_Ignored;

	int client = BotState_LookupClient(actorAddr);
	if (client < 1)
		return MRES_Ignored;

	// Bot can see enemies → let native AI handle
	if (BotState_HasVisibleEnemy(client))
		return MRES_Ignored;

	// No movement command → let native checkpoint logic run
	if (!BotState_HasMoveCommand(client))
		return MRES_Ignored;

	// Supercede: write CONTINUE to keep checkpoint alive but idle
	Address sret = view_as<Address>(hParams.Get(1));
	StoreToAddress(sret, 0, NumberType_Int32);
	StoreToAddress(sret + view_as<Address>(4), 0, NumberType_Int32);
	StoreToAddress(sret + view_as<Address>(8), 0, NumberType_Int32);

	return MRES_Supercede;
}

// ===========================================================================
// Initialization
// ===========================================================================

/**
 * Set up DHook detours from gamedata Functions section.
 * Call from OnPluginStart after loading gamedata.
 *
 * @param hGamedata    Handle from LoadGameConfigFile("smartbots")
 * @return             true on success
 */
stock bool SmartBots_DHooks_Init(Handle hGamedata)
{
	// CINSBotCombat::Update detour
	g_hDetour_CombatUpdate = DynamicDetour.FromConf(hGamedata, "CINSBotCombat_Update");
	if (g_hDetour_CombatUpdate == null)
	{
		LogError("[SmartBots] DHooks: failed to create CINSBotCombat_Update detour");
		return false;
	}

	if (!g_hDetour_CombatUpdate.Enable(Hook_Pre, DHook_CombatUpdate_Pre))
	{
		LogError("[SmartBots] DHooks: failed to enable CINSBotCombat_Update pre-hook");
		return false;
	}

	PrintToServer("[SmartBots] DHooks: CINSBotCombat::Update detour installed");

	// CINSBotActionCheckpoint::Update detour
	g_hDetour_CheckpointUpdate = DynamicDetour.FromConf(hGamedata, "CINSBotActionCheckpoint_Update");
	if (g_hDetour_CheckpointUpdate == null)
	{
		LogError("[SmartBots] DHooks: failed to create CINSBotActionCheckpoint_Update detour");
		return false;
	}

	if (!g_hDetour_CheckpointUpdate.Enable(Hook_Pre, DHook_CheckpointUpdate_Pre))
	{
		LogError("[SmartBots] DHooks: failed to enable CINSBotActionCheckpoint_Update pre-hook");
		return false;
	}

	PrintToServer("[SmartBots] DHooks: CINSBotActionCheckpoint::Update detour installed");
	return true;
}

/**
 * Remove all detours. Call from OnPluginEnd.
 */
stock void SmartBots_DHooks_Shutdown()
{
	if (g_hDetour_CombatUpdate != null)
	{
		g_hDetour_CombatUpdate.Disable(Hook_Pre, DHook_CombatUpdate_Pre);
		delete g_hDetour_CombatUpdate;
		g_hDetour_CombatUpdate = null;
	}

	if (g_hDetour_CheckpointUpdate != null)
	{
		g_hDetour_CheckpointUpdate.Disable(Hook_Pre, DHook_CheckpointUpdate_Pre);
		delete g_hDetour_CheckpointUpdate;
		g_hDetour_CheckpointUpdate = null;
	}

	PrintToServer("[SmartBots] DHooks: all detours removed");
}
