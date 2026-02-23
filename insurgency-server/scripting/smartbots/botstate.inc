/**
 * botstate.inc — Bot state tracking for SmartBots
 *
 * Scans all connected players/bots, maintains entity address ↔ client index
 * mapping (for DHook callbacks), computes per-bot vision and threat state,
 * and tracks movement/look commands.
 *
 * Depends on: sdkcalls.inc (for vision/threat SDKCalls and Approach/AimHead)
 */

#if defined _smartbots_botstate_included
#endinput
#endif
#define _smartbots_botstate_included

// ---------------------------------------------------------------------------
// Entity address → client index map
// ---------------------------------------------------------------------------

static Address g_entityAddrs[MAXPLAYERS + 1];  // [client] → CBaseEntity* address

// ---------------------------------------------------------------------------
// Per-client state (refreshed at 8Hz by ResolveBots)
// ---------------------------------------------------------------------------

static float g_botPos[MAXPLAYERS + 1][3];
static int   g_botTeam[MAXPLAYERS + 1];
static bool  g_botAlive[MAXPLAYERS + 1];
static bool  g_botIsFake[MAXPLAYERS + 1];
static int   g_botHealth[MAXPLAYERS + 1];

// List of alive bot client indices on the controlled team
static int g_teamBots[MAXPLAYERS + 1];
static int g_teamBotCount;

// ---------------------------------------------------------------------------
// Vision state
// ---------------------------------------------------------------------------

static bool g_hasVisibleEnemy[MAXPLAYERS + 1];

// Per-bot seen enemy list (for team intel)
static int g_seenEnemies[MAXPLAYERS + 1][MAXPLAYERS + 1];
static int g_seenEnemyCount[MAXPLAYERS + 1];

// ---------------------------------------------------------------------------
// Team intel — enemy positions seen by any friendly bot
// ---------------------------------------------------------------------------

static float g_intelPos[MAXPLAYERS + 1][3];
static int   g_intelCount;

// ---------------------------------------------------------------------------
// Per-bot movement/look command state
// ---------------------------------------------------------------------------

#define CMD_FLAG_INVESTIGATE 1  // cautious walk (post-contact)

static float g_cmdMoveTarget[MAXPLAYERS + 1][3];
static bool  g_cmdHasMove[MAXPLAYERS + 1];
static int   g_cmdFlags[MAXPLAYERS + 1];
static int   g_cmdTick[MAXPLAYERS + 1];

// Last-issued targets — avoids redundant SDKCalls when target hasn't changed
static float g_lastMoveTarget[MAXPLAYERS + 1][3];
static bool  g_lastMoveValid[MAXPLAYERS + 1];
static float g_lastLookTarget[MAXPLAYERS + 1][3];
static bool  g_lastLookValid[MAXPLAYERS + 1];

// ===========================================================================
// Entity address lookup (used by DHook callbacks)
// ===========================================================================

/**
 * Resolve an entity address to client index.
 * Called from DHook detour callbacks where we receive raw actor pointers.
 *
 * @param entityAddr    CBaseEntity* address from DHook param
 * @return              Client index, or -1 if not found
 */
stock int BotState_LookupClient(Address entityAddr)
{
	for (int i = 1; i <= MaxClients; i++)
	{
		if (g_entityAddrs[i] == entityAddr)
			return i;
	}
	return -1;
}

// ===========================================================================
// State queries (used by DHook callbacks and main loop)
// ===========================================================================

stock bool BotState_HasVisibleEnemy(int client)
{
	if (client < 1 || client > MaxClients)
		return false;
	return g_hasVisibleEnemy[client];
}

stock bool BotState_HasMoveCommand(int client)
{
	if (client < 1 || client > MaxClients)
		return false;
	return g_cmdHasMove[client];
}

stock int BotState_GetTeamBotCount()
{
	return g_teamBotCount;
}

stock int BotState_GetTeamBot(int index)
{
	return g_teamBots[index];
}

stock void BotState_GetPos(int client, float pos[3])
{
	pos[0] = g_botPos[client][0];
	pos[1] = g_botPos[client][1];
	pos[2] = g_botPos[client][2];
}

stock int BotState_GetHealth(int client)
{
	return g_botHealth[client];
}

stock int BotState_GetIntelCount()
{
	return g_intelCount;
}

stock void BotState_GetIntelPos(int index, float pos[3])
{
	pos[0] = g_intelPos[index][0];
	pos[1] = g_intelPos[index][1];
	pos[2] = g_intelPos[index][2];
}

// ===========================================================================
// Command management
// ===========================================================================

/**
 * Set a movement command for a bot.
 */
stock void BotState_SetMoveCommand(int client, float x, float y, float z, int flags)
{
	g_cmdMoveTarget[client][0] = x;
	g_cmdMoveTarget[client][1] = y;
	g_cmdMoveTarget[client][2] = z;
	g_cmdHasMove[client] = true;
	g_cmdFlags[client] = flags;
	g_cmdTick[client] = GetGameTickCount();
}

/**
 * Clear a bot's movement command (resumes native AI).
 */
stock void BotState_ClearMoveCommand(int client)
{
	g_cmdHasMove[client] = false;
	g_lastMoveValid[client] = false;
	g_lastLookValid[client] = false;
}

/**
 * Clear all movement commands.
 */
stock void BotState_ClearAllCommands()
{
	for (int i = 1; i <= MaxClients; i++)
	{
		g_cmdHasMove[i] = false;
		g_lastMoveValid[i] = false;
		g_lastLookValid[i] = false;
	}
}

// ===========================================================================
// Bot scanning (called at 8Hz from OnGameFrame)
// ===========================================================================

/**
 * Scan all connected clients, build entity address map,
 * collect state for alive bots on the controlled team.
 *
 * @param controlledTeam    Engine team index (2=Security, 3=Insurgent)
 */
stock void BotState_ResolveBots(int controlledTeam)
{
	g_teamBotCount = 0;

	for (int i = 1; i <= MaxClients; i++)
	{
		g_entityAddrs[i] = Address_Null;
		g_botIsFake[i] = false;
		g_botAlive[i] = false;
		g_botTeam[i] = 0;
		g_botHealth[i] = 0;

		if (!IsClientInGame(i))
			continue;

		g_botTeam[i] = GetClientTeam(i);
		g_botAlive[i] = IsPlayerAlive(i);
		g_botIsFake[i] = IsFakeClient(i);
		g_botHealth[i] = g_botAlive[i] ? GetClientHealth(i) : 0;

		if (g_botAlive[i])
			GetClientAbsOrigin(i, g_botPos[i]);

		// Build entity address map for all fake clients (bots)
		if (g_botIsFake[i])
		{
			g_entityAddrs[i] = GetEntityAddress(i);
		}

		// Collect alive bots on our team
		if (g_botIsFake[i] && g_botAlive[i] && g_botTeam[i] == controlledTeam)
		{
			g_teamBots[g_teamBotCount++] = i;
		}

		// Expire stale commands (>15 seconds old)
		if (g_cmdHasMove[i])
		{
			int age = GetGameTickCount() - g_cmdTick[i];
			if (age > 990)  // ~15s at 66 tick
			{
				g_cmdHasMove[i] = false;
				g_lastMoveValid[i] = false;
			}
		}
	}
}

// ===========================================================================
// Vision computation
// ===========================================================================

/**
 * Compute per-bot visibility: which enemies can each bot see.
 * Populates g_seenEnemies and g_seenEnemyCount for team intel.
 *
 * @param controlledTeam    Engine team index
 */
stock void BotState_ComputeVision(int controlledTeam)
{
	for (int i = 0; i < g_teamBotCount; i++)
	{
		int client = g_teamBots[i];
		g_seenEnemyCount[client] = 0;

		Address vision = SDKCall_GetVisionInterface(client);
		if (vision == Address_Null)
			continue;

		for (int j = 1; j <= MaxClients; j++)
		{
			if (j == client || !IsClientInGame(j) || !g_botAlive[j])
				continue;

			// Only check enemies (different team)
			if (g_botTeam[j] == controlledTeam)
				continue;

			if (SDKCall_IsAbleToSee(vision, j))
			{
				if (g_seenEnemyCount[client] < MAXPLAYERS)
					g_seenEnemies[client][g_seenEnemyCount[client]++] = j;
			}
		}
	}
}

// ===========================================================================
// Threat detection
// ===========================================================================

/**
 * Compute per-bot threat state using engine's GetPrimaryKnownThreat.
 * This covers all senses: vision, hearing, team reports.
 */
stock void BotState_ComputeThreats()
{
	for (int i = 1; i <= MaxClients; i++)
		g_hasVisibleEnemy[i] = false;

	for (int i = 0; i < g_teamBotCount; i++)
	{
		int client = g_teamBots[i];

		Address vision = SDKCall_GetVisionInterface(client);
		if (vision == Address_Null)
			continue;

		// onlyVisible=false: all senses (seen + heard + reported)
		Address threat = SDKCall_GetPrimaryKnownThreat(vision, false);
		g_hasVisibleEnemy[client] = (threat != Address_Null);
	}
}

// ===========================================================================
// Team intel
// ===========================================================================

/**
 * Aggregate enemy positions visible to any bot on the controlled team.
 * Must be called after ComputeVision.
 *
 * @param controlledTeam    Engine team index
 */
stock void BotState_ComputeTeamIntel(int controlledTeam)
{
	g_intelCount = 0;
	bool recorded[MAXPLAYERS + 1];

	for (int b = 0; b < g_teamBotCount; b++)
	{
		int bot = g_teamBots[b];

		for (int s = 0; s < g_seenEnemyCount[bot]; s++)
		{
			int enemy = g_seenEnemies[bot][s];
			if (enemy < 1 || enemy > MaxClients || recorded[enemy])
				continue;

			if (g_botTeam[enemy] == controlledTeam)
				continue;

			g_intelPos[g_intelCount][0] = g_botPos[enemy][0];
			g_intelPos[g_intelCount][1] = g_botPos[enemy][1];
			g_intelPos[g_intelCount][2] = g_botPos[enemy][2];
			g_intelCount++;
			recorded[enemy] = true;

			if (g_intelCount >= MAXPLAYERS)
				return;
		}
	}
}

// ===========================================================================
// Movement driving (called from OnGameFrame at 8Hz)
// ===========================================================================

/**
 * Check if a target position has changed significantly (>1 unit).
 */
static bool MoveTargetChanged(int client, float x, float y, float z)
{
	if (!g_lastMoveValid[client])
		return true;

	float dx = g_lastMoveTarget[client][0] - x;
	float dy = g_lastMoveTarget[client][1] - y;
	float dz = g_lastMoveTarget[client][2] - z;
	return (dx * dx + dy * dy + dz * dz) > 1.0;
}

static bool LookTargetChanged(int client, float x, float y, float z)
{
	if (!g_lastLookValid[client])
		return true;

	float dx = g_lastLookTarget[client][0] - x;
	float dy = g_lastLookTarget[client][1] - y;
	float dz = g_lastLookTarget[client][2] - z;
	return (dx * dx + dy * dy + dz * dz) > 1.0;
}

/**
 * Drive movement for a bot via Approach() SDKCall.
 * Only re-issues if the target has changed (avoids console flooding).
 *
 * @param client    Client index of the bot
 * @return          true if Approach was called
 */
stock bool BotState_DriveMovement(int client)
{
	if (!g_cmdHasMove[client])
		return false;

	float x = g_cmdMoveTarget[client][0];
	float y = g_cmdMoveTarget[client][1];
	float z = g_cmdMoveTarget[client][2];

	if (!MoveTargetChanged(client, x, y, z))
		return false;

	Address loco = SDKCall_GetLocoInterface(client);
	if (loco == Address_Null)
		return false;

	float goal[3];
	goal[0] = x;
	goal[1] = y;
	goal[2] = z;

	SDKCall_Approach(loco, goal, 1.0);

	g_lastMoveTarget[client][0] = x;
	g_lastMoveTarget[client][1] = y;
	g_lastMoveTarget[client][2] = z;
	g_lastMoveValid[client] = true;

	return true;
}

/**
 * Issue a look-at command for a bot via AimHeadTowards() SDKCall.
 *
 * @param client    Client index
 * @param x,y,z     Target position to look at
 * @return          true if AimHead was called
 */
stock bool BotState_IssueLookAt(int client, float x, float y, float z)
{
	if (!LookTargetChanged(client, x, y, z))
		return false;

	Address body = SDKCall_GetBodyInterface(client);
	if (body == Address_Null)
		return false;

	float target[3];
	target[0] = x;
	target[1] = y;
	target[2] = z;

	// Priority 2 = INTERESTING: overrides idle scan, yields to combat aim
	SDKCall_AimHeadTowards(body, target, 2, 1.0);

	g_lastLookTarget[client][0] = x;
	g_lastLookTarget[client][1] = y;
	g_lastLookTarget[client][2] = z;
	g_lastLookValid[client] = true;

	return true;
}

/**
 * Apply team intel: make idle bots (no enemies, no commands) look toward
 * the nearest known enemy position reported by teammates.
 *
 * @param controlledTeam    Engine team index
 */
stock void BotState_ApplyTeamIntelLook(int controlledTeam)
{
	if (g_intelCount == 0)
		return;

	for (int b = 0; b < g_teamBotCount; b++)
	{
		int client = g_teamBots[b];

		// Skip bots with movement commands — they have their own targets
		if (g_cmdHasMove[client])
			continue;

		// Skip bots that already see enemies
		if (g_hasVisibleEnemy[client])
			continue;

		// Find nearest enemy from team intel
		float bestDist2 = 999999999.0;
		int bestIdx = -1;

		for (int e = 0; e < g_intelCount; e++)
		{
			float dx = g_intelPos[e][0] - g_botPos[client][0];
			float dy = g_intelPos[e][1] - g_botPos[client][1];
			float d2 = dx * dx + dy * dy;
			if (d2 < bestDist2)
			{
				bestDist2 = d2;
				bestIdx = e;
			}
		}

		if (bestIdx >= 0)
		{
			// Horizontal aim: use bot's own Z for level aiming
			BotState_IssueLookAt(client,
				g_intelPos[bestIdx][0],
				g_intelPos[bestIdx][1],
				g_botPos[client][2]);
		}
	}
}
