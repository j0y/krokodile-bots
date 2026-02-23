/**
 * tactics.inc -- Tactical deployment around objectives for SmartBots
 *
 * Port of bot_tactics.cpp (slot generation, fan-pattern deployment,
 * greedy nearest-neighbor assignment, staggered deploy timing).
 *
 * Depends on:
 *   navmesh.inc    -- NavArea_GetCenter
 *   objectives.inc -- SmartBots_Objectives_IsReady, SmartBots_Objectives_Get,
 *                      SmartBots_Objectives_CurrentIndex,
 *                      SmartBots_Objectives_GetAttackerSpawn,
 *                      SmartBots_Objectives_GetPrevious
 *   sdkcalls.inc   -- g_hGetNearestNavArea, GetNearestNavArea helper
 */

#if defined _smartbots_tactics_included
#endinput
#endif
#define _smartbots_tactics_included

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define TAC_MAX_SLOTS 32

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

enum struct TacSlot {
	float pos[3];
	float lookAt[3];
	float deployTime;
	int   client;       // assigned bot client index (-1 = unassigned)
	bool  active;
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

TacSlot g_tac_slots[TAC_MAX_SLOTS];
int     g_tac_slotCount;
int     g_tac_deployedForObjective = -1;
float   g_tac_deployTime;

// Per-client command output (read by main plugin)
bool  g_tac_hasCommand[MAXPLAYERS + 1];
float g_tac_commandPos[MAXPLAYERS + 1][3];

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

ConVar g_tac_cvEnabled;
ConVar g_tac_cvRadius;
ConVar g_tac_cvStagger;
ConVar g_tac_cvForward;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Normalize a 2D vector in-place.
 */
stock void Vec2D_Normalize(float vec[2])
{
	float len = SquareRoot(vec[0] * vec[0] + vec[1] * vec[1]);
	if (len > 0.001)
	{
		vec[0] /= len;
		vec[1] /= len;
	}
}

/**
 * Snap a world position to the nearest navigable area center.
 *
 * @param inPos     Input world position
 * @param outPos    Output snapped position
 * @param maxDist   Maximum search distance
 * @return          True if a nav area was found
 */
stock bool SnapToNav(float inPos[3], float outPos[3], float maxDist = 500.0)
{
	Address area = GetNearestNavArea(inPos, true, maxDist);
	if (area == Address_Null)
		return false;

	NavArea_GetCenter(area, outPos);
	return true;
}

// ---------------------------------------------------------------------------
// Init / Reset
// ---------------------------------------------------------------------------

/**
 * Create all tactics ConVars.  Call once from OnPluginStart.
 */
stock void SmartBots_Tactics_Init()
{
	g_tac_cvEnabled = CreateConVar("sm_smartbots_tactics_enabled", "1",
		"Enable tactical deployment around objectives");
	g_tac_cvRadius = CreateConVar("sm_smartbots_tactics_radius", "600",
		"Base spread radius around objective (units)");
	g_tac_cvStagger = CreateConVar("sm_smartbots_tactics_stagger", "8.0",
		"Max stagger delay (seconds) for bot deployment");
	g_tac_cvForward = CreateConVar("sm_smartbots_tactics_forward", "500",
		"Forward picket distance toward enemy approach (units)");
}

/**
 * Clear all slots and per-client commands.  Call on round start / map change.
 */
stock void SmartBots_Tactics_Reset()
{
	for (int i = 0; i < TAC_MAX_SLOTS; i++)
	{
		g_tac_slots[i].pos[0] = 0.0;
		g_tac_slots[i].pos[1] = 0.0;
		g_tac_slots[i].pos[2] = 0.0;
		g_tac_slots[i].lookAt[0] = 0.0;
		g_tac_slots[i].lookAt[1] = 0.0;
		g_tac_slots[i].lookAt[2] = 0.0;
		g_tac_slots[i].deployTime = 0.0;
		g_tac_slots[i].client = -1;
		g_tac_slots[i].active = false;
	}

	g_tac_slotCount = 0;
	g_tac_deployedForObjective = -1;
	g_tac_deployTime = 0.0;

	for (int i = 0; i <= MAXPLAYERS; i++)
	{
		g_tac_hasCommand[i] = false;
		g_tac_commandPos[i][0] = 0.0;
		g_tac_commandPos[i][1] = 0.0;
		g_tac_commandPos[i][2] = 0.0;
	}
}

// ---------------------------------------------------------------------------
// Deployment computation
// ---------------------------------------------------------------------------

/**
 * Build tactical slots around the current objective in a fan pattern.
 *
 * Port of ComputeDeployment (bot_tactics.cpp:109-217).
 *
 * Angle 0 = directly toward enemy approach direction.
 * Bots are spread to +/-150 degrees.  Forward bots (< 30 deg) use forwardDist,
 * flanks use radius, rear use 0.6*radius.  Positions are snapped to nav mesh.
 * Stagger timing: forward deploy first, rear last.
 *
 * @param objPos        Objective world position
 * @param approachDir   Normalized 2D direction FROM which enemies approach
 * @param botCount      Number of bots to deploy
 * @param curtime       Current game time
 */
static void ComputeDeployment(float objPos[3], float approachDir[2],
                               int botCount, float curtime)
{
	g_tac_slotCount = 0;
	g_tac_deployTime = curtime;

	if (botCount <= 0)
		return;

	float radius     = g_tac_cvRadius.FloatValue;
	float forwardDist = g_tac_cvForward.FloatValue;
	float staggerMax  = g_tac_cvStagger.FloatValue;

	for (int i = 0; i < botCount && g_tac_slotCount < TAC_MAX_SLOTS; i++)
	{
		float t = float(i) / float(botCount);  // 0..1

		// Angle from approach direction:
		// t=0 -> 0 deg (forward), t=0.5 -> +/-90 deg, t=1 -> +/-150 deg
		// Alternate left/right
		float angleDeg;
		if (i == 0)
		{
			angleDeg = 0.0;
		}
		else
		{
			float spread = t * 150.0;
			spread += GetRandomFloat(-15.0, 15.0);  // jitter to avoid symmetry
			angleDeg = (i % 2 == 1) ? spread : -spread;
		}

		float angleRad = angleDeg * 3.14159 / 180.0;

		// Rotate approach dir by angle
		float cosA = Cosine(angleRad);
		float sinA = Sine(angleRad);
		float dirX = approachDir[0] * cosA - approachDir[1] * sinA;
		float dirY = approachDir[0] * sinA + approachDir[1] * cosA;

		// Distance: forward bots further out, rear bots closer
		float dist;
		float absDeg = FloatAbs(angleDeg);
		if (absDeg < 30.0)
			dist = forwardDist + GetRandomFloat(-50.0, 100.0);
		else if (absDeg < 90.0)
			dist = radius + GetRandomFloat(-100.0, 100.0);
		else
			dist = radius * 0.6 + GetRandomFloat(-50.0, 50.0);

		// Candidate world position
		float candidate[3];
		candidate[0] = objPos[0] + dirX * dist;
		candidate[1] = objPos[1] + dirY * dist;
		candidate[2] = objPos[2];

		// Snap to nav mesh
		float snapped[3];
		bool snappedOk = SnapToNav(candidate, snapped, 600.0);

		if (!snappedOk)
		{
			// Fallback: try closer
			candidate[0] = objPos[0] + dirX * (dist * 0.5);
			candidate[1] = objPos[1] + dirY * (dist * 0.5);
			snappedOk = SnapToNav(candidate, snapped, 600.0);
		}

		if (!snappedOk)
		{
			// Last resort: objective center
			snappedOk = SnapToNav(objPos, snapped, 1000.0);
			if (!snappedOk)
				continue;  // skip this slot entirely
		}

		g_tac_slots[g_tac_slotCount].pos[0] = snapped[0];
		g_tac_slots[g_tac_slotCount].pos[1] = snapped[1];
		g_tac_slots[g_tac_slotCount].pos[2] = snapped[2];

		// Look toward the enemy approach direction
		g_tac_slots[g_tac_slotCount].lookAt[0] = snapped[0] + approachDir[0] * 500.0;
		g_tac_slots[g_tac_slotCount].lookAt[1] = snapped[1] + approachDir[1] * 500.0;
		g_tac_slots[g_tac_slotCount].lookAt[2] = snapped[2];

		// Stagger: forward bots go first, rear last
		float delayFraction = absDeg / 150.0;
		if (delayFraction > 1.0) delayFraction = 1.0;
		g_tac_slots[g_tac_slotCount].deployTime = curtime + delayFraction * staggerMax
		                                           + GetRandomFloat(0.0, 1.0);

		g_tac_slots[g_tac_slotCount].client = -1;
		g_tac_slots[g_tac_slotCount].active = true;
		g_tac_slotCount++;
	}
}

// ---------------------------------------------------------------------------
// Bot-to-slot assignment
// ---------------------------------------------------------------------------

/**
 * Assign bots to tactical slots by proximity (greedy nearest-neighbor).
 *
 * Port of AssignBotsToSlots (bot_tactics.cpp:221-281).
 *
 * @param botClients    Client indices for each bot
 * @param botPositions  World positions for each bot
 * @param botCount      Number of bots
 */
static void AssignBotsToSlots(int[] botClients, float botPositions[][3], int botCount)
{
	// Clear stale assignments (bots that died or disconnected)
	for (int s = 0; s < g_tac_slotCount; s++)
	{
		if (g_tac_slots[s].client < 0)
			continue;

		bool found = false;
		for (int b = 0; b < botCount; b++)
		{
			if (botClients[b] == g_tac_slots[s].client)
			{
				found = true;
				break;
			}
		}
		if (!found)
			g_tac_slots[s].client = -1;
	}

	// Assign unassigned bots to nearest unassigned slot
	for (int b = 0; b < botCount; b++)
	{
		int client = botClients[b];

		// Already assigned?
		bool hasSlot = false;
		for (int s = 0; s < g_tac_slotCount; s++)
		{
			if (g_tac_slots[s].client == client)
			{
				hasSlot = true;
				break;
			}
		}
		if (hasSlot)
			continue;

		// Find nearest unassigned slot
		float bestDist2 = 999999.0;
		int bestSlot = -1;

		for (int s = 0; s < g_tac_slotCount; s++)
		{
			if (!g_tac_slots[s].active || g_tac_slots[s].client >= 0)
				continue;

			float dx = g_tac_slots[s].pos[0] - botPositions[b][0];
			float dy = g_tac_slots[s].pos[1] - botPositions[b][1];
			float d2 = dx * dx + dy * dy;
			if (d2 < bestDist2)
			{
				bestDist2 = d2;
				bestSlot = s;
			}
		}

		if (bestSlot >= 0)
			g_tac_slots[bestSlot].client = client;
	}
}

// ---------------------------------------------------------------------------
// Tactics update (main per-tick logic)
// ---------------------------------------------------------------------------

/**
 * Update tactical deployment for all bots.
 *
 * Port of BotTactics_Update (bot_tactics.cpp:327-399).
 *
 * Checks if the objective changed and recomputes deployment.
 * Assigns bots to slots, then writes per-client command arrays for
 * slots past their deploy time.
 *
 * @param botClients    Client indices for each bot
 * @param botPositions  World positions for each bot
 * @param botCount      Number of bots
 */
stock void SmartBots_Tactics_Update(int[] botClients, float botPositions[][3],
                                     int botCount)
{
	if (!g_tac_cvEnabled.BoolValue)
		return;

	if (!SmartBots_Objectives_IsReady())
		return;

	float curtime = GetGameTime();
	int currentObj = SmartBots_Objectives_CurrentIndex();

	// ---- Clear previous command state ----
	for (int i = 0; i <= MAXPLAYERS; i++)
		g_tac_hasCommand[i] = false;

	// ---- Check if we need a new deployment (objective changed) ----
	if (currentObj != g_tac_deployedForObjective)
	{
		float objPosArr[3];
		if (!SmartBots_Objectives_GetPos(currentObj, objPosArr))
			return;

		// Compute approach direction: from attacker spawn toward objective
		float approachDir[2];
		approachDir[0] = 0.0;
		approachDir[1] = 1.0;  // default: north

		float spawnPos[3];
		if (SmartBots_Objectives_GetAttackerSpawn(spawnPos))
		{
			approachDir[0] = objPosArr[0] - spawnPos[0];
			approachDir[1] = objPosArr[1] - spawnPos[1];
			Vec2D_Normalize(approachDir);
		}
		else
		{
			// No attacker spawn -- use direction from previous objective
			float prevPos[3];
			if (SmartBots_Objectives_GetPos(currentObj - 1, prevPos))
			{
				approachDir[0] = objPosArr[0] - prevPos[0];
				approachDir[1] = objPosArr[1] - prevPos[1];
				Vec2D_Normalize(approachDir);
			}
		}

		ComputeDeployment(objPosArr, approachDir, botCount, curtime);
		g_tac_deployedForObjective = currentObj;
	}

	if (g_tac_slotCount == 0)
		return;

	// ---- Assign bots to slots ----
	AssignBotsToSlots(botClients, botPositions, botCount);

	// ---- Write per-client commands for activated slots ----
	for (int s = 0; s < g_tac_slotCount; s++)
	{
		if (!g_tac_slots[s].active || g_tac_slots[s].client < 0)
			continue;

		// Stagger: don't issue command until deploy time
		if (curtime < g_tac_slots[s].deployTime)
			continue;

		int client = g_tac_slots[s].client;
		if (client < 1 || client > MAXPLAYERS)
			continue;

		g_tac_hasCommand[client] = true;
		g_tac_commandPos[client][0] = g_tac_slots[s].pos[0];
		g_tac_commandPos[client][1] = g_tac_slots[s].pos[1];
		g_tac_commandPos[client][2] = g_tac_slots[s].pos[2];
	}
}
