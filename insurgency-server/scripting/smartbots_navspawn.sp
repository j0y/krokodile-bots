/**
 * smartbots_navspawn.sp — Dynamic spawn relocation for Insurgency 2014 bots
 *
 * SourcePawn port of the NavSpawning Metamod:Source extension.
 * DHooks post-hook on CINSNextBot::Spawn to teleport bots to scored
 * nav mesh positions away from human players.
 *
 * Scoring: Multi-source BFS from attacker player positions.
 *   - Distance bell curve: peak at ideal distance, falloff
 *   - Visibility penalty: 0.1x if visible from any player's nav area
 *   - Indoor bonus: 1.5x
 *   - Random jitter: 0.85x-1.15x
 *
 * Standalone plugin — can be loaded independently of smartbots.sp.
 * Requires: DHooks extension, gamedata/smartbots_navspawn.txt
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>
#include <dhooks>

public Plugin myinfo =
{
	name        = "SmartBots NavSpawn",
	author      = "krokodile",
	description = "Dynamic nav mesh spawn relocation for Insurgency bots",
	version     = "1.0.0",
	url         = ""
};

// ---------------------------------------------------------------------------
// Nav mesh constants & offsets
// ---------------------------------------------------------------------------

#define NS_MAX_BFS_AREAS 2048
#define NS_SIZEOF_NAVCONNECT_VEC 4
#define NS_SIZEOF_NAVCONNECT 8

static int g_nsOffNavCenter;
static int g_nsOffNavConnect;
static int g_nsOffNavInsFlags;

// ---------------------------------------------------------------------------
// SDKCall handles
// ---------------------------------------------------------------------------

static Handle g_hSDK_NS_GetNearestNavArea;
static Handle g_hSDK_NS_IsPotentiallyVisible;
static Handle g_hSDK_NS_IsBlocked;

// ---------------------------------------------------------------------------
// Global addresses
// ---------------------------------------------------------------------------

static Address g_ppNS_TheNavMesh;   // address of TheNavMesh global

// ---------------------------------------------------------------------------
// DHook detour
// ---------------------------------------------------------------------------

static DynamicDetour g_hDetour_Spawn;

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

static ConVar g_cvEnabled;
static ConVar g_cvTeam;
static ConVar g_cvIdealDist;
static ConVar g_cvDistFalloff;
static ConVar g_cvMinPlayerDist;
static ConVar g_cvMaxPlayerDist;
static ConVar g_cvDebug;

// ---------------------------------------------------------------------------
// Player cache (updated at 4Hz from OnGameFrame)
// ---------------------------------------------------------------------------

#define NS_MAX_CACHED_PLAYERS 32

static float g_playerPos[NS_MAX_CACHED_PLAYERS][3];
static int   g_playerTeam[NS_MAX_CACHED_PLAYERS];
static Address g_playerNavArea[NS_MAX_CACHED_PLAYERS];
static int   g_playerCount;
static int   g_nsTickCount;

// BFS working memory
static Address g_nsBfsQueue[NS_MAX_BFS_AREAS];
static Address g_nsVisited[NS_MAX_BFS_AREAS];

// ===========================================================================
// Nav mesh field access
// ===========================================================================

static void NS_NavArea_GetCenter(Address area, float center[3])
{
	center[0] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_nsOffNavCenter), NumberType_Int32));
	center[1] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_nsOffNavCenter + 4), NumberType_Int32));
	center[2] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_nsOffNavCenter + 8), NumberType_Int32));
}

static int NS_NavArea_GetAdjacentCount(Address area, int dir)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_nsOffNavConnect + dir * NS_SIZEOF_NAVCONNECT_VEC),
		NumberType_Int32));
	if (vecPtr == Address_Null)
		return 0;
	int count = LoadFromAddress(vecPtr, NumberType_Int32);
	if (count < 0 || count > 256)
		return 0;
	return count;
}

static Address NS_NavArea_GetAdjacentArea(Address area, int dir, int index)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_nsOffNavConnect + dir * NS_SIZEOF_NAVCONNECT_VEC),
		NumberType_Int32));
	if (vecPtr == Address_Null)
		return Address_Null;
	return view_as<Address>(LoadFromAddress(
		vecPtr + view_as<Address>(4 + index * NS_SIZEOF_NAVCONNECT),
		NumberType_Int32));
}

static bool NS_NavArea_IsIndoor(Address area)
{
	int flags = LoadFromAddress(area + view_as<Address>(g_nsOffNavInsFlags), NumberType_Int32);
	return (flags & 0x80) != 0;
}

static Address NS_GetTheNavMesh()
{
	if (g_ppNS_TheNavMesh == Address_Null)
		return Address_Null;
	return view_as<Address>(LoadFromAddress(g_ppNS_TheNavMesh, NumberType_Int32));
}

static Address NS_GetNearestNavArea(float pos[3], bool anyZ, float maxDist)
{
	Address navMesh = NS_GetTheNavMesh();
	if (navMesh == Address_Null)
		return Address_Null;
	return view_as<Address>(SDKCall(g_hSDK_NS_GetNearestNavArea, navMesh, pos, anyZ, maxDist, false, false, 0));
}

// ===========================================================================
// Spawn position scoring
// ===========================================================================

/**
 * Multi-source BFS from attacker player positions.
 * Score areas by distance bell curve, visibility, indoor bonus.
 *
 * @param outPos    Output spawn position
 * @return          true if a valid position was found
 */
static bool PickSpawnPosition(float outPos[3])
{
	if (g_playerCount == 0)
		return false;

	Address navMesh = NS_GetTheNavMesh();
	if (navMesh == Address_Null)
		return false;

	float idealDist = g_cvIdealDist.FloatValue;
	float distFalloff = g_cvDistFalloff.FloatValue;
	float minPlayerDist = g_cvMinPlayerDist.FloatValue;
	float maxPlayerDist = g_cvMaxPlayerDist.FloatValue;
	int controlledTeam = g_cvTeam.IntValue;
	int attackerTeam = (controlledTeam == 3) ? 2 : 3;

	// BFS state
	int visitedCount = 0;
	int queueHead = 0, queueTail = 0;

	// Seed BFS from all attacker players' nav areas (multi-source)
	int seedCount = 0;
	for (int p = 0; p < g_playerCount; p++)
	{
		if (g_playerTeam[p] != attackerTeam)
			continue;
		Address playerNav = g_playerNavArea[p];
		if (playerNav == Address_Null)
			continue;

		// Check if already visited
		bool visited = false;
		for (int v = 0; v < visitedCount; v++)
		{
			if (g_nsVisited[v] == playerNav)
			{
				visited = true;
				break;
			}
		}
		if (visited || queueTail >= NS_MAX_BFS_AREAS)
			continue;

		g_nsVisited[visitedCount++] = playerNav;
		g_nsBfsQueue[queueTail++] = playerNav;
		seedCount++;
	}

	if (seedCount == 0)
		return false;

	// Score candidates
	Address bestArea = Address_Null;
	float bestScore = -1.0;
	int candidateCount = 0;

	while (queueHead < queueTail && visitedCount < NS_MAX_BFS_AREAS)
	{
		Address current = g_nsBfsQueue[queueHead++];

		float center[3];
		NS_NavArea_GetCenter(current, center);

		// Min distance to any attacker player
		float minDist = 999999.0;
		for (int p = 0; p < g_playerCount; p++)
		{
			if (g_playerTeam[p] != attackerTeam)
				continue;
			float dx = center[0] - g_playerPos[p][0];
			float dy = center[1] - g_playerPos[p][1];
			float dist = SquareRoot(dx * dx + dy * dy);
			if (dist < minDist)
				minDist = dist;
		}

		// Score if in range and not blocked
		bool shouldScore = (minDist <= maxPlayerDist)
		                 && !SDKCall(g_hSDK_NS_IsBlocked, current, 0, false)
		                 && (minDist >= minPlayerDist);

		if (shouldScore)
		{
			// Distance bell curve
			float distDelta = FloatAbs(minDist - idealDist);
			float distFactor = 1.0 - distDelta / distFalloff;
			if (distFactor < 0.1)
				distFactor = 0.1;

			float score = 100.0 * distFactor;

			// Visibility penalty: 0.1x if visible from any player's nav area
			if (g_hSDK_NS_IsPotentiallyVisible != null)
			{
				for (int p = 0; p < g_playerCount; p++)
				{
					if (g_playerNavArea[p] == Address_Null)
						continue;
					if (SDKCall(g_hSDK_NS_IsPotentiallyVisible, g_playerNavArea[p], current))
					{
						score *= 0.1;
						break;
					}
				}
			}

			// Indoor bonus: 1.5x
			if (NS_NavArea_IsIndoor(current))
				score *= 1.5;

			// Random jitter: 0.85x-1.15x
			score *= GetRandomFloat(0.85, 1.15);

			candidateCount++;

			if (score > bestScore)
			{
				bestScore = score;
				bestArea = current;
			}
		}

		// Expand neighbors
		for (int dir = 0; dir < 4; dir++)
		{
			int adjCount = NS_NavArea_GetAdjacentCount(current, dir);
			for (int i = 0; i < adjCount; i++)
			{
				Address neighbor = NS_NavArea_GetAdjacentArea(current, dir, i);
				if (neighbor == Address_Null)
					continue;

				bool visited = false;
				for (int v = 0; v < visitedCount; v++)
				{
					if (g_nsVisited[v] == neighbor)
					{
						visited = true;
						break;
					}
				}
				if (visited)
					continue;

				if (visitedCount < NS_MAX_BFS_AREAS && queueTail < NS_MAX_BFS_AREAS)
				{
					g_nsVisited[visitedCount++] = neighbor;
					g_nsBfsQueue[queueTail++] = neighbor;
				}
			}
		}
	}

	if (bestArea == Address_Null)
		return false;

	NS_NavArea_GetCenter(bestArea, outPos);

	if (g_cvDebug.BoolValue)
	{
		PrintToServer("[NavSpawn] Picked: (%.0f, %.0f, %.0f) score=%.1f dist=%.0f (%d candidates, %d visited, %d seeds)",
			outPos[0], outPos[1], outPos[2], bestScore,
			0.0, candidateCount, visitedCount, seedCount);
	}

	return true;
}

// ===========================================================================
// DHook callback
// ===========================================================================

/**
 * Post-hook on CINSNextBot::Spawn.
 * After the original Spawn runs (position, loadout, model),
 * teleport the bot to a scored nav position.
 */
public MRESReturn DHook_Spawn_Post(int pThis)
{
	if (!g_cvEnabled.BoolValue)
		return MRES_Ignored;

	int entity = pThis;
	if (!IsValidEntity(entity) || entity < 1 || entity > MaxClients)
		return MRES_Ignored;

	if (!IsClientInGame(entity) || !IsFakeClient(entity))
		return MRES_Ignored;

	// Only affect bots on the controlled (defender) team
	int team = GetClientTeam(entity);
	if (team != g_cvTeam.IntValue)
		return MRES_Ignored;

	// Pick spawn position
	float pos[3];
	if (!PickSpawnPosition(pos))
		return MRES_Ignored;

	// Teleport the bot
	TeleportEntity(entity, pos, NULL_VECTOR, NULL_VECTOR);

	if (g_cvDebug.BoolValue)
	{
		PrintToServer("[NavSpawn] Teleported bot %d (team %d) to (%.0f, %.0f, %.0f)",
			entity, team, pos[0], pos[1], pos[2]);
	}

	return MRES_Ignored;
}

// ===========================================================================
// Player cache update (from OnGameFrame)
// ===========================================================================

static void UpdatePlayerCache()
{
	g_playerCount = 0;
	int controlledTeam = g_cvTeam.IntValue;
	int attackerTeam = (controlledTeam == 3) ? 2 : 3;

	for (int i = 1; i <= MaxClients; i++)
	{
		if (!IsClientInGame(i) || !IsPlayerAlive(i))
			continue;

		// Only cache human players (attackers)
		if (IsFakeClient(i))
			continue;

		int team = GetClientTeam(i);
		if (g_playerCount >= NS_MAX_CACHED_PLAYERS)
			break;

		GetClientAbsOrigin(i, g_playerPos[g_playerCount]);
		g_playerTeam[g_playerCount] = team;

		// Resolve nav area for attacker team players
		if (team == attackerTeam)
		{
			g_playerNavArea[g_playerCount] = NS_GetNearestNavArea(
				g_playerPos[g_playerCount], true, 300.0);
		}
		else
		{
			g_playerNavArea[g_playerCount] = Address_Null;
		}

		g_playerCount++;
	}
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

public void OnPluginStart()
{
	Handle hGamedata = LoadGameConfigFile("smartbots_navspawn");
	if (hGamedata == null)
		SetFailState("[NavSpawn] Failed to load gamedata/smartbots_navspawn.txt");

	// Resolve global addresses
	g_ppNS_TheNavMesh = GameConfGetAddress(hGamedata, "TheNavMesh");
	if (g_ppNS_TheNavMesh == Address_Null)
		SetFailState("[NavSpawn] Failed to resolve TheNavMesh");

	// Load offsets
	g_nsOffNavCenter = GameConfGetOffset(hGamedata, "CNavArea::m_center");
	g_nsOffNavConnect = GameConfGetOffset(hGamedata, "CNavArea::m_connect");
	g_nsOffNavInsFlags = GameConfGetOffset(hGamedata, "CINSNavArea::m_insFlags");

	if (g_nsOffNavCenter < 0 || g_nsOffNavConnect < 0 || g_nsOffNavInsFlags < 0)
		SetFailState("[NavSpawn] Failed to get nav mesh offsets");

	// Create SDKCalls
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavMesh::GetNearestNavArea"))
		SetFailState("[NavSpawn] GetNearestNavArea signature not found");
	PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_hSDK_NS_GetNearestNavArea = EndPrepSDKCall();
	if (g_hSDK_NS_GetNearestNavArea == null)
		SetFailState("[NavSpawn] GetNearestNavArea SDKCall prep failed");

	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavArea::IsPotentiallyVisible"))
		SetFailState("[NavSpawn] IsPotentiallyVisible signature not found");
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_NS_IsPotentiallyVisible = EndPrepSDKCall();

	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavArea::IsBlocked"))
		SetFailState("[NavSpawn] IsBlocked signature not found");
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_NS_IsBlocked = EndPrepSDKCall();
	if (g_hSDK_NS_IsBlocked == null)
		SetFailState("[NavSpawn] IsBlocked SDKCall prep failed");

	// Create DHook detour
	g_hDetour_Spawn = DynamicDetour.FromConf(hGamedata, "CINSNextBot_Spawn");
	if (g_hDetour_Spawn == null)
		SetFailState("[NavSpawn] Failed to create Spawn detour");

	if (!g_hDetour_Spawn.Enable(Hook_Post, DHook_Spawn_Post))
		SetFailState("[NavSpawn] Failed to enable Spawn post-hook");

	delete hGamedata;

	// ConVars
	g_cvEnabled = CreateConVar("sm_navspawn_enabled", "0",
		"Enable nav mesh spawn relocation for defender bots");
	g_cvTeam = CreateConVar("sm_navspawn_team", "3",
		"Controlled team (2=Security, 3=Insurgent)");
	g_cvIdealDist = CreateConVar("sm_navspawn_ideal_dist", "2000",
		"Ideal distance from players (peak of scoring curve)");
	g_cvDistFalloff = CreateConVar("sm_navspawn_dist_falloff", "1500",
		"How quickly score drops from ideal distance");
	g_cvMinPlayerDist = CreateConVar("sm_navspawn_min_player_dist", "800",
		"Minimum distance from human players");
	g_cvMaxPlayerDist = CreateConVar("sm_navspawn_max_player_dist", "4000",
		"Maximum distance from human players");
	g_cvDebug = CreateConVar("sm_navspawn_debug", "0",
		"Log spawn decisions to console");

	PrintToServer("[NavSpawn] Plugin loaded (v1.0.0)");
}

public void OnPluginEnd()
{
	if (g_hDetour_Spawn != null)
	{
		g_hDetour_Spawn.Disable(Hook_Post, DHook_Spawn_Post);
		delete g_hDetour_Spawn;
		g_hDetour_Spawn = null;
	}

	PrintToServer("[NavSpawn] Plugin unloaded");
}

public void OnGameFrame()
{
	if (!g_cvEnabled.BoolValue)
		return;

	g_nsTickCount++;

	// Update player cache at 4Hz
	if (g_nsTickCount % 16 == 0)
		UpdatePlayerCache();
}
