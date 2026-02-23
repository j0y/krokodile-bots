/**
 * SmartBots Death Zones
 *
 * Standalone plugin that spreads death intensity to CINSNavArea fields
 * when friendly bots die. The engine's native bot AI reads m_deathIntensity
 * and avoids high-intensity areas automatically — no custom movement logic needed.
 *
 * How it works:
 * 1. Hook player_death events for the controlled team
 * 2. Queue death positions (unsafe to write nav areas from event handlers)
 * 3. On GameFrame (throttled to ~8Hz), BFS-spread intensity to nav areas
 * 4. Engine bot AI reads the intensity fields and avoids those areas
 *
 * Requires: SourceMod 1.10+, SDKTools
 * Gamedata: smartbots_deathzones.txt
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>

#include "smartbots_deathzones/navmesh.inc"

#define PLUGIN_VERSION "1.0.0"
#define MAX_DEATH_ZONES 16

public Plugin myinfo =
{
	name        = "SmartBots Death Zones",
	author      = "SmartBots Team",
	description = "Spreads death intensity to nav areas so bots avoid killzones",
	version     = PLUGIN_VERSION,
	url         = ""
};

// ---------------------------------------------------------------------------
// SDKCall handles
// ---------------------------------------------------------------------------

Handle g_hGetNearestNavArea;

// ---------------------------------------------------------------------------
// Nav mesh state
// ---------------------------------------------------------------------------

Address g_pTheNavMeshAddr;  // Address of the TheNavMesh global (CNavMesh**)
bool    g_bNavReady;

// ---------------------------------------------------------------------------
// Death ring buffer
// ---------------------------------------------------------------------------

float g_deathPos[MAX_DEATH_ZONES][3];
float g_deathTime[MAX_DEATH_ZONES];
bool  g_deathActive[MAX_DEATH_ZONES];
int   g_deathHead;

// ---------------------------------------------------------------------------
// Pending deaths (queued from event, drained in OnGameFrame)
// ---------------------------------------------------------------------------

float g_pendingDeaths[MAX_DEATH_ZONES][3];
int   g_pendingDeathCount;

// ---------------------------------------------------------------------------
// Death intensity offsets (loaded from gamedata)
// ---------------------------------------------------------------------------

int g_offDeathIntensity;
int g_offDeathTimestamp;

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

ConVar g_cvEnabled;
ConVar g_cvTeam;
ConVar g_cvBaseRadius;
ConVar g_cvClusterScale;
ConVar g_cvMaxRadius;
ConVar g_cvIntensityCap;
ConVar g_cvMaxAge;
ConVar g_cvDebug;

// ---------------------------------------------------------------------------
// Throttle
// ---------------------------------------------------------------------------

int g_frameCount;

// ===========================================================================
// Nav mesh helpers
// ===========================================================================

Address GetNavMesh()
{
	if (g_pTheNavMeshAddr == Address_Null)
		return Address_Null;
	return view_as<Address>(LoadFromAddress(g_pTheNavMeshAddr, NumberType_Int32));
}

Address GetNearestNavArea(Address navMesh, float pos[3],
	bool anyZ = true, float maxDist = 300.0,
	bool checkLOS = false, bool checkGround = false, int team = 0)
{
	return view_as<Address>(SDKCall(g_hGetNearestNavArea,
		navMesh, pos, anyZ, maxDist, checkLOS, checkGround, team));
}

bool EnsureNavReady()
{
	if (g_bNavReady)
		return true;

	Address navMesh = GetNavMesh();
	if (navMesh == Address_Null)
		return false;

	// Probe the nav mesh — if GetNearestNavArea returns a valid area,
	// the mesh is loaded and ready.
	float testPos[3];
	Address testArea = GetNearestNavArea(navMesh, testPos, true, 10000.0);
	if (testArea == Address_Null)
		return false;

	g_bNavReady = true;

	float tc[3];
	NavArea_GetCenter(testArea, tc);
	PrintToServer("[DeathZones] Nav mesh ready (test area at %.0f, %.0f, %.0f)",
		tc[0], tc[1], tc[2]);

	return true;
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

public void OnPluginStart()
{
	// --- Load gamedata ---
	GameData gc = new GameData("smartbots_deathzones");
	if (gc == null)
		SetFailState("Failed to load smartbots_deathzones gamedata");

	// --- Resolve TheNavMesh address ---
	g_pTheNavMeshAddr = gc.GetAddress("TheNavMesh");
	if (g_pTheNavMeshAddr == Address_Null)
		SetFailState("Failed to resolve TheNavMesh address");

	// --- Load offsets ---
	int offCenter   = gc.GetOffset("CNavArea::m_center");
	int offConnect   = gc.GetOffset("CNavArea::m_connect");
	int offInsFlags  = gc.GetOffset("CINSNavArea::m_insFlags");
	g_offDeathIntensity = gc.GetOffset("CINSNavArea::m_deathIntensity");
	g_offDeathTimestamp = gc.GetOffset("CINSNavArea::m_deathTimestamp");

	if (offCenter == -1 || offConnect == -1 || offInsFlags == -1
		|| g_offDeathIntensity == -1 || g_offDeathTimestamp == -1)
	{
		SetFailState("Failed to load required offsets from gamedata");
	}

	NavMesh_SetOffsets(offCenter, offConnect, offInsFlags);

	// --- Create SDKCalls ---

	// CNavMesh::GetNearestNavArea(const Vector&, bool, float, bool, bool, int) → CNavArea*
	StartPrepSDKCall(SDKCall_Raw);
	PrepSDKCall_SetFromConf(gc, SDKConf_Signature, "CNavMesh::GetNearestNavArea");
	PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);       // pos
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // anyZ
	PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);         // maxDist
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // checkLOS
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // checkGround
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // team
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain); // CNavArea*
	g_hGetNearestNavArea = EndPrepSDKCall();
	if (g_hGetNearestNavArea == null)
		SetFailState("Failed to create GetNearestNavArea SDKCall");

	// CNavArea::IsBlocked(int teamID, bool ignoreNavBlockers) const → bool
	Handle hIsBlocked;
	StartPrepSDKCall(SDKCall_Raw);
	PrepSDKCall_SetFromConf(gc, SDKConf_Signature, "CNavArea::IsBlocked");
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // teamID
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);           // ignoreNavBlockers
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	hIsBlocked = EndPrepSDKCall();
	if (hIsBlocked == null)
		SetFailState("Failed to create IsBlocked SDKCall");

	NavMesh_SetIsBlockedHandle(hIsBlocked);

	delete gc;

	// --- ConVars ---
	g_cvEnabled      = CreateConVar("sm_deathzone_enabled", "1",
		"Enable death zone spreading to nav mesh");
	g_cvTeam         = CreateConVar("sm_deathzone_team", "3",
		"Team to track deaths for (2=Security, 3=Insurgent)");
	g_cvBaseRadius   = CreateConVar("sm_deathzone_radius", "512.0",
		"Base radius for death spreading (units)");
	g_cvClusterScale = CreateConVar("sm_deathzone_cluster_scale", "256.0",
		"Additional radius per nearby death (units)");
	g_cvMaxRadius    = CreateConVar("sm_deathzone_max_radius", "2048.0",
		"Maximum spread radius (units)");
	g_cvIntensityCap = CreateConVar("sm_deathzone_intensity_cap", "5.0",
		"Maximum death intensity per nav area");
	g_cvMaxAge       = CreateConVar("sm_deathzone_age", "120.0",
		"Maximum age for death tracking (seconds)");
	g_cvDebug        = CreateConVar("sm_deathzone_debug", "0",
		"Enable debug output");

	// --- Event hooks ---
	HookEvent("player_death", Event_PlayerDeath);
	HookEvent("round_start", Event_RoundStart);

	// --- Admin commands ---
	RegAdminCmd("sm_deathzone_status", Cmd_Status, ADMFLAG_GENERIC,
		"Show death zone status");

	PrintToServer("[DeathZones] Loaded (TheNavMesh @ 0x%X)", view_as<int>(g_pTheNavMeshAddr));
}

public void OnMapStart()
{
	g_bNavReady = false;
	ClearDeathZones();
}

public void OnGameFrame()
{
	if (!g_cvEnabled.BoolValue)
		return;

	// Throttle to ~8Hz (every 8 ticks at 66 tick server)
	if (++g_frameCount % 8 != 0)
		return;

	if (!EnsureNavReady())
		return;

	DrainPendingDeaths();
}

// ===========================================================================
// Event handlers
// ===========================================================================

void Event_PlayerDeath(Event event, const char[] name, bool dontBroadcast)
{
	if (!g_cvEnabled.BoolValue)
		return;

	// player_death 'team' field uses 0-based indexing in Insurgency
	// (0 = Security, 1 = Insurgent).
	// Engine teams are 2-based (2 = Security, 3 = Insurgent).
	int team = event.GetInt("team");
	int controlledTeam = g_cvTeam.IntValue;

	if (team != controlledTeam - 2)
		return;

	// Get death position from event
	float pos[3];
	pos[0] = event.GetFloat("x");
	pos[1] = event.GetFloat("y");
	pos[2] = event.GetFloat("z");

	// Fallback: get position from entity if event fields are zero
	if (pos[0] == 0.0 && pos[1] == 0.0 && pos[2] == 0.0)
	{
		int userid = event.GetInt("userid");
		int client = GetClientOfUserId(userid);
		if (client > 0 && IsClientInGame(client))
		{
			GetClientAbsOrigin(client, pos);
		}
	}

	// Skip if still zero
	if (pos[0] == 0.0 && pos[1] == 0.0 && pos[2] == 0.0)
		return;

	// Record in ring buffer
	g_deathPos[g_deathHead][0] = pos[0];
	g_deathPos[g_deathHead][1] = pos[1];
	g_deathPos[g_deathHead][2] = pos[2];
	g_deathTime[g_deathHead] = GetGameTime();
	g_deathActive[g_deathHead] = true;
	g_deathHead = (g_deathHead + 1) % MAX_DEATH_ZONES;

	// Queue for deferred nav mesh spreading
	// (unsafe to write nav areas from inside event handler)
	if (g_pendingDeathCount < MAX_DEATH_ZONES)
	{
		g_pendingDeaths[g_pendingDeathCount][0] = pos[0];
		g_pendingDeaths[g_pendingDeathCount][1] = pos[1];
		g_pendingDeaths[g_pendingDeathCount][2] = pos[2];
		g_pendingDeathCount++;
	}

	if (g_cvDebug.BoolValue)
	{
		PrintToServer("[DeathZones] Death recorded at (%.0f, %.0f, %.0f)",
			pos[0], pos[1], pos[2]);
	}
}

void Event_RoundStart(Event event, const char[] name, bool dontBroadcast)
{
	ClearDeathZones();
	g_bNavReady = false;
	PrintToServer("[DeathZones] Round start — death zones cleared");
}

// ===========================================================================
// Core logic
// ===========================================================================

void ClearDeathZones()
{
	for (int i = 0; i < MAX_DEATH_ZONES; i++)
	{
		g_deathActive[i] = false;
		g_deathTime[i] = 0.0;
		g_deathPos[i][0] = 0.0;
		g_deathPos[i][1] = 0.0;
		g_deathPos[i][2] = 0.0;
	}
	g_deathHead = 0;
	g_pendingDeathCount = 0;
}

/**
 * Process all queued deaths — compute adaptive radius and spread to nav mesh.
 */
void DrainPendingDeaths()
{
	if (g_pendingDeathCount == 0)
		return;

	float baseRadius = g_cvBaseRadius.FloatValue;
	float clusterScale = g_cvClusterScale.FloatValue;
	float maxRadius = g_cvMaxRadius.FloatValue;
	float maxAge = g_cvMaxAge.FloatValue;
	float curtime = GetGameTime();

	for (int d = 0; d < g_pendingDeathCount; d++)
	{
		// Compute adaptive radius: count recent deaths clustered nearby
		int nearby = 0;
		for (int i = 0; i < MAX_DEATH_ZONES; i++)
		{
			if (!g_deathActive[i])
				continue;
			float age = curtime - g_deathTime[i];
			if (age > maxAge || age < 0.0)
				continue;

			float dx = g_pendingDeaths[d][0] - g_deathPos[i][0];
			float dy = g_pendingDeaths[d][1] - g_deathPos[i][1];
			float dz = g_pendingDeaths[d][2] - g_deathPos[i][2];
			float dist = SquareRoot(dx * dx + dy * dy + dz * dz);
			if (dist < baseRadius)
				nearby++;
		}

		float radius = baseRadius + nearby * clusterScale;
		if (radius > maxRadius)
			radius = maxRadius;

		SpreadDeathToNavMesh(g_pendingDeaths[d], radius);
	}

	g_pendingDeathCount = 0;
}

/**
 * BFS from the death position, writing death intensity to all nav areas in radius.
 *
 * Port of nav_flanking.cpp:958-1013 (NavFlanking_SpreadDeathToNavMesh).
 *
 * CINSNavArea death field layout (verified via memory dump):
 *   +0x218 (536): float m_deathIntensity[1]  (Insurgent team)
 *   +0x224 (548): void* IntervalTimer vtable  (DO NOT WRITE)
 *   +0x228 (552): float IntervalTimer timestamp
 */
void SpreadDeathToNavMesh(float deathPos[3], float radius)
{
	Address navMesh = GetNavMesh();
	if (navMesh == Address_Null)
		return;

	Address startArea = GetNearestNavArea(navMesh, deathPos, true, 300.0);
	if (startArea == Address_Null)
		return;

	// BFS collect all areas within radius
	Address areas[MAX_BFS_AREAS];
	int count = CollectCandidateAreas(startArea, radius, areas, MAX_BFS_AREAS);

	float curtime = GetGameTime();
	float intensityCap = g_cvIntensityCap.FloatValue;
	int written = 0;

	for (int i = 0; i < count; i++)
	{
		// Distance-based falloff: full intensity at center, fading at edge
		float ac[3];
		NavArea_GetCenter(areas[i], ac);
		float dx = ac[0] - deathPos[0];
		float dy = ac[1] - deathPos[1];
		float dist = SquareRoot(dx * dx + dy * dy);
		float intensity = 1.0 - (dist / radius);
		if (intensity < 0.1)
			intensity = 0.1;

		// Read current intensity, accumulate
		Address pIntensity = areas[i] + view_as<Address>(g_offDeathIntensity);
		float curIntensity = view_as<float>(LoadFromAddress(pIntensity, NumberType_Int32));
		float newIntensity = curIntensity + intensity;
		if (newIntensity > intensityCap)
			newIntensity = intensityCap;

		// Write new intensity
		StoreToAddress(pIntensity, view_as<int>(newIntensity), NumberType_Int32);

		// Update death timer timestamp (engine decay starts from now)
		Address pTimestamp = areas[i] + view_as<Address>(g_offDeathTimestamp);
		StoreToAddress(pTimestamp, view_as<int>(curtime), NumberType_Int32);

		written++;
	}

	if (g_cvDebug.BoolValue)
	{
		PrintToServer("[DeathZones] Spread to %d areas within %.0fu of (%.0f, %.0f, %.0f)",
			written, radius, deathPos[0], deathPos[1], deathPos[2]);
	}
}

// ===========================================================================
// Admin commands
// ===========================================================================

Action Cmd_Status(int client, int args)
{
	Address navMesh = GetNavMesh();

	ReplyToCommand(client, "[DeathZones] Status:");
	ReplyToCommand(client, "  Enabled: %s", g_cvEnabled.BoolValue ? "yes" : "no");
	ReplyToCommand(client, "  Nav ready: %s", g_bNavReady ? "yes" : "no");
	ReplyToCommand(client, "  NavMesh ptr: 0x%X", view_as<int>(navMesh));
	ReplyToCommand(client, "  Team: %d", g_cvTeam.IntValue);
	ReplyToCommand(client, "  Radius: %.0f (cluster +%.0f, max %.0f)",
		g_cvBaseRadius.FloatValue, g_cvClusterScale.FloatValue, g_cvMaxRadius.FloatValue);
	ReplyToCommand(client, "  Intensity cap: %.1f", g_cvIntensityCap.FloatValue);
	ReplyToCommand(client, "  Max age: %.0fs", g_cvMaxAge.FloatValue);

	float curtime = GetGameTime();
	int activeCount = 0;
	for (int i = 0; i < MAX_DEATH_ZONES; i++)
	{
		if (!g_deathActive[i])
			continue;
		float age = curtime - g_deathTime[i];
		if (age > g_cvMaxAge.FloatValue)
			continue;
		activeCount++;
		ReplyToCommand(client, "    DZ%d: (%.0f, %.0f, %.0f) age=%.0fs",
			i, g_deathPos[i][0], g_deathPos[i][1], g_deathPos[i][2], age);
	}

	ReplyToCommand(client, "  Active zones: %d", activeCount);
	ReplyToCommand(client, "  Pending deaths: %d", g_pendingDeathCount);

	return Plugin_Handled;
}
