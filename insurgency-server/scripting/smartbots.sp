/**
 * smartbots.sp — Full tactical AI for Insurgency 2014 bots
 *
 * SourcePawn port of the SmartBots Metamod:Source C++ extension.
 * Uses DHooks + SDKCalls + gamedata for cross-platform support.
 *
 * Architecture: "Block and Drive"
 *   - DHook detours on CINSBotCombat::Update and CINSBotActionCheckpoint::Update
 *   - When a bot has no visible enemies + has a movement command:
 *     supercede with ACTION_RESULT_CONTINUE (idle the action)
 *   - OnGameFrame (8Hz) drives movement via CINSBotLocomotion::Approach SDKCall
 *   - When enemies appear: let native AI run unmodified
 *
 * Requires: DHooks extension, gamedata/smartbots.txt
 * Optional: smartbots_deathzones.sp (can coexist — this plugin has its own spreading)
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>
#include <dhooks>

// Include order matters: sdkcalls first (provides handles and wrappers),
// then navmesh (uses SDKCall wrappers), then botstate (uses both),
// then dhooks (uses botstate), then the rest.
#include "smartbots/sdkcalls.inc"
#include "smartbots/navmesh.inc"
#include "smartbots/botstate.inc"
#include "smartbots/dhooks.inc"
#include "smartbots/events.inc"
#include "smartbots/objectives.inc"
#include "smartbots/flanking.inc"
#include "smartbots/tactics.inc"

public Plugin myinfo =
{
	name        = "SmartBots",
	author      = "krokodile",
	description = "Tactical AI for Insurgency 2014 bots (SourcePawn port)",
	version     = "1.0.0",
	url         = ""
};

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

static ConVar g_cvEnabled;
static ConVar g_cvTeam;
static ConVar g_cvDebug;
static ConVar g_cvDeathSpreadRadius;
static ConVar g_cvDeathClusterScale;
static ConVar g_cvDeathMaxRadius;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static int g_tickCount;

// Goto target (debug command)
static bool  g_hasGotoTarget;
static float g_gotoTarget[3];

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

public void OnPluginStart()
{
	// Load gamedata
	Handle hGamedata = LoadGameConfigFile("smartbots");
	if (hGamedata == null)
		SetFailState("[SmartBots] Failed to load gamedata/smartbots.txt");

	// Initialize subsystems
	if (!SmartBots_SDKCalls_Init(hGamedata))
		SetFailState("[SmartBots] SDKCalls init failed");

	if (!SmartBots_NavMesh_Init(hGamedata))
		SetFailState("[SmartBots] NavMesh init failed");

	if (!SmartBots_DHooks_Init(hGamedata))
		SetFailState("[SmartBots] DHooks init failed");

	delete hGamedata;

	// ConVars
	g_cvEnabled = CreateConVar("sm_smartbots_enabled", "1",
		"Enable SmartBots tactical AI");
	g_cvTeam = CreateConVar("sm_smartbots_team", "3",
		"Controlled team index (2=Security, 3=Insurgent)");
	g_cvDebug = CreateConVar("sm_smartbots_debug", "0",
		"Debug logging level (0=off, 1=basic, 2=verbose)");
	g_cvDeathSpreadRadius = CreateConVar("sm_smartbots_death_radius", "512",
		"Base death zone spread radius (units)");
	g_cvDeathClusterScale = CreateConVar("sm_smartbots_death_cluster_scale", "256",
		"Additional radius per nearby death (units)");
	g_cvDeathMaxRadius = CreateConVar("sm_smartbots_death_max_radius", "2048",
		"Maximum death zone spread radius (units)");

	// Initialize events (hooks game events)
	SmartBots_Events_Init(g_cvTeam.IntValue);

	// Initialize flanking and tactics ConVars
	SmartBots_Flanking_Init();
	SmartBots_Tactics_Init();

	// Admin commands
	RegAdminCmd("sm_smartbots_goto", Cmd_Goto, ADMFLAG_GENERIC,
		"Move all bots to position: sm_smartbots_goto <x> <y> <z>");
	RegAdminCmd("sm_smartbots_stop", Cmd_Stop, ADMFLAG_GENERIC,
		"Stop goto and resume normal AI");
	RegAdminCmd("sm_smartbots_status", Cmd_Status, ADMFLAG_GENERIC,
		"Show SmartBots status");
	RegAdminCmd("sm_smartbots_objectives", Cmd_Objectives, ADMFLAG_GENERIC,
		"Show discovered map objectives");
	RegAdminCmd("sm_smartbots_voice", Cmd_Voice, ADMFLAG_GENERIC,
		"Send voice concept to all bots: sm_smartbots_voice <concept_id>");

	PrintToServer("[SmartBots] Plugin loaded (v1.0.0)");
}

public void OnPluginEnd()
{
	SmartBots_DHooks_Shutdown();
	PrintToServer("[SmartBots] Plugin unloaded");
}

public void OnMapStart()
{
	SmartBots_Events_Reset();
	SmartBots_Flanking_Reset();
	SmartBots_Tactics_Reset();
	BotState_ClearAllCommands();

	g_hasGotoTarget = false;
	g_tickCount = 0;

	// Delay objective scan — entities need time to spawn
	CreateTimer(1.0, Timer_ScanObjectives);
}

public Action Timer_ScanObjectives(Handle timer)
{
	SmartBots_Objectives_Scan();
	return Plugin_Stop;
}

// ===========================================================================
// OnGameFrame — main loop
// ===========================================================================

public void OnGameFrame()
{
	if (!g_cvEnabled.BoolValue)
		return;

	g_tickCount++;
	int team = g_cvTeam.IntValue;

	// --- Death zone processing (every tick — cheap) ---
	DrainAndSpreadDeaths(team);

	// --- Heavy work at 8Hz (every 8 ticks) ---
	if (g_tickCount % 8 != 0)
		return;

	// Phase change detection: reset on new round
	{
		static char s_lastPhase[16];
		char curPhase[16];
		SmartBots_Events_GetPhase(curPhase, sizeof(curPhase));

		if (!StrEqual(s_lastPhase, curPhase))
		{
			if (StrEqual(curPhase, "preround"))
			{
				SmartBots_Flanking_Reset();
				SmartBots_Tactics_Reset();
				SmartBots_Objectives_Scan();
				BotState_ClearAllCommands();
			}
			strcopy(s_lastPhase, sizeof(s_lastPhase), curPhase);
		}
	}

	// Scan all bots and compute state
	BotState_ResolveBots(team);
	BotState_ComputeVision(team);
	BotState_ComputeThreats();
	BotState_ComputeTeamIntel(team);

	int botCount = BotState_GetTeamBotCount();
	if (botCount == 0)
		return;

	// --- Goto target (debug command) ---
	if (g_hasGotoTarget)
	{
		DriveGotoTarget(team);
		BotState_ApplyTeamIntelLook(team);
		return;
	}

	// --- Role assignment and movement ---
	AssignRolesAndDrive(team);

	// --- Team intel look-at for idle bots ---
	BotState_ApplyTeamIntelLook(team);

	// Periodic status log
	if (g_tickCount % 3300 == 0 && botCount > 0)
	{
		PrintToServer("[SmartBots] GameFrame: %d bots active (tick %d)",
			botCount, g_tickCount);
	}
}

// ===========================================================================
// Death zone processing
// ===========================================================================

static void DrainAndSpreadDeaths(int team)
{
	float deathPos[16][3];
	int deathCount = SmartBots_Events_DrainPendingDeaths(deathPos, 16);
	if (deathCount == 0)
		return;

	// Get existing death zones for clustering
	float dzPos[16][3];
	float dzTimes[16];
	int dzCount = SmartBots_Events_GetDeathZones(120.0, dzPos, dzTimes, 16);

	float baseRadius = g_cvDeathSpreadRadius.FloatValue;
	float clusterScale = g_cvDeathClusterScale.FloatValue;
	float maxRadius = g_cvDeathMaxRadius.FloatValue;

	for (int i = 0; i < deathCount; i++)
	{
		// Count nearby recent deaths for clustering
		int nearby = 0;
		for (int j = 0; j < dzCount; j++)
		{
			float dx = deathPos[i][0] - dzPos[j][0];
			float dy = deathPos[i][1] - dzPos[j][1];
			if (dx * dx + dy * dy < 500.0 * 500.0)
				nearby++;
		}

		float radius = baseRadius + nearby * clusterScale;
		if (radius > maxRadius)
			radius = maxRadius;

		SB_SpreadDeathToNavMesh(deathPos[i], radius);
	}
}

// ===========================================================================
// Goto target (debug movement)
// ===========================================================================

static void DriveGotoTarget(int team)
{
	int botCount = BotState_GetTeamBotCount();

	for (int b = 0; b < botCount; b++)
	{
		int client = BotState_GetTeamBot(b);

		// Bot in combat — let native AI handle
		if (BotState_HasVisibleEnemy(client))
		{
			BotState_ClearMoveCommand(client);
			continue;
		}

		BotState_SetMoveCommand(client,
			g_gotoTarget[0], g_gotoTarget[1], g_gotoTarget[2], 0);
		BotState_DriveMovement(client);
	}
}

// ===========================================================================
// Role assignment and movement driving
// ===========================================================================

static void AssignRolesAndDrive(int team)
{
	int botCount = BotState_GetTeamBotCount();
	int intelCount = BotState_GetIntelCount();

	// Build arrays for all alive team bots
	int allClients[MAXPLAYERS + 1];
	float allPositions[MAXPLAYERS + 1][3];
	int allHealths[MAXPLAYERS + 1];

	for (int b = 0; b < botCount; b++)
	{
		allClients[b] = BotState_GetTeamBot(b);
		BotState_GetPos(allClients[b], allPositions[b]);
		allHealths[b] = BotState_GetHealth(allClients[b]);
	}

	// Build intel target list: real enemies if available,
	// otherwise use attacker spawn as synthetic threat
	float intelPos[MAXPLAYERS + 1][3];
	int effectiveIntelCount = 0;

	if (intelCount > 0)
	{
		effectiveIntelCount = intelCount;
		for (int e = 0; e < intelCount; e++)
			BotState_GetIntelPos(e, intelPos[e]);
	}
	else
	{
		float spawnPos[3];
		if (SmartBots_Objectives_GetAttackerSpawn(spawnPos))
		{
			intelPos[0][0] = spawnPos[0];
			intelPos[0][1] = spawnPos[1];
			intelPos[0][2] = spawnPos[2];
			effectiveIntelCount = 1;
		}
	}

	// --- Split: ~15% defenders (closest to objective), rest flankers ---
	int defCount = botCount;
	int flankStart = botCount;

	if (effectiveIntelCount > 0 && SmartBots_Objectives_IsReady())
	{
		// Sort by distance to current objective
		float objPos[3];
		int objIdx = SmartBots_Objectives_CurrentIndex();
		if (SmartBots_Objectives_GetPos(objIdx, objPos))
		{
			// Compute distances
			float dist2[MAXPLAYERS + 1];
			int indices[MAXPLAYERS + 1];
			for (int i = 0; i < botCount; i++)
			{
				float dx = allPositions[i][0] - objPos[0];
				float dy = allPositions[i][1] - objPos[1];
				dist2[i] = dx * dx + dy * dy;
				indices[i] = i;
			}

			// Insertion sort by distance
			for (int i = 1; i < botCount; i++)
			{
				int tmp = indices[i];
				float tmpD = dist2[tmp];
				int j = i - 1;
				while (j >= 0 && dist2[indices[j]] > tmpD)
				{
					indices[j + 1] = indices[j];
					j--;
				}
				indices[j + 1] = tmp;
			}

			// Split
			float ratio = SmartBots_Flanking_GetDefendRatio();
			defCount = RoundFloat(float(botCount) * ratio);
			if (defCount < 1) defCount = 1;
			if (defCount > botCount) defCount = botCount;
			flankStart = defCount;

			// Reorder arrays by sorted indices
			int tmpClients[MAXPLAYERS + 1];
			float tmpPositions[MAXPLAYERS + 1][3];
			int tmpHealths[MAXPLAYERS + 1];
			for (int i = 0; i < botCount; i++)
			{
				int src = indices[i];
				tmpClients[i] = allClients[src];
				tmpPositions[i][0] = allPositions[src][0];
				tmpPositions[i][1] = allPositions[src][1];
				tmpPositions[i][2] = allPositions[src][2];
				tmpHealths[i] = allHealths[src];
			}
			for (int i = 0; i < botCount; i++)
			{
				allClients[i] = tmpClients[i];
				allPositions[i][0] = tmpPositions[i][0];
				allPositions[i][1] = tmpPositions[i][1];
				allPositions[i][2] = tmpPositions[i][2];
				allHealths[i] = tmpHealths[i];
			}
		}
	}

	// --- Defenders → Tactics (spread around objective) ---
	if (defCount > 0)
	{
		// Build defender arrays
		int defClients[MAXPLAYERS + 1];
		float defPositions[MAXPLAYERS + 1][3];
		for (int i = 0; i < defCount; i++)
		{
			defClients[i] = allClients[i];
			defPositions[i][0] = allPositions[i][0];
			defPositions[i][1] = allPositions[i][1];
			defPositions[i][2] = allPositions[i][2];
		}

		SmartBots_Tactics_Update(defClients, defPositions, defCount);

		// Apply tactical commands
		for (int i = 0; i < defCount; i++)
		{
			int client = defClients[i];
			if (g_tac_hasCommand[client])
			{
				BotState_SetMoveCommand(client,
					g_tac_commandPos[client][0],
					g_tac_commandPos[client][1],
					g_tac_commandPos[client][2], 0);
				BotState_DriveMovement(client);
			}
		}
	}

	// --- Flankers → NavFlanking (only those without visible enemies) ---
	if (flankStart < botCount && effectiveIntelCount > 0)
	{
		int flankClients[MAXPLAYERS + 1];
		int flankEdicts[MAXPLAYERS + 1];
		float flankPositions[MAXPLAYERS + 1][3];
		int flankHealths[MAXPLAYERS + 1];
		int flankCount = 0;

		for (int i = flankStart; i < botCount; i++)
		{
			int client = allClients[i];
			if (BotState_HasVisibleEnemy(client))
				continue;

			flankClients[flankCount] = client;
			flankEdicts[flankCount] = client;  // in SourcePawn, edict = client index
			flankPositions[flankCount][0] = allPositions[i][0];
			flankPositions[flankCount][1] = allPositions[i][1];
			flankPositions[flankCount][2] = allPositions[i][2];
			flankHealths[flankCount] = allHealths[i];
			flankCount++;
		}

		if (flankCount > 0)
		{
			bool isCounterAttack = SDKCall_IsCounterAttack();
			bool cautious = SmartBots_Flanking_IsCombatActive();
			int cmdFlags = cautious ? CMD_FLAG_INVESTIGATE : 0;

			SmartBots_Flanking_Update(flankEdicts, flankClients,
				flankPositions, flankHealths, flankCount,
				intelPos, effectiveIntelCount);

			for (int i = 0; i < flankCount; i++)
			{
				int client = flankClients[i];
				int edict = flankEdicts[i];

				// Reached target → clear command
				if (SmartBots_Flanking_HasReachedTarget(client))
				{
					BotState_ClearMoveCommand(client);
					continue;
				}

				// Tier filtering: who gets flank commands
				// Normal: AGR always, MOD before first contact, PAS never
				// Counter-attack: AGR only
				int tier = edict % 3;
				bool shouldCommand;
				if (isCounterAttack)
					shouldCommand = (tier == 0);
				else
					shouldCommand = (tier == 0) || (tier == 1 && !cautious);

				if (!shouldCommand)
				{
					BotState_ClearMoveCommand(client);
					continue;
				}

				float fx[3];
				if (SmartBots_Flanking_GetTarget(client, fx))
				{
					BotState_SetMoveCommand(client, fx[0], fx[1], fx[2], cmdFlags);
					BotState_DriveMovement(client);
				}
				else
				{
					BotState_ClearMoveCommand(client);
				}
			}
		}
	}
}

// ===========================================================================
// Admin commands
// ===========================================================================

public Action Cmd_Goto(int client, int args)
{
	if (args < 3)
	{
		ReplyToCommand(client, "[SmartBots] Usage: sm_smartbots_goto <x> <y> <z>");
		return Plugin_Handled;
	}

	char sx[16], sy[16], sz[16];
	GetCmdArg(1, sx, sizeof(sx));
	GetCmdArg(2, sy, sizeof(sy));
	GetCmdArg(3, sz, sizeof(sz));

	g_gotoTarget[0] = StringToFloat(sx);
	g_gotoTarget[1] = StringToFloat(sy);
	g_gotoTarget[2] = StringToFloat(sz);
	g_hasGotoTarget = true;

	ReplyToCommand(client, "[SmartBots] Goto: %.1f %.1f %.1f",
		g_gotoTarget[0], g_gotoTarget[1], g_gotoTarget[2]);
	return Plugin_Handled;
}

public Action Cmd_Stop(int client, int args)
{
	g_hasGotoTarget = false;
	BotState_ClearAllCommands();
	ReplyToCommand(client, "[SmartBots] Goto cleared, normal AI resumed");
	return Plugin_Handled;
}

public Action Cmd_Status(int client, int args)
{
	int botCount = BotState_GetTeamBotCount();
	int intelCount = BotState_GetIntelCount();

	ReplyToCommand(client, "[SmartBots] Status:");
	ReplyToCommand(client, "  Enabled: %s", g_cvEnabled.BoolValue ? "yes" : "no");
	ReplyToCommand(client, "  Team: %d", g_cvTeam.IntValue);
	ReplyToCommand(client, "  Bots: %d active", botCount);
	ReplyToCommand(client, "  Intel: %d enemies known", intelCount);
	ReplyToCommand(client, "  Goto: %s", g_hasGotoTarget ? "ACTIVE" : "none");

	if (SmartBots_Objectives_IsReady())
	{
		int objCount = SmartBots_Objectives_Count();
		int curObj = SmartBots_Objectives_CurrentIndex();
		int lost = SmartBots_Events_GetObjectivesLost();
		ReplyToCommand(client, "  Objectives: %d total, current=#%d (lost=%d)",
			objCount, curObj, lost);
	}
	else
	{
		ReplyToCommand(client, "  Objectives: not scanned yet");
	}

	return Plugin_Handled;
}

public Action Cmd_Objectives(int client, int args)
{
	if (!SmartBots_Objectives_IsReady())
	{
		ReplyToCommand(client, "[SmartBots] Objectives: not scanned yet");
		return Plugin_Handled;
	}

	int count = SmartBots_Objectives_Count();
	int current = SmartBots_Objectives_CurrentIndex();
	int lost = SmartBots_Events_GetObjectivesLost();

	ReplyToCommand(client, "[SmartBots] Objectives: %d total, current=#%d (lost=%d)",
		count, current, lost);

	for (int i = 0; i < count; i++)
	{
		ObjectiveInfo obj;
		if (SmartBots_Objectives_Get(i, obj))
		{
			ReplyToCommand(client, "  %s[%d] '%s' %s at (%.0f, %.0f, %.0f)",
				(i == current) ? ">> " : "   ",
				obj.order, obj.name,
				obj.isCapture ? "capture" : "destroy",
				obj.pos[0], obj.pos[1], obj.pos[2]);
		}
	}

	float spawnPos[3];
	if (SmartBots_Objectives_GetAttackerSpawn(spawnPos))
	{
		ReplyToCommand(client, "  Attacker spawn: (%.0f, %.0f, %.0f)",
			spawnPos[0], spawnPos[1], spawnPos[2]);
	}

	float approachPos[3];
	if (SmartBots_Objectives_GetApproachPoint(approachPos))
	{
		ReplyToCommand(client, "  Approach point: (%.0f, %.0f, %.0f)",
			approachPos[0], approachPos[1], approachPos[2]);
	}

	return Plugin_Handled;
}

public Action Cmd_Voice(int client, int args)
{
	if (args < 1)
	{
		ReplyToCommand(client, "[SmartBots] Usage: sm_smartbots_voice <concept_id>");
		return Plugin_Handled;
	}

	char sId[16];
	GetCmdArg(1, sId, sizeof(sId));
	int conceptId = StringToInt(sId);

	int spoken = 0;
	int botCount = BotState_GetTeamBotCount();
	for (int b = 0; b < botCount; b++)
	{
		int bot = BotState_GetTeamBot(b);
		if (SDKCall_SpeakConcept(bot, conceptId))
			spoken++;
	}

	ReplyToCommand(client, "[SmartBots] Voice: concept %d sent to %d bots",
		conceptId, spoken);
	return Plugin_Handled;
}
