/**
 * events.inc -- Game event hooks and state tracking for SmartBots
 *
 * SourcePawn port of game_events.cpp. Tracks round phase, objectives lost,
 * capture-point activity, and death positions via a ring buffer. Deaths are
 * queued for deferred processing in GameFrame (unsafe to write nav areas from
 * inside event handlers).
 *
 * Usage:
 *   #include "smartbots/events.inc"
 *
 *   public void OnPluginStart() {
 *       SmartBots_Events_Init(3);   // 3 = Insurgent (controlled team)
 *   }
 */

#if defined _smartbots_events_included
#endinput
#endif
#define _smartbots_events_included

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define EVT_MAX_DEATH_ZONES 16

// ---------------------------------------------------------------------------
// Death zone ring buffer
// ---------------------------------------------------------------------------

static float g_evt_deathPos[EVT_MAX_DEATH_ZONES][3];
static float g_evt_deathTime[EVT_MAX_DEATH_ZONES];
static bool  g_evt_deathActive[EVT_MAX_DEATH_ZONES];
static int   g_evt_deathHead;

// ---------------------------------------------------------------------------
// Pending deaths (queued from event handler, drained in GameFrame)
// ---------------------------------------------------------------------------

static float g_evt_pendingDeaths[EVT_MAX_DEATH_ZONES][3];
static int   g_evt_pendingDeathCount;

// ---------------------------------------------------------------------------
// Game state
// ---------------------------------------------------------------------------

static int  g_evt_controlledTeam;     // engine team (2=Security, 3=Insurgent)
static int  g_evt_objectivesLost;
static char g_evt_phase[16];          // "preround", "active", or "over"
static int  g_evt_cappingCP;          // area index of CP being capped, or -1

// ===========================================================================
// Internal helpers
// ===========================================================================

static void Events_ClearDeathZones()
{
	for (int i = 0; i < EVT_MAX_DEATH_ZONES; i++)
	{
		g_evt_deathActive[i] = false;
		g_evt_deathTime[i] = 0.0;
		g_evt_deathPos[i][0] = 0.0;
		g_evt_deathPos[i][1] = 0.0;
		g_evt_deathPos[i][2] = 0.0;
	}
	g_evt_deathHead = 0;
	g_evt_pendingDeathCount = 0;
}

static void Events_RecordObjectiveLost(const char[] source)
{
	if (strcmp(g_evt_phase, "over") == 0)
	{
		PrintToServer("[SmartBots] Ignoring objective event [%s] -- round is over", source);
		return;
	}
	g_evt_objectivesLost++;
	Events_ClearDeathZones();
	PrintToServer("[SmartBots] Objective lost [%s] (total lost: %d, death zones cleared)",
		source, g_evt_objectivesLost);
}

// ===========================================================================
// Event handlers
// ===========================================================================

static void Event_RoundStart(Event event, const char[] name, bool dontBroadcast)
{
	g_evt_objectivesLost = 0;
	strcopy(g_evt_phase, sizeof(g_evt_phase), "preround");
	g_evt_cappingCP = -1;
	Events_ClearDeathZones();
	PrintToServer("[SmartBots] Round start -- preround");
}

static void Event_RoundBegin(Event event, const char[] name, bool dontBroadcast)
{
	strcopy(g_evt_phase, sizeof(g_evt_phase), "active");
	PrintToServer("[SmartBots] Round active");
}

static void Event_RoundFreezeEnd(Event event, const char[] name, bool dontBroadcast)
{
	strcopy(g_evt_phase, sizeof(g_evt_phase), "active");
	PrintToServer("[SmartBots] Round active (freeze end)");
}

static void Event_RoundEnd(Event event, const char[] name, bool dontBroadcast)
{
	int winner = event.GetInt("winner");
	strcopy(g_evt_phase, sizeof(g_evt_phase), "over");
	g_evt_cappingCP = -1;
	PrintToServer("[SmartBots] Round over (winner: team %d, objectives lost: %d)",
		winner, g_evt_objectivesLost);
}

static void Event_ControlpointCaptured(Event event, const char[] name, bool dontBroadcast)
{
	int cp = event.GetInt("cp");
	int team = event.GetInt("team");
	g_evt_cappingCP = -1;

	if (team != g_evt_controlledTeam)
	{
		char src[64];
		FormatEx(src, sizeof(src), "controlpoint_captured cp=%d team=%d", cp, team);
		Events_RecordObjectiveLost(src);
	}
}

static void Event_ObjectDestroyed(Event event, const char[] name, bool dontBroadcast)
{
	Events_RecordObjectiveLost("object_destroyed");
}

static void Event_RoundLevelAdvanced(Event event, const char[] name, bool dontBroadcast)
{
	int level = event.GetInt("level");
	g_evt_cappingCP = -1;

	char src[64];
	FormatEx(src, sizeof(src), "round_level_advanced level=%d", level);
	Events_RecordObjectiveLost(src);
}

static void Event_ControlpointStarttouch(Event event, const char[] name, bool dontBroadcast)
{
	int area = event.GetInt("area");
	int team = event.GetInt("team");

	// Enemy stepping on capture point
	if (team != g_evt_controlledTeam)
	{
		g_evt_cappingCP = area;
		PrintToServer("[SmartBots] Capture started (cp=%d, by team %d)", area, team);
	}
}

static void Event_ControlpointEndtouch(Event event, const char[] name, bool dontBroadcast)
{
	int team = event.GetInt("team");

	// Enemy left the capture point -- clear capping flag
	if (team != g_evt_controlledTeam && g_evt_cappingCP >= 0)
	{
		PrintToServer("[SmartBots] Capture ended (cp=%d, team %d left)", g_evt_cappingCP, team);
		g_evt_cappingCP = -1;
	}
}

static void Event_PlayerDeath(Event event, const char[] name, bool dontBroadcast)
{
	// player_death 'team' field uses 0-based indexing in Insurgency
	// (0 = Security, 1 = Insurgent).
	// Engine teams are 2-based (2 = Security, 3 = Insurgent).
	int team = event.GetInt("team");

	if (team != g_evt_controlledTeam - 2)
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
	g_evt_deathPos[g_evt_deathHead][0] = pos[0];
	g_evt_deathPos[g_evt_deathHead][1] = pos[1];
	g_evt_deathPos[g_evt_deathHead][2] = pos[2];
	g_evt_deathTime[g_evt_deathHead] = GetGameTime();
	g_evt_deathActive[g_evt_deathHead] = true;
	g_evt_deathHead = (g_evt_deathHead + 1) % EVT_MAX_DEATH_ZONES;

	// Queue for deferred processing (unsafe to write nav areas from event handler)
	if (g_evt_pendingDeathCount < EVT_MAX_DEATH_ZONES)
	{
		g_evt_pendingDeaths[g_evt_pendingDeathCount][0] = pos[0];
		g_evt_pendingDeaths[g_evt_pendingDeathCount][1] = pos[1];
		g_evt_pendingDeaths[g_evt_pendingDeathCount][2] = pos[2];
		g_evt_pendingDeathCount++;
	}

	PrintToServer("[SmartBots] Death zone recorded at (%.0f, %.0f, %.0f)",
		pos[0], pos[1], pos[2]);
}

static void Event_GameEnd(Event event, const char[] name, bool dontBroadcast)
{
	PrintToServer("[SmartBots] Game ended -- resetting objectives (was %d)",
		g_evt_objectivesLost);
	g_evt_objectivesLost = 0;
}

// ===========================================================================
// Public API
// ===========================================================================

/**
 * Initialize event tracking and hook all relevant game events.
 *
 * @param controlledTeam    Engine team index (2=Security, 3=Insurgent)
 */
stock void SmartBots_Events_Init(int controlledTeam)
{
	g_evt_controlledTeam = controlledTeam;
	g_evt_objectivesLost = 0;
	g_evt_cappingCP = -1;
	strcopy(g_evt_phase, sizeof(g_evt_phase), "active");

	Events_ClearDeathZones();

	HookEvent("round_start",               Event_RoundStart);
	HookEvent("round_begin",               Event_RoundBegin);
	HookEvent("round_freeze_end",          Event_RoundFreezeEnd);
	HookEvent("round_end",                 Event_RoundEnd);
	HookEvent("controlpoint_captured",     Event_ControlpointCaptured);
	HookEvent("object_destroyed",          Event_ObjectDestroyed);
	HookEvent("round_level_advanced",      Event_RoundLevelAdvanced);
	HookEvent("controlpoint_starttouch",   Event_ControlpointStarttouch);
	HookEvent("controlpoint_endtouch",     Event_ControlpointEndtouch);
	HookEvent("player_death",              Event_PlayerDeath);
	HookEvent("game_end",                  Event_GameEnd);

	PrintToServer("[SmartBots] Game events: init (controlled team: %d)", controlledTeam);
}

/**
 * Reset all event state (objectives, phase, death zones).
 * Call on map change or full reset.
 */
stock void SmartBots_Events_Reset()
{
	g_evt_objectivesLost = 0;
	g_evt_cappingCP = -1;
	strcopy(g_evt_phase, sizeof(g_evt_phase), "active");
	Events_ClearDeathZones();
	PrintToServer("[SmartBots] Events: reset");
}

/**
 * Get the number of objectives lost this round.
 *
 * @return    Number of objectives lost since last round_start
 */
stock int SmartBots_Events_GetObjectivesLost()
{
	return g_evt_objectivesLost;
}

/**
 * Get the current round phase string.
 *
 * @param output    Buffer to receive the phase string
 * @param maxlen    Size of the output buffer
 */
stock void SmartBots_Events_GetPhase(char[] output, int maxlen)
{
	strcopy(output, maxlen, g_evt_phase);
}

/**
 * Get the area index of the control point currently being captured,
 * or -1 if no capture is in progress.
 *
 * @return    CP area index, or -1
 */
stock int SmartBots_Events_GetCappingCP()
{
	return g_evt_cappingCP;
}

/**
 * Drain all pending death positions (queued from player_death events).
 * After this call, the pending queue is empty.
 *
 * @param outPositions    Output array of float[3] positions
 * @param maxCount        Maximum number of entries to drain
 * @return                Number of entries written to outPositions
 */
stock int SmartBots_Events_DrainPendingDeaths(float outPositions[][3], int maxCount)
{
	int count = g_evt_pendingDeathCount;
	if (count > maxCount)
		count = maxCount;

	for (int i = 0; i < count; i++)
	{
		outPositions[i][0] = g_evt_pendingDeaths[i][0];
		outPositions[i][1] = g_evt_pendingDeaths[i][1];
		outPositions[i][2] = g_evt_pendingDeaths[i][2];
	}

	g_evt_pendingDeathCount = 0;
	return count;
}

/**
 * Get all active death zones within the given age limit.
 *
 * @param maxAge          Maximum age in seconds (zones older than this are skipped)
 * @param outPositions    Output array of float[3] positions
 * @param outTimes        Output array of timestamps (game time when death occurred)
 * @param maxCount        Maximum number of entries to return
 * @return                Number of entries written
 */
stock int SmartBots_Events_GetDeathZones(float maxAge, float outPositions[][3],
	float[] outTimes, int maxCount)
{
	float curtime = GetGameTime();
	int count = 0;

	for (int i = 0; i < EVT_MAX_DEATH_ZONES && count < maxCount; i++)
	{
		if (!g_evt_deathActive[i])
			continue;

		float age = curtime - g_evt_deathTime[i];
		if (age > maxAge || age < 0.0)
			continue;

		outPositions[count][0] = g_evt_deathPos[i][0];
		outPositions[count][1] = g_evt_deathPos[i][1];
		outPositions[count][2] = g_evt_deathPos[i][2];
		outTimes[count] = g_evt_deathTime[i];
		count++;
	}

	return count;
}
