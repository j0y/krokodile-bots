/**
 * objectives.inc -- Map objective and spawn zone scanner for SmartBots
 *
 * SourcePawn port of nav_objectives.cpp. Scans map entities at runtime to
 * discover control points, weapon caches, and spawn zones. No external data
 * files are needed -- everything is extracted from live entities.
 *
 * Usage:
 *   #include "smartbots/objectives.inc"
 *
 *   public void OnMapStart() {
 *       CreateTimer(1.0, Timer_ScanObjectives);  // entities need time to spawn
 *   }
 *
 *   Action Timer_ScanObjectives(Handle timer) {
 *       SmartBots_Objectives_Scan();
 *       return Plugin_Stop;
 *   }
 *
 * Requires events.inc for SmartBots_Events_GetObjectivesLost().
 */

#if defined _smartbots_objectives_included
#endinput
#endif
#define _smartbots_objectives_included

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define OBJ_MAX_OBJECTIVES 16
#define OBJ_MAX_SPAWNZONES 32

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

enum struct ObjectiveInfo
{
	float pos[3];
	char  name[64];
	int   order;        // 1-based sequence index parsed from targetname
	bool  isCapture;    // true = capture point, false = destroy (weapon cache)
}

enum struct SpawnZoneInfo
{
	float pos[3];
	int   team;         // 2 = Security (attacker), 3 = Insurgent (defender)
	int   phase;        // phase number (1-based)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static ObjectiveInfo  g_obj_objectives[OBJ_MAX_OBJECTIVES];
static int            g_obj_objectiveCount;

static SpawnZoneInfo  g_obj_spawnZones[OBJ_MAX_SPAWNZONES];
static int            g_obj_spawnZoneCount;

static float g_obj_attackerSpawn[3];
static bool  g_obj_hasAttackerSpawn;

static bool  g_obj_ready;

// ===========================================================================
// Internal helpers
// ===========================================================================

/**
 * Extract phase number from a spawnzone targetname like "sz_1", "phase_2", "sz_a".
 */
static int Obj_ParsePhase(const char[] targetname)
{
	if (targetname[0] == '\0')
		return 0;

	// Scan for the first digit run and parse the number manually.
	// Equivalent to C atoi(p) starting at the first digit.
	int len = strlen(targetname);
	for (int i = 0; i < len; i++)
	{
		if (targetname[i] >= '0' && targetname[i] <= '9')
		{
			int val = 0;
			while (i < len && targetname[i] >= '0' && targetname[i] <= '9')
			{
				val = val * 10 + (targetname[i] - '0');
				i++;
			}
			return val;
		}
	}

	// Try single trailing letter: "sz_a" -> 1, "sz_b" -> 2
	if (len >= 2 && targetname[len - 2] == '_')
	{
		int c = targetname[len - 1];
		if (c >= 'a' && c <= 'z')
			return (c - 'a') + 1;
		if (c >= 'A' && c <= 'Z')
			return (c - 'A') + 1;
	}

	return 0;
}

/**
 * Extract order from a control point targetname like "cp_1", "cap_a", "cachepoint_b".
 */
static int Obj_ParseOrder(const char[] targetname)
{
	if (targetname[0] == '\0')
		return 0;

	int len = strlen(targetname);

	// Try trailing number: "cp_1" -> 1, "cp_12" -> 12
	// Walk backward to find the start of the digit run
	int numStart = len;
	while (numStart > 0 && targetname[numStart - 1] >= '0' && targetname[numStart - 1] <= '9')
		numStart--;

	if (numStart < len)
	{
		// Parse the trailing digit run manually
		int val = 0;
		for (int i = numStart; i < len; i++)
		{
			val = val * 10 + (targetname[i] - '0');
		}
		return val;
	}

	// Try trailing letter: "cp_a" -> 1, "cap_b" -> 2
	if (len >= 2)
	{
		int c = targetname[len - 1];
		if (c >= 'a' && c <= 'z')
			return (c - 'a') + 1;
		if (c >= 'A' && c <= 'Z')
			return (c - 'A') + 1;
	}

	return 0;
}

/**
 * Check if a string contains a substring (case-sensitive).
 * Compatible with SourceMod 1.10+ (does not require StrContains from 1.11).
 */
static bool Obj_StrContains(const char[] haystack, const char[] needle)
{
	int hLen = strlen(haystack);
	int nLen = strlen(needle);

	if (nLen == 0 || nLen > hLen)
		return false;

	for (int i = 0; i <= hLen - nLen; i++)
	{
		bool match = true;
		for (int j = 0; j < nLen; j++)
		{
			if (haystack[i + j] != needle[j])
			{
				match = false;
				break;
			}
		}
		if (match)
			return true;
	}

	return false;
}

// ===========================================================================
// Public API
// ===========================================================================

/**
 * Scan the map for objectives (control points, weapon caches) and spawn zones.
 *
 * Two-pass entity scan:
 *   Pass 1: Find trigger_capture_zone entities to identify capture-type CPs
 *   Pass 2: Collect point_controlpoint, obj_weapon_cache, ins_spawnzone
 *
 * After scanning, objectives are deduplicated by XY proximity, sorted by order,
 * and the attacker spawn centroid is computed (Security team=2, first phase).
 *
 * Safe to call multiple times -- rescans each time.
 */
stock void SmartBots_Objectives_Scan()
{
	g_obj_objectiveCount = 0;
	g_obj_spawnZoneCount = 0;
	g_obj_hasAttackerSpawn = false;
	g_obj_ready = false;

	// Track which CP targetnames have trigger_capture_zone references
	char captureNames[OBJ_MAX_OBJECTIVES][64];
	int captureNameCount = 0;

	// -----------------------------------------------------------------
	// Pass 1: find trigger_capture_zone to identify capture-type CPs
	// -----------------------------------------------------------------

	int ent = -1;
	while ((ent = FindEntityByClassname(ent, "trigger_capture_zone")) != -1)
	{
		if (!IsValidEntity(ent))
			continue;

		char cpName[64];

		// Try reading the "controlpoint" key via Prop_Data m_iszCapPointName
		// (the send/data table name for the capture zone's CP reference).
		// If that fails, the zone is skipped -- harmless, just means we
		// won't pre-tag the CP as capture type (heuristics in Pass 2 cover it).
		bool gotName = false;
		if (HasEntProp(ent, Prop_Data, "m_iszCapPointName"))
		{
			GetEntPropString(ent, Prop_Data, "m_iszCapPointName", cpName, sizeof(cpName));
			if (cpName[0] != '\0')
				gotName = true;
		}

		if (!gotName)
			continue;

		if (captureNameCount < OBJ_MAX_OBJECTIVES)
		{
			strcopy(captureNames[captureNameCount], sizeof(captureNames[]),
				cpName);
			captureNameCount++;
		}
	}

	// -----------------------------------------------------------------
	// Pass 2: collect point_controlpoint, obj_weapon_cache, ins_spawnzone
	// -----------------------------------------------------------------

	// --- point_controlpoint ---
	ent = -1;
	while ((ent = FindEntityByClassname(ent, "point_controlpoint")) != -1)
	{
		if (!IsValidEntity(ent))
			continue;

		if (g_obj_objectiveCount >= OBJ_MAX_OBJECTIVES)
			break;

		float pos[3];
		char targetname[64];

		GetEntPropVector(ent, Prop_Send, "m_vecOrigin", pos);
		GetEntPropString(ent, Prop_Data, "m_iName", targetname, sizeof(targetname));

		ObjectiveInfo obj;
		obj.pos[0] = pos[0];
		obj.pos[1] = pos[1];
		obj.pos[2] = pos[2];
		strcopy(obj.name, sizeof(obj.name), targetname);
		obj.order = Obj_ParseOrder(targetname);

		// Check if this CP has a trigger_capture_zone reference
		obj.isCapture = false;
		for (int i = 0; i < captureNameCount; i++)
		{
			if (strcmp(captureNames[i], targetname) == 0)
			{
				obj.isCapture = true;
				break;
			}
		}

		// Heuristic: if name doesn't contain "cache" and no capture zone
		// was found, default to capture type (some maps lack trigger_capture_zone)
		if (!obj.isCapture
			&& !Obj_StrContains(targetname, "cache")
			&& !Obj_StrContains(targetname, "Cache"))
		{
			obj.isCapture = true;
		}

		g_obj_objectives[g_obj_objectiveCount] = obj;
		g_obj_objectiveCount++;
	}

	// --- obj_weapon_cache ---
	ent = -1;
	while ((ent = FindEntityByClassname(ent, "obj_weapon_cache")) != -1)
	{
		if (!IsValidEntity(ent))
			continue;

		if (g_obj_objectiveCount >= OBJ_MAX_OBJECTIVES)
			break;

		float pos[3];
		char targetname[64];
		char cpRef[64];

		GetEntPropVector(ent, Prop_Send, "m_vecOrigin", pos);
		GetEntPropString(ent, Prop_Data, "m_iName", targetname, sizeof(targetname));

		// Try to get the associated control point name
		cpRef[0] = '\0';
		if (HasEntProp(ent, Prop_Data, "m_iszControlPoint"))
		{
			GetEntPropString(ent, Prop_Data, "m_iszControlPoint", cpRef, sizeof(cpRef));
		}

		// Merge with existing point_controlpoint: match by name or proximity
		bool merged = false;
		for (int i = 0; i < g_obj_objectiveCount; i++)
		{
			bool nameMatch = (cpRef[0] != '\0'
				&& strcmp(g_obj_objectives[i].name, cpRef) == 0);

			// Same XY within 2 units = same objective at different Z
			float dx = g_obj_objectives[i].pos[0] - pos[0];
			float dy = g_obj_objectives[i].pos[1] - pos[1];
			bool posMatch = (dx * dx + dy * dy) < 4.0;

			if (nameMatch || posMatch)
			{
				g_obj_objectives[i].pos[0] = pos[0];
				g_obj_objectives[i].pos[1] = pos[1];
				g_obj_objectives[i].pos[2] = pos[2];
				g_obj_objectives[i].isCapture = false;  // confirmed destroy
				merged = true;
				break;
			}
		}

		if (!merged)
		{
			ObjectiveInfo obj;
			obj.pos[0] = pos[0];
			obj.pos[1] = pos[1];
			obj.pos[2] = pos[2];

			if (cpRef[0] != '\0')
				strcopy(obj.name, sizeof(obj.name), cpRef);
			else
				strcopy(obj.name, sizeof(obj.name), targetname);

			obj.order = Obj_ParseOrder(obj.name);
			obj.isCapture = false;

			g_obj_objectives[g_obj_objectiveCount] = obj;
			g_obj_objectiveCount++;
		}
	}

	// --- ins_spawnzone ---
	ent = -1;
	while ((ent = FindEntityByClassname(ent, "ins_spawnzone")) != -1)
	{
		if (!IsValidEntity(ent))
			continue;

		if (g_obj_spawnZoneCount >= OBJ_MAX_SPAWNZONES)
			break;

		float pos[3];
		char targetname[64];

		GetEntPropVector(ent, Prop_Send, "m_vecOrigin", pos);
		GetEntPropString(ent, Prop_Data, "m_iName", targetname, sizeof(targetname));

		SpawnZoneInfo sz;
		sz.pos[0] = pos[0];
		sz.pos[1] = pos[1];
		sz.pos[2] = pos[2];

		// Read team number (m_iTeamNum is a standard networked prop)
		if (HasEntProp(ent, Prop_Send, "m_iTeamNum"))
		{
			sz.team = GetEntProp(ent, Prop_Send, "m_iTeamNum");
		}
		else
		{
			sz.team = 0;
		}

		sz.phase = Obj_ParsePhase(targetname);

		g_obj_spawnZones[g_obj_spawnZoneCount] = sz;
		g_obj_spawnZoneCount++;
	}

	// -----------------------------------------------------------------
	// Deduplicate objectives by XY proximity (< 2 units)
	// -----------------------------------------------------------------

	for (int i = 0; i < g_obj_objectiveCount; i++)
	{
		for (int j = i + 1; j < g_obj_objectiveCount; j++)
		{
			float dx = g_obj_objectives[i].pos[0] - g_obj_objectives[j].pos[0];
			float dy = g_obj_objectives[i].pos[1] - g_obj_objectives[j].pos[1];

			if (dx * dx + dy * dy < 4.0)
			{
				// Keep the one with higher order (parseable name)
				int keep = (g_obj_objectives[i].order >= g_obj_objectives[j].order) ? i : j;
				int drop = (keep == i) ? j : i;

				g_obj_objectives[drop] = g_obj_objectives[g_obj_objectiveCount - 1];
				g_obj_objectiveCount--;
				j--;  // re-check this index
			}
		}
	}

	// -----------------------------------------------------------------
	// Sort objectives by order (insertion sort)
	// -----------------------------------------------------------------

	for (int i = 1; i < g_obj_objectiveCount; i++)
	{
		ObjectiveInfo key;
		key = g_obj_objectives[i];
		int j = i - 1;

		while (j >= 0 && g_obj_objectives[j].order > key.order)
		{
			g_obj_objectives[j + 1] = g_obj_objectives[j];
			j--;
		}
		g_obj_objectives[j + 1] = key;
	}

	// -----------------------------------------------------------------
	// Compute attacker spawn centroid (Security team=2, first phase)
	// -----------------------------------------------------------------

	if (g_obj_spawnZoneCount > 0)
	{
		// Find the minimum phase among Security spawn zones
		int minPhase = 999;
		for (int i = 0; i < g_obj_spawnZoneCount; i++)
		{
			if (g_obj_spawnZones[i].team == 2
				&& g_obj_spawnZones[i].phase > 0
				&& g_obj_spawnZones[i].phase < minPhase)
			{
				minPhase = g_obj_spawnZones[i].phase;
			}
		}

		float sumX = 0.0;
		float sumY = 0.0;
		float sumZ = 0.0;
		int count = 0;
		for (int i = 0; i < g_obj_spawnZoneCount; i++)
		{
			if (g_obj_spawnZones[i].team == 2
				&& g_obj_spawnZones[i].phase == minPhase)
			{
				sumX += g_obj_spawnZones[i].pos[0];
				sumY += g_obj_spawnZones[i].pos[1];
				sumZ += g_obj_spawnZones[i].pos[2];
				count++;
			}
		}

		if (count > 0)
		{
			g_obj_attackerSpawn[0] = sumX / float(count);
			g_obj_attackerSpawn[1] = sumY / float(count);
			g_obj_attackerSpawn[2] = sumZ / float(count);
			g_obj_hasAttackerSpawn = true;
		}
	}

	g_obj_ready = (g_obj_objectiveCount > 0);

	// Log results
	PrintToServer("[SmartBots] Objectives: scanned %d objectives, %d spawn zones",
		g_obj_objectiveCount, g_obj_spawnZoneCount);

	for (int i = 0; i < g_obj_objectiveCount; i++)
	{
		PrintToServer("  [%d] '%s' order=%d %s at (%.0f, %.0f, %.0f)",
			i, g_obj_objectives[i].name,
			g_obj_objectives[i].order,
			g_obj_objectives[i].isCapture ? "capture" : "destroy",
			g_obj_objectives[i].pos[0], g_obj_objectives[i].pos[1],
			g_obj_objectives[i].pos[2]);
	}

	if (g_obj_hasAttackerSpawn)
	{
		PrintToServer("  Attacker spawn: (%.0f, %.0f, %.0f)",
			g_obj_attackerSpawn[0], g_obj_attackerSpawn[1], g_obj_attackerSpawn[2]);
	}
}

/**
 * Check if objectives have been scanned successfully.
 *
 * @return    true if at least one objective was found
 */
stock bool SmartBots_Objectives_IsReady()
{
	return g_obj_ready;
}

/**
 * Get the number of objectives discovered (ordered by sequence).
 *
 * @return    Objective count
 */
stock int SmartBots_Objectives_Count()
{
	return g_obj_objectiveCount;
}

/**
 * Get objective info by 0-based index.
 *
 * @param index    0-based objective index
 * @param out      Output ObjectiveInfo struct
 * @return         true if index is valid, false if out of range
 */
stock bool SmartBots_Objectives_Get(int index, ObjectiveInfo out)
{
	if (index < 0 || index >= g_obj_objectiveCount)
		return false;

	out = g_obj_objectives[index];
	return true;
}

/**
 * Get the current "active" objective index (0-based).
 *
 * Derived from the objectives-lost count (from events.inc). In coop
 * checkpoint mode, this is the objective defenders protect next.
 * Clamped to the last valid index.
 *
 * @return    Current objective index
 */
stock int SmartBots_Objectives_CurrentIndex()
{
	int lost = SmartBots_Events_GetObjectivesLost();

	if (g_obj_objectiveCount <= 0)
		return 0;

	if (lost >= g_obj_objectiveCount)
		return g_obj_objectiveCount - 1;  // clamp to last

	return lost;
}

/**
 * Get the Security (attacker) spawn centroid for the first phase.
 *
 * @param out    Output position vector
 * @return       true if spawn data was found, false otherwise
 */
stock bool SmartBots_Objectives_GetAttackerSpawn(float out[3])
{
	if (!g_obj_hasAttackerSpawn)
		return false;

	out[0] = g_obj_attackerSpawn[0];
	out[1] = g_obj_attackerSpawn[1];
	out[2] = g_obj_attackerSpawn[2];
	return true;
}

/**
 * Get the approach point (midpoint between attacker spawn and first objective).
 *
 * @param out    Output position vector
 * @return       true if both spawn and first objective exist, false otherwise
 */
stock bool SmartBots_Objectives_GetApproachPoint(float out[3])
{
	if (!g_obj_hasAttackerSpawn || g_obj_objectiveCount == 0)
		return false;

	out[0] = (g_obj_attackerSpawn[0] + g_obj_objectives[0].pos[0]) / 2.0;
	out[1] = (g_obj_attackerSpawn[1] + g_obj_objectives[0].pos[1]) / 2.0;
	out[2] = (g_obj_attackerSpawn[2] + g_obj_objectives[0].pos[2]) / 2.0;
	return true;
}

/**
 * Get just the position of an objective by index.
 * Convenience wrapper used by flanking.inc and tactics.inc.
 *
 * @param index    0-based objective index
 * @param pos      Output position vector
 * @return         true if index is valid
 */
stock bool SmartBots_Objectives_GetPos(int index, float pos[3])
{
	if (index < 0 || index >= g_obj_objectiveCount)
		return false;

	pos[0] = g_obj_objectives[index].pos[0];
	pos[1] = g_obj_objectives[index].pos[1];
	pos[2] = g_obj_objectives[index].pos[2];
	return true;
}

/**
 * Clear all scanned objective and spawn zone data.
 * Call on map change or full reset.
 */
stock void SmartBots_Objectives_Reset()
{
	g_obj_objectiveCount = 0;
	g_obj_spawnZoneCount = 0;
	g_obj_hasAttackerSpawn = false;
	g_obj_ready = false;
	PrintToServer("[SmartBots] Objectives: reset");
}
