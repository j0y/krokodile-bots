/**
 * flanking.inc -- Position scoring and flanking update for SmartBots
 *
 * Port of nav_flanking.cpp (position scoring, BFS candidate collection,
 * hiding spots, death zone avoidance, per-bot aggression tiers, voice callouts).
 *
 * Depends on:
 *   navmesh.inc   -- NavArea_GetCenter, NavArea_GetAdjacentCount/Area,
 *                     NavArea_IsIndoor, CollectCandidateAreas
 *   sdkcalls.inc  -- g_hIsPotentiallyVisible (Handle), g_bHasVisData (bool)
 *   events.inc    -- SmartBots_Events_GetDeathZones
 *   objectives.inc -- SmartBots_Objectives_Get, SmartBots_Objectives_CurrentIndex,
 *                      SmartBots_Objectives_IsReady
 */

#if defined _smartbots_flanking_included
#endinput
#endif
#define _smartbots_flanking_included

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define FLANK_MAX_BFS_AREAS  256
#define FLANK_MAX_BFS_DIST   2000.0
#define FLANK_MAX_DZ         16

// Hiding spot access: CINSNavArea +0xD0 holds CUtlVectorUltraConservative<HidingSpot*>
// Data_t: { int count; HidingSpot* spots[]; }
// HidingSpot: +0x04 float x, +0x08 float y, +0x0C float z
#define OFF_HIDING_SPOTS     0xD0
#define MAX_HIDING_PER_AREA  8

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

enum struct BotTarget {
	float pos[3];
	float score;
	float evalTime;
	int   lastEnemyCount;
	float lastEnemyPos[3];
	int   lastHealth;
	float lastVoiceTime;
	bool  valid;
	bool  reached;
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

BotTarget g_flank_targets[MAXPLAYERS + 1];

// Death zone cache (refreshed each update cycle)
float g_flank_dzPos[FLANK_MAX_DZ][3];
float g_flank_dzTimes[FLANK_MAX_DZ];
int   g_flank_dzHeat[FLANK_MAX_DZ];
int   g_flank_dzCount;
bool  g_flank_dzFresh;               // any death < 15s old

float g_flank_lastEnemySeenTime;

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

ConVar g_flank_cvEnabled;
ConVar g_flank_cvDefendRatio;
ConVar g_flank_cvEvalInterval;
ConVar g_flank_cvIdealDist;
ConVar g_flank_cvCoverWeight;
ConVar g_flank_cvLofWeight;
ConVar g_flank_cvDistWeight;
ConVar g_flank_cvSpreadWeight;
ConVar g_flank_cvIndoorWeight;
ConVar g_flank_cvFlankWeight;
ConVar g_flank_cvDeathZoneWeight;
ConVar g_flank_cvDeathZoneRadius;
ConVar g_flank_cvDeathZoneAge;
ConVar g_flank_cvReachedDist;
ConVar g_flank_cvReachedEval;
ConVar g_flank_cvAdvanceSafeTime;
ConVar g_flank_cvAdvanceDistMin;
ConVar g_flank_cvHidingSpots;
ConVar g_flank_cvVoiceCallouts;
ConVar g_flank_cvVoiceCooldown;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

stock float VecDist(float a[3], float b[3])
{
	float dx = a[0] - b[0];
	float dy = a[1] - b[1];
	float dz = a[2] - b[2];
	return SquareRoot(dx * dx + dy * dy + dz * dz);
}

// ---------------------------------------------------------------------------
// Hiding spot extraction
// ---------------------------------------------------------------------------

/**
 * Read hiding spots from CINSNavArea +0xD0.
 *
 * Port of GetHidingSpotsFromArea (nav_flanking.cpp:120-148).
 *
 * @param area          CNavArea address
 * @param outPos        Output array of spot positions
 * @param outParents    Output array of parent area addresses (same index)
 * @param maxSpots      Maximum spots to return
 * @return              Number of hiding spots written
 */
stock int GetHidingSpotsFromArea(Address area, float outPos[][3],
                                  Address[] outParents, int maxSpots)
{
	Address vecData = view_as<Address>(
		LoadFromAddress(area + view_as<Address>(OFF_HIDING_SPOTS), NumberType_Int32));

	if (vecData == Address_Null)
		return 0;

	int count = LoadFromAddress(vecData, NumberType_Int32);
	if (count <= 0 || count > 64)
		return 0;

	int written = 0;
	for (int i = 0; i < count && written < maxSpots; i++)
	{
		// spots[i] is a pointer at offset 4 + i * 4
		Address spot = view_as<Address>(
			LoadFromAddress(vecData + view_as<Address>(4 + i * 4), NumberType_Int32));

		if (spot == Address_Null)
			continue;

		outPos[written][0] = view_as<float>(LoadFromAddress(spot + view_as<Address>(0x04), NumberType_Int32));
		outPos[written][1] = view_as<float>(LoadFromAddress(spot + view_as<Address>(0x08), NumberType_Int32));
		outPos[written][2] = view_as<float>(LoadFromAddress(spot + view_as<Address>(0x0C), NumberType_Int32));
		outParents[written] = area;
		written++;
	}

	return written;
}

// ---------------------------------------------------------------------------
// Init / Reset
// ---------------------------------------------------------------------------

/**
 * Create all flanking ConVars.  Call once from OnPluginStart.
 */
stock void SmartBots_Flanking_Init()
{
	g_flank_cvEnabled = CreateConVar("sm_smartbots_flank_enabled", "1",
		"Enable position scoring for bots without visible enemies");
	g_flank_cvDefendRatio = CreateConVar("sm_smartbots_flank_defend_ratio", "0.15",
		"Fraction of bots that defend objective (rest flank)");

	g_flank_cvEvalInterval = CreateConVar("sm_smartbots_pos_eval_interval", "2.0",
		"Seconds between position re-evaluation per bot");
	g_flank_cvIdealDist = CreateConVar("sm_smartbots_pos_ideal_dist", "800",
		"Peak of distance bell curve from threat (units)");
	g_flank_cvCoverWeight = CreateConVar("sm_smartbots_pos_cover_weight", "40",
		"Weight for cover from threat (0-100)");
	g_flank_cvLofWeight = CreateConVar("sm_smartbots_pos_lof_weight", "20",
		"Weight for line-of-fire peek ability (0-100)");
	g_flank_cvDistWeight = CreateConVar("sm_smartbots_pos_dist_weight", "15",
		"Weight for distance bell curve (0-100)");
	g_flank_cvSpreadWeight = CreateConVar("sm_smartbots_pos_spread_weight", "15",
		"Weight for spreading from allies (0-100)");
	g_flank_cvIndoorWeight = CreateConVar("sm_smartbots_pos_indoor_weight", "10",
		"Weight for indoor area bonus (0-100)");
	g_flank_cvFlankWeight = CreateConVar("sm_smartbots_pos_flank_weight", "5",
		"Weight for lateral flanking offset from threat-to-objective line (0-100)");

	g_flank_cvDeathZoneWeight = CreateConVar("sm_smartbots_pos_deathzone_weight", "60",
		"Weight for death zone avoidance (0-100)");
	g_flank_cvDeathZoneRadius = CreateConVar("sm_smartbots_pos_deathzone_radius", "600",
		"Radius of death zone penalty (units)");
	g_flank_cvDeathZoneAge = CreateConVar("sm_smartbots_pos_deathzone_age", "45.0",
		"How long death zones remain active (seconds)");

	g_flank_cvReachedDist = CreateConVar("sm_smartbots_pos_reached_dist", "100",
		"Distance to consider position reached (units)");
	g_flank_cvReachedEval = CreateConVar("sm_smartbots_pos_reached_eval", "5.0",
		"Eval interval when positioned at target (seconds)");
	g_flank_cvAdvanceSafeTime = CreateConVar("sm_smartbots_pos_advance_safe_time", "10.0",
		"Seconds with no enemies before bots start advancing");
	g_flank_cvAdvanceDistMin = CreateConVar("sm_smartbots_pos_advance_dist_min", "200",
		"Minimum ideal distance when advancing (units)");
	g_flank_cvHidingSpots = CreateConVar("sm_smartbots_pos_hiding_spots", "1",
		"Use nav mesh hiding spots as additional candidate positions");
	g_flank_cvVoiceCallouts = CreateConVar("sm_smartbots_pos_voice_callouts", "0",
		"Enable vocal callouts when bots pick flanking positions");
	g_flank_cvVoiceCooldown = CreateConVar("sm_smartbots_pos_voice_cooldown", "8.0",
		"Minimum seconds between voice callouts per bot");
}

/**
 * Clear all targets and state.  Call on round start / map change.
 */
stock void SmartBots_Flanking_Reset()
{
	for (int i = 0; i <= MAXPLAYERS; i++)
	{
		g_flank_targets[i].pos[0] = 0.0;
		g_flank_targets[i].pos[1] = 0.0;
		g_flank_targets[i].pos[2] = 0.0;
		g_flank_targets[i].score = 0.0;
		g_flank_targets[i].evalTime = 0.0;
		g_flank_targets[i].lastEnemyCount = 0;
		g_flank_targets[i].lastEnemyPos[0] = 0.0;
		g_flank_targets[i].lastEnemyPos[1] = 0.0;
		g_flank_targets[i].lastEnemyPos[2] = 0.0;
		g_flank_targets[i].lastHealth = 0;
		g_flank_targets[i].lastVoiceTime = 0.0;
		g_flank_targets[i].valid = false;
		g_flank_targets[i].reached = false;
	}

	g_flank_dzCount = 0;
	g_flank_dzFresh = false;
	g_flank_lastEnemySeenTime = 0.0;
}

// ---------------------------------------------------------------------------
// Position scoring
// ---------------------------------------------------------------------------

/**
 * Score a candidate position for a bot.
 *
 * Port of ScorePosition (nav_flanking.cpp:382-512).
 *
 * Seven factors:
 *   1. Cover      -- not visible from threat (IsPotentiallyVisible)
 *   2. LOF        -- can peek from adjacent area
 *   3. Distance   -- gaussian bell curve at idealDist
 *   4. Spread     -- distance to nearest ally
 *   5. Indoor     -- CINSNavArea indoor flag bonus
 *   6. Flanking   -- cross product lateral offset from threat-to-objective line
 *   7. Death zone -- avoid positions where teammates recently died
 *
 * @param pos           Candidate world position
 * @param area          CNavArea address for candidate
 * @param threatArea    CNavArea address for closest threat (may be Address_Null)
 * @param threatPos     World position of closest threat
 * @param objPos        Current objective position
 * @param hasObj        True if objPos is valid
 * @param allyPositions Positions of allied bots (targets or current positions)
 * @param allyCount     Number of allies
 * @param idealDist     Ideal distance from threat (already tier-adjusted)
 * @return              Composite weighted score
 */
stock float SmartBots_ScorePosition(float pos[3], Address area,
                                     Address threatArea, float threatPos[3],
                                     float objPos[3], bool hasObj,
                                     float allyPositions[][3], int allyCount,
                                     float idealDist)
{
	bool useVis = g_bHasVisData && g_hIsPotentiallyVisible != null && threatArea != Address_Null;

	float wCover  = g_flank_cvCoverWeight.FloatValue;
	float wLof    = g_flank_cvLofWeight.FloatValue;
	float wDist   = g_flank_cvDistWeight.FloatValue;
	float wSpread = g_flank_cvSpreadWeight.FloatValue;
	float wIndoor = g_flank_cvIndoorWeight.FloatValue;
	float wFlank  = g_flank_cvFlankWeight.FloatValue;

	// ---- 1. Cover factor: not visible from threat = 1.0, visible = 0.2 ----
	float coverFactor = 0.5;  // default when no vis data
	if (useVis)
	{
		bool visible = SDKCall(g_hIsPotentiallyVisible, threatArea, area);
		coverFactor = visible ? 0.2 : 1.0;
	}

	// ---- 2. LOF factor: can peek from adjacent area = 1.0, else 0.3 ----
	float lofFactor = 0.3;
	if (useVis)
	{
		for (int dir = 0; dir < 4; dir++)
		{
			int adjCount = NavArea_GetAdjacentCount(area, dir);
			for (int i = 0; i < adjCount; i++)
			{
				Address adj = NavArea_GetAdjacentArea(area, dir, i);
				if (adj != Address_Null && SDKCall(g_hIsPotentiallyVisible, threatArea, adj))
				{
					lofFactor = 1.0;
					dir = 4;  // break outer loop
					break;
				}
			}
		}
	}

	// ---- 3. Distance factor: gaussian bell curve peaking at idealDist ----
	float dist = VecDist(pos, threatPos);
	float distDelta = (dist - idealDist) / (idealDist * 0.5);
	float distFactor = Exponential(-0.5 * distDelta * distDelta);

	// ---- 4. Spread factor: distance to nearest ally ----
	float spreadFactor = 1.0;
	if (allyCount > 0)
	{
		float nearestAllyDist = 999999.0;
		for (int a = 0; a < allyCount; a++)
		{
			float d = VecDist(pos, allyPositions[a]);
			if (d < nearestAllyDist)
				nearestAllyDist = d;
		}
		if (nearestAllyDist < 100.0)
			spreadFactor = nearestAllyDist / 300.0 * 0.5;  // harsh penalty for overlap
		else
			spreadFactor = nearestAllyDist / 300.0;

		if (spreadFactor > 1.0)
			spreadFactor = 1.0;
	}

	// ---- 5. Indoor factor ----
	float indoorFactor = NavArea_IsIndoor(area) ? 1.5 : 1.0;

	// ---- 6. Flanking factor: lateral offset from threat-to-objective line ----
	float flankFactor = 0.5;  // neutral default
	if (hasObj)
	{
		float toObjX = objPos[0] - threatPos[0];
		float toObjY = objPos[1] - threatPos[1];
		float toObjLen = SquareRoot(toObjX * toObjX + toObjY * toObjY);

		if (toObjLen > 1.0)
		{
			float toCandX = pos[0] - threatPos[0];
			float toCandY = pos[1] - threatPos[1];
			float toCandLen = SquareRoot(toCandX * toCandX + toCandY * toCandY);

			if (toCandLen > 1.0)
			{
				// 2D cross product magnitude = lateral offset
				float cross = (toObjX * toCandY - toObjY * toCandX) / (toObjLen * toCandLen);
				flankFactor = FloatAbs(cross);  // 0 = inline, 1 = perpendicular
			}
		}
	}

	// ---- 7. Death zone penalty ----
	float wDeathZone  = g_flank_cvDeathZoneWeight.FloatValue;
	float dzBaseRadius = g_flank_cvDeathZoneRadius.FloatValue;
	float dzMaxAge     = g_flank_cvDeathZoneAge.FloatValue;
	float deathZoneFactor = 1.0;

	if (wDeathZone > 0.0 && g_flank_dzCount > 0)
	{
		float curtime = GetGameTime();
		float totalPenalty = 0.0;

		for (int d = 0; d < g_flank_dzCount; d++)
		{
			float effectiveRadius = dzBaseRadius * (1.0 + 0.5 * float(g_flank_dzHeat[d] - 1));
			float dzDist = VecDist(pos, g_flank_dzPos[d]);

			if (dzDist < effectiveRadius)
			{
				float distPenalty = 1.0 - dzDist / effectiveRadius;
				float age = curtime - g_flank_dzTimes[d];
				float ageFade = 1.0 - age / dzMaxAge;
				if (ageFade < 0.0) ageFade = 0.0;
				totalPenalty += distPenalty * ageFade;
			}
		}

		deathZoneFactor = 1.0 - totalPenalty;
		if (deathZoneFactor < 0.0) deathZoneFactor = 0.0;
	}

	// ---- Composite score ----
	float score = coverFactor     * wCover
	            + lofFactor       * wLof
	            + distFactor      * wDist
	            + spreadFactor    * wSpread
	            + indoorFactor    * wIndoor
	            + flankFactor     * wFlank
	            + deathZoneFactor * wDeathZone;

	return score;
}

// ---------------------------------------------------------------------------
// Flanking update (main per-tick logic)
// ---------------------------------------------------------------------------

/**
 * Update flanking targets for all bots.
 *
 * Port of NavFlanking_Update (nav_flanking.cpp:604-907).
 *
 * @param botEdicts       Edict indices for each bot
 * @param botClients      Client indices for each bot
 * @param botPositions    World positions for each bot
 * @param botHealths      Current health for each bot
 * @param botCount        Number of bots
 * @param enemyPositions  Known enemy world positions
 * @param enemyCount      Number of known enemies
 */
stock void SmartBots_Flanking_Update(int[] botEdicts, int[] botClients,
                                      float botPositions[][3], int[] botHealths,
                                      int botCount,
                                      float enemyPositions[][3], int enemyCount)
{
	if (!g_flank_cvEnabled.BoolValue)
		return;

	float curtime = GetGameTime();
	float evalInterval     = g_flank_cvEvalInterval.FloatValue;
	float reachedEvalInterval = g_flank_cvReachedEval.FloatValue;
	float reachedDist      = g_flank_cvReachedDist.FloatValue;

	// ---- Refresh death zone cache ----
	float dzMaxAge    = g_flank_cvDeathZoneAge.FloatValue;
	float dzBaseRadius = g_flank_cvDeathZoneRadius.FloatValue;

	g_flank_dzCount = SmartBots_Events_GetDeathZones(dzMaxAge, g_flank_dzPos,
	                                                  g_flank_dzTimes, FLANK_MAX_DZ);

	// Compute heat per death zone (clustered kills grow radius)
	g_flank_dzFresh = false;
	for (int d = 0; d < g_flank_dzCount; d++)
	{
		g_flank_dzHeat[d] = 1;  // count self
		for (int d2 = 0; d2 < g_flank_dzCount; d2++)
		{
			if (d2 != d && VecDist(g_flank_dzPos[d], g_flank_dzPos[d2]) < dzBaseRadius)
				g_flank_dzHeat[d]++;
		}
		if (curtime - g_flank_dzTimes[d] < 15.0)
			g_flank_dzFresh = true;
	}

	// ---- Advance when safe: shrink idealDist after 10s with no enemies ----
	if (enemyCount > 0)
		g_flank_lastEnemySeenTime = curtime;

	float idealDist = g_flank_cvIdealDist.FloatValue;
	float safeTime  = g_flank_cvAdvanceSafeTime.FloatValue;
	float timeSinceEnemy = curtime - g_flank_lastEnemySeenTime;

	if (g_flank_lastEnemySeenTime > 0.0 && timeSinceEnemy > safeTime)
	{
		// Linearly reduce ideal distance over 20s past safe threshold
		float advanceProgress = (timeSinceEnemy - safeTime) / 20.0;
		if (advanceProgress > 1.0) advanceProgress = 1.0;
		float minDist = g_flank_cvAdvanceDistMin.FloatValue;
		idealDist = idealDist + (minDist - idealDist) * advanceProgress;
	}

	// ---- Get objective position for flanking bias ----
	float objPos[3];
	bool hasObj = false;
	if (SmartBots_Objectives_IsReady())
	{
		int objIdx = SmartBots_Objectives_CurrentIndex();
		if (SmartBots_Objectives_GetPos(objIdx, objPos))
			hasObj = true;
	}

	// ---- Per-bot evaluation ----
	for (int b = 0; b < botCount; b++)
	{
		int edict = botEdicts[b];
		int client = botClients[b];
		if (client < 1 || client > MAXPLAYERS)
			continue;

		// Check if bot reached its target
		if (g_flank_targets[client].valid)
			g_flank_targets[client].reached = (VecDist(botPositions[b], g_flank_targets[client].pos) < reachedDist);

		// Find closest enemy to this bot
		float closestEnemyDist = 999999.0;
		int closestEnemyIdx = -1;
		for (int e = 0; e < enemyCount; e++)
		{
			float d = VecDist(botPositions[b], enemyPositions[e]);
			if (d < closestEnemyDist)
			{
				closestEnemyDist = d;
				closestEnemyIdx = e;
			}
		}

		if (closestEnemyIdx < 0)
		{
			g_flank_targets[client].valid = false;
			continue;
		}

		float threatPos[3];
		threatPos[0] = enemyPositions[closestEnemyIdx][0];
		threatPos[1] = enemyPositions[closestEnemyIdx][1];
		threatPos[2] = enemyPositions[closestEnemyIdx][2];

		// ---- Check if re-evaluation needed ----
		float activeInterval = g_flank_targets[client].reached ? reachedEvalInterval : evalInterval;
		bool needEval = false;

		if (!g_flank_targets[client].valid)
			needEval = true;
		else if (curtime - g_flank_targets[client].evalTime >= activeInterval)
			needEval = true;
		else if (enemyCount != g_flank_targets[client].lastEnemyCount)
			needEval = true;
		else if (VecDist(threatPos, g_flank_targets[client].lastEnemyPos) > 400.0)
			needEval = true;
		else if (botHealths[b] < g_flank_targets[client].lastHealth)
			needEval = true;

		// Force re-eval if a fresh death zone appeared near the bot's current target
		if (!needEval && g_flank_targets[client].valid && g_flank_dzCount > 0)
		{
			float dzCheckRadius = g_flank_cvDeathZoneRadius.FloatValue;
			for (int d = 0; d < g_flank_dzCount; d++)
			{
				if (g_flank_dzTimes[d] > g_flank_targets[client].evalTime &&
				    VecDist(g_flank_targets[client].pos, g_flank_dzPos[d]) < dzCheckRadius)
				{
					needEval = true;
					break;
				}
			}
		}

		if (!needEval)
			continue;

		// ---- Aggression tier based on edict index (stable across re-evals) ----
		// tier 0 -- aggressive: 1.0x ideal dist
		// tier 1 -- moderate:   1.3x ideal dist
		// tier 2 -- passive:    1.6x ideal dist
		int aggressionTier = edict % 3;
		float tierMultiplier = 1.0 + float(aggressionTier) * 0.3;
		float botIdealDist = idealDist * tierMultiplier;

		// ---- Resolve nav areas ----
		Address botArea = GetNearestNavArea(botPositions[b], true, 300.0);
		Address threatArea = GetNearestNavArea(threatPos, true, 500.0);

		if (botArea == Address_Null)
		{
			g_flank_targets[client].valid = false;
			continue;
		}

		// ---- BFS collect candidate areas ----
		Address candidates[FLANK_MAX_BFS_AREAS];
		int candidateCount = CollectCandidateAreas(botArea, FLANK_MAX_BFS_DIST,
		                                            candidates, FLANK_MAX_BFS_AREAS);

		if (candidateCount == 0)
		{
			g_flank_targets[client].valid = false;
			continue;
		}

		// ---- Build ally position array (all bots except this one) ----
		float allyPos[MAXPLAYERS][3];
		int allyCount = 0;
		for (int a = 0; a < botCount && allyCount < MAXPLAYERS; a++)
		{
			if (a == b)
				continue;

			int allyClient = botClients[a];
			if (allyClient >= 1 && allyClient <= MAXPLAYERS && g_flank_targets[allyClient].valid)
			{
				allyPos[allyCount][0] = g_flank_targets[allyClient].pos[0];
				allyPos[allyCount][1] = g_flank_targets[allyClient].pos[1];
				allyPos[allyCount][2] = g_flank_targets[allyClient].pos[2];
			}
			else
			{
				allyPos[allyCount][0] = botPositions[a][0];
				allyPos[allyCount][1] = botPositions[a][1];
				allyPos[allyCount][2] = botPositions[a][2];
			}
			allyCount++;
		}

		// ---- Score all area center candidates, pick highest ----
		float bestScore = -1.0;
		float bestPos[3];
		bool foundBest = false;

		for (int c = 0; c < candidateCount; c++)
		{
			float cpos[3];
			NavArea_GetCenter(candidates[c], cpos);

			float s = SmartBots_ScorePosition(cpos, candidates[c],
			                                   threatArea, threatPos,
			                                   objPos, hasObj,
			                                   allyPos, allyCount,
			                                   botIdealDist);
			if (s > bestScore)
			{
				bestScore = s;
				bestPos[0] = cpos[0];
				bestPos[1] = cpos[1];
				bestPos[2] = cpos[2];
				foundBest = true;
			}
		}

		// ---- Also score hiding spots from candidate areas ----
		if (g_flank_cvHidingSpots.BoolValue)
		{
			float hspotPos[MAX_HIDING_PER_AREA][3];
			Address hspotParents[MAX_HIDING_PER_AREA];

			for (int c = 0; c < candidateCount; c++)
			{
				int hcount = GetHidingSpotsFromArea(candidates[c], hspotPos,
				                                     hspotParents, MAX_HIDING_PER_AREA);
				for (int h = 0; h < hcount; h++)
				{
					float s = SmartBots_ScorePosition(hspotPos[h], hspotParents[h],
					                                   threatArea, threatPos,
					                                   objPos, hasObj,
					                                   allyPos, allyCount,
					                                   botIdealDist);
					if (s > bestScore)
					{
						bestScore = s;
						bestPos[0] = hspotPos[h][0];
						bestPos[1] = hspotPos[h][1];
						bestPos[2] = hspotPos[h][2];
						foundBest = true;
					}
				}
			}
		}

		// ---- Commit best position ----
		if (foundBest)
		{
			// Check if position actually changed (>50u from old target)
			bool posChanged = !g_flank_targets[client].valid ||
				VecDist(bestPos, g_flank_targets[client].pos) > 50.0;

			g_flank_targets[client].pos[0] = bestPos[0];
			g_flank_targets[client].pos[1] = bestPos[1];
			g_flank_targets[client].pos[2] = bestPos[2];
			g_flank_targets[client].score = bestScore;
			g_flank_targets[client].evalTime = curtime;
			g_flank_targets[client].lastEnemyCount = enemyCount;
			g_flank_targets[client].lastEnemyPos[0] = threatPos[0];
			g_flank_targets[client].lastEnemyPos[1] = threatPos[1];
			g_flank_targets[client].lastEnemyPos[2] = threatPos[2];
			g_flank_targets[client].lastHealth = botHealths[b];
			g_flank_targets[client].valid = true;
			g_flank_targets[client].reached = false;

			// ---- Voice callouts (flank left/right/moving) ----
			if (posChanged && g_flank_cvVoiceCallouts.BoolValue && hasObj &&
			    curtime - g_flank_targets[client].lastVoiceTime >= g_flank_cvVoiceCooldown.FloatValue)
			{
				float toObjX = objPos[0] - threatPos[0];
				float toObjY = objPos[1] - threatPos[1];
				float toObjLen = SquareRoot(toObjX * toObjX + toObjY * toObjY);
				float toCandX = bestPos[0] - threatPos[0];
				float toCandY = bestPos[1] - threatPos[1];
				float toCandLen = SquareRoot(toCandX * toCandX + toCandY * toCandY);

				if (toObjLen > 1.0 && toCandLen > 1.0)
				{
					float cross = (toObjX * toCandY - toObjY * toCandX)
					              / (toObjLen * toCandLen);
					float absCross = FloatAbs(cross);

					if (absCross > 0.5)
					{
						// Laterally offset > 30 degrees -- flanking callout
						// 92 = "Flank left!", 93 = "Flank right!"
						int voiceId = (cross > 0.0) ? 92 : 93;
						SmartBots_Voice_Speak(client, voiceId);
						g_flank_targets[client].lastVoiceTime = curtime;
					}
					else if (absCross <= 0.3)
					{
						// Inline with threat-objective axis -- "Moving!"
						SmartBots_Voice_Speak(client, 82);
						g_flank_targets[client].lastVoiceTime = curtime;
					}
				}
			}
		}
		else
		{
			g_flank_targets[client].valid = false;
		}
	}
}

// ---------------------------------------------------------------------------
// Query API
// ---------------------------------------------------------------------------

/**
 * Get the flanking target position for a client.
 *
 * @param client    Client index
 * @param out       Output position
 * @return          True if the client has a valid target
 */
stock bool SmartBots_Flanking_GetTarget(int client, float out[3])
{
	if (client < 1 || client > MAXPLAYERS)
		return false;

	if (!g_flank_targets[client].valid)
		return false;

	out[0] = g_flank_targets[client].pos[0];
	out[1] = g_flank_targets[client].pos[1];
	out[2] = g_flank_targets[client].pos[2];
	return true;
}

/**
 * Check if a client has an active flanking target.
 */
stock bool SmartBots_Flanking_IsActive(int client)
{
	if (client < 1 || client > MAXPLAYERS)
		return false;
	return g_flank_targets[client].valid;
}

/**
 * Check if a client has reached its flanking target.
 */
stock bool SmartBots_Flanking_HasReachedTarget(int client)
{
	if (client < 1 || client > MAXPLAYERS)
		return false;
	return g_flank_targets[client].valid && g_flank_targets[client].reached;
}

/**
 * Get the configured defend ratio (fraction of bots that hold objective).
 */
stock float SmartBots_Flanking_GetDefendRatio()
{
	return g_flank_cvDefendRatio.FloatValue;
}

/**
 * Check if recent combat is active (any death zone < 15s old).
 */
stock bool SmartBots_Flanking_IsCombatActive()
{
	return g_flank_dzFresh;
}
