/**
 * navmesh.inc — Nav mesh access for SmartBots (extended)
 *
 * Raw memory access to CNavArea / CINSNavArea fields via LoadFromAddress.
 * Extends the base deathzones navmesh with:
 *   - Death intensity/timestamp reads (for position scoring)
 *   - Hiding spot count (for cover scoring)
 *   - IsPotentiallyVisible wrapper (via SDKCall)
 *
 * Before using, call SmartBots_NavMesh_Init() with gamedata handle.
 * Requires sdkcalls.inc to be included first (for SDKCall wrappers).
 */

#if defined _smartbots_navmesh_included
#endinput
#endif
#define _smartbots_navmesh_included

#define SB_MAX_BFS_AREAS 256

// CUtlVectorUltraConservative<NavConnect>: single pointer to Data_t
#define SB_SIZEOF_NAVCONNECT_VEC 4

// NavConnect = { CNavArea *area; float length; }
#define SB_SIZEOF_NAVCONNECT 8

// CUtlVector size offset (after m_pMemory, m_nAllocationCount, m_nGrowSize)
#define SB_UTLVECTOR_SIZE_OFFSET 12

// ---------------------------------------------------------------------------
// Offsets (set from gamedata)
// ---------------------------------------------------------------------------

static int g_sbOffNavCenter;          // CNavArea::m_center (Vector, 3 floats)
static int g_sbOffNavConnect;         // CNavArea::m_connect[4] (4 direction vecs)
static int g_sbOffNavInsFlags;        // CINSNavArea::m_insFlags (uint32)
static int g_sbOffNavDeathIntensity;  // CINSNavArea::m_deathIntensity (float)
static int g_sbOffNavDeathTimestamp;  // CINSNavArea::m_deathTimestamp (float)
static int g_sbOffNavHidingSpots;     // CINSNavArea::m_hidingSpots (CUtlVector)

// ---------------------------------------------------------------------------
// BFS queue (global to avoid stack overflow)
// ---------------------------------------------------------------------------

static Address g_sbBfsQueue[SB_MAX_BFS_AREAS];

// ===========================================================================
// Initialization
// ===========================================================================

/**
 * Load nav mesh offsets from gamedata.
 *
 * @param hGamedata    Handle from LoadGameConfigFile("smartbots")
 * @return             true on success
 */
stock bool SmartBots_NavMesh_Init(Handle hGamedata)
{
	g_sbOffNavCenter = GameConfGetOffset(hGamedata, "CNavArea::m_center");
	g_sbOffNavConnect = GameConfGetOffset(hGamedata, "CNavArea::m_connect");
	g_sbOffNavInsFlags = GameConfGetOffset(hGamedata, "CINSNavArea::m_insFlags");
	g_sbOffNavDeathIntensity = GameConfGetOffset(hGamedata, "CINSNavArea::m_deathIntensity");
	g_sbOffNavDeathTimestamp = GameConfGetOffset(hGamedata, "CINSNavArea::m_deathTimestamp");
	g_sbOffNavHidingSpots = GameConfGetOffset(hGamedata, "CINSNavArea::m_hidingSpots");

	if (g_sbOffNavCenter < 0 || g_sbOffNavConnect < 0 || g_sbOffNavInsFlags < 0)
	{
		LogError("[SmartBots] NavMesh: failed to get required offsets");
		return false;
	}

	PrintToServer("[SmartBots] NavMesh: init OK (center=%d connect=%d insFlags=%d death=%d/%d hiding=%d)",
		g_sbOffNavCenter, g_sbOffNavConnect, g_sbOffNavInsFlags,
		g_sbOffNavDeathIntensity, g_sbOffNavDeathTimestamp, g_sbOffNavHidingSpots);
	return true;
}

// ===========================================================================
// Field access
// ===========================================================================

/**
 * Read the center position (Vector) of a CNavArea.
 */
stock void SB_NavArea_GetCenter(Address area, float center[3])
{
	center[0] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_sbOffNavCenter), NumberType_Int32));
	center[1] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_sbOffNavCenter + 4), NumberType_Int32));
	center[2] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_sbOffNavCenter + 8), NumberType_Int32));
}

/**
 * Get the number of adjacent areas in a given direction (0-3: N/E/S/W).
 *
 * m_connect[dir] is a CUtlVectorUltraConservative:
 * pointer to Data_t { int m_Size; NavConnect[] }
 */
stock int SB_NavArea_GetAdjacentCount(Address area, int dir)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_sbOffNavConnect + dir * SB_SIZEOF_NAVCONNECT_VEC),
		NumberType_Int32));

	if (vecPtr == Address_Null)
		return 0;

	int count = LoadFromAddress(vecPtr, NumberType_Int32);
	if (count < 0 || count > 256)
		return 0;

	return count;
}

/**
 * Get the adjacent area at the given direction and index.
 *
 * Data_t layout: { int m_Size; NavConnect m_Elements[]; }
 * NavConnect: { CNavArea *area; float length; } = 8 bytes
 */
stock Address SB_NavArea_GetAdjacentArea(Address area, int dir, int index)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_sbOffNavConnect + dir * SB_SIZEOF_NAVCONNECT_VEC),
		NumberType_Int32));

	if (vecPtr == Address_Null)
		return Address_Null;

	Address neighbor = view_as<Address>(LoadFromAddress(
		vecPtr + view_as<Address>(4 + index * SB_SIZEOF_NAVCONNECT),
		NumberType_Int32));

	return neighbor;
}

/**
 * Check if a CINSNavArea has the INDOOR flag (bit 0x80 in m_insFlags).
 */
stock bool SB_NavArea_IsIndoor(Address area)
{
	int flags = LoadFromAddress(area + view_as<Address>(g_sbOffNavInsFlags), NumberType_Int32);
	return (flags & 0x80) != 0;
}

/**
 * Read the death intensity (float) from CINSNavArea.
 * Written by the deathzones plugin or by SpreadDeathToNavMesh.
 */
stock float SB_NavArea_GetDeathIntensity(Address area)
{
	if (g_sbOffNavDeathIntensity < 0)
		return 0.0;
	return view_as<float>(LoadFromAddress(
		area + view_as<Address>(g_sbOffNavDeathIntensity), NumberType_Int32));
}

/**
 * Read the death timestamp from CINSNavArea (IntervalTimer value).
 */
stock float SB_NavArea_GetDeathTimestamp(Address area)
{
	if (g_sbOffNavDeathTimestamp < 0)
		return 0.0;
	return view_as<float>(LoadFromAddress(
		area + view_as<Address>(g_sbOffNavDeathTimestamp), NumberType_Int32));
}

/**
 * Write death intensity and timestamp to a CINSNavArea.
 * Same as deathzones plugin — used when smartbots handles its own death spreading.
 */
stock void SB_NavArea_SetDeathIntensity(Address area, float intensity, float timestamp)
{
	if (g_sbOffNavDeathIntensity < 0 || g_sbOffNavDeathTimestamp < 0)
		return;
	StoreToAddress(area + view_as<Address>(g_sbOffNavDeathIntensity),
		view_as<int>(intensity), NumberType_Int32);
	StoreToAddress(area + view_as<Address>(g_sbOffNavDeathTimestamp),
		view_as<int>(timestamp), NumberType_Int32);
}

/**
 * Get the number of hiding spots in a CINSNavArea.
 *
 * m_hidingSpots is a CUtlVector<HidingSpot*>:
 * { T* m_pMemory (+0), int m_nAlloc (+4), int m_nGrow (+8), int m_Size (+12) }
 */
stock int SB_NavArea_GetHidingSpotCount(Address area)
{
	if (g_sbOffNavHidingSpots < 0)
		return 0;
	int count = LoadFromAddress(
		area + view_as<Address>(g_sbOffNavHidingSpots + SB_UTLVECTOR_SIZE_OFFSET),
		NumberType_Int32);
	if (count < 0 || count > 256)
		return 0;
	return count;
}

// ===========================================================================
// BFS traversal
// ===========================================================================

/**
 * BFS-collect candidate nav areas within maxDist of startArea.
 *
 * @param startArea     Starting CNavArea address
 * @param maxDist       Maximum distance from start center (units)
 * @param outAreas      Output array of CNavArea addresses
 * @param maxAreas      Maximum number of areas to collect
 * @return              Number of areas collected
 */
stock int SB_CollectCandidateAreas(Address startArea, float maxDist,
	Address[] outAreas, int maxAreas)
{
	if (startArea == Address_Null || maxAreas <= 0)
		return 0;

	if (maxAreas > SB_MAX_BFS_AREAS)
		maxAreas = SB_MAX_BFS_AREAS;

	int head = 0, tail = 0, count = 0;

	float startCenter[3];
	SB_NavArea_GetCenter(startArea, startCenter);

	g_sbBfsQueue[tail++] = startArea;
	outAreas[count++] = startArea;

	while (head < tail && count < maxAreas)
	{
		Address current = g_sbBfsQueue[head++];

		for (int dir = 0; dir < 4; dir++)
		{
			int adjCount = SB_NavArea_GetAdjacentCount(current, dir);
			for (int i = 0; i < adjCount; i++)
			{
				Address neighbor = SB_NavArea_GetAdjacentArea(current, dir, i);
				if (neighbor == Address_Null)
					continue;

				// Linear scan for visited check (small array)
				bool visited = false;
				for (int v = 0; v < count; v++)
				{
					if (outAreas[v] == neighbor)
					{
						visited = true;
						break;
					}
				}
				if (visited)
					continue;

				// Skip blocked areas
				if (SDKCall_IsAreaBlocked(neighbor, 0))
					continue;

				// Distance check from start center
				float nc[3];
				SB_NavArea_GetCenter(neighbor, nc);
				float dx = nc[0] - startCenter[0];
				float dy = nc[1] - startCenter[1];
				float dz = nc[2] - startCenter[2];
				float dist = SquareRoot(dx * dx + dy * dy + dz * dz);
				if (dist > maxDist)
					continue;

				if (count >= maxAreas || tail >= SB_MAX_BFS_AREAS)
					break;

				outAreas[count++] = neighbor;
				g_sbBfsQueue[tail++] = neighbor;
			}
		}
	}

	return count;
}

// ===========================================================================
// Non-prefixed aliases (for compatibility with flanking.inc / tactics.inc)
// ===========================================================================

stock void NavArea_GetCenter(Address area, float center[3])
{ SB_NavArea_GetCenter(area, center); }

stock int NavArea_GetAdjacentCount(Address area, int dir)
{ return SB_NavArea_GetAdjacentCount(area, dir); }

stock Address NavArea_GetAdjacentArea(Address area, int dir, int index)
{ return SB_NavArea_GetAdjacentArea(area, dir, index); }

stock bool NavArea_IsIndoor(Address area)
{ return SB_NavArea_IsIndoor(area); }

stock int CollectCandidateAreas(Address startArea, float maxDist,
	Address[] outAreas, int maxAreas)
{ return SB_CollectCandidateAreas(startArea, maxDist, outAreas, maxAreas); }

// ===========================================================================
// Death zone spreading
// ===========================================================================

/**
 * Spread death intensity to nav areas around a position.
 * Adaptive radius: more clustered deaths -> wider killzone.
 *
 * @param deathPos      Death position
 * @param radius        Spread radius in units
 */
stock void SB_SpreadDeathToNavMesh(float deathPos[3], float radius)
{
	Address startArea = SDKCall_GetNearestNavArea(deathPos);
	if (startArea == Address_Null)
		return;

	Address areas[SB_MAX_BFS_AREAS];
	int areaCount = SB_CollectCandidateAreas(startArea, radius, areas, SB_MAX_BFS_AREAS);

	float startCenter[3];
	SB_NavArea_GetCenter(startArea, startCenter);
	float gameTime = GetGameTime();

	for (int i = 0; i < areaCount; i++)
	{
		float ac[3];
		SB_NavArea_GetCenter(areas[i], ac);

		float dx = ac[0] - startCenter[0];
		float dy = ac[1] - startCenter[1];
		float dz = ac[2] - startCenter[2];
		float dist = SquareRoot(dx * dx + dy * dy + dz * dz);

		// Distance-based intensity falloff
		float intensity = 1.0;
		if (radius > 0.0)
			intensity = 1.0 - (dist / radius);
		if (intensity < 0.1)
			intensity = 0.1;

		// Accumulate: read existing intensity and add
		float existing = SB_NavArea_GetDeathIntensity(areas[i]);
		float newIntensity = existing + intensity;
		if (newIntensity > 5.0)
			newIntensity = 5.0;

		SB_NavArea_SetDeathIntensity(areas[i], newIntensity, gameTime);
	}
}
