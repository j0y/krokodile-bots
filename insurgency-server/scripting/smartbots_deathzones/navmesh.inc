/**
 * navmesh.inc — Raw memory access to CNavArea / CINSNavArea fields
 *
 * Provides BFS traversal and field reads via LoadFromAddress.
 * Shared between smartbots_deathzones and smartbots plugins.
 *
 * Before using, call NavMesh_SetOffsets() with values from gamedata,
 * and NavMesh_SetIsBlockedHandle() with a valid SDKCall handle.
 */

#if defined _smartbots_navmesh_included
#endinput
#endif
#define _smartbots_navmesh_included

#define MAX_BFS_AREAS 256

// CUtlVectorUltraConservative<NavConnect>: single pointer to Data_t
#define SIZEOF_NAVCONNECT_VEC 4

// NavConnect = { CNavArea *area; float length; }
#define SIZEOF_NAVCONNECT 8

// --- Offsets (set from gamedata) ---
static int g_offNavCenter;    // CNavArea::m_center (Vector, 3 floats)
static int g_offNavConnect;   // CNavArea::m_connect[4] (4 direction vectors)
static int g_offNavInsFlags;  // CINSNavArea::m_insFlags (uint32)

// --- BFS queue (global to avoid stack overflow) ---
static Address g_bfsQueue[MAX_BFS_AREAS];

// --- SDKCall handle for CNavArea::IsBlocked ---
static Handle g_hSDK_NavIsBlocked;

/**
 * Initialize nav mesh offsets from gamedata values.
 */
stock void NavMesh_SetOffsets(int center, int connect, int insFlags)
{
	g_offNavCenter = center;
	g_offNavConnect = connect;
	g_offNavInsFlags = insFlags;
}

/**
 * Set the IsBlocked SDKCall handle used by BFS.
 * May be null to skip blocked checks.
 */
stock void NavMesh_SetIsBlockedHandle(Handle h)
{
	g_hSDK_NavIsBlocked = h;
}

/**
 * Read the center position (Vector) of a CNavArea.
 */
stock void NavArea_GetCenter(Address area, float center[3])
{
	center[0] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_offNavCenter), NumberType_Int32));
	center[1] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_offNavCenter + 4), NumberType_Int32));
	center[2] = view_as<float>(LoadFromAddress(area + view_as<Address>(g_offNavCenter + 8), NumberType_Int32));
}

/**
 * Get the number of adjacent areas in a given direction (0-3: N/E/S/W).
 *
 * m_connect[dir] is a CUtlVectorUltraConservative: pointer to Data_t { int m_Size; NavConnect[] }
 */
stock int NavArea_GetAdjacentCount(Address area, int dir)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_offNavConnect + dir * SIZEOF_NAVCONNECT_VEC),
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
stock Address NavArea_GetAdjacentArea(Address area, int dir, int index)
{
	Address vecPtr = view_as<Address>(LoadFromAddress(
		area + view_as<Address>(g_offNavConnect + dir * SIZEOF_NAVCONNECT_VEC),
		NumberType_Int32));

	if (vecPtr == Address_Null)
		return Address_Null;

	// NavConnect[index].area at offset: sizeof(int) + index * sizeof(NavConnect)
	Address neighbor = view_as<Address>(LoadFromAddress(
		vecPtr + view_as<Address>(4 + index * SIZEOF_NAVCONNECT),
		NumberType_Int32));

	return neighbor;
}

/**
 * Check if a CINSNavArea has the INDOOR flag (bit 0x80 in m_insFlags).
 */
stock bool NavArea_IsIndoor(Address area)
{
	int flags = LoadFromAddress(area + view_as<Address>(g_offNavInsFlags), NumberType_Int32);
	return (flags & 0x80) != 0;
}

/**
 * BFS-collect candidate nav areas within maxDist of startArea.
 *
 * @param startArea     Starting CNavArea address
 * @param maxDist       Maximum distance from start center (units)
 * @param outAreas      Output array of CNavArea addresses
 * @param maxAreas      Maximum number of areas to collect
 * @return              Number of areas collected
 */
stock int CollectCandidateAreas(Address startArea, float maxDist, Address[] outAreas, int maxAreas)
{
	if (startArea == Address_Null || maxAreas <= 0)
		return 0;

	if (maxAreas > MAX_BFS_AREAS)
		maxAreas = MAX_BFS_AREAS;

	int head = 0, tail = 0, count = 0;

	float startCenter[3];
	NavArea_GetCenter(startArea, startCenter);

	g_bfsQueue[tail++] = startArea;
	outAreas[count++] = startArea;

	while (head < tail && count < maxAreas)
	{
		Address current = g_bfsQueue[head++];

		for (int dir = 0; dir < 4; dir++)
		{
			int adjCount = NavArea_GetAdjacentCount(current, dir);
			for (int i = 0; i < adjCount; i++)
			{
				Address neighbor = NavArea_GetAdjacentArea(current, dir, i);
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
				if (g_hSDK_NavIsBlocked != null)
				{
					if (SDKCall(g_hSDK_NavIsBlocked, neighbor, 0, false))
						continue;
				}

				// Distance check from start center
				float nc[3];
				NavArea_GetCenter(neighbor, nc);
				float dx = nc[0] - startCenter[0];
				float dy = nc[1] - startCenter[1];
				float dz = nc[2] - startCenter[2];
				float dist = SquareRoot(dx * dx + dy * dy + dz * dz);
				if (dist > maxDist)
					continue;

				if (count >= maxAreas || tail >= MAX_BFS_AREAS)
					break;

				outAreas[count++] = neighbor;
				g_bfsQueue[tail++] = neighbor;
			}
		}
	}

	return count;
}
