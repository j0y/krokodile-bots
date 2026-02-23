/**
 * insurgency_stocks.inc -- Insurgency 2014 constants and utility stocks
 *
 * Cherry-picked from jballou's insurgency.inc, ported to newdecls syntax.
 * No external dependencies (no smlib, no updater, no insurgency.sp plugin).
 */

#if defined _insurgency_stocks_included
#endinput
#endif
#define _insurgency_stocks_included

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define MAX_CONTROLPOINTS 64

// ---------------------------------------------------------------------------
// Team indices (Insurgency-specific)
// ---------------------------------------------------------------------------

enum
{
	TEAM_NONE       = 0,
	TEAM_SPECTATORS = 1,
	TEAM_SECURITY   = 2,
	TEAM_INSURGENTS = 3,
}

// ---------------------------------------------------------------------------
// Client validation
// ---------------------------------------------------------------------------

stock bool IsValidClient(int client)
{
	return (client > 0 && client <= MaxClients &&
		IsClientConnected(client) && IsClientInGame(client) &&
		!IsClientReplay(client) && !IsClientSourceTV(client));
}

// ---------------------------------------------------------------------------
// Team counting
// ---------------------------------------------------------------------------

stock int Team_CountPlayers(int team)
{
	int count = 0;
	for (int i = 1; i <= MaxClients; i++)
	{
		if (IsValidClient(i) && GetClientTeam(i) == team)
			count++;
	}
	return count;
}

stock int Team_CountAlivePlayers(int team)
{
	int count = 0;
	for (int i = 1; i <= MaxClients; i++)
	{
		if (IsValidClient(i) && GetClientTeam(i) == team && IsPlayerAlive(i))
			count++;
	}
	return count;
}

// ---------------------------------------------------------------------------
// Visibility: trace-ray line of sight
// ---------------------------------------------------------------------------

stock bool ClientCanSeeVector(int client, float targetPos[3], float distance = 0.0, float height = 50.0)
{
	float clientPos[3];
	GetEntPropVector(client, Prop_Send, "m_vecOrigin", clientPos);
	clientPos[2] += height;

	if (distance > 0.0 && GetVectorDistance(clientPos, targetPos) > distance)
		return false;

	Handle trace = TR_TraceRayFilterEx(clientPos, targetPos,
		MASK_SOLID_BRUSHONLY, RayType_EndPoint, TraceFilter_IgnorePlayers);

	bool hit = TR_DidHit(trace);
	delete trace;

	return !hit;
}

stock bool ClientCanSeeClient(int client, int target, float distance = 0.0, float height = 50.0)
{
	float targetPos[3];
	GetEntPropVector(target, Prop_Send, "m_vecOrigin", targetPos);
	targetPos[2] += height;
	return ClientCanSeeVector(client, targetPos, distance, height);
}

public bool TraceFilter_IgnorePlayers(int entity, int contentsMask)
{
	return (entity > MaxClients);
}

// ---------------------------------------------------------------------------
// FOV check: is a position within a client's view cone?
// ---------------------------------------------------------------------------

stock bool IsVectorInSightRange(int client, float targetPos[3], float angle = 90.0, float distance = 0.0)
{
	float clientPos[3], eyeAng[3], fwd[3], toTarget[3];

	GetClientAbsOrigin(client, clientPos);
	GetClientEyeAngles(client, eyeAng);

	// Flatten to 2D
	eyeAng[0] = 0.0;
	eyeAng[2] = 0.0;
	GetAngleVectors(eyeAng, fwd, NULL_VECTOR, NULL_VECTOR);
	NormalizeVector(fwd, fwd);

	float flatTarget[3], flatClient[3];
	flatTarget[0] = targetPos[0]; flatTarget[1] = targetPos[1]; flatTarget[2] = 0.0;
	flatClient[0] = clientPos[0]; flatClient[1] = clientPos[1]; flatClient[2] = 0.0;

	MakeVectorFromPoints(flatClient, flatTarget, toTarget);
	NormalizeVector(toTarget, toTarget);

	float dot = GetVectorDotProduct(fwd, toTarget);
	float resultAngle = RadToDeg(ArcCosine(dot));

	if (resultAngle > angle / 2.0)
		return false;

	if (distance > 0.0 && GetVectorDistance(clientPos, targetPos) > distance)
		return false;

	return true;
}

stock bool IsClientInSightRange(int client, int target, float angle = 90.0, float distance = 0.0)
{
	float targetPos[3];
	GetClientAbsOrigin(target, targetPos);
	return IsVectorInSightRange(client, targetPos, angle, distance);
}

// ---------------------------------------------------------------------------
// SendProp helper
// ---------------------------------------------------------------------------

stock int GetSendPropOffset(const char[] netClass, const char[] propName)
{
	int offset = FindSendPropInfo(netClass, propName);
	if (offset == -1)
		LogError("Can't find %s::%s", netClass, propName);
	return offset;
}
