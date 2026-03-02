/**
 * smartbots_resupply.sp -- Battlefield-style resupply boxes for Insurgency 2014
 *
 * Players type !resupply (or /resupply) to throw a resupply crate forward.
 * The crate periodically gives +1 spare magazine (primary + secondary) to all
 * nearby teammates within a configurable radius.  After its lifetime expires
 * the crate despawns.
 *
 * Unlike the single-use ammobox, this crate stays active and keeps resupplying
 * on a timer -- just like the Battlefield support class ammo box.
 *
 * Standalone plugin -- shares the same gamedata file (smartbots_ammobox.txt)
 * for CINSWeaponMagazines access but has no code dependency on smartbots.sp.
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>
#include <sdkhooks>
#include <insurgency_stocks>

public Plugin myinfo =
{
	name        = "SmartBots Resupply",
	author      = "krokodile",
	description = "Battlefield-style area resupply boxes for Insurgency 2014",
	version     = "1.0.0",
	url         = ""
};

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

static ConVar g_cvEnabled;
static ConVar g_cvCooldown;
static ConVar g_cvLifetime;
static ConVar g_cvRadius;
static ConVar g_cvInterval;
static ConVar g_cvTeamOnly;

// ---------------------------------------------------------------------------
// Per-client cooldown tracking
// ---------------------------------------------------------------------------

static float g_lastDropTime[MAXPLAYERS + 1];

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#define RESUPPLY_MODEL "models/static_props/wcache_box_01.mdl"

// ---------------------------------------------------------------------------
// SDKCalls (loaded from smartbots_ammobox.txt gamedata)
// ---------------------------------------------------------------------------

static Handle g_sdkGetMagazines  = null;   // CINSPlayer::GetMagazines(int) -> CINSWeaponMagazines*
static Handle g_sdkGetMagCapacity = null;  // CINSWeapon::GetMagazineCapacity() -> int

// ---------------------------------------------------------------------------
// Platform-specific offsets loaded from gamedata
// ---------------------------------------------------------------------------

static int g_off_weapon_slotVal   = -1;
static int g_off_weapon_ammoType  = -1;
static int g_off_weapon_magCap    = -1;
static int g_off_mags_dataPtr     = -1;
static int g_off_mags_allocated   = -1;
static int g_off_mags_count       = -1;

// ---------------------------------------------------------------------------
// Active resupply box tracking
// ---------------------------------------------------------------------------

static int    g_boxOwnerTeam[2048];     // team of the player who dropped each box
static Handle g_boxRepeatTimer[2048];   // repeating resupply timer per entity

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

public void OnPluginStart()
{
	g_cvEnabled  = CreateConVar("sm_resupply_enabled",   "1",    "Enable resupply box dropping");
	g_cvCooldown = CreateConVar("sm_resupply_cooldown",  "60",   "Seconds between drops per player");
	g_cvLifetime = CreateConVar("sm_resupply_lifetime",  "120",  "Seconds before resupply box despawns");
	g_cvRadius   = CreateConVar("sm_resupply_radius",    "256",  "Radius in units for resupply effect");
	g_cvInterval = CreateConVar("sm_resupply_interval",  "15",   "Seconds between each resupply tick");
	g_cvTeamOnly = CreateConVar("sm_resupply_teamonly",  "1",    "Only resupply teammates of the dropper");

	RegConsoleCmd("sm_resupply", Cmd_Resupply, "Throw a resupply box");

	GameData gameConf = new GameData("smartbots_ammobox");
	if (gameConf == null)
	{
		PrintToServer("[Resupply] WARNING: failed to load gamedata/smartbots_ammobox.txt -- ammo giving disabled");
		PrintToServer("[Resupply] Plugin loaded (v1.0.0) -- DISABLED");
		return;
	}

	// SDKCall: CINSPlayer::GetMagazines
	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetFromConf(gameConf, SDKConf_Signature, "CINSPlayer::GetMagazines");
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
	g_sdkGetMagazines = EndPrepSDKCall();

	// SDKCall: CINSWeapon::GetMagazineCapacity
	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetFromConf(gameConf, SDKConf_Signature, "CINSWeapon::GetMagazineCapacity");
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_sdkGetMagCapacity = EndPrepSDKCall();

	// Platform-specific offsets
	g_off_weapon_slotVal  = gameConf.GetOffset("CINSWeapon.slotVal");
	g_off_weapon_ammoType = gameConf.GetOffset("CINSWeapon.ammoType");
	g_off_weapon_magCap   = gameConf.GetOffset("CINSWeapon.magCapacity");
	g_off_mags_dataPtr    = gameConf.GetOffset("CINSWeaponMagazines.dataPtr");
	g_off_mags_allocated  = gameConf.GetOffset("CINSWeaponMagazines.allocated");
	g_off_mags_count      = gameConf.GetOffset("CINSWeaponMagazines.count");

	delete gameConf;

	bool ok = true;
	if (g_sdkGetMagazines == null)
		{ PrintToServer("[Resupply] MISSING: CINSPlayer::GetMagazines signature"); ok = false; }
	if (g_off_weapon_slotVal  < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeapon.slotVal");          ok = false; }
	if (g_off_weapon_ammoType < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeapon.ammoType");         ok = false; }
	if (g_off_weapon_magCap   < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeapon.magCapacity");      ok = false; }
	if (g_off_mags_dataPtr    < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.dataPtr"); ok = false; }
	if (g_off_mags_allocated  < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.allocated"); ok = false; }
	if (g_off_mags_count      < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.count");   ok = false; }

	if (!ok)
	{
		PrintToServer("[Resupply] One or more offsets missing -- ammo giving disabled");
		PrintToServer("[Resupply] Plugin loaded (v1.0.0) -- DISABLED");
		return;
	}

	PrintToServer("[Resupply] Plugin loaded (v1.0.0) -- all offsets OK");
}

public void OnMapStart()
{
	PrecacheModel(RESUPPLY_MODEL, true);
}

public void OnClientDisconnect(int client)
{
	g_lastDropTime[client] = 0.0;
}

// ---------------------------------------------------------------------------
// Command: !resupply / /resupply / sm_resupply
// ---------------------------------------------------------------------------

public Action Cmd_Resupply(int client, int args)
{
	if (!g_cvEnabled.BoolValue)
	{
		ReplyToCommand(client, "[Resupply] Resupply boxes are disabled.");
		return Plugin_Handled;
	}

	if (!IsValidClient(client))
		return Plugin_Handled;

	if (!IsPlayerAlive(client))
	{
		PrintToChat(client, "[Resupply] You must be alive to drop a resupply box.");
		return Plugin_Handled;
	}

	// Cooldown check
	float now = GetGameTime();
	float cooldown = g_cvCooldown.FloatValue;
	float elapsed = now - g_lastDropTime[client];
	if (elapsed < cooldown)
	{
		int remaining = RoundToCeil(cooldown - elapsed);
		PrintToChat(client, "[Resupply] Cooldown: %d seconds remaining.", remaining);
		return Plugin_Handled;
	}

	// Spawn at eye position, toss forward
	float eyePos[3], eyeAng[3], fwd[3], vel[3];
	GetClientEyePosition(client, eyePos);
	GetClientEyeAngles(client, eyeAng);
	GetAngleVectors(eyeAng, fwd, NULL_VECTOR, NULL_VECTOR);

	float spawnPos[3];
	spawnPos[0] = eyePos[0] + fwd[0] * 30.0;
	spawnPos[1] = eyePos[1] + fwd[1] * 30.0;
	spawnPos[2] = eyePos[2] + fwd[2] * 30.0;

	vel[0] = fwd[0] * 250.0;
	vel[1] = fwd[1] * 250.0;
	vel[2] = fwd[2] * 250.0 + 100.0;

	int entity = CreateEntityByName("prop_physics_override");
	if (entity == -1)
	{
		PrintToChat(client, "[Resupply] Failed to create resupply box.");
		return Plugin_Handled;
	}

	SetEntityModel(entity, RESUPPLY_MODEL);
	DispatchKeyValue(entity, "solid", "6");
	DispatchKeyValue(entity, "spawnflags", "256");
	DispatchSpawn(entity);
	TeleportEntity(entity, spawnPos, NULL_VECTOR, vel);

	// Blue tint to distinguish from single-use ammo boxes
	SetEntityRenderColor(entity, 150, 200, 255, 255);

	// Track owner team for team-only resupply
	g_boxOwnerTeam[entity] = GetClientTeam(client);

	// Start repeating resupply timer
	int ref = EntIndexToEntRef(entity);
	float interval = g_cvInterval.FloatValue;
	g_boxRepeatTimer[entity] = CreateTimer(interval, Timer_ResupplyTick, ref,
		TIMER_REPEAT | TIMER_FLAG_NO_MAPCHANGE);

	// Despawn timer
	float lifetime = g_cvLifetime.FloatValue;
	CreateTimer(lifetime, Timer_DespawnBox, ref, TIMER_FLAG_NO_MAPCHANGE);

	g_lastDropTime[client] = now;

	PrintToChat(client, "[Resupply] Resupply box deployed! Nearby teammates will receive ammo periodically.");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Repeating timer: resupply all nearby players
// ---------------------------------------------------------------------------

public Action Timer_ResupplyTick(Handle timer, int entRef)
{
	int entity = EntRefToEntIndex(entRef);
	if (entity == INVALID_ENT_REFERENCE || !IsValidEntity(entity))
	{
		// Entity gone, stop repeating
		g_boxRepeatTimer[entity] = null;
		return Plugin_Stop;
	}

	float boxPos[3];
	GetEntPropVector(entity, Prop_Data, "m_vecOrigin", boxPos);

	float radius = g_cvRadius.FloatValue;
	float radiusSq = radius * radius;
	bool teamOnly = g_cvTeamOnly.BoolValue;
	int boxTeam = g_boxOwnerTeam[entity];

	for (int i = 1; i <= MaxClients; i++)
	{
		if (!IsClientInGame(i) || !IsPlayerAlive(i))
			continue;

		if (teamOnly && GetClientTeam(i) != boxTeam)
			continue;

		float playerPos[3];
		GetClientAbsOrigin(i, playerPos);

		float distSq = GetVectorDistanceSq(boxPos, playerPos);
		if (distSq > radiusSq)
			continue;

		bool gaveSomething = false;
		for (int slot = 0; slot <= 1; slot++)
		{
			if (GiveMagazine(i, slot))
				gaveSomething = true;
		}

		if (gaveSomething)
			PrintHintText(i, "Resupplied (+1 magazine)");
	}

	return Plugin_Continue;
}

// ---------------------------------------------------------------------------
// Despawn timer
// ---------------------------------------------------------------------------

public Action Timer_DespawnBox(Handle timer, int entRef)
{
	int entity = EntRefToEntIndex(entRef);
	if (entity != INVALID_ENT_REFERENCE && IsValidEntity(entity))
	{
		// Kill the repeat timer if still running
		if (g_boxRepeatTimer[entity] != null)
		{
			KillTimer(g_boxRepeatTimer[entity]);
			g_boxRepeatTimer[entity] = null;
		}
		AcceptEntityInput(entity, "Kill");
	}
	return Plugin_Stop;
}

// ---------------------------------------------------------------------------
// Squared distance helper
// ---------------------------------------------------------------------------

static float GetVectorDistanceSq(const float a[3], const float b[3])
{
	float dx = a[0] - b[0];
	float dy = a[1] - b[1];
	float dz = a[2] - b[2];
	return dx * dx + dy * dy + dz * dz;
}

// ---------------------------------------------------------------------------
// Give one spare magazine for a weapon slot.
// (Same logic as smartbots_ammobox.sp -- duplicated for standalone operation)
// ---------------------------------------------------------------------------

#define AMMO_HARD_CAP  8

static bool GiveMagazine(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	if (g_sdkGetMagazines == null || g_off_weapon_slotVal < 0)
		return false;

	int slotVal  = GetEntData(weapon, g_off_weapon_slotVal);
	int ammoType = GetEntData(weapon, g_off_weapon_ammoType);

	if (slotVal < 0 || ammoType < 0)
	{
		ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
		if (ammoType < 0)
			return false;
	}

	int magsPtr = SDKCall(g_sdkGetMagazines, client, ammoType);
	if (magsPtr == 0)
		return false;

	int dataPtr   = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_dataPtr),   NumberType_Int32);
	int allocated = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_allocated), NumberType_Int32);
	int count     = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_count),     NumberType_Int32);

	if (dataPtr == 0 || allocated <= 0 || count < 0 ||
	    count >= allocated || count >= AMMO_HARD_CAP)
	{
		return false;
	}

	int roundsPerMag = -1;
	if (g_sdkGetMagCapacity != null)
		roundsPerMag = SDKCall(g_sdkGetMagCapacity, weapon);
	if (roundsPerMag < 1)
		roundsPerMag = GetEntData(weapon, g_off_weapon_magCap);
	if (roundsPerMag < 1)
		roundsPerMag = 30;

	// Append: data[count] = roundsPerMag, count++
	StoreToAddress(view_as<Address>(dataPtr + count * 4),         roundsPerMag, NumberType_Int32);
	StoreToAddress(view_as<Address>(magsPtr + g_off_mags_count), count + 1,    NumberType_Int32);

	// Sync m_iAmmo to the new vector size
	SetEntProp(client, Prop_Data, "m_iAmmo", count + 1, _, ammoType);
	SetEntProp(client, Prop_Send, "m_iAmmo", count + 1, _, ammoType);

	return true;
}
