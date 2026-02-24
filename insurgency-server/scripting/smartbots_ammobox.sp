/**
 * smartbots_ammobox.sp -- Player-droppable ammo boxes for Insurgency 2014
 *
 * Players type !ammobox (or /ammobox) to drop a weapon cache prop at their
 * feet.  Other players press USE on it to receive +1 spare magazine for
 * their primary and secondary weapons (capped at loadout max).
 *
 * Single-use: box disappears after one pickup.
 * Standalone plugin -- no dependencies on smartbots.sp or other custom plugins.
 *
 * Ammo system notes:
 *   Insurgency weapons use CINSWeaponMagazines -- a UTL vector of per-magazine
 *   round counts stored in a player-side CUtlMap at player+0x17d8, keyed by
 *   ammo type index.
 *
 *   CINSWeaponMagazines::UpdateCounter() syncs m_iAmmo = vector.count after
 *   every vector modification, so direct SetEntProp on m_iAmmo is overwritten
 *   by the next reload.  The fix: append directly to the UTL vector, then
 *   manually sync m_iAmmo.
 *
 *   CINSPlayer::GiveAmmo() only works for ammo types with ammoDef flag 0x4.
 *   ammoType=29 (the weapon's ammo type) does NOT have this flag, so GiveAmmo
 *   always returns 0.  Instead, we call CINSPlayer::GetMagazines(ammoType) to
 *   get the actual CINSWeaponMagazines* heap object, then append to its UTL
 *   vector directly.
 *
 * CINSWeaponMagazines heap object layout (32-bit):
 *   +0x00  vtable ptr
 *   +0x04  player entity handle
 *   +0x08  int* data ptr (array of per-magazine round counts)
 *   +0x0c  allocated capacity
 *   +0x10  grow size
 *   +0x14  element count (number of spare magazines)
 */

#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <sdktools>
#include <sdkhooks>
#include <insurgency_stocks>

public Plugin myinfo =
{
	name        = "SmartBots AmmoBox",
	author      = "krokodile",
	description = "Player-droppable ammo boxes for Insurgency 2014",
	version     = "1.7.0",
	url         = ""
};

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

static ConVar g_cvEnabled;
static ConVar g_cvCooldown;
static ConVar g_cvLifetime;

// ---------------------------------------------------------------------------
// Per-client cooldown tracking
// ---------------------------------------------------------------------------

static float g_lastDropTime[MAXPLAYERS + 1];

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#define AMMOBOX_MODEL "models/static_props/wcache_box_01.mdl"

// ---------------------------------------------------------------------------
// SDKCalls
// ---------------------------------------------------------------------------

static Handle g_sdkGetMagazines = null;  // CINSPlayer::GetMagazines(int) -> CINSWeaponMagazines*

// ---------------------------------------------------------------------------
// Platform-specific offsets loaded from gamedata
// ---------------------------------------------------------------------------

static int g_off_weapon_slotVal   = -1;  // CINSWeapon: slotVal (>= 0 = has mag system)
static int g_off_weapon_ammoType  = -1;  // CINSWeapon: GetPrimaryAmmoType result
static int g_off_weapon_magCap    = -1;  // CINSWeapon: rounds per magazine
static int g_off_mags_dataPtr     = -1;  // CINSWeaponMagazines: int* data array
static int g_off_mags_allocated   = -1;  // CINSWeaponMagazines: allocated capacity
static int g_off_mags_count       = -1;  // CINSWeaponMagazines: element count

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

public void OnPluginStart()
{
	g_cvEnabled  = CreateConVar("sm_ammobox_enabled",  "1",   "Enable ammo box dropping");
	g_cvCooldown = CreateConVar("sm_ammobox_cooldown", "60",  "Seconds between drops per player");
	g_cvLifetime = CreateConVar("sm_ammobox_lifetime", "120", "Seconds before unclaimed box despawns");

	RegConsoleCmd("sm_ammobox", Cmd_AmmoBox, "Drop an ammo box at your feet");
	RegAdminCmd("sm_ammobox_scan", Cmd_AmmoScan, ADMFLAG_ROOT, "Scan player memory for internal ammo counter");

	GameData gameConf = new GameData("smartbots_ammobox");
	if (gameConf == null)
	{
		PrintToServer("[AmmoBox] WARNING: failed to load gamedata/smartbots_ammobox.txt -- ammo giving disabled");
		PrintToServer("[AmmoBox] Plugin loaded (v1.7.0) -- DISABLED");
		return;
	}

	// SDKCall: CINSPlayer::GetMagazines
	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetFromConf(gameConf, SDKConf_Signature, "CINSPlayer::GetMagazines");
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);
	g_sdkGetMagazines = EndPrepSDKCall();

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
		{ PrintToServer("[AmmoBox] MISSING: CINSPlayer::GetMagazines signature"); ok = false; }
	if (g_off_weapon_slotVal  < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeapon.slotVal");          ok = false; }
	if (g_off_weapon_ammoType < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeapon.ammoType");         ok = false; }
	if (g_off_weapon_magCap   < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeapon.magCapacity");      ok = false; }
	if (g_off_mags_dataPtr    < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.dataPtr"); ok = false; }
	if (g_off_mags_allocated  < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.allocated"); ok = false; }
	if (g_off_mags_count      < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.count");   ok = false; }

	if (!ok)
	{
		PrintToServer("[AmmoBox] One or more offsets missing for this platform -- ammo giving disabled");
		PrintToServer("[AmmoBox] Plugin loaded (v1.7.0) -- DISABLED");
		return;
	}

	PrintToServer("[AmmoBox] Plugin loaded (v1.7.0) -- all offsets OK");
}

// ---------------------------------------------------------------------------
// Debug scan
// ---------------------------------------------------------------------------

public Action Cmd_AmmoScan(int client, int args)
{
	int target = (client == 0) ? 1 : client;

	int weapon = GetPlayerWeaponSlot(target, 0);
	if (weapon == -1)
	{
		ReplyToCommand(client, "[Scan] No primary weapon on player %d", target);
		return Plugin_Handled;
	}

	int ammoTypeDM   = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
	int slotVal      = GetEntData(weapon, 0x5a4);
	int ammoTypeVirt = GetEntData(weapon, 0x15c0);
	int roundsPerMag = GetEntData(weapon, 0x1600);

	ReplyToCommand(client, "[Scan] weapon=%d DataMap_ammoType=%d slotVal=%d virt_ammoType=%d roundsPerMag=%d",
		weapon, ammoTypeDM, slotVal, ammoTypeVirt, roundsPerMag);

	if (ammoTypeDM >= 0)
		ReplyToCommand(client, "[Scan] m_iAmmo[DM=%d]=%d",
			ammoTypeDM, GetEntProp(target, Prop_Data, "m_iAmmo", _, ammoTypeDM));

	if (g_sdkGetMagazines != null && ammoTypeDM >= 0)
	{
		int magsPtr = SDKCall(g_sdkGetMagazines, target, ammoTypeDM);
		ReplyToCommand(client, "[Scan] GetMagazines(%d) -> 0x%x", ammoTypeDM, magsPtr);
		if (magsPtr != 0)
		{
			int dataPtr   = LoadFromAddress(view_as<Address>(magsPtr + 0x08), NumberType_Int32);
			int allocated = LoadFromAddress(view_as<Address>(magsPtr + 0x0c), NumberType_Int32);
			int count     = LoadFromAddress(view_as<Address>(magsPtr + 0x14), NumberType_Int32);
			ReplyToCommand(client, "[Scan]   data=0x%x allocated=%d count=%d", dataPtr, allocated, count);
			for (int i = 0; i < count && i < 16; i++)
			{
				int rounds = LoadFromAddress(view_as<Address>(dataPtr + i * 4), NumberType_Int32);
				ReplyToCommand(client, "[Scan]   mag[%d] = %d rounds", i, rounds);
			}
		}
	}

	return Plugin_Handled;
}

public void OnMapStart()
{
	PrecacheModel(AMMOBOX_MODEL, true);
}

public void OnClientDisconnect(int client)
{
	g_lastDropTime[client] = 0.0;
}

// ---------------------------------------------------------------------------
// Command: !ammobox / /ammobox / sm_ammobox
// ---------------------------------------------------------------------------

public Action Cmd_AmmoBox(int client, int args)
{
	if (!g_cvEnabled.BoolValue)
	{
		ReplyToCommand(client, "[AmmoBox] Ammo boxes are disabled.");
		return Plugin_Handled;
	}

	if (!IsValidClient(client))
		return Plugin_Handled;

	if (!IsPlayerAlive(client))
	{
		PrintToChat(client, "[AmmoBox] You must be alive to drop an ammo box.");
		return Plugin_Handled;
	}

	// Cooldown check
	float now = GetGameTime();
	float cooldown = g_cvCooldown.FloatValue;
	float elapsed = now - g_lastDropTime[client];
	if (elapsed < cooldown)
	{
		int remaining = RoundToCeil(cooldown - elapsed);
		PrintToChat(client, "[AmmoBox] Cooldown: %d seconds remaining.", remaining);
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
		PrintToChat(client, "[AmmoBox] Failed to create ammo box.");
		return Plugin_Handled;
	}

	SetEntityModel(entity, AMMOBOX_MODEL);
	DispatchKeyValue(entity, "solid", "6");
	DispatchKeyValue(entity, "spawnflags", "256");
	DispatchSpawn(entity);
	TeleportEntity(entity, spawnPos, NULL_VECTOR, vel);

	SetEntityRenderColor(entity, 255, 200, 200, 255);

	SDKHook(entity, SDKHook_Use, OnAmmoBoxUse);

	float lifetime = g_cvLifetime.FloatValue;
	int ref = EntIndexToEntRef(entity);
	CreateTimer(lifetime, Timer_RemoveBox, ref, TIMER_FLAG_NO_MAPCHANGE);

	g_lastDropTime[client] = now;

	PrintToChat(client, "[AmmoBox] Ammo box dropped! Teammates can press USE to pick it up.");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Use callback: give +1 magazine to primary + secondary
// ---------------------------------------------------------------------------

public Action OnAmmoBoxUse(int entity, int activator, int caller, UseType type, float value)
{
	if (!IsValidClient(activator) || !IsPlayerAlive(activator))
		return Plugin_Continue;

	bool gaveSomething = false;

	for (int slot = 0; slot <= 1; slot++)
	{
		if (GiveMagazine(activator, slot))
			gaveSomething = true;
	}

	if (!gaveSomething)
	{
		PrintHintText(activator, "Ammo full.");
		return Plugin_Handled;
	}

	PrintHintText(activator, "Picked up ammo box (+1 magazine)");
	EmitSoundToClient(activator, "physics/metal/weapon_impact_hard1.wav");

	SDKUnhook(entity, SDKHook_Use, OnAmmoBoxUse);
	AcceptEntityInput(entity, "Kill");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Give one spare magazine for a weapon slot.
//
// Strategy:
//   1. Get ammoType from weapon+0x15c0 (= CINSWeapon::GetPrimaryAmmoType()).
//   2. Call CINSPlayer::GetMagazines(ammoType) to get the CINSWeaponMagazines*
//      heap object from the player's internal CUtlMap at player+0x17d8.
//   3. Directly append an entry to the UTL vector inside that object.
//   4. Sync m_iAmmo to the new count (mirrors what UpdateCounter does).
//
// CINSPlayer::GiveAmmo is NOT used here: it requires ammoDef flag 0x4 which
// ammoType=29 does not have, causing it to always return 0.
// ---------------------------------------------------------------------------

#define AMMO_HARD_CAP  8

static bool GiveMagazine(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	if (g_sdkGetMagazines == null || g_off_weapon_slotVal < 0)
		return false;  // offsets not loaded (unsupported platform)

	int slotVal  = GetEntData(weapon, g_off_weapon_slotVal);
	int ammoType = GetEntData(weapon, g_off_weapon_ammoType);

	if (slotVal < 0 || ammoType < 0)
	{
		// Non-magazine weapon; fall back to DataMap ammoType.
		ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
		if (ammoType < 0)
			return false;
	}

	// Get (or create) the CINSWeaponMagazines object for this ammoType.
	int magsPtr = SDKCall(g_sdkGetMagazines, client, ammoType);

	PrintToServer("[AmmoBox] GiveMagazine client=%d slot=%d slotVal=%d ammoType=%d magsPtr=0x%x",
		client, slot, slotVal, ammoType, magsPtr);

	if (magsPtr == 0)
	{
		PrintToServer("[AmmoBox] GetMagazines returned null, skipping");
		return false;
	}

	// Read the UTL vector fields from the heap object.
	int dataPtr   = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_dataPtr),   NumberType_Int32);
	int allocated = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_allocated), NumberType_Int32);
	int count     = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_count),     NumberType_Int32);

	PrintToServer("[AmmoBox]   dataPtr=0x%x allocated=%d count=%d",
		dataPtr, allocated, count);

	if (dataPtr == 0 || allocated <= 0 || count < 0 ||
	    count >= allocated || count >= AMMO_HARD_CAP)
	{
		PrintToServer("[AmmoBox] at cap or bad state (%d/%d data=0x%x), skip",
			count, allocated, dataPtr);
		return false;
	}

	int roundsPerMag = GetEntData(weapon, g_off_weapon_magCap);
	if (roundsPerMag < 1)
		roundsPerMag = 30;

	// Append: data[count] = roundsPerMag, count++
	StoreToAddress(view_as<Address>(dataPtr + count * 4),          roundsPerMag, NumberType_Int32);
	StoreToAddress(view_as<Address>(magsPtr + g_off_mags_count),  count + 1,    NumberType_Int32);

	// Sync m_iAmmo to the new vector size (mirrors UpdateCounter).
	SetEntProp(client, Prop_Data, "m_iAmmo", count + 1, _, ammoType);
	SetEntProp(client, Prop_Send, "m_iAmmo", count + 1, _, ammoType);

	PrintToServer("[AmmoBox] added mag[%d]=%d rounds, m_iAmmo[%d]->%d",
		count, roundsPerMag, ammoType, count + 1);
	return true;
}

// ---------------------------------------------------------------------------
// Auto-despawn timer
// ---------------------------------------------------------------------------

public Action Timer_RemoveBox(Handle timer, int entRef)
{
	int entity = EntRefToEntIndex(entRef);
	if (entity != INVALID_ENT_REFERENCE && IsValidEntity(entity))
	{
		SDKUnhook(entity, SDKHook_Use, OnAmmoBoxUse);
		AcceptEntityInput(entity, "Kill");
	}
	return Plugin_Stop;
}
