/**
 * smartbots_ammobox.sp -- Player-droppable ammo boxes for Insurgency 2014
 *
 * Players type !ammobox (or /ammobox) to drop a weapon cache prop at their
 * feet.  Other players press USE on it to receive ammo for their primary
 * and secondary weapons (capped at loadout max).
 *
 * Single-use: box disappears after one pickup.
 * Standalone plugin -- no dependencies on smartbots.sp or other custom plugins.
 *
 * Ammo system notes:
 *   Insurgency has TWO ammo tracking systems, selected per-weapon by the
 *   ammoDef flag 0x4 (checked at ammoDefEntry+0x94):
 *
 *   MAGAZINE weapons (flag 0x4 SET -- rifles, SMGs, pistols, bolt-action):
 *     CINSWeaponMagazines -- a UTL vector of per-magazine round counts
 *     stored in a player-side CUtlMap at player+0x17d8, keyed by ammo type.
 *     m_iAmmo[ammoType] = number of spare MAGAZINES (synced by UpdateCounter).
 *     Reload swaps the whole magazine via SwitchToBest().
 *
 *   NON-MAGAZINE weapons (flag 0x4 NOT SET -- shotguns):
 *     Simple integer in m_iAmmo[ammoType] = number of spare SHELLS/ROUNDS.
 *     Reload loads shells one at a time via ReloadCycle -> TakeAmmo.
 *     CINSWeaponMagazines is NEVER used by the engine for these weapons.
 *
 *   WARNING: CINSPlayer::GetMagazines(ammoType) creates a new
 *   CINSWeaponMagazines entry if one doesn't exist.  The constructor calls
 *   UpdateCounter() which RESETS m_iAmmo to 0 -- destroying the player's
 *   spare shell count for non-magazine weapons.  NEVER call GetMagazines
 *   for non-magazine weapons.
 *
 *   Detection: weapon field magCapacity (weapon+0x1600 Linux) stores the
 *   detachable magazine size.  If > 0, the weapon uses magazines.
 *   nonMagCapacity (weapon+0x15f8 Linux) stores the tube/internal capacity.
 *   If magCapacity <= 0 and nonMagCapacity > 0, use simple m_iAmmo shells.
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
	version     = "1.8.0",
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

static Handle g_sdkGetMagazines = null;     // CINSPlayer::GetMagazines(int) -> CINSWeaponMagazines*
static Handle g_sdkGetMagCapacity = null;   // CINSWeapon::GetMagazineCapacity() -> int

// ---------------------------------------------------------------------------
// Platform-specific offsets loaded from gamedata
// ---------------------------------------------------------------------------

static int g_off_weapon_slotVal      = -1;  // CINSWeapon: slotVal (>= 0 = valid INS ammo type)
static int g_off_weapon_ammoType     = -1;  // CINSWeapon: GetPrimaryAmmoType result
static int g_off_weapon_magCap       = -1;  // CINSWeapon: rounds per magazine (magazine path)
static int g_off_weapon_nonMagCap    = -1;  // CINSWeapon: rounds capacity (non-magazine path)
static int g_off_mags_dataPtr        = -1;  // CINSWeaponMagazines: int* data array
static int g_off_mags_allocated      = -1;  // CINSWeaponMagazines: allocated capacity
static int g_off_mags_count          = -1;  // CINSWeaponMagazines: element count

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
		PrintToServer("[AmmoBox] Plugin loaded (v1.8.0) -- DISABLED");
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
	if (g_sdkGetMagCapacity == null)
		PrintToServer("[AmmoBox] NOTE: CINSWeapon::GetMagazineCapacity sig not found (debug scan limited)");

	// Platform-specific offsets
	g_off_weapon_slotVal   = gameConf.GetOffset("CINSWeapon.slotVal");
	g_off_weapon_ammoType  = gameConf.GetOffset("CINSWeapon.ammoType");
	g_off_weapon_magCap    = gameConf.GetOffset("CINSWeapon.magCapacity");
	g_off_weapon_nonMagCap = gameConf.GetOffset("CINSWeapon.nonMagCapacity");
	g_off_mags_dataPtr     = gameConf.GetOffset("CINSWeaponMagazines.dataPtr");
	g_off_mags_allocated   = gameConf.GetOffset("CINSWeaponMagazines.allocated");
	g_off_mags_count       = gameConf.GetOffset("CINSWeaponMagazines.count");

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
	if (g_off_weapon_nonMagCap < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeapon.nonMagCapacity");   ok = false; }
	if (g_off_mags_dataPtr    < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.dataPtr"); ok = false; }
	if (g_off_mags_allocated  < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.allocated"); ok = false; }
	if (g_off_mags_count      < 0)
		{ PrintToServer("[AmmoBox] MISSING offset: CINSWeaponMagazines.count");   ok = false; }

	if (!ok)
	{
		PrintToServer("[AmmoBox] One or more offsets missing for this platform -- ammo giving disabled");
		PrintToServer("[AmmoBox] Plugin loaded (v1.8.0) -- DISABLED");
		return;
	}

	PrintToServer("[AmmoBox] Plugin loaded (v1.8.0) -- all offsets OK");
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
	int slotVal      = (g_off_weapon_slotVal   >= 0) ? GetEntData(weapon, g_off_weapon_slotVal)   : -1;
	int ammoTypeVirt = (g_off_weapon_ammoType  >= 0) ? GetEntData(weapon, g_off_weapon_ammoType)  : -1;
	int rawMagCap    = (g_off_weapon_magCap    >= 0) ? GetEntData(weapon, g_off_weapon_magCap)    : -1;
	int rawNonMagCap = (g_off_weapon_nonMagCap >= 0) ? GetEntData(weapon, g_off_weapon_nonMagCap) : -1;

	ReplyToCommand(client, "[Scan] weapon=%d DataMap_ammoType=%d slotVal=%d virt_ammoType=%d",
		weapon, ammoTypeDM, slotVal, ammoTypeVirt);
	ReplyToCommand(client, "[Scan] magCapacity(raw)=%d nonMagCapacity(raw)=%d type=%s",
		rawMagCap, rawNonMagCap,
		(rawMagCap > 0) ? "MAGAZINE" : ((rawNonMagCap > 0) ? "NON-MAG(shells)" : "UNKNOWN"));

	// Compare field read vs engine's GetMagazineCapacity (accounts for attachments)
	if (g_sdkGetMagCapacity != null)
	{
		int engineCap = SDKCall(g_sdkGetMagCapacity, weapon);
		ReplyToCommand(client, "[Scan] GetMagazineCapacity(engine)=%d", engineCap);
	}
	else
	{
		ReplyToCommand(client, "[Scan] GetMagazineCapacity unavailable (no sig for this platform)");
	}

	if (ammoTypeDM >= 0)
		ReplyToCommand(client, "[Scan] m_iAmmo[DM=%d]=%d",
			ammoTypeDM, GetEntProp(target, Prop_Data, "m_iAmmo", _, ammoTypeDM));

	if (g_sdkGetMagazines != null && ammoTypeDM >= 0 && g_off_mags_dataPtr >= 0
		&& rawMagCap > 0)  // Only call GetMagazines for magazine weapons!
	{
		int magsPtr = SDKCall(g_sdkGetMagazines, target, ammoTypeDM);
		ReplyToCommand(client, "[Scan] GetMagazines(%d) -> 0x%x", ammoTypeDM, magsPtr);
		if (magsPtr != 0)
		{
			int dataPtr   = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_dataPtr),   NumberType_Int32);
			int allocated = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_allocated), NumberType_Int32);
			int count     = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_count),     NumberType_Int32);
			ReplyToCommand(client, "[Scan]   data=0x%x allocated=%d count=%d", dataPtr, allocated, count);
			for (int i = 0; i < count && i < 16; i++)
			{
				int rounds = LoadFromAddress(view_as<Address>(dataPtr + i * 4), NumberType_Int32);
				ReplyToCommand(client, "[Scan]   mag[%d] = %d rounds", i, rounds);
			}
		}
	}
	else if (rawMagCap <= 0 && ammoTypeDM >= 0)
	{
		ReplyToCommand(client, "[Scan] Non-magazine weapon -- skipping GetMagazines (would destroy m_iAmmo)");
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
// Use callback: give ammo to primary + secondary
// ---------------------------------------------------------------------------

public Action OnAmmoBoxUse(int entity, int activator, int caller, UseType type, float value)
{
	if (!IsValidClient(activator) || !IsPlayerAlive(activator))
		return Plugin_Continue;

	bool gaveSomething = false;

	for (int slot = 0; slot <= 1; slot++)
	{
		if (GiveAmmoForSlot(activator, slot))
			gaveSomething = true;
	}

	if (!gaveSomething)
	{
		PrintHintText(activator, "Ammo full.");
		return Plugin_Handled;
	}

	PrintHintText(activator, "Picked up ammo box (+ammo)");
	EmitSoundToClient(activator, "physics/metal/weapon_impact_hard1.wav");

	SDKUnhook(entity, SDKHook_Use, OnAmmoBoxUse);
	AcceptEntityInput(entity, "Kill");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Give ammo for a weapon slot.  Detects whether the weapon uses the magazine
// system (rifles, bolt-action) or simple shell counts (shotguns) and handles
// each path appropriately.
//
// Detection: read the raw magCapacity field (magazine path) and
// nonMagCapacity field (non-magazine path).  If magCapacity > 0, the weapon
// uses detachable magazines and the CINSWeaponMagazines vector.
// Otherwise nonMagCapacity > 0 means simple m_iAmmo shell counts.
// ---------------------------------------------------------------------------

#define MAG_HARD_CAP    8    // max spare magazines for magazine weapons
#define SHELL_HARD_CAP  48   // max spare shells for non-magazine weapons

static bool GiveAmmoForSlot(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	if (g_off_weapon_slotVal < 0)
		return false;  // offsets not loaded (unsupported platform)

	int slotVal  = GetEntData(weapon, g_off_weapon_slotVal);
	int ammoType = GetEntData(weapon, g_off_weapon_ammoType);

	if (slotVal < 0 || ammoType < 0)
	{
		ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
		if (ammoType < 0)
			return false;
	}

	// Detect weapon type: magazine vs non-magazine
	int rawMagCap    = GetEntData(weapon, g_off_weapon_magCap);
	int rawNonMagCap = GetEntData(weapon, g_off_weapon_nonMagCap);

	if (rawMagCap > 0)
	{
		// Magazine weapon (rifles, SMGs, pistols, bolt-action with clips).
		// Use CINSWeaponMagazines vector approach.
		return GiveMagazine(client, weapon, slot, ammoType, rawMagCap);
	}
	else if (rawNonMagCap > 0)
	{
		// Non-magazine weapon (shotguns, etc.).
		// Add shells directly to m_iAmmo.
		return GiveShells(client, weapon, slot, ammoType, rawNonMagCap);
	}
	else
	{
		// Both capacity fields are 0.  Try SDK call for capacity and
		// assume magazine weapon (handles ammoDef fallback cases).
		int capacity = -1;
		if (g_sdkGetMagCapacity != null)
			capacity = SDKCall(g_sdkGetMagCapacity, weapon);
		if (capacity < 1)
			return false;

		return GiveMagazine(client, weapon, slot, ammoType, capacity);
	}
}

// ---------------------------------------------------------------------------
// Give +1 spare magazine for a magazine-based weapon.
//
// Appends an entry to the CINSWeaponMagazines UTL vector, then syncs
// m_iAmmo to the new count (mirrors UpdateCounter).
// ---------------------------------------------------------------------------

static bool GiveMagazine(int client, int weapon, int slot, int ammoType, int rawMagCap)
{
	if (g_sdkGetMagazines == null)
		return false;

	int magsPtr = SDKCall(g_sdkGetMagazines, client, ammoType);

	PrintToServer("[AmmoBox] GiveMagazine client=%d slot=%d ammoType=%d magsPtr=0x%x",
		client, slot, ammoType, magsPtr);

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
	    count >= allocated || count >= MAG_HARD_CAP)
	{
		PrintToServer("[AmmoBox] at cap or bad state (%d/%d data=0x%x), skip",
			count, allocated, dataPtr);
		return false;
	}

	// Determine rounds per magazine.  Prefer SDK call (accounts for
	// attachments like extended mags), fall back to raw field.
	int roundsPerMag = -1;
	if (g_sdkGetMagCapacity != null)
		roundsPerMag = SDKCall(g_sdkGetMagCapacity, weapon);
	if (roundsPerMag < 1)
		roundsPerMag = rawMagCap;
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
// Give spare shells for a non-magazine weapon (shotgun, etc.).
//
// For non-magazine weapons, m_iAmmo[ammoType] is the number of spare
// SHELLS (not magazines).  The engine's ReloadCycle loads shells one at
// a time from this count into the clip.  We simply increment m_iAmmo.
//
// IMPORTANT: Do NOT call GetMagazines for these weapons -- doing so
// creates a CINSWeaponMagazines entry whose constructor resets m_iAmmo
// to 0, destroying the player's existing shell reserves.
// ---------------------------------------------------------------------------

static bool GiveShells(int client, int weapon, int slot, int ammoType, int tubeCapacity)
{
	int currentAmmo = GetEntProp(client, Prop_Data, "m_iAmmo", _, ammoType);

	if (currentAmmo >= SHELL_HARD_CAP)
	{
		PrintToServer("[AmmoBox] GiveShells client=%d slot=%d shells at cap (%d/%d), skip",
			client, slot, currentAmmo, SHELL_HARD_CAP);
		return false;
	}

	// Give one "tube load" worth of shells (e.g. 6 for a 6-shell shotgun).
	// This is equivalent to giving +1 magazine for magazine weapons.
	int shellsToGive = tubeCapacity;
	if (shellsToGive < 1)
		shellsToGive = 8;  // fallback

	if (currentAmmo + shellsToGive > SHELL_HARD_CAP)
		shellsToGive = SHELL_HARD_CAP - currentAmmo;

	if (shellsToGive <= 0)
		return false;

	int newAmmo = currentAmmo + shellsToGive;
	SetEntProp(client, Prop_Data, "m_iAmmo", newAmmo, _, ammoType);
	SetEntProp(client, Prop_Send, "m_iAmmo", newAmmo, _, ammoType);

	PrintToServer("[AmmoBox] GiveShells client=%d slot=%d +%d shells, m_iAmmo[%d]: %d->%d",
		client, slot, shellsToGive, ammoType, currentAmmo, newAmmo);
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
