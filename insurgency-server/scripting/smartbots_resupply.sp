/**
 * smartbots_resupply.sp -- Battlefield-style resupply boxes for Insurgency 2014
 *
 * Players type !resupply (or /resupply) to throw a resupply crate forward.
 * The crate periodically gives ammo (primary + secondary) to all nearby
 * teammates within a configurable radius.  After its lifetime expires the
 * crate despawns.
 *
 * Unlike the single-use ammobox, this crate stays active and keeps resupplying
 * on a timer -- just like the Battlefield support class ammo box.
 *
 * Standalone plugin -- shares the same gamedata file (smartbots_ammobox.txt)
 * for CINSWeaponMagazines access but has no code dependency on smartbots.sp.
 *
 * Handles both ammo systems:
 *   MAGAZINE weapons (ammoDef flag 0x4): +1 magazine via CINSWeaponMagazines
 *   NON-MAGAZINE weapons (shotguns):     +shells via direct m_iAmmo increment
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
	version     = "1.2.0",
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

static Handle g_sdkGetAmmoDef    = null;   // GetAmmoDef() -> CAmmoDef*
static Handle g_sdkGetMagazines  = null;   // CINSPlayer::GetMagazines(int) -> CINSWeaponMagazines*
static Handle g_sdkGetMagCapacity = null;  // CINSWeapon::GetMagazineCapacity() -> int

// ---------------------------------------------------------------------------
// Platform-specific offsets loaded from gamedata
// ---------------------------------------------------------------------------

static int g_off_weapon_slotVal      = -1;  // CINSWeapon: slotVal (>= 0 = valid INS ammo type)
static int g_off_weapon_nonMagCap    = -1;  // CINSWeapon: rounds capacity (non-magazine path)
static int g_off_mags_dataPtr        = -1;  // CINSWeaponMagazines: int* data array
static int g_off_mags_allocated      = -1;  // CINSWeaponMagazines: allocated capacity
static int g_off_mags_count          = -1;  // CINSWeaponMagazines: element count

// ---------------------------------------------------------------------------
// Ammo type flags loaded from CAmmoDef at map start.
//
// g_ammoIsMag[ammoType] == true  -> magazine weapon (CINSWeaponMagazines system)
// g_ammoIsMag[ammoType] == false -> shell-count weapon (simple m_iAmmo)
//
// Populated by reading Ammo_t::flags & 0x4 for each registered ammo type.
// This is exactly the same flag GetMagazineCapacity() branches on internally.
//
// CAmmoDef layout (both Linux and Windows, 32-bit):
//   +0x04  int count          (number of registered ammo types)
//   +0x08  Ammo_t[0]          (array, stride 0xbc per entry)
//   Ammo_t entry:
//     +0x94  int flags        (bit 0x4 = magazine weapon)
// ---------------------------------------------------------------------------

#define AMMO_FLAGS_OFFSET  0x94
#define AMMO_ENTRY_STRIDE  0xbc
#define AMMO_ARRAY_OFFSET  0x08
#define AMMO_COUNT_OFFSET  0x04
#define AMMO_FLAG_MAGAZINE 0x4
#define MAX_AMMO_TYPES     512

static bool g_ammoIsMag[MAX_AMMO_TYPES];
static bool g_ammoFlagsLoaded = false;

// Fallback-only: per-type detection cache used when GetAmmoDef is unavailable.
static bool g_ammoKnown[MAX_AMMO_TYPES];

// Address of CINSWeapon::GetMagazineCapacity -- used on Windows to navigate
// to GetAmmoDef (which has no stable byte signature due to ASLR relocation).
static Address g_getMagCapAddr = Address_Null;

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

	GameData gameConf = new GameData("smartbots_ammobox");
	if (gameConf == null)
	{
		PrintToServer("[Resupply] WARNING: failed to load gamedata/smartbots_ammobox.txt -- ammo giving disabled");
		PrintToServer("[Resupply] Plugin loaded (v1.1.0) -- DISABLED");
		return;
	}

	// SDKCall: GetAmmoDef() -> CAmmoDef*
	StartPrepSDKCall(SDKCall_Static);
	PrepSDKCall_SetFromConf(gameConf, SDKConf_Signature, "GetAmmoDef");
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_sdkGetAmmoDef = EndPrepSDKCall();
	if (g_sdkGetAmmoDef == null)
		PrintToServer("[Resupply] NOTE: GetAmmoDef sig not found -- ammo type detection will use fallback");

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

	// Save raw address of GetMagazineCapacity for Windows g_AmmoDef navigation.
	// On Windows, GetAmmoDef contains an absolute VA (patched by loader under ASLR)
	// so its bytes can't be used as a stable signature.  Instead we navigate from
	// GetMagazineCapacity (whose signature is stable) at a fixed relative offset.
	g_getMagCapAddr = gameConf.GetMemSig("CINSWeapon::GetMagazineCapacity");

	// Platform-specific offsets
	g_off_weapon_slotVal   = gameConf.GetOffset("CINSWeapon.slotVal");
	g_off_weapon_nonMagCap = gameConf.GetOffset("CINSWeapon.nonMagCapacity");
	g_off_mags_dataPtr     = gameConf.GetOffset("CINSWeaponMagazines.dataPtr");
	g_off_mags_allocated   = gameConf.GetOffset("CINSWeaponMagazines.allocated");
	g_off_mags_count       = gameConf.GetOffset("CINSWeaponMagazines.count");

	delete gameConf;

	bool ok = true;
	if (g_sdkGetMagazines == null)
		{ PrintToServer("[Resupply] MISSING: CINSPlayer::GetMagazines signature"); ok = false; }
	if (g_off_weapon_slotVal  < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeapon.slotVal");          ok = false; }
	if (g_off_weapon_nonMagCap < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeapon.nonMagCapacity");   ok = false; }
	if (g_off_mags_dataPtr    < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.dataPtr"); ok = false; }
	if (g_off_mags_allocated  < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.allocated"); ok = false; }
	if (g_off_mags_count      < 0)
		{ PrintToServer("[Resupply] MISSING offset: CINSWeaponMagazines.count");   ok = false; }

	if (!ok)
	{
		PrintToServer("[Resupply] One or more offsets missing -- ammo giving disabled");
		PrintToServer("[Resupply] Plugin loaded (v1.2.0) -- DISABLED");
		return;
	}

	RegConsoleCmd("sm_resupply", Cmd_Resupply, "Throw a resupply box");
	PrintToServer("[Resupply] Plugin loaded (v1.2.0) -- all offsets OK");
}

// ---------------------------------------------------------------------------
// Read ammoDef flag 0x4 for every registered ammo type into g_ammoIsMag[].
// Called on OnMapStart (ammo types are registered from scripts by then).
// ---------------------------------------------------------------------------

static void LoadAmmoFlags()
{
	g_ammoFlagsLoaded = false;
	for (int i = 0; i < MAX_AMMO_TYPES; i++)
		g_ammoKnown[i] = false;

	int ammoDef = 0;

	if (g_sdkGetAmmoDef != null)
	{
		// Linux path: direct SDKCall via exported symbol.
		ammoDef = SDKCall(g_sdkGetAmmoDef);
	}
	else if (g_getMagCapAddr != Address_Null)
	{
		// Windows path: navigate from GetMagazineCapacity to GetAmmoDef.
		//
		// GetMagazineCapacity (RVA 0x303D10) calls GetAmmoDef at offset +0x4E:
		//   RVA 0x303D5E:  E8 FD 70 F2 FF   call GetAmmoDef
		// The rel32 is stable under ASLR (relative offset, not in reloc table).
		// GetAmmoDef body:  B8 [g_AmmoDef_VA] C3  (loader patches the VA on load).
		// We read the patched VA directly from the instruction stream.
		int callOpcode = LoadFromAddress(g_getMagCapAddr + view_as<Address>(0x4E), NumberType_Int8);
		if (callOpcode != 0xE8)
		{
			PrintToServer("[Resupply] Windows nav: unexpected byte 0x%02x at GetMagCap+0x4E (expected 0xE8) -- delta fallback",
				callOpcode & 0xFF);
			return;
		}
		int rel32 = LoadFromAddress(g_getMagCapAddr + view_as<Address>(0x4F), NumberType_Int32);
		Address getAmmoDefAddr = g_getMagCapAddr + view_as<Address>(0x53) + view_as<Address>(rel32);

		int movOpcode = LoadFromAddress(getAmmoDefAddr, NumberType_Int8);
		if (movOpcode != 0xB8)
		{
			PrintToServer("[Resupply] Windows nav: GetAmmoDef body starts with 0x%02x (expected 0xB8) -- delta fallback",
				movOpcode & 0xFF);
			return;
		}
		ammoDef = LoadFromAddress(getAmmoDefAddr + view_as<Address>(1), NumberType_Int32);
		PrintToServer("[Resupply] Windows nav: g_AmmoDef=0x%x (via GetMagCap+0x4E)", ammoDef);
	}
	else
	{
		PrintToServer("[Resupply] GetAmmoDef unavailable -- weapon type detection will use delta fallback");
		return;
	}

	if (ammoDef == 0)
	{
		PrintToServer("[Resupply] GetAmmoDef() returned null");
		return;
	}

	int count = LoadFromAddress(view_as<Address>(ammoDef + AMMO_COUNT_OFFSET), NumberType_Int32);
	if (count <= 0 || count > MAX_AMMO_TYPES)
	{
		PrintToServer("[Resupply] CAmmoDef count=%d out of range -- skipping", count);
		return;
	}

	int magCount = 0;
	for (int i = 0; i < count; i++)
	{
		int entry = ammoDef + AMMO_ARRAY_OFFSET + i * AMMO_ENTRY_STRIDE;
		int flags  = LoadFromAddress(view_as<Address>(entry + AMMO_FLAGS_OFFSET), NumberType_Int32);
		g_ammoIsMag[i] = (flags & AMMO_FLAG_MAGAZINE) != 0;
		if (g_ammoIsMag[i]) magCount++;
	}

	g_ammoFlagsLoaded = true;
	PrintToServer("[Resupply] Loaded ammoDef flags: %d types (%d magazine, %d shell-count)",
		count, magCount, count - magCount);
}

public void OnMapStart()
{
	PrecacheModel(RESUPPLY_MODEL, true);
	LoadAmmoFlags();
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

	// Start repeating resupply timer (first tick after a short delay to let the box land)
	int ref = EntIndexToEntRef(entity);
	float interval = g_cvInterval.FloatValue;
	CreateTimer(2.0, Timer_ResupplyTick_Once, ref, TIMER_FLAG_NO_MAPCHANGE);
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
		return Plugin_Stop;

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
			if (GiveAmmoForSlot(i, slot))
				gaveSomething = true;
		}

		if (gaveSomething)
			PrintHintText(i, "Resupplied (+ammo)");
	}

	return Plugin_Continue;
}

// ---------------------------------------------------------------------------
// One-shot initial resupply tick (fires 2s after deploy so the box has landed)
// ---------------------------------------------------------------------------

public Action Timer_ResupplyTick_Once(Handle timer, int entRef)
{
	Timer_ResupplyTick(timer, entRef);
	return Plugin_Stop;
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
// Give ammo for a weapon slot.  Uses the CAmmoDef flag 0x4 loaded at map
// start to distinguish magazine weapons (CINSWeaponMagazines system) from
// non-magazine weapons (simple m_iAmmo shell count).
//
// Always uses the DataMap ammoType (m_iPrimaryAmmoType) for GetMagazines and
// m_iAmmo operations -- the raw CINSWeapon.ammoType field can differ
// (e.g. weapon_ak74: raw=29, game tracks magazines under DM=31).
//
// WARNING: calling GetMagazines on a non-magazine weapon creates a
// CINSWeaponMagazines entry whose constructor resets m_iAmmo to 0,
// destroying the player's spare shell count.  The ammoDef flag is the
// authoritative guard against this.
// ---------------------------------------------------------------------------

#define MAG_HARD_CAP    8    // max spare magazines for magazine weapons
#define SHELL_HARD_CAP  48   // max spare shells for non-magazine weapons

static bool GiveAmmoForSlot(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	if (g_sdkGetMagazines == null || g_off_weapon_slotVal < 0)
		return false;

	// slotVal >= 0 means this weapon has a valid INS ammo slot.
	int slotVal = GetEntData(weapon, g_off_weapon_slotVal);
	if (slotVal < 0)
		return false;

	// Always use the HL2 DataMap ammoType for GetMagazines and m_iAmmo operations.
	int ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
	if (ammoType < 0 || ammoType >= MAX_AMMO_TYPES)
		return false;

	bool isMag;
	if (g_ammoFlagsLoaded)
	{
		isMag = g_ammoIsMag[ammoType];
	}
	else
	{
		// Fallback: delta detection -- only when GetAmmoDef is unavailable.
		// g_ammoKnown[] caches results so the probe is only done once per
		// ammo type per map (avoids misclassification on second use when
		// the UTL entry already exists and delta is 0).
		if (g_ammoKnown[ammoType])
		{
			isMag = g_ammoIsMag[ammoType];
		}
		else
		{
			int prevAmmo = GetEntProp(client, Prop_Data, "m_iAmmo", _, ammoType);
			int magsPtr  = SDKCall(g_sdkGetMagazines, client, ammoType);
			if (magsPtr == 0) return false;
			int postAmmo = GetEntProp(client, Prop_Data, "m_iAmmo", _, ammoType);
			isMag = (postAmmo >= prevAmmo);  // delta < 0 = ctor reset = non-magazine
			if (!isMag && postAmmo != prevAmmo)
			{
				SetEntProp(client, Prop_Data, "m_iAmmo", prevAmmo, _, ammoType);
				SetEntProp(client, Prop_Send, "m_iAmmo", prevAmmo, _, ammoType);
			}
			g_ammoIsMag[ammoType] = isMag;
			g_ammoKnown[ammoType] = true;
		}

		if (!isMag)
		{
			int shellCap = GetEntData(weapon, g_off_weapon_nonMagCap);
			if (shellCap < 1 && g_sdkGetMagCapacity != null)
				shellCap = SDKCall(g_sdkGetMagCapacity, weapon);
			return GiveShells(client, weapon, slot, ammoType, shellCap);
		}
		int magsPtr2 = SDKCall(g_sdkGetMagazines, client, ammoType);
		if (magsPtr2 == 0) return false;
		return GiveMagazine(client, weapon, slot, ammoType, magsPtr2);
	}

	if (!isMag)
	{
		int shellCap = GetEntData(weapon, g_off_weapon_nonMagCap);
		if (shellCap < 1 && g_sdkGetMagCapacity != null)
			shellCap = SDKCall(g_sdkGetMagCapacity, weapon);
		return GiveShells(client, weapon, slot, ammoType, shellCap);
	}

	int magsPtr = SDKCall(g_sdkGetMagazines, client, ammoType);
	if (magsPtr == 0)
		return false;
	return GiveMagazine(client, weapon, slot, ammoType, magsPtr);
}

// ---------------------------------------------------------------------------
// Give +1 spare magazine for a magazine-based weapon.
//
// Appends an entry to the CINSWeaponMagazines UTL vector, then syncs
// m_iAmmo to the new count (mirrors UpdateCounter).
// ---------------------------------------------------------------------------

static bool GiveMagazine(int client, int weapon, int slot, int ammoType, int magsPtr)
{
	// Read the UTL vector fields from the heap object.
	int dataPtr   = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_dataPtr),   NumberType_Int32);
	int allocated = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_allocated), NumberType_Int32);
	int count     = LoadFromAddress(view_as<Address>(magsPtr + g_off_mags_count),     NumberType_Int32);

	if (dataPtr == 0 || allocated <= 0 || count < 0 ||
	    count >= allocated || count >= MAG_HARD_CAP)
	{
		return false;
	}

	// Determine rounds per magazine.  Prefer SDK call (accounts for
	// attachments like extended mags), fall back to nonMagCap field.
	// Note: magCapacity raw field is -1 on this build for all weapons;
	// GetMagazineCapacity() falls back to ammoDef->MagazineCapacity internally.
	int roundsPerMag = -1;
	if (g_sdkGetMagCapacity != null)
		roundsPerMag = SDKCall(g_sdkGetMagCapacity, weapon);
	if (roundsPerMag < 1)
		roundsPerMag = GetEntData(weapon, g_off_weapon_nonMagCap);
	if (roundsPerMag < 1)
		roundsPerMag = 30;

	// Append: data[count] = roundsPerMag, count++
	StoreToAddress(view_as<Address>(dataPtr + count * 4),         roundsPerMag, NumberType_Int32);
	StoreToAddress(view_as<Address>(magsPtr + g_off_mags_count),  count + 1,    NumberType_Int32);

	// Sync m_iAmmo to the new vector size (mirrors UpdateCounter).
	SetEntProp(client, Prop_Data, "m_iAmmo", count + 1, _, ammoType);
	SetEntProp(client, Prop_Send, "m_iAmmo", count + 1, _, ammoType);

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
		return false;

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

	return true;
}
