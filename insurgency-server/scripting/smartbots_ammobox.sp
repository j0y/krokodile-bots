/**
 * smartbots_ammobox.sp -- Player-droppable ammo boxes for Insurgency 2014
 *
 * Players type !ammobox (or /ammobox) to drop a weapon cache prop at their
 * feet.  Other players press USE on it to receive +1 spare magazine for
 * their primary and secondary weapons (capped at loadout max).
 *
 * Single-use: box disappears after one pickup.
 * Standalone plugin -- no dependencies on smartbots.sp or other custom plugins.
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
	version     = "1.0.0",
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
// Plugin lifecycle
// ---------------------------------------------------------------------------

public void OnPluginStart()
{
	g_cvEnabled  = CreateConVar("sm_ammobox_enabled",  "1",   "Enable ammo box dropping");
	g_cvCooldown = CreateConVar("sm_ammobox_cooldown", "60",  "Seconds between drops per player");
	g_cvLifetime = CreateConVar("sm_ammobox_lifetime", "120", "Seconds before unclaimed box despawns");

	RegConsoleCmd("sm_ammobox", Cmd_AmmoBox, "Drop an ammo box at your feet");
	RegAdminCmd("sm_ammobox_scan", Cmd_AmmoScan, ADMFLAG_ROOT, "Scan player memory for internal ammo counter");

	PrintToServer("[AmmoBox] Plugin loaded (v1.0.0)");
}

// ---------------------------------------------------------------------------
// Debug scan: dump all int-sized values near m_iAmmo[ammoType] on the player
// that equal the current magazine count.  Run before and after a reload to
// identify which offset is the internal counter (the one that decrements
// while m_iAmmo gets reset).
// ---------------------------------------------------------------------------

public Action Cmd_AmmoScan(int client, int args)
{
	int target = (client == 0) ? 1 : client;   // default: first connected player

	// Find the base offset of the m_iAmmo array via SendProp
	int ammoBase = FindSendPropInfo("CINSPlayer", "m_iAmmo");
	if (ammoBase <= 0)
		ammoBase = FindSendPropInfo("CBasePlayer", "m_iAmmo");

	int weapon = GetPlayerWeaponSlot(target, 0);
	if (weapon == -1)
	{
		ReplyToCommand(client, "[Scan] No primary weapon on player %d", target);
		return Plugin_Handled;
	}

	int ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
	if (ammoType < 0)
	{
		ReplyToCommand(client, "[Scan] ammoType < 0");
		return Plugin_Handled;
	}

	int ammoOffset = ammoBase + ammoType * 4;   // offset of m_iAmmo[ammoType]
	int curMags    = GetEntProp(target, Prop_Data, "m_iAmmo", _, ammoType);

	PrintToServer("[Scan] player=%d ammoType=%d ammoBase=%d ammoOffset=%d curMags=%d",
		target, ammoType, ammoBase, ammoOffset, curMags);

	// Scan ±600 bytes in 4-byte steps from ammoOffset on the PLAYER entity
	for (int delta = -600; delta <= 600; delta += 4)
	{
		int off = ammoOffset + delta;
		if (off < 0)
			continue;
		int val = GetEntData(target, off);
		if (val == curMags)
			PrintToServer("[Scan]  player+%d = %d  (delta %+d from m_iAmmo[%d])",
				off, val, delta, ammoType);
	}

	// Also scan the weapon entity ±600 bytes from its start
	PrintToServer("[Scan] --- weapon entity scan (mags=%d) ---", curMags);
	for (int off = 0; off < 1200; off += 4)
	{
		int val = GetEntData(weapon, off);
		if (val == curMags)
			PrintToServer("[Scan]  weapon+%d = %d", off, val);
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

	// Spawn at eye position, toss forward like dropping a weapon
	float eyePos[3], eyeAng[3], fwd[3], vel[3];
	GetClientEyePosition(client, eyePos);
	GetClientEyeAngles(client, eyeAng);
	GetAngleVectors(eyeAng, fwd, NULL_VECTOR, NULL_VECTOR);

	// Start slightly in front of face so it doesn't clip into the player
	float spawnPos[3];
	spawnPos[0] = eyePos[0] + fwd[0] * 30.0;
	spawnPos[1] = eyePos[1] + fwd[1] * 30.0;
	spawnPos[2] = eyePos[2] + fwd[2] * 30.0;

	// Toss velocity: forward + upward arc
	vel[0] = fwd[0] * 250.0;
	vel[1] = fwd[1] * 250.0;
	vel[2] = fwd[2] * 250.0 + 100.0; // add upward loft

	// Create the ammo box prop
	int entity = CreateEntityByName("prop_physics_override");
	if (entity == -1)
	{
		PrintToChat(client, "[AmmoBox] Failed to create ammo box.");
		return Plugin_Handled;
	}

	SetEntityModel(entity, AMMOBOX_MODEL);
	DispatchKeyValue(entity, "solid", "6");
	DispatchKeyValue(entity, "spawnflags", "256"); // not affected by rotor wash
	DispatchSpawn(entity);
	TeleportEntity(entity, spawnPos, NULL_VECTOR, vel);

	// Red tint to distinguish from health boxes
	SetEntityRenderColor(entity, 255, 200, 200, 255);

	// Hook Use key
	SDKHook(entity, SDKHook_Use, OnAmmoBoxUse);

	// Auto-despawn timer
	float lifetime = g_cvLifetime.FloatValue;
	int ref = EntIndexToEntRef(entity);
	CreateTimer(lifetime, Timer_RemoveBox, ref, TIMER_FLAG_NO_MAPCHANGE);

	// Record cooldown
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

	// Give +1 magazine to primary (slot 0) and secondary (slot 1)
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

	// Play a pickup sound
	EmitSoundToClient(activator, "physics/metal/weapon_impact_hard1.wav");

	// Destroy the box
	SDKUnhook(entity, SDKHook_Use, OnAmmoBoxUse);
	AcceptEntityInput(entity, "Kill");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Give one magazine worth of spare ammo for a weapon slot.
//
// Insurgency stores reserve ammo in m_iAmmoBelt on the weapon entity
// (DT_LocalActiveINSWeaponBallistic) rather than in the base-engine
// m_iAmmo[] on the player.  We write to both fields so the HUD and the
// reload logic stay in sync.
// ---------------------------------------------------------------------------

static int s_magsOffset = -2;  // offset for CINSWeapon "mags" (looked up once)

static bool GiveMagazine(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	// ---- ammo type on the player side ----
	int ammoType = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoType");
	if (ammoType < 0)
		return false;

	// ---- "mags" offset on the weapon (Insurgency-specific reserve counter) ----
	if (s_magsOffset == -2)
	{
		s_magsOffset = FindSendPropInfo("CINSWeapon", "mags");
		if (s_magsOffset <= 0)
			s_magsOffset = FindSendPropInfo("CINSWeaponBallistic", "mags");
		PrintToServer("[AmmoBox] mags offset=%d", s_magsOffset);
	}

	int beforeAmmo    = GetEntProp(client, Prop_Data, "m_iAmmo", _, ammoType);
	int beforeAmmoS   = GetEntProp(client, Prop_Send, "m_iAmmo", _, ammoType);
	int beforeWepCnt  = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoCount");

	PrintToServer("[AmmoBox] slot=%d ammoType=%d  player:m_iAmmo(Data)=%d m_iAmmo(Send)=%d  weapon:m_iPrimaryAmmoCount=%d",
		slot, ammoType, beforeAmmo, beforeAmmoS, beforeWepCnt);

	if (beforeAmmo >= 8)
		return false;

	// Write +1 to the player's ammo array (both Prop_Data and Prop_Send)
	SetEntProp(client, Prop_Data, "m_iAmmo", beforeAmmo + 1, _, ammoType);
	SetEntProp(client, Prop_Send, "m_iAmmo", beforeAmmo + 1, _, ammoType);

	// Write +1 to weapon's m_iPrimaryAmmoCount (candidate for internal counter)
	if (beforeWepCnt >= 0)
		SetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoCount", beforeWepCnt + 1);

	int afterAmmo   = GetEntProp(client, Prop_Data, "m_iAmmo", _, ammoType);
	int afterAmmoS  = GetEntProp(client, Prop_Send, "m_iAmmo", _, ammoType);
	int afterWepCnt = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoCount");
	PrintToServer("[AmmoBox] after: m_iAmmo(Data)=%d m_iAmmo(Send)=%d weapon:m_iPrimaryAmmoCount=%d",
		afterAmmo, afterAmmoS, afterWepCnt);

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
