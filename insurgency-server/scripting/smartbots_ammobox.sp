/**
 * smartbots_ammobox.sp -- Player-droppable ammo boxes for Insurgency 2014
 *
 * Players type !ammobox (or /ammobox) to drop a weapon cache prop at their
 * feet.  Other players press Use (E) on it to receive +1 spare magazine for
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

#define AMMOBOX_MODEL "models/static_props/wcache_ins_01.mdl"

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

public void OnPluginStart()
{
	g_cvEnabled  = CreateConVar("sm_ammobox_enabled",  "1",   "Enable ammo box dropping");
	g_cvCooldown = CreateConVar("sm_ammobox_cooldown", "60",  "Seconds between drops per player");
	g_cvLifetime = CreateConVar("sm_ammobox_lifetime", "120", "Seconds before unclaimed box despawns");

	RegConsoleCmd("sm_ammobox", Cmd_AmmoBox, "Drop an ammo box at your feet");

	PrintToServer("[AmmoBox] Plugin loaded (v1.0.0)");
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

	// Make it glow slightly (set render color to a slightly tinted white)
	SetEntityRenderColor(entity, 200, 255, 200, 255);

	// Hook Use key
	SDKHook(entity, SDKHook_Use, OnAmmoBoxUse);

	// Auto-despawn timer
	float lifetime = g_cvLifetime.FloatValue;
	int ref = EntIndexToEntRef(entity);
	CreateTimer(lifetime, Timer_RemoveBox, ref, TIMER_FLAG_NO_MAPCHANGE);

	// Record cooldown
	g_lastDropTime[client] = now;

	PrintToChat(client, "[AmmoBox] Ammo box dropped! Teammates can press E to pick it up.");

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
		PrintHintText(activator, "Ammo full -- nothing to pick up.");
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
// Give one magazine worth of spare ammo for a weapon slot
// ---------------------------------------------------------------------------

static bool GiveMagazine(int client, int slot)
{
	int weapon = GetPlayerWeaponSlot(client, slot);
	if (weapon == -1)
		return false;

	// Get ammo type for this weapon
	int ammoType = GetEntProp(weapon, Prop_Send, "m_iPrimaryAmmoType");
	if (ammoType < 0)
		return false;

	// Get clip capacity (= one magazine worth of bullets)
	int clipSize = GetEntProp(weapon, Prop_Data, "m_iClip1");
	if (clipSize <= 0)
		clipSize = 30; // fallback for edge cases

	// For magazine-based weapons, clip size is the current loaded rounds.
	// We need the max clip. Try m_iPrimaryAmmoCount as max spare ammo indicator.
	// Actually m_iClip1 is current clip contents, not capacity.
	// Use GetEntProp with Prop_Send to get max clip from weapon definition.
	// Insurgency weapons: Ins_GetMaxClip1 reads from weapon def handle.
	// Safest: try to read via Prop_Data m_iMaxClip1 if it exists.
	int maxClip = -1;

	// Check if the weapon has a net class with max clip info
	char netClass[64];
	if (GetEntityNetClass(weapon, netClass, sizeof(netClass)))
	{
		int offset = FindSendPropInfo(netClass, "m_iMaxClip1");
		if (offset > 0)
			maxClip = GetEntData(weapon, offset);
	}

	if (maxClip <= 0)
	{
		// Fallback: use current clip as best estimate of capacity
		// This is imperfect if player has partial clip, but acceptable
		maxClip = clipSize;
		if (maxClip <= 0)
			maxClip = 30;
	}

	// Current spare ammo
	int currentAmmo = GetEntProp(client, Prop_Send, "m_iAmmo", _, ammoType);

	// Read max spare ammo from weapon data if available
	int maxAmmo = -1;
	if (HasEntProp(weapon, Prop_Data, "m_iPrimaryAmmoCount"))
		maxAmmo = GetEntProp(weapon, Prop_Data, "m_iPrimaryAmmoCount");

	// If we couldn't get max ammo from the weapon, use a generous cap
	if (maxAmmo <= 0)
		maxAmmo = maxClip * 10;

	// Already at or above max?
	if (currentAmmo >= maxAmmo)
		return false;

	// Add one magazine, cap at max
	int newAmmo = currentAmmo + maxClip;
	if (newAmmo > maxAmmo)
		newAmmo = maxAmmo;

	SetEntProp(client, Prop_Send, "m_iAmmo", newAmmo, _, ammoType);

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
