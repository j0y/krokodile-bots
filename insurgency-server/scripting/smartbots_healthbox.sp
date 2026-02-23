/**
 * smartbots_healthbox.sp -- Player-droppable health boxes for Insurgency 2014
 *
 * Players type !healthbox (or /healthbox) to toss a prop forward.
 * Other players press USE on it to restore HP (default 40),
 * capped at max health.
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
	name        = "SmartBots HealthBox",
	author      = "krokodile",
	description = "Player-droppable health boxes for Insurgency 2014",
	version     = "1.0.0",
	url         = ""
};

// ---------------------------------------------------------------------------
// ConVars
// ---------------------------------------------------------------------------

static ConVar g_cvEnabled;
static ConVar g_cvCooldown;
static ConVar g_cvLifetime;
static ConVar g_cvHealAmount;

// ---------------------------------------------------------------------------
// Per-client cooldown tracking
// ---------------------------------------------------------------------------

static float g_lastDropTime[MAXPLAYERS + 1];

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#define HEALTHBOX_MODEL "models/static_props/wcache_box_02.mdl"

// ---------------------------------------------------------------------------
// Plugin lifecycle
// ---------------------------------------------------------------------------

public void OnPluginStart()
{
	g_cvEnabled    = CreateConVar("sm_healthbox_enabled",  "1",   "Enable health box dropping");
	g_cvCooldown   = CreateConVar("sm_healthbox_cooldown", "60",  "Seconds between drops per player");
	g_cvLifetime   = CreateConVar("sm_healthbox_lifetime", "120", "Seconds before unclaimed box despawns");
	g_cvHealAmount = CreateConVar("sm_healthbox_heal",     "40",  "HP restored on pickup");

	RegConsoleCmd("sm_healthbox", Cmd_HealthBox, "Toss a health box");

	PrintToServer("[HealthBox] Plugin loaded (v1.0.0)");
}

public void OnMapStart()
{
	PrecacheModel(HEALTHBOX_MODEL, true);
}

public void OnClientDisconnect(int client)
{
	g_lastDropTime[client] = 0.0;
}

// ---------------------------------------------------------------------------
// Command: !healthbox / /healthbox / sm_healthbox
// ---------------------------------------------------------------------------

public Action Cmd_HealthBox(int client, int args)
{
	if (!g_cvEnabled.BoolValue)
	{
		ReplyToCommand(client, "[HealthBox] Health boxes are disabled.");
		return Plugin_Handled;
	}

	if (!IsValidClient(client))
		return Plugin_Handled;

	if (!IsPlayerAlive(client))
	{
		PrintToChat(client, "[HealthBox] You must be alive to drop a health box.");
		return Plugin_Handled;
	}

	// Cooldown check
	float now = GetGameTime();
	float cooldown = g_cvCooldown.FloatValue;
	float elapsed = now - g_lastDropTime[client];
	if (elapsed < cooldown)
	{
		int remaining = RoundToCeil(cooldown - elapsed);
		PrintToChat(client, "[HealthBox] Cooldown: %d seconds remaining.", remaining);
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
	vel[2] = fwd[2] * 250.0 + 100.0;

	// Create the health box prop
	int entity = CreateEntityByName("prop_physics_override");
	if (entity == -1)
	{
		PrintToChat(client, "[HealthBox] Failed to create health box.");
		return Plugin_Handled;
	}

	SetEntityModel(entity, HEALTHBOX_MODEL);
	DispatchKeyValue(entity, "solid", "6");
	DispatchKeyValue(entity, "spawnflags", "256");
	DispatchSpawn(entity);
	TeleportEntity(entity, spawnPos, NULL_VECTOR, vel);

	// Red tint to distinguish from ammo boxes
	SetEntityRenderColor(entity, 200, 255, 200, 255);

	// Hook Use key
	SDKHook(entity, SDKHook_Use, OnHealthBoxUse);

	// Auto-despawn timer
	float lifetime = g_cvLifetime.FloatValue;
	int ref = EntIndexToEntRef(entity);
	CreateTimer(lifetime, Timer_RemoveBox, ref, TIMER_FLAG_NO_MAPCHANGE);

	// Record cooldown
	g_lastDropTime[client] = now;

	PrintToChat(client, "[HealthBox] Health box tossed! Teammates can press USE to pick it up.");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Use callback: heal the player
// ---------------------------------------------------------------------------

public Action OnHealthBoxUse(int entity, int activator, int caller, UseType type, float value)
{
	if (!IsValidClient(activator) || !IsPlayerAlive(activator))
		return Plugin_Continue;

	int health = GetClientHealth(activator);
	int maxHealth = GetEntProp(activator, Prop_Data, "m_iMaxHealth");

	if (health >= maxHealth)
	{
		PrintHintText(activator, "Health full -- nothing to pick up.");
		return Plugin_Handled;
	}

	int healAmount = g_cvHealAmount.IntValue;
	int newHealth = health + healAmount;
	if (newHealth > maxHealth)
		newHealth = maxHealth;

	SetEntityHealth(activator, newHealth);

	int healed = newHealth - health;
	PrintHintText(activator, "Picked up health box (+%d HP)", healed);

	EmitSoundToClient(activator, "physics/metal/weapon_impact_hard1.wav");

	// Destroy the box
	SDKUnhook(entity, SDKHook_Use, OnHealthBoxUse);
	AcceptEntityInput(entity, "Kill");

	return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Auto-despawn timer
// ---------------------------------------------------------------------------

public Action Timer_RemoveBox(Handle timer, int entRef)
{
	int entity = EntRefToEntIndex(entRef);
	if (entity != INVALID_ENT_REFERENCE && IsValidEntity(entity))
	{
		SDKUnhook(entity, SDKHook_Use, OnHealthBoxUse);
		AcceptEntityInput(entity, "Kill");
	}
	return Plugin_Stop;
}
