/**
 * SmartBots Bridge — SourceMod ↔ Python AI UDP bridge
 *
 * Uses DHooks to detour CINSBotLocomotion::Approach, redirecting bot
 * movement goals to positions provided by the Python AI brain.
 * Since PlayerLocomotion converts goals into button presses, bots get
 * proper running animations for free.
 */

#include <sourcemod>
#include <sdktools>
#include <sdkhooks>
#include <dhooks>
#include <socket>

#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION "0.4.0"
#define MAX_BOTS 64
#define MAX_MSG_LEN 4096
#define SEND_INTERVAL 0.125  // ~8Hz

public Plugin myinfo = {
    name = "SmartBots Bridge",
    author = "SmartBots",
    description = "UDP bridge between game bots and Python AI brain (DHooks)",
    version = PLUGIN_VERSION,
    url = ""
};

// ConVars
ConVar g_cvAIHost;
ConVar g_cvAIPort;
ConVar g_cvDebug;

// Socket
Handle g_hSocket = INVALID_HANDLE;
bool g_bSocketReady = false;

// DHooks detours
DynamicDetour g_detourApproach;
DynamicDetour g_detourUpdate;
DynamicDetour g_detourIntention;
// SDKCall for clearing locomotion stuck status
Handle g_hClearStuckStatus;

// SDKCall for getting locomotion interface directly from entity
Handle g_hGetLocomotionInterface;
// SDKCall for directly calling Approach on ILocomotion*
Handle g_hCallApproach;
// SDKCall for calling Run() to set locomotion speed
Handle g_hCallRun;
// SDKCall for calling FaceTowards() to rotate bot toward target
Handle g_hCallFaceTowards;

// Per-bot state
bool g_bHasCommand[MAX_BOTS + 1];
float g_fTargetPos[MAX_BOTS + 1][3];
float g_fTargetSpeed[MAX_BOTS + 1];
Address g_pBotLoco[MAX_BOTS + 1];  // ILocomotion* per client

// Guard: skip Approach detour when called from our Update hook
bool g_bInUpdateHook = false;

// Tick counter for state messages
int g_iTickCount = 0;

// Debug counters
int g_iCmdsReceived = 0;
int g_iApproachRedirected = 0;

public void OnPluginStart()
{
    g_cvAIHost = CreateConVar("sm_smartbots_host", "127.0.0.1",
        "AI brain host address");
    g_cvAIPort = CreateConVar("sm_smartbots_port", "9000",
        "AI brain port", _, true, 1.0, true, 65535.0);
    g_cvDebug = CreateConVar("sm_smartbots_debug", "1",
        "Enable debug logging (0=off, 1=on)", _, true, 0.0, true, 1.0);

    RegAdminCmd("sm_smartbots_status", Cmd_Status, ADMFLAG_GENERIC,
        "Show SmartBots bridge status");

    // Clear state
    for (int i = 0; i <= MAX_BOTS; i++)
    {
        g_bHasCommand[i] = false;
        g_fTargetSpeed[i] = 0.0;
        g_pBotLoco[i] = Address_Null;
    }

    // Load gamedata and setup DHooks
    if (!SetupDHooks())
    {
        SetFailState("[SmartBots] Failed to setup DHooks — check gamedata");
        return;
    }

    // Connect after a short delay to let the server finish loading
    CreateTimer(3.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);

    LogMessage("[SmartBots] Plugin loaded (v%s) — DHooks locomotion control", PLUGIN_VERSION);
}

bool SetupDHooks()
{
    GameData hConf = new GameData("smartbots_bridge");
    if (hConf == null)
    {
        LogError("[SmartBots] Could not load gamedata 'smartbots_bridge'");
        return false;
    }

    // --- Detour: CINSBotLocomotion::Approach ---
    g_detourApproach = DynamicDetour.FromConf(hConf, "CINSBotLocomotion::Approach");
    if (g_detourApproach == null)
    {
        LogError("[SmartBots] Failed to create detour for CINSBotLocomotion::Approach");
        delete hConf;
        return false;
    }

    if (!g_detourApproach.Enable(Hook_Pre, Detour_OnApproach))
    {
        LogError("[SmartBots] Failed to enable Approach detour");
        delete hConf;
        return false;
    }

    LogMessage("[SmartBots] Approach detour enabled");

    // --- Detour: CINSBotLocomotion::Update ---
    // Called every tick by the NextBot framework. We inject Approach(target) in
    // the pre-hook so the locomotion system always has our goal to process,
    // regardless of what the behavior tree decided.
    g_detourUpdate = DynamicDetour.FromConf(hConf, "CINSBotLocomotion::Update");
    if (g_detourUpdate == null)
    {
        LogError("[SmartBots] Failed to create detour for CINSBotLocomotion::Update");
        delete hConf;
        return false;
    }

    if (!g_detourUpdate.Enable(Hook_Pre, Detour_OnUpdate))
    {
        LogError("[SmartBots] Failed to enable Update detour");
        delete hConf;
        return false;
    }

    LogMessage("[SmartBots] Update detour enabled");

    // --- Detour: CINSNextBot::CINSNextBotIntention::Update ---
    // Suppress the behavior tree entirely so it can't interfere with our
    // movement commands (no Stop(), no hold position, no state changes).
    g_detourIntention = DynamicDetour.FromConf(hConf, "CINSNextBot::CINSNextBotIntention::Update");
    if (g_detourIntention == null)
    {
        LogError("[SmartBots] Failed to create detour for Intention::Update");
        delete hConf;
        return false;
    }

    if (!g_detourIntention.Enable(Hook_Pre, Detour_OnIntentionUpdate))
    {
        LogError("[SmartBots] Failed to enable Intention detour");
        delete hConf;
        return false;
    }

    LogMessage("[SmartBots] Intention detour enabled (behavior tree suppressed)");

    // --- SDKCall: ILocomotion::ClearStuckStatus (ILocomotion* → clear stuck flag) ---
    StartPrepSDKCall(SDKCall_Raw);
    PrepSDKCall_SetFromConf(hConf, SDKConf_Signature,
        "ILocomotion::ClearStuckStatus");
    PrepSDKCall_AddParameter(SDKType_String, SDKPass_Pointer);
    g_hClearStuckStatus = EndPrepSDKCall();

    if (g_hClearStuckStatus == null)
    {
        LogError("[SmartBots] Failed to create SDKCall for ClearStuckStatus");
        delete hConf;
        return false;
    }

    LogMessage("[SmartBots] SDKCalls ready (ClearStuckStatus)");

    // --- SDKCall: GetLocomotionInterface (entity → ILocomotion*) ---
    // CINSNextBot inherits CINSPlayer at offset 0, so CBaseEntity* == CINSNextBot*.
    // Calling CINSNextBot::GetLocomotionInterface via SDKCall_Entity is safe.
    StartPrepSDKCall(SDKCall_Entity);
    PrepSDKCall_SetFromConf(hConf, SDKConf_Signature,
        "CINSNextBot::GetLocomotionInterface");
    PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
    g_hGetLocomotionInterface = EndPrepSDKCall();

    if (g_hGetLocomotionInterface == null)
    {
        LogError("[SmartBots] Failed to create SDKCall for GetLocomotionInterface");
        delete hConf;
        return false;
    }

    // --- SDKCall: CINSBotLocomotion::Approach (ILocomotion* → direct call) ---
    StartPrepSDKCall(SDKCall_Raw);
    PrepSDKCall_SetFromConf(hConf, SDKConf_Signature,
        "CINSBotLocomotion::Approach");
    PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);
    PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);
    g_hCallApproach = EndPrepSDKCall();

    if (g_hCallApproach == null)
    {
        LogError("[SmartBots] Failed to create SDKCall for Approach");
        delete hConf;
        return false;
    }

    // --- SDKCall: PlayerLocomotion::Run (ILocomotion* → set run speed) ---
    StartPrepSDKCall(SDKCall_Raw);
    PrepSDKCall_SetFromConf(hConf, SDKConf_Signature,
        "PlayerLocomotion::Run");
    g_hCallRun = EndPrepSDKCall();

    if (g_hCallRun == null)
    {
        LogError("[SmartBots] Failed to create SDKCall for Run");
        delete hConf;
        return false;
    }

    // --- SDKCall: CINSBotLocomotion::FaceTowards (ILocomotion* → rotate toward target) ---
    StartPrepSDKCall(SDKCall_Raw);
    PrepSDKCall_SetFromConf(hConf, SDKConf_Signature,
        "CINSBotLocomotion::FaceTowards");
    PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);
    g_hCallFaceTowards = EndPrepSDKCall();

    if (g_hCallFaceTowards == null)
    {
        LogError("[SmartBots] Failed to create SDKCall for FaceTowards");
        delete hConf;
        return false;
    }

    LogMessage("[SmartBots] SDKCalls ready (GetLocomotionInterface, Approach, Run, FaceTowards)");

    delete hConf;
    return true;
}

public void OnPluginEnd()
{
    if (g_detourApproach != null)
    {
        g_detourApproach.Disable(Hook_Pre, Detour_OnApproach);
    }
    if (g_detourUpdate != null)
    {
        g_detourUpdate.Disable(Hook_Pre, Detour_OnUpdate);
    }
    if (g_detourIntention != null)
    {
        g_detourIntention.Disable(Hook_Pre, Detour_OnIntentionUpdate);
    }

    if (g_hSocket != INVALID_HANDLE)
    {
        CloseHandle(g_hSocket);
        g_hSocket = INVALID_HANDLE;
        g_bSocketReady = false;
    }
}

public void OnMapStart()
{
    if (!g_bSocketReady)
    {
        CreateTimer(3.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
    }
}

// ---------------------------------------------------------------------------
// Bot locomotion mapping: client index ↔ ILocomotion* address
// ---------------------------------------------------------------------------

public void OnClientPutInServer(int client)
{
    g_pBotLoco[client] = Address_Null;
    g_bHasCommand[client] = false;

    if (IsFakeClient(client))
    {
        // Delay to let the bot entity fully initialize
        CreateTimer(0.5, Timer_SetupBot, GetClientUserId(client),
            TIMER_FLAG_NO_MAPCHANGE);
    }
}

public void OnClientDisconnect(int client)
{
    g_pBotLoco[client] = Address_Null;
    g_bHasCommand[client] = false;
}

public Action Timer_SetupBot(Handle timer, int userid)
{
    int client = GetClientOfUserId(userid);
    if (client <= 0 || !IsClientInGame(client) || !IsFakeClient(client))
        return Plugin_Stop;

    // entity → ILocomotion* (CINSNextBot* == CBaseEntity* at offset 0)
    Address pLoco = SDKCall(g_hGetLocomotionInterface, client);
    if (pLoco == Address_Null)
    {
        LogError("[SmartBots] Bot %d: GetLocomotionInterface returned null", client);
        return Plugin_Stop;
    }

    g_pBotLoco[client] = pLoco;

    if (g_cvDebug.BoolValue)
    {
        LogMessage("[SmartBots] Bot %d mapped: ILocomotion=0x%X", client, pLoco);
    }

    return Plugin_Stop;
}

int LocoToClient(Address pLoco)
{
    for (int i = 1; i <= MaxClients; i++)
    {
        if (g_pBotLoco[i] == pLoco)
            return i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// DHooks detour: CINSNextBot::CINSNextBotIntention::Update()
//
// Suppress the behavior tree entirely. Without this, the behavior calls
// Stop(), enters hold-position states, and fights our movement commands.
// Locomotion, body, and vision subsystems continue to update normally.
// ---------------------------------------------------------------------------

public MRESReturn Detour_OnIntentionUpdate(Address pThis)
{
    return MRES_Supercede;
}

// ---------------------------------------------------------------------------
// DHooks detour: CINSBotLocomotion::Approach(const Vector &goal, float weight)
//
// When the bot's behavior tree calls Approach with its own destination,
// we replace 'goal' with the target from Python. The bot's locomotion
// system naturally converts this into button presses → proper animations.
// ---------------------------------------------------------------------------

public MRESReturn Detour_OnApproach(Address pThis, DHookParam hParams)
{
    // Skip if this Approach call came from our own Update hook
    if (g_bInUpdateHook)
        return MRES_Ignored;

    int client = LocoToClient(pThis);
    if (client <= 0)
        return MRES_Ignored;

    if (!g_bHasCommand[client])
        return MRES_Ignored;

    if (!IsClientInGame(client) || !IsPlayerAlive(client))
        return MRES_Ignored;

    // Replace the goal vector with our target
    hParams.SetVector(1, g_fTargetPos[client]);

    g_iApproachRedirected++;

    // Debug log every ~5 seconds
    if (g_cvDebug.BoolValue && (g_iApproachRedirected % 320 == 1))
    {
        LogMessage("[SmartBots] Approach redirect bot=%d target=(%.0f,%.0f,%.0f) total=%d",
            client,
            g_fTargetPos[client][0], g_fTargetPos[client][1], g_fTargetPos[client][2],
            g_iApproachRedirected);
    }

    return MRES_ChangedHandled;
}

// ---------------------------------------------------------------------------
// DHooks detour: CINSBotLocomotion::Update()
//
// Only clear stuck status. All movement is handled via OnPlayerRunCmd.
// ---------------------------------------------------------------------------

public MRESReturn Detour_OnUpdate(Address pThis)
{
    int client = LocoToClient(pThis);
    if (client <= 0)
        return MRES_Ignored;

    if (!IsClientInGame(client) || !IsPlayerAlive(client))
        return MRES_Ignored;

    SDKCall(g_hClearStuckStatus, pThis, "smartbots");

    return MRES_Ignored;
}

// ---------------------------------------------------------------------------
// OnPlayerRunCmd — direct movement control
//
// Calculate direction to target, set eye angles + forward velocity.
// With the behavior tree suppressed, nothing fights our overrides.
// ---------------------------------------------------------------------------

public Action OnPlayerRunCmd(int client, int &buttons, int &impulse,
    float vel[3], float angles[3], int &weapon,
    int &subtype, int &cmdnum, int &tickcount, int &seed,
    int mouse[2])
{
    if (!g_bHasCommand[client])
        return Plugin_Continue;

    if (!IsPlayerAlive(client))
        return Plugin_Continue;

    float pos[3];
    GetClientAbsOrigin(client, pos);

    // Direction to target (2D)
    float dx = g_fTargetPos[client][0] - pos[0];
    float dy = g_fTargetPos[client][1] - pos[1];
    float dist = SquareRoot(dx * dx + dy * dy);

    if (dist < 10.0)
        return Plugin_Continue;  // close enough

    // Face toward target
    float desiredYaw = ArcTangent2(dy, dx) * (180.0 / 3.14159265);
    angles[0] = 0.0;
    angles[1] = desiredYaw;
    angles[2] = 0.0;

    // Run forward
    vel[0] = 450.0;
    vel[1] = 0.0;
    vel[2] = 0.0;
    buttons |= IN_FORWARD;

    return Plugin_Changed;
}

// ---------------------------------------------------------------------------
// Debug status command
// ---------------------------------------------------------------------------

public Action Cmd_Status(int client, int args)
{
    char host[64];
    g_cvAIHost.GetString(host, sizeof(host));

    PrintToServer("[SmartBots] === Status ===");
    PrintToServer("[SmartBots] Socket: %s | Host: %s:%d",
        g_bSocketReady ? "CONNECTED" : "DISCONNECTED",
        host, g_cvAIPort.IntValue);
    PrintToServer("[SmartBots] Ticks sent: %d | Cmds received: %d | Approach redirects: %d",
        g_iTickCount, g_iCmdsReceived, g_iApproachRedirected);

    for (int i = 1; i <= MaxClients; i++)
    {
        if (!IsClientInGame(i) || !IsFakeClient(i))
            continue;

        float pos[3];
        GetClientAbsOrigin(i, pos);
        bool alive = IsPlayerAlive(i);
        int team = GetClientTeam(i);

        PrintToServer("[SmartBots] Bot %d: alive=%d team=%d pos=(%.0f,%.0f,%.0f) loco=0x%X hasCmd=%d target=(%.0f,%.0f,%.0f)",
            i, alive, team, pos[0], pos[1], pos[2],
            g_pBotLoco[i],
            g_bHasCommand[i],
            g_fTargetPos[i][0], g_fTargetPos[i][1], g_fTargetPos[i][2]);
    }

    return Plugin_Handled;
}

// ---------------------------------------------------------------------------
// Socket management
// ---------------------------------------------------------------------------

public Action Timer_Connect(Handle timer)
{
    ConnectToAI();
    return Plugin_Stop;
}

void ConnectToAI()
{
    if (g_hSocket != INVALID_HANDLE)
    {
        CloseHandle(g_hSocket);
        g_hSocket = INVALID_HANDLE;
        g_bSocketReady = false;
    }

    g_hSocket = SocketCreate(SOCKET_UDP, OnSocketError);
    if (g_hSocket == INVALID_HANDLE)
    {
        LogError("[SmartBots] Failed to create UDP socket");
        CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
        return;
    }

    char host[64];
    g_cvAIHost.GetString(host, sizeof(host));
    int port = g_cvAIPort.IntValue;

    LogMessage("[SmartBots] Connecting to AI brain at %s:%d", host, port);
    SocketConnect(g_hSocket, OnSocketConnected, OnSocketReceive,
        OnSocketDisconnected, host, port);
}

public void OnSocketConnected(Handle socket, any arg)
{
    g_bSocketReady = true;
    LogMessage("[SmartBots] Connected to AI brain");

    CreateTimer(SEND_INTERVAL, Timer_SendState, _,
        TIMER_REPEAT | TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketDisconnected(Handle socket, any arg)
{
    g_bSocketReady = false;
    LogMessage("[SmartBots] Disconnected from AI brain, reconnecting...");
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketError(Handle socket, const int errorType,
    const int errorNum, any arg)
{
    g_bSocketReady = false;
    LogError("[SmartBots] Socket error: type=%d errno=%d", errorType, errorNum);
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

// ---------------------------------------------------------------------------
// Receive commands from Python
//
// Format: one bot per line — "id x y z speed\n"
// ---------------------------------------------------------------------------

public void OnSocketReceive(Handle socket, const char[] receiveData,
    const int dataSize, any arg)
{
    bool dbg = g_cvDebug.BoolValue;

    char lines[MAX_BOTS][128];
    int count = ExplodeString(receiveData, "\n", lines, MAX_BOTS, 128);

    int parsed = 0;
    for (int i = 0; i < count; i++)
    {
        TrimString(lines[i]);
        if (strlen(lines[i]) == 0)
            continue;

        char parts[5][32];
        int numParts = ExplodeString(lines[i], " ", parts, 5, 32);
        if (numParts < 5)
        {
            if (dbg)
                LogMessage("[SmartBots] Bad command line (parts=%d): '%s'",
                    numParts, lines[i]);
            continue;
        }

        int botId = StringToInt(parts[0]);
        if (botId < 1 || botId > MaxClients)
        {
            if (dbg)
                LogMessage("[SmartBots] Bad bot id: %d", botId);
            continue;
        }

        g_fTargetPos[botId][0] = StringToFloat(parts[1]);
        g_fTargetPos[botId][1] = StringToFloat(parts[2]);
        g_fTargetPos[botId][2] = StringToFloat(parts[3]);
        g_fTargetSpeed[botId] = StringToFloat(parts[4]);
        g_bHasCommand[botId] = true;
        parsed++;
    }

    g_iCmdsReceived += parsed;

    if (dbg && (g_iTickCount % 40 == 0))
    {
        LogMessage("[SmartBots] Recv: %d bytes, %d lines, %d commands parsed",
            dataSize, count, parsed);
    }
}

// ---------------------------------------------------------------------------
// Send state to Python (~8Hz)
// ---------------------------------------------------------------------------

public Action Timer_SendState(Handle timer)
{
    if (!g_bSocketReady)
        return Plugin_Continue;

    g_iTickCount++;

    char msg[MAX_MSG_LEN];
    int offset = 0;

    offset += FormatEx(msg[offset], MAX_MSG_LEN - offset,
        "{\"tick\":%d,\"bots\":[", g_iTickCount);

    bool first = true;
    int botCount = 0;
    int aliveCount = 0;

    for (int client = 1; client <= MaxClients; client++)
    {
        if (!IsClientInGame(client))
            continue;
        if (!IsFakeClient(client))
            continue;

        float pos[3], ang[3];
        GetClientAbsOrigin(client, pos);
        GetClientAbsAngles(client, ang);
        int health = GetClientHealth(client);
        int team = GetClientTeam(client);
        bool alive = IsPlayerAlive(client);

        botCount++;
        if (alive) aliveCount++;

        if (!first)
        {
            offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, ",");
        }
        first = false;

        offset += FormatEx(msg[offset], MAX_MSG_LEN - offset,
            "{\"id\":%d,\"pos\":[%.1f,%.1f,%.1f],\"ang\":[%.1f,%.1f,%.1f],\"hp\":%d,\"alive\":%d,\"team\":%d}",
            client, pos[0], pos[1], pos[2], ang[0], ang[1], ang[2],
            health, alive ? 1 : 0, team);
    }

    offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, "]}");

    SocketSend(g_hSocket, msg);

    if (g_cvDebug.BoolValue && (g_iTickCount % 40 == 0))
    {
        LogMessage("[SmartBots] Sent tick=%d bots=%d alive=%d bytes=%d",
            g_iTickCount, botCount, aliveCount, offset);
    }

    return Plugin_Continue;
}
