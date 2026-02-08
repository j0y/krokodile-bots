/**
 * SmartBots Bridge — SourceMod ↔ Python AI UDP bridge
 *
 * Collects bot state at ~8Hz and sends it to the Python AI brain via UDP.
 * Receives movement commands back and applies them in OnPlayerRunCmd.
 */

#include <sourcemod>
#include <sdktools>
#include <sdkhooks>
#include <socket>

#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION "0.1.0"
#define MAX_BOTS 64
#define MAX_MSG_LEN 4096
#define SEND_INTERVAL 0.125  // ~8Hz
#define ARRIVAL_DIST 50.0
#define DEADZONE 0.25
#define DEFAULT_MAXSPEED 250.0

public Plugin myinfo = {
    name = "SmartBots Bridge",
    author = "SmartBots",
    description = "UDP bridge between game bots and Python AI brain",
    version = PLUGIN_VERSION,
    url = ""
};

// ConVars
ConVar g_cvAIHost;
ConVar g_cvAIPort;

// Socket
Handle g_hSocket = INVALID_HANDLE;
bool g_bSocketReady = false;

// Per-bot command storage
bool g_bHasCommand[MAX_BOTS + 1];
float g_fTargetPos[MAX_BOTS + 1][3];
float g_fTargetSpeed[MAX_BOTS + 1];

// Tick counter for state messages
int g_iTickCount = 0;

public void OnPluginStart()
{
    g_cvAIHost = CreateConVar("sm_smartbots_host", "127.0.0.1",
        "AI brain host address");
    g_cvAIPort = CreateConVar("sm_smartbots_port", "9000",
        "AI brain port", _, true, 1.0, true, 65535.0);

    // Clear command state
    for (int i = 0; i <= MAX_BOTS; i++)
    {
        g_bHasCommand[i] = false;
        g_fTargetSpeed[i] = 0.0;
    }

    // Connect after a short delay to let the server finish loading
    CreateTimer(3.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);

    LogMessage("[SmartBots] Plugin loaded (v%s)", PLUGIN_VERSION);
}

public void OnPluginEnd()
{
    if (g_hSocket != INVALID_HANDLE)
    {
        CloseHandle(g_hSocket);
        g_hSocket = INVALID_HANDLE;
        g_bSocketReady = false;
    }
}

public void OnMapStart()
{
    // Reconnect on map change if needed
    if (!g_bSocketReady)
    {
        CreateTimer(3.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
    }
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

    // Start the state-send timer
    CreateTimer(SEND_INTERVAL, Timer_SendState, _, TIMER_REPEAT | TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketDisconnected(Handle socket, any arg)
{
    g_bSocketReady = false;
    LogMessage("[SmartBots] Disconnected from AI brain, reconnecting...");
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketError(Handle socket, const int errorType, const int errorNum, any arg)
{
    g_bSocketReady = false;
    LogError("[SmartBots] Socket error: type=%d errno=%d", errorType, errorNum);
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

// ---------------------------------------------------------------------------
// Receive commands from Python
//
// Format: one bot per line — "id x y z speed\n"
// Example: "3 2000.0 -300.0 64.0 1.0\n5 1500.0 -200.0 64.0 0.5\n"
// ---------------------------------------------------------------------------

public void OnSocketReceive(Handle socket, const char[] receiveData,
    const int dataSize, any arg)
{
    // Split into lines
    char lines[MAX_BOTS][128];
    int count = ExplodeString(receiveData, "\n", lines, MAX_BOTS, 128);

    for (int i = 0; i < count; i++)
    {
        TrimString(lines[i]);
        if (strlen(lines[i]) == 0)
            continue;

        // Parse: "id x y z speed"
        char parts[5][32];
        int numParts = ExplodeString(lines[i], " ", parts, 5, 32);
        if (numParts < 5)
            continue;

        int botId = StringToInt(parts[0]);
        if (botId < 1 || botId > MaxClients)
            continue;

        g_fTargetPos[botId][0] = StringToFloat(parts[1]);
        g_fTargetPos[botId][1] = StringToFloat(parts[2]);
        g_fTargetPos[botId][2] = StringToFloat(parts[3]);
        g_fTargetSpeed[botId] = StringToFloat(parts[4]);
        g_bHasCommand[botId] = true;
    }
}

// ---------------------------------------------------------------------------
// Send state to Python (~8Hz)
//
// JSON: {"tick":N,"bots":[{"id":N,"pos":[x,y,z],"ang":[p,y,r],"hp":N,"alive":N,"team":N},...]}
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
    for (int client = 1; client <= MaxClients; client++)
    {
        if (!IsClientInGame(client))
            continue;
        if (!IsFakeClient(client))
            continue;

        // Get state
        float pos[3], ang[3];
        GetClientAbsOrigin(client, pos);
        GetClientAbsAngles(client, ang);
        int health = GetClientHealth(client);
        int team = GetClientTeam(client);
        bool alive = IsPlayerAlive(client);

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
    return Plugin_Continue;
}

// ---------------------------------------------------------------------------
// OnPlayerRunCmd — apply movement commands to bots
// ---------------------------------------------------------------------------

public Action OnPlayerRunCmd(int client, int &buttons, int &impulse,
    float vel[3], float angles[3], int &weapon, int &subtype,
    int &cmdnum, int &tickcount, int &seed, int mouse[2])
{
    if (!IsFakeClient(client))
        return Plugin_Continue;
    if (!IsPlayerAlive(client))
        return Plugin_Continue;
    if (!g_bHasCommand[client])
        return Plugin_Continue;

    // Get bot position
    float pos[3];
    GetClientAbsOrigin(client, pos);

    // Direction to target (2D)
    float dx = g_fTargetPos[client][0] - pos[0];
    float dy = g_fTargetPos[client][1] - pos[1];
    float dist = SquareRoot(dx * dx + dy * dy);

    // Arrival check
    if (dist < ARRIVAL_DIST)
    {
        vel[0] = 0.0;
        vel[1] = 0.0;
        vel[2] = 0.0;
        return Plugin_Changed;
    }

    // Normalize direction
    float dirX = dx / dist;
    float dirY = dy / dist;

    // Get max speed
    float maxspeed = GetEntPropFloat(client, Prop_Data, "m_flMaxspeed");
    if (maxspeed <= 0.0)
        maxspeed = DEFAULT_MAXSPEED;
    maxspeed *= g_fTargetSpeed[client];

    // Bot's current forward vector from yaw
    float yawRad = DegToRad(angles[1]);
    float fwdX = Cosine(yawRad);
    float fwdY = Sine(yawRad);

    // Right vector (perpendicular)
    float rightX = fwdY;
    float rightY = -fwdX;

    // Decompose desired direction into forward/side components
    float fwdDot = dirX * fwdX + dirY * fwdY;
    float rightDot = dirX * rightX + dirY * rightY;

    // Apply deadzone
    if (FloatAbs(fwdDot) < DEADZONE)
        fwdDot = 0.0;
    if (FloatAbs(rightDot) < DEADZONE)
        rightDot = 0.0;

    vel[0] = fwdDot * maxspeed;
    vel[1] = rightDot * maxspeed;
    vel[2] = 0.0;

    // Turn bot to face target
    float targetYaw = RadToDeg(ArcTangent2(dirY, dirX));
    angles[1] = targetYaw;

    return Plugin_Changed;
}
