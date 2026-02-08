/**
 * SmartBots Observer — lightweight position recorder
 *
 * Sends bot positions to the Python AI brain over UDP for spatial recording.
 * No detours, no command processing, no interference with the original AI.
 * Use this instead of smartbots_bridge.smx when you want the game's native
 * bot AI to run while recording walkable positions to DuckDB.
 */

#include <sourcemod>
#include <sdktools>
#include <socket>

#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION "0.1.0"
#define MAX_BOTS 64
#define MAX_MSG_LEN 4096
#define SEND_INTERVAL 0.125  // ~8Hz (recording only, no need for 32Hz)

public Plugin myinfo = {
    name = "SmartBots Observer",
    author = "SmartBots",
    description = "Sends bot positions to Python AI brain for spatial recording",
    version = PLUGIN_VERSION,
    url = ""
};

ConVar g_cvAIHost;
ConVar g_cvAIPort;

Handle g_hSocket = INVALID_HANDLE;
bool g_bSocketReady = false;
int g_iTickCount = 0;

public void OnPluginStart()
{
    g_cvAIHost = CreateConVar("sm_smartbots_host", "127.0.0.1",
        "AI brain host address");
    g_cvAIPort = CreateConVar("sm_smartbots_port", "9000",
        "AI brain port", _, true, 1.0, true, 65535.0);

    CreateTimer(3.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);

    LogMessage("[SmartBots Observer] Plugin loaded (v%s)", PLUGIN_VERSION);
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
        LogError("[SmartBots Observer] Failed to create UDP socket");
        CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
        return;
    }

    char host[64];
    g_cvAIHost.GetString(host, sizeof(host));
    int port = g_cvAIPort.IntValue;

    LogMessage("[SmartBots Observer] Connecting to AI brain at %s:%d", host, port);
    SocketConnect(g_hSocket, OnSocketConnected, OnSocketReceive,
        OnSocketDisconnected, host, port);
}

public void OnSocketConnected(Handle socket, any arg)
{
    g_bSocketReady = true;
    LogMessage("[SmartBots Observer] Connected to AI brain");

    CreateTimer(SEND_INTERVAL, Timer_SendState, _,
        TIMER_REPEAT | TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketDisconnected(Handle socket, any arg)
{
    g_bSocketReady = false;
    LogMessage("[SmartBots Observer] Disconnected, reconnecting...");
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketError(Handle socket, const int errorType,
    const int errorNum, any arg)
{
    g_bSocketReady = false;
    LogError("[SmartBots Observer] Socket error: type=%d errno=%d", errorType, errorNum);
    CreateTimer(5.0, Timer_Connect, _, TIMER_FLAG_NO_MAPCHANGE);
}

public void OnSocketReceive(Handle socket, const char[] receiveData,
    const int dataSize, any arg)
{
    // Ignore any commands from Python — we're observe-only
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
