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

#define PLUGIN_VERSION "0.2.0"
#define MAX_BOTS 64
#define MAX_MSG_LEN 8192
#define SEND_INTERVAL 0.125  // ~8Hz (recording only, no need for 32Hz)

// Lidar trace config
#define TRACE_DIRS 24
#define TRACE_RANGE 200.0
#define TRACE_STEP 15.0      // degrees between traces (360 / 24)
#define TRACE_NUM_HEIGHTS 2
// Heights: foot (z+8, hull covers z-8..z+24) and waist (z+32, hull covers z+16..z+48)
float g_fTraceHeights[TRACE_NUM_HEIGHTS] = { 8.0, 32.0 };

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
// Trace filter — ignore the bot entity itself
// ---------------------------------------------------------------------------

public bool TraceFilter_IgnoreSelf(int entity, int contentsMask, any data)
{
    return entity != view_as<int>(data);
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
            "{\"id\":%d,\"pos\":[%.1f,%.1f,%.1f],\"ang\":[%.1f,%.1f,%.1f],\"hp\":%d,\"alive\":%d,\"team\":%d",
            client, pos[0], pos[1], pos[2], ang[0], ang[1], ang[2],
            health, alive ? 1 : 0, team);

        // Cast hull traces at 2 heights × 24 directions (lidar scan)
        // Layout: [foot_0..foot_23, waist_0..waist_23] = 48 fractions
        if (alive)
        {
            offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, ",\"traces\":[");

            float mins[3], maxs[3];
            mins[0] = -4.0; mins[1] = -4.0; mins[2] = -16.0;
            maxs[0] = 4.0;  maxs[1] = 4.0;  maxs[2] = 16.0;

            bool firstFrac = true;
            for (int h = 0; h < TRACE_NUM_HEIGHTS; h++)
            {
                float start[3];
                start[0] = pos[0];
                start[1] = pos[1];
                start[2] = pos[2] + g_fTraceHeights[h];

                for (int t = 0; t < TRACE_DIRS; t++)
                {
                    float angle = float(t) * TRACE_STEP;
                    float rad = DegToRad(angle);

                    float end[3];
                    end[0] = start[0] + TRACE_RANGE * Cosine(rad);
                    end[1] = start[1] + Sine(rad) * TRACE_RANGE;
                    end[2] = start[2];

                    TR_TraceHullFilter(start, end, mins, maxs,
                        MASK_NPCSOLID, TraceFilter_IgnoreSelf, client);

                    float frac;
                    if (TR_StartSolid())
                        frac = 0.0;
                    else
                        frac = TR_GetFraction();

                    if (!firstFrac)
                        offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, ",");
                    firstFrac = false;
                    offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, "%.2f", frac);
                }
            }

            offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, "]");
        }

        offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, "}");
    }

    offset += FormatEx(msg[offset], MAX_MSG_LEN - offset, "]}");

    SocketSend(g_hSocket, msg);

    return Plugin_Continue;
}
