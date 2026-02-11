#include "extension.h"
#include <dlfcn.h>

SmartBotsExtension g_Extension;
PLUGIN_EXPOSE(SmartBotsExtension, g_Extension);

// Engine interfaces
IServerGameDLL *g_pServerGameDLL = nullptr;
IVEngineServer *g_pEngineServer = nullptr;
IServerGameClients *g_pServerGameClients = nullptr;
IPlayerInfoManager *g_pPlayerInfoManager = nullptr;
ICvar *g_pCVar = nullptr;

// Server module handle
void *g_pServerHandle = nullptr;

bool SmartBotsExtension::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
    PLUGIN_SAVEVARS();

    GET_V_IFACE_CURRENT(GetEngineFactory, g_pEngineServer, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
    GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
    GET_V_IFACE_ANY(GetServerFactory, g_pServerGameDLL, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
    GET_V_IFACE_ANY(GetServerFactory, g_pServerGameClients, IServerGameClients, INTERFACEVERSION_SERVERGAMECLIENTS);
    GET_V_IFACE_ANY(GetServerFactory, g_pPlayerInfoManager, IPlayerInfoManager, INTERFACEVERSION_PLAYERINFOMANAGER);

    // Resolve server module for symbol lookups (constructors, Update methods, etc.)
    g_pServerHandle = dlopen("insurgency/bin/server_srv.so", RTLD_NOW | RTLD_NOLOAD);
    if (!g_pServerHandle)
    {
        snprintf(error, maxlen, "Failed to get server_srv.so handle: %s", dlerror());
        return false;
    }

    META_CONPRINTF("[SmartBots] Extension loaded (v0.1.0)\n");

    if (late)
    {
        META_CONPRINTF("[SmartBots] Late load - server already running\n");
    }

    return true;
}

void SmartBotsExtension::AllPluginsLoaded()
{
    META_CONPRINTF("[SmartBots] All plugins loaded\n");
}

bool SmartBotsExtension::Unload(char *error, size_t maxlen)
{
    if (g_pServerHandle)
    {
        dlclose(g_pServerHandle);
        g_pServerHandle = nullptr;
    }

    META_CONPRINTF("[SmartBots] Extension unloaded\n");
    return true;
}
