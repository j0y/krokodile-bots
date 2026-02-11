#ifndef _SMARTBOTS_EXTENSION_H_
#define _SMARTBOTS_EXTENSION_H_

// META_NO_HL2SDK: ISmmPlugin.h uses its own CreateInterface with visibility attr.
// We include HL2SDK headers manually below for engine interfaces.
#include <ISmmPlugin.h>

// HL2SDK headers (not auto-included under META_NO_HL2SDK)
#include <eiface.h>
#include <igameevents.h>
#include <iplayerinfo.h>

class SmartBotsExtension : public ISmmPlugin
{
public:
    bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late);
    bool Unload(char *error, size_t maxlen);
    void AllPluginsLoaded();

public:
    const char *GetAuthor()      { return "SmartBots"; }
    const char *GetName()        { return "SmartBots Coordinator"; }
    const char *GetDescription() { return "Team coordination via native bot actions"; }
    const char *GetURL()         { return ""; }
    const char *GetLicense()     { return "MIT"; }
    const char *GetVersion()     { return "0.1.0"; }
    const char *GetDate()        { return __DATE__; }
    const char *GetLogTag()      { return "SMARTBOTS"; }
};

extern SmartBotsExtension g_Extension;

// Engine interfaces
extern IServerGameDLL *g_pServerGameDLL;
extern IVEngineServer *g_pEngineServer;
extern IServerGameClients *g_pServerGameClients;
extern IPlayerInfoManager *g_pPlayerInfoManager;
extern ICvar *g_pCVar;

// Server module handle for symbol resolution (dlsym)
extern void *g_pServerHandle;

#endif // _SMARTBOTS_EXTENSION_H_
