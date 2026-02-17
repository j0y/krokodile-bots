#ifndef _NAVSPAWNING_EXTENSION_H_
#define _NAVSPAWNING_EXTENSION_H_

#include <ISmmPlugin.h>

#include <eiface.h>
#include <igameevents.h>
#include <iplayerinfo.h>

class NavSpawningExtension : public ISmmPlugin
{
public:
    bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late);
    bool Unload(char *error, size_t maxlen);
    void AllPluginsLoaded();

public:
    void Hook_GameFrame(bool simulating);

public:
    const char *GetAuthor()      { return "NavSpawning"; }
    const char *GetName()        { return "Nav Mesh Spawning"; }
    const char *GetDescription() { return "Dynamic nav-based spawn positions for defender bots"; }
    const char *GetURL()         { return ""; }
    const char *GetLicense()     { return "MIT"; }
    const char *GetVersion()     { return "0.1.0"; }
    const char *GetDate()        { return __DATE__; }
    const char *GetLogTag()      { return "NAVSPAWN"; }
};

extern NavSpawningExtension g_Extension;

extern IServerGameDLL *g_pServerGameDLL;
extern IVEngineServer *g_pEngineServer;
extern IPlayerInfoManager *g_pPlayerInfoManager;
extern ICvar *g_pCVar;
extern CGlobalVars *gpGlobals;

extern void *g_pServerHandle;

inline edict_t *PEntityOfEntIndex(int iEntIndex)
{
    if (iEntIndex >= 0 && iEntIndex < gpGlobals->maxEntities)
        return (edict_t *)(gpGlobals->pEdicts + iEntIndex);
    return nullptr;
}

#endif // _NAVSPAWNING_EXTENSION_H_
