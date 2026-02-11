#include "sig_resolve.h"
#include <link.h>    // dl_iterate_phdr
#include <cstring>

// Callback data for dl_iterate_phdr
struct ModuleSearchData
{
    const char *name;
    uintptr_t   base;
};

static int FindModuleCallback(struct dl_phdr_info *info, size_t size, void *data)
{
    auto *search = static_cast<ModuleSearchData *>(data);

    if (info->dlpi_name && strstr(info->dlpi_name, search->name))
    {
        search->base = info->dlpi_addr;
        return 1; // stop iteration
    }

    return 0; // continue
}

uintptr_t GetServerModuleBase()
{
    ModuleSearchData search = { "server_srv.so", 0 };
    dl_iterate_phdr(FindModuleCallback, &search);
    return search.base;
}

bool VerifySignature(void *address, const unsigned char *expected, size_t len)
{
    if (!address || !expected || len == 0)
        return false;

    return memcmp(address, expected, len) == 0;
}
