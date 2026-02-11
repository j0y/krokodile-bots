#include "sig_resolve.h"
#include <link.h>    // struct link_map
#include <dlfcn.h>   // dlinfo
#include <cstring>

uintptr_t GetServerModuleBaseFromHandle(void *handle)
{
    if (!handle)
        return 0;

    struct link_map *lm = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) != 0 || !lm)
        return 0;

    return (uintptr_t)lm->l_addr;
}

bool VerifySignature(void *address, const unsigned char *expected, size_t len)
{
    if (!address || !expected || len == 0)
        return false;

    return memcmp(address, expected, len) == 0;
}
