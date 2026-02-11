#ifndef _SMARTBOTS_SIG_RESOLVE_H_
#define _SMARTBOTS_SIG_RESOLVE_H_

#include <cstddef>
#include <cstdint>

// Resolve server_srv.so base address via dl_iterate_phdr
uintptr_t GetServerModuleBase();

// Offsets from `nm server_srv.so` (binary is frozen — Insurgency 2014)
struct ServerOffsets
{
    static constexpr uintptr_t CINSBotApproach_ctor   = 0x006e7490;
    static constexpr uintptr_t CINSBotCombat_Update   = 0x00706550;
    static constexpr uintptr_t CINSBotCombat_ctor     = 0x00705390;
};

// Verify first N bytes at address match expected prologue
bool VerifySignature(void *address, const unsigned char *expected, size_t len);

// Compute absolute address from base + offset
inline void *ResolveOffset(uintptr_t base, uintptr_t offset)
{
    return reinterpret_cast<void *>(base + offset);
}

#endif // _SMARTBOTS_SIG_RESOLVE_H_
