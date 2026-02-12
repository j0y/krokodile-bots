#ifndef _SMARTBOTS_SIG_RESOLVE_H_
#define _SMARTBOTS_SIG_RESOLVE_H_

#include <cstddef>
#include <cstdint>

// Resolve server module base address from dlopen handle via dlinfo/link_map.
// dl_iterate_phdr is NOT usable here — it matches MetaMod's stub server_srv.so
// instead of the real game binary (server_i486.so -> server_srv.so symlink).
uintptr_t GetServerModuleBaseFromHandle(void *handle);

// Offsets from `nm server_srv.so` (binary is frozen — Insurgency 2014)
struct ServerOffsets
{
    static constexpr uintptr_t CINSBotApproach_ctor   = 0x006e7490;
    static constexpr uintptr_t CINSBotCombat_Update   = 0x00706550;
    static constexpr uintptr_t CINSBotCombat_ctor     = 0x00705390;
    static constexpr uintptr_t CINSBotLocomotion_AddMovementRequest = 0x00750dd0;
};

// CINSNextBot vtable byte offset for GetLocomotionInterface virtual call
static constexpr uintptr_t kVtableOff_GetLocomotionInterface = 0x96c;

// CINSNextBot vtable byte offset for GetVisionInterface virtual call
static constexpr uintptr_t kVtableOff_GetVisionInterface = 0x974;

// CINSBotVision (IVision) vtable byte offsets
static constexpr uintptr_t kVtableOff_IVision_IsAbleToSee_Entity = 260;  // (CBaseEntity*, int checkFOV, Vector*)
static constexpr uintptr_t kVtableOff_IVision_IsAbleToSee_Pos    = 264;  // (const Vector&, int checkFOV)

// Verify first N bytes at address match expected prologue
bool VerifySignature(void *address, const unsigned char *expected, size_t len);

// Compute absolute address from base + offset
inline void *ResolveOffset(uintptr_t base, uintptr_t offset)
{
    return reinterpret_cast<void *>(base + offset);
}

#endif // _SMARTBOTS_SIG_RESOLVE_H_
