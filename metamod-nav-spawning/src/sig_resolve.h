#ifndef _NAVSPAWNING_SIG_RESOLVE_H_
#define _NAVSPAWNING_SIG_RESOLVE_H_

#include <cstddef>
#include <cstdint>

// Resolve server module base address from dlopen handle via dlinfo/link_map.
uintptr_t GetServerModuleBaseFromHandle(void *handle);

// Offsets from `nm server_srv.so` (binary is frozen -- Insurgency 2014)
struct ServerOffsets
{
    // Hook target
    static constexpr uintptr_t CINSNextBot_Spawn              = 0x0073a3c0;

    // Nav mesh
    static constexpr uintptr_t TheNavMesh                      = 0x00c99800;
    static constexpr uintptr_t CNavMesh_GetNearestNavArea      = 0x004f20d0;
    static constexpr uintptr_t CNavArea_IsPotentiallyVisible   = 0x004ae260;
    static constexpr uintptr_t CNavArea_IsBlocked              = 0x004adc40;

    // Game rules (BSS)
    static constexpr uintptr_t g_pGameRules                    = 0x00c0c3d8;
    // CINSRules::IsCounterAttack() const -- non-virtual, thiscall
    static constexpr uintptr_t CINSRules_IsCounterAttack       = 0x0022e150;

    // CBaseEntity::GetTeamNumber() const -- local symbol, not exported (nm shows 't')
    static constexpr uintptr_t CBaseEntity_GetTeamNumber        = 0x003b96c0;
};

// CBaseFlex::Teleport vtable byte offset (from vtable_map.json)
static constexpr uintptr_t kVtableOff_Teleport = 464;

// Verify first N bytes at address match expected prologue
bool VerifySignature(void *address, const unsigned char *expected, size_t len);

// Compute absolute address from base + offset
inline void *ResolveOffset(uintptr_t base, uintptr_t offset)
{
    return reinterpret_cast<void *>(base + offset);
}

#endif // _NAVSPAWNING_SIG_RESOLVE_H_
