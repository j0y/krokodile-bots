#ifndef _SMARTBOTS_DETOUR_H_
#define _SMARTBOTS_DETOUR_H_

#include <cstdint>
#include <cstddef>

// Minimal inline JMP rel32 detour for x86-32 Linux.
// Patches 5 bytes (E9 rel32) at the target to jump to the hook.
// Creates an executable trampoline to call the original function.
class InlineDetour
{
public:
    InlineDetour();
    ~InlineDetour();

    // Install detour: redirect `target` to `hook`.
    // Returns true on success.
    bool Install(void *target, void *hook);

    // Remove detour, restore original bytes.
    void Remove();

    // Get trampoline pointer to call the original function.
    void *GetTrampoline() const { return m_trampoline; }

    bool IsInstalled() const { return m_installed; }

private:
    void *m_target;
    void *m_hook;
    void *m_trampoline;       // mmap'd executable page
    unsigned char m_saved[5]; // original 5 bytes
    bool m_installed;
};

#endif // _SMARTBOTS_DETOUR_H_
