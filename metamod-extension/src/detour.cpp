#include "detour.h"
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

// x86 JMP rel32 opcode
static constexpr unsigned char JMP_OPCODE = 0xE9;
static constexpr size_t JMP_SIZE = 5;

// Trampoline layout (total 10 bytes):
//   [0..4] = saved original 5 bytes
//   [5..9] = JMP rel32 back to target+5
static constexpr size_t TRAMPOLINE_SIZE = 10;

static void *AllocExecutablePage()
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        return nullptr;
    return page;
}

static bool SetMemoryRWX(void *addr, size_t len)
{
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t page_end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    return mprotect((void *)page_start, page_end - page_start,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static void WriteJump(void *from, void *to)
{
    unsigned char *p = static_cast<unsigned char *>(from);
    p[0] = JMP_OPCODE;
    int32_t rel = (int32_t)((uintptr_t)to - (uintptr_t)from - JMP_SIZE);
    memcpy(p + 1, &rel, 4);
}

InlineDetour::InlineDetour()
    : m_target(nullptr)
    , m_hook(nullptr)
    , m_trampoline(nullptr)
    , m_installed(false)
{
    memset(m_saved, 0, sizeof(m_saved));
}

InlineDetour::~InlineDetour()
{
    Remove();
}

bool InlineDetour::Install(void *target, void *hook)
{
    if (m_installed || !target || !hook)
        return false;

    // Allocate executable page for trampoline
    m_trampoline = AllocExecutablePage();
    if (!m_trampoline)
        return false;

    // Save original 5 bytes
    memcpy(m_saved, target, JMP_SIZE);

    // Build trampoline: original bytes + JMP back to target+5
    unsigned char *tramp = static_cast<unsigned char *>(m_trampoline);
    memcpy(tramp, m_saved, JMP_SIZE);
    WriteJump(tramp + JMP_SIZE, static_cast<unsigned char *>(target) + JMP_SIZE);

    // Make target writable
    if (!SetMemoryRWX(target, JMP_SIZE))
    {
        long page_size = sysconf(_SC_PAGESIZE);
        munmap(m_trampoline, page_size);
        m_trampoline = nullptr;
        return false;
    }

    // Patch target with JMP to hook
    WriteJump(target, hook);

    m_target = target;
    m_hook = hook;
    m_installed = true;

    return true;
}

void InlineDetour::Remove()
{
    if (!m_installed)
        return;

    // Restore original bytes
    if (m_target)
    {
        SetMemoryRWX(m_target, JMP_SIZE);
        memcpy(m_target, m_saved, JMP_SIZE);
    }

    // Free trampoline
    if (m_trampoline)
    {
        long page_size = sysconf(_SC_PAGESIZE);
        munmap(m_trampoline, page_size);
        m_trampoline = nullptr;
    }

    m_installed = false;
}
