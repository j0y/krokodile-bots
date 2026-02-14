#include "bot_voice.h"

#include <ISmmPlugin.h>
#include <cstdint>
#include <cstddef>

extern ISmmAPI *g_SMAPI;   // from PLUGIN_EXPOSE macro

// SpeakConceptIfAllowed vtable offset (bytes from vtable start).
// Signature: int SpeakConceptIfAllowed(int concept, const char *modifiers,
//                                       char *outBuf, size_t bufSize,
//                                       IRecipientFilter *filter)
// x86-32 Linux/GCC: this + all args on stack.
static constexpr uintptr_t kVtableOff_SpeakConceptIfAllowed = 0x800;

typedef int (*SpeakConceptFn)(void *thisEntity, int conceptId,
                               const char *modifiers, char *outBuf,
                               size_t bufSize, void *filter);

// Complete concept ID mapping (extracted from g_pszMPConcepts[] in server_srv.so).
// IDs 0-62 are base Source SDK (TF2 heritage), 63-104 are Insurgency-specific.
//
// Voice lines are team-specific: the response rules engine picks different sound
// groups for Security vs Insurgent bots. The bot_chatter.txt rules also distinguish
// squad leaders (slot 0) from subordinates, and require nearby teammates for many
// callouts. The engine handles all of this — we just pass the concept ID.
//
// See reverseEngineering/analysis/voice-concepts.md for the full reference.
//
// Tactical posture callouts used by the Python planner:
//   82  (0x52) TLK_RADIAL_MOVING            — "Moving!"       (push)
//   94  (0x5e) TLK_RADIAL_GET_READY         — "Get ready!"    (ambush)
//   96  (0x60) TLK_RADIAL_WATCH_AREA        — "Watch that area" (sniper)
//   97  (0x61) TLK_RADIAL_GO                — "Go go go!"     (overrun)
//  101  (0x65) TLK_RADIAL_HOLD_POSITION     — "Hold position" (defend)
//
// 125 crashes the server — blocked below.

static bool IsCrashingConceptId(int id)
{
    return id == 125;
}

bool BotVoice_Speak(void *entityPtr, int conceptId)
{
    if (!entityPtr)
        return false;

    if (IsCrashingConceptId(conceptId))
    {
        META_CONPRINTF("[SmartBots] Voice: BLOCKED concept %d (0x%02x) — known crash\n",
                       conceptId, conceptId);
        return false;
    }

    void **vtable = *reinterpret_cast<void ***>(entityPtr);
    if (!vtable)
        return false;

    auto fn = reinterpret_cast<SpeakConceptFn>(
        vtable[kVtableOff_SpeakConceptIfAllowed / 4]);
    if (!fn)
        return false;

    fn(entityPtr, conceptId, nullptr, nullptr, 0, nullptr);
    return true;
}
