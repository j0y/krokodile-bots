#ifndef _SMARTBOTS_BOT_VOICE_H_
#define _SMARTBOTS_BOT_VOICE_H_

// Trigger a voice callout on a bot entity via SpeakConceptIfAllowed vtable dispatch.
// entityPtr must be a CINSNextBot* (CBaseEntity pointer).
// conceptId is the concept index (see reverseEngineering/analysis/voice-concepts.md).
// Returns true if the vtable call was dispatched.
bool BotVoice_Speak(void *entityPtr, int conceptId);

#endif // _SMARTBOTS_BOT_VOICE_H_
