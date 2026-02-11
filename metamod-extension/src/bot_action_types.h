#ifndef _SMARTBOTS_BOT_ACTION_TYPES_H_
#define _SMARTBOTS_BOT_ACTION_TYPES_H_

#include <cstddef>
#include <cstdint>

// From NextBotBehavior.h — ActionResult<T> return type
enum ActionResultType
{
    ACTION_RESULT_CONTINUE   = 0,
    ACTION_RESULT_CHANGE_TO  = 1,
    ACTION_RESULT_SUSPEND_FOR = 2,
    ACTION_RESULT_DONE       = 3,
};

// ActionResult is returned by Update/OnStart/etc. via sret on x86-32.
// 12 bytes: type(4) + action*(4) + reason*(4)
struct ActionResult
{
    ActionResultType type;
    void            *action;    // Action<CINSNextBot>* — new action for CHANGE_TO/SUSPEND_FOR
    const char      *reason;    // debug string
};
static_assert(sizeof(ActionResult) == 12, "ActionResult must be 12 bytes (x86-32)");

// x86-32 GCC Linux ABI: struct > 8 bytes returned via hidden sret pointer.
// CINSBotCombat::Update real signature:
//   void Update(ActionResult *sret, void *this, void *actor, float interval)
// EAX = sret on return.
typedef void (*CINSBotCombat_Update_t)(ActionResult *sret, void *thisptr, void *actor, float interval);

// CINSBotApproach constructor: takes Vector by value (3 floats on stack for x86-32)
// void CINSBotApproach::CINSBotApproach(void *this, float x, float y, float z)
typedef void (*CINSBotApproach_Ctor_t)(void *thisptr, float x, float y, float z);

// Object sizes from class_data_layouts.md
static constexpr size_t CINSBOT_APPROACH_SIZE = 128;  // last member at +0x60, pad to 128
static constexpr size_t CINSBOT_COMBAT_SIZE   = 136;  // 0x88

#endif // _SMARTBOTS_BOT_ACTION_TYPES_H_
