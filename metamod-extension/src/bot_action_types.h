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

// CINSBotActionCheckpoint::Update — same sret ABI as CINSBotCombat::Update
typedef void (*CINSBotActionCheckpoint_Update_t)(ActionResult *sret, void *thisptr, void *actor, float interval);

// CINSBotApproach constructor: takes Vector by value (3 floats on stack for x86-32)
// void CINSBotApproach::CINSBotApproach(void *this, float x, float y, float z)
typedef void (*CINSBotApproach_Ctor_t)(void *thisptr, float x, float y, float z);

// CINSBotInvestigate constructor: takes Vector by value (3 floats, same as Approach)
// Walks cautiously, checks threats more carefully, stealth movement
typedef void (*CINSBotInvestigate_Ctor_Vec_t)(void *thisptr, float x, float y, float z);

// CINSBotLocomotion::AddMovementRequest(Vector, INSBotMovementType, INSBotPriority, float)
// x86-32 cdecl: all args on stack, this = first arg
typedef void (*AddMovementRequest_t)(void *thisptr, float x, float y, float z,
                                     int moveType, int priority, float speed);

// IBody::AimHeadTowards(const Vector &target, int priority, float duration, INextBotReply*, const char*)
// x86-32 Linux/GCC: this + all args on stack
typedef void (*AimHeadTowards_t)(void *thisBody, const float *target,
                                  int priority, float duration,
                                  void *reply, const char *reason);

// Object sizes from class_data_layouts.md
static constexpr size_t CINSBOT_APPROACH_SIZE     = 128;  // last member at +0x60, pad to 128
static constexpr size_t CINSBOT_COMBAT_SIZE       = 136;  // 0x88
static constexpr size_t CINSBOT_INVESTIGATE_SIZE  = 0x4900;  // 18688 bytes — embeds CINSPathFollower with CNavPath (from decompiled operator_new calls)

// Command flags (Python → C++ via BotCommandEntry.flags)
static constexpr int CMD_FLAG_INVESTIGATE = 1;  // Use CINSBotInvestigate instead of CINSBotApproach

// Movement request constants (from decompiled CINSBotApproach::OnStart)
static constexpr int MOVE_TYPE_APPROACH = 6;
static constexpr int MOVE_PRIORITY_NORMAL = 8;
static constexpr float MOVE_SPEED_DEFAULT = 5.0f;

#endif // _SMARTBOTS_BOT_ACTION_TYPES_H_
