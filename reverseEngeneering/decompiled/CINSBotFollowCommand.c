/*
 * CINSBotFollowCommand -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 11
 */

/* ----------------------------------------
 * CINSBotFollowCommand::CINSBotFollowCommand
 * Address: 00720350
 * ---------------------------------------- */

/* CINSBotFollowCommand::CINSBotFollowCommand(eRadialCommands) */

void __thiscall
CINSBotFollowCommand::CINSBotFollowCommand(undefined4 param_1,int *param_2,int param_3)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  param_2[10] = 0;
  *param_2 = unaff_EBX + 0x476c4a /* vtable for CINSBotFollowCommand+0x8 */;
  param_2[1] = unaff_EBX + 0x476dda /* vtable for CINSBotFollowCommand+0x198 */;
  param_2[0x10] = (int)(&UNK_00407e5a + unaff_EBX);
  param_2[3] = 0;
  param_2[4] = 0;
  param_2[5] = 0;
  param_2[6] = 0;
  param_2[7] = 0;
  param_2[2] = 0;
  *(undefined1 *)(param_2 + 0xc) = 0;
  *(undefined1 *)((int)param_2 + 0x31) = 0;
  param_2[0xb] = 0;
  param_2[0xd] = 0;
  param_2[0x11] = 0;
  CountdownTimer::NetworkStateChanged(param_2 + 0x10);
  param_2[0x12] = -0x40800000;
  (**(code **)(param_2[0x10] + 4))(param_2 + 0x10,param_2 + 0x12);
  param_2[0xe] = param_3;
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::OnStart
 * Address: 007201d0
 * ---------------------------------------- */

/* CINSBotFollowCommand::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotFollowCommand::OnStart(CINSNextBot *param_1,Action *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  if (*(int *)(param_2 + 0x38) != -1) {
    param_2[0x3c] = (Action)0x0;
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return;
  }
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x261067 /* "No radial command!" */;
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::Update
 * Address: 00720170
 * ---------------------------------------- */

/* CINSBotFollowCommand::Update(CINSNextBot*, float) */

CINSNextBot * CINSBotFollowCommand::Update(CINSNextBot *param_1,float param_2)

{
  __i686_get_pc_thunk_bx();
  CountdownTimer::Now();
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotFollowCommand::OnEnd
 * Address: 00720160
 * ---------------------------------------- */

/* CINSBotFollowCommand::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotFollowCommand::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::OnSuspend
 * Address: 00720140
 * ---------------------------------------- */

/* CINSBotFollowCommand::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotFollowCommand::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::OnResume
 * Address: 00720110
 * ---------------------------------------- */

/* CINSBotFollowCommand::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotFollowCommand::OnResume(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  param_2[0x3c] = (Action)0x0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::GetName
 * Address: 00720430
 * ---------------------------------------- */

/* CINSBotFollowCommand::GetName() const */

int CINSBotFollowCommand::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x260df9 /* "FollowCommand" */;
}



/* ----------------------------------------
 * CINSBotFollowCommand::~CINSBotFollowCommand
 * Address: 00720450
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFollowCommand::~CINSBotFollowCommand() */

void __thiscall CINSBotFollowCommand::~CINSBotFollowCommand(CINSBotFollowCommand *this)

{
  ~CINSBotFollowCommand(this);
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::~CINSBotFollowCommand
 * Address: 00720460
 * ---------------------------------------- */

/* CINSBotFollowCommand::~CINSBotFollowCommand() */

void __thiscall CINSBotFollowCommand::~CINSBotFollowCommand(CINSBotFollowCommand *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x476b43 /* vtable for CINSBotFollowCommand+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x476cd3 /* vtable for CINSBotFollowCommand+0x198 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x486d13 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::~CINSBotFollowCommand
 * Address: 00720490
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFollowCommand::~CINSBotFollowCommand() */

void __thiscall CINSBotFollowCommand::~CINSBotFollowCommand(CINSBotFollowCommand *this)

{
  ~CINSBotFollowCommand(this);
  return;
}



/* ----------------------------------------
 * CINSBotFollowCommand::~CINSBotFollowCommand
 * Address: 007204a0
 * ---------------------------------------- */

/* CINSBotFollowCommand::~CINSBotFollowCommand() */

void __thiscall CINSBotFollowCommand::~CINSBotFollowCommand(CINSBotFollowCommand *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x476afa /* vtable for CINSBotFollowCommand+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x476c8a /* vtable for CINSBotFollowCommand+0x198 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



