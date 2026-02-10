/*
 * CINSBotSpecialAction -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotSpecialAction::CINSBotSpecialAction
 * Address: 00731370
 * ---------------------------------------- */

/* CINSBotSpecialAction::CINSBotSpecialAction(BotSpecialActions, bool) */

void __thiscall
CINSBotSpecialAction::CINSBotSpecialAction
          (undefined4 param_1,int *param_2,int param_3,undefined1 param_4)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  *param_2 = unaff_EBX + 0x4671ad /* vtable for CINSBotSpecialAction+0x8 */;
  param_2[1] = unaff_EBX + 0x46733d /* vtable for CINSBotSpecialAction+0x198 */;
  param_2[0xf] = unaff_EBX + 0x3f6e3d /* vtable for CountdownTimer+0x8 */;
  param_2[9] = 0;
  param_2[10] = 0;
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
  param_2[0x10] = 0;
  (*(code *)(unaff_EBX + -0x500c0b /* CountdownTimer::NetworkStateChanged */))(param_2 + 0xf,param_2 + 0x10);
  param_2[0x11] = -0x40800000 /* -1.0f */;
  (**(code **)(param_2[0xf] + 4))(param_2 + 0xf,param_2 + 0x11);
  param_2[0x13] = 0;
  param_2[0x12] = unaff_EBX + 0x3f6e3d /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x500c0b /* CountdownTimer::NetworkStateChanged */))(param_2 + 0x12,param_2 + 0x13);
  param_2[0x14] = -0x40800000 /* -1.0f */;
  (**(code **)(param_2[0x12] + 4))(param_2 + 0x12,param_2 + 0x14);
  param_2[0xe] = param_3;
  *(undefined1 *)(param_2 + 0x15) = param_4;
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::OnStart
 * Address: 007310d0
 * ---------------------------------------- */

/* CINSBotSpecialAction::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotSpecialAction::OnStart(CINSNextBot *param_1,Action *param_2)

{
  int unaff_EBX;
  float10 fVar1;
  float fVar2;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(param_2 + 0x38) == 1) {
    fVar1 = (float10)CountdownTimer::Now();
    fVar2 = (float)fVar1 + *(float *)(unaff_EBX + 0x1f3691 /* typeinfo name for CBaseGameSystem+0x32 */);
    if (*(float *)(param_2 + 0x44) != fVar2) {
      (**(code **)(*(int *)(param_2 + 0x3c) + 4))(param_2 + 0x3c,param_2 + 0x44);
      *(float *)(param_2 + 0x44) = fVar2;
    }
    if (*(int *)(param_2 + 0x40) != 0x40a00000 /* 5.0f */) {
      (**(code **)(*(int *)(param_2 + 0x3c) + 4))(param_2 + 0x3c,param_2 + 0x40);
      *(undefined4 *)(param_2 + 0x40) = 0x40a00000 /* 5.0f */;
    }
    fVar1 = (float10)CountdownTimer::Now();
    fVar2 = (float)fVar1 + *(float *)(unaff_EBX + 0x187ea1 /* typeinfo name for IServerBenchmark+0x13 */);
    if (*(float *)(param_2 + 0x50) != fVar2) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x50);
      *(float *)(param_2 + 0x50) = fVar2;
    }
    if (*(int *)(param_2 + 0x4c) != 0x40400000 /* 3.0f */) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x4c);
      *(undefined4 *)(param_2 + 0x4c) = 0x40400000 /* 3.0f */;
    }
    param_2[0x54] = (Action)0x0;
  }
  else {
    fVar1 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x40a00000 /* 5.0f */);
    fVar2 = (float)fVar1;
    fVar1 = (float10)CountdownTimer::Now();
    if (*(float *)(param_2 + 0x44) != (float)fVar1 + fVar2) {
      (**(code **)(*(int *)(param_2 + 0x3c) + 4))(param_2 + 0x3c,param_2 + 0x44);
      *(float *)(param_2 + 0x44) = (float)fVar1 + fVar2;
    }
    if (*(float *)(param_2 + 0x40) != fVar2) {
      (**(code **)(*(int *)(param_2 + 0x3c) + 4))(param_2 + 0x3c,param_2 + 0x40);
      *(float *)(param_2 + 0x40) = fVar2;
    }
    fVar1 = (float10)CountdownTimer::Now();
    fVar2 = (float)fVar1 + *(float *)(unaff_EBX + 0x187a39 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
    if (*(float *)(param_2 + 0x50) != fVar2) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x50);
      *(float *)(param_2 + 0x50) = fVar2;
    }
    if (*(int *)(param_2 + 0x4c) != 0x3f800000 /* 1.0f */) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x4c);
      *(undefined4 *)(param_2 + 0x4c) = 0x3f800000 /* 1.0f */;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSpecialAction::Update
 * Address: 00730f90
 * ---------------------------------------- */

/* CINSBotSpecialAction::Update(CINSNextBot*, float) */

CINSNextBot * CINSBotSpecialAction::Update(CINSNextBot *param_1,float param_2)

{
  int unaff_EBX;
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)CountdownTimer::Now();
  if ((float)fVar1 < *(float *)((int)param_2 + 0x44) ||
      (float)fVar1 == *(float *)((int)param_2 + 0x44)) {
    fVar1 = (float10)CountdownTimer::Now();
    if ((*(float *)((int)param_2 + 0x50) <= (float)fVar1 &&
         (float)fVar1 != *(float *)((int)param_2 + 0x50)) &&
       (*(char *)((int)param_2 + 0x54) == '\0')) {
      *(undefined1 *)((int)param_2 + 0x54) = 1;
    }
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_00250de0 + unaff_EBX;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotSpecialAction::OnEnd
 * Address: 00730ed0
 * ---------------------------------------- */

/* CINSBotSpecialAction::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotSpecialAction::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int iVar2;
  CBaseEntity *this;
  
  __i686_get_pc_thunk_bx();
  if (param_2 != (Action *)0x0) {
    cVar1 = (**(code **)(*(int *)param_2 + 0x118))(param_2);
    if ((cVar1 != '\0') && (*(int *)(param_1 + 0x38) == 1)) {
      CBaseEntity::GetTeamNumber(this);
      iVar2 = TheINSNextBots();
      CINSNextBotManager::CallForReinforcements(iVar2);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::OnSuspend
 * Address: 00730eb0
 * ---------------------------------------- */

/* CINSBotSpecialAction::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotSpecialAction::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::OnResume
 * Address: 00730e90
 * ---------------------------------------- */

/* CINSBotSpecialAction::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotSpecialAction::OnResume(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::GetName
 * Address: 007314a0
 * ---------------------------------------- */

/* CINSBotSpecialAction::GetName() const */

int CINSBotSpecialAction::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2508ca /* "Special Action" */;
}



/* ----------------------------------------
 * CINSBotSpecialAction::OnInjured
 * Address: 00730f40
 * ---------------------------------------- */

/* CINSBotSpecialAction::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotSpecialAction::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  if (param_2[0x54] == (CTakeDamageInfo)0x0) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
    return;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::~CINSBotSpecialAction
 * Address: 007314c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSpecialAction::~CINSBotSpecialAction() */

void __thiscall CINSBotSpecialAction::~CINSBotSpecialAction(CINSBotSpecialAction *this)

{
  ~CINSBotSpecialAction(this);
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::~CINSBotSpecialAction
 * Address: 007314d0
 * ---------------------------------------- */

/* CINSBotSpecialAction::~CINSBotSpecialAction() */

void __thiscall CINSBotSpecialAction::~CINSBotSpecialAction(CINSBotSpecialAction *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x467053 /* vtable for CINSBotSpecialAction+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x4671e3 /* vtable for CINSBotSpecialAction+0x198 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(&UNK_00475ca3 + extraout_ECX));
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::~CINSBotSpecialAction
 * Address: 00731500
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSpecialAction::~CINSBotSpecialAction() */

void __thiscall CINSBotSpecialAction::~CINSBotSpecialAction(CINSBotSpecialAction *this)

{
  ~CINSBotSpecialAction(this);
  return;
}



/* ----------------------------------------
 * CINSBotSpecialAction::~CINSBotSpecialAction
 * Address: 00731510
 * ---------------------------------------- */

/* CINSBotSpecialAction::~CINSBotSpecialAction() */

void __thiscall CINSBotSpecialAction::~CINSBotSpecialAction(CINSBotSpecialAction *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0046700a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x46719a /* vtable for CINSBotSpecialAction+0x198 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



