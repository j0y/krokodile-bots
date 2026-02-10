/*
 * CINSBotPursue -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 20
 */

/* ----------------------------------------
 * CINSBotPursue::CINSBotPursue
 * Address: 0072a780
 * ---------------------------------------- */

/* CINSBotPursue::CINSBotPursue() */

void __thiscall CINSBotPursue::CINSBotPursue(CINSBotPursue *this)

{
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  in_stack_00000004[10] = 0;
  *in_stack_00000004 = unaff_EBX + 0x46d3ba /* vtable for CINSBotPursue+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46d552 /* vtable for CINSBotPursue+0x1a0 */;
  in_stack_00000004[0xe] = unaff_EBX + 0x3fda2a /* vtable for CountdownTimer+0x8 */;
  in_stack_00000004[3] = 0;
  in_stack_00000004[4] = 0;
  in_stack_00000004[5] = 0;
  in_stack_00000004[6] = 0;
  in_stack_00000004[7] = 0;
  in_stack_00000004[2] = 0;
  *(undefined1 *)(in_stack_00000004 + 0xc) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x31) = 0;
  in_stack_00000004[0xb] = 0;
  in_stack_00000004[0xd] = 0;
  in_stack_00000004[0xf] = 0;
  CountdownTimer::NetworkStateChanged(in_stack_00000004 + 0xe);
  in_stack_00000004[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0xe] + 4))(in_stack_00000004 + 0xe,in_stack_00000004 + 0x10);
  *(undefined1 *)(in_stack_00000004 + 0x16) = 0;
  in_stack_00000004[0x15] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x14] = -1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnStart
 * Address: 0072a100
 * ---------------------------------------- */

/* CINSBotPursue::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotPursue::OnStart(CINSBotPursue *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  int unaff_EBX;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar2,0);
  if (piVar2 == (int *)0x0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2575af /* "No Known Threats" */;
    *(undefined4 *)(param_1 + 4) = 0;
    return param_1;
  }
  puVar3 = (undefined4 *)(**(code **)(*piVar2 + 0x14))(piVar2);
  uVar4 = (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
  CINSBotLocomotion::AddMovementRequest(uVar4,*puVar3,puVar3[1],puVar3[2],9,3,0x40a00000 /* 5.0f */);
  CINSNextBot::ResetIdleStatus(this_00);
  *(int *)(param_2 + 0x50) = in_stack_0000000c[0x2cce];
  cVar1 = CINSNextBot::IsEscorting(this_01);
  if (cVar1 == '\0') {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x257605 /* "I should not be pursuing while escorting" */;
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPursue::Update
 * Address: 0072a350
 * ---------------------------------------- */

/* CINSBotPursue::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotPursue::Update(CINSBotPursue *this,CINSNextBot *param_1,float param_2)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  float *pfVar6;
  int *piVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSPlayer *this_02;
  CINSNextBot *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar10 = (float10)CountdownTimer::Now();
  if ((float)fVar10 < *(float *)((int)param_2 + 0x40) ||
      (float)fVar10 == *(float *)((int)param_2 + 0x40)) goto LAB_0072a550;
  if ((in_stack_0000000c[0x2cce] == -1) ||
     (iVar3 = UTIL_EntityByIndex(in_stack_0000000c[0x2cce]), iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) || (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), iVar3 == 0))
    goto LAB_0072a5b0;
  }
  iVar4 = 0;
  if (*(int *)(iVar3 + 0x20) != 0) {
    iVar4 = *(int *)(iVar3 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x47c542 /* &gpGlobals */) + 0x5c) >> 4;
  }
  if (*(int *)((int)param_2 + 0x50) != iVar4) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_0025736d + unaff_EBX;
    return param_1;
  }
  piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar5 = (int *)(**(code **)(*piVar5 + 0xe4 /* IVision::GetKnown */))(piVar5,iVar3);
  if (piVar5 == (int *)0x0) {
LAB_0072a5b0:
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_0025735c + unaff_EBX;
    return param_1;
  }
  cVar2 = (**(code **)(*piVar5 + 0x38))(piVar5);
  this_00 = extraout_ECX;
  if (cVar2 != '\0') {
    piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar3 = (**(code **)(*piVar7 + 0xd4 /* IIntention::ShouldAttack */))(piVar7,in_stack_0000000c + 0x818,piVar5);
    this_00 = extraout_ECX_00;
    if (iVar3 != 0) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined **)(param_1 + 8) = &UNK_0025738b + unaff_EBX;
      return param_1;
    }
  }
  cVar2 = CINSNextBot::IsIdle(this_00);
  if ((cVar2 != '\0') &&
     (fVar10 = (float10)CINSNextBot::GetIdleDuration(this_01),
     *(float *)(unaff_EBX + 0x1fa40e /* typeinfo name for CBaseGameSystem+0x32 */) <= (float)fVar10 &&
     (float)fVar10 != *(float *)(unaff_EBX + 0x1fa40e /* typeinfo name for CBaseGameSystem+0x32 */))) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_002573a3 + unaff_EBX;
    return param_1;
  }
  pfVar6 = (float *)(**(code **)(*piVar5 + 0x14))(piVar5);
  fVar13 = *pfVar6 - *(float *)((int)param_2 + 0x44);
  fVar11 = pfVar6[1] - *(float *)((int)param_2 + 0x48);
  fVar12 = pfVar6[2] - *(float *)((int)param_2 + 0x4c);
  fVar11 = SQRT(fVar11 * fVar11 + fVar13 * fVar13 + fVar12 * fVar12);
  cVar2 = CINSPlayer::IsMoving(this_02);
  bVar1 = true;
  if (cVar2 != '\0') {
    bVar1 = *(float *)(unaff_EBX + 0x20daba /* typeinfo name for CUseTraceFilter+0x19 */) <= fVar11 && fVar11 != *(float *)(unaff_EBX + 0x20daba /* typeinfo name for CUseTraceFilter+0x19 */)
    ;
  }
  piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
  cVar2 = (**(code **)(*piVar7 + 0x128 /* CINSBotBody::IsPostureMobile */))(piVar7);
  if (cVar2 == '\0') {
    piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    (**(code **)(*piVar7 + 0x110 /* CINSBotBody::SetDesiredPosture */))(piVar7,0xc);
LAB_0072a67c:
    puVar8 = (undefined4 *)(**(code **)(*piVar5 + 0x14))(piVar5);
    uVar9 = (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
    CINSBotLocomotion::AddMovementRequest(uVar9,*puVar8,puVar8[1],puVar8[2],9,3,0x40a00000 /* 5.0f */);
    puVar8 = (undefined4 *)(**(code **)(*piVar5 + 0x14))(piVar5);
    *(undefined4 *)((int)param_2 + 0x44) = *puVar8;
    *(undefined4 *)((int)param_2 + 0x48) = puVar8[1];
    *(undefined4 *)((int)param_2 + 0x4c) = puVar8[2];
  }
  else if (bVar1) goto LAB_0072a67c;
  fVar10 = (float10)CountdownTimer::Now();
  fVar11 = (float)fVar10 + *(float *)(unaff_EBX + 0x18e7b6 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
  if (*(float *)((int)param_2 + 0x40) != fVar11) {
    (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40);
    *(float *)((int)param_2 + 0x40) = fVar11;
  }
  if (*(int *)((int)param_2 + 0x3c) != 0x3f800000 /* 1.0f */) {
    (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c);
    *(undefined4 *)((int)param_2 + 0x3c) = 0x3f800000 /* 1.0f */;
  }
LAB_0072a550:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPursue::OnEnd
 * Address: 00729f60
 * ---------------------------------------- */

/* CINSBotPursue::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotPursue::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnSuspend
 * Address: 00729f40
 * ---------------------------------------- */

/* CINSBotPursue::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotPursue::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::GetName
 * Address: 0072a870
 * ---------------------------------------- */

/* CINSBotPursue::GetName() const */

int CINSBotPursue::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x256e37 /* "Pursue Threat" */;
}



/* ----------------------------------------
 * CINSBotPursue::ShouldHurry
 * Address: 0072a220
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPursue::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotPursue::ShouldHurry(CINSBotPursue *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotPursue::ShouldHurry
 * Address: 0072a230
 * ---------------------------------------- */

/* CINSBotPursue::ShouldHurry(INextBot const*) const */

byte __cdecl CINSBotPursue::ShouldHurry(INextBot *param_1)

{
  byte bVar1;
  int iVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(**(int **)(unaff_EBX + 0x47c30e /* &ins_bot_knives_only */) + 0x40))(*(int **)(unaff_EBX + 0x47c30e /* &ins_bot_knives_only */));
  if (iVar2 == 0) {
    bVar1 = 2;
    if (param_1[0x58] == (INextBot)0x0) {
      return ~-(*(float *)(unaff_EBX + 0x25750e /* typeinfo name for CINSBotPursue+0x13 */) < *(float *)(param_1 + 0x54)) & 2;
    }
  }
  else {
    bVar1 = *(float *)(unaff_EBX + 0x1fb59a /* typeinfo name for IPlayerAnimState+0x2f */) <= *(float *)(param_1 + 0x54) &&
            *(float *)(param_1 + 0x54) != *(float *)(unaff_EBX + 0x1fb59a /* typeinfo name for IPlayerAnimState+0x2f */);
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSBotPursue::OnContact
 * Address: 0072a050
 * ---------------------------------------- */

/* CINSBotPursue::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotPursue::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnMoveToSuccess
 * Address: 00729fd0
 * ---------------------------------------- */

/* CINSBotPursue::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotPursue::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x25746b /* "Arrived at investigation target." */;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnMoveToFailure
 * Address: 0072a010
 * ---------------------------------------- */

/* CINSBotPursue::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotPursue::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = &UNK_0025744f + extraout_ECX;
  param_1[3] = 3;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnStuck
 * Address: 00729fa0
 * ---------------------------------------- */

/* CINSBotPursue::OnStuck(CINSNextBot*) */

void CINSBotPursue::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnLostSight
 * Address: 00729f70
 * ---------------------------------------- */

/* CINSBotPursue::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotPursue::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::OnNavAreaChanged
 * Address: 0072a080
 * ---------------------------------------- */

/* CINSBotPursue::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotPursue::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPursue::ShouldWalk
 * Address: 0072a0b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPursue::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotPursue::ShouldWalk(CINSBotPursue *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotPursue::ShouldWalk
 * Address: 0072a0c0
 * ---------------------------------------- */

/* CINSBotPursue::ShouldWalk(INextBot const*) const */

byte __cdecl CINSBotPursue::ShouldWalk(INextBot *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  if (param_1[0x58] != (INextBot)0x0) {
    return 2;
  }
  return ~-(*(float *)(extraout_ECX + 0x221bd3 /* typeinfo name for CUtlCachedFileData<CModelSoundsCache>+0x38 */) < *(float *)(param_1 + 0x54)) & 2;
}



/* ----------------------------------------
 * CINSBotPursue::~CINSBotPursue
 * Address: 0072a890
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPursue::~CINSBotPursue() */

void __thiscall CINSBotPursue::~CINSBotPursue(CINSBotPursue *this)

{
  ~CINSBotPursue(this);
  return;
}



/* ----------------------------------------
 * CINSBotPursue::~CINSBotPursue
 * Address: 0072a8a0
 * ---------------------------------------- */

/* CINSBotPursue::~CINSBotPursue() */

void __thiscall CINSBotPursue::~CINSBotPursue(CINSBotPursue *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x46d2a3 /* vtable for CINSBotPursue+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x46d43b /* vtable for CINSBotPursue+0x1a0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(&UNK_0047c8d3 + extraout_ECX));
  return;
}



/* ----------------------------------------
 * CINSBotPursue::~CINSBotPursue
 * Address: 0072a8d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPursue::~CINSBotPursue() */

void __thiscall CINSBotPursue::~CINSBotPursue(CINSBotPursue *this)

{
  ~CINSBotPursue(this);
  return;
}



/* ----------------------------------------
 * CINSBotPursue::~CINSBotPursue
 * Address: 0072a8e0
 * ---------------------------------------- */

/* CINSBotPursue::~CINSBotPursue() */

void __thiscall CINSBotPursue::~CINSBotPursue(CINSBotPursue *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0046d25a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x46d3f2 /* vtable for CINSBotPursue+0x1a0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



