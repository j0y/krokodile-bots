/*
 * CINSBotRetreat -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 19
 */

/* ----------------------------------------
 * CINSBotRetreat::CINSBotRetreat
 * Address: 0072c190
 * ---------------------------------------- */

/* CINSBotRetreat::CINSBotRetreat(bool, float) */

void __thiscall CINSBotRetreat::CINSBotRetreat(CINSBotRetreat *this,bool param_1,float param_2)

{
  undefined4 *puVar1;
  int iVar2;
  code *pcVar3;
  CINSPathFollower *this_00;
  int unaff_EBX;
  undefined3 in_stack_00000005;
  undefined4 in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  _param_1[8] = 0;
  *_param_1 = &UNK_0046bd8d + unaff_EBX;
  _param_1[9] = 0;
  _param_1[10] = 0;
  _param_1[3] = 0;
  _param_1[4] = 0;
  _param_1[5] = 0;
  _param_1[6] = 0;
  _param_1[7] = 0;
  _param_1[2] = 0;
  *(undefined1 *)(_param_1 + 0xc) = 0;
  *(undefined1 *)((int)_param_1 + 0x31) = 0;
  _param_1[0xb] = 0;
  _param_1[0xd] = 0;
  _param_1[1] = unaff_EBX + 0x46bf25 /* vtable for CINSBotRetreat+0x1a0 */;
  CINSPathFollower::CINSPathFollower(this_00);
  _param_1[0x122b] = 0;
  _param_1[0xe] = unaff_EBX + 0x46822d /* vtable for CINSRetreatPath+0x8 */;
  puVar1 = _param_1 + 0x122a;
  iVar2 = unaff_EBX + 0x3fc01d /* vtable for CountdownTimer+0x8 */;
  _param_1[0x122a] = iVar2;
  pcVar3 = (code *)(unaff_EBX + -0x4fba2b /* CountdownTimer::NetworkStateChanged */);
  (*pcVar3)(puVar1,_param_1 + 0x122b);
  _param_1[0x122c] = 0xbf800000 /* -1.0f */;
  (**(code **)(_param_1[0x122a] + 4))(puVar1,_param_1 + 0x122c);
  _param_1[0x122d] = 0xffffffff;
  if (_param_1[0x122c] != -0x40800000 /* -1.0f */) {
    (**(code **)(_param_1[0x122a] + 4))(puVar1,_param_1 + 0x122c);
    _param_1[0x122c] = 0xbf800000 /* -1.0f */;
  }
  _param_1[0x1231] = iVar2;
  _param_1[0x122d] = 0xffffffff;
  _param_1[0x1232] = 0;
  (*pcVar3)(_param_1 + 0x1231,_param_1 + 0x1232);
  _param_1[0x1233] = 0xbf800000 /* -1.0f */;
  (**(code **)(_param_1[0x1231] + 4))(_param_1 + 0x1231,_param_1 + 0x1233);
  _param_1[0x1236] = iVar2;
  _param_1[0x1237] = 0;
  (*pcVar3)(_param_1 + 0x1236,_param_1 + 0x1237);
  _param_1[0x1238] = 0xbf800000 /* -1.0f */;
  (**(code **)(_param_1[0x1236] + 4))(_param_1 + 0x1236,_param_1 + 0x1238);
  _param_1[0x1239] = iVar2;
  _param_1[0x123a] = 0;
  (*pcVar3)(_param_1 + 0x1239,_param_1 + 0x123a);
  _param_1[0x123b] = 0xbf800000 /* -1.0f */;
  (**(code **)(_param_1[0x1239] + 4))(_param_1 + 0x1239,_param_1 + 0x123b);
  *(undefined1 *)(_param_1 + 0x123c) = 0;
  _param_1[0x123d] = 0xffffffff;
  *(undefined1 *)(_param_1 + 0x1234) = param_2._0_1_;
  _param_1[0x1235] = in_stack_0000000c;
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::CINSBotRetreat
 * Address: 0072c420
 * ---------------------------------------- */

/* CINSBotRetreat::CINSBotRetreat(float) */

void __thiscall CINSBotRetreat::CINSBotRetreat(CINSBotRetreat *this,float param_1)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  CINSPathFollower *this_00;
  int unaff_EBX;
  undefined4 in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)((int)param_1 + 0x20) = 0;
  *(undefined4 *)((int)param_1 + 0x24) = 0;
  *(undefined **)param_1 = &UNK_0046bafd + unaff_EBX;
  *(int *)((int)param_1 + 4) = unaff_EBX + 0x46bc95 /* vtable for CINSBotRetreat+0x1a0 */;
  *(undefined4 *)((int)param_1 + 0x28) = 0;
  *(undefined4 *)((int)param_1 + 0xc) = 0;
  *(undefined4 *)((int)param_1 + 0x10) = 0;
  *(undefined4 *)((int)param_1 + 0x14) = 0;
  *(undefined4 *)((int)param_1 + 0x18) = 0;
  *(undefined4 *)((int)param_1 + 0x1c) = 0;
  *(undefined4 *)((int)param_1 + 8) = 0;
  *(undefined1 *)((int)param_1 + 0x30) = 0;
  *(undefined1 *)((int)param_1 + 0x31) = 0;
  *(undefined4 *)((int)param_1 + 0x2c) = 0;
  *(undefined4 *)((int)param_1 + 0x34) = 0;
  CINSPathFollower::CINSPathFollower(this_00);
  *(undefined4 *)((int)param_1 + 0x48ac) = 0;
  *(undefined **)((int)param_1 + 0x38) = &UNK_00467f9d + unaff_EBX;
  pcVar1 = (code *)(unaff_EBX + -0x4fbcbb /* CountdownTimer::NetworkStateChanged */);
  iVar2 = (int)param_1 + 0x48a8;
  iVar3 = unaff_EBX + 0x3fbd8d /* vtable for CountdownTimer+0x8 */;
  *(int *)((int)param_1 + 0x48a8) = iVar3;
  (*pcVar1)(iVar2,(int)param_1 + 0x48ac);
  *(undefined4 *)((int)param_1 + 0x48b0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)((int)param_1 + 0x48a8) + 4))(iVar2,(int)param_1 + 0x48b0);
  *(undefined4 *)((int)param_1 + 0x48b4) = 0xffffffff;
  if (*(int *)((int)param_1 + 0x48b0) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)((int)param_1 + 0x48a8) + 4))(iVar2,(int)param_1 + 0x48b0);
    *(undefined4 *)((int)param_1 + 0x48b0) = 0xbf800000 /* -1.0f */;
  }
  *(int *)((int)param_1 + 0x48c4) = iVar3;
  *(undefined4 *)((int)param_1 + 0x48b4) = 0xffffffff;
  *(undefined4 *)((int)param_1 + 0x48c8) = 0;
  (*pcVar1)((int)param_1 + 0x48c4,(int)param_1 + 0x48c8);
  *(undefined4 *)((int)param_1 + 0x48cc) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)((int)param_1 + 0x48c4) + 4))((int)param_1 + 0x48c4,(int)param_1 + 0x48cc);
  *(int *)((int)param_1 + 0x48d8) = iVar3;
  *(undefined4 *)((int)param_1 + 0x48dc) = 0;
  (*pcVar1)((int)param_1 + 0x48d8,(int)param_1 + 0x48dc);
  *(undefined4 *)((int)param_1 + 0x48e0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)((int)param_1 + 0x48d8) + 4))((int)param_1 + 0x48d8,(int)param_1 + 0x48e0);
  *(int *)((int)param_1 + 0x48e4) = iVar3;
  *(undefined4 *)((int)param_1 + 0x48e8) = 0;
  (*pcVar1)((int)param_1 + 0x48e4,(int)param_1 + 0x48e8);
  *(undefined4 *)((int)param_1 + 0x48ec) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)((int)param_1 + 0x48e4) + 4))((int)param_1 + 0x48e4,(int)param_1 + 0x48ec);
  *(undefined1 *)((int)param_1 + 0x48d0) = 0;
  *(undefined4 *)((int)param_1 + 0x48f4) = 0xffffffff;
  *(undefined1 *)((int)param_1 + 0x48f0) = 0;
  *(undefined4 *)((int)param_1 + 0x48d4) = in_stack_00000008;
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::CINSBotRetreat
 * Address: 0072c6a0
 * ---------------------------------------- */

/* CINSBotRetreat::CINSBotRetreat(int) */

void __thiscall CINSBotRetreat::CINSBotRetreat(CINSBotRetreat *this,int param_1)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  CINSPathFollower *this_00;
  int unaff_EBX;
  undefined4 in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(int *)param_1 = unaff_EBX + 0x46b87d /* vtable for CINSBotRetreat+0x8 */;
  *(int *)(param_1 + 4) = unaff_EBX + 0x46ba15 /* vtable for CINSBotRetreat+0x1a0 */;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined1 *)(param_1 + 0x30) = 0;
  *(undefined1 *)(param_1 + 0x31) = 0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  CINSPathFollower::CINSPathFollower(this_00);
  *(undefined4 *)(param_1 + 0x48ac) = 0;
  *(int *)(param_1 + 0x38) = unaff_EBX + 0x467d1d /* vtable for CINSRetreatPath+0x8 */;
  pcVar1 = (code *)(unaff_EBX + -0x4fbf3b /* CountdownTimer::NetworkStateChanged */);
  iVar2 = param_1 + 0x48a8;
  iVar3 = unaff_EBX + 0x3fbb0d /* vtable for CountdownTimer+0x8 */;
  *(int *)(param_1 + 0x48a8) = iVar3;
  (*pcVar1)(iVar2,param_1 + 0x48ac);
  *(undefined4 *)(param_1 + 0x48b0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48a8) + 4))(iVar2,param_1 + 0x48b0);
  *(undefined4 *)(param_1 + 0x48b4) = 0xffffffff;
  if (*(int *)(param_1 + 0x48b0) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(param_1 + 0x48a8) + 4))(iVar2,param_1 + 0x48b0);
    *(undefined4 *)(param_1 + 0x48b0) = 0xbf800000 /* -1.0f */;
  }
  *(int *)(param_1 + 0x48c4) = iVar3;
  *(undefined4 *)(param_1 + 0x48b4) = 0xffffffff;
  *(undefined4 *)(param_1 + 0x48c8) = 0;
  (*pcVar1)(param_1 + 0x48c4,param_1 + 0x48c8);
  *(undefined4 *)(param_1 + 0x48cc) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48c4) + 4))(param_1 + 0x48c4,param_1 + 0x48cc);
  *(int *)(param_1 + 0x48d8) = iVar3;
  *(undefined4 *)(param_1 + 0x48dc) = 0;
  (*pcVar1)(param_1 + 0x48d8,param_1 + 0x48dc);
  *(undefined4 *)(param_1 + 0x48e0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48d8) + 4))(param_1 + 0x48d8,param_1 + 0x48e0);
  *(int *)(param_1 + 0x48e4) = iVar3;
  *(undefined4 *)(param_1 + 0x48e8) = 0;
  (*pcVar1)(param_1 + 0x48e4,param_1 + 0x48e8);
  *(undefined4 *)(param_1 + 0x48ec) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48e4) + 4))(param_1 + 0x48e4,param_1 + 0x48ec);
  *(undefined1 *)(param_1 + 0x48d0) = 0;
  *(undefined4 *)(param_1 + 0x48d4) = 0x40a00000 /* 5.0f */;
  *(undefined1 *)(param_1 + 0x48f0) = 0;
  *(undefined4 *)(param_1 + 0x48f4) = in_stack_00000008;
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::OnStart
 * Address: 0072bbd0
 * ---------------------------------------- */

/* CINSBotRetreat::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotRetreat::OnStart(CINSBotRetreat *this,CINSNextBot *param_1,Action *param_2)

{
  CINSRetreatPath *this_00;
  uint *puVar1;
  uint uVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  char *pcVar7;
  CINSPathFollower *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CBaseEntity *this_03;
  CBaseEntity *pCVar8;
  CBaseEntity *extraout_ECX_01;
  CINSNextBot *pCVar9;
  int unaff_EBX;
  bool bVar10;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  int *in_stack_0000000c;
  undefined4 uVar16;
  undefined8 uVar15;
  int *local_30;
  
  __i686_get_pc_thunk_bx();
  fVar12 = *(float *)(param_2 + 0x48d4);
  if (*(float *)(unaff_EBX + 0x1f8b91 /* typeinfo name for CBaseGameSystem+0x32 */) <= *(float *)(param_2 + 0x48d4)) {
    fVar12 = *(float *)(unaff_EBX + 0x1f8b91 /* typeinfo name for CBaseGameSystem+0x32 */);
  }
  fVar11 = (float10)CountdownTimer::Now();
  if (*(float *)(param_2 + 0x48e0) != (float)fVar11 + fVar12) {
    (**(code **)(*(int *)(param_2 + 0x48d8) + 4))(param_2 + 0x48d8);
    *(float *)(param_2 + 0x48e0) = (float)fVar11 + fVar12;
  }
  if (*(float *)(param_2 + 0x48dc) != fVar12) {
    (**(code **)(*(int *)(param_2 + 0x48d8) + 4))(param_2 + 0x48d8);
    *(float *)(param_2 + 0x48dc) = fVar12;
  }
  (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
  CINSBotLocomotion::ClearMovementRequests();
  *(undefined4 *)(param_2 + 0x4814) = 0x428a0000 /* 69.0f */;
  if ((in_stack_0000000c[0x2cce] == -1) ||
     (local_30 = (int *)UTIL_EntityByIndex(in_stack_0000000c[0x2cce]), local_30 == (int *)0x0)) {
    piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6);
    if ((piVar6 == (int *)0x0) ||
       (local_30 = (int *)(**(code **)(*piVar6 + 0x10))(piVar6), local_30 == (int *)0x0)) {
      fVar11 = (float10)CountdownTimer::Now();
      fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1f8b7d /* typeinfo name for CBaseGameSystem+0x1e */);
      if (*(float *)(param_2 + 0x48ec) != fVar12) {
        (**(code **)(*(int *)(param_2 + 0x48e4) + 4))(param_2 + 0x48e4,param_2 + 0x48ec);
        *(float *)(param_2 + 0x48ec) = fVar12;
      }
      if (*(int *)(param_2 + 0x48e8) != 0x3f000000 /* 0.5f */) {
        (**(code **)(*(int *)(param_2 + 0x48e4) + 4))(param_2 + 0x48e4,param_2 + 0x48e8);
        *(undefined4 *)(param_2 + 0x48e8) = 0x3f000000 /* 0.5f */;
      }
      param_2[0x48f0] = (Action)0x1;
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
  }
  pCVar8 = (CBaseEntity *)(in_stack_0000000c + 0x818);
  this_00 = (CINSRetreatPath *)(param_2 + 0x38);
  bVar10 = *(int *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bVar10) &&
     (iVar5 = *(int *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
     iVar5 == iVar4)) {
    pcVar7 = *(char **)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*(undefined **)pcVar7 != &UNK_00255c9d + unaff_EBX) {
      pcVar7 = (char *)CVProfNode::GetSubNode
                                 (pcVar7,(int)(&UNK_00255c9d + unaff_EBX),(char *)0x0,
                                  unaff_EBX + 0x25508e /* "NextBot" */);
      *(char **)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = pcVar7;
    }
    puVar1 = (uint *)(*(int *)(pcVar7 + 0x70) * 8 +
                      *(int *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  uVar2 = *(uint *)(param_2 + 0x48b4);
  if (((uVar2 == 0xffffffff) ||
      (iVar5 = **(int **)(unaff_EBX + 0x47abfd /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
      *(uint *)(iVar5 + 8) != uVar2 >> 0x10)) || (local_30 != *(int **)(iVar5 + 4))) {
    uVar16 = 4;
    cVar3 = (**(code **)(in_stack_0000000c[0x818] + 0x140))(pCVar8);
    if (cVar3 != '\0') {
      (**(code **)(in_stack_0000000c[0x818] + 200))(pCVar8);
      uVar16 = (undefined4)
               ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x47acc5 /* &gpGlobals */) + 0xc) >> 0x20);
      DevMsg((char *)(INextBotEventResponder::OnMoveToFailure + unaff_EBX + 1));
    }
    (**(code **)(*(int *)(param_2 + 0x38) + 0x44))(this_00,uVar16);
  }
  piVar6 = local_30;
  CINSRetreatPath::RefreshPath(this_00,(INextBot *)this_00,pCVar8);
  uVar15 = CONCAT44(pCVar8,this_00);
  CINSPathFollower::Update(this_01,(INextBot *)this_00);
  this_02 = extraout_ECX;
  if (((bVar10) &&
      ((*(char *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
       (this_02 = *(CINSNextBot **)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c),
       this_02 != (CINSNextBot *)0x0)))) &&
     (iVar5 = *(int *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
     iVar4 = ThreadGetCurrentId(uVar15,piVar6), this_02 = extraout_ECX_00, iVar5 == iVar4)) {
    cVar3 = CVProfNode::ExitScope();
    if (cVar3 == '\0') {
      pCVar9 = *(CINSNextBot **)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      pCVar9 = *(CINSNextBot **)(*(int *)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(CINSNextBot **)(*(int *)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = pCVar9;
    }
    this_02 = *(CINSNextBot **)(unaff_EBX + 0x47ad99 /* &GCSDK::GetPchTempTextBuffer */);
    this_02[0x1010] = (CINSNextBot)(pCVar9 == this_02 + 0x1018);
  }
  CINSNextBot::ResetIdleStatus(this_02);
  cVar3 = (**(code **)(*local_30 + 0x158))(local_30);
  if (((cVar3 == '\0') &&
      (iVar5 = __dynamic_cast(local_30,*(undefined4 *)(unaff_EBX + 0x47b529 /* &typeinfo for CBaseEntity */),
                              *(undefined4 *)(unaff_EBX + 0x47b051 /* &typeinfo for CBaseDetonator */),0), iVar5 != 0)) &&
     (fVar11 = (float10)CBaseDetonator::GetDetonateDamage(),
     *(float *)(unaff_EBX + 0x18cf2d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar11 &&
     (float)fVar11 != *(float *)(unaff_EBX + 0x18cf2d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */))) {
    pCVar8 = this_03;
    if ((*(byte *)(iVar5 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_03);
      pCVar8 = extraout_ECX_01;
    }
    if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar8);
    }
    fVar14 = (float)in_stack_0000000c[0x82] - *(float *)(iVar5 + 0x208);
    fVar12 = (float)in_stack_0000000c[0x83] - *(float *)(iVar5 + 0x20c);
    fVar13 = (float)in_stack_0000000c[0x84] - *(float *)(iVar5 + 0x210);
    fVar11 = (float10)CBaseDetonator::GetDetonateDamageRadius();
    if (SQRT(fVar12 * fVar12 + fVar14 * fVar14 + fVar13 * fVar13) < (float)fVar11) {
      (**(code **)(*in_stack_0000000c + 0x800 /* CINSPlayer::SpeakConceptIfAllowed */))(in_stack_0000000c,0x68,0,0,0,0);
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreat::Update
 * Address: 0072b780
 * ---------------------------------------- */

/* CINSBotRetreat::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotRetreat::Update(CINSBotRetreat *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSRetreatPath *extraout_ECX_01;
  CINSRetreatPath *this_02;
  CINSRetreatPath *extraout_ECX_02;
  CountdownTimer *this_03;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_0000000c;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  this_00 = extraout_ECX;
  if ((*(char *)((int)param_2 + 0x48f0) != '\0') &&
     (fVar5 = (float10)CountdownTimer::Now(), this_00 = extraout_ECX_00,
     *(float *)((int)param_2 + 0x48ec) <= (float)fVar5 &&
     (float)fVar5 != *(float *)((int)param_2 + 0x48ec))) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_002560fc + unaff_EBX;
    return param_1;
  }
  cVar2 = CINSNextBot::IsIdle(this_00);
  if ((cVar2 != '\0') &&
     (fVar5 = (float10)CINSNextBot::GetIdleDuration(this_01),
     *(float *)(unaff_EBX + 0x1f8fd8 /* typeinfo name for CBaseGameSystem+0x32 */) <= (float)fVar5 &&
     (float)fVar5 != *(float *)(unaff_EBX + 0x1f8fd8 /* typeinfo name for CBaseGameSystem+0x32 */))) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25611a /* "Idle in retreat" */;
    return param_1;
  }
  if ((0.0 < *(float *)((int)param_2 + 0x48e0)) &&
     (fVar5 = (float10)CountdownTimer::Now(),
     *(float *)((int)param_2 + 0x48e0) <= (float)fVar5 &&
     (float)fVar5 != *(float *)((int)param_2 + 0x48e0))) {
    if (*(char *)((int)param_2 + 0x48d0) == '\0') {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25612a /* "Retreat timer elapsed." */;
      return param_1;
    }
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar4 = *(int *)(unaff_EBX + 0x47b264 /* &vtable for CINSBotReload */);
    piVar3[0xf] = 0;
    piVar3[1] = iVar4 + 0x198;
    *piVar3 = iVar4 + 8;
    iVar4 = unaff_EBX + 0x3fca24 /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4fb024 /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar4;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10);
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar4;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar4;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(int **)(param_1 + 4) = piVar3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2562b4 /* "Retreat timer elapsed, changing to reload" */;
    return param_1;
  }
  fVar5 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x48cc) <= (float)fVar5 &&
      (float)fVar5 != *(float *)((int)param_2 + 0x48cc)) {
    if ((in_stack_0000000c[0x2cce] == -1) ||
       (iVar4 = UTIL_EntityByIndex(in_stack_0000000c[0x2cce]), this_02 = extraout_ECX_01, iVar4 == 0
       )) {
      piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
      if ((piVar3 == (int *)0x0) ||
         (iVar4 = (**(code **)(*piVar3 + 0x10))(piVar3), this_02 = extraout_ECX_02, iVar4 == 0)) {
        *(undefined1 *)((int)param_2 + 0x48f0) = 1;
        RandomFloat(0x3ecccccd /* 0.4f */,0x3f19999a /* 0.6f */);
        CountdownTimer::Start(this_03,(float)((int)param_2 + 0x48e4));
        *(undefined4 *)param_1 = 0 /* Continue */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
    }
    if (0 < *(int *)((int)param_2 + 0x443c)) {
      CINSRetreatPath::Update
                (this_02,(INextBot *)((int)param_2 + 0x38),
                 (CBaseEntity *)(in_stack_0000000c + 0x818));
    }
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x47b5fc /* &ins_bot_path_update_interval */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x47b5fc /* &ins_bot_path_update_interval */)) {
      local_20 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar5 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      local_20 = (float)fVar5;
    }
    fVar5 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x48cc) != (float)fVar5 + local_20) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48cc);
      *(float *)((int)param_2 + 0x48cc) = (float)fVar5 + local_20;
    }
    if (*(float *)((int)param_2 + 0x48c8) != local_20) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48c8);
      *(float *)((int)param_2 + 0x48c8) = local_20;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreat::OnEnd
 * Address: 0072b090
 * ---------------------------------------- */

/* CINSBotRetreat::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotRetreat::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::GetName
 * Address: 0072c920
 * ---------------------------------------- */

/* CINSBotRetreat::GetName() const */

int CINSBotRetreat::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x254efa /* "Retreating!" */;
}



/* ----------------------------------------
 * CINSBotRetreat::ShouldHurry
 * Address: 0072b0a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreat::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotRetreat::ShouldHurry(CINSBotRetreat *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::ShouldHurry
 * Address: 0072b0b0
 * ---------------------------------------- */

/* CINSBotRetreat::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotRetreat::ShouldHurry(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotRetreat::ShouldAttack
 * Address: 0072b0c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreat::ShouldAttack(INextBot const*, CKnownEntity const*) const */

void __thiscall
CINSBotRetreat::ShouldAttack(CINSBotRetreat *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::ShouldAttack
 * Address: 0072b0d0
 * ---------------------------------------- */

/* CINSBotRetreat::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotRetreat::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotRetreat::OnMoveToSuccess
 * Address: 0072b180
 * ---------------------------------------- */

/* CINSBotRetreat::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotRetreat::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar2 + 0x48d0) == '\0') {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar2 = *(int *)(unaff_EBX + 0x47b867 /* &vtable for CINSBotReload */);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x3fd027 /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4faa21 /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar2;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10);
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar2;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar2;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(int **)(param_1 + 4) = piVar3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x256757 /* "Doing reload after OnMoveToFailure" */;
    *(undefined4 *)(param_1 + 0xc) = 2;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreat::OnMoveToFailure
 * Address: 0072b520
 * ---------------------------------------- */

/* CINSBotRetreat::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotRetreat::OnMoveToFailure(undefined4 *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar2 + 0x48d0) == '\0') {
    *param_1 = 3;
    param_1[1] = 0;
    param_1[2] = unaff_EBX + 0x2563db /* "We couldn't get to target's position!" */;
    param_1[3] = 2;
  }
  else {
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar2 = *(int *)(&DAT_0047b4c7 + unaff_EBX);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x3fcc87 /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4fadc1 /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar2;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10);
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar2;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar2;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *param_1 = 1;
    param_1[1] = piVar3;
    param_1[2] = unaff_EBX + 0x2563b7 /* "Doing reload after OnMoveToFailure" */;
    param_1[3] = 2;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreat::OnStuck
 * Address: 0072b350
 * ---------------------------------------- */

/* CINSBotRetreat::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotRetreat::OnStuck(CINSNextBot *param_1)

{
  undefined *puVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  int unaff_EBX;
  
  iVar3 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar3 + 0x48d0) == '\0') {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
    piVar4 = (int *)::operator_new(0x5c);
    piVar4[8] = 0;
    piVar4[9] = 0;
    piVar4[10] = 0;
    piVar4[3] = 0;
    piVar4[4] = 0;
    piVar4[5] = 0;
    piVar4[6] = 0;
    piVar4[7] = 0;
    piVar4[2] = 0;
    *(undefined1 *)(piVar4 + 0xc) = 0;
    *(undefined1 *)((int)piVar4 + 0x31) = 0;
    piVar4[0xb] = 0;
    piVar4[0xd] = 0;
    iVar3 = *(int *)(&DAT_0047b697 + unaff_EBX);
    piVar4[0xf] = 0;
    piVar4[1] = iVar3 + 0x198;
    *piVar4 = iVar3 + 8;
    puVar1 = &UNK_003fce57 + unaff_EBX;
    pcVar2 = (code *)(unaff_EBX + -0x4fabf1 /* CountdownTimer::NetworkStateChanged */);
    piVar4[0xe] = (int)puVar1;
    (*pcVar2)(piVar4 + 0xe,piVar4 + 0xf);
    piVar4[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
    piVar4[0x12] = 0;
    piVar4[0x11] = (int)puVar1;
    (*pcVar2)(piVar4 + 0x11,piVar4 + 0x12);
    piVar4[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
    piVar4[0x15] = 0;
    piVar4[0x14] = (int)puVar1;
    (*pcVar2)(piVar4 + 0x14,piVar4 + 0x15);
    piVar4[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(int **)(param_1 + 4) = piVar4;
    *(int *)(param_1 + 8) = unaff_EBX + 0x256587 /* "Doing reload after OnMoveToFailure" */;
    *(undefined4 *)(param_1 + 0xc) = 2;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreat::OnInjured
 * Address: 0072c940
 * ---------------------------------------- */

/* CINSBotRetreat::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotRetreat::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 4;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x254ee6 /* "Sustaining retreat." */;
  *(undefined4 *)(param_1 + 0xc) = 2;
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::~CINSBotRetreat
 * Address: 0072c980
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreat::~CINSBotRetreat() */

void __thiscall CINSBotRetreat::~CINSBotRetreat(CINSBotRetreat *this)

{
  ~CINSBotRetreat(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::~CINSBotRetreat
 * Address: 0072c990
 * ---------------------------------------- */

/* CINSBotRetreat::~CINSBotRetreat() */

void __thiscall CINSBotRetreat::~CINSBotRetreat(CINSBotRetreat *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46b58a /* vtable for CINSBotRetreat+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46b722 /* vtable for CINSBotRetreat+0x1a0 */;
  in_stack_00000004[0xe] = unaff_EBX + 0x467a2a /* vtable for CINSRetreatPath+0x8 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::~CINSBotRetreat
 * Address: 0072ca00
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreat::~CINSBotRetreat() */

void __thiscall CINSBotRetreat::~CINSBotRetreat(CINSBotRetreat *this)

{
  ~CINSBotRetreat(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreat::~CINSBotRetreat
 * Address: 0072ca10
 * ---------------------------------------- */

/* CINSBotRetreat::~CINSBotRetreat() */

void __thiscall CINSBotRetreat::~CINSBotRetreat(CINSBotRetreat *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46b50a /* vtable for CINSBotRetreat+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46b6a2 /* vtable for CINSBotRetreat+0x1a0 */;
  in_stack_00000004[0xe] = unaff_EBX + 0x4679aa /* vtable for CINSRetreatPath+0x8 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



