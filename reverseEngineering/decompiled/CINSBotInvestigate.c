/*
 * CINSBotInvestigate -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 25
 */

/* ----------------------------------------
 * CINSBotInvestigate::CINSBotInvestigate
 * Address: 00723fa0
 * ---------------------------------------- */

/* CINSBotInvestigate::CINSBotInvestigate(CNavArea const*) */

void __thiscall CINSBotInvestigate::CINSBotInvestigate(CINSBotInvestigate *this,CNavArea *param_1)

{
  code *pcVar1;
  undefined *puVar2;
  CNavArea *pCVar3;
  CNavArea *pCVar4;
  float fVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  CINSPathFollower *this_00;
  CINSPathFollower *this_01;
  int unaff_EBX;
  float10 fVar8;
  undefined4 in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(int *)param_1 = unaff_EBX + 0x47359d /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */;
  *(int *)(param_1 + 4) = unaff_EBX + 0x473735 /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  param_1[0x30] = (CNavArea)0x0;
  param_1[0x31] = (CNavArea)0x0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  CINSPathFollower::CINSPathFollower(this_00);
  pcVar1 = (code *)(unaff_EBX + -0x4f383b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  *(undefined4 *)(param_1 + 0x48bc) = 0;
  puVar2 = &UNK_0040420d + unaff_EBX;
  *(undefined **)(param_1 + 0x48b8) = puVar2;
  (*pcVar1)(param_1 + 0x48b8,param_1 + 0x48bc);
  *(undefined4 *)(param_1 + 0x48c0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48b8) + 4))(param_1 + 0x48b8,param_1 + 0x48c0); /* timer_0.NetworkStateChanged() */
  *(undefined **)(param_1 + 0x48c4) = puVar2;
  *(undefined4 *)(param_1 + 0x48c8) = 0;
  (*pcVar1)(param_1 + 0x48c4,param_1 + 0x48c8);
  *(undefined4 *)(param_1 + 0x48cc) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48c4) + 4))(param_1 + 0x48c4,param_1 + 0x48cc); /* timer_1.NetworkStateChanged() */
  pCVar3 = param_1 + 0x48d0;
  *(undefined **)(param_1 + 0x48d0) = puVar2;
  *(undefined4 *)(param_1 + 0x48d4) = 0;
  (*pcVar1)(pCVar3,param_1 + 0x48d4);
  *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48d0) + 4))(pCVar3,param_1 + 0x48d8); /* timer_2.NetworkStateChanged() */
  pCVar4 = param_1 + 0x48e8;
  *(undefined **)(param_1 + 0x48e8) = puVar2;
  *(undefined4 *)(param_1 + 0x48ec) = 0;
  (*pcVar1)(pCVar4,param_1 + 0x48ec);
  *(undefined4 *)(param_1 + 0x48f0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(pCVar4,param_1 + 0x48f0); /* timer_3.NetworkStateChanged() */
  CINSPathFollower::Invalidate(this_01);
  fVar8 = (float10)CountdownTimer::Now();
  fVar5 = *(float *)(param_1 + 0x48d4);
  if (*(float *)(param_1 + 0x48d8) != (float)fVar8 + fVar5) {
    (**(code **)(*(int *)(param_1 + 0x48d0) + 4))(pCVar3,param_1 + 0x48d8); /* timer_2.NetworkStateChanged() */
    *(float *)(param_1 + 0x48d8) = (float)fVar8 + fVar5; /* timer_2.Start(...) */
  }
  fVar8 = (float10)CountdownTimer::Now();
  fVar5 = *(float *)(param_1 + 0x48ec);
  if (*(float *)(param_1 + 0x48f0) != (float)fVar8 + fVar5) {
    (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(pCVar4,param_1 + 0x48f0); /* timer_3.NetworkStateChanged() */
    *(float *)(param_1 + 0x48f0) = (float)fVar8 + fVar5; /* timer_3.Start(...) */
  }
  param_1[0x48f8] = (CNavArea)0x0;
  *(undefined4 *)(param_1 + 0x48f4) = 0xbf800000 /* -1.0f */;
  param_1[0x48fa] = (CNavArea)0x0;
  *(undefined4 *)(param_1 + 0x48fc) = 0;
  *(undefined4 *)(param_1 + 0x38) = in_stack_00000008;
  puVar6 = *(undefined4 **)(unaff_EBX + 0x482621 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *(undefined4 *)(param_1 + 0x3c) = *puVar6;
  uVar7 = puVar6[2];
  *(undefined4 *)(param_1 + 0x40) = puVar6[1];
  *(undefined4 *)(param_1 + 0x44) = uVar7;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::CINSBotInvestigate
 * Address: 00724290
 * ---------------------------------------- */

/* CINSBotInvestigate::CINSBotInvestigate(Vector) */

void __thiscall CINSBotInvestigate::CINSBotInvestigate(undefined4 param_1,int *param_2)

{
  code *pcVar1;
  int *piVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  CINSPathFollower *this;
  CINSPathFollower *this_00;
  int unaff_EBX;
  float10 fVar6;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  *param_2 = unaff_EBX + 0x4732ad /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */;
  param_2[1] = unaff_EBX + 0x473445 /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */;
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
  CINSPathFollower::CINSPathFollower(this);
  pcVar1 = (code *)(unaff_EBX + -0x4f3b2b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  param_2[0x122f] = 0;
  iVar5 = unaff_EBX + 0x403f1d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  param_2[0x122e] = iVar5; /* CountdownTimer timer_0 */
  (*pcVar1)(param_2 + 0x122e,param_2 + 0x122f);
  param_2[0x1230] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x122e] + 4))(param_2 + 0x122e,param_2 + 0x1230); /* timer_0.NetworkStateChanged() */
  param_2[0x1231] = iVar5; /* CountdownTimer timer_1 */
  param_2[0x1232] = 0;
  (*pcVar1)(param_2 + 0x1231,param_2 + 0x1232);
  param_2[0x1233] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x1231] + 4))(param_2 + 0x1231,param_2 + 0x1233); /* timer_1.NetworkStateChanged() */
  piVar4 = param_2 + 0x1234;
  param_2[0x1234] = iVar5; /* CountdownTimer timer_2 */
  param_2[0x1235] = 0;
  (*pcVar1)(piVar4,param_2 + 0x1235);
  param_2[0x1236] = -0x40800000 /* -1.0f */; /* timer_2.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x1234] + 4))(piVar4,param_2 + 0x1236); /* timer_2.NetworkStateChanged() */
  piVar2 = param_2 + 0x123a;
  param_2[0x123a] = iVar5; /* CountdownTimer timer_3 */
  param_2[0x123b] = 0;
  (*pcVar1)(piVar2,param_2 + 0x123b);
  param_2[0x123c] = -0x40800000 /* -1.0f */; /* timer_3.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x123a] + 4))(piVar2,param_2 + 0x123c); /* timer_3.NetworkStateChanged() */
  CINSPathFollower::Invalidate(this_00);
  fVar6 = (float10)CountdownTimer::Now();
  fVar3 = (float)param_2[0x1235];
  if ((float)param_2[0x1236] != (float)fVar6 + fVar3) {
    (**(code **)(param_2[0x1234] + 4))(piVar4,param_2 + 0x1236); /* timer_2.NetworkStateChanged() */
    param_2[0x1236] = (int)((float)fVar6 + fVar3); /* timer_2.Start(...) */
  }
  fVar6 = (float10)CountdownTimer::Now();
  fVar3 = (float)param_2[0x123b];
  if ((float)param_2[0x123c] != (float)fVar6 + fVar3) {
    (**(code **)(param_2[0x123a] + 4))(piVar2,param_2 + 0x123c); /* timer_3.NetworkStateChanged() */
    param_2[0x123c] = (int)((float)fVar6 + fVar3); /* timer_3.Start(...) */
  }
  iVar5 = CNavMesh::GetNearestNavArea();
  param_2[0xe] = iVar5;
  piVar4 = *(int **)(unaff_EBX + 0x482331 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *(undefined1 *)(param_2 + 0x123e) = 0;
  param_2[0x123d] = -0x40800000 /* -1.0f */;
  *(undefined1 *)((int)param_2 + 0x48fa) = 0;
  param_2[0x123f] = 0;
  param_2[0xf] = *piVar4;
  iVar5 = piVar4[2];
  param_2[0x10] = piVar4[1];
  param_2[0x11] = iVar5;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::CINSBotInvestigate
 * Address: 007245b0
 * ---------------------------------------- */

/* CINSBotInvestigate::CINSBotInvestigate() */

void __thiscall CINSBotInvestigate::CINSBotInvestigate(CINSBotInvestigate *this)

{
  code *pcVar1;
  undefined *puVar2;
  int *piVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  CINSPathFollower *this_00;
  CINSPathFollower *this_01;
  int unaff_EBX;
  float10 fVar7;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x472f8d /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x473125 /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */;
  in_stack_00000004[10] = 0;
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
  CINSPathFollower::CINSPathFollower(this_00);
  pcVar1 = (code *)(unaff_EBX + -0x4f3e4b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[0x122f] = 0;
  puVar2 = &UNK_00403bfd + unaff_EBX;
  in_stack_00000004[0x122e] = (int)puVar2;
  (*pcVar1)(in_stack_00000004 + 0x122e,in_stack_00000004 + 0x122f);
  in_stack_00000004[0x1230] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x122e] + 4)) /* timer_0.NetworkStateChanged() */
            (in_stack_00000004 + 0x122e,in_stack_00000004 + 0x1230);
  in_stack_00000004[0x1231] = (int)puVar2;
  in_stack_00000004[0x1232] = 0;
  (*pcVar1)(in_stack_00000004 + 0x1231,in_stack_00000004 + 0x1232);
  in_stack_00000004[0x1233] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x1231] + 4)) /* timer_1.NetworkStateChanged() */
            (in_stack_00000004 + 0x1231,in_stack_00000004 + 0x1233);
  piVar5 = in_stack_00000004 + 0x1234;
  in_stack_00000004[0x1234] = (int)puVar2;
  in_stack_00000004[0x1235] = 0;
  (*pcVar1)(piVar5,in_stack_00000004 + 0x1235);
  in_stack_00000004[0x1236] = -0x40800000 /* -1.0f */; /* timer_2.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x1234] + 4))(piVar5,in_stack_00000004 + 0x1236); /* timer_2.NetworkStateChanged() */
  piVar3 = in_stack_00000004 + 0x123a;
  in_stack_00000004[0x123a] = (int)puVar2;
  in_stack_00000004[0x123b] = 0;
  (*pcVar1)(piVar3,in_stack_00000004 + 0x123b);
  in_stack_00000004[0x123c] = -0x40800000 /* -1.0f */; /* timer_3.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x123a] + 4))(piVar3,in_stack_00000004 + 0x123c); /* timer_3.NetworkStateChanged() */
  CINSPathFollower::Invalidate(this_01);
  fVar7 = (float10)CountdownTimer::Now();
  fVar4 = (float)in_stack_00000004[0x1235];
  if ((float)in_stack_00000004[0x1236] != (float)fVar7 + fVar4) {
    (**(code **)(in_stack_00000004[0x1234] + 4))(piVar5,in_stack_00000004 + 0x1236); /* timer_2.NetworkStateChanged() */
    in_stack_00000004[0x1236] = (int)((float)fVar7 + fVar4); /* timer_2.Start(...) */
  }
  fVar7 = (float10)CountdownTimer::Now();
  fVar4 = (float)in_stack_00000004[0x123b];
  if ((float)in_stack_00000004[0x123c] != (float)fVar7 + fVar4) {
    (**(code **)(in_stack_00000004[0x123a] + 4))(piVar3,in_stack_00000004 + 0x123c); /* timer_3.NetworkStateChanged() */
    in_stack_00000004[0x123c] = (int)((float)fVar7 + fVar4); /* timer_3.Start(...) */
  }
  piVar5 = *(int **)(unaff_EBX + 0x482011 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *(undefined1 *)(in_stack_00000004 + 0x123e) = 0;
  in_stack_00000004[0x123d] = -0x40800000 /* -1.0f */;
  *(undefined1 *)((int)in_stack_00000004 + 0x48fa) = 0;
  in_stack_00000004[0x123f] = 0;
  in_stack_00000004[0xf] = *piVar5;
  iVar6 = piVar5[2];
  in_stack_00000004[0x10] = piVar5[1];
  in_stack_00000004[0x11] = iVar6;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnStart
 * Address: 00723540
 * ---------------------------------------- */

/* CINSBotInvestigate::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotInvestigate::OnStart(CINSBotInvestigate *this,CINSNextBot *param_1,Action *param_2)

{
  Action AVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_01;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  iVar3 = CINSNextBot::GetCurrentInvestigation(this_00);
  if (iVar3 == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25de7c /* "Invalid investigation?" */ /* "Invalid investigation?" */ /* "Invalid investigation?" */;
    *(undefined4 *)(param_1 + 4) = 0;
    return param_1;
  }
  if (*(int *)(param_2 + 0x38) == 0) {
    iVar5 = CNavMesh::GetNearestNavArea();
    *(int *)(param_2 + 0x38) = iVar5;
    if (iVar5 == 0) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25de93 /* "No Place to investigate " */ /* "No Place to investigate " */ /* "No Place to investigate " */;
      *(undefined4 *)(param_1 + 4) = 0;
      return param_1;
    }
  }
  AVar1 = (Action)CINSNextBot::IsInvestigating(in_stack_0000000c);
  param_2[0x48f9] = AVar1;
  CINSNextBot::SetInvestigating(in_stack_0000000c,SUB41(in_stack_0000000c,0));
  *(undefined4 *)(param_2 + 0x3c) = *(undefined4 *)(iVar3 + 0xc);
  *(undefined4 *)(param_2 + 0x40) = *(undefined4 *)(iVar3 + 0x10);
  *(undefined4 *)(param_2 + 0x44) = *(undefined4 *)(iVar3 + 0x14);
  fVar6 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
  this_01 = extraout_ECX;
  if (*(float *)(unaff_EBX + 0x201205 /* 0.6f */ /* 0.6f */ /* 0.6f */) <= (float)fVar6 &&
      (float)fVar6 != *(float *)(unaff_EBX + 0x201205 /* 0.6f */ /* 0.6f */ /* 0.6f */)) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (piVar4 != (int *)0x0) {
      cVar2 = (**(code **)(*piVar4 + 0x3c))(piVar4);
      if (cVar2 != '\0') {
        CINSNextBot::BotSpeakConceptIfAllowed
                  (in_stack_0000000c,(int)in_stack_0000000c,(char *)0x66,(char *)0x0,0,
                   (IRecipientFilter *)0x0);
        this_01 = extraout_ECX_00;
        goto LAB_007235e5;
      }
    }
    CINSNextBot::BotSpeakConceptIfAllowed
              (in_stack_0000000c,(int)in_stack_0000000c,(char *)0x47,(char *)0x0,0,
               (IRecipientFilter *)0x0);
    this_01 = extraout_ECX_01;
  }
LAB_007235e5:
  *(undefined4 *)(param_2 + 0x48fc) = *(undefined4 *)(iVar3 + 0x20);
  CINSNextBot::ResetIdleStatus(this_01);
  fVar6 = (float10)CountdownTimer::Now();
  fVar7 = (float)fVar6 + *(float *)(unaff_EBX + 0x201221 /* 5.0f */ /* 5.0f */ /* 5.0f */);
  if (*(float *)(param_2 + 0x48c0) != fVar7) {
    (**(code **)(*(int *)(param_2 + 0x48b8) + 4))(param_2 + 0x48b8,param_2 + 0x48c0); /* timer_0.NetworkStateChanged() */
    *(float *)(param_2 + 0x48c0) = fVar7; /* timer_0.Start(5.0f) */
  }
  if (*(int *)(param_2 + 0x48bc) != 0x40a00000 /* 5.0f */) {
    (**(code **)(*(int *)(param_2 + 0x48b8) + 4))(param_2 + 0x48b8,param_2 + 0x48bc); /* timer_0.NetworkStateChanged() */
    *(undefined4 *)(param_2 + 0x48bc) = 0x40a00000 /* 5.0f */;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigate::Update
 * Address: 00723960
 * ---------------------------------------- */

/* CINSBotInvestigate::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotInvestigate::Update(CINSBotInvestigate *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  CINSNextBot *this_00;
  char cVar2;
  undefined1 uVar3;
  CINSNextBot *pCVar4;
  undefined4 uVar5;
  int *piVar6;
  int iVar7;
  float *pfVar8;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *this_01;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  CINSNextBot *in_stack_0000000c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  if (*(CINSNextBot **)((int)param_2 + 0x38) == (CINSNextBot *)0x0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25da83 /* "Invalid investigation area?" */ /* "Invalid investigation area?" */ /* "Invalid investigation area?" */;
  }
  else {
    cVar2 = CINSNextBot::HasInvestigations(*(CINSNextBot **)((int)param_2 + 0x38));
    if (cVar2 == '\0') {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25db18 /* "No move investigations to worry about" */ /* "No move investigations to worry about" */ /* "No move investigations to worry about" */;
    }
    else {
      this_00 = *(CINSNextBot **)((int)param_2 + 0x38);
      pCVar4 = (CINSNextBot *)CINSNextBot::GetCurrentInvestigationArea(this_00);
      this_01 = extraout_ECX;
      if (this_00 != pCVar4) {
        uVar5 = CINSNextBot::GetCurrentInvestigationArea(in_stack_0000000c);
        *(undefined4 *)((int)param_2 + 0x38) = uVar5;
        CNavArea::GetRandomPoint();
        *(undefined4 *)((int)param_2 + 0x3c) = local_28;
        *(undefined4 *)((int)param_2 + 0x40) = local_24;
        *(undefined4 *)((int)param_2 + 0x44) = local_20;
        this_01 = extraout_ECX_00;
        if (*(int *)((int)param_2 + 0x48cc) != -0x40800000 /* -1.0f */) {
          (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4)) /* timer_1.NetworkStateChanged() */
                    ((int)param_2 + 0x48c4,(int)param_2 + 0x48cc);
          *(undefined4 *)((int)param_2 + 0x48cc) = 0xbf800000 /* -1.0f */;
          this_01 = extraout_ECX_01;
        }
      }
      cVar2 = CINSNextBot::IsIdle(this_01);
      if ((cVar2 == '\0') ||
         (fVar9 = (float10)CINSNextBot::GetIdleDuration(in_stack_0000000c),
         (float)fVar9 < *(float *)(unaff_EBX + 0x200df8 /* 5.0f */ /* 5.0f */ /* 5.0f */) ||
         (float)fVar9 == *(float *)(unaff_EBX + 0x200df8 /* 5.0f */ /* 5.0f */ /* 5.0f */))) {
        piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        iVar7 = (**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,1);
        if (iVar7 != 0) {
          piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
          iVar7 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))(piVar6,in_stack_0000000c + 0x2060,iVar7);
          if (iVar7 == 1) {
            *(undefined4 *)param_1 = 3 /* Done */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined **)(param_1 + 8) = &UNK_0025c0e7 + unaff_EBX;
            return param_1;
          }
        }
        fVar11 = *(float *)(&DAT_00205858 + unaff_EBX);
        if (((((*(float *)((int)param_2 + 0x3c) <= fVar11) ||
              (fVar1 = *(float *)(unaff_EBX + 0x2016bc /* 0.01f */ /* 0.01f */ /* 0.01f */), fVar1 <= *(float *)((int)param_2 + 0x3c)))
             || (*(float *)((int)param_2 + 0x40) <= fVar11)) ||
            ((fVar1 <= *(float *)((int)param_2 + 0x40) ||
             (*(float *)((int)param_2 + 0x44) <= fVar11)))) ||
           (fVar1 <= *(float *)((int)param_2 + 0x44))) {
          fVar9 = (float10)CountdownTimer::Now();
          if (*(float *)((int)param_2 + 0x48c0) <= (float)fVar9 && /* timer_0.IsElapsed() */
              (float)fVar9 != *(float *)((int)param_2 + 0x48c0)) {
            piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
            pfVar8 = (float *)(**(code **)(*piVar6 + 0x148 /* PlayerLocomotion::GetFeet */))(piVar6);
            fVar11 = pfVar8[1];
            fVar13 = *(float *)((int)param_2 + 0x48dc) - *pfVar8;
            fVar1 = pfVar8[2];
            fVar10 = *(float *)((int)param_2 + 0x48e0) - fVar11;
            fVar12 = *(float *)((int)param_2 + 0x48e4) - fVar1;
            if (SQRT(fVar10 * fVar10 + fVar13 * fVar13 + fVar12 * fVar12) <
                *(float *)(unaff_EBX + 0x200114 /* 16.0f */ /* 16.0f */ /* 16.0f */)) {
              *(undefined4 *)param_1 = 3 /* Done */;
              *(undefined4 *)(param_1 + 4) = 0;
              *(int *)(param_1 + 8) = unaff_EBX + 0x25db60 /* "Gave up investigating, took too long." */ /* "Gave up investigating, took too long." */ /* "Gave up investigating, took too long." */;
              return param_1;
            }
            *(float *)((int)param_2 + 0x48dc) = *pfVar8;
            *(float *)((int)param_2 + 0x48e0) = fVar11;
            *(float *)((int)param_2 + 0x48e4) = fVar1;
            fVar9 = (float10)CountdownTimer::Now();
            fVar11 = (float)fVar9 + *(float *)(unaff_EBX + 0x200df8 /* 5.0f */ /* 5.0f */ /* 5.0f */);
            if (*(float *)((int)param_2 + 0x48c0) != fVar11) {
              (**(code **)(*(int *)((int)param_2 + 0x48b8) + 4)) /* timer_0.NetworkStateChanged() */
                        ((int)param_2 + 0x48b8,(int)param_2 + 0x48c0);
              *(float *)((int)param_2 + 0x48c0) = fVar11; /* timer_0.Start(5.0f) */
            }
            if (*(int *)((int)param_2 + 0x48bc) != 0x40a00000 /* 5.0f */) {
              (**(code **)(*(int *)((int)param_2 + 0x48b8) + 4)) /* timer_0.NetworkStateChanged() */
                        ((int)param_2 + 0x48b8,(int)param_2 + 0x48bc);
              *(undefined4 *)((int)param_2 + 0x48bc) = 0x40a00000 /* 5.0f */;
            }
          }
          fVar9 = (float10)CountdownTimer::Now();
          if (*(float *)((int)param_2 + 0x48cc) <= (float)fVar9 && /* timer_1.IsElapsed() */
              (float)fVar9 != *(float *)((int)param_2 + 0x48cc)) {
            uVar5 = (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
            CINSBotLocomotion::AddMovementRequest
                      (uVar5,*(undefined4 *)((int)param_2 + 0x3c),
                       *(undefined4 *)((int)param_2 + 0x40),*(undefined4 *)((int)param_2 + 0x44),2,5
                       ,0x3f19999a /* 0.6f */);
            piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
            uVar3 = (**(code **)(*piVar6 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar6,(int)param_2 + 0x3c,0);
            *(undefined1 *)((int)param_2 + 0x48f8) = uVar3;
            piVar6 = (int *)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))
                                      (in_stack_0000000c + 0x2060);
            if (piVar6 == (int *)0x0) {
              fVar9 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                                         (in_stack_0000000c + 0x2060,(int)param_2 + 0x3c);
              *(float *)((int)param_2 + 0x48f4) = (float)fVar9;
            }
            else {
              iVar7 = (**(code **)(*piVar6 + 0x3c))(piVar6);
              fVar11 = 0.0;
              for (iVar7 = *(int *)(iVar7 + 0x1c); iVar7 != 0;
                  iVar7 = (**(code **)(*piVar6 + 0x54))(piVar6,iVar7)) {
                fVar11 = fVar11 + *(float *)(iVar7 + 0x28);
              }
              *(float *)((int)param_2 + 0x48f4) = fVar11;
            }
            fVar9 = (float10)CountdownTimer::Now();
            fVar11 = (float)fVar9 + *(float *)(unaff_EBX + 0x200de4 /* 0.5f */ /* 0.5f */ /* 0.5f */);
            if (*(float *)((int)param_2 + 0x48cc) != fVar11) {
              (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4)) /* timer_1.NetworkStateChanged() */
                        ((int)param_2 + 0x48c4,(int)param_2 + 0x48cc);
              *(float *)((int)param_2 + 0x48cc) = fVar11; /* timer_1.Start(0.5f) */
            }
            if (*(int *)((int)param_2 + 0x48c8) != 0x3f000000 /* 0.5f */) {
              (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4)) /* timer_1.NetworkStateChanged() */
                        ((int)param_2 + 0x48c4,(int)param_2 + 0x48c8);
              *(undefined4 *)((int)param_2 + 0x48c8) = 0x3f000000 /* 0.5f */;
            }
          }
          if ((*(char *)((int)param_2 + 0x48fa) == '\0') ||
             (fVar9 = (float10)CountdownTimer::Now(),
             (float)fVar9 < *(float *)((int)param_2 + 0x48f0) || /* !timer_3.IsElapsed() */
             (float)fVar9 == *(float *)((int)param_2 + 0x48f0))) {
            *(undefined4 *)param_1 = 0 /* Continue */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined4 *)(param_1 + 8) = 0;
          }
          else {
            *(undefined4 *)param_1 = 3 /* Done */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(int *)(param_1 + 8) = unaff_EBX + 0x25dab3 /* "Bot can't do anything" */ /* "Bot can't do anything" */ /* "Bot can't do anything" */;
          }
        }
        else {
          *(undefined4 *)param_1 = 3 /* Done */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x25db40 /* "Goal position no longer valid?" */ /* "Goal position no longer valid?" */ /* "Goal position no longer valid?" */;
        }
      }
      else {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x25da9f /* "Idle in Investigate" */ /* "Idle in Investigate" */ /* "Idle in Investigate" */;
      }
    }
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnEnd
 * Address: 00723330
 * ---------------------------------------- */

/* CINSBotInvestigate::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotInvestigate::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  char cVar2;
  CINSNextBot *this;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  
  __i686_get_pc_thunk_bx();
  cVar2 = CINSNextBot::HasInvestigations(this);
  this_00 = extraout_ECX;
  if ((cVar2 != '\0') && (piVar1 = *(int **)(param_2 + 0xb45c), piVar1[2] != -0x40800000 /* -1.0f */)) {
    (**(code **)(*piVar1 + 4))(piVar1,piVar1 + 2);
    piVar1[2] = -0x40800000 /* -1.0f */;
    this_00 = extraout_ECX_00;
  }
  CINSNextBot::SortAndRemoveInvestigations(this_00);
  CINSNextBot::SetInvestigating(this_01,SUB41(param_2,0));
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnSuspend
 * Address: 007233b0
 * ---------------------------------------- */

/* CINSBotInvestigate::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotInvestigate::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  bool bVar1;
  CINSNextBot *this;
  
  bVar1 = (bool)__i686_get_pc_thunk_bx();
  CINSNextBot::SetInvestigating(this,bVar1);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnResume
 * Address: 00723800
 * ---------------------------------------- */

/* CINSBotInvestigate::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotInvestigate::OnResume(CINSBotInvestigate *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  char cVar2;
  undefined4 uVar3;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *this_03;
  int unaff_EBX;
  float10 fVar4;
  bool in_stack_0000000c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  if ((*(int *)(param_2 + 0x38) != 0) &&
     (cVar2 = CINSNextBot::HasInvestigations(this_00), cVar2 != '\0')) {
    CINSNextBot::SetInvestigating(this_01,in_stack_0000000c);
    CNavArea::GetRandomPoint();
    *(undefined4 *)(param_2 + 0x3c) = local_28;
    *(undefined4 *)(param_2 + 0x40) = local_24;
    *(undefined4 *)(param_2 + 0x44) = local_20;
    uVar3 = CINSNextBot::GetCurrentInvestigationPriority(this_02);
    *(undefined4 *)(param_2 + 0x48fc) = uVar3;
    fVar4 = (float10)CountdownTimer::Now();
    fVar1 = *(float *)(&LAB_00200f58 + unaff_EBX);
    this_03 = extraout_ECX;
    if (*(float *)(param_2 + 0x48c0) != (float)fVar4 + fVar1) {
      (**(code **)(*(int *)(param_2 + 0x48b8) + 4))(param_2 + 0x48b8,param_2 + 0x48c0); /* timer_0.NetworkStateChanged() */
      *(float *)(param_2 + 0x48c0) = (float)fVar4 + fVar1; /* timer_0.Start(...) */
      this_03 = extraout_ECX_00;
    }
    if (*(int *)(param_2 + 0x48bc) != 0x40a00000 /* 5.0f */) {
      (**(code **)(*(int *)(param_2 + 0x48b8) + 4))(param_2 + 0x48b8,param_2 + 0x48bc); /* timer_0.NetworkStateChanged() */
      *(undefined4 *)(param_2 + 0x48bc) = 0x40a00000 /* 5.0f */;
      this_03 = extraout_ECX_01;
    }
    CINSNextBot::ResetIdleStatus(this_03);
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x25dbe3 /* "Invalid investigation area?" */ /* "Invalid investigation area?" */ /* "Invalid investigation area?" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigate::GetName
 * Address: 00724890
 * ---------------------------------------- */

/* CINSBotInvestigate::GetName() const */

int CINSBotInvestigate::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25cb24 /* "Investigating" */ /* "Investigating" */ /* "Investigating" */;
}



/* ----------------------------------------
 * CINSBotInvestigate::ShouldHurry
 * Address: 00723400
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigate::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotInvestigate::ShouldHurry(CINSBotInvestigate *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::ShouldHurry
 * Address: 00723410
 * ---------------------------------------- */

/* CINSBotInvestigate::ShouldHurry(INextBot const*) const */

uint __cdecl CINSBotInvestigate::ShouldHurry(INextBot *param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int unaff_EBX;
  
  uVar2 = __i686_get_pc_thunk_bx();
  if (*(int *)(param_1 + 0x48fc) != 8) {
    iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x483123 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */) + 0x40))(*(int **)(unaff_EBX + 0x483123 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */));
    fVar1 = *(float *)(param_1 + 0x48f4);
    if (iVar3 == 0) {
      uVar2 = 0;
      if (*(float *)(unaff_EBX + 0x201c0f /* 180.0f */ /* 180.0f */ /* 180.0f */) <= fVar1) {
        return (fVar1 < *(float *)(unaff_EBX + 0x25e0e7 /* 1440.0f */ /* 1440.0f */ /* 1440.0f */) ||
               fVar1 == *(float *)(unaff_EBX + 0x25e0e7 /* 1440.0f */ /* 1440.0f */ /* 1440.0f */)) + 1;
      }
    }
    else {
      uVar2 = (uint)(*(float *)(unaff_EBX + 0x2023af /* 80.0f */ /* 80.0f */ /* 80.0f */) <= fVar1 &&
                    fVar1 != *(float *)(unaff_EBX + 0x2023af /* 80.0f */ /* 80.0f */ /* 80.0f */));
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnContact
 * Address: 00723110
 * ---------------------------------------- */

/* CINSBotInvestigate::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotInvestigate::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnMoveToSuccess
 * Address: 00723090
 * ---------------------------------------- */

/* CINSBotInvestigate::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotInvestigate::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x25e3ab /* "Arrived at investigation target." */ /* "Arrived at investigation target." */ /* "Arrived at investigation target." */;
  *(undefined4 *)(param_1 + 0xc) = 3;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnMoveToFailure
 * Address: 007230d0
 * ---------------------------------------- */

/* CINSBotInvestigate::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotInvestigate::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = &UNK_0025e38f + extraout_ECX;
  param_1[3] = 3;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnStuck
 * Address: 007231f0
 * ---------------------------------------- */

/* CINSBotInvestigate::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotInvestigate::OnStuck(CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)::operator_new(0x6c);
  piVar2[8] = 0;
  piVar2[9] = 0;
  piVar2[10] = 0;
  piVar2[3] = 0;
  piVar2[4] = 0;
  piVar2[5] = 0;
  piVar2[6] = 0;
  piVar2[7] = 0;
  piVar2[2] = 0;
  *(undefined1 *)(piVar2 + 0xc) = 0;
  *(undefined1 *)((int)piVar2 + 0x31) = 0;
  piVar2[0xb] = 0;
  piVar2[0xd] = 0;
  iVar1 = *(int *)(unaff_EBX + 0x4837bd /* &vtable for CINSBotStuck */ /* &vtable for CINSBotStuck */ /* &vtable for CINSBotStuck */);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = (int)(&UNK_00404fbd + unaff_EBX);
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x25c856 /* "I'm Stuck" */ /* "I'm Stuck" */ /* "I'm Stuck" */;
  piVar2[0x17] = 0;
  piVar2[0x18] = 0;
  piVar2[0x19] = 0;
  piVar2[0x1a] = 0;
  *(undefined4 *)param_1 = 1 /* ChangeTo */;
  *(int **)(param_1 + 4) = piVar2;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnLostSight
 * Address: 00723060
 * ---------------------------------------- */

/* CINSBotInvestigate::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotInvestigate::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnHeardFootsteps
 * Address: 00723170
 * ---------------------------------------- */

/* CINSBotInvestigate::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotInvestigate::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnNavAreaChanged
 * Address: 00723140
 * ---------------------------------------- */

/* CINSBotInvestigate::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotInvestigate::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::OnSeeSomethingSuspicious
 * Address: 007231a0
 * ---------------------------------------- */

/* CINSBotInvestigate::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void CINSBotInvestigate::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::ShouldWalk
 * Address: 007231d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigate::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotInvestigate::ShouldWalk(CINSBotInvestigate *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::ShouldWalk
 * Address: 007231e0
 * ---------------------------------------- */

/* CINSBotInvestigate::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotInvestigate::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotInvestigate::~CINSBotInvestigate
 * Address: 007248b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigate::~CINSBotInvestigate() */

void __thiscall CINSBotInvestigate::~CINSBotInvestigate(CINSBotInvestigate *this)

{
  ~CINSBotInvestigate(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::~CINSBotInvestigate
 * Address: 007248c0
 * ---------------------------------------- */

/* CINSBotInvestigate::~CINSBotInvestigate() */

void __thiscall CINSBotInvestigate::~CINSBotInvestigate(CINSBotInvestigate *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x472c7a /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x472e12 /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::~CINSBotInvestigate
 * Address: 00724920
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigate::~CINSBotInvestigate() */

void __thiscall CINSBotInvestigate::~CINSBotInvestigate(CINSBotInvestigate *this)

{
  ~CINSBotInvestigate(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigate::~CINSBotInvestigate
 * Address: 00724930
 * ---------------------------------------- */

/* CINSBotInvestigate::~CINSBotInvestigate() */

void __thiscall CINSBotInvestigate::~CINSBotInvestigate(CINSBotInvestigate *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x472c0a /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */ /* vtable for CINSBotInvestigate+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x472da2 /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */ /* vtable for CINSBotInvestigate+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



