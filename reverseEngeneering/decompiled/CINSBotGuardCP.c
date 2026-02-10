/*
 * CINSBotGuardCP -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 15
 */

/* ----------------------------------------
 * CINSBotGuardCP::CINSBotGuardCP
 * Address: 007208d0
 * ---------------------------------------- */

/* CINSBotGuardCP::CINSBotGuardCP(int, float) */

void __thiscall CINSBotGuardCP::CINSBotGuardCP(CINSBotGuardCP *this,int param_1,float param_2)

{
  code *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  CINSPathFollower *this_00;
  int unaff_EBX;
  undefined4 in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(int *)param_1 = unaff_EBX + 0x4768ad /* vtable for CINSBotGuardCP+0x8 */;
  *(int *)(param_1 + 4) = unaff_EBX + 0x476a3d /* vtable for CINSBotGuardCP+0x198 */;
  puVar3 = *(undefined4 **)(unaff_EBX + 0x485cf1 /* &vec3_origin */);
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  uVar4 = *puVar3;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x3c) = uVar4;
  uVar4 = puVar3[1];
  uVar5 = puVar3[2];
  *(undefined1 *)(param_1 + 0x30) = 0;
  *(undefined1 *)(param_1 + 0x31) = 0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x40) = uVar4;
  *(undefined4 *)(param_1 + 0x44) = uVar5;
  puVar3 = *(undefined4 **)(unaff_EBX + 0x486465 /* &vec3_angle */);
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x48) = *puVar3;
  uVar4 = puVar3[2];
  *(undefined4 *)(param_1 + 0x4c) = puVar3[1];
  *(undefined4 *)(param_1 + 0x50) = uVar4;
  CINSPathFollower::CINSPathFollower(this_00);
  pcVar1 = (code *)(unaff_EBX + -0x4f016b /* CountdownTimer::NetworkStateChanged */);
  *(undefined4 *)(param_1 + 0x48c8) = 0;
  iVar2 = unaff_EBX + 0x4078dd /* vtable for CountdownTimer+0x8 */;
  *(int *)(param_1 + 0x48c4) = iVar2;
  (*pcVar1)(param_1 + 0x48c4,param_1 + 0x48c8);
  *(undefined4 *)(param_1 + 0x48cc) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48c4) + 4))(param_1 + 0x48c4,param_1 + 0x48cc);
  *(int *)(param_1 + 0x48d0) = iVar2;
  *(undefined4 *)(param_1 + 0x48d4) = 0;
  (*pcVar1)(param_1 + 0x48d0,param_1 + 0x48d4);
  *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48d0) + 4))(param_1 + 0x48d0,param_1 + 0x48d8);
  iVar6 = *(int *)(unaff_EBX + 0x486375 /* &vtable for IntervalTimer */);
  *(undefined4 *)(param_1 + 0x48e8) = 0xbf800000 /* -1.0f */;
  *(int *)(param_1 + 0x48e4) = iVar6 + 8;
  (**(code **)(iVar6 + 0x10))(param_1 + 0x48e4,param_1 + 0x48e8);
  *(int *)(param_1 + 0x48ec) = iVar2;
  *(undefined4 *)(param_1 + 0x48f0) = 0;
  (*pcVar1)(param_1 + 0x48ec,param_1 + 0x48f0);
  *(undefined4 *)(param_1 + 0x48f4) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48ec) + 4))(param_1 + 0x48ec,param_1 + 0x48f4);
  *(undefined1 *)(param_1 + 0x48dc) = 0;
  *(float *)(param_1 + 0x38) = param_2;
  *(undefined4 *)(param_1 + 0x48e0) = in_stack_0000000c;
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnStart
 * Address: 00721550
 * ---------------------------------------- */

/* CINSBotGuardCP::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotGuardCP::OnStart(CINSBotGuardCP *this,CINSNextBot *param_1,Action *param_2)

{
  CINSNextBot *this_00;
  CINSBotGuardCP *this_01;
  float10 fVar1;
  int in_stack_0000000c;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this_00);
  *(float *)(param_2 + 0x4830) = (float)fVar1;
  GetRandomHidingSpotForPoint(this_01,(CINSNextBot *)&local_34,in_stack_0000000c);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_2 + 0x3c) = local_34;
  *(undefined4 *)(param_2 + 0x40) = local_30;
  *(undefined4 *)(param_2 + 0x44) = local_2c;
  *(undefined4 *)(param_2 + 0x48) = local_28;
  *(undefined4 *)(param_2 + 0x4c) = local_24;
  *(undefined4 *)(param_2 + 0x50) = local_20;
  *(undefined1 *)(in_stack_0000000c + 0x2290) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardCP::Update
 * Address: 00720f80
 * ---------------------------------------- */

/* CINSBotGuardCP::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotGuardCP::Update(CINSBotGuardCP *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSPathFollower *extraout_ECX_03;
  CINSPathFollower *extraout_ECX_04;
  CINSPathFollower *extraout_ECX_05;
  CINSPathFollower *extraout_ECX_06;
  CINSPathFollower *extraout_ECX_07;
  CINSPathFollower *this_01;
  CINSPathFollower *extraout_ECX_08;
  int unaff_EBX;
  float10 fVar7;
  int *in_stack_0000000c;
  undefined4 uVar8;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x720f8b;
  __i686_get_pc_thunk_bx();
  piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  iVar6 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
  if (iVar6 != 0) {
    piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar6 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,in_stack_0000000c + 0x818,iVar6);
    if (iVar6 == 1) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2602f7 /* "LoS to an enemy." */;
      return param_1;
    }
  }
  iVar6 = **(int **)(unaff_EBX + 0x485d91 /* &g_pObjectiveResource */);
  iVar2 = *(int *)(iVar6 + 0x770);
  iVar3 = *(int *)(iVar6 + 0x450 + iVar2 * 4);
  if (iVar3 == 2) {
    iVar6 = *(int *)(iVar6 + 0x590 + iVar2 * 4);
LAB_00721127:
    if (0 < iVar6) {
      if ((*(char *)((int)param_2 + 0x48dc) != '\0') &&
         (fVar7 = (float10)CountdownTimer::Now(),
         *(float *)((int)param_2 + 0x48d8) <= (float)fVar7 &&
         (float)fVar7 != *(float *)((int)param_2 + 0x48d8))) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26035d /* "Exiting guard state, enemy entering CP" */;
        return param_1;
      }
      fVar7 = (float10)RandomFloat(0,0x41000000 /* 8.0f */);
      fVar1 = (float)fVar7;
      fVar7 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x48d8) != (float)fVar7 + fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48d0) + 4))
                  ((int)param_2 + 0x48d0,(int)param_2 + 0x48d8);
        *(float *)((int)param_2 + 0x48d8) = (float)fVar7 + fVar1;
      }
      if (*(float *)((int)param_2 + 0x48d4) != fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48d0) + 4))
                  ((int)param_2 + 0x48d0,(int)param_2 + 0x48d4);
        *(float *)((int)param_2 + 0x48d4) = fVar1;
      }
      *(undefined1 *)((int)param_2 + 0x48dc) = 1;
    }
  }
  else if (iVar3 == 3) {
    iVar6 = *(int *)(iVar6 + 0x550 + iVar2 * 4);
    goto LAB_00721127;
  }
  if (0.0 < *(float *)((int)param_2 + 0x48e8)) {
    if ((0.0 < *(float *)((int)param_2 + 0x48e0)) &&
       (fVar7 = (float10)IntervalTimer::Now(),
       *(float *)((int)param_2 + 0x48e0) <= (float)fVar7 - *(float *)((int)param_2 + 0x48e8))) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x260308 /* "Finished guarding spot." */;
      return param_1;
    }
    fVar7 = (float10)CountdownTimer::Now();
    this_00 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x48f4) <= (float)fVar7 &&
        (float)fVar7 != *(float *)((int)param_2 + 0x48f4)) {
      AngleVectors((QAngle *)((int)param_2 + 0x48),(Vector *)&local_34);
      fVar1 = *(float *)(unaff_EBX + 0x231245 /* typeinfo name for CPhysicsShake+0x12 */);
      local_24 = local_30 * fVar1 + *(float *)((int)param_2 + 0x40);
      local_28 = fVar1 * local_34 + *(float *)((int)param_2 + 0x3c);
      local_20 = local_2c * fVar1 + *(float *)((int)param_2 + 0x44) +
                 *(float *)(unaff_EBX + 0x197b81 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x2c */);
      piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      (**(code **)(*piVar5 + 0xd4 /* PlayerBody::AimHeadTowards */))(piVar5,&local_28,0,0x3dcccccd /* 0.1f */,0,unaff_EBX + 0x260320 /* "Guard Aiming" */);
      fVar7 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x40a00000 /* 5.0f */);
      fVar1 = (float)fVar7;
      fVar7 = (float10)CountdownTimer::Now();
      this_00 = extraout_ECX_00;
      if (*(float *)((int)param_2 + 0x48f4) != (float)fVar7 + fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48ec) + 4))
                  ((int)param_2 + 0x48ec,(int)param_2 + 0x48f4);
        *(float *)((int)param_2 + 0x48f4) = (float)fVar7 + fVar1;
        this_00 = extraout_ECX_01;
      }
      if (*(float *)((int)param_2 + 0x48f0) != fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48ec) + 4))
                  ((int)param_2 + 0x48ec,(int)param_2 + 0x48f0);
        *(float *)((int)param_2 + 0x48f0) = fVar1;
        this_00 = extraout_ECX_02;
      }
    }
    uVar8 = 0;
    fVar7 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_00,(float)in_stack_0000000c,0x41000000 /* 8.0f */);
    if ((double)(float)fVar7 < *(double *)(unaff_EBX + 0x260395 /* typeinfo name for CINSBotGuardCP+0x11 */)) {
      (**(code **)(*in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3e800000 /* 0.25f */,uVar8);
    }
    goto LAB_007210f5;
  }
  fVar7 = (float10)CountdownTimer::Now();
  this_01 = extraout_ECX_03;
  if (*(float *)((int)param_2 + 0x48cc) <= (float)fVar7 &&
      (float)fVar7 != *(float *)((int)param_2 + 0x48cc)) {
    fVar7 = (float10)CountdownTimer::Now();
    fVar1 = *(float *)(&LAB_002041d9 + unaff_EBX);
    this_01 = extraout_ECX_04;
    if (*(float *)((int)param_2 + 0x48cc) != (float)fVar7 + fVar1) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48cc);
      *(float *)((int)param_2 + 0x48cc) = (float)fVar7 + fVar1;
      this_01 = extraout_ECX_05;
    }
    if (*(int *)((int)param_2 + 0x48c8) != 0x3fc00000 /* 1.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48c8);
      *(undefined4 *)((int)param_2 + 0x48c8) = 0x3fc00000 /* 1.5f */;
      this_01 = extraout_ECX_06;
    }
    pfVar4 = *(float **)(unaff_EBX + 0x485641 /* &vec3_origin */);
    if ((*pfVar4 == *(float *)((int)param_2 + 0x3c)) &&
       (pfVar4[1] == *(float *)((int)param_2 + 0x40))) {
      if (pfVar4[2] == *(float *)((int)param_2 + 0x44)) {
        GetRandomHidingSpotForPoint
                  (*(CINSBotGuardCP **)((int)param_2 + 0x38),(CINSNextBot *)&local_4c,
                   (int)in_stack_0000000c);
        *(float *)((int)param_2 + 0x3c) = local_4c;
        *(undefined4 *)((int)param_2 + 0x44) = local_44;
        *(float *)((int)param_2 + 0x40) = local_48;
        *(undefined4 *)((int)param_2 + 0x48) = local_40;
        *(undefined4 *)((int)param_2 + 0x4c) = local_3c;
        *(undefined4 *)((int)param_2 + 0x50) = local_38;
        if ((local_4c != *pfVar4) || (this_01 = extraout_ECX_07, local_48 != pfVar4[1]))
        goto LAB_00721506;
      }
      if (pfVar4[2] == *(float *)((int)param_2 + 0x44)) goto LAB_007213d2;
    }
LAB_00721506:
    CINSNextBot::MaxPathLength();
    CINSPathFollower::ComputePath();
    this_01 = extraout_ECX_08;
  }
LAB_007213d2:
  if (0 < *(int *)((int)param_2 + 0x4458)) {
    CINSPathFollower::Update(this_01,(INextBot *)((int)param_2 + 0x54));
  }
LAB_007210f5:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnEnd
 * Address: 00720510
 * ---------------------------------------- */

/* CINSBotGuardCP::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotGuardCP::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  param_2[0x2290] = (Action)0x0;
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::GetName
 * Address: 007215f0
 * ---------------------------------------- */

/* CINSBotGuardCP::GetName() const */

int CINSBotGuardCP::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25fc71 /* "Guarding CP" */;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnMoveToSuccess
 * Address: 00720720
 * ---------------------------------------- */

/* CINSBotGuardCP::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * __thiscall
CINSBotGuardCP::OnMoveToSuccess(CINSBotGuardCP *this,CINSNextBot *param_1,Path *param_2)

{
  int unaff_EBX;
  float10 fVar1;
  float fVar2;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x48e8) != (float)fVar1) {
    (**(code **)(*(int *)(param_2 + 0x48e4) + 8))(param_2 + 0x48e4,param_2 + 0x48e8);
    *(float *)(param_2 + 0x48e8) = (float)fVar1;
  }
  fVar1 = (float10)CountdownTimer::Now();
  fVar2 = (float)fVar1 + *(float *)(unaff_EBX + 0x20402a /* typeinfo name for CBaseGameSystem+0x1e */);
  if (*(float *)(param_2 + 0x48f4) != fVar2) {
    (**(code **)(*(int *)(param_2 + 0x48ec) + 4))(param_2 + 0x48ec,param_2 + 0x48f4);
    *(float *)(param_2 + 0x48f4) = fVar2;
  }
  if (*(int *)(param_2 + 0x48f0) != 0x3f000000 /* 0.5f */) {
    (**(code **)(*(int *)(param_2 + 0x48ec) + 4))(param_2 + 0x48ec,param_2 + 0x48f0);
    *(undefined4 *)(param_2 + 0x48f0) = 0x3f000000 /* 0.5f */;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  *(undefined1 *)(in_stack_0000000c + 0x2290) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnMoveToFailure
 * Address: 00720520
 * ---------------------------------------- */

/* CINSBotGuardCP::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotGuardCP::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = extraout_ECX + 0x260d4d /* "Failed move-to." */;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnWeaponFired
 * Address: 00720560
 * ---------------------------------------- */

/* CINSBotGuardCP::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotGuardCP::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::OnCommandApproach
 * Address: 00720590
 * ---------------------------------------- */

/* CINSBotGuardCP::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotGuardCP::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::GetRandomHidingSpotForPoint
 * Address: 00720b40
 * ---------------------------------------- */

/* CINSBotGuardCP::GetRandomHidingSpotForPoint(CINSNextBot*, int) */

CINSNextBot * __thiscall
CINSBotGuardCP::GetRandomHidingSpotForPoint(CINSBotGuardCP *this,CINSNextBot *param_1,int param_2)

{
  CGlobalEntityList *this_00;
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  CSpawnPoint *this_01;
  char cVar7;
  int iVar8;
  char *pcVar9;
  CBaseEntity *pCVar10;
  int iVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  undefined4 uVar14;
  CINSBlockZoneBase *extraout_ECX;
  CINSBlockZoneBase *extraout_ECX_00;
  CSpawnPoint *extraout_ECX_01;
  CSpawnPoint *extraout_ECX_02;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBaseEntity *this_04;
  CBaseEntity *this_05;
  CINSBlockZoneBase *this_06;
  CBaseEntity *this_07;
  CUtlVector<guardData_t,CUtlMemory<guardData_t,int>> *extraout_ECX_03;
  int unaff_EBX;
  uint in_stack_0000000c;
  CGlobalEntityList *pCVar15;
  int local_40;
  
  __i686_get_pc_thunk_bx();
  if (0xf < in_stack_0000000c) {
    puVar12 = *(undefined4 **)(unaff_EBX + 0x485a81 /* &vec3_origin */);
    *(undefined4 *)param_1 = *puVar12;
    uVar14 = puVar12[2];
    *(undefined4 *)(param_1 + 4) = puVar12[1];
    *(undefined4 *)(param_1 + 8) = uVar14;
    puVar12 = *(undefined4 **)(unaff_EBX + 0x4861f5 /* &vec3_angle */);
    *(undefined4 *)(param_1 + 0xc) = *puVar12;
    uVar14 = puVar12[2];
    *(undefined4 *)(param_1 + 0x10) = puVar12[1];
    *(undefined4 *)(param_1 + 0x14) = uVar14;
    return param_1;
  }
  piVar1 = (int *)(unaff_EBX + 0x5cbc15 /* CINSBotGuardCP::m_HidingSpotsAtPoint */ + in_stack_0000000c * 0x14);
  local_40 = piVar1[3];
  if (piVar1[3] == 0) {
    this_00 = (CGlobalEntityList *)(unaff_EBX + 0x2090f9 /* "ins_spawnzone" */);
    pCVar15 = this_00;
    pcVar9 = (char *)CGlobalEntityList::FindEntityByClassname
                               (this_00,*(CBaseEntity **)(unaff_EBX + 0x486219 /* &gEntList */),(char *)0x0);
    this_06 = extraout_ECX;
    while (pcVar9 != (char *)0x0) {
      cVar7 = CINSBlockZoneBase::IsActive(this_06);
      if (cVar7 != '\0') {
        pCVar10 = (CBaseEntity *)
                  CGlobalEntityList::FindEntityByClassname
                            (*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                             (CBaseEntity *)*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                             (char *)0x0);
        this_01 = extraout_ECX_01;
        while (pCVar10 != (CBaseEntity *)0x0) {
          cVar7 = CSpawnPoint::IsDisabled(this_01);
          if (cVar7 == '\0') {
            iVar11 = CBaseEntity::GetTeamNumber(this_02);
            iVar8 = CBaseEntity::GetTeamNumber(this_03);
            if (iVar11 == iVar8) {
              if (((byte)pCVar10[0xd1] & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition(this_04);
              }
              cVar7 = CINSSpawnZone::PointInSpawnZone
                                ((Vector *)(pCVar10 + 0x208),pCVar10,(CINSSpawnZone **)0x0);
              if (cVar7 != '\0') {
                this_05 = *(CBaseEntity **)(unaff_EBX + 0x485a81 /* &vec3_origin */);
                if ((((byte)pCVar10[0xd1] & 8) != 0) &&
                   (CBaseEntity::CalcAbsolutePosition(this_05), this_05 = this_07,
                   (*(uint *)(pCVar10 + 0xd0) & 0x800) != 0)) {
                  CBaseEntity::CalcAbsolutePosition(this_07);
                  this_05 = (CBaseEntity *)extraout_ECX_03;
                }
                CUtlVector<guardData_t,CUtlMemory<guardData_t,int>>::InsertBefore
                          ((CUtlVector<guardData_t,CUtlMemory<guardData_t,int>> *)this_05,
                           (int)piVar1,(guardData_t *)piVar1[3]);
              }
            }
          }
          pCVar10 = (CBaseEntity *)
                    CGlobalEntityList::FindEntityByClassname
                              (*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                               (CBaseEntity *)*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                               (char *)pCVar10);
          this_01 = extraout_ECX_02;
        }
      }
      pCVar15 = this_00;
      pcVar9 = (char *)CGlobalEntityList::FindEntityByClassname
                                 (*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                                  (CBaseEntity *)*(CGlobalEntityList **)(unaff_EBX + 0x486219 /* &gEntList */),
                                  pcVar9);
      this_06 = extraout_ECX_00;
    }
    iVar11 = piVar1[3];
    if (0 < iVar11) {
      local_40 = 0;
      iVar8 = 0;
      do {
        puVar12 = (undefined4 *)(*piVar1 + iVar8);
        uVar14 = *puVar12;
        uVar2 = puVar12[1];
        uVar3 = puVar12[2];
        uVar4 = puVar12[3];
        uVar5 = puVar12[4];
        uVar6 = puVar12[5];
        iVar11 = RandomInt(0,iVar11 + -1,pCVar15);
        local_40 = local_40 + 1;
        puVar12 = (undefined4 *)(*piVar1 + iVar11 * 0x18);
        puVar13 = (undefined4 *)(*piVar1 + iVar8);
        iVar8 = iVar8 + 0x18;
        *puVar13 = *puVar12;
        puVar13[1] = puVar12[1];
        puVar13[2] = puVar12[2];
        puVar13[3] = puVar12[3];
        puVar13[4] = puVar12[4];
        puVar13[5] = puVar12[5];
        this_06 = (CINSBlockZoneBase *)(iVar11 * 0x18 + *piVar1);
        *(undefined4 *)this_06 = uVar14;
        *(undefined4 *)((CBaseEntity *)this_06 + 4) = uVar2;
        *(undefined4 *)((CBaseEntity *)this_06 + 8) = uVar3;
        *(undefined4 *)((CBaseEntity *)this_06 + 0xc) = uVar4;
        *(undefined4 *)((CBaseEntity *)this_06 + 0x10) = uVar5;
        *(undefined4 *)((CBaseEntity *)this_06 + 0x14) = uVar6;
        iVar11 = piVar1[3];
      } while (local_40 < iVar11);
    }
    if (iVar11 == 0) {
      uVar14 = CBaseEntity::GetTeamNumber((CBaseEntity *)this_06);
      Warning(unaff_EBX + 0x26076d /* "Failed finding guard spots for CP %i, Team %i
" */,in_stack_0000000c,uVar14);
      iVar11 = piVar1[3];
    }
    local_40 = iVar11;
    if (iVar11 == 0) {
      puVar12 = *(undefined4 **)(unaff_EBX + 0x485a81 /* &vec3_origin */);
      *(undefined4 *)param_1 = *puVar12;
      uVar14 = puVar12[2];
      *(undefined4 *)(param_1 + 4) = puVar12[1];
      *(undefined4 *)(param_1 + 8) = uVar14;
      puVar12 = *(undefined4 **)(unaff_EBX + 0x4861f5 /* &vec3_angle */);
      *(undefined4 *)(param_1 + 0xc) = *puVar12;
      uVar14 = puVar12[2];
      *(undefined4 *)(param_1 + 0x10) = puVar12[1];
      *(undefined4 *)(param_1 + 0x14) = uVar14;
      return param_1;
    }
  }
  iVar11 = *piVar1;
  iVar8 = *(int *)(unaff_EBX + 0x5cbbd5 /* CINSBotGuardCP::m_iSelectedHidingSpot */ + in_stack_0000000c * 4) + 1;
  *(int *)(unaff_EBX + 0x5cbbd5 /* CINSBotGuardCP::m_iSelectedHidingSpot */ + in_stack_0000000c * 4) = iVar8;
  puVar12 = (undefined4 *)(iVar11 + (iVar8 % local_40) * 0x18);
  *(undefined4 *)param_1 = *puVar12;
  *(undefined4 *)(param_1 + 4) = puVar12[1];
  *(undefined4 *)(param_1 + 8) = puVar12[2];
  *(undefined4 *)(param_1 + 0xc) = puVar12[3];
  uVar14 = puVar12[5];
  *(undefined4 *)(param_1 + 0x10) = puVar12[4];
  *(undefined4 *)(param_1 + 0x14) = uVar14;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardCP::ResetHidingSpots
 * Address: 00720af0
 * ---------------------------------------- */

/* CINSBotGuardCP::ResetHidingSpots() */

void CINSBotGuardCP::ResetHidingSpots(void)

{
  int iVar1;
  int iVar2;
  int unaff_EBX;
  
  iVar1 = __i686_get_pc_thunk_bx();
  do {
    *(undefined4 *)(iVar1 * 4 + unaff_EBX + 0x5cbc24 /* CINSBotGuardCP::m_iSelectedHidingSpot */) = 0;
    iVar2 = iVar1 + 1;
    *(undefined4 *)(unaff_EBX + 0x5cbc70 /* CINSBotGuardCP::m_HidingSpotsAtPoint+0xc */ + iVar1 * 0x14) = 0;
    iVar1 = iVar2;
  } while (iVar2 != 0x10);
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::~CINSBotGuardCP
 * Address: 00721610
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGuardCP::~CINSBotGuardCP() */

void __thiscall CINSBotGuardCP::~CINSBotGuardCP(CINSBotGuardCP *this)

{
  ~CINSBotGuardCP(this);
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::~CINSBotGuardCP
 * Address: 00721620
 * ---------------------------------------- */

/* CINSBotGuardCP::~CINSBotGuardCP() */

void __thiscall CINSBotGuardCP::~CINSBotGuardCP(CINSBotGuardCP *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x475b5a /* vtable for CINSBotGuardCP+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x475cea /* vtable for CINSBotGuardCP+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::~CINSBotGuardCP
 * Address: 00721680
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGuardCP::~CINSBotGuardCP() */

void __thiscall CINSBotGuardCP::~CINSBotGuardCP(CINSBotGuardCP *this)

{
  ~CINSBotGuardCP(this);
  return;
}



/* ----------------------------------------
 * CINSBotGuardCP::~CINSBotGuardCP
 * Address: 00721690
 * ---------------------------------------- */

/* CINSBotGuardCP::~CINSBotGuardCP() */

void __thiscall CINSBotGuardCP::~CINSBotGuardCP(CINSBotGuardCP *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x475aea /* vtable for CINSBotGuardCP+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x475c7a /* vtable for CINSBotGuardCP+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



