/*
 * CINSBotInvestigateGunshot -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 21
 */

/* ----------------------------------------
 * CINSBotInvestigateGunshot::CINSBotInvestigateGunshot
 * Address: 00724d40
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::CINSBotInvestigateGunshot(Vector) */

void __thiscall
CINSBotInvestigateGunshot::CINSBotInvestigateGunshot
          (undefined4 param_1,int *param_2,int param_3,int param_4,int param_5)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  float fVar4;
  CINSPathFollower *this;
  CINSPathFollower *this_00;
  int unaff_EBX;
  float10 fVar5;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  *param_2 = unaff_EBX + 0x4729fd /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */;
  param_2[1] = unaff_EBX + 0x472b95 /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */;
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
  pcVar1 = (code *)(unaff_EBX + -0x4f45db /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  param_2[0x122e] = 0;
  iVar2 = unaff_EBX + 0x40346d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  param_2[0x122d] = iVar2; /* CountdownTimer timer_0 */
  (*pcVar1)(param_2 + 0x122d,param_2 + 0x122e);
  param_2[0x122f] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x122d] + 4))(param_2 + 0x122d,param_2 + 0x122f); /* timer_0.NetworkStateChanged() */
  param_2[0x1231] = 0;
  param_2[0x1230] = iVar2; /* CountdownTimer timer_1 */
  (*pcVar1)(param_2 + 0x1230,param_2 + 0x1231);
  param_2[0x1232] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x1230] + 4))(param_2 + 0x1230,param_2 + 0x1232); /* timer_1.NetworkStateChanged() */
  piVar3 = param_2 + 0x1233;
  param_2[0x1234] = 0;
  param_2[0x1233] = iVar2; /* CountdownTimer timer_2 */
  (*pcVar1)(piVar3,param_2 + 0x1234);
  param_2[0x1235] = -0x40800000 /* -1.0f */; /* timer_2.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x1233] + 4))(piVar3,param_2 + 0x1235); /* timer_2.NetworkStateChanged() */
  CINSPathFollower::Invalidate(this_00);
  fVar5 = (float10)CountdownTimer::Now();
  fVar4 = (float)param_2[0x1234];
  if ((float)param_2[0x1235] != (float)fVar5 + fVar4) {
    (**(code **)(param_2[0x1233] + 4))(piVar3,param_2 + 0x1235); /* timer_2.NetworkStateChanged() */
    param_2[0x1235] = (int)((float)fVar5 + fVar4); /* timer_2.Start(...) */
  }
  *(undefined1 *)(param_2 + 0x123a) = 0;
  param_2[0x1239] = -0x40800000 /* -1.0f */;
  param_2[0xe] = param_3;
  param_2[0xf] = param_4;
  param_2[0x10] = param_5;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnStart
 * Address: 00724b70
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotInvestigateGunshot::OnStart
          (CINSBotInvestigateGunshot *this,CINSNextBot *param_1,Action *param_2)

{
  CINSPathFollower *pCVar1;
  CINSNextBot *this_00;
  float10 fVar2;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar2 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this_00);
  *(float *)(param_2 + 0x4820) = (float)fVar2;
  fVar2 = (float10)CINSNextBot::MaxPathLength();
  pCVar1 = (CINSPathFollower *)0x0;
  if (in_stack_0000000c != 0) {
    pCVar1 = (CINSPathFollower *)(in_stack_0000000c + 0x2060);
  }
  CINSPathFollower::ComputePath
            ((CINSPathFollower *)(in_stack_0000000c + 0x2060),param_2 + 0x44,pCVar1,param_2 + 0x38,2
             ,(float)fVar2,0,0x41f00000 /* 30.0f */);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::Update
 * Address: 00725040
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotInvestigateGunshot::Update
          (CINSBotInvestigateGunshot *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  code *pcVar2;
  undefined1 uVar3;
  char cVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  float *pfVar8;
  CINSNextBotManager *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  int extraout_EDX;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  CBaseEntity *this_01;
  float fVar12;
  float fVar13;
  int *in_stack_0000000c;
  int *piVar14;
  float local_30;
  int local_2c;
  int *local_28;
  CINSPathFollower *local_20;
  
  __i686_get_pc_thunk_bx();
  if (0 < in_stack_0000000c[0x2d1a]) {
    iVar6 = in_stack_0000000c[0x2d17];
    if (((*(float *)(extraout_EDX + 0x38 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) != *(float *)(iVar6 + 0xc)) ||
        (*(float *)(extraout_EDX + 0x3c /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) != *(float *)(iVar6 + 0x10))) ||
       (*(float *)(extraout_EDX + 0x40 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) != *(float *)(iVar6 + 0x14))) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25c4d1 /* "Leaving investigation, we changed targets." */ /* "Leaving investigation, we changed targets." */ /* "Leaving investigation, we changed targets." */;
      return param_1;
    }
    fVar9 = (float10)CountdownTimer::Now();
    if (*(float *)(iVar6 + 8) <= (float)fVar9 && (float)fVar9 != *(float *)(iVar6 + 8)) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25c4fd /* "Leaving investigation, time elapsed." */ /* "Leaving investigation, time elapsed." */ /* "Leaving investigation, time elapsed." */;
      return param_1;
    }
  }
  piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  iVar6 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
  if (iVar6 == 0) {
    fVar10 = *(float *)(unaff_EBX + 0x204175 /* -0.01f */ /* -0.01f */ /* -0.01f */);
    if ((((*(float *)(extraout_EDX + 0x38 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) <= fVar10) ||
         (fVar1 = *(float *)(&DAT_001fffd9 + unaff_EBX), fVar1 <= *(float *)(extraout_EDX + 0x38 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */)))
        || ((*(float *)(extraout_EDX + 0x3c /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) <= fVar10 ||
            ((fVar1 <= *(float *)(extraout_EDX + 0x3c /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) ||
             (*(float *)(extraout_EDX + 0x40 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) <= fVar10)))))) ||
       (fVar1 <= *(float *)(extraout_EDX + 0x40 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */))) {
      fVar9 = (float10)CountdownTimer::Now();
      if (*(float *)(extraout_EDX + 0x48bc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) <= (float)fVar9 &&
          (float)fVar9 != *(float *)(extraout_EDX + 0x48bc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */)) {
        piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))();
        pfVar8 = (float *)(**(code **)(*piVar5 + 0x148 /* PlayerLocomotion::GetFeet */))(piVar5);
        fVar10 = pfVar8[1];
        fVar1 = pfVar8[2];
        fVar13 = *(float *)(extraout_EDX + 0x48d8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) - *pfVar8;
        fVar11 = *(float *)(extraout_EDX + 0x48dc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) - fVar10;
        fVar12 = *(float *)(extraout_EDX + 0x48e0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) - fVar1;
        if (SQRT(fVar11 * fVar11 + fVar13 * fVar13 + fVar12 * fVar12) <
            *(float *)(unaff_EBX + 0x1fea31 /* 16.0f */ /* 16.0f */ /* 16.0f */)) {
          if (0 < in_stack_0000000c[0x2d1a]) {
            CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::Remove
                      ((int)(in_stack_0000000c + 0x2d17));
          }
          *(undefined4 *)param_1 = 3 /* Done */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x25c47d /* "Gave up investigating, took too long." */ /* "Gave up investigating, took too long." */ /* "Gave up investigating, took too long." */;
          return param_1;
        }
        *(float *)(extraout_EDX + 0x48d8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = *pfVar8;
        *(float *)(extraout_EDX + 0x48dc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = fVar10;
        *(float *)(extraout_EDX + 0x48e0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = fVar1;
        fVar9 = (float10)CountdownTimer::Now();
        fVar10 = *(float *)(&LAB_001ff715 + unaff_EBX);
        if (*(float *)(extraout_EDX + 0x48bc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != (float)fVar9 + fVar10) {
          (**(code **)(*(int *)(extraout_EDX + 0x48b4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48b4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48bc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(float *)(extraout_EDX + 0x48bc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = (float)fVar9 + fVar10;
        }
        if (*(int *)(extraout_EDX + 0x48b8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != 0x40a00000 /* 5.0f */) {
          (**(code **)(*(int *)(extraout_EDX + 0x48b4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48b4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48b8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(undefined4 *)(extraout_EDX + 0x48b8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = 0x40a00000 /* 5.0f */;
        }
      }
      fVar9 = (float10)CountdownTimer::Now();
      if (*(float *)(extraout_EDX + 0x48c8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) <= (float)fVar9 &&
          (float)fVar9 != *(float *)(extraout_EDX + 0x48c8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */)) {
        fVar9 = (float10)RandomFloat(0x40200000 /* 2.5f */,0x40a00000 /* 5.0f */);
        fVar10 = (float)fVar9;
        fVar9 = (float10)CountdownTimer::Now();
        this_01 = (CBaseEntity *)((float)fVar9 + fVar10);
        if (*(CBaseEntity **)(extraout_EDX + 0x48c8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != this_01) {
          (**(code **)(*(int *)(extraout_EDX + 0x48c0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48c0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48c8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(CBaseEntity **)(extraout_EDX + 0x48c8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = this_01;
          this_01 = extraout_ECX;
        }
        if (*(float *)(extraout_EDX + 0x48c4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != fVar10) {
          (**(code **)(*(int *)(extraout_EDX + 0x48c0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48c0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48c4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(float *)(extraout_EDX + 0x48c4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = fVar10;
          this_01 = extraout_ECX_00;
        }
        this_00 = (CINSNextBotManager *)CBaseEntity::GetTeamNumber(this_01);
        iVar6 = TheINSNextBots();
        cVar4 = CINSNextBotManager::AreBotsOnTeamInCombat(this_00,iVar6);
        if (cVar4 != '\0') {
          fVar9 = (float10)CINSNextBot::MaxPathLength();
          CINSPathFollower::ComputePath
                    ((CINSPathFollower *)(extraout_EDX + 0x44 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */),
                     (CINSPathFollower *)(extraout_EDX + 0x44 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */),in_stack_0000000c + 0x818,
                     extraout_EDX + 0x38 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */,0,(float)fVar9,0,0x41f00000 /* 30.0f */);
        }
      }
      local_20 = (CINSPathFollower *)(extraout_EDX + 0x44 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */);
      local_2c = extraout_EDX + 0x38 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */;
      local_28 = in_stack_0000000c + 0x818;
      fVar9 = (float10)CountdownTimer::Now();
      if (*(float *)(extraout_EDX + 0x48d4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) <= (float)fVar9 &&
          (float)fVar9 != *(float *)(extraout_EDX + 0x48d4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */)) {
        piVar14 = local_28;
        CINSPathFollower::Update(local_20,(INextBot *)local_20);
        piVar5 = (int *)(*(int **)(unaff_EBX + 0x481d39 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */))[7];
        if (piVar5 == *(int **)(unaff_EBX + 0x481d39 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */)) {
          local_30 = (float)((uint)piVar5 ^ piVar5[0xb]);
        }
        else {
          fVar9 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5,piVar14);
          local_30 = (float)fVar9;
        }
        fVar9 = (float10)CountdownTimer::Now();
        if (*(float *)(extraout_EDX + 0x48d4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != (float)fVar9 + local_30) {
          (**(code **)(*(int *)(extraout_EDX + 0x48cc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48cc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48d4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(float *)(extraout_EDX + 0x48d4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = (float)fVar9 + local_30;
        }
        if (*(float *)(extraout_EDX + 0x48d0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) != local_30) {
          (**(code **)(*(int *)(extraout_EDX + 0x48cc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) + 4))
                    (extraout_EDX + 0x48cc /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */,extraout_EDX + 0x48d0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */);
          *(float *)(extraout_EDX + 0x48d0 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = local_30;
        }
      }
      pcVar2 = *(code **)(*(int *)(extraout_EDX + 0x44 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) + 0x28);
      uVar7 = (**(code **)(in_stack_0000000c[0x818] + 0xe4))(local_28);
      (*pcVar2)(local_20,uVar7,0,0);
      iVar6 = (**(code **)(*(int *)(extraout_EDX + 0x44 /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */ /* CINSBotInvestigateGunshot::Update */) + 0x3c))(local_20);
      fVar10 = 0.0;
      for (iVar6 = *(int *)(iVar6 + 0x1c); iVar6 != 0;
          iVar6 = (**(code **)(*(int *)local_20 + 0x54))(local_20,iVar6)) {
        fVar10 = fVar10 + *(float *)(iVar6 + 0x28);
      }
      *(float *)(extraout_EDX + 0x48e4 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = fVar10;
      uVar3 = (**(code **)(*in_stack_0000000c + 0x444 /* CINSPlayer::IsLineOfSightClear */))(in_stack_0000000c,local_2c,1,0);
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      *(undefined1 *)(extraout_EDX + 0x48e8 /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */ /* CollectIdealPatrolAreas::operator */) = uVar3;
    }
    else {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25c45d /* "Goal position no longer valid?" */ /* "Goal position no longer valid?" */ /* "Goal position no longer valid?" */;
    }
  }
  else {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25c525 /* "Not investigating, we have a threat.
" */ /* "Not investigating, we have a threat.
" */ /* "Not investigating, we have a threat.
" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnEnd
 * Address: 00724a00
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotInvestigateGunshot::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnSuspend
 * Address: 007249e0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotInvestigateGunshot::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnResume
 * Address: 007249c0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotInvestigateGunshot::OnResume(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::GetName
 * Address: 00725690
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::GetName() const */

int CINSBotInvestigateGunshot::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25be7f /* "Gunshot Investigate" */ /* "Gunshot Investigate" */ /* "Gunshot Investigate" */;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::ShouldHurry
 * Address: 00724ad0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigateGunshot::ShouldHurry(INextBot const*) const */

void __thiscall
CINSBotInvestigateGunshot::ShouldHurry(CINSBotInvestigateGunshot *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::ShouldHurry
 * Address: 00724ae0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::ShouldHurry(INextBot const*) const */

int __cdecl CINSBotInvestigateGunshot::ShouldHurry(INextBot *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  if (*(float *)(param_1 + 0x48e4) <= *(float *)(extraout_ECX + 0x2271b3 /* 2000.0f */ /* 2000.0f */ /* 2000.0f */)) {
    return 2;
  }
  return 2 - (uint)(param_1[0x48e8] == (INextBot)0x0);
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnContact
 * Address: 00724a70
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotInvestigateGunshot::OnContact
               (CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnMoveToSuccess
 * Address: 00724fd0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotInvestigateGunshot::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int iVar1;
  int unaff_EBX;
  
  iVar1 = __i686_get_pc_thunk_bx();
  if (0 < *(int *)(iVar1 + 0xb468)) {
    CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::Remove(iVar1 + 0xb45c);
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x25c45f /* "Arrived at investigation target." */ /* "Arrived at investigation target." */ /* "Arrived at investigation target." */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0xc) = 3;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnMoveToFailure
 * Address: 00724f60
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotInvestigateGunshot::OnMoveToFailure(undefined4 *param_1)

{
  int iVar1;
  int unaff_EBX;
  
  iVar1 = __i686_get_pc_thunk_bx();
  if (0 < *(int *)(iVar1 + 0xb468)) {
    CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::Remove(iVar1 + 0xb45c);
  }
  *param_1 = 3;
  param_1[2] = unaff_EBX + 0x25c4f3 /* "Failed pathing to investigation target." */ /* "Failed pathing to investigation target." */ /* "Failed pathing to investigation target." */;
  param_1[1] = 0;
  param_1[3] = 3;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnStuck
 * Address: 00724a40
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnStuck(CINSNextBot*) */

void CINSBotInvestigateGunshot::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnLostSight
 * Address: 00724a10
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotInvestigateGunshot::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::OnNavAreaChanged
 * Address: 00724aa0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotInvestigateGunshot::OnNavAreaChanged
               (CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::ShouldWalk
 * Address: 00724b20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigateGunshot::ShouldWalk(INextBot const*) const */

void __thiscall
CINSBotInvestigateGunshot::ShouldWalk(CINSBotInvestigateGunshot *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::ShouldWalk
 * Address: 00724b30
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::ShouldWalk(INextBot const*) const */

char __cdecl CINSBotInvestigateGunshot::ShouldWalk(INextBot *param_1)

{
  char cVar1;
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  cVar1 = '\x01';
  if (param_1[0x48e8] == (INextBot)0x0) {
    cVar1 = (*(float *)(&LAB_002022a7 + extraout_ECX) < *(float *)(param_1 + 0x48e4) ||
            *(float *)(&LAB_002022a7 + extraout_ECX) == *(float *)(param_1 + 0x48e4)) + '\x01';
  }
  return cVar1;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot
 * Address: 007256b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot() */

void __thiscall
CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot(CINSBotInvestigateGunshot *this)

{
  ~CINSBotInvestigateGunshot(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot
 * Address: 007256c0
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot() */

void __thiscall
CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot(CINSBotInvestigateGunshot *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47207a /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x472212 /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot
 * Address: 00725720
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot() */

void __thiscall
CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot(CINSBotInvestigateGunshot *this)

{
  ~CINSBotInvestigateGunshot(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot
 * Address: 00725730
 * ---------------------------------------- */

/* CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot() */

void __thiscall
CINSBotInvestigateGunshot::~CINSBotInvestigateGunshot(CINSBotInvestigateGunshot *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47200a /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */ /* vtable for CINSBotInvestigateGunshot+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4721a2 /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */ /* vtable for CINSBotInvestigateGunshot+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



