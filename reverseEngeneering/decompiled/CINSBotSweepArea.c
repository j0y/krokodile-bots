/*
 * CINSBotSweepArea -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 10
 */

/* ----------------------------------------
 * CINSBotSweepArea::OnStart
 * Address: 00733450
 * ---------------------------------------- */

/* CINSBotSweepArea::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotSweepArea::OnStart(CINSNextBot *param_1,Action *param_2)

{
  undefined4 uVar1;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this;
  CBaseEntity *this_00;
  float10 fVar2;
  
  __i686_get_pc_thunk_bx();
  this = extraout_ECX;
  if (*(int *)(param_2 + 0x48c8) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(param_2 + 0x48c0) + 4))(param_2 + 0x48c0,param_2 + 0x48c8);
    *(undefined4 *)(param_2 + 0x48c8) = 0xbf800000 /* -1.0f */;
    this = extraout_ECX_00;
  }
  fVar2 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this);
  *(undefined4 *)(param_2 + 0x48b4) = 0;
  *(float *)(param_2 + 0x4814) = (float)fVar2;
  uVar1 = CBaseEntity::GetTeamNumber(this_00);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_2 + 0x48b8) = uVar1;
  *(undefined4 *)(param_2 + 0x48bc) = 0;
  *(undefined4 *)(param_2 + 0x48e4) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSweepArea::Update
 * Address: 007339d0
 * ---------------------------------------- */

/* CINSBotSweepArea::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotSweepArea::Update(CINSBotSweepArea *this,CINSNextBot *param_1,float param_2)

{
  undefined4 *puVar1;
  int iVar2;
  code *pcVar3;
  int *piVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  CINSPathFollower *pCVar9;
  CINSPathFollower *extraout_ECX;
  CINSBotSweepArea *extraout_ECX_00;
  CINSPathFollower *extraout_ECX_01;
  CINSPathFollower *extraout_ECX_02;
  CINSPathFollower *extraout_ECX_03;
  int unaff_EBX;
  int iVar10;
  float10 fVar11;
  float fVar12;
  CINSPathFollower *in_stack_0000000c;
  int local_74;
  int local_70;
  int local_6c [3];
  Vector *local_60;
  undefined4 local_5c;
  CINSPathFollower *local_58;
  undefined4 local_4c;
  undefined4 local_48;
  float local_44;
  undefined1 local_40 [12];
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x7339db;
  __i686_get_pc_thunk_bx();
  fVar11 = (float10)CountdownTimer::Now();
  if (((float)fVar11 < *(float *)((int)param_2 + 0x48d4) ||
       (float)fVar11 == *(float *)((int)param_2 + 0x48d4)) ||
     (fVar11 = (float10)CountdownTimer::Now(),
     (float)fVar11 < *(float *)((int)param_2 + 0x48e0) ||
     (float)fVar11 == *(float *)((int)param_2 + 0x48e0))) {
    fVar11 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x48e0) <= (float)fVar11 &&
        (float)fVar11 != *(float *)((int)param_2 + 0x48e0)) {
      iVar6 = (**(code **)(*(int *)in_stack_0000000c + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_0000000c);
      if (iVar6 == 0) {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24e579 /* "No last known area when sweeping?" */;
        return param_1;
      }
      fVar11 = (float10)RandomFloat(0x3fc00000 /* 1.5f */,0x40000000 /* 2.0f */);
      fVar12 = (float)fVar11;
      fVar11 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x48e0) != (float)fVar11 + fVar12) {
        (**(code **)(*(int *)((int)param_2 + 0x48d8) + 4))
                  ((int)param_2 + 0x48d8,(int)param_2 + 0x48e0);
        *(float *)((int)param_2 + 0x48e0) = (float)fVar11 + fVar12;
      }
      if (*(float *)((int)param_2 + 0x48dc) != fVar12) {
        (**(code **)(*(int *)((int)param_2 + 0x48d8) + 4))
                  ((int)param_2 + 0x48d8,(int)param_2 + 0x48dc);
        *(float *)((int)param_2 + 0x48dc) = fVar12;
      }
      local_6c[0] = 0;
      local_6c[1] = 0;
      local_6c[2] = 0;
      local_60 = (Vector *)0x0;
      local_58 = in_stack_0000000c;
      iVar10 = *(int *)(iVar6 + 0x13c);
      **(int **)(unaff_EBX + 0x4730a1 /* &CNavArea::s_nCurrVisTestCounter */) = **(int **)(unaff_EBX + 0x4730a1 /* &CNavArea::s_nCurrVisTestCounter */) + 1;
      local_5c = 0;
      if (0 < iVar10) {
        iVar10 = 0;
        do {
          while( true ) {
            iVar2 = *(int *)(*(int *)(iVar6 + 0x134) + iVar10 * 8);
            if ((iVar2 == 0) ||
               (*(undefined4 *)(iVar2 + 0x148) = **(undefined4 **)(unaff_EBX + 0x4730a1 /* &CNavArea::s_nCurrVisTestCounter */),
               *(char *)(*(int *)(iVar6 + 0x134) + 4 + iVar10 * 8) == '\0')) break;
            if (local_58 == (CINSPathFollower *)0x0) goto LAB_00733de0;
            local_74 = 3;
            do {
              CNavArea::GetRandomPoint();
              local_44 = *(float *)(unaff_EBX + 0x22a675 /* typeinfo name for CMemberFunctor0<CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>*, void (CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>::*)(), CRefCounted1<CFunctor, CRefCountServiceBase<true, CRefMT> >, CFuncMemPolicyNone>+0xb0 */) + local_2c;
              local_4c = local_34;
              local_48 = local_30;
              cVar5 = (**(code **)(*(int *)local_58 + 0x444 /* CINSPlayer::IsLineOfSightClear */))(local_58,&local_4c,1,local_58);
              if (cVar5 != '\0') {
                CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)local_6c,local_60);
              }
              local_74 = local_74 + -1;
            } while (local_74 != 0);
            iVar10 = iVar10 + 1;
            if (*(int *)(iVar6 + 0x13c) <= iVar10) goto LAB_00733cca;
          }
          iVar10 = iVar10 + 1;
        } while (iVar10 < *(int *)(iVar6 + 0x13c));
      }
LAB_00733cca:
      iVar6 = *(int *)(iVar6 + 300);
      if ((iVar6 != 0) && (0 < *(int *)(iVar6 + 0x13c))) {
        iVar10 = 0;
        do {
          iVar2 = *(int *)(*(int *)(iVar6 + 0x134) + iVar10 * 8);
          if (((iVar2 != 0) && (*(int *)(iVar2 + 0x148) != **(int **)(unaff_EBX + 0x4730a1 /* &CNavArea::s_nCurrVisTestCounter */))) &&
             (*(int *)(iVar2 + 0x148) = **(int **)(unaff_EBX + 0x4730a1 /* &CNavArea::s_nCurrVisTestCounter */),
             *(char *)(iVar10 * 8 + *(int *)(iVar6 + 0x134) + 4) != '\0')) {
            if (local_58 == (CINSPathFollower *)0x0) break;
            local_70 = 3;
            do {
              CNavArea::GetRandomPoint();
              local_44 = *(float *)(unaff_EBX + 0x22a675 /* typeinfo name for CMemberFunctor0<CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>*, void (CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>::*)(), CRefCounted1<CFunctor, CRefCountServiceBase<true, CRefMT> >, CFuncMemPolicyNone>+0xb0 */) + local_20;
              local_4c = local_28;
              local_48 = local_24;
              cVar5 = (**(code **)(*(int *)local_58 + 0x444 /* CINSPlayer::IsLineOfSightClear */))(local_58,&local_4c,1,local_58);
              if (cVar5 != '\0') {
                CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)local_6c,local_60);
              }
              local_70 = local_70 + -1;
            } while (local_70 != 0);
          }
          iVar10 = iVar10 + 1;
        } while (iVar10 < *(int *)(iVar6 + 0x13c));
      }
LAB_00733de0:
      if (0 < (int)local_60) {
        iVar6 = RandomInt(0,local_60 + -1);
        puVar1 = (undefined4 *)(local_6c[0] + iVar6 * 0xc);
        local_4c = *puVar1;
        local_48 = puVar1[1];
        local_44 = (float)puVar1[2];
        piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        pcVar3 = *(code **)(*piVar7 + 0xd4);
        CINSNextBot::GetViewPosition(local_40);
        (*pcVar3)(piVar7,local_40,3,fVar12,0,unaff_EBX + 0x24e59d /* "Looking at random visible areas" */);
      }
      local_60 = (Vector *)0x0;
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      if (local_6c[2] < 0) {
        return param_1;
      }
      if (local_6c[0] == 0) {
        return param_1;
      }
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x472e9d /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x472e9d /* &GCSDK::GetPchTempTextBuffer */),local_6c[0]);
      return param_1;
    }
  }
  else {
    fVar11 = (float10)CountdownTimer::Now();
    pCVar9 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x48c8) <= (float)fVar11 &&
        (float)fVar11 != *(float *)((int)param_2 + 0x48c8)) {
      fVar11 = (float10)CountdownTimer::Now();
      fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x220c65 /* typeinfo name for CEntityFactory<CShower>+0x1e */);
      if (*(float *)((int)param_2 + 0x48c8) != fVar12) {
        (**(code **)(*(int *)((int)param_2 + 0x48c0) + 4))
                  ((int)param_2 + 0x48c0,(int)param_2 + 0x48c8);
        *(float *)((int)param_2 + 0x48c8) = fVar12;
      }
      if (*(int *)((int)param_2 + 0x48c4) != 0x40200000 /* 2.5f */) {
        (**(code **)(*(int *)((int)param_2 + 0x48c0) + 4))
                  ((int)param_2 + 0x48c0,(int)param_2 + 0x48c4);
        *(undefined4 *)((int)param_2 + 0x48c4) = 0x40200000 /* 2.5f */;
      }
      cVar5 = CINSNextBot::IsSpotOccupied
                        (in_stack_0000000c,*(undefined4 *)((int)param_2 + 0x48a8),
                         *(undefined4 *)((int)param_2 + 0x48ac),
                         *(undefined4 *)((int)param_2 + 0x48b0));
      if (cVar5 == '\0') {
        *(undefined4 *)((int)param_2 + 0x48e4) = 0;
      }
      else {
        *(int *)((int)param_2 + 0x48e4) = *(int *)((int)param_2 + 0x48e4) + 1;
      }
      (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_4c,in_stack_0000000c);
      pCVar9 = extraout_ECX_01;
      if (((*(uint *)((int)param_2 + 0x48bc) < 0x10) &&
          (piVar7 = (int *)(**(int **)(unaff_EBX + 0x472cdd /* &TheNavMesh */) + 0x974 +
                           *(uint *)((int)param_2 + 0x48bc) * 0x14), piVar7 != (int *)0x0)) &&
         (pCVar9 = (CINSPathFollower *)piVar7[3], 0 < (int)pCVar9)) {
        iVar6 = 0;
        do {
          piVar4 = *(int **)(*piVar7 + iVar6 * 4);
          if ((piVar4 != (int *)0x0) &&
             (cVar5 = (**(code **)(*piVar4 + 0x94))(piVar4,*(undefined4 *)((int)param_2 + 0x48b8)),
             pCVar9 = extraout_ECX_02, cVar5 != '\0')) {
            piVar8 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
            cVar5 = (**(code **)(*piVar8 + 0x114 /* IVision::IsInFieldOfView */))(piVar8,piVar4 + 0xb);
            pCVar9 = extraout_ECX_03;
            if (cVar5 != '\0') {
              iVar10 = *(int *)((int)param_2 + 0x48b8) * 3;
              pCVar9 = (CINSPathFollower *)(piVar4 + iVar10 + 0x79);
              fVar11 = (float10)CountdownTimer::Now();
              fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1f07d5 /* typeinfo name for CTraceFilterNoCombatCharacters+0x30 */);
              if ((float)piVar4[iVar10 + 0x7b] != fVar12) {
                (**(code **)(piVar4[iVar10 + 0x79] + 4))(pCVar9,piVar4 + iVar10 + 0x7b);
                piVar4[iVar10 + 0x7b] = (int)fVar12;
              }
              if (piVar4[iVar10 + 0x7a] != 0x41200000 /* 10.0f */) {
                (**(code **)(piVar4[iVar10 + 0x79] + 4))(pCVar9,piVar4 + iVar10 + 0x7a);
                piVar4[iVar10 + 0x7a] = 0x41200000 /* 10.0f */;
              }
            }
          }
          iVar6 = iVar6 + 1;
        } while (iVar6 < piVar7[3]);
      }
    }
    if (1 < *(int *)((int)param_2 + 0x48e4)) {
      CINSPathFollower::Invalidate(pCVar9);
      pCVar9 = (CINSPathFollower *)extraout_ECX_00;
    }
    if (*(int *)((int)param_2 + 0x443c) < 1) {
      cVar5 = GetAreaToSweep((CINSBotSweepArea *)pCVar9);
      if (cVar5 == '\0') {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24e563 /* "No areas to sweep." */;
        return param_1;
      }
      fVar11 = (float10)CINSNextBot::MaxPathLength();
      pCVar9 = (CINSPathFollower *)0x0;
      if (in_stack_0000000c != (CINSPathFollower *)0x0) {
        pCVar9 = in_stack_0000000c + 0x2060;
      }
      CINSPathFollower::ComputePath
                (in_stack_0000000c + 0x2060,(INextBot *)((int)param_2 + 0x38),pCVar9,
                 (int)param_2 + 0x48a8,0,(float)fVar11,0,0x41f00000 /* 30.0f */);
      if (*(int *)((int)param_2 + 0x443c) < 1) goto LAB_00733a40;
    }
    CINSPathFollower::Update(in_stack_0000000c,(INextBot *)((int)param_2 + 0x38));
  }
LAB_00733a40:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSweepArea::GetName
 * Address: 007342b0
 * ---------------------------------------- */

/* CINSBotSweepArea::GetName() const */

undefined * CINSBotSweepArea::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return &UNK_0024dc7b + extraout_ECX;
}



/* ----------------------------------------
 * CINSBotSweepArea::OnMoveToSuccess
 * Address: 007335b0
 * ---------------------------------------- */

/* CINSBotSweepArea::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotSweepArea::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int iVar1;
  CBaseEntity *this;
  int unaff_EBX;
  float10 fVar2;
  float fVar3;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(param_2 + 0x48b4) != 0) {
    iVar1 = CBaseEntity::GetTeamNumber(this);
    iVar1 = (iVar1 * 3 + -6) * 4 + 0x1f0 + *(int *)(param_2 + 0x48b4);
    fVar2 = (float10)CountdownTimer::Now();
    fVar3 = (float)fVar2 + *(float *)(unaff_EBX + 0x1f0bf5 /* typeinfo name for CTraceFilterNoCombatCharacters+0x30 */);
    if (*(float *)(iVar1 + 0x14) != fVar3) {
      (**(code **)(*(int *)(iVar1 + 0xc) + 4))(iVar1 + 0xc,iVar1 + 0x14);
      *(float *)(iVar1 + 0x14) = fVar3;
    }
    if (*(int *)(iVar1 + 0x10) != 0x41200000 /* 10.0f */) {
      (**(code **)(*(int *)(iVar1 + 0xc) + 4))(iVar1 + 0xc,iVar1 + 0x10);
      *(undefined4 *)(iVar1 + 0x10) = 0x41200000 /* 10.0f */;
    }
  }
  fVar2 = (float10)CountdownTimer::Now();
  fVar3 = (float)fVar2 + *(float *)(unaff_EBX + 0x1f11ad /* typeinfo name for CBaseGameSystem+0x2e */);
  if (*(float *)(param_2 + 0x48d4) != fVar3) {
    (**(code **)(*(int *)(param_2 + 0x48cc) + 4))(param_2 + 0x48cc,param_2 + 0x48d4);
    *(float *)(param_2 + 0x48d4) = fVar3;
  }
  if (*(int *)(param_2 + 0x48d0) != 0x40e00000 /* 7.0f */) {
    (**(code **)(*(int *)(param_2 + 0x48cc) + 4))(param_2 + 0x48cc,param_2 + 0x48d0);
    *(undefined4 *)(param_2 + 0x48d0) = 0x40e00000 /* 7.0f */;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSweepArea::OnMoveToFailure
 * Address: 007333f0
 * ---------------------------------------- */

/* CINSBotSweepArea::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotSweepArea::OnMoveToFailure(undefined4 *param_1)

{
  CINSPathFollower *this;
  
  __i686_get_pc_thunk_bx();
  CINSPathFollower::Invalidate(this);
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSweepArea::GetAreaToSweep
 * Address: 007337b0
 * ---------------------------------------- */

/* CINSBotSweepArea::GetAreaToSweep() */

undefined4 __thiscall CINSBotSweepArea::GetAreaToSweep(CINSBotSweepArea *this)

{
  float *pfVar1;
  int *piVar2;
  int iVar3;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX_00;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX_01;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *pCVar4;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX_02;
  int unaff_EBX;
  undefined4 uVar5;
  int iVar6;
  float10 fVar7;
  int in_stack_00000004;
  int local_3c [3];
  CINSNavArea **local_30;
  int local_2c;
  undefined4 uStack_14;
  
  uStack_14 = 0x7337bb;
  __i686_get_pc_thunk_bx();
  if (0xf < *(uint *)(in_stack_00000004 + 0x48bc)) {
    return 0;
  }
  piVar2 = (int *)(**(int **)(unaff_EBX + 0x472efd /* &TheNavMesh */) + 0x974 +
                  *(uint *)(in_stack_00000004 + 0x48bc) * 0x14);
  if (piVar2 == (int *)0x0) {
    return 0;
  }
  if (piVar2[3] == 0) {
    return 0;
  }
  local_30 = (CINSNavArea **)0x0;
  iVar6 = 0;
  local_2c = 0;
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  pCVar4 = extraout_ECX;
  if (0 < piVar2[3]) {
    do {
      iVar3 = *(int *)(iVar6 * 4 + *piVar2);
      if (iVar3 != 0) {
        pCVar4 = (CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *)
                 (*(int *)(in_stack_00000004 + 0x48b8) * 3 + -6);
        iVar3 = iVar3 + 0x1fc + (int)pCVar4 * 4;
        if ((*(float *)(iVar3 + 8) <= 0.0) ||
           (fVar7 = (float10)CountdownTimer::Now(), pfVar1 = (float *)(iVar3 + 8),
           pCVar4 = extraout_ECX_00, *pfVar1 <= (float)fVar7 && (float)fVar7 != *pfVar1)) {
          CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>>::InsertBefore
                    (pCVar4,(int)local_3c,local_30);
          pCVar4 = extraout_ECX_01;
        }
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 < piVar2[3]);
    if (local_30 != (CINSNavArea **)0x0) {
      iVar6 = RandomInt(0,(int)local_30 + -1);
      iVar6 = *(int *)(local_3c[0] + iVar6 * 4);
      *(int *)(in_stack_00000004 + 0x48b4) = iVar6;
      *(undefined4 *)(in_stack_00000004 + 0x48a8) = *(undefined4 *)(iVar6 + 0x2c);
      pCVar4 = *(CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> **)(iVar6 + 0x30);
      *(CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> **)(in_stack_00000004 + 0x48ac) =
           pCVar4;
      *(undefined4 *)(in_stack_00000004 + 0x48b0) = *(undefined4 *)(iVar6 + 0x34);
      uVar5 = 1;
      goto LAB_007338af;
    }
  }
  uVar5 = 0;
LAB_007338af:
  local_30 = (CINSNavArea **)0x0;
  iVar6 = local_3c[0];
  if (-1 < local_3c[2]) {
    if (local_3c[0] != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4730bd /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x4730bd /* &GCSDK::GetPchTempTextBuffer */),local_3c[0]);
      local_3c[0] = 0;
      pCVar4 = extraout_ECX_02;
    }
    local_3c[1] = 0;
    iVar6 = 0;
  }
  local_2c = iVar6;
  CUtlMemory<CINSNavArea*,int>::~CUtlMemory((CUtlMemory<CINSNavArea*,int> *)pCVar4);
  return uVar5;
}



/* ----------------------------------------
 * CINSBotSweepArea::~CINSBotSweepArea
 * Address: 007342d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSweepArea::~CINSBotSweepArea() */

void __thiscall CINSBotSweepArea::~CINSBotSweepArea(CINSBotSweepArea *this)

{
  ~CINSBotSweepArea(this);
  return;
}



/* ----------------------------------------
 * CINSBotSweepArea::~CINSBotSweepArea
 * Address: 007342e0
 * ---------------------------------------- */

/* CINSBotSweepArea::~CINSBotSweepArea() */

void __thiscall CINSBotSweepArea::~CINSBotSweepArea(CINSBotSweepArea *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4647fa /* vtable for CINSBotSweepArea+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46498a /* vtable for CINSBotSweepArea+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotSweepArea::~CINSBotSweepArea
 * Address: 00734340
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSweepArea::~CINSBotSweepArea() */

void __thiscall CINSBotSweepArea::~CINSBotSweepArea(CINSBotSweepArea *this)

{
  ~CINSBotSweepArea(this);
  return;
}



/* ----------------------------------------
 * CINSBotSweepArea::~CINSBotSweepArea
 * Address: 00734350
 * ---------------------------------------- */

/* CINSBotSweepArea::~CINSBotSweepArea() */

void __thiscall CINSBotSweepArea::~CINSBotSweepArea(CINSBotSweepArea *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46478a /* vtable for CINSBotSweepArea+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46491a /* vtable for CINSBotSweepArea+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



