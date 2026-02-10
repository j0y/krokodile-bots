/*
 * CINSBotGuardDefensive -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 14
 */

/* ----------------------------------------
 * CINSBotGuardDefensive::CINSBotGuardDefensive
 * Address: 00721d70
 * ---------------------------------------- */

/* CINSBotGuardDefensive::CINSBotGuardDefensive(int) */

void __thiscall
CINSBotGuardDefensive::CINSBotGuardDefensive(CINSBotGuardDefensive *this,int param_1)

{
  code *pcVar1;
  undefined *puVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  CINSPathFollower *this_00;
  int unaff_EBX;
  undefined4 in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(int *)param_1 = unaff_EBX + 0x4755ed /* vtable for CINSBotGuardDefensive+0x8 */;
  *(int *)(param_1 + 4) = unaff_EBX + 0x47577d /* vtable for CINSBotGuardDefensive+0x198 */;
  puVar3 = *(undefined4 **)(unaff_EBX + 0x484851 /* &vec3_origin */);
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
  puVar3 = *(undefined4 **)(unaff_EBX + 0x484fc5 /* &vec3_angle */);
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x48) = *puVar3;
  uVar4 = puVar3[2];
  *(undefined4 *)(param_1 + 0x4c) = puVar3[1];
  *(undefined4 *)(param_1 + 0x50) = uVar4;
  CINSPathFollower::CINSPathFollower(this_00);
  pcVar1 = (code *)(unaff_EBX + -0x4f160b /* CountdownTimer::NetworkStateChanged */);
  *(undefined4 *)(param_1 + 0x48c8) = 0;
  puVar2 = &UNK_0040643d + unaff_EBX;
  *(undefined **)(param_1 + 0x48c4) = puVar2;
  (*pcVar1)(param_1 + 0x48c4,param_1 + 0x48c8);
  *(undefined4 *)(param_1 + 0x48cc) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48c4) + 4))(param_1 + 0x48c4,param_1 + 0x48cc);
  *(undefined **)(param_1 + 0x48d0) = puVar2;
  *(undefined4 *)(param_1 + 0x48d4) = 0;
  (*pcVar1)(param_1 + 0x48d0,param_1 + 0x48d4);
  *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48d0) + 4))(param_1 + 0x48d0,param_1 + 0x48d8);
  iVar6 = *(int *)(unaff_EBX + 0x484ed5 /* &vtable for IntervalTimer */);
  *(undefined4 *)(param_1 + 0x48e4) = 0xbf800000 /* -1.0f */;
  *(int *)(param_1 + 0x48e0) = iVar6 + 8;
  (**(code **)(iVar6 + 0x10))(param_1 + 0x48e0,param_1 + 0x48e4);
  *(undefined **)(param_1 + 0x48e8) = puVar2;
  *(undefined4 *)(param_1 + 0x48ec) = 0;
  (*pcVar1)(param_1 + 0x48e8,param_1 + 0x48ec);
  *(undefined4 *)(param_1 + 0x48f0) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(param_1 + 0x48e8,param_1 + 0x48f0);
  *(undefined1 *)(param_1 + 0x48dc) = 0;
  *(undefined4 *)(param_1 + 0x38) = in_stack_00000008;
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::OnStart
 * Address: 00722e90
 * ---------------------------------------- */

/* CINSBotGuardDefensive::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotGuardDefensive::OnStart(CINSBotGuardDefensive *this,CINSNextBot *param_1,Action *param_2)

{
  CINSNextBot *this_00;
  CINSBotGuardDefensive *this_01;
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
 * CINSBotGuardDefensive::Update
 * Address: 007224a0
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x007226d0) */
/* WARNING: Removing unreachable block (ram,0x007226da) */
/* WARNING: Removing unreachable block (ram,0x007226e1) */
/* WARNING: Removing unreachable block (ram,0x007226f9) */
/* WARNING: Removing unreachable block (ram,0x00722700) */
/* WARNING: Removing unreachable block (ram,0x007226f0) */
/* WARNING: Removing unreachable block (ram,0x00722a00) */
/* WARNING: Removing unreachable block (ram,0x00722a0e) */
/* WARNING: Removing unreachable block (ram,0x00722ab5) */
/* WARNING: Removing unreachable block (ram,0x00722ac2) */
/* WARNING: Removing unreachable block (ram,0x00722ac9) */
/* WARNING: Removing unreachable block (ram,0x00722ae9) */
/* WARNING: Removing unreachable block (ram,0x00722af0) */
/* WARNING: Removing unreachable block (ram,0x00722ae0) */
/* WARNING: Removing unreachable block (ram,0x00722bc0) */
/* WARNING: Removing unreachable block (ram,0x00722bce) */
/* CINSBotGuardDefensive::Update(CINSNextBot*, float) */

CINSNextBot * CINSBotGuardDefensive::Update(CINSNextBot *param_1,float param_2)

{
  float fVar1;
  int iVar2;
  code *pcVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  CINSNextBot *pCVar7;
  int iVar8;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSPathFollower *extraout_ECX_02;
  CINSPathFollower *this;
  CINSBotGuardDefensive *extraout_ECX_03;
  CINSBotGuardDefensive *this_00;
  CINSPathFollower *extraout_ECX_04;
  int unaff_EBX;
  int iVar9;
  float10 fVar10;
  int *in_stack_0000000c;
  undefined4 in_stack_00000010;
  undefined4 uVar11;
  CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *this_01;
  int local_78 [3];
  CNavArea **local_6c;
  int local_68;
  float local_5c;
  float local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined1 local_38 [12];
  int local_2c [6];
  undefined4 uStack_14;
  
  uStack_14 = 0x7224ab;
  __i686_get_pc_thunk_bx();
  piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  iVar6 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
  if (iVar6 != 0) {
    piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar6 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,in_stack_0000000c + 0x818,iVar6);
    if (iVar6 == 1) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x25edd7 /* "LoS to an enemy." */;
      return param_1;
    }
  }
  pCVar7 = (CINSNextBot *)TheINSNextBots();
  piVar5 = in_stack_0000000c;
  iVar6 = CINSNextBotManager::GetDesiredPushTypeObjective(pCVar7);
  if (iVar6 != *(int *)((int)param_2 + 0x38)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25eeb9 /* "Point we were guarding is inactive, relocating to new point." */;
    return param_1;
  }
  iVar6 = **(int **)(unaff_EBX + 0x484871 /* &g_pObjectiveResource */);
  pCVar7 = *(CINSNextBot **)(iVar6 + 0x770);
  iVar8 = *(int *)(iVar6 + 0x450 + (int)pCVar7 * 4);
  if (iVar8 == 2) {
    iVar6 = *(int *)(iVar6 + 0x590 + (int)pCVar7 * 4);
LAB_007228df:
    if (0 < iVar6) {
      uVar11 = 0;
      piVar5 = (int *)0x41000000;
      fVar10 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                  (pCVar7,(float)in_stack_0000000c,0x41000000 /* 8.0f */);
      if ((double)(float)fVar10 < *(double *)(&LAB_002022cd + unaff_EBX)) {
        if ((*(char *)((int)param_2 + 0x48dc) != '\0') &&
           (fVar10 = (float10)CountdownTimer::Now(),
           *(float *)((int)param_2 + 0x48d8) <= (float)fVar10 &&
           (float)fVar10 != *(float *)((int)param_2 + 0x48d8))) {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x25ee3d /* "Exiting guard state, enemy entering CP" */;
          return param_1;
        }
        piVar5 = (int *)0x41000000;
        fVar10 = (float10)RandomFloat(0,0x41000000 /* 8.0f */,uVar11);
        fVar1 = (float)fVar10;
        fVar10 = (float10)CountdownTimer::Now();
        if (*(float *)((int)param_2 + 0x48d8) != (float)fVar10 + fVar1) {
          piVar5 = (int *)((int)param_2 + 0x48d8);
          (**(code **)(*(int *)((int)param_2 + 0x48d0) + 4))((int)param_2 + 0x48d0,piVar5);
          *(float *)((int)param_2 + 0x48d8) = (float)fVar10 + fVar1;
        }
        if (*(float *)((int)param_2 + 0x48d4) != fVar1) {
          piVar5 = (int *)((int)param_2 + 0x48d4);
          (**(code **)(*(int *)((int)param_2 + 0x48d0) + 4))((int)param_2 + 0x48d0,piVar5);
          *(float *)((int)param_2 + 0x48d4) = fVar1;
        }
        *(undefined1 *)((int)param_2 + 0x48dc) = 1;
      }
    }
  }
  else if (iVar8 == 3) {
    iVar6 = *(int *)(iVar6 + 0x550 + (int)pCVar7 * 4);
    goto LAB_007228df;
  }
  if (0.0 < *(float *)((int)param_2 + 0x48e4)) {
    (**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c,piVar5);
    iVar6 = unaff_EBX + 0x25e176 /* "Crouching at CP" */;
    this_01 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)0x7;
    uVar11 = 3;
    CINSBotBody::SetPosture();
    fVar10 = (float10)CountdownTimer::Now();
    pCVar7 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x48f0) <= (float)fVar10 &&
        (float)fVar10 != *(float *)((int)param_2 + 0x48f0)) {
      iVar8 = (**(code **)(*in_stack_0000000c + 0x548 /* CINSNextBot::GetLastKnownArea */))
                        (in_stack_0000000c,uVar11,this_01,in_stack_00000010,iVar6);
      iVar6 = local_68;
      if (iVar8 != 0) {
        local_78[0] = 0;
        iVar6 = *(int *)(iVar8 + 0x13c);
        local_78[1] = 0;
        local_78[2] = 0;
        local_6c = (CNavArea **)0x0;
        **(int **)(&DAT_004845d1 + unaff_EBX) = **(int **)(&DAT_004845d1 + unaff_EBX) + 1;
        local_68 = 0;
        if (0 < iVar6) {
          iVar6 = 0;
          do {
            iVar9 = *(int *)(*(int *)(iVar8 + 0x134) + iVar6 * 8);
            if ((iVar9 != 0) &&
               (*(undefined4 *)(iVar9 + 0x148) = **(undefined4 **)(&DAT_004845d1 + unaff_EBX),
               ((byte)((CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)(iVar6 * 8))
                      [*(int *)(iVar8 + 0x134) + 4] & 2) != 0)) {
              this_01 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)local_2c;
              local_2c[0] = iVar9;
              CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>>::InsertBefore
                        ((CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)(iVar6 * 8),
                         (int)local_78,local_6c);
            }
            iVar6 = iVar6 + 1;
          } while (iVar6 < *(int *)(iVar8 + 0x13c));
        }
        iVar6 = *(int *)(iVar8 + 300);
        if ((iVar6 != 0) && (0 < *(int *)(iVar6 + 0x13c))) {
          iVar9 = 0;
          do {
            iVar2 = *(int *)(*(int *)(iVar6 + 0x134) + iVar9 * 8);
            if ((iVar2 != 0) && (*(int *)(iVar2 + 0x148) != **(int **)(&DAT_004845d1 + unaff_EBX)))
            {
              *(int *)(iVar2 + 0x148) = **(int **)(&DAT_004845d1 + unaff_EBX);
              piVar5 = (int *)(iVar9 * 8 + *(int *)(iVar6 + 0x134));
              if ((*(byte *)(piVar5 + 1) & 2) != 0) {
                local_2c[0] = *piVar5;
                this_01 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)local_2c;
                CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>>::InsertBefore
                          (this_01,(int)local_78,local_6c);
              }
            }
            iVar9 = iVar9 + 1;
          } while (iVar9 < *(int *)(iVar6 + 0x13c));
        }
        if (0 < (int)local_6c) {
          iVar6 = RandomInt(0,(int)local_6c + -1,this_01);
          iVar6 = *(int *)(local_78[0] + iVar6 * 4);
          if ((iVar8 != iVar6) && (iVar6 != 0)) {
            piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            pcVar3 = *(code **)(*piVar5 + 0xd4);
            CNavArea::GetRandomPoint();
            CINSNextBot::GetViewPosition(local_38);
            (*pcVar3)(piVar5,local_38,0,0x3dcccccd /* 0.1f */,0,unaff_EBX + 0x25ee00 /* "Guard Aiming" */);
          }
        }
        local_6c = (CNavArea **)0x0;
        iVar6 = local_78[0];
        if (-1 < local_78[2]) {
          if (local_78[0] != 0) {
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4843cd /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x4843cd /* &GCSDK::GetPchTempTextBuffer */),local_78[0]);
            local_78[0] = 0;
          }
          local_78[1] = 0;
          local_68 = 0;
          iVar6 = local_68;
        }
      }
      local_68 = iVar6;
      fVar10 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x40a00000 /* 5.0f */);
      fVar1 = (float)fVar10;
      fVar10 = (float10)CountdownTimer::Now();
      pCVar7 = extraout_ECX_00;
      if (*(float *)((int)param_2 + 0x48f0) != (float)fVar10 + fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48e8) + 4))
                  ((int)param_2 + 0x48e8,(int)param_2 + 0x48f0);
        *(float *)((int)param_2 + 0x48f0) = (float)fVar10 + fVar1;
        pCVar7 = (CINSNextBot *)param_2;
      }
      if (*(float *)((int)param_2 + 0x48ec) != fVar1) {
        (**(code **)(*(int *)((int)param_2 + 0x48e8) + 4))
                  ((int)param_2 + 0x48e8,(int)param_2 + 0x48ec);
        *(float *)((int)param_2 + 0x48ec) = fVar1;
        pCVar7 = extraout_ECX_01;
      }
    }
    uVar11 = 0;
    fVar10 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                (pCVar7,(float)in_stack_0000000c,0x41000000 /* 8.0f */);
    if ((double)(float)fVar10 < *(double *)(unaff_EBX + 0x25ee75 /* typeinfo name for CINSBotGuardCP+0x11 */)) {
      (**(code **)(*in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3e800000 /* 0.25f */,uVar11);
    }
    goto LAB_00722894;
  }
  fVar10 = (float10)CountdownTimer::Now();
  this = extraout_ECX_02;
  if (*(float *)((int)param_2 + 0x48cc) <= (float)fVar10 &&
      (float)fVar10 != *(float *)((int)param_2 + 0x48cc)) {
    fVar10 = (float10)CountdownTimer::Now();
    fVar1 = *(float *)(&DAT_00202cb9 + unaff_EBX);
    if (*(float *)((int)param_2 + 0x48cc) != (float)fVar10 + fVar1) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48cc);
      *(float *)((int)param_2 + 0x48cc) = (float)fVar10 + fVar1;
    }
    this_00 = (CINSBotGuardDefensive *)param_2;
    if (*(int *)((int)param_2 + 0x48c8) != 0x3fc00000 /* 1.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x48c4) + 4))
                ((int)param_2 + 0x48c4,(int)param_2 + 0x48c8);
      *(undefined4 *)((int)param_2 + 0x48c8) = 0x3fc00000 /* 1.5f */;
      this_00 = extraout_ECX_03;
    }
    pfVar4 = *(float **)(unaff_EBX + 0x484121 /* &vec3_origin */);
    if ((*pfVar4 == *(float *)((int)param_2 + 0x3c)) &&
       (pfVar4[1] == *(float *)((int)param_2 + 0x40))) {
      if (pfVar4[2] == *(float *)((int)param_2 + 0x44)) {
        GetRandomHidingSpotForPoint(this_00,(CINSNextBot *)&local_5c,(int)in_stack_0000000c);
        *(float *)((int)param_2 + 0x3c) = local_5c;
        fVar1 = *pfVar4;
        *(float *)((int)param_2 + 0x40) = local_58;
        *(undefined4 *)((int)param_2 + 0x44) = local_54;
        *(undefined4 *)((int)param_2 + 0x48) = local_50;
        *(undefined4 *)((int)param_2 + 0x4c) = local_4c;
        *(undefined4 *)((int)param_2 + 0x50) = local_48;
        if ((local_5c != fVar1) || (local_58 != pfVar4[1])) goto LAB_00722d96;
      }
      this = (CINSPathFollower *)param_2;
      if (pfVar4[2] == *(float *)((int)param_2 + 0x44)) goto LAB_00722b47;
    }
LAB_00722d96:
    CINSNextBot::MaxPathLength();
    CINSPathFollower::ComputePath();
    this = extraout_ECX_04;
  }
LAB_00722b47:
  if (0 < *(int *)((int)param_2 + 0x4458)) {
    CINSPathFollower::Update(this,(INextBot *)((int)param_2 + 0x54));
  }
LAB_00722894:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::OnEnd
 * Address: 007218f0
 * ---------------------------------------- */

/* CINSBotGuardDefensive::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotGuardDefensive::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  param_2[0x2290] = (Action)0x0;
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::GetName
 * Address: 00722f30
 * ---------------------------------------- */

/* CINSBotGuardDefensive::GetName() const */

int CINSBotGuardDefensive::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25e3f3 /* "Defensive Guard" */;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::OnMoveToSuccess
 * Address: 00721bd0
 * ---------------------------------------- */

/* CINSBotGuardDefensive::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotGuardDefensive::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int unaff_EBX;
  float10 fVar1;
  float fVar2;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x48e4) != (float)fVar1) {
    (**(code **)(*(int *)(param_2 + 0x48e0) + 8))(param_2 + 0x48e0,param_2 + 0x48e4);
    *(float *)(param_2 + 0x48e4) = (float)fVar1;
  }
  fVar1 = (float10)CountdownTimer::Now();
  fVar2 = (float)fVar1 + *(float *)(unaff_EBX + 0x202b7a /* typeinfo name for CBaseGameSystem+0x1e */);
  if (*(float *)(param_2 + 0x48f0) != fVar2) {
    (**(code **)(*(int *)(param_2 + 0x48e8) + 4))(param_2 + 0x48e8,param_2 + 0x48f0);
    *(float *)(param_2 + 0x48f0) = fVar2;
  }
  if (*(int *)(param_2 + 0x48ec) != 0x3f000000 /* 0.5f */) {
    (**(code **)(*(int *)(param_2 + 0x48e8) + 4))(param_2 + 0x48e8,param_2 + 0x48ec);
    *(undefined4 *)(param_2 + 0x48ec) = 0x3f000000 /* 0.5f */;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::OnMoveToFailure
 * Address: 00721900
 * ---------------------------------------- */

/* CINSBotGuardDefensive::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotGuardDefensive::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = extraout_ECX + 0x25f96d /* "Failed move-to." */;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::OnWeaponFired
 * Address: 00721940
 * ---------------------------------------- */

/* CINSBotGuardDefensive::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

CINSNextBot * __thiscall
CINSBotGuardDefensive::OnWeaponFired
          (CINSBotGuardDefensive *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CBaseCombatWeapon *param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  CBaseEntity *this_00;
  undefined4 extraout_ECX;
  CBaseEntity *this_01;
  int unaff_EBX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar2,0);
  this_00 = (CBaseEntity *)0x0;
  if (piVar2 != (int *)0x0) {
    cVar1 = (**(code **)(*piVar2 + 0x3c))(piVar2);
    this_00 = (CBaseEntity *)CONCAT31((int3)((uint)extraout_ECX >> 8),cVar1 != '\0');
  }
  if (in_stack_00000010 != 0) {
    iVar3 = CBaseEntity::GetTeamNumber(this_00);
    iVar4 = CBaseEntity::GetTeamNumber(this_01);
    if ((iVar3 != iVar4) && ((piVar2 == (int *)0x0 || ((char)this_00 == '\0')))) {
      piVar2 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
      cVar1 = (**(code **)(*piVar2 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar2,in_stack_00000010,1,0);
      if (cVar1 != '\0') {
        piVar2 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
        (**(code **)(*piVar2 + 0xd8 /* PlayerBody::AimHeadTowards */))(piVar2,in_stack_00000010,2,0x41200000 /* 10.0f */,0,unaff_EBX + 0x25f9ed /* "Heard some gunshots." */);
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::GetRandomHidingSpotForPoint
 * Address: 00721fe0
 * ---------------------------------------- */

/* CINSBotGuardDefensive::GetRandomHidingSpotForPoint(CINSNextBot*, int) */

CINSNextBot * __thiscall
CINSBotGuardDefensive::GetRandomHidingSpotForPoint
          (CINSBotGuardDefensive *this,CINSNextBot *param_1,int param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  CBaseEntity *pCVar9;
  int iVar10;
  undefined4 *puVar11;
  undefined4 uVar12;
  CBaseEntity *this_00;
  int *piVar13;
  int unaff_EBX;
  int iVar14;
  CBaseEntity *in_stack_0000000c;
  int local_54;
  int local_50;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x721feb;
  __i686_get_pc_thunk_bx();
  if ((CBaseEntity *)0xf < in_stack_0000000c) goto LAB_00722276;
  piVar2 = (int *)(unaff_EBX + 0x5ca935 /* CINSBotGuardDefensive::m_HidingSpotsAtPoint */ + (int)in_stack_0000000c * 0x14);
  if (piVar2[3] != 0) goto LAB_007222b8;
  iVar8 = (int)in_stack_0000000c * 0x14 + **(int **)(&DAT_004846cd + unaff_EBX);
  pCVar9 = (CBaseEntity *)(iVar8 + 0x974);
  if ((pCVar9 == (CBaseEntity *)0x0) || (*(int *)(iVar8 + 0x980) == 0)) goto LAB_00722276;
  local_54 = 0;
  this_00 = in_stack_0000000c;
  if (*(int *)(iVar8 + 0x980) < 1) {
LAB_00722467:
    uVar12 = CBaseEntity::GetTeamNumber(this_00);
    Warning(unaff_EBX + 0x25f2cd /* "Failed finding guard spots for CP %i, Team %i
" */,in_stack_0000000c,uVar12);
    iVar10 = piVar2[3];
  }
  else {
    do {
      iVar10 = *(int *)(*(int *)pCVar9 + local_54 * 4);
      if ((iVar10 != 0) && (piVar13 = *(int **)(iVar10 + 0xd0), 0 < *piVar13)) {
        iVar14 = 0;
        do {
          while (iVar7 = piVar13[iVar14 + 1], (*(byte *)(iVar7 + 0x1c) & 8) != 0) {
            iVar14 = iVar14 + 1;
            if (*piVar13 <= iVar14) goto LAB_00722151;
          }
          iVar14 = iVar14 + 1;
          local_34 = *(float *)(iVar10 + 0x2c) - *(float *)(iVar7 + 4);
          local_30 = *(float *)(iVar10 + 0x30) - *(float *)(iVar7 + 8);
          local_2c = *(float *)(iVar10 + 0x34) - *(float *)(iVar7 + 0xc);
          VectorAngles((Vector *)&local_34,(QAngle *)&local_28);
          CUtlVector<guardData_t,CUtlMemory<guardData_t,int>>::InsertBefore
                    (*(CUtlVector<guardData_t,CUtlMemory<guardData_t,int>> **)
                      (*(int *)(&DAT_00484d55 + unaff_EBX) + 4),(int)piVar2,(guardData_t *)piVar2[3]
                    );
          piVar13 = *(int **)(iVar10 + 0xd0);
        } while (iVar14 < *piVar13);
      }
LAB_00722151:
      local_54 = local_54 + 1;
    } while (local_54 < *(int *)(iVar8 + 0x980));
    iVar10 = piVar2[3];
    if (iVar10 < 0x1e) {
      if (0 < *(int *)(iVar8 + 0x980)) {
        local_54 = 0;
        do {
          iVar10 = *(int *)(*(int *)pCVar9 + local_54 * 4);
          if ((iVar10 != 0) && (piVar13 = *(int **)(iVar10 + 0xd0), 0 < *piVar13)) {
            iVar14 = 0;
            do {
              while (iVar7 = piVar13[iVar14 + 1], (*(byte *)(iVar7 + 0x1c) & 8) == 0) {
                iVar14 = iVar14 + 1;
                if (*piVar13 <= iVar14) goto LAB_00722441;
              }
              iVar14 = iVar14 + 1;
              local_28 = *(float *)(iVar7 + 4) - *(float *)(iVar10 + 0x2c);
              local_24 = *(float *)(iVar7 + 8) - *(float *)(iVar10 + 0x30);
              local_20 = *(float *)(iVar7 + 0xc) - *(float *)(iVar10 + 0x34);
              VectorAngles((Vector *)&local_28,(QAngle *)&local_34);
              CUtlVector<guardData_t,CUtlMemory<guardData_t,int>>::InsertBefore
                        (*(CUtlVector<guardData_t,CUtlMemory<guardData_t,int>> **)
                          (*(int *)(&DAT_00484d55 + unaff_EBX) + 4),(int)piVar2,
                         (guardData_t *)piVar2[3]);
              piVar13 = *(int **)(iVar10 + 0xd0);
            } while (iVar14 < *piVar13);
          }
LAB_00722441:
          local_54 = local_54 + 1;
        } while (local_54 < *(int *)(iVar8 + 0x980));
        iVar10 = piVar2[3];
      }
      if (0 < iVar10) goto LAB_00722173;
    }
    else {
LAB_00722173:
      iVar8 = 0;
      local_50 = 0;
      do {
        piVar13 = (int *)(*piVar2 + iVar8);
        iVar14 = *piVar13;
        iVar7 = piVar13[1];
        iVar3 = piVar13[2];
        iVar4 = piVar13[3];
        iVar5 = piVar13[4];
        iVar6 = piVar13[5];
        iVar10 = RandomInt(0,iVar10 + -1);
        local_50 = local_50 + 1;
        puVar1 = (undefined4 *)(*piVar2 + iVar10 * 0x18);
        puVar11 = (undefined4 *)(*piVar2 + iVar8);
        iVar8 = iVar8 + 0x18;
        *puVar11 = *puVar1;
        puVar11[1] = puVar1[1];
        puVar11[2] = puVar1[2];
        puVar11[3] = puVar1[3];
        puVar11[4] = puVar1[4];
        puVar11[5] = puVar1[5];
        pCVar9 = (CBaseEntity *)(iVar10 * 0x18 + *piVar2);
        *(int *)pCVar9 = iVar14;
        *(int *)(pCVar9 + 4) = iVar7;
        *(int *)(pCVar9 + 8) = iVar3;
        *(int *)(pCVar9 + 0xc) = iVar4;
        *(int *)(pCVar9 + 0x10) = iVar5;
        *(int *)(pCVar9 + 0x14) = iVar6;
        iVar10 = piVar2[3];
      } while (local_50 < iVar10);
    }
    this_00 = pCVar9;
    if (iVar10 == 0) goto LAB_00722467;
  }
  if (iVar10 != 0) {
LAB_007222b8:
    iVar8 = unaff_EBX + 0x5ca8f5 /* CINSBotGuardDefensive::m_iSelectedHidingSpot */;
    *(int *)(iVar8 + (int)in_stack_0000000c * 4) = *(int *)(iVar8 + (int)in_stack_0000000c * 4) + 1;
    DevMsg((char *)(unaff_EBX + 0x25f362 /* "Bot hiding in spot %i
" */));
    puVar1 = (undefined4 *)
             (*piVar2 + (*(int *)(iVar8 + (int)in_stack_0000000c * 4) % piVar2[3]) * 0x18);
    *(undefined4 *)param_1 = *puVar1;
    *(undefined4 *)(param_1 + 4) = puVar1[1];
    *(undefined4 *)(param_1 + 8) = puVar1[2];
    *(undefined4 *)(param_1 + 0xc) = puVar1[3];
    uVar12 = puVar1[5];
    *(undefined4 *)(param_1 + 0x10) = puVar1[4];
    *(undefined4 *)(param_1 + 0x14) = uVar12;
    return param_1;
  }
LAB_00722276:
  puVar1 = *(undefined4 **)(CServerGameDLL::CreateEntityTransitionList + unaff_EBX + 1);
  *(undefined4 *)param_1 = *puVar1;
  uVar12 = puVar1[2];
  *(undefined4 *)(param_1 + 4) = puVar1[1];
  *(undefined4 *)(param_1 + 8) = uVar12;
  puVar1 = *(undefined4 **)(&DAT_00484d55 + unaff_EBX);
  *(undefined4 *)(param_1 + 0xc) = *puVar1;
  uVar12 = puVar1[2];
  *(undefined4 *)(param_1 + 0x10) = puVar1[1];
  *(undefined4 *)(param_1 + 0x14) = uVar12;
  return param_1;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::ResetHidingSpots
 * Address: 00721f90
 * ---------------------------------------- */

/* CINSBotGuardDefensive::ResetHidingSpots() */

void CINSBotGuardDefensive::ResetHidingSpots(void)

{
  int iVar1;
  int iVar2;
  int unaff_EBX;
  
  iVar1 = __i686_get_pc_thunk_bx();
  do {
    *(undefined4 *)(iVar1 * 4 + unaff_EBX + 0x5ca944 /* CINSBotGuardDefensive::m_iSelectedHidingSpot */) = 0;
    iVar2 = iVar1 + 1;
    *(undefined4 *)(unaff_EBX + 0x5ca990 /* CINSBotGuardDefensive::m_HidingSpotsAtPoint+0xc */ + iVar1 * 0x14) = 0;
    iVar1 = iVar2;
  } while (iVar2 != 0x10);
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::~CINSBotGuardDefensive
 * Address: 00722f50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGuardDefensive::~CINSBotGuardDefensive() */

void __thiscall CINSBotGuardDefensive::~CINSBotGuardDefensive(CINSBotGuardDefensive *this)

{
  ~CINSBotGuardDefensive(this);
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::~CINSBotGuardDefensive
 * Address: 00722f60
 * ---------------------------------------- */

/* CINSBotGuardDefensive::~CINSBotGuardDefensive() */

void __thiscall CINSBotGuardDefensive::~CINSBotGuardDefensive(CINSBotGuardDefensive *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4743fa /* vtable for CINSBotGuardDefensive+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x47458a /* vtable for CINSBotGuardDefensive+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::~CINSBotGuardDefensive
 * Address: 00722fc0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGuardDefensive::~CINSBotGuardDefensive() */

void __thiscall CINSBotGuardDefensive::~CINSBotGuardDefensive(CINSBotGuardDefensive *this)

{
  ~CINSBotGuardDefensive(this);
  return;
}



/* ----------------------------------------
 * CINSBotGuardDefensive::~CINSBotGuardDefensive
 * Address: 00722fd0
 * ---------------------------------------- */

/* CINSBotGuardDefensive::~CINSBotGuardDefensive() */

void __thiscall CINSBotGuardDefensive::~CINSBotGuardDefensive(CINSBotGuardDefensive *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47438a /* vtable for CINSBotGuardDefensive+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x47451a /* vtable for CINSBotGuardDefensive+0x198 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



