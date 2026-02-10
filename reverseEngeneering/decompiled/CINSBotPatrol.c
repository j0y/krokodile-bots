/*
 * CINSBotPatrol -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 29
 */

/* ----------------------------------------
 * CINSBotPatrol::CINSBotPatrol
 * Address: 00726f10
 * ---------------------------------------- */

/* CINSBotPatrol::CINSBotPatrol() */

void __thiscall CINSBotPatrol::CINSBotPatrol(CINSBotPatrol *this)

{
  code *pcVar1;
  undefined *puVar2;
  float fVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  CINSPathFollower *this_00;
  int unaff_EBX;
  float10 fVar8;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x470a2d /* vtable for CINSBotPatrol+0x8 */ /* vtable for CINSBotPatrol+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x470bc5 /* vtable for CINSBotPatrol+0x1a0 */ /* vtable for CINSBotPatrol+0x1a0 */;
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
  pcVar1 = (code *)(unaff_EBX + -0x4f67ab /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[0x122f] = 0;
  puVar2 = &UNK_0040129d + unaff_EBX;
  in_stack_00000004[0x122e] = (int)puVar2;
  (*pcVar1)(in_stack_00000004 + 0x122e,in_stack_00000004 + 0x122f);
  in_stack_00000004[0x1230] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x122e] + 4))
            (in_stack_00000004 + 0x122e,in_stack_00000004 + 0x1230);
  in_stack_00000004[0x1231] = (int)puVar2;
  in_stack_00000004[0x1232] = 0;
  (*pcVar1)(in_stack_00000004 + 0x1231,in_stack_00000004 + 0x1232);
  in_stack_00000004[0x1233] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1231] + 4))
            (in_stack_00000004 + 0x1231,in_stack_00000004 + 0x1233);
  in_stack_00000004[0x1234] = (int)puVar2;
  in_stack_00000004[0x1235] = 0;
  (*pcVar1)(in_stack_00000004 + 0x1234,in_stack_00000004 + 0x1235);
  in_stack_00000004[0x1236] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1234] + 4))
            (in_stack_00000004 + 0x1234,in_stack_00000004 + 0x1236);
  piVar5 = in_stack_00000004 + 0x123d;
  in_stack_00000004[0x123d] = (int)puVar2;
  in_stack_00000004[0x123e] = 0;
  (*pcVar1)(piVar5,in_stack_00000004 + 0x123e);
  in_stack_00000004[0x123f] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x123d] + 4))(piVar5,in_stack_00000004 + 0x123f);
  iVar4 = *(int *)(unaff_EBX + 0x47fd35 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  in_stack_00000004[0x1241] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x1240] = iVar4 + 8;
  (**(code **)(iVar4 + 0x10))(in_stack_00000004 + 0x1240,in_stack_00000004 + 0x1241);
  in_stack_00000004[0x1242] = (int)puVar2;
  in_stack_00000004[0x1243] = 0;
  (*pcVar1)(in_stack_00000004 + 0x1242,in_stack_00000004 + 0x1243);
  in_stack_00000004[0x1244] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1242] + 4))
            (in_stack_00000004 + 0x1242,in_stack_00000004 + 0x1244);
  in_stack_00000004[0x1245] = (int)puVar2;
  in_stack_00000004[0x1246] = 0;
  (*pcVar1)(in_stack_00000004 + 0x1245,in_stack_00000004 + 0x1246);
  in_stack_00000004[0x1247] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1245] + 4))
            (in_stack_00000004 + 0x1245,in_stack_00000004 + 0x1247);
  fVar8 = (float10)CountdownTimer::Now();
  fVar3 = (float)in_stack_00000004[0x123e];
  if ((float)in_stack_00000004[0x123f] != (float)fVar8 + fVar3) {
    (**(code **)(in_stack_00000004[0x123d] + 4))(piVar5,in_stack_00000004 + 0x123f);
    in_stack_00000004[0x123f] = (int)((float)fVar8 + fVar3);
  }
  piVar5 = *(int **)(unaff_EBX + 0x47f6b1 /* &vec3_origin */ /* &vec3_origin */);
  *(undefined1 *)(in_stack_00000004 + 0x123c) = 0;
  *(undefined1 *)(in_stack_00000004 + 0x1237) = 0;
  in_stack_00000004[0x123b] = -0x40800000 /* -1.0f */;
  *(undefined1 *)(in_stack_00000004 + 0x1248) = 0;
  iVar4 = *piVar5;
  iVar6 = piVar5[1];
  iVar7 = piVar5[2];
  in_stack_00000004[0xf] = iVar4;
  in_stack_00000004[0x10] = iVar6;
  in_stack_00000004[0x11] = iVar7;
  in_stack_00000004[0x1249] = iVar4;
  in_stack_00000004[0x124a] = iVar6;
  in_stack_00000004[0x124b] = iVar7;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::OnStart
 * Address: 00728440
 * ---------------------------------------- */

/* CINSBotPatrol::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotPatrol::OnStart(CINSBotPatrol *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  CINSRules *this_00;
  CINSBotPatrol *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *extraout_ECX_02;
  CINSNextBot *this_05;
  CINSWeapon *this_06;
  CINSWeapon *this_07;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSRules::IsSurvival(this_00);
  if (cVar1 != '\0') {
    *(undefined4 *)(param_2 + 0x4930) = *(undefined4 *)(**(int **)(unaff_EBX + 0x47e8d1 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x770);
  }
  cVar1 = GetNextPatrolArea(this_01);
  if (cVar1 != '\0') {
    fVar4 = (float10)IntervalTimer::Now();
    if (*(float *)(param_2 + 0x4904) != (float)fVar4) {
      (**(code **)(*(int *)(param_2 + 0x4900) + 8))(param_2 + 0x4900,param_2 + 0x4904);
      *(float *)(param_2 + 0x4904) = (float)fVar4;
    }
    fVar4 = (float10)CountdownTimer::Now();
    fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x1fd905 /* 6.0f */ /* 6.0f */);
    this_02 = extraout_ECX;
    if (*(float *)(param_2 + 0x4910) != fVar5) {
      (**(code **)(*(int *)(param_2 + 0x4908) + 4))(param_2 + 0x4908,param_2 + 0x4910);
      *(float *)(param_2 + 0x4910) = fVar5;
      this_02 = extraout_ECX_00;
    }
    if (*(int *)(param_2 + 0x490c) != 0x40c00000 /* 6.0f */) {
      (**(code **)(*(int *)(param_2 + 0x4908) + 4))(param_2 + 0x4908,param_2 + 0x490c);
      *(undefined4 *)(param_2 + 0x490c) = 0x40c00000 /* 6.0f */;
      this_02 = extraout_ECX_01;
    }
    if ((*(byte *)(in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_02);
    }
    uVar2 = CNavMesh::GetNearestNavArea();
    *(undefined4 *)(param_2 + 0x38) = uVar2;
    iVar3 = CINSPlayer::GetActiveINSWeapon();
    if ((iVar3 != 0) &&
       (((cVar1 = CINSWeapon::HasLasersights(this_03), this_06 = this_04, cVar1 != '\0' &&
         (cVar1 = CINSWeapon::IsLasersightsOn(this_04), this_06 = extraout_ECX_02, cVar1 != '\0'))
        || ((cVar1 = CINSWeapon::HasFlashlight(this_06), cVar1 != '\0' &&
            (cVar1 = CINSWeapon::IsFlashlightOn(this_07), cVar1 != '\0')))))) {
      param_2[0x48dc] = (Action)0x1;
    }
    fVar4 = (float10)CountdownTimer::Now();
    if (*(float *)(in_stack_0000000c + 0xb4a8) <= (float)fVar4 &&
        (float)fVar4 != *(float *)(in_stack_0000000c + 0xb4a8)) {
      CINSNextBot::BotSpeakConceptIfAllowed
                (this_05,in_stack_0000000c,(char *)0x45,(char *)0x0,0,(IRecipientFilter *)0x0);
      fVar4 = (float10)RandomFloat(0x41200000 /* 10.0f */,0x42200000 /* 40.0f */);
      fVar5 = (float)fVar4;
      fVar4 = (float10)CountdownTimer::Now();
      if (*(float *)(in_stack_0000000c + 0xb4a8) != (float)fVar4 + fVar5) {
        (**(code **)(*(int *)(in_stack_0000000c + 0xb4a0) + 4))
                  (in_stack_0000000c + 0xb4a0,in_stack_0000000c + 0xb4a8);
        *(float *)(in_stack_0000000c + 0xb4a8) = (float)fVar4 + fVar5;
      }
      if (*(float *)(in_stack_0000000c + 0xb4a4) != fVar5) {
        (**(code **)(*(int *)(in_stack_0000000c + 0xb4a0) + 4))
                  (in_stack_0000000c + 0xb4a0,in_stack_0000000c + 0xb4a4);
        *(float *)(in_stack_0000000c + 0xb4a4) = fVar5;
      }
    }
    fVar4 = (float10)RandomFloat(0x3dcccccd /* 0.1f */,0x3f800000 /* 1.0f */);
    fVar5 = (float)fVar4;
    fVar4 = (float10)CountdownTimer::Now();
    if (*(float *)(param_2 + 0x48fc) != (float)fVar4 + fVar5) {
      (**(code **)(*(int *)(param_2 + 0x48f4) + 4))(param_2 + 0x48f4,param_2 + 0x48fc);
      *(float *)(param_2 + 0x48fc) = (float)fVar4 + fVar5;
    }
    if (*(float *)(param_2 + 0x48f8) != fVar5) {
      (**(code **)(*(int *)(param_2 + 0x48f4) + 4))(param_2 + 0x48f4,param_2 + 0x48f8);
      *(float *)(param_2 + 0x48f8) = fVar5;
    }
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined **)(param_1 + 8) = &UNK_00259205 + unaff_EBX;
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::Update
 * Address: 007279a0
 * ---------------------------------------- */

/* CINSBotPatrol::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotPatrol::Update(CINSBotPatrol *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  ushort uVar4;
  float fVar5;
  float fVar6;
  uint *puVar7;
  ushort *puVar8;
  ushort *puVar9;
  char cVar10;
  undefined1 uVar11;
  int *piVar12;
  int iVar13;
  int *piVar14;
  undefined4 uVar15;
  ushort *puVar16;
  int iVar17;
  CINSRules *extraout_ECX;
  CINSRules *this_00;
  CINSNextBot *this_01;
  CINSNavArea *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSWeapon *this_07;
  CINSWeapon *this_08;
  CINSWeapon *extraout_ECX_00;
  CINSNextBot *this_09;
  CINSBotPatrol *this_10;
  CINSRules *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar18;
  float fVar19;
  int *in_stack_0000000c;
  uint local_38;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  piVar12 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  iVar13 = (**(code **)(*piVar12 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar12,0);
  if (iVar13 != 0) {
    piVar12 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
    iVar13 = (**(code **)(*piVar12 + 0xd4 /* IIntention::ShouldAttack */))(piVar12,in_stack_0000000c + 0x818,iVar13);
    if (iVar13 == 1) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined **)(param_1 + 8) = &UNK_002580a4 + unaff_EBX;
      return param_1;
    }
  }
  if (in_stack_0000000c[0x2d1a] < 1) {
    fVar19 = *(float *)((int)param_2 + 0x3c);
    if ((((((uint)fVar19 & 0x7f800000) == 0x7f800000) ||
         (fVar5 = *(float *)((int)param_2 + 0x40), ((uint)fVar5 & 0x7f800000) == 0x7f800000)) ||
        (fVar6 = *(float *)((int)param_2 + 0x44), ((uint)fVar6 & 0x7f800000) == 0x7f800000)) ||
       ((((fVar1 = *(float *)(::__tcf_0 + unaff_EBX + 5), fVar1 < fVar19 &&
          (fVar2 = *(float *)(unaff_EBX + 0x1fd679 /* 0.01f */ /* 0.01f */), fVar19 < fVar2)) &&
         ((fVar1 < fVar5 && ((fVar5 < fVar2 && (fVar1 < fVar6)))))) && (fVar6 < fVar2)))) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x259afd /* "Goal position no longer valid?" */ /* "Goal position no longer valid?" */;
    }
    else {
      if ((0.0 < *(float *)((int)param_2 + 0x4904)) &&
         (fVar18 = (float10)IntervalTimer::Now(),
         fVar19 = (float)fVar18 - *(float *)((int)param_2 + 0x4904),
         fVar19 < *(float *)(unaff_EBX + 0x1ff1e9 /* 40.0f */ /* 40.0f */) || fVar19 == *(float *)(unaff_EBX + 0x1ff1e9 /* 40.0f */ /* 40.0f */))) {
        if (0.0 < *(float *)((int)param_2 + 0x48d8)) {
          fVar18 = (float10)CountdownTimer::Now();
          this_00 = *(CINSRules **)((int)param_2 + 0x48d8);
          if ((float)this_00 < (float)fVar18) {
            if (this_00 != (CINSRules *)0xbf800000) {
              (**(code **)(*(int *)((int)param_2 + 0x48d0) + 4))
                        ((int)param_2 + 0x48d0,(int)param_2 + 0x48d8);
              *(undefined4 *)((int)param_2 + 0x48d8) = 0xbf800000 /* -1.0f */;
              this_00 = extraout_ECX;
            }
            *(undefined1 *)(in_stack_0000000c + 0x8a4) = 0;
            cVar10 = CINSRules::IsSurvival(this_00);
            if (cVar10 != '\0') {
              (**(code **)(*in_stack_0000000c + 0x548 /* CINSNextBot::GetLastKnownArea */))();
              iVar13 = CINSNavArea::GetAssociatedControlPoint(this_02);
              if (iVar13 == *(int *)((int)param_2 + 0x4930)) {
                *(undefined4 *)((int)param_2 + 0x4930) = 0xffffffff;
                iVar13 = **(int **)(unaff_EBX + 0x47f365 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
                if (*(int *)(iVar13 + 0x770) != -1) {
                  if (*(char *)(iVar13 + 0x5c) == '\0') {
                    puVar7 = *(uint **)(iVar13 + 0x20);
                    if ((puVar7 != (uint *)0x0) && ((*puVar7 & 0x100) == 0)) {
                      *puVar7 = *puVar7 | 1;
                      puVar16 = (ushort *)CBaseEdict::GetChangeAccessor((CBaseEdict *)param_2);
                      piVar12 = *(int **)(::__CreateCServerGameTagsIServerGameTags_interface +
                                         unaff_EBX + 5);
                      puVar8 = (ushort *)*piVar12;
                      if (puVar16[1] == *puVar8) {
                        uVar3 = *puVar16;
                        uVar4 = puVar8[(uint)uVar3 * 0x14 + 0x14];
                        local_38 = (uint)uVar4;
                        if (uVar4 == 0) {
LAB_00728298:
                          puVar8[(uint)uVar3 * 0x14 + local_38 + 1] = 0x770;
                          puVar8[(uint)uVar3 * 0x14 + 0x14] = uVar4 + 1;
                        }
                        else if (puVar8[(uint)uVar3 * 0x14 + 1] != 0x770) {
                          iVar17 = 0;
                          do {
                            if (iVar17 == (local_38 - 1 & 0xffff) * 2) {
                              if (uVar4 == 0x13) goto LAB_00728208;
                              goto LAB_00728298;
                            }
                            iVar17 = iVar17 + 2;
                          } while (*(short *)((int)puVar8 + iVar17 + (uint)uVar3 * 0x28 + 2) !=
                                   0x770);
                        }
                      }
                      else if ((puVar8[0x7d1] == 100) || (puVar16[1] != 0)) {
LAB_00728208:
                        puVar16[1] = 0;
                        *puVar7 = *puVar7 | 0x100;
                      }
                      else {
                        *puVar16 = puVar8[0x7d1];
                        puVar9 = (ushort *)*piVar12;
                        puVar8 = puVar9 + 0x7d1;
                        *puVar8 = *puVar8 + 1;
                        puVar16[1] = *puVar9;
                        iVar17 = (uint)*puVar16 * 0x28 + *piVar12;
                        *(undefined2 *)(iVar17 + 2) = 0x770;
                        *(undefined2 *)(iVar17 + 0x28) = 1;
                      }
                    }
                  }
                  else {
                    *(byte *)(iVar13 + 0x60) = *(byte *)(iVar13 + 0x60) | 1;
                  }
                  *(undefined4 *)(iVar13 + 0x770) = 0xffffffff;
                }
              }
            }
            GetNextPatrolArea((CINSBotPatrol *)param_2);
            *(undefined4 *)param_1 = 0 /* Continue */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined4 *)(param_1 + 8) = 0;
            return param_1;
          }
          (**(code **)(*in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))();
        }
        fVar18 = (float10)CountdownTimer::Now();
        if ((((*(float *)((int)param_2 + 0x48cc) <= (float)fVar18 &&
               (float)fVar18 != *(float *)((int)param_2 + 0x48cc)) &&
             (*(char *)((int)param_2 + 0x48dc) == '\0')) &&
            (iVar13 = TheINSNextBots(), *(char *)(iVar13 + 0x129) != '\0')) &&
           (iVar13 = CINSPlayer::GetActiveINSWeapon(), iVar13 != 0)) {
          cVar10 = CINSWeapon::HasLasersights(this_03);
          this_05 = this_04;
          if ((cVar10 != '\0') &&
             (cVar10 = CINSWeapon::IsLasersightsOn(this_04), this_05 = this_08, cVar10 != '\0')) {
            CINSWeapon::ToggleLasersights(this_08);
            this_05 = extraout_ECX_00;
          }
          cVar10 = CINSWeapon::HasFlashlight(this_05);
          if ((cVar10 != '\0') && (cVar10 = CINSWeapon::IsFlashlightOn(this_06), cVar10 != '\0')) {
            CINSWeapon::ToggleFlashlight(this_07);
          }
        }
        fVar18 = (float10)CountdownTimer::Now();
        if (*(float *)((int)param_2 + 0x48c0) <= (float)fVar18 &&
            (float)fVar18 != *(float *)((int)param_2 + 0x48c0)) {
          piVar12 = *(int **)(CServerGameDLL::ShouldAllowDirectConnect + unaff_EBX + 1);
          cVar10 = CINSRules::IsHunt((CINSRules *)param_2);
          if ((cVar10 != '\0') && (*(char *)(*piVar12 + 0x3ac) != '\0')) {
            *(undefined4 *)param_1 = 3 /* Done */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(int *)(param_1 + 8) = unaff_EBX + 0x259c69 /* "We are in counterattack, time to go to the CP" */ /* "We are in counterattack, time to go to the CP" */;
            return param_1;
          }
          fVar18 = (float10)CountdownTimer::Now();
          fVar19 = (float)fVar18 + *(float *)(unaff_EBX + 0x19115d /* 1.0f */ /* 1.0f */);
          if (*(float *)((int)param_2 + 0x48c0) != fVar19) {
            (**(code **)(*(int *)((int)param_2 + 0x48b8) + 4))
                      ((int)param_2 + 0x48b8,(int)param_2 + 0x48c0);
            *(float *)((int)param_2 + 0x48c0) = fVar19;
          }
          if (*(int *)((int)param_2 + 0x48bc) != 0x3f800000 /* 1.0f */) {
            (**(code **)(*(int *)((int)param_2 + 0x48b8) + 4))
                      ((int)param_2 + 0x48b8,(int)param_2 + 0x48bc);
            *(undefined4 *)((int)param_2 + 0x48bc) = 0x3f800000 /* 1.0f */;
          }
        }
        fVar18 = (float10)CountdownTimer::Now();
        if (*(float *)((int)param_2 + 0x48fc) <= (float)fVar18 &&
            (float)fVar18 != *(float *)((int)param_2 + 0x48fc)) {
          this_01 = (CINSNextBot *)param_2;
          if (((*(float *)((int)param_2 + 0x48d8) <= 0.0) &&
              (cVar10 = CINSNextBot::IsIdle((CINSNextBot *)param_2), this_01 = this_09,
              cVar10 != '\0')) &&
             (fVar18 = (float10)CINSNextBot::GetIdleDuration(this_09),
             this_01 = (CINSNextBot *)this_10,
             *(float *)(unaff_EBX + 0x1fcda9 /* 4.0f */ /* 4.0f */) <= (float)fVar18 &&
             (float)fVar18 != *(float *)(unaff_EBX + 0x1fcda9 /* 4.0f */ /* 4.0f */))) {
            GetNextPatrolArea(this_10);
            this_01 = (CINSNextBot *)extraout_ECX_01;
          }
          cVar10 = CINSRules::IsSurvival((CINSRules *)this_01);
          if ((cVar10 != '\0') &&
             (iVar13 = *(int *)(**(int **)(unaff_EBX + 0x47f365 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x770),
             *(int *)((int)param_2 + 0x4930) != iVar13)) {
            *(int *)((int)param_2 + 0x4930) = iVar13;
            GetNextPatrolArea((CINSBotPatrol *)param_2);
          }
          fVar18 = (float10)CountdownTimer::Now();
          fVar19 = (float)fVar18 + *(float *)(unaff_EBX + 0x19115d /* 1.0f */ /* 1.0f */);
          if (*(float *)((int)param_2 + 0x48fc) != fVar19) {
            (**(code **)(*(int *)((int)param_2 + 0x48f4) + 4))
                      ((int)param_2 + 0x48f4,(int)param_2 + 0x48fc);
            *(float *)((int)param_2 + 0x48fc) = fVar19;
          }
          if (*(int *)((int)param_2 + 0x48f8) != 0x3f800000 /* 1.0f */) {
            (**(code **)(*(int *)((int)param_2 + 0x48f4) + 4))
                      ((int)param_2 + 0x48f4,(int)param_2 + 0x48f8);
            *(undefined4 *)((int)param_2 + 0x48f8) = 0x3f800000 /* 1.0f */;
          }
          piVar12 = in_stack_0000000c + 0x818;
          iVar13 = (**(code **)(in_stack_0000000c[0x818] + 0x114))(piVar12);
          if (iVar13 == 0) {
            fVar18 = (float10)(**(code **)(in_stack_0000000c[0x818] + 0x134))
                                        (piVar12,(int)param_2 + 0x3c);
          }
          else {
            piVar14 = (int *)(**(code **)(in_stack_0000000c[0x818] + 0x114))(piVar12);
            fVar18 = (float10)(**(code **)(*piVar14 + 0x74))(piVar14,piVar12);
          }
          *(float *)((int)param_2 + 0x48ec) = (float)fVar18;
          piVar12 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
          local_28 = *(undefined4 *)((int)param_2 + 0x3c);
          local_24 = *(undefined4 *)((int)param_2 + 0x40);
          local_20 = *(float *)(unaff_EBX + 0x2366c1 /* 69.0f */ /* 69.0f */) + *(float *)((int)param_2 + 0x44);
          uVar11 = (**(code **)(*piVar12 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar12,&local_28,0);
          *(undefined1 *)((int)param_2 + 0x48f0) = uVar11;
        }
        if (((*(char *)((int)param_2 + 0x4920) != '\0') &&
            (fVar18 = (float10)CountdownTimer::Now(),
            *(float *)((int)param_2 + 0x491c) <= (float)fVar18 &&
            (float)fVar18 != *(float *)((int)param_2 + 0x491c))) &&
           ((*(undefined1 *)((int)param_2 + 0x4920) = 0,
            (*(uint *)((int)param_2 + 0x4924) & 0x7f800000) != 0x7f800000 &&
            (((*(uint *)((int)param_2 + 0x4928) & 0x7f800000) != 0x7f800000 &&
             ((*(uint *)((int)param_2 + 0x492c) & 0x7f800000) != 0x7f800000)))))) {
          *(undefined4 *)((int)param_2 + 0x3c) = *(undefined4 *)((int)param_2 + 0x4924);
          *(undefined4 *)((int)param_2 + 0x40) = *(undefined4 *)((int)param_2 + 0x4928);
          *(undefined4 *)((int)param_2 + 0x44) = *(undefined4 *)((int)param_2 + 0x492c);
          uVar15 = (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))();
          CINSBotLocomotion::AddMovementRequest
                    (uVar15,*(undefined4 *)((int)param_2 + 0x3c),
                     *(undefined4 *)((int)param_2 + 0x40),*(undefined4 *)((int)param_2 + 0x44),4,3,
                     0x40a00000 /* 5.0f */);
        }
        *(undefined4 *)param_1 = 0 /* Continue */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x259c39 /* "Patrol expiry time reached." */ /* "Patrol expiry time reached." */;
    }
  }
  else {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x259c1b /* "I have things to investigate!" */ /* "I have things to investigate!" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnEnd
 * Address: 00725990
 * ---------------------------------------- */

/* CINSBotPatrol::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotPatrol::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  param_2[0x2290] = (Action)0x0;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::OnSuspend
 * Address: 00725970
 * ---------------------------------------- */

/* CINSBotPatrol::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotPatrol::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::OnResume
 * Address: 007282c0
 * ---------------------------------------- */

/* CINSBotPatrol::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotPatrol::OnResume(CINSBotPatrol *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  undefined4 uVar2;
  CNavMesh *extraout_ECX;
  CNavMesh *pCVar3;
  CINSRules *this_00;
  CINSBotPatrol *this_01;
  int unaff_EBX;
  float10 fVar4;
  CBaseEntity *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(param_2 + 0x48c0) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(param_2 + 0x48b8) + 4))(param_2 + 0x48b8,param_2 + 0x48c0);
    *(undefined4 *)(param_2 + 0x48c0) = 0xbf800000 /* -1.0f */;
  }
  fVar4 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x4904) != (float)fVar4) {
    (**(code **)(*(int *)(param_2 + 0x4900) + 8))(param_2 + 0x4900,param_2 + 0x4904);
    *(float *)(param_2 + 0x4904) = (float)fVar4;
  }
  pCVar3 = (CNavMesh *)in_stack_0000000c;
  if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(in_stack_0000000c);
    pCVar3 = extraout_ECX;
  }
  uVar2 = CNavMesh::GetNearestNavArea
                    (pCVar3,**(undefined4 **)(unaff_EBX + 0x47e3ed /* &TheNavMesh */ /* &TheNavMesh */),in_stack_0000000c + 0x208,0,
                     0x461c4000 /* 10000.0f */,0,1,0);
  *(undefined4 *)(param_2 + 0x38) = uVar2;
  cVar1 = CINSRules::IsSurvival(this_00);
  if (cVar1 != '\0') {
    *(undefined4 *)(param_2 + 0x4930) = *(undefined4 *)(**(int **)(unaff_EBX + 0x47ea51 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x770);
  }
  cVar1 = GetNextPatrolArea(this_01);
  if (cVar1 != '\0') {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x259341 /* "Nothing to patrol" */ /* "Nothing to patrol" */;
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::GetName
 * Address: 00728820
 * ---------------------------------------- */

/* CINSBotPatrol::GetName() const */

int CINSBotPatrol::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x259a75 /* "Patrol" */ /* "Patrol" */;
}



/* ----------------------------------------
 * CINSBotPatrol::ShouldHurry
 * Address: 00725e00
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPatrol::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotPatrol::ShouldHurry(CINSBotPatrol *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::ShouldHurry
 * Address: 00725e10
 * ---------------------------------------- */

/* CINSBotPatrol::ShouldHurry(INextBot const*) const */

int __cdecl CINSBotPatrol::ShouldHurry(INextBot *param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  CINSRules *this;
  CINSRules *this_00;
  CINSRules *extraout_ECX;
  CINSRules *this_01;
  CINSRules *extraout_ECX_00;
  CINSRules *extraout_ECX_01;
  int iVar4;
  int unaff_EBX;
  float fVar5;
  undefined8 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  
  uVar6 = __i686_get_pc_thunk_bx();
  iVar4 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  if (((iVar4 != 0) && (iVar4 != 0x2060)) &&
     (piVar1 = *(int **)(unaff_EBX + 0x480ad2 /* &g_pGameRules */ /* &g_pGameRules */), *piVar1 != 0)) {
    cVar2 = CINSRules::IsSurvival(this);
    if (cVar2 != '\0') {
      fVar5 = ((float)*(int *)(*piVar1 + 1000) + *(float *)(unaff_EBX + 0x192cea /* -1.0f */ /* -1.0f */)) *
              *(float *)(unaff_EBX + 0x20dd1a /* rodata:0x3DAAAAAB */ /* rodata:0x3DAAAAAB */);
      if (*(float *)(unaff_EBX + 0x192cee /* 1.0f */ /* 1.0f */) <= fVar5) {
        fVar5 = *(float *)(unaff_EBX + 0x192cee /* 1.0f */ /* 1.0f */);
      }
      if (fVar5 <= *(float *)(unaff_EBX + 0x192ce2 /* 0.0f */ /* 0.0f */)) {
        fVar5 = *(float *)(unaff_EBX + 0x192ce2 /* 0.0f */ /* 0.0f */);
      }
      if (fVar5 * *(float *)(&DAT_0025b87a + unaff_EBX) + *(float *)(unaff_EBX + 0x1ff1ea /* 1000.0f */ /* 1000.0f */) <
          *(float *)(param_1 + 0x48ec)) {
        return 1;
      }
    }
    cVar2 = CINSRules::IsConquer(this_00);
    this_01 = extraout_ECX;
    if (cVar2 != '\0') {
      uVar9 = 0;
      uVar8 = 1;
      uVar7 = 0;
      iVar3 = CNavMesh::GetNearestNavArea();
      this_01 = extraout_ECX_00;
      if (((iVar3 != 0) &&
          (iVar3 = __dynamic_cast(iVar3,*(undefined4 *)(unaff_EBX + 0x4807c2 /* &typeinfo for CNavArea */ /* &typeinfo for CNavArea */),
                                  *(undefined4 *)(unaff_EBX + 0x480e62 /* &typeinfo for CINSNavArea */ /* &typeinfo for CINSNavArea */),0,uVar7,uVar8,uVar9),
          this_01 = extraout_ECX_01, iVar3 != 0)) && ((*(uint *)(iVar3 + 0x160) & 0x2004) != 0)) {
        if (*(float *)(unaff_EBX + 0x233a92 /* 1500.0f */ /* 1500.0f */) < *(float *)(param_1 + 0x48ec)) {
          return 1;
        }
        if (param_1[0x48f0] != (INextBot)0x0) {
          return 0;
        }
      }
    }
    cVar2 = CINSRules::IsHunt(this_01);
    iVar3 = 2;
    if ((cVar2 == '\0') && (*(float *)(unaff_EBX + 0x233a92 /* 1500.0f */ /* 1500.0f */) < *(float *)(param_1 + 0x48ec))) {
      iVar3 = 2 - (uint)(param_1[0x48f0] == (INextBot)0x0);
    }
  }
  return iVar3;
}



/* ----------------------------------------
 * CINSBotPatrol::OnContact
 * Address: 00725a10
 * ---------------------------------------- */

/* CINSBotPatrol::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

CINSNextBot *
CINSBotPatrol::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
  iVar2 = (**(code **)(*piVar1 + 0x134 /* CINSBotBody::GetArousal */))(piVar1);
  if (iVar2 < 3) {
    piVar1 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
    (**(code **)(*piVar1 + 0x130 /* CINSBotBody::SetArousal */))(piVar1,3);
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnMoveToSuccess
 * Address: 007263d0
 * ---------------------------------------- */

/* CINSBotPatrol::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * __thiscall
CINSBotPatrol::OnMoveToSuccess(CINSBotPatrol *this,CINSNextBot *param_1,Path *param_2)

{
  float fVar1;
  float *pfVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  CINSRules *this_00;
  int unaff_EBX;
  float10 fVar6;
  CBaseEntity *in_stack_0000000c;
  CBaseEntity *pCVar7;
  undefined4 uVar8;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  cVar3 = CINSRules::IsHunt(this_00);
  if (cVar3 == '\0') {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x25b1dd /* "Completed our task." */ /* "Completed our task." */;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
    uVar8 = 1;
    CINSNextBot::GetHidingCover(true);
    pfVar2 = *(float **)(unaff_EBX + 0x4801eb /* &vec3_origin */ /* &vec3_origin */);
    if (((*pfVar2 == local_3c) && (pfVar2[1] == local_38)) && (pfVar2[2] == local_34)) {
      fVar6 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */,uVar8);
      fVar1 = (float)fVar6;
      fVar6 = (float10)CountdownTimer::Now();
      if (*(float *)(param_2 + 0x48d8) != (float)fVar6 + fVar1) {
        (**(code **)(*(int *)(param_2 + 0x48d0) + 4))(param_2 + 0x48d0,param_2 + 0x48d8);
        *(float *)(param_2 + 0x48d8) = (float)fVar6 + fVar1;
      }
      if (*(float *)(param_2 + 0x48d4) != fVar1) {
        (**(code **)(*(int *)(param_2 + 0x48d0) + 4))(param_2 + 0x48d0,param_2 + 0x48d4);
        *(float *)(param_2 + 0x48d4) = fVar1;
      }
    }
    else {
      uVar8 = 1;
      pCVar7 = in_stack_0000000c;
      CINSNextBot::GetHidingCover(true);
      uVar8 = (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,pCVar7,uVar8);
      CINSBotLocomotion::AddMovementRequest(uVar8,local_28,local_24,local_20,4,3,0x40000000 /* 2.0f */);
      in_stack_0000000c[0x2290] = (CBaseEntity)0x1;
      fVar6 = (float10)RandomFloat(0x41200000 /* 10.0f */,0x41700000 /* 15.0f */);
      fVar1 = (float)fVar6;
      iVar4 = (**(code **)(*(int *)in_stack_0000000c + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_0000000c);
      if (iVar4 != 0) {
        iVar5 = CBaseEntity::GetTeamNumber(in_stack_0000000c);
        iVar4 = iVar4 + 0x1f0 + (iVar5 * 3 + -6) * 4;
        fVar6 = (float10)CountdownTimer::Now();
        if (*(float *)(iVar4 + 0x14) != (float)fVar6 + fVar1) {
          (**(code **)(*(int *)(iVar4 + 0xc) + 4))(iVar4 + 0xc,iVar4 + 0x14);
          *(float *)(iVar4 + 0x14) = (float)fVar6 + fVar1;
        }
        if (*(float *)(iVar4 + 0x10) != fVar1) {
          (**(code **)(*(int *)(iVar4 + 0xc) + 4))(iVar4 + 0xc,iVar4 + 0x10);
          *(float *)(iVar4 + 0x10) = fVar1;
        }
      }
      fVar6 = (float10)CountdownTimer::Now();
      if (*(float *)(param_2 + 0x48d8) != (float)fVar6 + fVar1) {
        (**(code **)(*(int *)(param_2 + 0x48d0) + 4))(param_2 + 0x48d0,param_2 + 0x48d8);
        *(float *)(param_2 + 0x48d8) = (float)fVar6 + fVar1;
      }
      if (*(float *)(param_2 + 0x48d4) != fVar1) {
        (**(code **)(*(int *)(param_2 + 0x48d0) + 4))(param_2 + 0x48d0,param_2 + 0x48d4);
        *(float *)(param_2 + 0x48d4) = fVar1;
      }
    }
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnMoveToFailure
 * Address: 007259d0
 * ---------------------------------------- */

/* CINSBotPatrol::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotPatrol::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = &UNK_0025a2df + extraout_ECX;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::OnStuck
 * Address: 00725b80
 * ---------------------------------------- */

/* CINSBotPatrol::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotPatrol::OnStuck(CINSNextBot *param_1)

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
  iVar1 = *(int *)(unaff_EBX + 0x480e2d /* &vtable for CINSBotStuck */ /* &vtable for CINSBotStuck */);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = unaff_EBX + 0x40262d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x259ec6 /* "I'm Stuck" */ /* "I'm Stuck" */;
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
 * CINSBotPatrol::OnInjured
 * Address: 00725a80
 * ---------------------------------------- */

/* CINSBotPatrol::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

CINSNextBot * __thiscall
CINSBotPatrol::OnInjured(CINSBotPatrol *this,CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  int *piVar1;
  int iVar2;
  int *in_stack_0000000c;
  
  piVar1 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
  iVar2 = (**(code **)(*piVar1 + 0x134 /* CINSBotBody::GetArousal */))(piVar1);
  if (iVar2 < 5) {
    piVar1 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    (**(code **)(*piVar1 + 0x130 /* CINSBotBody::SetArousal */))(piVar1,5);
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnOtherKilled
 * Address: 00725fc0
 * ---------------------------------------- */

/* CINSBotPatrol::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

CINSNextBot * __thiscall
CINSBotPatrol::OnOtherKilled
          (CINSBotPatrol *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CTakeDamageInfo *param_3)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  int unaff_EBX;
  int *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if (param_3 != (CTakeDamageInfo *)0x0) {
    piVar1 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
    iVar2 = (**(code **)(*piVar1 + 0x134 /* CINSBotBody::GetArousal */))(piVar1);
    if ((iVar2 < 8) && (in_stack_00000010 != (int *)0x0)) {
      iVar2 = CBaseEntity::GetTeamNumber(this_00);
      iVar3 = CBaseEntity::GetTeamNumber(this_01);
      if (iVar2 == iVar3) {
        pfVar4 = (float *)(**(code **)(*in_stack_00000010 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000010);
        pfVar5 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
        if (SQRT((pfVar5[1] - pfVar4[1]) * (pfVar5[1] - pfVar4[1]) +
                 (*pfVar5 - *pfVar4) * (*pfVar5 - *pfVar4) +
                 (pfVar5[2] - pfVar4[2]) * (pfVar5[2] - pfVar4[2])) <
            *(float *)(unaff_EBX + 0x1ff044 /* 400.0f */ /* 400.0f */)) {
          piVar1 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
          (**(code **)(*piVar1 + 0x130 /* CINSBotBody::SetArousal */))(piVar1,8);
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnSight
 * Address: 00726ab0
 * ---------------------------------------- */

/* CINSBotPatrol::OnSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotPatrol::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  char cVar1;
  int iVar2;
  CBaseEntity *pCVar3;
  int *piVar4;
  CINSBotVision *this;
  CINSWeapon *this_00;
  CINSWeapon *this_01;
  CINSWeapon *extraout_ECX;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  CBaseEntity *in_stack_0000000c;
  int *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000010 != (int *)0x0) {
    cVar1 = (**(code **)(*in_stack_00000010 + 0x158))();
    if (cVar1 != '\0') {
      cVar1 = CBaseEntity::InSameTeam(in_stack_0000000c);
      if (cVar1 == '\0') {
        iVar2 = CINSPlayer::GetActiveINSWeapon();
        if (iVar2 != 0) {
          if (**(int **)(unaff_EBX + 0x47fbf4 /* &TheNavMesh */ /* &TheNavMesh */) != 0) {
            iVar2 = TheINSNextBots();
            if (*(char *)(iVar2 + 0x129) != '\0') {
              pCVar3 = (CBaseEntity *)
                       (**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
              iVar2 = CINSBotVision::GetSilhouetteType(this,pCVar3);
              if ((iVar2 == -1) || (iVar2 == 2)) goto LAB_00726ae3;
              cVar1 = CINSWeapon::HasFlashlight(this_00);
              if (cVar1 != '\0') {
                cVar1 = CINSWeapon::IsFlashlightOn(this_01);
                if (cVar1 == '\0') {
                  fVar5 = (float10)CountdownTimer::Now();
                  fVar6 = (float)fVar5 + *(float *)(unaff_EBX + 0x1fdca8 /* 5.0f */ /* 5.0f */);
                  if (*(float *)(param_2 + 0x48cc) != fVar6) {
                    (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48cc)
                    ;
                    *(float *)(param_2 + 0x48cc) = fVar6;
                  }
                  if (*(int *)(param_2 + 0x48c8) != 0x40a00000 /* 5.0f */) {
                    (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48c8)
                    ;
                    *(undefined4 *)(param_2 + 0x48c8) = 0x40a00000 /* 5.0f */;
                    param_2 = (CBaseEntity *)extraout_ECX;
                  }
                  CINSWeapon::ToggleFlashlight((CINSWeapon *)param_2);
                }
              }
            }
          }
          piVar4 = (int *)TheINSNextBots();
          (**(code **)(*piVar4 + 0x38))(piVar4,in_stack_0000000c);
        }
      }
    }
  }
LAB_00726ae3:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnLostSight
 * Address: 007259a0
 * ---------------------------------------- */

/* CINSBotPatrol::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotPatrol::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::OnCommandApproach
 * Address: 00726710
 * ---------------------------------------- */

/* CINSBotPatrol::OnCommandApproach(CINSNextBot*, Vector const&, float) */

CINSNextBot * CINSBotPatrol::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float *pfVar6;
  int unaff_EBX;
  float10 fVar7;
  float *in_stack_00000010;
  float in_stack_00000014;
  
  __i686_get_pc_thunk_bx();
  pfVar6 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
  fVar1 = *in_stack_00000010;
  if (SQRT((pfVar6[1] - in_stack_00000010[1]) * (pfVar6[1] - in_stack_00000010[1]) +
           (*pfVar6 - fVar1) * (*pfVar6 - fVar1) +
           (pfVar6[2] - in_stack_00000010[2]) * (pfVar6[2] - in_stack_00000010[2])) <
      in_stack_00000014) {
    *(float *)(param_2 + 0x4924) = fVar1;
    fVar4 = in_stack_00000010[1];
    *(float *)(param_2 + 0x4928) = fVar4;
    fVar5 = in_stack_00000010[2];
    *(float *)(param_2 + 0x492c) = fVar5;
    if ((((((uint)fVar1 & 0x7f800000) != 0x7f800000) && (((uint)fVar4 & 0x7f800000) != 0x7f800000))
        && (((uint)fVar5 & 0x7f800000) != 0x7f800000)) &&
       ((((fVar2 = *(float *)(unaff_EBX + 0x202ab1 /* -0.01f */ /* -0.01f */), fVar1 <= fVar2 ||
          (fVar3 = *(float *)(unaff_EBX + 0x1fe915 /* 0.01f */ /* 0.01f */), fVar3 <= fVar1)) ||
         ((fVar4 <= fVar2 || ((fVar3 <= fVar4 || (fVar5 <= fVar2)))))) || (fVar3 <= fVar5)))) {
      param_2[0x4920] = (Vector)0x1;
      fVar7 = (float10)RandomFloat(0x3dcccccd /* 0.1f */,0x40400000 /* 3.0f */);
      fVar1 = (float)fVar7;
      fVar7 = (float10)CountdownTimer::Now();
      if (*(float *)(param_2 + 0x491c) != (float)fVar7 + fVar1) {
        (**(code **)(*(int *)(param_2 + 0x4914) + 4))(param_2 + 0x4914,param_2 + 0x491c);
        *(float *)(param_2 + 0x491c) = (float)fVar7 + fVar1;
      }
      if (*(float *)(param_2 + 0x4918) != fVar1) {
        (**(code **)(*(int *)(param_2 + 0x4914) + 4))(param_2 + 0x4914,param_2 + 0x4918);
        *(float *)(param_2 + 0x4918) = fVar1;
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::GetNextPatrolArea
 * Address: 00727280
 * ---------------------------------------- */

/* CINSBotPatrol::GetNextPatrolArea() */

undefined4 __thiscall CINSBotPatrol::GetNextPatrolArea(CINSBotPatrol *this)

{
  uint uVar1;
  uint uVar2;
  float fVar3;
  byte bVar4;
  int *piVar5;
  float *pfVar6;
  char cVar7;
  undefined4 uVar8;
  int iVar9;
  int *piVar10;
  CollectIdealPatrolAreas *this_00;
  CollectIdealPatrolAreas *extraout_ECX;
  CollectIdealPatrolAreas *extraout_ECX_00;
  CollectIdealPatrolAreas *pCVar11;
  CINSNavArea *this_01;
  CBaseEntity *pCVar12;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBaseEntity *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_01;
  int unaff_EBX;
  int iVar13;
  int iVar14;
  ushort in_FPUControlWord;
  float10 fVar15;
  float10 fVar16;
  float fVar17;
  int in_stack_00000004;
  int local_8c [2];
  int local_84 [2];
  int local_7c;
  int local_78;
  int local_5c;
  undefined4 local_58;
  int local_54;
  Vector *local_50;
  int local_4c;
  float local_3c;
  float local_38;
  float local_34;
  float local_2c;
  float local_28;
  float local_24;
  ushort local_1e;
  undefined4 uStack_14;
  
  uStack_14 = 0x72728b;
  __i686_get_pc_thunk_bx();
  piVar5 = *(int **)(in_stack_00000004 + 0x1c);
  if (piVar5 == (int *)0x0) {
    return 0;
  }
  CollectIdealPatrolAreas::CollectIdealPatrolAreas(this_00,(CINSNextBot *)local_8c);
  iVar14 = *(int *)(unaff_EBX + 0x47fd55 /* &TheNavAreas */ /* &TheNavAreas */);
  pCVar11 = extraout_ECX;
  if (0 < *(int *)(iVar14 + 0xc)) {
    iVar13 = 0;
    do {
      cVar7 = CollectIdealPatrolAreas::operator()(pCVar11,(CNavArea *)local_8c);
      pCVar11 = extraout_ECX_00;
      if (cVar7 == '\0') break;
      iVar13 = iVar13 + 1;
    } while (iVar13 < *(int *)(iVar14 + 0xc));
  }
  if (local_78 < 1) {
LAB_00727520:
    local_5c = 0;
    local_58 = 0;
    local_54 = 0;
    local_50 = (Vector *)0x0;
    iVar14 = **(int **)(unaff_EBX + 0x47fa91 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
    local_4c = 0;
    pCVar12 = *(CBaseEntity **)(iVar14 + 0x37c);
    if ((int)pCVar12 < 1) {
LAB_007277ad:
      iVar14 = 1;
      do {
        piVar10 = (int *)UTIL_PlayerByIndex(iVar14);
        if (piVar10 != (int *)0x0) {
          iVar13 = CBaseEntity::GetTeamNumber(this_03);
          iVar9 = CBaseEntity::GetTeamNumber(this_04);
          if (((iVar13 == iVar9) &&
              (cVar7 = (**(code **)(*piVar10 + 0x118 /* CBaseEntity::IsAlive */))(piVar10), cVar7 != '\0')) &&
             (iVar13 = (**(code **)(*piVar10 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar10), iVar13 != 0)) {
            if ((*(byte *)((int)piVar10 + 0xd1) & 8) == 0) {
              bVar4 = *(byte *)((int)piVar5 + 0xd1);
              pCVar12 = this_05;
            }
            else {
              CBaseEntity::CalcAbsolutePosition(this_05);
              bVar4 = *(byte *)((int)piVar5 + 0xd1);
              pCVar12 = extraout_ECX_01;
            }
            if ((bVar4 & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(pCVar12);
            }
            fVar17 = ((float)piVar5[0x83] - (float)piVar10[0x83]) *
                     ((float)piVar5[0x83] - (float)piVar10[0x83]) +
                     ((float)piVar5[0x82] - (float)piVar10[0x82]) *
                     ((float)piVar5[0x82] - (float)piVar10[0x82]) +
                     ((float)piVar5[0x84] - (float)piVar10[0x84]) *
                     ((float)piVar5[0x84] - (float)piVar10[0x84]);
            if (*(float *)(unaff_EBX + 0x25a41d /* rodata:0x48742400 */ /* rodata:0x48742400 */) <= fVar17 &&
                fVar17 != *(float *)(unaff_EBX + 0x25a41d /* rodata:0x48742400 */ /* rodata:0x48742400 */)) {
              iVar14 = (**(code **)(*piVar10 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar10);
              goto LAB_0072775e;
            }
          }
        }
        iVar14 = iVar14 + 1;
      } while (iVar14 != 0x31);
      iVar14 = 0;
    }
    else {
      iVar13 = 0;
      do {
        iVar14 = *(int *)(iVar14 + 0x490 + iVar13 * 4);
        iVar9 = CBaseEntity::GetTeamNumber(pCVar12);
        if (iVar9 == iVar14) {
          iVar14 = CBaseEntity::GetTeamNumber(this_02);
          if (iVar14 == 2) {
            cVar7 = *(char *)(**(int **)(unaff_EBX + 0x47fa91 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x6a0 + iVar13);
          }
          else {
            cVar7 = *(char *)(**(int **)(unaff_EBX + 0x47fa91 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x690 + iVar13);
          }
          if (cVar7 == '\0') {
            CINSNavMesh::GetControlPointHidingSpot((int)&local_3c);
            pfVar6 = *(float **)(unaff_EBX + 0x47f341 /* &vec3_origin */ /* &vec3_origin */);
            if (((*pfVar6 != local_3c) || (pfVar6[1] != local_38)) || (pfVar6[2] != local_34)) {
              CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)&local_5c,local_50);
            }
          }
        }
        pCVar12 = *(CBaseEntity **)(unaff_EBX + 0x47fa91 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
        iVar13 = iVar13 + 1;
        iVar14 = *(int *)pCVar12;
      } while (iVar13 < *(int *)(iVar14 + 0x37c));
      if ((int)local_50 < 1) goto LAB_007277ad;
      RandomInt(0,local_50 + -1);
      iVar14 = CNavMesh::GetNearestNavArea();
      if (iVar14 == 0) goto LAB_007277ad;
    }
LAB_0072775e:
    local_50 = (Vector *)0x0;
    if (local_54 < 0) {
      local_4c = local_5c;
    }
    else {
      if (local_5c != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47f5ed /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x47f5ed /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_5c);
        local_5c = 0;
      }
      local_58 = 0;
      local_4c = 0;
    }
    if (iVar14 != 0) goto LAB_0072741d;
  }
  else {
    CUtlVector<AreaPatrolData*,CUtlMemory<AreaPatrolData*,int>>::Sort
              ((CUtlVector<AreaPatrolData*,CUtlMemory<AreaPatrolData*,int>> *)pCVar11,
               (_func_int_AreaPatrolData_ptr_ptr_AreaPatrolData_ptr_ptr *)local_84);
    iVar14 = 0x31;
    do {
      local_1e = in_FPUControlWord & 0xf3ff | 0x400;
      iVar13 = RandomInt(0,(int)ROUND((double)(local_78 / 2)));
      iVar13 = *(int *)(local_84[0] + iVar13 * 4);
      if (*(int *)(iVar13 + 4) != 0) {
        CINSPlayer::GetTeamID();
        fVar15 = (float10)CINSNavArea::GetNearbyDeathIntensity(this_01,*(int *)(iVar13 + 4));
        uVar1 = *(uint *)(unaff_EBX + 0x191891 /* 0.1f */ /* 0.1f */);
        uVar2 = *(uint *)(unaff_EBX + 0x1fd4c1 /* 0.3f */ /* 0.3f */);
        fVar16 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
        if ((float)(~-(uint)(0.0 < (float)fVar15) & uVar2 | uVar1 & -(uint)(0.0 < (float)fVar15)) <=
            (float)fVar16) {
          iVar14 = *(int *)(iVar13 + 4);
          if (iVar14 != 0) goto LAB_0072741d;
          break;
        }
      }
      iVar14 = iVar14 + -1;
    } while (iVar14 != 0);
    iVar14 = RandomInt(0,local_78 + -1);
    iVar14 = *(int *)(*(int *)(local_84[0] + iVar14 * 4) + 4);
    if (iVar14 == 0) goto LAB_00727520;
LAB_0072741d:
    CNavArea::GetRandomPoint();
    *(float *)(in_stack_00000004 + 0x3c) = local_2c;
    *(float *)(in_stack_00000004 + 0x40) = local_28;
    *(float *)(in_stack_00000004 + 0x44) = local_24;
    if (((((uint)local_2c & 0x7f800000) != 0x7f800000) &&
        (((uint)local_28 & 0x7f800000) != 0x7f800000)) &&
       ((((uint)local_24 & 0x7f800000) != 0x7f800000 &&
        (((((fVar17 = *(float *)(unaff_EBX + 0x201f41 /* -0.01f */ /* -0.01f */), local_2c <= fVar17 ||
            (fVar3 = *(float *)(unaff_EBX + 0x1fdda5 /* 0.01f */ /* 0.01f */), fVar3 <= local_2c)) || (local_28 <= fVar17))
          || ((fVar3 <= local_28 || (local_24 <= fVar17)))) || (fVar3 <= local_24)))))) {
      uVar8 = (**(code **)(*piVar5 + 0x96c /* CINSNextBot::GetLocomotionInterface */))(piVar5,iVar14);
      CINSBotLocomotion::AddMovementRequest
                (uVar8,*(undefined4 *)(in_stack_00000004 + 0x3c),
                 *(undefined4 *)(in_stack_00000004 + 0x40),*(undefined4 *)(in_stack_00000004 + 0x44)
                 ,4,3,0x40a00000 /* 5.0f */);
      uVar8 = 1;
      goto LAB_00727662;
    }
  }
  uVar8 = 0;
LAB_00727662:
  local_8c[0] = unaff_EBX + 0x470895 /* vtable for CollectIdealPatrolAreas+0x8 */ /* vtable for CollectIdealPatrolAreas+0x8 */;
  if (0 < local_78) {
    iVar14 = 0;
    do {
      iVar13 = iVar14 * 4;
      iVar14 = iVar14 + 1;
      operator_delete(*(void **)(local_84[0] + iVar13));
    } while (iVar14 < local_78);
  }
  local_78 = 0;
  if ((-1 < local_7c) && (local_84[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47f5ed /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x47f5ed /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_84[0]);
  }
  return uVar8;
}



/* ----------------------------------------
 * CINSBotPatrol::OnCommandAttack
 * Address: 00725af0
 * ---------------------------------------- */

/* CINSBotPatrol::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotPatrol::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int *piVar1;
  int unaff_EBX;
  undefined4 in_stack_00000010;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  piVar1 = (int *)(**(code **)(*piVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(piVar1);
  (**(code **)(*piVar1 + 0xe8 /* IVision::AddKnownEntity */))(piVar1,in_stack_00000010);
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x259f33 /* "Received the order to attack" */ /* "Received the order to attack" */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0xc) = 2;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnHeardFootsteps
 * Address: 00726c70
 * ---------------------------------------- */

/* CINSBotPatrol::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

CINSNextBot * __thiscall
CINSBotPatrol::OnHeardFootsteps
          (CINSBotPatrol *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  CBaseEntity *this_00;
  CNavMesh *extraout_ECX;
  CNavMesh *pCVar4;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  int *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000010 != (int *)0x0) &&
     (cVar1 = (**(code **)(*in_stack_00000010 + 0x158))(), cVar1 != '\0')) {
    iVar2 = CBaseEntity::GetTeamNumber((CBaseEntity *)param_3);
    iVar3 = CBaseEntity::GetTeamNumber(this_00);
    if ((iVar2 != iVar3) &&
       (((iVar2 = CINSPlayer::GetActiveINSWeapon(), iVar2 != 0 &&
         (iVar2 = **(int **)(unaff_EBX + 0x47fa34 /* &TheNavMesh */ /* &TheNavMesh */), iVar2 != 0)) &&
        (iVar3 = TheINSNextBots(), *(char *)(iVar3 + 0x129) != '\0')))) {
      pCVar4 = (CNavMesh *)param_3;
      if (((byte)param_3[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)param_3);
        pCVar4 = extraout_ECX;
      }
      iVar2 = CNavMesh::GetNearestNavArea(pCVar4,iVar2,param_3 + 0x208,0,0x461c4000 /* 10000.0f */,0,1,0);
      if (((iVar2 != 0) &&
          ((*(float *)(iVar2 + 0xe4) + *(float *)(iVar2 + 0xe0) + *(float *)(iVar2 + 0xe8) +
           *(float *)(iVar2 + 0xec)) * *(float *)(unaff_EBX + 0x1fce08 /* 0.25f */ /* 0.25f */) <
           *(float *)(unaff_EBX + 0x1fdad4 /* 0.5f */ /* 0.5f */))) &&
         ((cVar1 = CINSWeapon::HasFlashlight(this_01), cVar1 != '\0' &&
          (cVar1 = CINSWeapon::IsFlashlightOn(this_02), cVar1 == '\0')))) {
        fVar5 = (float10)CountdownTimer::Now();
        fVar6 = (float)fVar5 + *(float *)(unaff_EBX + 0x1fdae8 /* 5.0f */ /* 5.0f */);
        if (*(float *)(param_2 + 0x48cc) != fVar6) {
          (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48cc);
          *(float *)(param_2 + 0x48cc) = fVar6;
        }
        if (*(int *)(param_2 + 0x48c8) != 0x40a00000 /* 5.0f */) {
          (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48c8);
          *(undefined4 *)(param_2 + 0x48c8) = 0x40a00000 /* 5.0f */;
          param_2 = (CBaseCombatCharacter *)extraout_ECX_00;
        }
        CINSWeapon::ToggleFlashlight((CINSWeapon *)param_2);
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnNavAreaChanged
 * Address: 00726920
 * ---------------------------------------- */

/* CINSBotPatrol::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

CINSNextBot * __thiscall
CINSBotPatrol::OnNavAreaChanged
          (CINSBotPatrol *this,CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  char cVar1;
  int iVar2;
  CINSPlayer *this_00;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *extraout_ECX;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000010 != 0) && (param_3 != (CNavArea *)0x0)) {
    iVar2 = TheINSNextBots();
    if ((*(char *)(iVar2 + 0x129) != '\0') &&
       ((*(float *)(in_stack_00000010 + 0xe4) + *(float *)(in_stack_00000010 + 0xe0) +
         *(float *)(in_stack_00000010 + 0xe8) + *(float *)(in_stack_00000010 + 0xec)) *
        *(float *)(unaff_EBX + 0x1fd158 /* 0.25f */ /* 0.25f */) < *(float *)(&LAB_00202880 + unaff_EBX))) {
      cVar1 = CINSPlayer::IsSprinting(this_00);
      if (cVar1 == '\0') {
        iVar2 = CINSPlayer::GetActiveINSWeapon();
        if (iVar2 != 0) {
          cVar1 = CINSWeapon::HasFlashlight(this_01);
          if (cVar1 != '\0') {
            cVar1 = CINSWeapon::IsFlashlightOn(this_02);
            if (cVar1 == '\0') {
              fVar3 = (float10)CountdownTimer::Now();
              fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x192648 /* 3.0f */ /* 3.0f */);
              if (*(float *)(param_2 + 0x48cc) != fVar4) {
                (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48cc);
                *(float *)(param_2 + 0x48cc) = fVar4;
              }
              if (*(int *)(param_2 + 0x48c8) != 0x40400000 /* 3.0f */) {
                (**(code **)(*(int *)(param_2 + 0x48c4) + 4))(param_2 + 0x48c4,param_2 + 0x48c8);
                *(undefined4 *)(param_2 + 0x48c8) = 0x40400000 /* 3.0f */;
                param_2 = (CNavArea *)extraout_ECX;
              }
              CINSWeapon::ToggleFlashlight((CINSWeapon *)param_2);
            }
          }
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotPatrol::OnSeeSomethingSuspicious
 * Address: 007260f0
 * ---------------------------------------- */

/* CINSBotPatrol::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void __thiscall
CINSBotPatrol::OnSeeSomethingSuspicious
          (CINSBotPatrol *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  byte bVar3;
  char cVar4;
  float *pfVar5;
  float *pfVar6;
  undefined4 *puVar7;
  CINSGrenadeTarget *pCVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *pCVar12;
  CINSNextBotManager *this_01;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *this_02;
  int unaff_EBX;
  float10 fVar13;
  float fVar14;
  int *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000010 != (int *)0x0) &&
     (cVar4 = (**(code **)(*in_stack_00000010 + 0x158 /* CBasePlayer::IsPlayer */))(in_stack_00000010), cVar4 != '\0')) {
    iVar9 = CBaseEntity::GetTeamNumber(this_00);
    iVar10 = CBaseEntity::GetTeamNumber(this_02);
    if (iVar9 != iVar10) {
      piVar11 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
      iVar9 = (**(code **)(*piVar11 + 0x134 /* CINSBotBody::GetArousal */))(piVar11);
      if (iVar9 < 3) {
        piVar11 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
        (**(code **)(*piVar11 + 0x130 /* CINSBotBody::SetArousal */))(piVar11,3);
      }
    }
  }
  pfVar5 = (float *)(**(code **)(*in_stack_00000010 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000010);
  pfVar6 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
  fVar14 = SQRT((pfVar6[1] - pfVar5[1]) * (pfVar6[1] - pfVar5[1]) +
                (*pfVar6 - *pfVar5) * (*pfVar6 - *pfVar5) +
                (pfVar6[2] - pfVar5[2]) * (pfVar6[2] - pfVar5[2]));
  if ((fVar14 < *(float *)(unaff_EBX + 0x1fef15 /* 1000.0f */ /* 1000.0f */) || fVar14 == *(float *)(unaff_EBX + 0x1fef15 /* 1000.0f */ /* 1000.0f */)) ||
     (*(float *)(unaff_EBX + 0x2337bd /* 1500.0f */ /* 1500.0f */) <= fVar14)) {
    fVar13 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
    if ((float)fVar13 < *(float *)(NDebugOverlay::Circle + unaff_EBX + 5) ||
        (float)fVar13 == *(float *)(NDebugOverlay::Circle + unaff_EBX + 5)) goto LAB_007262ea;
    bVar3 = *(byte *)((int)in_stack_00000010 + 0xd1);
    pCVar12 = extraout_ECX_03;
  }
  else {
    bVar3 = *(byte *)((int)in_stack_00000010 + 0xd1);
    pCVar12 = extraout_ECX;
  }
  if ((bVar3 & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(pCVar12);
  }
  puVar7 = (undefined4 *)::operator_new(0x24);
  puVar1 = puVar7 + 1;
  iVar9 = in_stack_00000010[0x82];
  iVar10 = in_stack_00000010[0x83];
  iVar2 = in_stack_00000010[0x84];
  puVar7[1] = unaff_EBX + 0x4020bd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  puVar7[2] = 0;
  CountdownTimer::NetworkStateChanged(puVar1);
  puVar7[3] = 0xbf800000 /* -1.0f */;
  (**(code **)(puVar7[1] + 4))(puVar1,puVar7 + 3);
  puVar7[4] = iVar9;
  puVar7[5] = iVar10;
  puVar7[6] = iVar2;
  fVar13 = (float10)CountdownTimer::Now();
  fVar14 = (float)fVar13 + *(float *)(unaff_EBX + 0x1fe0b5 /* 10.0f */ /* 10.0f */);
  pCVar12 = extraout_ECX_00;
  if ((float)puVar7[3] != fVar14) {
    (**(code **)(puVar7[1] + 4))(puVar1,puVar7 + 3);
    puVar7[3] = fVar14;
    pCVar12 = extraout_ECX_01;
  }
  if (puVar7[2] != 0x41200000 /* 10.0f */) {
    (**(code **)(puVar7[1] + 4))(puVar1,puVar7 + 2);
    puVar7[2] = 0x41200000 /* 10.0f */;
    pCVar12 = extraout_ECX_02;
  }
  *(undefined1 *)(puVar7 + 7) = 0;
  *(undefined1 *)((int)puVar7 + 0x1d) = 0;
  *puVar7 = 0xd;
  puVar7[8] = 0x42c80000 /* 100.0f */;
  pCVar8 = (CINSGrenadeTarget *)CBaseEntity::GetTeamNumber(pCVar12);
  iVar9 = TheINSNextBots();
  CINSNextBotManager::AddGrenadeTarget(this_01,iVar9,pCVar8);
LAB_007262ea:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::ShouldWalk
 * Address: 00725d60
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPatrol::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotPatrol::ShouldWalk(CINSBotPatrol *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::ShouldWalk
 * Address: 00725d70
 * ---------------------------------------- */

/* CINSBotPatrol::ShouldWalk(INextBot const*) const */

char __cdecl CINSBotPatrol::ShouldWalk(INextBot *param_1)

{
  int unaff_EBX;
  float10 fVar1;
  float fVar2;
  
  fVar2 = 0.0;
  __i686_get_pc_thunk_bx();
  if ((fVar2 < *(float *)(param_1 + 0x48d8)) &&
     (fVar1 = (float10)CountdownTimer::Now(),
     (float)fVar1 < *(float *)(param_1 + 0x48d8) || (float)fVar1 == *(float *)(param_1 + 0x48d8))) {
    return '\x01';
  }
  if (param_1[0x48f0] != (INextBot)0x0) {
    return '\x01';
  }
  return (*(float *)(unaff_EBX + 0x1ff295 /* 300.0f */ /* 300.0f */) < *(float *)(param_1 + 0x48ec) ||
         *(float *)(unaff_EBX + 0x1ff295 /* 300.0f */ /* 300.0f */) == *(float *)(param_1 + 0x48ec)) + '\x01';
}



/* ----------------------------------------
 * CINSBotPatrol::~CINSBotPatrol
 * Address: 00728840
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPatrol::~CINSBotPatrol() */

void __thiscall CINSBotPatrol::~CINSBotPatrol(CINSBotPatrol *this)

{
  ~CINSBotPatrol(this);
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::~CINSBotPatrol
 * Address: 00728850
 * ---------------------------------------- */

/* CINSBotPatrol::~CINSBotPatrol() */

void __thiscall CINSBotPatrol::~CINSBotPatrol(CINSBotPatrol *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46f0ea /* vtable for CINSBotPatrol+0x8 */ /* vtable for CINSBotPatrol+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46f282 /* vtable for CINSBotPatrol+0x1a0 */ /* vtable for CINSBotPatrol+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::~CINSBotPatrol
 * Address: 007288b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotPatrol::~CINSBotPatrol() */

void __thiscall CINSBotPatrol::~CINSBotPatrol(CINSBotPatrol *this)

{
  ~CINSBotPatrol(this);
  return;
}



/* ----------------------------------------
 * CINSBotPatrol::~CINSBotPatrol
 * Address: 007288c0
 * ---------------------------------------- */

/* CINSBotPatrol::~CINSBotPatrol() */

void __thiscall CINSBotPatrol::~CINSBotPatrol(CINSBotPatrol *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46f07a /* vtable for CINSBotPatrol+0x8 */ /* vtable for CINSBotPatrol+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46f212 /* vtable for CINSBotPatrol+0x1a0 */ /* vtable for CINSBotPatrol+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



