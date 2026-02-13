/*
 * CINSBotAttackFromCover -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackFromCover::CINSBotAttackFromCover
 * Address: 007089f0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::CINSBotAttackFromCover() */

void __thiscall CINSBotAttackFromCover::CINSBotAttackFromCover(CINSBotAttackFromCover *this)

{
  int *piVar1;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48c60d /* vtable for CINSBotAttackFromCover+0x8 */ /* vtable for CINSBotAttackFromCover+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x48c7b5 /* vtable for CINSBotAttackFromCover+0x1b0 */ /* vtable for CINSBotAttackFromCover+0x1b0 */;
  in_stack_00000004[0xe] = (int)(&UNK_0041f7bd + unaff_EBX);
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
  in_stack_00000004[0xf] = 0;
  (*(code *)(unaff_EBX + -0x4d828b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
  in_stack_00000004[0x13] = 0;
  in_stack_00000004[0x12] = (int)(&UNK_0041f7bd + unaff_EBX);
  (*(code *)(unaff_EBX + -0x4d828b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0x12,in_stack_00000004 + 0x13);
  in_stack_00000004[0x14] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x12] + 4))(in_stack_00000004 + 0x12,in_stack_00000004 + 0x14);
  *(undefined1 *)(in_stack_00000004 + 0x18) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x61) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x62) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 99) = 0;
  *(undefined1 *)(in_stack_00000004 + 0x19) = 0;
  if (in_stack_00000004[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = -0x40800000 /* -1.0f */;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnStart
 * Address: 007087e0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackFromCover::OnStart(CINSBotAttackFromCover *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  code *pcVar2;
  int *piVar3;
  CINSBotBody *pCVar4;
  int *piVar5;
  undefined4 uVar6;
  int unaff_EBX;
  float10 fVar7;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
  if (piVar3 != (int *)0x0) {
    pCVar4 = (CINSBotBody *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    CINSBotBody::SetPosture(pCVar4,pCVar4,3,8,0x3f800000 /* 1.0f */,unaff_EBX + 0x277999 /* "Crouching in fire from cover start" */ /* "Crouching in fire from cover start" */);
    piVar5 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    pcVar2 = *(code **)(*piVar5 + 0xd8);
    uVar6 = (**(code **)(*piVar3 + 0x10))(piVar3);
    (*pcVar2)(piVar5,uVar6,3,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x2779bd /* "Aiming towards enemy in fire from cover start" */ /* "Aiming towards enemy in fire from cover start" */);
    fVar7 = (float10)CountdownTimer::Now();
    fVar1 = *(float *)(&DAT_0021c979 + unaff_EBX);
    if (*(float *)(param_2 + 0x50) != (float)fVar7 + fVar1) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x50);
      *(float *)(param_2 + 0x50) = (float)fVar7 + fVar1;
    }
    if (*(int *)(param_2 + 0x4c) != 0x3fc00000 /* 1.5f */) {
      (**(code **)(*(int *)(param_2 + 0x48) + 4))(param_2 + 0x48,param_2 + 0x4c);
      *(undefined4 *)(param_2 + 0x4c) = 0x3fc00000 /* 1.5f */;
    }
    param_2[0x54] = (Action)0x1;
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::Update
 * Address: 00709720
 * ---------------------------------------- */

/* CINSBotAttackFromCover::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackFromCover::Update(CINSBotAttackFromCover *this,CINSNextBot *param_1,float param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  CINSNextBot CVar3;
  code *pcVar4;
  char cVar5;
  int *piVar6;
  int iVar7;
  int *piVar8;
  CINSNextBot *pCVar9;
  undefined4 uVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  CINSGrenadeTarget *pCVar14;
  int iVar15;
  void *pvVar16;
  CINSPlayer *this_00;
  CINSNextBot *this_01;
  CFmtStrN<256,false> *this_02;
  CINSNextBot *extraout_ECX;
  CINSPlayer *this_03;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_04;
  CINSBotAttackFromCover *this_05;
  CINSNextBot *pCVar17;
  CINSNextBot *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *extraout_ECX_04;
  CBaseEntity *this_06;
  CINSNextBotManager *this_07;
  CINSBotAttackInPlace *this_08;
  CINSBotThrowGrenade *this_09;
  CINSNextBot *pCVar18;
  int unaff_EBX;
  float10 fVar19;
  float fVar20;
  CINSNextBot *in_stack_0000000c;
  int *piVar21;
  CINSNextBot *local_140;
  char local_13c [5];
  CINSNextBot local_137 [255];
  CINSNextBot local_38 [4];
  int local_34;
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x70972b;
  __i686_get_pc_thunk_bx();
  fVar19 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x50) <= (float)fVar19 &&
      (float)fVar19 != *(float *)((int)param_2 + 0x50)) {
    piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
    if (((piVar6 == (int *)0x0) || (iVar7 = (**(code **)(*piVar6 + 0x10))(piVar6), iVar7 == 0)) ||
       (cVar5 = (**(code **)(*piVar6 + 0x54))(piVar6), cVar5 != '\0')) goto LAB_00709b98;
    piVar8 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    piVar21 = piVar6;
    iVar7 = (**(code **)(*piVar8 + 0xd4 /* IIntention::ShouldAttack */))(piVar8,in_stack_0000000c + 0x2060,piVar6);
    if (iVar7 == 0) goto LAB_00709806;
    fVar19 = (float10)RandomFloat(0x40a00000 /* 5.0f */,0x41200000 /* 10.0f */);
    cVar5 = CINSPlayer::IsCrouched(this_00);
    if (cVar5 == '\0') {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      piVar21 = (int *)0x8;
      CINSBotBody::SetPosture();
    }
    else {
      cVar5 = CINSNextBot::ShouldOpportunisticReload(this_01);
      if (cVar5 != '\0') {
        puVar11 = (undefined4 *)(**(code **)(*piVar6 + 0x14))(piVar6);
        puVar12 = (undefined4 *)::operator_new(0x24);
        puVar13 = puVar12 + 1;
        iVar7 = unaff_EBX + 0x41ea8d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
        uVar10 = *puVar11;
        uVar1 = puVar11[1];
        uVar2 = puVar11[2];
        puVar12[1] = iVar7;
        pcVar4 = (code *)(unaff_EBX + -0x4d8fbb /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
        puVar12[2] = 0;
        (*pcVar4)(puVar13,puVar12 + 2);
        puVar12[3] = 0xbf800000 /* -1.0f */;
        (**(code **)(puVar12[1] + 4))(puVar13,puVar12 + 3);
        puVar12[4] = uVar10;
        puVar12[5] = uVar1;
        puVar12[6] = uVar2;
        fVar19 = (float10)CountdownTimer::Now();
        fVar20 = (float)fVar19 + *(float *)(unaff_EBX + 0x21aa85 /* 10.0f */ /* 10.0f */);
        this_06 = extraout_ECX_02;
        if ((float)puVar12[3] != fVar20) {
          (**(code **)(puVar12[1] + 4))(puVar13,puVar12 + 3);
          puVar12[3] = fVar20;
          this_06 = extraout_ECX_03;
        }
        if (puVar12[2] != 0x41200000 /* 10.0f */) {
          (**(code **)(puVar12[1] + 4))(puVar13,puVar12 + 2);
          puVar12[2] = 0x41200000 /* 10.0f */;
          this_06 = extraout_ECX_04;
        }
        *(undefined1 *)(puVar12 + 7) = 0;
        *(undefined1 *)((int)puVar12 + 0x1d) = 0;
        *puVar12 = 0xd;
        puVar12[8] = 0x42c80000 /* 100.0f */;
        pCVar14 = (CINSGrenadeTarget *)CBaseEntity::GetTeamNumber(this_06);
        iVar15 = TheINSNextBots();
        CINSNextBotManager::AddGrenadeTarget(this_07,iVar15,pCVar14);
        piVar6 = (int *)::operator_new(0x5c);
        piVar6[8] = 0;
        piVar6[9] = 0;
        piVar6[10] = 0;
        piVar6[3] = 0;
        piVar6[4] = 0;
        piVar6[5] = 0;
        piVar6[6] = 0;
        piVar6[7] = 0;
        piVar6[2] = 0;
        *(undefined1 *)(piVar6 + 0xc) = 0;
        *(undefined1 *)((int)piVar6 + 0x31) = 0;
        piVar6[0xb] = 0;
        piVar6[0xd] = 0;
        iVar15 = *(int *)(unaff_EBX + 0x49d2cd /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
        piVar6[0xf] = 0;
        piVar6[1] = iVar15 + 0x198;
        *piVar6 = iVar15 + 8;
        piVar6[0xe] = iVar7;
        (*pcVar4)(piVar6 + 0xe,piVar6 + 0xf,puVar12);
        piVar6[0x10] = -0x40800000 /* -1.0f */;
        (**(code **)(piVar6[0xe] + 4))(piVar6 + 0xe,piVar6 + 0x10);
        piVar6[0x12] = 0;
        piVar6[0x11] = iVar7;
        (*pcVar4)(piVar6 + 0x11,piVar6 + 0x12);
        piVar6[0x13] = -0x40800000 /* -1.0f */;
        (**(code **)(piVar6[0x11] + 4))(piVar6 + 0x11,piVar6 + 0x13);
        piVar6[0x15] = 0;
        piVar6[0x14] = iVar7;
        (*pcVar4)(piVar6 + 0x14,piVar6 + 0x15);
        piVar6[0x16] = -0x40800000 /* -1.0f */;
        (**(code **)(piVar6[0x14] + 4))(piVar6 + 0x14,piVar6 + 0x16);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(int **)(param_1 + 4) = piVar6;
        *(int *)(param_1 + 8) = unaff_EBX + 0x276a11 /* "Need to Reload" */ /* "Need to Reload" */;
        return param_1;
      }
      if (*(char *)((int)param_2 + 0x54) != '\0') {
        piVar8 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        pcVar4 = *(code **)(*piVar8 + 0xd8);
        uVar10 = (**(code **)(*piVar6 + 0x10))(piVar6);
        piVar21 = (int *)0x3;
        (*pcVar4)(piVar8,uVar10,3,(float)fVar19,0,unaff_EBX + 0x276aad /* "Aiming towards enemy in fire from cover" */ /* "Aiming towards enemy in fire from cover" */);
        if (*(char *)((int)param_2 + 0x61) == '\0') {
          if (*(char *)((int)param_2 + 99) == '\0') {
            if (*(char *)((int)param_2 + 100) != '\0') {
              (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
              piVar21 = (int *)0x8;
              CINSBotBody::SetPosture();
            }
          }
          else {
            (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            piVar21 = (int *)0x8;
            CINSBotBody::SetPosture();
          }
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          piVar21 = (int *)0x8;
          CINSBotBody::SetPosture();
        }
      }
    }
    fVar20 = (float)fVar19 - *(float *)(unaff_EBX + 0x1af3f1 /* 0.1f */ /* 0.1f */);
    fVar19 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x50) != (float)fVar19 + fVar20) {
      (**(code **)(*(int *)((int)param_2 + 0x48) + 4))
                ((int)param_2 + 0x48,(int)param_2 + 0x50,piVar21);
      *(float *)((int)param_2 + 0x50) = (float)fVar19 + fVar20;
    }
    if (*(float *)((int)param_2 + 0x4c) != fVar20) {
      (**(code **)(*(int *)((int)param_2 + 0x48) + 4))((int)param_2 + 0x48,(int)param_2 + 0x4c);
      *(float *)((int)param_2 + 0x4c) = fVar20;
    }
  }
  fVar19 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar19 &&
      (float)fVar19 != *(float *)((int)param_2 + 0x40)) {
    piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
    if (((piVar6 == (int *)0x0) || (iVar7 = (**(code **)(*piVar6 + 0x10))(piVar6), iVar7 == 0)) ||
       (cVar5 = (**(code **)(*piVar6 + 0x54))(piVar6), cVar5 != '\0')) {
LAB_00709b98:
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
    piVar21 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar7 = (**(code **)(*piVar21 + 0xd4 /* IIntention::ShouldAttack */))(piVar21,in_stack_0000000c + 0x2060,piVar6);
    if (iVar7 == 0) {
LAB_00709806:
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x276854 /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */;
      return param_1;
    }
    cVar5 = CINSPlayer::IsCrouched(this_03);
    if (cVar5 == '\0') {
      *(undefined4 *)((int)param_2 + 0x58) = 0xbf800000 /* -1.0f */;
      pCVar17 = extraout_ECX_00;
    }
    else {
      cVar5 = CINSBotThrowGrenade::CanIThrowGrenade(in_stack_0000000c,local_28);
      if (cVar5 != '\0') {
        pvVar16 = ::operator_new(0x6c);
        CINSBotThrowGrenade::CINSBotThrowGrenade(this_09);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(void **)(param_1 + 4) = pvVar16;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
      pCVar17 = extraout_ECX_01;
      if (*(float *)((int)param_2 + 0x58) < 0.0) {
        *(undefined4 *)((int)param_2 + 0x58) =
             *(undefined4 *)(**(int **)(unaff_EBX + 0x49d175 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
      }
      else {
        fVar20 = *(float *)(**(int **)(unaff_EBX + 0x49d175 /* &gpGlobals */ /* &gpGlobals */) + 0xc) -
                 *(float *)((int)param_2 + 0x58);
        if (*(float *)(unaff_EBX + 0x21c625 /* 6.0f */ /* 6.0f */) <= fVar20 && fVar20 != *(float *)(unaff_EBX + 0x21c625 /* 6.0f */ /* 6.0f */)
           ) {
          *(undefined4 *)param_1 = 3 /* Done */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined **)(param_1 + 8) = &UNK_00276afd + unaff_EBX;
          return param_1;
        }
      }
    }
    *(undefined1 *)((int)param_2 + 0x54) = 1;
    cVar5 = CINSNextBot::IsSuppressed(pCVar17);
    if (cVar5 != '\0') {
      *(undefined1 *)((int)param_2 + 0x54) = 0;
    }
    cVar5 = CINSNextBot::ShouldOpportunisticReload(this_04);
    if (cVar5 != '\0') {
      *(undefined1 *)((int)param_2 + 0x54) = 0;
    }
    UpdateLOS(this_05);
    if (((*(char *)((int)param_2 + 0x61) != '\0') && (*(char *)((int)param_2 + 0x62) != '\0')) &&
       (*(char *)((int)param_2 + 0x60) != '\0')) {
      pvVar16 = ::operator_new(0x50);
      CINSBotAttackInPlace::CINSBotAttackInPlace(this_08);
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(void **)(param_1 + 4) = pvVar16;
      *(int *)(param_1 + 8) = unaff_EBX + 0x276a3d /* "we have shitty cover" */ /* "we have shitty cover" */;
      return param_1;
    }
    fVar19 = (float10)CountdownTimer::Now();
    fVar20 = *(float *)(&LAB_0021b02d + unaff_EBX);
    if (*(float *)((int)param_2 + 0x40) != (float)fVar19 + fVar20) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40);
      *(float *)((int)param_2 + 0x40) = (float)fVar19 + fVar20;
    }
    if (*(int *)((int)param_2 + 0x3c) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c);
      *(undefined4 *)((int)param_2 + 0x3c) = 0x3f000000 /* 0.5f */;
    }
  }
  iVar7 = (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
  iVar7 = *(int *)(iVar7 + 0x100);
  CFmtStrN<256,false>::CFmtStrN(this_02,local_13c,unaff_EBX + 0x276a52 /* "AFC:" */ /* "AFC:" */);
  if (iVar7 == 9) {
    pCVar17 = (CINSNextBot *)(unaff_EBX + 0x2769dc /* "Trying Lean Left," */ /* "Trying Lean Left," */);
    local_140 = local_137 + local_34;
    if (local_140 < local_38) {
      do {
        CVar3 = *pCVar17;
        pCVar17 = pCVar17 + 1;
        *local_140 = CVar3;
        local_140 = local_140 + 1;
        if (local_140 == local_38) break;
      } while (*pCVar17 != (CINSNextBot)0x0);
    }
  }
  else {
    pCVar17 = extraout_ECX;
    if (iVar7 != 10) goto LAB_007099c4;
    pCVar17 = (CINSNextBot *)(unaff_EBX + 0x2769ee /* "Trying Lean Right," */ /* "Trying Lean Right," */);
    local_140 = local_137 + local_34;
    if (local_140 < local_38) {
      do {
        CVar3 = *pCVar17;
        pCVar17 = pCVar17 + 1;
        *local_140 = CVar3;
        local_140 = local_140 + 1;
        if (local_140 == local_38) break;
      } while (*pCVar17 != (CINSNextBot)0x0);
    }
  }
  pCVar17 = local_137;
  *local_140 = (CINSNextBot)0x0;
  local_34 = (int)local_140 - (int)pCVar17;
LAB_007099c4:
  if (*(char *)((int)param_2 + 0x61) != '\0') {
    pCVar17 = (CINSNextBot *)(unaff_EBX + 0x276a01 /* "ST," */ /* "ST," */);
    local_140 = local_137 + local_34;
    if (local_140 < local_38) {
      do {
        CVar3 = *pCVar17;
        pCVar17 = pCVar17 + 1;
        *local_140 = CVar3;
        local_140 = local_140 + 1;
        if (local_140 == local_38) goto LAB_00709d4d;
      } while (*pCVar17 != (CINSNextBot)0x0);
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
    else {
LAB_00709d4d:
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
  }
  if (*(char *)((int)param_2 + 99) != '\0') {
    pCVar17 = (CINSNextBot *)(unaff_EBX + 0x276a05 /* "LL," */ /* "LL," */);
    local_140 = local_137 + local_34;
    if (local_140 < local_38) {
      do {
        CVar3 = *pCVar17;
        pCVar17 = pCVar17 + 1;
        *local_140 = CVar3;
        local_140 = local_140 + 1;
        if (local_140 == local_38) goto LAB_00709cdd;
      } while (*pCVar17 != (CINSNextBot)0x0);
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
    else {
LAB_00709cdd:
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
  }
  if (*(char *)((int)param_2 + 100) != '\0') {
    pCVar17 = (CINSNextBot *)(unaff_EBX + 0x276a09 /* "RL," */ /* "RL," */);
    local_140 = local_137 + local_34;
    if (local_140 < local_38) {
      do {
        CVar3 = *pCVar17;
        pCVar17 = pCVar17 + 1;
        *local_140 = CVar3;
        local_140 = local_140 + 1;
        if (local_140 == local_38) goto LAB_00709c6d;
      } while (*pCVar17 != (CINSNextBot)0x0);
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
    else {
LAB_00709c6d:
      pCVar17 = local_137;
      *local_140 = (CINSNextBot)0x0;
      local_34 = (int)local_140 - (int)pCVar17;
    }
  }
  if (*(char *)((int)param_2 + 0x62) != '\0') {
    pCVar18 = local_137 + local_34;
    pCVar9 = (CINSNextBot *)(unaff_EBX + 0x276a0d /* "CR," */ /* "CR," */);
    pCVar17 = local_38;
    if (pCVar18 < local_38) {
      do {
        CVar3 = *pCVar9;
        pCVar17 = (CINSNextBot *)(uint)(byte)CVar3;
        pCVar9 = pCVar9 + 1;
        *pCVar18 = CVar3;
        pCVar18 = pCVar18 + 1;
        if (pCVar18 == local_38) break;
      } while (*pCVar9 != (CINSNextBot)0x0);
    }
    *pCVar18 = (CINSNextBot)0x0;
    local_34 = (int)pCVar18 - (int)local_137;
  }
  CINSNextBot::FireWeaponAtEnemy(pCVar17);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnEnd
 * Address: 00708280
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackFromCover::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::GetName
 * Address: 0070a500
 * ---------------------------------------- */

/* CINSBotAttackFromCover::GetName() const */

int CINSBotAttackFromCover::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x275bf2 /* "AttackFromCover" */ /* "AttackFromCover" */;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldHurry
 * Address: 00708290
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackFromCover::ShouldHurry(CINSBotAttackFromCover *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldHurry
 * Address: 007082a0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldHurry(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldRetreat
 * Address: 007082b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldRetreat(INextBot const*) const */

void __thiscall
CINSBotAttackFromCover::ShouldRetreat(CINSBotAttackFromCover *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldRetreat
 * Address: 007082c0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldRetreat(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldAttack
 * Address: 007082d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackFromCover::ShouldAttack
          (CINSBotAttackFromCover *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldAttack
 * Address: 007082e0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnContact
 * Address: 00708350
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackFromCover::OnContact
               (CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnMoveToSuccess
 * Address: 00708380
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackFromCover::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnMoveToFailure
 * Address: 007083b0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackFromCover::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnStuck
 * Address: 007083e0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnStuck(CINSNextBot*) */

void CINSBotAttackFromCover::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnUnStuck
 * Address: 00708410
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnUnStuck(CINSNextBot*) */

void CINSBotAttackFromCover::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnInjured
 * Address: 00708470
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackFromCover::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnKilled
 * Address: 007084a0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackFromCover::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnOtherKilled
 * Address: 007084d0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo
   const&) */

void CINSBotAttackFromCover::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnSight
 * Address: 00708500
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackFromCover::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnLostSight
 * Address: 00708530
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackFromCover::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnWeaponFired
 * Address: 00708560
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackFromCover::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnCommandApproach
 * Address: 007085f0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackFromCover::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnCommandApproach
 * Address: 00708620
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackFromCover::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnCommandString
 * Address: 00708680
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackFromCover::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnBlinded
 * Address: 007086b0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackFromCover::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnCommandAttack
 * Address: 007085c0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackFromCover::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnCommandRetreat
 * Address: 00708650
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackFromCover::OnCommandRetreat
               (CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnHeardFootsteps
 * Address: 007086e0
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackFromCover::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnNavAreaChanged
 * Address: 00708590
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackFromCover::OnNavAreaChanged
               (CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnPostureChanged
 * Address: 00708440
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackFromCover::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::OnSeeSomethingSuspicious
 * Address: 00708710
 * ---------------------------------------- */

/* CINSBotAttackFromCover::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

void CINSBotAttackFromCover::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldIronsight
 * Address: 00708310
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldIronsight(INextBot const*) const */

void __thiscall
CINSBotAttackFromCover::ShouldIronsight(CINSBotAttackFromCover *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldIronsight
 * Address: 00708320
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldIronsight(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldProne
 * Address: 00708330
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackFromCover::ShouldProne(CINSBotAttackFromCover *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldProne
 * Address: 00708340
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldProne(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldWalk
 * Address: 007082f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackFromCover::ShouldWalk(CINSBotAttackFromCover *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::ShouldWalk
 * Address: 00708300
 * ---------------------------------------- */

/* CINSBotAttackFromCover::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackFromCover::ShouldWalk(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::UpdateLOS
 * Address: 00708b40
 * ---------------------------------------- */

/* CINSBotAttackFromCover::UpdateLOS() */

void __thiscall CINSBotAttackFromCover::UpdateLOS(CINSBotAttackFromCover *this)

{
  float fVar1;
  Vector *pVVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  CBaseEntity *this_00;
  CTraceFilterSimple *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_02;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *pCVar7;
  CBasePlayer *extraout_ECX_03;
  float fVar8;
  float fVar9;
  int unaff_EBX;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  int in_stack_00000004;
  Vector local_11c [12];
  Vector local_110 [32];
  float local_f0;
  char local_e5;
  undefined4 local_d0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_ac;
  float local_a8;
  float local_a4;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_7c;
  undefined1 local_78;
  undefined1 local_77;
  int local_6c [4];
  int local_5c;
  undefined4 local_58;
  int local_54;
  undefined4 local_50;
  undefined4 local_4c;
  float local_40;
  float local_3c;
  float local_38;
  Vector local_34 [12];
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x708b4b;
  __i686_get_pc_thunk_bx();
  pVVar2 = *(Vector **)(in_stack_00000004 + 0x1c);
  if (pVVar2 != (Vector *)0x0) {
    piVar4 = (int *)(**(code **)(*(int *)pVVar2 + 0x974 /* CINSNextBot::GetVisionInterface */))(pVVar2);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (((byte)pVVar2[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
    }
    fVar12 = *(float *)(unaff_EBX + 0x25552d /* 69.0f */ /* 69.0f */) + *(float *)(pVVar2 + 0x210);
    fVar8 = *(float *)(pVVar2 + 0x208);
    fVar1 = *(float *)(pVVar2 + 0x20c);
    piVar4 = (int *)(**(code **)(*piVar4 + 0x10 /* CBaseEntity::GetCollideable */))(piVar4);
    (**(code **)(*piVar4 + 0x20c /* CINSNextBot::EyePosition */))(&local_40,piVar4);
    local_d0 = 0;
    CTraceFilterSimple::CTraceFilterSimple
              (this_01,(IHandleEntity *)local_6c,(int)pVVar2,(_func_bool_IHandleEntity_ptr_int *)0x0
              );
    local_6c[0] = unaff_EBX + 0x48ba45 /* vtable for INSVisionTraceFilterIgnorePlayers+0x8 */ /* vtable for INSVisionTraceFilterIgnorePlayers+0x8 */;
    local_5c = 0;
    local_58 = 0;
    local_ac = local_40 - fVar8;
    local_78 = 1;
    local_a8 = local_3c - fVar1;
    local_54 = 0;
    local_50 = 0;
    local_a4 = local_38 - fVar12;
    local_4c = 0;
    local_7c = 0;
    local_84 = 0;
    local_88 = 0;
    local_8c = 0;
    local_77 = local_a8 * local_a8 + local_ac * local_ac + local_a4 * local_a4 != 0.0;
    local_94 = 0;
    local_98 = 0;
    local_9c = 0;
    local_bc = fVar8;
    local_b8 = fVar1;
    local_b4 = fVar12;
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */) + 0x14))
              ((int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */),&local_bc,0x2006241,local_6c,local_11c
              );
    piVar4 = *(int **)(&DAT_0049def5 + unaff_EBX);
    iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
    pCVar7 = extraout_ECX;
    if (iVar5 != 0) {
      iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
      fVar8 = 0.5;
      if (iVar5 != 0) {
        fVar8 = -1.0;
      }
      DebugDrawLine(local_11c,local_110,0xff,0,0,true,fVar8);
      pCVar7 = extraout_ECX_01;
    }
    cVar3 = local_e5;
    if (*(float *)(unaff_EBX + 0x1affc9 /* 1.0f */ /* 1.0f */) <= local_f0) {
      cVar3 = '\x01';
    }
    *(char *)(in_stack_00000004 + 0x61) = cVar3;
    if (((byte)pVVar2[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar7);
    }
    local_bc = *(float *)(pVVar2 + 0x208);
    local_b8 = *(float *)(pVVar2 + 0x20c);
    local_ac = local_40 - local_bc;
    local_a8 = local_3c - local_b8;
    local_b4 = *(float *)(unaff_EBX + 0x255535 /* 37.0f */ /* 37.0f */) + *(float *)(pVVar2 + 0x210);
    local_7c = 0;
    local_a4 = local_38 - local_b4;
    local_78 = 1;
    local_84 = 0;
    local_88 = 0;
    local_8c = 0;
    local_77 = local_a8 * local_a8 + local_ac * local_ac + local_a4 * local_a4 != 0.0;
    local_94 = 0;
    local_98 = 0;
    local_9c = 0;
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */) + 0x14))
              ((int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */),&local_bc,0x2006241,local_6c,local_11c
              );
    iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
    pCVar7 = extraout_ECX_00;
    if (iVar5 != 0) {
      iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
      fVar8 = 0.5;
      if (iVar5 != 0) {
        fVar8 = -1.0;
      }
      DebugDrawLine(local_11c,local_110,0xff,0,0,true,fVar8);
      pCVar7 = extraout_ECX_02;
    }
    cVar3 = local_e5;
    if (*(float *)(unaff_EBX + 0x1affc9 /* 1.0f */ /* 1.0f */) <= local_f0) {
      cVar3 = '\x01';
    }
    *(char *)(in_stack_00000004 + 0x62) = cVar3;
    if (((byte)pVVar2[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar7);
    }
    local_bc = *(float *)(pVVar2 + 0x208);
    local_b8 = *(float *)(pVVar2 + 0x20c);
    local_ac = local_40 - local_bc;
    local_a8 = local_3c - local_b8;
    local_b4 = *(float *)(unaff_EBX + 0x21f7e9 /* 12.0f */ /* 12.0f */) + *(float *)(pVVar2 + 0x210);
    local_7c = 0;
    local_a4 = local_38 - local_b4;
    local_78 = 1;
    local_84 = 0;
    local_88 = 0;
    local_8c = 0;
    local_77 = local_a8 * local_a8 + local_ac * local_ac + local_a4 * local_a4 != 0.0;
    local_94 = 0;
    local_98 = 0;
    local_9c = 0;
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */) + 0x14))
              ((int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */),&local_bc,0x2006241,local_6c,local_11c
              );
    iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
    if (iVar5 != 0) {
      iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
      fVar8 = 0.5;
      if (iVar5 != 0) {
        fVar8 = -1.0;
      }
      DebugDrawLine(local_11c,local_110,0xff,0,0,true,fVar8);
    }
    cVar3 = local_e5;
    if (*(float *)(unaff_EBX + 0x1affc9 /* 1.0f */ /* 1.0f */) <= local_f0) {
      cVar3 = '\x01';
    }
    *(char *)(in_stack_00000004 + 0x60) = cVar3;
    if (((*(char *)(in_stack_00000004 + 0x61) == '\0') ||
        (*(char *)(in_stack_00000004 + 0x62) == '\0')) || (cVar3 == '\0')) {
      piVar6 = (int *)(**(code **)(*(int *)pVVar2 + 0x970 /* CINSNextBot::GetBodyInterface */))(pVVar2);
      cVar3 = (**(code **)(*piVar6 + 0xdc /* PlayerBody::IsHeadAimingOnTarget */))(piVar6);
      if (cVar3 == '\0') {
        *(undefined1 *)(in_stack_00000004 + 99) = 0;
        *(undefined1 *)(in_stack_00000004 + 100) = 0;
      }
      else {
        pCVar7 = this_02;
        if (((byte)pVVar2[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_02);
          pCVar7 = (CBaseEntity *)extraout_ECX_03;
        }
        fVar8 = *(float *)(pVVar2 + 0x208);
        fVar1 = *(float *)(pVVar2 + 0x20c);
        fVar12 = *(float *)(pVVar2 + 0x210);
        CBasePlayer::EyeVectors((CBasePlayer *)pCVar7,pVVar2,local_34,(Vector *)&local_28);
        local_78 = 1;
        fVar10 = *(float *)(unaff_EBX + 0x22f2cd /* 32.0f */ /* 32.0f */);
        local_7c = 0;
        fVar11 = local_28 * fVar10 + fVar8;
        fVar13 = local_24 * fVar10 + fVar1;
        fVar10 = fVar10 * local_20 + fVar12 + 69.0;
        local_ac = local_40 - fVar11;
        local_a8 = local_3c - fVar13;
        local_84 = 0;
        local_a4 = local_38 - fVar10;
        local_88 = 0;
        local_8c = 0;
        local_94 = 0;
        local_98 = 0;
        local_9c = 0;
        local_77 = local_a8 * local_a8 + local_ac * local_ac + local_a4 * local_a4 != 0.0;
        local_bc = fVar11;
        local_b8 = fVar13;
        local_b4 = fVar10;
        local_28 = fVar11;
        local_24 = fVar13;
        local_20 = fVar10;
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */) + 0x14))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */),&local_bc,0x2006241,local_6c,
                   local_11c);
        iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
        if (iVar5 != 0) {
          iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
          fVar9 = 0.5;
          if (iVar5 != 0) {
            fVar9 = -1.0;
          }
          DebugDrawLine(local_11c,local_110,0xff,0,0,true,fVar9);
        }
        local_78 = 1;
        local_7c = 0;
        fVar9 = *(float *)(unaff_EBX + 0x2575bd /* CSWTCH.200+0xb4 */ /* CSWTCH.200+0xb4 */);
        local_bc = fVar11 * fVar9 + fVar8;
        cVar3 = local_e5;
        if (*(float *)(unaff_EBX + 0x1affc9 /* 1.0f */ /* 1.0f */) <= local_f0) {
          cVar3 = '\x01';
        }
        local_b8 = fVar13 * fVar9 + fVar1;
        local_b4 = fVar9 * fVar10 + fVar12 + 69.0;
        local_ac = local_40 - local_bc;
        local_a8 = local_3c - local_b8;
        local_a4 = local_38 - local_b4;
        *(char *)(in_stack_00000004 + 100) = cVar3;
        local_84 = 0;
        local_88 = 0;
        local_8c = 0;
        local_94 = 0;
        local_98 = 0;
        local_9c = 0;
        local_77 = local_a8 * local_a8 + local_ac * local_ac + local_a4 * local_a4 != 0.0;
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */) + 0x14))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x49dc2d /* &enginetrace */ /* &enginetrace */),&local_bc,0x2006241,local_6c,
                   local_11c);
        iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
        if (iVar5 != 0) {
          iVar5 = (**(code **)(*piVar4 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar4);
          fVar8 = 0.5;
          if (iVar5 != 0) {
            fVar8 = -1.0;
          }
          DebugDrawLine(local_11c,local_110,0xff,0,0,true,fVar8);
        }
        if (*(float *)(unaff_EBX + 0x1affc9 /* 1.0f */ /* 1.0f */) <= local_f0) {
          local_e5 = '\x01';
        }
        *(char *)(in_stack_00000004 + 99) = local_e5;
      }
      local_6c[0] = unaff_EBX + 0x48ba2d /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */;
      local_50 = 0;
      if ((-1 < local_54) && (local_5c != 0)) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dd2d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x49dd2d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_5c);
      }
    }
    else {
      local_6c[0] = unaff_EBX + 0x48ba2d /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */;
      local_50 = 0;
      if ((-1 < local_54) && (local_5c != 0)) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49dd2d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x49dd2d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_5c);
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::~CINSBotAttackFromCover
 * Address: 0070a520
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::~CINSBotAttackFromCover() */

void __thiscall CINSBotAttackFromCover::~CINSBotAttackFromCover(CINSBotAttackFromCover *this)

{
  ~CINSBotAttackFromCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::~CINSBotAttackFromCover
 * Address: 0070a530
 * ---------------------------------------- */

/* CINSBotAttackFromCover::~CINSBotAttackFromCover() */

void __thiscall CINSBotAttackFromCover::~CINSBotAttackFromCover(CINSBotAttackFromCover *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x48aad3 /* vtable for CINSBotAttackFromCover+0x8 */ /* vtable for CINSBotAttackFromCover+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48ac7b /* vtable for CINSBotAttackFromCover+0x1b0 */ /* vtable for CINSBotAttackFromCover+0x1b0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(&UNK_0049cc43 + extraout_ECX));
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::~CINSBotAttackFromCover
 * Address: 0070a560
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackFromCover::~CINSBotAttackFromCover() */

void __thiscall CINSBotAttackFromCover::~CINSBotAttackFromCover(CINSBotAttackFromCover *this)

{
  ~CINSBotAttackFromCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackFromCover::~CINSBotAttackFromCover
 * Address: 0070a570
 * ---------------------------------------- */

/* CINSBotAttackFromCover::~CINSBotAttackFromCover() */

void __thiscall CINSBotAttackFromCover::~CINSBotAttackFromCover(CINSBotAttackFromCover *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48aa8a /* vtable for CINSBotAttackFromCover+0x8 */ /* vtable for CINSBotAttackFromCover+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x48ac32 /* vtable for CINSBotAttackFromCover+0x1b0 */ /* vtable for CINSBotAttackFromCover+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



