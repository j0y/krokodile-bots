/*
 * CINSBotCombat -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 19
 */

/* ----------------------------------------
 * CINSBotCombat::CINSBotCombat
 * Address: 00715390
 * ---------------------------------------- */

/* CINSBotCombat::CINSBotCombat() */

void __thiscall CINSBotCombat::CINSBotCombat(CINSBotCombat *this)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  code *pcVar6;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48104d /* vtable for CINSBotCombat+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4811e5 /* vtable for CINSBotCombat+0x1a0 */;
  piVar1 = in_stack_00000004 + 0x15;
  iVar5 = unaff_EBX + 0x412e1d /* vtable for CountdownTimer+0x8 */;
  in_stack_00000004[10] = 0;
  in_stack_00000004[3] = 0;
  pcVar6 = (code *)(unaff_EBX + -0x4e4c2b /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[4] = 0;
  in_stack_00000004[5] = 0;
  in_stack_00000004[6] = 0;
  in_stack_00000004[7] = 0;
  in_stack_00000004[2] = 0;
  *(undefined1 *)(in_stack_00000004 + 0xc) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x31) = 0;
  in_stack_00000004[0xb] = 0;
  in_stack_00000004[0xd] = 0;
  in_stack_00000004[0x15] = iVar5;
  in_stack_00000004[0x16] = 0;
  (*pcVar6)(piVar1,in_stack_00000004 + 0x16);
  in_stack_00000004[0x17] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x15] + 4))(piVar1,in_stack_00000004 + 0x17);
  piVar2 = in_stack_00000004 + 0x18;
  in_stack_00000004[0x18] = iVar5;
  in_stack_00000004[0x19] = 0;
  (*pcVar6)(piVar2,in_stack_00000004 + 0x19);
  in_stack_00000004[0x1a] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x18] + 4))(piVar2,in_stack_00000004 + 0x1a);
  piVar3 = in_stack_00000004 + 0x1b;
  in_stack_00000004[0x1b] = iVar5;
  in_stack_00000004[0x1c] = 0;
  (*pcVar6)(piVar3,in_stack_00000004 + 0x1c);
  in_stack_00000004[0x1d] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1b] + 4))(piVar3,in_stack_00000004 + 0x1d);
  piVar4 = in_stack_00000004 + 0x1e;
  in_stack_00000004[0x1e] = iVar5;
  in_stack_00000004[0x1f] = 0;
  (*pcVar6)(piVar4,in_stack_00000004 + 0x1f);
  in_stack_00000004[0x20] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1e] + 4))(piVar4,in_stack_00000004 + 0x20);
  in_stack_00000004[0xe] = -1;
  in_stack_00000004[0xf] = 0;
  in_stack_00000004[0x10] = 0;
  in_stack_00000004[0x11] = 0;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x14] = 0;
  if (in_stack_00000004[0x17] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x15] + 4))(piVar1,in_stack_00000004 + 0x17);
    in_stack_00000004[0x17] = -0x40800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x1a] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x18] + 4))(piVar2,in_stack_00000004 + 0x1a);
    in_stack_00000004[0x1a] = -0x40800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x1d] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1b] + 4))(piVar3,in_stack_00000004 + 0x1d);
    in_stack_00000004[0x1d] = -0x40800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x20] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1e] + 4))(piVar4,in_stack_00000004 + 0x20);
    in_stack_00000004[0x20] = -0x40800000 /* -1.0f */;
  }
  *(undefined1 *)(in_stack_00000004 + 0x13) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x4d) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x4e) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotCombat::OnStart
 * Address: 00716200
 * ---------------------------------------- */

/* CINSBotCombat::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall CINSBotCombat::OnStart(CINSBotCombat *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  int iVar2;
  CINSBotCombat *extraout_ECX;
  CINSBotCombat *extraout_ECX_00;
  CINSBotCombat *extraout_ECX_01;
  CINSBotCombat *this_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar3 = (float10)CountdownTimer::Now();
  fVar1 = *(float *)(unaff_EBX + 0x20e551 /* typeinfo name for CBaseGameSystem+0x22 */);
  fVar4 = (float)fVar3 + fVar1;
  this_00 = extraout_ECX;
  if (*(float *)(in_stack_0000000c + 0xb384) != fVar4) {
    (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
              (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb384);
    *(float *)(in_stack_0000000c + 0xb384) = fVar4;
    this_00 = extraout_ECX_00;
  }
  if (*(int *)(in_stack_0000000c + 0xb380) != 0x41f00000 /* 30.0f */) {
    (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
              (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb380);
    *(undefined4 *)(in_stack_0000000c + 0xb380) = 0x41f00000 /* 30.0f */;
    this_00 = extraout_ECX_01;
  }
  fVar4 = *(float *)(**(int **)(unaff_EBX + 0x490695 /* &gpGlobals */) + 0xc);
  *(float *)(param_2 + 0x3c) = fVar4;
  *(float *)(param_2 + 0x40) = fVar1 + fVar4;
  UpdateInternalInfo(this_00);
  iVar2 = CINSNextBot::GetDifficulty(this_01);
  if (iVar2 == 2) {
    *(undefined4 *)(param_2 + 0x50) = 0x40400000 /* 3.0f */;
  }
  else if (iVar2 == 3) {
    *(undefined4 *)(param_2 + 0x50) = 0x40000000 /* 2.0f */;
  }
  else {
    *(undefined4 *)(param_2 + 0x50) = 0x40a00000 /* 5.0f */;
  }
  CINSNextBot::ResetIdleStatus(this_02);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotCombat::Update
 * Address: 00716550
 * ---------------------------------------- */

/* CINSBotCombat::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotCombat::Update(CINSBotCombat *this,CINSNextBot *param_1,float param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  float *pfVar4;
  bool bVar5;
  char cVar6;
  char cVar7;
  int iVar8;
  int *piVar9;
  int *piVar10;
  int *piVar11;
  int iVar12;
  int *piVar13;
  void *pvVar14;
  float fVar15;
  undefined4 *puVar16;
  undefined4 *puVar17;
  CINSGrenadeTarget *pCVar18;
  CBaseEntity *this_00;
  CFmtStrN<256,false> *this_01;
  CBaseEntity *this_02;
  CFmtStrN<256,false> *this_03;
  CINSRules *this_04;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_05;
  CINSBotRetreatToCover *this_06;
  CINSBotRetreatToCover *this_07;
  CINSBotRetreat *this_08;
  CINSPlayer *this_09;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *this_10;
  CINSBotRetreat *this_11;
  CINSBotRetreat *this_12;
  CINSBotReload *this_13;
  CINSBotAttack *this_14;
  CINSBotAttack *this_15;
  CINSBotPursue *this_16;
  CINSBotRetreat *this_17;
  CINSNextBot *this_18;
  CINSRules *this_19;
  CINSNextBot *extraout_ECX_01;
  CINSNextBotManager *this_20;
  CINSNextBot *extraout_ECX_02;
  CINSBotReload *this_21;
  Vector *this_22;
  Vector *extraout_ECX_03;
  Vector *pVVar19;
  CINSBotCombat *extraout_ECX_04;
  CINSBotCombat *this_23;
  CINSBotRetreat *this_24;
  Vector *this_25;
  Vector *extraout_ECX_05;
  Vector *extraout_ECX_06;
  CINSNextBot *extraout_ECX_07;
  CINSNextBot *extraout_ECX_08;
  CINSBotPursue *this_26;
  CINSBotCombat *extraout_ECX_09;
  CINSBotReload *this_27;
  int unaff_EBX;
  float10 fVar20;
  float10 fVar21;
  CINSNextBot *pCVar22;
  CINSNextBot *in_stack_0000000c;
  char local_3b0 [5];
  char local_3ab [263];
  char local_2a4 [5];
  char local_29f [263];
  char local_198 [5];
  char local_193 [263];
  float local_8c;
  float local_88;
  float local_84;
  Vector local_7c [12];
  Vector local_70 [12];
  Vector local_64 [12];
  undefined4 local_58 [3];
  Vector local_4c [12];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  Vector local_34 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x71655b;
  __i686_get_pc_thunk_bx();
  iVar8 = (**(code **)(*(int *)(unaff_EBX + 0x5d5e65 /* ins_bot_debug_combat_decisions */) + 0x40))();
  if (iVar8 != 0) {
    piVar9 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar9 = (int *)(**(code **)(*piVar9 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))();
    if (piVar9 != (int *)0x0) {
      (**(code **)(*piVar9 + 0x10))();
    }
    if (*(int *)((int)param_2 + 0x38) == -1) {
      CFmtStrN<256,false>::CFmtStrN((CFmtStrN<256,false> *)param_2,local_198);
      (**(code **)(**(int **)((int)param_2 + 0x1c) + 0x20c))();
      NDebugOverlay::Text(local_64,local_193,true,0.11);
    }
    else {
      iVar8 = UTIL_PlayerByIndex(*(int *)((int)param_2 + 0x38));
      if (iVar8 == 0) {
        CFmtStrN<256,false>::CFmtStrN(this_01,local_2a4);
        (**(code **)(**(int **)((int)param_2 + 0x1c) + 0x20c))();
        NDebugOverlay::Text(local_70,local_29f,true,0.11);
      }
      else {
        this_02 = (CBaseEntity *)this_01;
        if (*(int *)(iVar8 + 0x20) != 0) {
          this_02 = (CBaseEntity *)**(undefined4 **)(unaff_EBX + 0x490345 /* &gpGlobals */);
        }
        CBaseEntity::GetDebugName(this_02);
        CFmtStrN<256,false>::CFmtStrN(this_03,local_3b0);
        (**(code **)(**(int **)((int)param_2 + 0x1c) + 0x20c))();
        NDebugOverlay::Text(local_7c,local_3ab,true,0.11);
      }
    }
  }
  fVar20 = (float10)CountdownTimer::Now();
  if ((float)fVar20 < *(float *)((int)param_2 + 0x5c) ||
      (float)fVar20 == *(float *)((int)param_2 + 0x5c)) goto LAB_007166b8;
  cVar6 = CINSRules::IsSoloMode();
  if (cVar6 == '\0') {
LAB_007165c2:
    fVar20 = (float10)CountdownTimer::Now();
    pCVar22 = (CINSNextBot *)((float)fVar20 + *(float *)(unaff_EBX + 0x20e689 /* typeinfo name for CBroadcastRecipientFilter+0x28 */));
    if (*(CINSNextBot **)((int)param_2 + 0x5c) != pCVar22) {
      (**(code **)(*(int *)((int)param_2 + 0x54) + 4))();
      *(CINSNextBot **)((int)param_2 + 0x5c) = pCVar22;
      pCVar22 = (CINSNextBot *)param_2;
    }
    if (*(int *)((int)param_2 + 0x58) != 0x3e4ccccd /* 0.2f */) {
      (**(code **)(*(int *)((int)param_2 + 0x54) + 4))();
      *(undefined4 *)((int)param_2 + 0x58) = 0x3e4ccccd /* 0.2f */;
      pCVar22 = (CINSNextBot *)param_2;
    }
  }
  else {
    iVar8 = CBaseEntity::GetTeamNumber(this_00);
    iVar12 = CINSRules::GetHumanTeam(this_04);
    if (iVar8 != iVar12) goto LAB_007165c2;
    fVar20 = (float10)CountdownTimer::Now();
    fVar15 = (float)fVar20 + *(float *)(unaff_EBX + 0x217149 /* typeinfo name for CEntityFactory<CINSRulesProxy>+0x44 */);
    pCVar22 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x5c) != fVar15) {
      (**(code **)(*(int *)((int)param_2 + 0x54) + 4))();
      *(float *)((int)param_2 + 0x5c) = fVar15;
      pCVar22 = (CINSNextBot *)param_2;
    }
    if (*(int *)((int)param_2 + 0x58) != 0x3d4ccccd /* 0.05f */) {
      (**(code **)(*(int *)((int)param_2 + 0x54) + 4))();
      *(undefined4 *)((int)param_2 + 0x58) = 0x3d4ccccd /* 0.05f */;
      pCVar22 = (CINSNextBot *)param_2;
    }
  }
  cVar6 = CINSNextBot::IsEscorting(pCVar22);
  if ((*(int *)((int)param_2 + 0x38) == -1) &&
     (UpdateInternalInfo((CINSBotCombat *)param_2), *(int *)((int)param_2 + 0x38) == -1)) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a475 /* "Combat no longer has a target 
" */;
    return param_1;
  }
  fVar15 = *(float *)(**(int **)(unaff_EBX + 0x490345 /* &gpGlobals */) + 0xc);
  if (*(float *)((int)param_2 + 0x40) <= fVar15 && fVar15 != *(float *)((int)param_2 + 0x40)) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a317 /* "Combat has timed out" */;
    return param_1;
  }
  piVar9 = (int *)UTIL_EntityByIndex(*(int *)((int)param_2 + 0x38));
  if ((piVar9 == (int *)0x0) || (cVar7 = (**(code **)(*piVar9 + 0x118))(), cVar7 == '\0')) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a495 /* "Ending Combat in Update, Unable to retrieve primary target" */;
    return param_1;
  }
  cVar7 = (**(code **)(*piVar9 + 0x158))();
  if (cVar7 == '\0') {
    pvVar14 = ::operator_new(0x48f8);
    CINSBotRetreat::CINSBotRetreat((CINSBotRetreat *)param_2,(int)pvVar14);
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(void **)(param_1 + 4) = pvVar14;
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a4d1 /* "Retreating From Non-Player Target" */;
    return param_1;
  }
  piVar10 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  piVar10 = (int *)(**(code **)(*piVar10 + 0xe4 /* IVision::GetKnown */))();
  if (piVar10 == (int *)0x0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a4f5 /* "Ending Combat in Update , Target ent is not a Known Entity" */;
    return param_1;
  }
  piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
  iVar8 = (**(code **)(*piVar11 + 0xf4 /* IIntention::ShouldPursue */))();
  piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
  iVar12 = (**(code **)(*piVar11 + 0xd4 /* IIntention::ShouldAttack */))();
  if (iVar12 == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x269a24 /* "Should Not Attack This Threat" */;
    return param_1;
  }
  piVar11 = (int *)CINSPlayer::GetActiveINSWeapon();
  if (piVar11 == (int *)0x0) {
    CINSNextBot::ChooseBestWeapon(this_05,(CKnownEntity *)in_stack_0000000c);
LAB_007166b8:
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  fVar20 = (float10)CINSNextBot::GetActiveWeaponAmmoRatio();
  CINSNextBot::GetHidingCover(SUB41(&local_8c,0));
  pfVar4 = *(float **)(unaff_EBX + 0x490071 /* &vec3_origin */);
  bVar5 = true;
  if ((*pfVar4 == local_8c) && (pfVar4[1] == local_88)) {
    bVar5 = pfVar4[2] != local_84;
  }
  piVar13 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
  cVar7 = (**(code **)(*piVar13 + 0x164 /* CINSBotBody::IsMinArousal */))();
  if ((cVar7 != '\0') && (cVar6 == '\0')) {
    if (bVar5) {
      pvVar14 = ::operator_new(100);
      CINSBotRetreatToCover::CINSBotRetreatToCover(this_06,SUB41(pvVar14,0),0.0);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a32c /* "Retreating to Cover BC Scared" */;
      return param_1;
    }
    pvVar14 = ::operator_new(0x48f8);
    CINSBotRetreat::CINSBotRetreat(this_08,SUB41(pvVar14,0),0.0);
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(void **)(param_1 + 4) = pvVar14;
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a531 /* "Retreating without Cover BC Scared" */;
    return param_1;
  }
  if (*(float *)(unaff_EBX + 0x1a25c1 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */) <= (float)fVar20) {
LAB_00716d63:
    cVar7 = (**(code **)(*piVar10 + 0x38))();
    if (cVar7 != '\0') {
      (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))();
      piVar9 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
      (**(code **)(*piVar9 + 0xd8 /* PlayerBody::AimHeadTowards */))();
      pvVar14 = ::operator_new(0x50);
      CINSBotAttack::CINSBotAttack(this_14);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a5f1 /* "Attacking a visible/HasLOS threat" */;
      return param_1;
    }
    if (*(char *)((int)param_2 + 0x4d) != '\0') {
      piVar13 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
      (**(code **)(*piVar13 + 0xd8 /* PlayerBody::AimHeadTowards */))();
    }
    fVar21 = (float10)(**(code **)(*piVar10 + 0x30))();
    if ((((float)fVar21 < *(float *)(unaff_EBX + 0x1a25b9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */)) && (cVar6 == '\0')) && (iVar8 == 1)) {
      piVar9 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
      iVar8 = (**(code **)(*piVar9 + 0xd0 /* IIntention::ShouldRetreat */))();
      if (iVar8 != 1) {
        pvVar14 = ::operator_new(0x5c);
        CINSBotPursue::CINSBotPursue(this_16);
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(void **)(param_1 + 4) = pvVar14;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26a635 /* "Pursuing a new target that I just lost" */;
        return param_1;
      }
      pvVar14 = ::operator_new(0x48f8);
      CINSBotRetreat::CINSBotRetreat(this_24,SUB41(pvVar14,0),0.0);
LAB_0071721a:
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a615 /* "Retreating BC behavior said to" */;
      return param_1;
    }
    pCVar22 = (CINSNextBot *)(**(code **)(*piVar11 + 0x5f0 /* CINSPlayer::RemoveAllItems */))();
    if (((pCVar22 < (CINSNextBot *)0xd) && ((1 << ((byte)pCVar22 & 0x1f) & 0x1600U) != 0)) &&
       (cVar7 = CINSNextBot::ShouldSuppressThreat(pCVar22,(CKnownEntity *)in_stack_0000000c),
       cVar7 != '\0')) {
      puVar16 = (undefined4 *)&stack0xfffffbd4;
      puVar17 = (undefined4 *)(**(code **)(*piVar10 + 0x14))();
      pvVar14 = ::operator_new(0x78);
      for (iVar8 = 3; puVar16 = puVar16 + 1, iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar16 = *puVar17;
        puVar17 = puVar17 + 1;
      }
      CINSBotSuppressTarget::CINSBotSuppressTarget();
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a65d /* "Suppressing a recently lost threat" */;
      return param_1;
    }
    if ((cVar6 == '\0') &&
       (fVar21 = (float10)(**(code **)(*piVar10 + 0x48))(),
       (float)fVar21 < *(float *)(unaff_EBX + 0x1a25b9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */))) {
      piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
      iVar12 = (**(code **)(*piVar11 + 0xd0 /* IIntention::ShouldRetreat */))();
      if (iVar12 == 1) {
        pvVar14 = ::operator_new(0x48f8);
        CINSBotRetreat::CINSBotRetreat(this_17,SUB41(pvVar14,0),0.0);
        goto LAB_0071721a;
      }
    }
    fVar21 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x74) <= (float)fVar21 &&
        (float)fVar21 != *(float *)((int)param_2 + 0x74)) {
      if ((cVar6 == '\0') && (iVar8 == 1)) {
        pvVar14 = ::operator_new(0x5c);
        CINSBotPursue::CINSBotPursue(this_26);
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(void **)(param_1 + 4) = pvVar14;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26a390 /* "Pursuing a Lost Enemy" */;
        return param_1;
      }
    }
    else {
      cVar7 = (**(code **)(*piVar9 + 0x158))();
      this_10 = this_09;
      if (((cVar7 != '\0') &&
          (cVar7 = CINSPlayer::IsSprinting(this_09), this_10 = (CINSPlayer *)extraout_ECX_00,
          cVar7 == '\0')) &&
         ((iVar8 = CINSNextBot::GetDifficulty(in_stack_0000000c), 1 < iVar8 ||
          ((iVar8 = CINSNextBot::GetDifficulty(this_18), this_10 = (CINSPlayer *)extraout_ECX_07,
           iVar8 < 2 &&
           (fVar21 = (float10)(**(code **)(*piVar10 + 0x48))(),
           this_10 = (CINSPlayer *)extraout_ECX_08,
           *(float *)(unaff_EBX + 0x1a2a21 /* typeinfo name for IServerBenchmark+0x13 */) <= (float)fVar21 &&
           (float)fVar21 != *(float *)(unaff_EBX + 0x1a2a21 /* typeinfo name for IServerBenchmark+0x13 */))))))) {
        cVar7 = CINSRules::IsSoloMode();
        if (cVar7 != '\0') {
          iVar8 = CINSRules::GetHumanTeam(this_19);
          iVar12 = CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_0000000c);
          this_10 = (CINSPlayer *)extraout_ECX_01;
          if (iVar8 == iVar12) goto LAB_00716e5d;
        }
        puVar16 = (undefined4 *)(**(code **)(*piVar10 + 0x14))();
        puVar17 = (undefined4 *)::operator_new(0x24);
        uVar1 = *puVar16;
        uVar2 = puVar16[1];
        uVar3 = puVar16[2];
        puVar17[2] = 0;
        puVar17[1] = unaff_EBX + 0x411c5d /* vtable for CountdownTimer+0x8 */;
        CountdownTimer::NetworkStateChanged(puVar17 + 1);
        puVar17[3] = 0xbf800000 /* -1.0f */;
        (**(code **)(puVar17[1] + 4))();
        puVar17[4] = uVar1;
        puVar17[5] = uVar2;
        puVar17[6] = uVar3;
        fVar21 = (float10)CountdownTimer::Now();
        fVar15 = (float)fVar21 + *(float *)(unaff_EBX + 0x20dc55 /* typeinfo name for CTraceFilterNoCombatCharacters+0x30 */);
        if ((float)puVar17[3] != fVar15) {
          (**(code **)(puVar17[1] + 4))();
          puVar17[3] = fVar15;
        }
        if (puVar17[2] != 0x41200000 /* 10.0f */) {
          (**(code **)(puVar17[1] + 4))();
          puVar17[2] = 0x41200000 /* 10.0f */;
        }
        *(undefined1 *)(puVar17 + 7) = 0;
        *(undefined1 *)((int)puVar17 + 0x1d) = 0;
        *puVar17 = 0xd;
        puVar17[8] = 0x42c80000 /* 100.0f */;
        pCVar18 = (CINSGrenadeTarget *)CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_0000000c);
        iVar8 = TheINSNextBots();
        CINSNextBotManager::AddGrenadeTarget(this_20,iVar8,pCVar18);
        this_10 = (CINSPlayer *)extraout_ECX_02;
      }
LAB_00716e5d:
      if ((float)fVar20 < *(float *)(unaff_EBX + 0x21089d /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x78 */)) {
        cVar7 = CINSNextBot::IsInCover((CINSNextBot *)this_10);
        if (cVar7 != '\0') {
          pvVar14 = ::operator_new(0x5c);
          CINSBotReload::CINSBotReload(this_27);
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(void **)(param_1 + 4) = pvVar14;
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x26a37d /* "Reloading In Cover" */;
          return param_1;
        }
        if (cVar6 != '\0') {
          pvVar14 = ::operator_new(0x5c);
          CINSBotReload::CINSBotReload(this_21);
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(void **)(param_1 + 4) = pvVar14;
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x26a681 /* "Reloading in place because of escort/formation" */;
          return param_1;
        }
        pvVar14 = ::operator_new(0x48f8);
        CINSBotRetreat::CINSBotRetreat(this_11,SUB41(pvVar14,0),1.4013e-45);
        goto LAB_00716eb8;
      }
      local_58[0] = 0;
      local_58[1] = 0;
      local_58[2] = 0;
      CINSNextBot::GetAttackCover(SUB41(local_4c,0));
      cVar6 = Vector::operator!=(this_22,local_4c);
      if (cVar6 == '\0') {
        CINSNextBot::GetAttackCover(SUB41(local_34,0));
        cVar6 = Vector::operator!=(this_25,local_34);
        pVVar19 = extraout_ECX_05;
        if (cVar6 != '\0') {
          CINSNextBot::GetAttackCover(SUB41(&local_28,0));
          local_58[0] = local_28;
          local_58[1] = local_24;
          local_58[2] = local_20;
          pVVar19 = extraout_ECX_06;
        }
      }
      else {
        CINSNextBot::GetAttackCover(SUB41(&local_40,0));
        local_58[0] = local_40;
        local_58[1] = local_3c;
        local_58[2] = local_38;
        pVVar19 = extraout_ECX_03;
      }
      cVar6 = Vector::operator!=(pVVar19,(Vector *)local_58);
      this_23 = extraout_ECX_04;
      if (cVar6 != '\0') {
        CountdownTimer::Now();
        puVar16 = (undefined4 *)&stack0xfffffbd4;
        (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))();
        pVVar19 = (Vector *)local_58;
        for (iVar8 = 3; puVar16 = puVar16 + 1, iVar8 != 0; iVar8 = iVar8 + -1) {
          *puVar16 = *(undefined4 *)pVVar19;
          pVVar19 = pVVar19 + 4;
        }
        CINSBotLocomotion::AddMovementRequest();
        this_23 = extraout_ECX_09;
      }
      UpdateInternalInfo(this_23);
    }
    UpdateInternalInfo((CINSBotCombat *)param_2);
    if (*(int *)((int)param_2 + 0x38) == -1) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a3a6 /* "Bailing on Combat, no target" */;
    }
    else {
      CINSNextBot::GetIdleDuration(in_stack_0000000c);
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
    }
  }
  else {
    if ((*(float *)((int)param_2 + 0x48) <= *(float *)(unaff_EBX + 0x20eac1 /* typeinfo name for ITraceFilter+0x2c */) &&
         *(float *)(unaff_EBX + 0x20eac1 /* typeinfo name for ITraceFilter+0x2c */) != *(float *)((int)param_2 + 0x48)) &&
       (*(char *)((int)param_2 + 0x4e) != '\0')) {
      fVar15 = (float)CINSPlayer::GetWeaponInSlot((CINSPlayer *)param_2,(int)in_stack_0000000c,true)
      ;
      CINSNextBot::ChooseBestWeapon(in_stack_0000000c,(CINSWeapon *)in_stack_0000000c,fVar15);
      fVar21 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x68) <= (float)fVar21 &&
          (float)fVar21 != *(float *)((int)param_2 + 0x68)) {
        pvVar14 = ::operator_new(0x50);
        CINSBotAttack::CINSBotAttack(this_15);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(void **)(param_1 + 4) = pvVar14;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26a555 /* "Pistol Swap with primary empty for close target who is firing." */;
        return param_1;
      }
      goto LAB_00716d63;
    }
    if (cVar6 != '\0') {
      pvVar14 = ::operator_new(0x5c);
      CINSBotReload::CINSBotReload(this_13);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a595 /* "Reloading in place because of escorting or formation" */;
      return param_1;
    }
    if (bVar5) {
      pvVar14 = ::operator_new(100);
      CINSBotRetreatToCover::CINSBotRetreatToCover(this_07,SUB41(pvVar14,0),1.4013e-45);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar14;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a34a /* "Retreating to Cover to Reload" */;
      return param_1;
    }
    pvVar14 = ::operator_new(0x48f8);
    CINSBotRetreat::CINSBotRetreat(this_12,SUB41(pvVar14,0),1.4013e-45);
LAB_00716eb8:
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(void **)(param_1 + 4) = pvVar14;
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26a368 /* "Retreating to Reload" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotCombat::OnEnd
 * Address: 007151c0
 * ---------------------------------------- */

/* CINSBotCombat::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotCombat::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (param_2 != (Action *)0x0) {
    cVar1 = (**(code **)(*(int *)param_2 + 0x118 /* CBaseEntity::IsAlive */))(param_2);
    if (cVar1 != '\0') {
      if (*(int *)(param_2 + 0xb384) != -0x40800000 /* -1.0f */) {
        (**(code **)(*(int *)(param_2 + 0xb37c) + 4))(param_2 + 0xb37c,param_2 + 0xb384);
        *(undefined4 *)(param_2 + 0xb384) = 0xbf800000 /* -1.0f */;
      }
      *(undefined4 *)(param_2 + 0xb338) = 0xffffffff;
      *(undefined4 *)(param_2 + 0xb33c) = *(undefined4 *)(**(int **)(unaff_EBX + 0x4916d6 /* &gpGlobals */) + 0xc);
      iVar2 = (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
      if (iVar2 != 0) {
        piVar3 = (int *)(**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
        (**(code **)(*piVar3 + 0x160 /* PlayerBody::ForceLookAtExpire */))(piVar3);
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotCombat::OnResume
 * Address: 00716350
 * ---------------------------------------- */

/* CINSBotCombat::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotCombat::OnResume(CINSBotCombat *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  CINSBotCombat *this_00;
  CINSBotCombat *extraout_ECX;
  CINSBotCombat *extraout_ECX_00;
  CINSBotCombat *this_01;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *this_02;
  CINSNextBot *extraout_ECX_04;
  int extraout_EDX;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(extraout_EDX + 0x38 /* CINSBotCombat::OnResume */) == -1) {
    UpdateInternalInfo(this_00);
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    piVar2 = (int *)UTIL_EntityByIndex(*(int *)(extraout_EDX + 0x38 /* CINSBotCombat::OnResume */));
    this_01 = extraout_ECX;
    if ((piVar2 == (int *)0x0) ||
       (cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2), this_01 = extraout_ECX_00, cVar1 == '\0')) {
      *(undefined4 *)(param_2 + 0x38) = 0xffffffff;
      UpdateInternalInfo(this_01);
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a4ad /* "Our threat is gone" */;
    }
    else {
      piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      piVar2 = (int *)(**(code **)(*piVar3 + 0xe4 /* IVision::GetKnown */))(piVar3,piVar2);
      if (piVar2 == (int *)0x0) {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26a64b /* "Primary target is no longer known" */;
      }
      else {
        piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
        iVar4 = (**(code **)(*piVar3 + 0xd4 /* IIntention::ShouldAttack */))(piVar3,in_stack_0000000c + 0x818,piVar2);
        if (iVar4 == 0) {
          *(undefined4 *)param_1 = 3 /* Done */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x269c1e /* "Should Not Attack This Threat" */;
        }
        else {
          cVar1 = (**(code **)(*piVar2 + 0x3c))(piVar2);
          this_02 = extraout_ECX_01;
          if ((cVar1 != '\0') ||
             (fVar5 = (float10)(**(code **)(*piVar2 + 0x48))(piVar2), this_02 = extraout_ECX_04,
             (float)fVar5 < *(float *)(unaff_EBX + 0x20d733 /* typeinfo name for ISaveRestoreOps+0x6f */))) {
            if (*(int *)(param_2 + 0x68) != -0x40800000 /* -1.0f */) {
              (**(code **)(*(int *)(param_2 + 0x60) + 4))(param_2 + 0x60,param_2 + 0x68);
              *(undefined4 *)(param_2 + 0x68) = 0xbf800000 /* -1.0f */;
              this_02 = extraout_ECX_02;
            }
            if (*(int *)(param_2 + 0x74) != -0x40800000 /* -1.0f */) {
              (**(code **)(*(int *)(param_2 + 0x6c) + 4))(param_2 + 0x6c,param_2 + 0x74);
              *(undefined4 *)(param_2 + 0x74) = 0xbf800000 /* -1.0f */;
              this_02 = extraout_ECX_03;
            }
          }
          CINSNextBot::ResetIdleStatus(this_02);
          *(undefined4 *)param_1 = 0 /* Continue */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined4 *)(param_1 + 8) = 0;
        }
      }
    }
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotCombat::GetName
 * Address: 007178c0
 * ---------------------------------------- */

/* CINSBotCombat::GetName() const */

int CINSBotCombat::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x268efe /* "Combat" */;
}



/* ----------------------------------------
 * CINSBotCombat::ShouldHurry
 * Address: 00715060
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCombat::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotCombat::ShouldHurry(CINSBotCombat *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotCombat::ShouldHurry
 * Address: 00715070
 * ---------------------------------------- */

/* CINSBotCombat::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotCombat::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotCombat::OnStuck
 * Address: 00715080
 * ---------------------------------------- */

/* CINSBotCombat::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotCombat::OnStuck(CINSNextBot *param_1)

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
  iVar1 = *(int *)(unaff_EBX + 0x49192d /* &vtable for CINSBotStuck */);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = unaff_EBX + 0x41312d /* vtable for CountdownTimer+0x8 */;
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x26a9c6 /* "I'm Stuck" */;
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
 * CINSBotCombat::OnSight
 * Address: 00716090
 * ---------------------------------------- */

/* CINSBotCombat::OnSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotCombat::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int iVar1;
  CINSBotCombat *this;
  int unaff_EBX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  this = *(CINSBotCombat **)(in_stack_00000010 + 0x20);
  iVar1 = 0;
  if (this != (CINSBotCombat *)0x0) {
    this = this + -*(int *)(**(int **)(unaff_EBX + 0x490806 /* &gpGlobals */) + 0x5c);
    iVar1 = (int)this >> 4;
  }
  if (*(int *)(param_2 + 0x38) == iVar1) {
    param_2[0x4c] = (CBaseEntity)0x1;
  }
  UpdateInternalInfo(this);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCombat::OnLostSight
 * Address: 00716100
 * ---------------------------------------- */

/* CINSBotCombat::OnLostSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotCombat::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  char cVar1;
  int iVar2;
  CINSNextBot *this;
  CINSNextBot *this_00;
  CINSBotCombat *this_01;
  int iVar3;
  int unaff_EBX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSNextBot::IsEscorting(this);
  this_01 = (CINSBotCombat *)this_00;
  if (cVar1 != '\0') {
    iVar3 = 0;
    if (*(int *)(in_stack_00000010 + 0x20) != 0) {
      iVar3 = *(int *)(in_stack_00000010 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x490792 /* &gpGlobals */) + 0x5c)
              >> 4;
    }
    iVar2 = CINSNextBot::GetEscortTarget(this_00);
    this_01 = *(CINSBotCombat **)(iVar2 + 0x20);
    iVar2 = 0;
    if (this_01 != (CINSBotCombat *)0x0) {
      this_01 = this_01 + -*(int *)(**(int **)(unaff_EBX + 0x490792 /* &gpGlobals */) + 0x5c);
      iVar2 = (int)this_01 >> 4;
    }
    if (iVar3 == iVar2) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26a87e /* "Lost sight of my Escort Target" */;
      *(undefined4 *)(param_1 + 0xc) = 2;
      return param_1;
    }
  }
  iVar3 = 0;
  if (*(int *)(in_stack_00000010 + 0x20) != 0) {
    iVar3 = *(int *)(in_stack_00000010 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x490792 /* &gpGlobals */) + 0x5c)
            >> 4;
  }
  if (*(int *)(param_2 + 0x38) == iVar3) {
    param_2[0x4c] = (CBaseEntity)0x0;
  }
  UpdateInternalInfo(this_01);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCombat::ShouldPursue
 * Address: 00715040
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCombat::ShouldPursue(INextBot const*, CKnownEntity const*) const */

void __thiscall
CINSBotCombat::ShouldPursue(CINSBotCombat *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldPursue(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotCombat::ShouldPursue
 * Address: 00715050
 * ---------------------------------------- */

/* CINSBotCombat::ShouldPursue(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotCombat::ShouldPursue(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotCombat::UpdateInternalInfo
 * Address: 00715600
 * ---------------------------------------- */

/* CINSBotCombat::UpdateInternalInfo() [clone .part.75] */

void CINSBotCombat::UpdateInternalInfo(void)

{
  CBaseEntity *pCVar1;
  int iVar2;
  bool bVar3;
  char cVar4;
  undefined1 uVar5;
  byte bVar6;
  int in_EAX;
  int *piVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  CBaseEntity *this;
  int iVar11;
  int *piVar12;
  undefined4 uVar13;
  CFmtStrN<256,false> *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CFmtStrN<256,false> *this_03;
  CINSPlayer *this_04;
  CFmtStrN<256,false> *this_05;
  CFmtStrN<256,false> *this_06;
  CFmtStrN<256,false> *this_07;
  CFmtStrN<256,false> *this_08;
  int unaff_EBX;
  float10 fVar14;
  float10 fVar15;
  float fVar16;
  CINSWeapon *pCVar17;
  uint uVar18;
  char local_700 [5];
  char local_6fb [263];
  char local_5f4 [5];
  char local_5ef [263];
  char local_4e8 [5];
  char local_4e3 [263];
  char local_3dc [5];
  char local_3d7 [263];
  char local_2d0 [5];
  char local_2cb [263];
  char local_1c4 [5];
  char local_1bf [263];
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  float local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  float local_8c;
  undefined4 local_88;
  undefined4 local_84;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  undefined4 local_4c;
  undefined4 local_48;
  float local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x715610;
  __i686_get_pc_thunk_bx();
  fVar14 = (float10)CountdownTimer::Now();
  fVar16 = (float)fVar14 + *(float *)(unaff_EBX + 0x1a3504 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
  if (*(float *)(in_EAX + 0x80) != fVar16) {
    (**(code **)(*(int *)(in_EAX + 0x78) + 4))(in_EAX + 0x78,in_EAX + 0x80);
    *(float *)(in_EAX + 0x80) = fVar16;
  }
  if (*(int *)(in_EAX + 0x7c) != 0x3f800000 /* 1.0f */) {
    (**(code **)(*(int *)(in_EAX + 0x78) + 4))(in_EAX + 0x78,in_EAX + 0x7c);
    *(undefined4 *)(in_EAX + 0x7c) = 0x3f800000 /* 1.0f */;
  }
  pCVar1 = *(CBaseEntity **)(in_EAX + 0x1c);
  if (pCVar1 == (CBaseEntity *)0x0) {
    return;
  }
  piVar7 = (int *)(**(code **)(*(int *)pCVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar1);
  piVar7 = (int *)(**(code **)(*piVar7 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar7,0);
  if (piVar7 == (int *)0x0) {
    return;
  }
  iVar2 = *(int *)(in_EAX + 0x38);
  piVar8 = (int *)UTIL_EntityByIndex(iVar2);
  if ((piVar8 == (int *)0x0) || (cVar4 = (**(code **)(*piVar8 + 0x118))(piVar8), cVar4 == '\0')) {
    *(undefined4 *)(in_EAX + 0x38) = 0xffffffff;
LAB_007156ff:
    iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */);
    if (iVar9 != 0) {
      CFmtStrN<256,false>::CFmtStrN(this_00,local_1c4,&UNK_0026b1a3 + unaff_EBX);
      (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_34,*(int **)(in_EAX + 0x1c));
      local_20 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_2c;
      local_28 = local_34;
      local_24 = local_30;
      NDebugOverlay::Text((Vector *)&local_28,local_1bf,false,5.0);
    }
    iVar10 = (**(code **)(*piVar7 + 0x10))(piVar7);
    iVar9 = 0;
    if (*(int *)(iVar10 + 0x20) != 0) {
      iVar9 = *(int *)(iVar10 + 0x20) -
              *(int *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0x5c) >> 4;
    }
  }
  else {
    iVar9 = *(int *)(in_EAX + 0x38);
    if (iVar9 == -1) goto LAB_007156ff;
    iVar10 = (**(code **)(*piVar7 + 0x10))(piVar7);
    iVar11 = 0;
    if (*(int *)(iVar10 + 0x20) != 0) {
      iVar11 = *(int *)(iVar10 + 0x20) -
               *(int *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0x5c) >> 4;
    }
    if (iVar9 == iVar11) {
LAB_00715770:
      iVar9 = *(int *)(in_EAX + 0x38);
      goto LAB_00715773;
    }
    iVar9 = *(int *)(pCVar1 + 0xb338);
    iVar10 = (**(code **)(*piVar7 + 0x10))(piVar7);
    iVar11 = 0;
    if (*(int *)(iVar10 + 0x20) != 0) {
      iVar11 = *(int *)(iVar10 + 0x20) -
               *(int *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0x5c) >> 4;
    }
    if (iVar9 == iVar11) {
      iVar9 = (**(code **)(*piVar7 + 0x10))(piVar7);
      iVar10 = 0;
      if (*(int *)(iVar9 + 0x20) != 0) {
        iVar10 = *(int *)(iVar9 + 0x20) -
                 *(int *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0x5c) >> 4;
      }
      *(int *)(in_EAX + 0x38) = iVar10;
      iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */);
      if (iVar9 != 0) {
        CFmtStrN<256,false>::CFmtStrN(this_05,local_2d0,unaff_EBX + 0x26b310 /* "primary target and primary threat match, change our combat primary" */);
        (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_4c,*(int **)(in_EAX + 0x1c));
        local_38 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_44;
        local_40 = local_4c;
        local_3c = local_48;
        NDebugOverlay::Text((Vector *)&local_40,local_2cb,false,5.0);
        iVar9 = *(int *)(in_EAX + 0x38);
        goto LAB_00715773;
      }
      goto LAB_00715770;
    }
    iVar9 = *(int *)(in_EAX + 0x38);
    if (*(int *)(pCVar1 + 0xb338) != iVar9) goto LAB_00715773;
    fVar16 = *(float *)(unaff_EBX + 0x20f15c /* typeinfo name for CBaseGameSystem+0x32 */);
    if (fVar16 < *(float *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0xc) -
                 *(float *)(pCVar1 + 0xb33c)) {
      iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */);
      bVar3 = true;
      if (iVar9 != 0) {
        CFmtStrN<256,false>::CFmtStrN(this_06,local_3dc,unaff_EBX + 0x26b1ba /* "Stale Primary Target" */);
        (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_64,*(int **)(in_EAX + 0x1c));
        local_50 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_5c;
        local_58 = local_64;
        local_54 = local_60;
        NDebugOverlay::Text((Vector *)&local_58,local_3d7,false,fVar16);
      }
    }
    else {
      bVar3 = false;
    }
    if (*(char *)(in_EAX + 0x4d) == '\0') {
      iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */);
      bVar3 = true;
      if (iVar9 != 0) {
        CFmtStrN<256,false>::CFmtStrN(this_07,local_4e8,unaff_EBX + 0x26b1cf /* "Primary Lost LOS" */);
        (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_7c,*(int **)(in_EAX + 0x1c));
        local_68 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_74;
        local_70 = local_7c;
        local_6c = local_78;
        NDebugOverlay::Text((Vector *)&local_70,local_4e3,false,5.0);
      }
    }
    if ((*(char *)(in_EAX + 0x4e) == '\0') &&
       (*(float *)(unaff_EBX + 0x2442a8 /* typeinfo name for CEntityFactory<CGib>+0x1f */) < *(float *)(in_EAX + 0x48))) {
      iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */);
      bVar3 = true;
      if (iVar9 != 0) {
        CFmtStrN<256,false>::CFmtStrN(this_08,local_5f4,unaff_EBX + 0x26b354 /* "Primary is not firing and at Distance" */);
        (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_94,*(int **)(in_EAX + 0x1c));
        local_80 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_8c;
        local_88 = local_94;
        local_84 = local_90;
        NDebugOverlay::Text((Vector *)&local_88,local_5ef,false,5.0);
      }
    }
    piVar12 = (int *)(**(code **)(*piVar7 + 0x10))(piVar7);
    cVar4 = CINSPlayer::IsThreatFiringAtMe(this_01,pCVar1);
    if ((cVar4 == '\0') ||
       ((cVar4 = (**(code **)(*piVar8 + 0x118))(piVar8,piVar12), cVar4 != '\0' &&
        (cVar4 = CINSPlayer::IsThreatFiringAtMe(this_02,pCVar1), piVar12 = piVar8, cVar4 != '\0'))))
    {
      if (!bVar3) goto LAB_00715770;
    }
    else {
      iVar9 = (**(code **)(*(int *)(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */) + 0x40))(unaff_EBX + 0x5d6db0 /* ins_bot_debug_combat_decisions */,piVar12);
      if (iVar9 != 0) {
        CFmtStrN<256,false>::CFmtStrN(this_03,local_700,unaff_EBX + 0x26b1e0 /* "New Primary is greater threat" */);
        (**(code **)(**(int **)(in_EAX + 0x1c) + 0x20c))(&local_ac,*(int **)(in_EAX + 0x1c));
        local_98 = *(float *)(unaff_EBX + 0x212d24 /* typeinfo name for IPartitionEnumerator+0x21 */) + local_a4;
        local_a0 = local_ac;
        local_9c = local_a8;
        NDebugOverlay::Text((Vector *)&local_a0,local_6fb,false,5.0);
      }
    }
    iVar10 = (**(code **)(*piVar7 + 0x10))(piVar7);
    iVar9 = 0;
    if (*(int *)(iVar10 + 0x20) != 0) {
      iVar9 = *(int *)(iVar10 + 0x20) -
              *(int *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0x5c) >> 4;
    }
  }
  *(int *)(in_EAX + 0x38) = iVar9;
LAB_00715773:
  this = (CBaseEntity *)UTIL_EntityByIndex(iVar9);
  piVar7 = (int *)(**(code **)(*(int *)pCVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar1);
  piVar7 = (int *)(**(code **)(*piVar7 + 0xe4 /* IVision::GetKnown */))(piVar7,this);
  if ((piVar7 == (int *)0x0) || (this == (CBaseEntity *)0x0)) {
    *(undefined4 *)(in_EAX + 0x48) = 0xbf800000 /* -1.0f */;
    *(undefined1 *)(in_EAX + 0x4d) = 0;
    *(undefined4 *)(in_EAX + 0x38) = 0xffffffff;
  }
  else {
    *(undefined4 *)(pCVar1 + 0xb338) = *(undefined4 *)(in_EAX + 0x38);
    *(undefined4 *)(pCVar1 + 0xb33c) =
         *(undefined4 *)(**(int **)(GlobalEntity_GetName + unaff_EBX) + 0xc);
    if (((byte)this[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    local_b8 = *(undefined4 *)(this + 0x208);
    local_b4 = *(undefined4 *)(this + 0x20c);
    local_b0 = *(undefined4 *)(this + 0x210);
    cVar4 = (**(code **)(*(int *)(pCVar1 + 0x2060) + 0x124))(pCVar1 + 0x2060,&local_b8,0x459c4000 /* 5000.0f */);
    if (cVar4 == '\0') {
      fVar14 = (float10)(**(code **)(*(int *)(pCVar1 + 0x2060) + 0x134))(pCVar1 + 0x2060,&local_b8);
      *(float *)(in_EAX + 0x48) = (float)fVar14;
    }
    else {
      fVar14 = (float10)CINSNextBot::GetTravelDistance(pCVar1,local_b8,local_b4,local_b0,0x469c4000 /* 20000.0f */)
      ;
      *(float *)(in_EAX + 0x48) = (float)fVar14;
    }
    piVar8 = (int *)(**(code **)(*(int *)pCVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar1);
    uVar5 = (**(code **)(*piVar8 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar8,this,1,0);
    *(undefined1 *)(in_EAX + 0x4d) = uVar5;
    uVar5 = (**(code **)(*piVar7 + 0x38))(piVar7);
    *(undefined1 *)(in_EAX + 0x4c) = uVar5;
    uVar5 = CINSPlayer::IsThreatFiringAtMe(this_04,pCVar1);
    *(undefined1 *)(in_EAX + 0x4e) = uVar5;
    bVar6 = (**(code **)(*piVar7 + 0x38))(piVar7,this);
    uVar13 = CINSPlayer::GetActiveINSWeapon();
    uVar18 = (uint)bVar6;
    pCVar17 = *(CINSWeapon **)(in_EAX + 0x48);
    fVar14 = (float10)CINSNextBot::GetAttackDelay((float)pCVar1,pCVar17,SUB41(uVar13,0));
    fVar15 = (float10)(**(code **)(*piVar7 + 0x40))(piVar7,pCVar17,uVar13,uVar18);
    if ((float)fVar15 < (float)fVar14) {
      fVar15 = (float10)(**(code **)(*piVar7 + 0x40))(piVar7);
      fVar16 = (float)fVar14 - (float)fVar15;
      fVar14 = (float10)CountdownTimer::Now();
      if (*(float *)(in_EAX + 0x68) != (float)fVar14 + fVar16) {
        (**(code **)(*(int *)(in_EAX + 0x60) + 4))(in_EAX + 0x60,in_EAX + 0x68);
        *(float *)(in_EAX + 0x68) = (float)fVar14 + fVar16;
      }
      if (*(float *)(in_EAX + 100) != fVar16) {
        (**(code **)(*(int *)(in_EAX + 0x60) + 4))(in_EAX + 0x60,in_EAX + 100);
        *(float *)(in_EAX + 100) = fVar16;
      }
    }
    if ((*(char *)(in_EAX + 0x4d) == '\0') && (iVar2 != *(int *)(in_EAX + 0x38))) {
      fVar16 = *(float *)(in_EAX + 0x50);
      fVar14 = (float10)CountdownTimer::Now();
      if (*(float *)(in_EAX + 0x74) != (float)fVar14 + fVar16) {
        (**(code **)(*(int *)(in_EAX + 0x6c) + 4))(in_EAX + 0x6c,in_EAX + 0x74);
        *(float *)(in_EAX + 0x74) = (float)fVar14 + fVar16;
      }
      if (*(float *)(in_EAX + 0x70) != fVar16) {
        (**(code **)(*(int *)(in_EAX + 0x6c) + 4))(in_EAX + 0x6c,in_EAX + 0x70);
        *(float *)(in_EAX + 0x70) = fVar16;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotCombat::UpdateInternalInfo
 * Address: 00716040
 * ---------------------------------------- */

/* CINSBotCombat::UpdateInternalInfo() */

void __thiscall CINSBotCombat::UpdateInternalInfo(CINSBotCombat *this)

{
  float10 fVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)CountdownTimer::Now();
  if ((float)fVar1 < *(float *)(in_stack_00000004 + 0x80) ||
      (float)fVar1 == *(float *)(in_stack_00000004 + 0x80)) {
    return;
  }
  UpdateInternalInfo();
  return;
}



/* ----------------------------------------
 * CINSBotCombat::~CINSBotCombat
 * Address: 007178e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCombat::~CINSBotCombat() */

void __thiscall CINSBotCombat::~CINSBotCombat(CINSBotCombat *this)

{
  ~CINSBotCombat(this);
  return;
}



/* ----------------------------------------
 * CINSBotCombat::~CINSBotCombat
 * Address: 007178f0
 * ---------------------------------------- */

/* CINSBotCombat::~CINSBotCombat() */

void __thiscall CINSBotCombat::~CINSBotCombat(CINSBotCombat *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x47eaf3 /* vtable for CINSBotCombat+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x47ec8b /* vtable for CINSBotCombat+0x1a0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x48f883 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotCombat::~CINSBotCombat
 * Address: 00717920
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCombat::~CINSBotCombat() */

void __thiscall CINSBotCombat::~CINSBotCombat(CINSBotCombat *this)

{
  ~CINSBotCombat(this);
  return;
}



/* ----------------------------------------
 * CINSBotCombat::~CINSBotCombat
 * Address: 00717930
 * ---------------------------------------- */

/* CINSBotCombat::~CINSBotCombat() */

void __thiscall CINSBotCombat::~CINSBotCombat(CINSBotCombat *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47eaaa /* vtable for CINSBotCombat+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_0047ec42 + unaff_EBX);
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



