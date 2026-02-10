/*
 * CINSBotAttackLMG -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackLMG::CINSBotAttackLMG
 * Address: 0070e1f0
 * ---------------------------------------- */

/* CINSBotAttackLMG::CINSBotAttackLMG() */

void __thiscall CINSBotAttackLMG::CINSBotAttackLMG(CINSBotAttackLMG *this)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = &UNK_0048742d + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x4875d5 /* vtable for CINSBotAttackLMG+0x1b0 */;
  puVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[0xe] = &UNK_00419fbd + unaff_EBX;
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
  (*(code *)(unaff_EBX + -0x4dda8b /* CountdownTimer::NetworkStateChanged */))(puVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = 0xbf800000;
  (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
  puVar2 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = &UNK_00419fbd + unaff_EBX;
  (*(code *)(unaff_EBX + -0x4dda8b /* CountdownTimer::NetworkStateChanged */))(puVar2,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = 0xbf800000;
  (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
  if (in_stack_00000004[0x10] != -0x40800000) {
    (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = 0xbf800000;
  }
  if (in_stack_00000004[0x13] != -0x40800000) {
    (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
    in_stack_00000004[0x13] = 0xbf800000;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnStart
 * Address: 0070d9c0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackLMG::OnStart(CINSBotAttackLMG *this,CINSNextBot *param_1,Action *param_2)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  float fVar4;
  int *piVar5;
  int *piVar6;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_02;
  CINSNextBot *extraout_ECX_01;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  float10 fVar7;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar8;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c == (CINSWeapon *)0x0) goto LAB_0070dac0;
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_00 = extraout_ECX,
     iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) ||
       (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), this_00 = extraout_ECX_01, iVar3 == 0)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
  }
  fVar4 = *(float *)(in_stack_0000000c + 0xb340);
  fVar7 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
  if ((float)fVar7 <= fVar4) {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
    goto LAB_0070dac0;
  }
  cVar2 = CINSNextBot::IsSuppressed(this_01);
  if (cVar2 == '\0') {
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (fVar4 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
       this_02 = extraout_ECX_00, fVar4 == 0.0)) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
      piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
      fVar4 = 0.0;
      this_02 = extraout_ECX_02;
      if (piVar5 != (int *)0x0) {
        fVar4 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
        this_02 = extraout_ECX_03;
      }
    }
    uVar8 = 0x3f4ccccd;
    cVar2 = CINSPlayer::IsThreatAimingTowardMe(this_02,(CBaseEntity *)in_stack_0000000c,fVar4);
    if (cVar2 != '\0') {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
      pcVar1 = *(code **)(*piVar5 + 0x104);
      if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
         (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), iVar3 == 0)) {
        piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
        piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0,uVar8);
        iVar3 = 0;
        if (piVar6 != (int *)0x0) {
          iVar3 = (**(code **)(*piVar6 + 0x10))(piVar6);
        }
      }
      cVar2 = (*pcVar1)(piVar5,iVar3,0,0);
      if (cVar2 != '\0') {
        (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
        goto LAB_0070db81;
      }
    }
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
LAB_0070db81:
    CINSBotBody::SetPosture();
  }
LAB_0070dac0:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackLMG::InitialContainedAction
 * Address: 0070d800
 * ---------------------------------------- */

/* CINSBotAttackLMG::InitialContainedAction(CINSNextBot*) */

void * __thiscall
CINSBotAttackLMG::InitialContainedAction(CINSBotAttackLMG *this,CINSNextBot *param_1)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  void *pvVar4;
  int *piVar5;
  CINSNextBot *this_00;
  CINSBotAttackAdvance *this_01;
  CINSBotAttackInPlace *this_02;
  CINSBotAttackInPlace *this_03;
  int unaff_EBX;
  float10 fVar6;
  CINSWeapon *in_stack_00000008;
  float local_1c;
  float local_18;
  float local_14;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (CINSWeapon *)0x0) {
    return (void *)0x0;
  }
  if ((*(int *)(in_stack_00000008 + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_00000008 + 0xb338)), iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) || (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), iVar3 == 0)) {
      pvVar4 = ::operator_new(0x50);
      CINSBotAttackInPlace::CINSBotAttackInPlace(this_02);
      return pvVar4;
    }
  }
  CINSNextBot::GetAttackCover(true);
  pfVar2 = *(float **)(unaff_EBX + 0x498dc2 /* &vec3_origin */);
  if (((*pfVar2 == local_1c) && (pfVar2[1] == local_18)) && (pfVar2[2] == local_14)) {
    fVar1 = *(float *)(in_stack_00000008 + 0xb340);
    fVar6 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_00000008);
    if (fVar1 <= (float)fVar6) {
      pvVar4 = ::operator_new(0x50);
      CINSBotAttackInPlace::CINSBotAttackInPlace(this_03);
      return pvVar4;
    }
    pvVar4 = ::operator_new(0x5c);
    CINSBotAttackAdvance::CINSBotAttackAdvance(this_01);
    return pvVar4;
  }
  pvVar4 = ::operator_new(0x54);
  CINSBotAttackIntoCover::CINSBotAttackIntoCover();
  return pvVar4;
}



/* ----------------------------------------
 * CINSBotAttackLMG::Update
 * Address: 0070dca0
 * ---------------------------------------- */

/* CINSBotAttackLMG::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackLMG::Update(CINSBotAttackLMG *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  CINSNextBot *pCVar4;
  int *piVar5;
  uint uVar6;
  int *piVar7;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *this_01;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar8;
  float fVar9;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  
  __i686_get_pc_thunk_bx();
  fVar8 = (float10)CountdownTimer::Now();
  if ((float)fVar8 < *(float *)((int)param_2 + 0x4c) ||
      (float)fVar8 == *(float *)((int)param_2 + 0x4c)) goto LAB_0070dcdc;
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), pCVar4 = extraout_ECX,
     iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) ||
       (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), pCVar4 = extraout_ECX_00, iVar3 == 0)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
  }
  fVar9 = *(float *)(in_stack_0000000c + 0xb340);
  uVar10 = 0;
  fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(pCVar4,in_stack_0000000c);
  if (fVar9 < (float)fVar8) {
    cVar2 = CINSNextBot::IsSuppressed(this_00);
    if (cVar2 == '\0') {
      if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
         (fVar9 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
         this_01 = extraout_ECX_01, fVar9 == 0.0)) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c,uVar10);
        piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
        fVar9 = 0.0;
        this_01 = extraout_ECX_02;
        if (piVar5 != (int *)0x0) {
          fVar9 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
          this_01 = extraout_ECX_03;
        }
      }
      uVar10 = 0x3f4ccccd;
      cVar2 = CINSPlayer::IsThreatAimingTowardMe(this_01,(CBaseEntity *)in_stack_0000000c,fVar9);
      if (cVar2 != '\0') {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))
                                  (in_stack_0000000c,fVar9,uVar10);
        pcVar1 = *(code **)(*piVar5 + 0x104);
        if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
           (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), iVar3 == 0)) {
          piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          piVar7 = (int *)(**(code **)(*piVar7 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar7,0);
          iVar3 = 0;
          if (piVar7 != (int *)0x0) {
            iVar3 = (**(code **)(*piVar7 + 0x10))(piVar7);
          }
        }
        cVar2 = (*pcVar1)(piVar5,iVar3,0,0);
        if (cVar2 != '\0') {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          iVar3 = unaff_EBX + 0x2727e6 /* "CProne from aiming threat" */;
          goto LAB_0070ded6;
        }
      }
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar12 = 0x3f0ccccd;
      uVar11 = 7;
      iVar3 = unaff_EBX + 0x2727d1 /* "Crouch for stability" */;
      uVar10 = 3;
      CINSBotBody::SetPosture();
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      iVar3 = unaff_EBX + 0x2727ba /* "Prone From Suppression" */;
LAB_0070ded6:
      uVar12 = 0x3f0ccccd;
      uVar11 = 7;
      uVar10 = 1;
      CINSBotBody::SetPosture();
    }
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    uVar12 = 0x3f0ccccd;
    uVar11 = 7;
    iVar3 = unaff_EBX + 0x272410 /* "Walking At Target" */;
    uVar10 = 0xc;
    CINSBotBody::SetPosture();
  }
  pCVar4 = (CINSNextBot *)CINSPlayer::GetActiveINSWeapon();
  if (pCVar4 != (CINSNextBot *)0x0) {
    uVar10 = 0;
    cVar2 = CINSWeapon::CanBipod((Vector *)pCVar4);
    if (cVar2 != '\0') {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))
                                (in_stack_0000000c,uVar10,uVar11,uVar12,iVar3);
      uVar10 = 1;
      cVar2 = (**(code **)(*piVar5 + 0x124 /* CINSBotBody::IsActualPosture */))(piVar5,1);
      if (cVar2 == '\0') {
LAB_0070dde8:
        uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4);
        if ((uVar6 & 2) == 0) goto LAB_0070de08;
      }
      else {
        fVar9 = *(float *)(in_stack_0000000c + 0xb340);
        uVar10 = 0;
        fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(pCVar4,in_stack_0000000c);
        if (((fVar9 <= (float)fVar8 * *(float *)(unaff_EBX + 0x215de2 /* typeinfo name for ISaveRestoreOps+0x6b */)) ||
            (uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4), (uVar6 & 2) == 0)) ||
           (cVar2 = CINSWeapon::InBipodTransition(), cVar2 != '\0')) goto LAB_0070dde8;
      }
      uVar10 = 0;
      CINSWeapon::ToggleBipod((CINSWeapon *)pCVar4,SUB41(pCVar4,0));
    }
  }
LAB_0070de08:
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c,uVar10);
  iVar3 = (**(code **)(*piVar5 + 0xec /* IIntention::ShouldIronsight */))(piVar5,in_stack_0000000c + 0x2060);
  if (iVar3 != 0) {
    (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3f0ccccd);
  }
  fVar8 = (float10)CountdownTimer::Now();
  fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x216aaa /* typeinfo name for CBaseGameSystem+0x1e */);
  if (*(float *)((int)param_2 + 0x4c) != fVar9) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c);
    *(float *)((int)param_2 + 0x4c) = fVar9;
  }
  if (*(int *)((int)param_2 + 0x48) != 0x3f000000) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48);
    *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000;
  }
LAB_0070dcdc:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnEnd
 * Address: 0070d170
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackLMG::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::GetName
 * Address: 0070e360
 * ---------------------------------------- */

/* CINSBotAttackLMG::GetName() const */

int CINSBotAttackLMG::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2720f2 /* "CINSBotAttackLMG" */;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldHurry
 * Address: 0070d180
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackLMG::ShouldHurry(CINSBotAttackLMG *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldHurry
 * Address: 0070d190
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackLMG::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldRetreat
 * Address: 0070d1a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackLMG::ShouldRetreat(CINSBotAttackLMG *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldRetreat
 * Address: 0070d1b0
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackLMG::ShouldRetreat(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldAttack
 * Address: 0070d1c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotAttackLMG::ShouldAttack(CINSBotAttackLMG *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldAttack
 * Address: 0070d1d0
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackLMG::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnContact
 * Address: 0070d220
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackLMG::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnMoveToSuccess
 * Address: 0070d250
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackLMG::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnMoveToFailure
 * Address: 0070d280
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackLMG::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnStuck
 * Address: 0070d2b0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnStuck(CINSNextBot*) */

void CINSBotAttackLMG::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnUnStuck
 * Address: 0070d2e0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnUnStuck(CINSNextBot*) */

void CINSBotAttackLMG::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnInjured
 * Address: 0070d340
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackLMG::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnKilled
 * Address: 0070d370
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackLMG::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnOtherKilled
 * Address: 0070d3a0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotAttackLMG::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnSight
 * Address: 0070d3d0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackLMG::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnLostSight
 * Address: 0070d400
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackLMG::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnWeaponFired
 * Address: 0070d430
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackLMG::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnCommandApproach
 * Address: 0070d4c0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackLMG::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnCommandApproach
 * Address: 0070d4f0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackLMG::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnCommandString
 * Address: 0070d550
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackLMG::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnBlinded
 * Address: 0070d580
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackLMG::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnCommandAttack
 * Address: 0070d490
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackLMG::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnCommandRetreat
 * Address: 0070d520
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackLMG::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnHeardFootsteps
 * Address: 0070d5b0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackLMG::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnNavAreaChanged
 * Address: 0070d460
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackLMG::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnPostureChanged
 * Address: 0070d310
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackLMG::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::OnSeeSomethingSuspicious
 * Address: 0070d5e0
 * ---------------------------------------- */

/* CINSBotAttackLMG::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackLMG::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldIronsight
 * Address: 0070d6b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackLMG::ShouldIronsight(CINSBotAttackLMG *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldIronsight
 * Address: 0070d6c0
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldIronsight(INextBot const*) const */

int __cdecl CINSBotAttackLMG::ShouldIronsight(INextBot *param_1)

{
  float fVar1;
  CINSWeapon *pCVar2;
  char cVar3;
  int iVar4;
  float fVar5;
  int *piVar6;
  CINSPlayer *this;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSPlayer *this_02;
  CINSNextBot *extraout_ECX_00;
  int iVar7;
  float10 fVar8;
  
  iVar4 = __i686_get_pc_thunk_bx();
  iVar7 = 2;
  pCVar2 = *(CINSWeapon **)(iVar4 + 0x1c);
  if (pCVar2 != (CINSWeapon *)0x0) {
    iVar7 = 0;
    cVar3 = CINSPlayer::IsSprinting(this);
    if (cVar3 == '\0') {
      if ((*(int *)(pCVar2 + 0xb338) == -1) ||
         (fVar5 = (float)UTIL_EntityByIndex(*(int *)(pCVar2 + 0xb338)), this_00 = extraout_ECX,
         fVar5 == 0.0)) {
        piVar6 = (int *)(**(code **)(*(int *)pCVar2 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar2);
        piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
        if (piVar6 == (int *)0x0) {
          return 0;
        }
        fVar5 = (float)(**(code **)(*piVar6 + 0x10))(piVar6);
        this_00 = extraout_ECX_00;
        if (fVar5 == 0.0) {
          return 0;
        }
      }
      iVar7 = 1;
      fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,pCVar2);
      fVar1 = *(float *)(pCVar2 + 0xb340);
      if ((float)fVar8 <= fVar1) {
        iVar7 = 2;
        fVar8 = (float10)CINSNextBot::GetMaxAttackRange(this_01,pCVar2);
        if (fVar1 < (float)fVar8) {
          cVar3 = CINSPlayer::IsThreatAimingTowardMe(this_02,(CBaseEntity *)pCVar2,fVar5);
          iVar7 = ~-(uint)(cVar3 == '\0') + 2;
        }
      }
    }
  }
  return iVar7;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldProne
 * Address: 0070d200
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackLMG::ShouldProne(CINSBotAttackLMG *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldProne
 * Address: 0070d210
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackLMG::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldWalk
 * Address: 0070d1e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackLMG::ShouldWalk(CINSBotAttackLMG *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::ShouldWalk
 * Address: 0070d1f0
 * ---------------------------------------- */

/* CINSBotAttackLMG::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackLMG::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackLMG::~CINSBotAttackLMG
 * Address: 0070e380
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::~CINSBotAttackLMG() */

void __thiscall CINSBotAttackLMG::~CINSBotAttackLMG(CINSBotAttackLMG *this)

{
  ~CINSBotAttackLMG(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::~CINSBotAttackLMG
 * Address: 0070e390
 * ---------------------------------------- */

/* CINSBotAttackLMG::~CINSBotAttackLMG() */

void __thiscall CINSBotAttackLMG::~CINSBotAttackLMG(CINSBotAttackLMG *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x487293 /* vtable for CINSBotAttackLMG+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48743b /* vtable for CINSBotAttackLMG+0x1b0 */;
  Action<CINSNextBot>::~Action
            ((Action<CINSNextBot> *)(CHLTVDirector::~CHLTVDirector + extraout_ECX + 3));
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::~CINSBotAttackLMG
 * Address: 0070e3c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackLMG::~CINSBotAttackLMG() */

void __thiscall CINSBotAttackLMG::~CINSBotAttackLMG(CINSBotAttackLMG *this)

{
  ~CINSBotAttackLMG(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackLMG::~CINSBotAttackLMG
 * Address: 0070e3d0
 * ---------------------------------------- */

/* CINSBotAttackLMG::~CINSBotAttackLMG() */

void __thiscall CINSBotAttackLMG::~CINSBotAttackLMG(CINSBotAttackLMG *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48724a /* vtable for CINSBotAttackLMG+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4873f2 /* vtable for CINSBotAttackLMG+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



