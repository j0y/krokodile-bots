/*
 * CINSBotAttackRifle -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackRifle::CINSBotAttackRifle
 * Address: 00711680
 * ---------------------------------------- */

/* CINSBotAttackRifle::CINSBotAttackRifle() */

void __thiscall CINSBotAttackRifle::CINSBotAttackRifle(CINSBotAttackRifle *this)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = &UNK_0048459d + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x484745 /* vtable for CINSBotAttackRifle+0x1b0 */ /* vtable for CINSBotAttackRifle+0x1b0 */;
  puVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[0xe] = &UNK_00416b2d + unaff_EBX;
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
  (*(code *)(unaff_EBX + -0x4e0f1b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(puVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
  puVar2 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = &UNK_00416b2d + unaff_EBX;
  (*(code *)(unaff_EBX + -0x4e0f1b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(puVar2,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
  if (in_stack_00000004[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = 0xbf800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x13] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
    in_stack_00000004[0x13] = 0xbf800000 /* -1.0f */;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnStart
 * Address: 00710e60
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackRifle::OnStart(CINSBotAttackRifle *this,CINSNextBot *param_1,Action *param_2)

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
  if (in_stack_0000000c == (CINSWeapon *)0x0) {
LAB_00710fea:
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_00 = extraout_ECX,
     iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) ||
       (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), this_00 = extraout_ECX_01, iVar3 == 0))
    goto LAB_00710fea;
  }
  fVar4 = *(float *)(in_stack_0000000c + 0xb340);
  fVar7 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
  if ((float)fVar7 <= fVar4) {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
    goto LAB_00710f07;
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
    uVar8 = 0x3f4ccccd /* 0.8f */;
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
        goto LAB_00711019;
      }
    }
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
LAB_00711019:
    CINSBotBody::SetPosture();
  }
LAB_00710f07:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackRifle::InitialContainedAction
 * Address: 00710ca0
 * ---------------------------------------- */

/* CINSBotAttackRifle::InitialContainedAction(CINSNextBot*) */

void * __thiscall
CINSBotAttackRifle::InitialContainedAction(CINSBotAttackRifle *this,CINSNextBot *param_1)

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
  pfVar2 = *(float **)(unaff_EBX + 0x495922 /* &vec3_origin */ /* &vec3_origin */);
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
 * CINSBotAttackRifle::Update
 * Address: 00711130
 * ---------------------------------------- */

/* CINSBotAttackRifle::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackRifle::Update(CINSBotAttackRifle *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  CINSNextBot *pCVar4;
  int *piVar5;
  uint uVar6;
  float fVar7;
  int *piVar8;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *this_01;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar9;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  
  __i686_get_pc_thunk_bx();
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < *(float *)((int)param_2 + 0x4c) ||
      (float)fVar9 == *(float *)((int)param_2 + 0x4c)) goto LAB_0071116c;
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), pCVar4 = extraout_ECX,
     iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if ((piVar5 == (int *)0x0) ||
       (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), pCVar4 = extraout_ECX_00, iVar3 == 0)) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
  }
  fVar7 = *(float *)(in_stack_0000000c + 0xb340);
  uVar10 = 0;
  fVar9 = (float10)CINSNextBot::GetDesiredAttackRange(pCVar4,in_stack_0000000c);
  if (fVar7 < (float)fVar9) {
    cVar2 = CINSNextBot::IsSuppressed(this_00);
    if (cVar2 == '\0') {
      if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
         (fVar7 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
         this_01 = extraout_ECX_01, fVar7 == 0.0)) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c,uVar10);
        piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
        fVar7 = 0.0;
        this_01 = extraout_ECX_02;
        if (piVar5 != (int *)0x0) {
          fVar7 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
          this_01 = extraout_ECX_03;
        }
      }
      uVar10 = 0x3f4ccccd /* 0.8f */;
      cVar2 = CINSPlayer::IsThreatAimingTowardMe(this_01,(CBaseEntity *)in_stack_0000000c,fVar7);
      if (cVar2 != '\0') {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))
                                  (in_stack_0000000c,fVar7,uVar10);
        pcVar1 = *(code **)(*piVar5 + 0x104);
        if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
           (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), iVar3 == 0)) {
          piVar8 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          piVar8 = (int *)(**(code **)(*piVar8 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar8,0);
          iVar3 = 0;
          if (piVar8 != (int *)0x0) {
            iVar3 = (**(code **)(*piVar8 + 0x10))(piVar8);
          }
        }
        cVar2 = (*pcVar1)(piVar5,iVar3,0,0);
        if (cVar2 != '\0') {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          iVar3 = unaff_EBX + 0x26f356 /* "CProne from aiming threat" */ /* "CProne from aiming threat" */;
          goto LAB_00711366;
        }
      }
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar12 = 0x3f0ccccd /* 0.55f */;
      uVar11 = 7;
      iVar3 = unaff_EBX + 0x26f341 /* "Crouch for stability" */ /* "Crouch for stability" */;
      uVar10 = 3;
      CINSBotBody::SetPosture();
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      iVar3 = unaff_EBX + 0x26f32a /* "Prone From Suppression" */ /* "Prone From Suppression" */;
LAB_00711366:
      uVar12 = 0x3f0ccccd /* 0.55f */;
      uVar11 = 7;
      uVar10 = 1;
      CINSBotBody::SetPosture();
    }
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    uVar12 = 0x3f0ccccd /* 0.55f */;
    uVar11 = 7;
    iVar3 = unaff_EBX + 0x26ef80 /* "Walking At Target" */ /* "Walking At Target" */;
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
LAB_00711278:
        uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4);
        if ((uVar6 & 2) == 0) goto LAB_00711298;
      }
      else {
        fVar7 = *(float *)(in_stack_0000000c + 0xb340);
        uVar10 = 0;
        fVar9 = (float10)CINSNextBot::GetDesiredAttackRange(pCVar4,in_stack_0000000c);
        if (((fVar7 <= (float)fVar9 * *(float *)(unaff_EBX + 0x212952 /* 0.75f */ /* 0.75f */)) ||
            (uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4), (uVar6 & 2) == 0)) ||
           (cVar2 = CINSWeapon::InBipodTransition(), cVar2 != '\0')) goto LAB_00711278;
      }
      uVar10 = 0;
      CINSWeapon::ToggleBipod((CINSWeapon *)pCVar4,SUB41(pCVar4,0));
    }
  }
LAB_00711298:
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c,uVar10);
  iVar3 = (**(code **)(*piVar5 + 0xec /* IIntention::ShouldIronsight */))(piVar5,in_stack_0000000c + 0x2060);
  if (iVar3 != 0) {
    (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3f0ccccd /* 0.55f */);
  }
  fVar9 = (float10)CountdownTimer::Now();
  fVar7 = *(float *)(&DAT_0021361a + unaff_EBX);
  if (*(float *)((int)param_2 + 0x4c) != (float)fVar9 + fVar7) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c);
    *(float *)((int)param_2 + 0x4c) = (float)fVar9 + fVar7;
  }
  if (*(int *)((int)param_2 + 0x48) != 0x3f000000 /* 0.5f */) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48);
    *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000 /* 0.5f */;
  }
LAB_0071116c:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnEnd
 * Address: 00710610
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackRifle::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::GetName
 * Address: 007117f0
 * ---------------------------------------- */

/* CINSBotAttackRifle::GetName() const */

int CINSBotAttackRifle::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x26ed56 /* "CINSBotAttackRifle" */ /* "CINSBotAttackRifle" */;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldHurry
 * Address: 00710620
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackRifle::ShouldHurry(CINSBotAttackRifle *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldHurry
 * Address: 00710630
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackRifle::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldRetreat
 * Address: 00710640
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackRifle::ShouldRetreat(CINSBotAttackRifle *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldRetreat
 * Address: 00710650
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackRifle::ShouldRetreat(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldAttack
 * Address: 00710660
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotAttackRifle::ShouldAttack(CINSBotAttackRifle *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldAttack
 * Address: 00710670
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackRifle::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnContact
 * Address: 007106c0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackRifle::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnMoveToSuccess
 * Address: 007106f0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackRifle::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnMoveToFailure
 * Address: 00710720
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackRifle::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnStuck
 * Address: 00710750
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnStuck(CINSNextBot*) */

void CINSBotAttackRifle::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnUnStuck
 * Address: 00710780
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnUnStuck(CINSNextBot*) */

void CINSBotAttackRifle::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnInjured
 * Address: 007107e0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackRifle::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnKilled
 * Address: 00710810
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackRifle::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnOtherKilled
 * Address: 00710840
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotAttackRifle::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnSight
 * Address: 00710870
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackRifle::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnLostSight
 * Address: 007108a0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackRifle::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnWeaponFired
 * Address: 007108d0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackRifle::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnCommandApproach
 * Address: 00710960
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackRifle::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnCommandApproach
 * Address: 00710990
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackRifle::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnCommandString
 * Address: 007109f0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackRifle::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnBlinded
 * Address: 00710a20
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackRifle::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnCommandAttack
 * Address: 00710930
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackRifle::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnCommandRetreat
 * Address: 007109c0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackRifle::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnHeardFootsteps
 * Address: 00710a50
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackRifle::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnNavAreaChanged
 * Address: 00710900
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackRifle::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnPostureChanged
 * Address: 007107b0
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackRifle::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::OnSeeSomethingSuspicious
 * Address: 00710a80
 * ---------------------------------------- */

/* CINSBotAttackRifle::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void CINSBotAttackRifle::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldIronsight
 * Address: 00710b50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackRifle::ShouldIronsight(CINSBotAttackRifle *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldIronsight
 * Address: 00710b60
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldIronsight(INextBot const*) const */

int __cdecl CINSBotAttackRifle::ShouldIronsight(INextBot *param_1)

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
 * CINSBotAttackRifle::ShouldProne
 * Address: 007106a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackRifle::ShouldProne(CINSBotAttackRifle *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldProne
 * Address: 007106b0
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackRifle::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldWalk
 * Address: 00710680
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackRifle::ShouldWalk(CINSBotAttackRifle *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::ShouldWalk
 * Address: 00710690
 * ---------------------------------------- */

/* CINSBotAttackRifle::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackRifle::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackRifle::~CINSBotAttackRifle
 * Address: 00711810
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::~CINSBotAttackRifle() */

void __thiscall CINSBotAttackRifle::~CINSBotAttackRifle(CINSBotAttackRifle *this)

{
  ~CINSBotAttackRifle(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::~CINSBotAttackRifle
 * Address: 00711820
 * ---------------------------------------- */

/* CINSBotAttackRifle::~CINSBotAttackRifle() */

void __thiscall CINSBotAttackRifle::~CINSBotAttackRifle(CINSBotAttackRifle *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x484403 /* vtable for CINSBotAttackRifle+0x8 */ /* vtable for CINSBotAttackRifle+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_004845ab + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x495953 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::~CINSBotAttackRifle
 * Address: 00711850
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackRifle::~CINSBotAttackRifle() */

void __thiscall CINSBotAttackRifle::~CINSBotAttackRifle(CINSBotAttackRifle *this)

{
  ~CINSBotAttackRifle(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackRifle::~CINSBotAttackRifle
 * Address: 00711860
 * ---------------------------------------- */

/* CINSBotAttackRifle::~CINSBotAttackRifle() */

void __thiscall CINSBotAttackRifle::~CINSBotAttackRifle(CINSBotAttackRifle *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4843ba /* vtable for CINSBotAttackRifle+0x8 */ /* vtable for CINSBotAttackRifle+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x484562 /* vtable for CINSBotAttackRifle+0x1b0 */ /* vtable for CINSBotAttackRifle+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



