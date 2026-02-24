/*
 * CINSBotAttackSniper -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackSniper::CINSBotAttackSniper
 * Address: 007127c0
 * ---------------------------------------- */

/* CINSBotAttackSniper::CINSBotAttackSniper() */

void __thiscall CINSBotAttackSniper::CINSBotAttackSniper(CINSBotAttackSniper *this)

{
  int *piVar1;
  int *piVar2;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48365d /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x483805 /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */;
  piVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[0xe] = unaff_EBX + 0x4159ed /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_0 */
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
  (*(code *)(unaff_EBX + -0x4e205b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10); /* timer_0.NetworkStateChanged() */
  piVar2 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = unaff_EBX + 0x4159ed /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_1 */
  (*(code *)(unaff_EBX + -0x4e205b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar2,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x11] + 4))(piVar2,in_stack_00000004 + 0x13); /* timer_1.NetworkStateChanged() */
  if (in_stack_00000004[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10); /* timer_0.NetworkStateChanged() */
    in_stack_00000004[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  }
  if (in_stack_00000004[0x13] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x11] + 4))(piVar2,in_stack_00000004 + 0x13); /* timer_1.NetworkStateChanged() */
    in_stack_00000004[0x13] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnStart
 * Address: 00711fa0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackSniper::OnStart(CINSBotAttackSniper *this,CINSNextBot *param_1,Action *param_2)

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
LAB_0071212a:
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
    goto LAB_0071212a;
  }
  fVar4 = *(float *)(in_stack_0000000c + 0xb340);
  fVar7 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
  if ((float)fVar7 <= fVar4) {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
    goto LAB_00712047;
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
        goto LAB_00712159;
      }
    }
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
    CINSBotBody::SetPosture();
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
LAB_00712159:
    CINSBotBody::SetPosture();
  }
LAB_00712047:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackSniper::InitialContainedAction
 * Address: 00711e30
 * ---------------------------------------- */

/* CINSBotAttackSniper::InitialContainedAction(CINSNextBot*) */

void * __thiscall
CINSBotAttackSniper::InitialContainedAction(CINSBotAttackSniper *this,CINSNextBot *param_1)

{
  float *pfVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  CINSBotAttackInPlace *this_00;
  CINSBotAttackInPlace *this_01;
  int unaff_EBX;
  int *in_stack_00000008;
  float local_1c;
  float local_18;
  float local_14;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (int *)0x0) {
    return (void *)0x0;
  }
  if ((in_stack_00000008[0x2cce] == -1) ||
     (iVar2 = UTIL_EntityByIndex(in_stack_00000008[0x2cce]), iVar2 == 0)) {
    piVar4 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if ((piVar4 == (int *)0x0) || (iVar2 = (**(code **)(*piVar4 + 0x10))(piVar4), iVar2 == 0)) {
      pvVar3 = ::operator_new(0x50);
      CINSBotAttackInPlace::CINSBotAttackInPlace(this_01);
      return pvVar3;
    }
  }
  CINSNextBot::GetAttackCover(true);
  pfVar1 = *(float **)(unaff_EBX + 0x494792 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (((*pfVar1 == local_1c) && (pfVar1[1] == local_18)) && (pfVar1[2] == local_14)) {
    pvVar3 = ::operator_new(0x50);
    CINSBotAttackInPlace::CINSBotAttackInPlace(this_00);
    return pvVar3;
  }
  pvVar3 = ::operator_new(0x54);
  CINSBotAttackIntoCover::CINSBotAttackIntoCover();
  return pvVar3;
}



/* ----------------------------------------
 * CINSBotAttackSniper::Update
 * Address: 00712270
 * ---------------------------------------- */

/* CINSBotAttackSniper::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackSniper::Update(CINSBotAttackSniper *this,CINSNextBot *param_1,float param_2)

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
  if ((float)fVar8 < *(float *)((int)param_2 + 0x4c) || /* !timer_1.IsElapsed() */
      (float)fVar8 == *(float *)((int)param_2 + 0x4c)) goto LAB_007122ac;
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
      uVar10 = 0x3f4ccccd /* 0.8f */;
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
          iVar3 = unaff_EBX + 0x26e216 /* "CProne from aiming threat" */ /* "CProne from aiming threat" */ /* "CProne from aiming threat" */;
          goto LAB_007124a6;
        }
      }
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar12 = 0x3f0ccccd /* 0.55f */;
      uVar11 = 7;
      iVar3 = unaff_EBX + 0x26e201 /* "Crouch for stability" */ /* "Crouch for stability" */ /* "Crouch for stability" */;
      uVar10 = 3;
      CINSBotBody::SetPosture();
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      iVar3 = unaff_EBX + 0x26e1ea /* "Prone From Suppression" */ /* "Prone From Suppression" */ /* "Prone From Suppression" */;
LAB_007124a6:
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
    iVar3 = unaff_EBX + 0x26de40 /* "Walking At Target" */ /* "Walking At Target" */ /* "Walking At Target" */;
    uVar10 = 7;
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
LAB_007123b8:
        uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4);
        if ((uVar6 & 2) == 0) goto LAB_007123d8;
      }
      else {
        fVar9 = *(float *)(in_stack_0000000c + 0xb340);
        uVar10 = 0;
        fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(pCVar4,in_stack_0000000c);
        if (((fVar9 <= (float)fVar8 * *(float *)(unaff_EBX + 0x211812 /* 0.75f */ /* 0.75f */ /* 0.75f */)) ||
            (uVar6 = CINSPlayer::GetPlayerFlags((CINSPlayer *)pCVar4), (uVar6 & 2) == 0)) ||
           (cVar2 = CINSWeapon::InBipodTransition(), cVar2 != '\0')) goto LAB_007123b8;
      }
      uVar10 = 0;
      CINSWeapon::ToggleBipod((CINSWeapon *)pCVar4,SUB41(pCVar4,0));
    }
  }
LAB_007123d8:
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c,uVar10);
  iVar3 = (**(code **)(*piVar5 + 0xec /* IIntention::ShouldIronsight */))(piVar5,in_stack_0000000c + 0x2060);
  if (iVar3 != 0) {
    (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3f0ccccd /* 0.55f */);
  }
  fVar8 = (float10)CountdownTimer::Now();
  fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x2124da /* 0.5f */ /* 0.5f */ /* 0.5f */);
  if (*(float *)((int)param_2 + 0x4c) != fVar9) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c); /* timer_1.NetworkStateChanged() */
    *(float *)((int)param_2 + 0x4c) = fVar9; /* timer_1.Start(0.5f) */
  }
  if (*(int *)((int)param_2 + 0x48) != 0x3f000000 /* 0.5f */) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48); /* timer_1.NetworkStateChanged() */
    *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000 /* 0.5f */;
  }
LAB_007122ac:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnEnd
 * Address: 007118d0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackSniper::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::GetName
 * Address: 00712930
 * ---------------------------------------- */

/* CINSBotAttackSniper::GetName() const */

int CINSBotAttackSniper::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x26dc3e /* "CINSBotAttackSniper" */ /* "CINSBotAttackSniper" */ /* "CINSBotAttackSniper" */;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldHurry
 * Address: 007118e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackSniper::ShouldHurry(CINSBotAttackSniper *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldHurry
 * Address: 007118f0
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldRetreat
 * Address: 00711900
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackSniper::ShouldRetreat(CINSBotAttackSniper *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldRetreat
 * Address: 00711910
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldRetreat(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldAttack
 * Address: 00711920
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackSniper::ShouldAttack(CINSBotAttackSniper *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldAttack
 * Address: 00711930
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnContact
 * Address: 007119a0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackSniper::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnMoveToSuccess
 * Address: 007119d0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackSniper::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnMoveToFailure
 * Address: 00711a00
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackSniper::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnStuck
 * Address: 00711a30
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnStuck(CINSNextBot*) */

void CINSBotAttackSniper::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnUnStuck
 * Address: 00711a60
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnUnStuck(CINSNextBot*) */

void CINSBotAttackSniper::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnInjured
 * Address: 00711ac0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackSniper::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnKilled
 * Address: 00711af0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackSniper::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnOtherKilled
 * Address: 00711b20
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&)
    */

void CINSBotAttackSniper::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnSight
 * Address: 00711b50
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackSniper::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnLostSight
 * Address: 00711b80
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackSniper::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnWeaponFired
 * Address: 00711bb0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackSniper::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnCommandApproach
 * Address: 00711c40
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackSniper::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnCommandApproach
 * Address: 00711c70
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackSniper::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnCommandString
 * Address: 00711cd0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackSniper::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnBlinded
 * Address: 00711d00
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackSniper::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnCommandAttack
 * Address: 00711c10
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackSniper::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnCommandRetreat
 * Address: 00711ca0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackSniper::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnHeardFootsteps
 * Address: 00711d30
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackSniper::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnNavAreaChanged
 * Address: 00711be0
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackSniper::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnPostureChanged
 * Address: 00711a90
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackSniper::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::OnSeeSomethingSuspicious
 * Address: 00711d60
 * ---------------------------------------- */

/* CINSBotAttackSniper::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void CINSBotAttackSniper::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldIronsight
 * Address: 00711960
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackSniper::ShouldIronsight(CINSBotAttackSniper *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldIronsight
 * Address: 00711970
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldIronsight(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldProne
 * Address: 00711980
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackSniper::ShouldProne(CINSBotAttackSniper *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldProne
 * Address: 00711990
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldWalk
 * Address: 00711940
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackSniper::ShouldWalk(CINSBotAttackSniper *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::ShouldWalk
 * Address: 00711950
 * ---------------------------------------- */

/* CINSBotAttackSniper::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackSniper::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackSniper::~CINSBotAttackSniper
 * Address: 00712950
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::~CINSBotAttackSniper() */

void __thiscall CINSBotAttackSniper::~CINSBotAttackSniper(CINSBotAttackSniper *this)

{
  ~CINSBotAttackSniper(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::~CINSBotAttackSniper
 * Address: 00712960
 * ---------------------------------------- */

/* CINSBotAttackSniper::~CINSBotAttackSniper() */

void __thiscall CINSBotAttackSniper::~CINSBotAttackSniper(CINSBotAttackSniper *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4834c3 /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48366b /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x494813 /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::~CINSBotAttackSniper
 * Address: 00712990
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackSniper::~CINSBotAttackSniper() */

void __thiscall CINSBotAttackSniper::~CINSBotAttackSniper(CINSBotAttackSniper *this)

{
  ~CINSBotAttackSniper(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackSniper::~CINSBotAttackSniper
 * Address: 007129a0
 * ---------------------------------------- */

/* CINSBotAttackSniper::~CINSBotAttackSniper() */

void __thiscall CINSBotAttackSniper::~CINSBotAttackSniper(CINSBotAttackSniper *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48347a /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */ /* vtable for CINSBotAttackSniper+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x483622 /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */ /* vtable for CINSBotAttackSniper+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



