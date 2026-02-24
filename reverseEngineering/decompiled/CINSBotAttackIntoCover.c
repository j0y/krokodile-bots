/*
 * CINSBotAttackIntoCover -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 44
 */

/* ----------------------------------------
 * CINSBotAttackIntoCover::CINSBotAttackIntoCover
 * Address: 0070cf60
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::CINSBotAttackIntoCover(Vector, bool, bool) */

void __thiscall
CINSBotAttackIntoCover::CINSBotAttackIntoCover
          (undefined4 param_1,int *param_2,int param_3,int param_4,int param_5,undefined1 param_6,
          undefined1 param_7)

{
  int *piVar1;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  *param_2 = unaff_EBX + 0x4884bd /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */;
  piVar1 = param_2 + 0xe;
  param_2[1] = unaff_EBX + 0x488669 /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */;
  param_2[0xe] = unaff_EBX + 0x41b24d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_0 */
  param_2[9] = 0;
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
  param_2[0xf] = 0;
  CountdownTimer::NetworkStateChanged(piVar1);
  param_2[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0xe] + 4))(piVar1,param_2 + 0x10); /* timer_0.NetworkStateChanged() */
  *(undefined1 *)(param_2 + 0x14) = param_6;
  param_2[0x11] = param_3;
  param_2[0x12] = param_4;
  param_2[0x13] = param_5;
  if (param_2[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(param_2[0xe] + 4))(piVar1,param_2 + 0x10); /* timer_0.NetworkStateChanged() */
    param_2[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  }
  *(undefined1 *)((int)param_2 + 0x51) = param_7;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnStart
 * Address: 0070cb80
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotAttackIntoCover::OnStart(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  uVar2 = (**(code **)(*piVar1 + 0x96c /* CINSNextBot::GetLocomotionInterface */))(piVar1);
  CINSBotLocomotion::AddMovementRequest
            (uVar2,*(undefined4 *)(param_2 + 0x44),*(undefined4 *)(param_2 + 0x48),
             *(undefined4 *)(param_2 + 0x4c),2,7,0x40a00000 /* 5.0f */);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::Update
 * Address: 0070c400
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackIntoCover::Update(CINSBotAttackIntoCover *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  void *pvVar7;
  int iVar8;
  CINSBotAttackFromCover *this_00;
  CINSPlayer *extraout_ECX;
  CINSPlayer *pCVar9;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSBotVision *this_03;
  CINSPlayer *extraout_ECX_02;
  CINSBotLocomotion *this_04;
  CINSPlayer *extraout_ECX_03;
  CINSPlayer *extraout_ECX_04;
  int *extraout_EDX;
  CINSNextBot *pCVar10;
  int unaff_EBX;
  float10 fVar11;
  float fVar12;
  CINSNextBot *in_stack_0000000c;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)(**(code **)(*extraout_EDX + 0x974 /* CINSNextBot::GetVisionInterface */))(extraout_EDX);
  piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
  if (((piVar4 == (int *)0x0) || (iVar5 = (**(code **)(*piVar4 + 0x10))(piVar4), iVar5 == 0)) ||
     (cVar2 = (**(code **)(*piVar4 + 0x54))(piVar4), cVar2 != '\0')) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
  pCVar10 = in_stack_0000000c + 0x2060;
  iVar5 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))(piVar6,pCVar10,piVar4);
  if (iVar5 == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x273b6e /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */;
    return param_1;
  }
  piVar6 = (int *)(**(code **)(*piVar4 + 0x10))(piVar4);
  if ((piVar6 == (int *)0x0) || (cVar2 = (**(code **)(*piVar6 + 0x158))(piVar6), cVar2 == '\0')) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x273f40 /* "Non INS Player Enemy?" */ /* "Non INS Player Enemy?" */ /* "Non INS Player Enemy?" */;
    return param_1;
  }
  fVar11 = (float10)CountdownTimer::Now();
  if ((float)fVar11 < *(float *)((int)param_2 + 0x40) || /* !timer_0.IsElapsed() */
      (float)fVar11 == *(float *)((int)param_2 + 0x40)) goto LAB_0070c532;
  fVar11 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                              (pCVar10,(int)param_2 + 0x44);
  if ((float)fVar11 < *(float *)(CGameStringPool::~CGameStringPool + unaff_EBX + 7)) {
    if (*(char *)((int)param_2 + 0x50) != '\0') {
      piVar4 = (int *)::operator_new(0x5c);
      pcVar1 = (code *)(unaff_EBX + -0x4dbca1 /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
      piVar4[8] = 0;
      piVar4[9] = 0;
      piVar4[10] = 0;
      piVar4[3] = 0;
      piVar4[4] = 0;
      piVar4[5] = 0;
      piVar4[6] = 0;
      piVar4[7] = 0;
      piVar4[2] = 0;
      *(undefined1 *)(piVar4 + 0xc) = 0;
      *(undefined1 *)((int)piVar4 + 0x31) = 0;
      piVar4[0xb] = 0;
      piVar4[0xd] = 0;
      iVar5 = *(int *)(unaff_EBX + 0x49a5e7 /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
      piVar4[0xf] = 0;
      piVar4[1] = iVar5 + 0x198;
      *piVar4 = iVar5 + 8;
      iVar5 = unaff_EBX + 0x41bda7 /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
      piVar4[0xe] = iVar5;
      (*pcVar1)(piVar4 + 0xe,piVar4 + 0xf);
      piVar4[0x10] = -0x40800000 /* -1.0f */; /* timer_0.Invalidate() */
      (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10); /* timer_0.NetworkStateChanged() */
      piVar4[0x12] = 0;
      piVar4[0x11] = iVar5;
      (*pcVar1)(piVar4 + 0x11,piVar4 + 0x12);
      piVar4[0x13] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
      piVar4[0x15] = 0;
      piVar4[0x14] = iVar5;
      (*pcVar1)(piVar4 + 0x14,piVar4 + 0x15);
      piVar4[0x16] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(int **)(param_1 + 4) = piVar4;
      *(int *)(param_1 + 8) = unaff_EBX + 0x273f56 /* "Made it, now reloading!" */ /* "Made it, now reloading!" */ /* "Made it, now reloading!" */;
      return param_1;
    }
    pvVar7 = ::operator_new(0x68);
    CINSBotAttackFromCover::CINSBotAttackFromCover(this_00);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(void **)(param_1 + 4) = pvVar7;
    *(int *)(param_1 + 8) = unaff_EBX + 0x273f6e /* "Made It!" */ /* "Made It!" */ /* "Made It!" */;
    return param_1;
  }
  fVar12 = *(float *)(in_stack_0000000c + 0xb340);
  uVar13 = 0;
  fVar11 = (float10)CINSNextBot::GetDesiredAttackRange
                              (in_stack_0000000c,(CINSWeapon *)in_stack_0000000c);
  if (fVar12 <= (float)fVar11) {
    iVar5 = *(int *)((int)param_2 + 0xc);
    piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c,uVar13);
    pcVar1 = *(code **)(*piVar6 + 0x108);
    uVar13 = (**(code **)(*piVar4 + 0x18))(piVar4);
    cVar2 = (*pcVar1)(piVar6,uVar13,1);
    cVar3 = (**(code **)(*piVar4 + 0x38))(piVar4);
    if ((cVar3 == '\0') && (cVar2 == '\0')) {
      iVar8 = (**(code **)(*(int *)(iVar5 + 4) + 0xc))(iVar5 + 4,pCVar10);
      if ((((iVar8 == 0) &&
           (iVar5 = (**(code **)(*(int *)(iVar5 + 4) + 0x10))(iVar5 + 4,pCVar10), iVar5 == 0)) &&
          (cVar2 = CINSNextBot::ShouldRushToCover(this_01), cVar2 == '\0')) &&
         (cVar2 = CINSNextBot::IsSuppressed(this_02), cVar2 == '\0')) {
        (**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        fVar11 = (float10)CINSBotVision::GetCombatIntensity(this_03);
        if ((float)fVar11 < *(float *)(&DAT_00218347 + unaff_EBX) ||
            (float)fVar11 == *(float *)(&DAT_00218347 + unaff_EBX)) {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          uVar15 = 0x3e99999a /* 0.3f */;
          uVar14 = 8;
          iVar5 = unaff_EBX + 0x273fa4 /* "Sprinting to Cover" */ /* "Sprinting to Cover" */ /* "Sprinting to Cover" */;
          uVar13 = 0xc;
          CINSBotBody::SetPosture();
          pCVar9 = extraout_ECX_02;
          goto LAB_0070c910;
        }
      }
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar15 = 0x3e99999a /* 0.3f */;
      uVar14 = 8;
      iVar5 = unaff_EBX + 0x273fa4 /* "Sprinting to Cover" */ /* "Sprinting to Cover" */ /* "Sprinting to Cover" */;
      uVar13 = 0xd;
      CINSBotBody::SetPosture();
      pCVar9 = extraout_ECX_01;
    }
    else {
      piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      pcVar1 = *(code **)(*piVar6 + 0xd8);
      uVar13 = (**(code **)(*piVar4 + 0x10))(piVar4);
      (*pcVar1)(piVar6,uVar13,3,0x3e99999a /* 0.3f */,0,unaff_EBX + 0x273e64 /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */);
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar15 = 0x3e99999a /* 0.3f */;
      uVar14 = 8;
      iVar5 = unaff_EBX + 0x273f93 /* "Walking to Cover" */ /* "Walking to Cover" */ /* "Walking to Cover" */;
      uVar13 = 0xb;
      CINSBotBody::SetPosture();
      pcVar1 = *(code **)(*(int *)in_stack_0000000c + 0x434);
      uVar13 = (**(code **)(*piVar4 + 0x14))(piVar4,uVar13,uVar14,uVar15,iVar5);
      uVar14 = 0x3f666666 /* 0.9f */;
      cVar2 = (*pcVar1)(in_stack_0000000c,uVar13,0x3f666666 /* 0.9f */);
      pCVar9 = extraout_ECX;
      if (cVar2 != '\0') {
        uVar13 = 0x3f19999a /* 0.6f */;
        (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3f19999a /* 0.6f */);
        pCVar9 = extraout_ECX_04;
      }
    }
LAB_0070c910:
    cVar2 = CINSPlayer::IsProned(pCVar9);
    if ((cVar2 == '\0') ||
       (cVar2 = (**(code **)(*piVar4 + 0x38))(piVar4,uVar13,uVar14,uVar15,iVar5), cVar2 == '\0')) {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar15 = 0x3e99999a /* 0.3f */;
      uVar14 = 8;
      iVar5 = unaff_EBX + 0x273fb7 /* "Getting up from prone" */ /* "Getting up from prone" */ /* "Getting up from prone" */;
      uVar13 = 0xc;
      CINSBotBody::SetPosture();
      pCVar9 = extraout_ECX_00;
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar15 = 0x3e99999a /* 0.3f */;
      uVar14 = 8;
      iVar5 = unaff_EBX + 0x273fcf /* "staying prone while attacking our enemy" */ /* "staying prone while attacking our enemy" */ /* "staying prone while attacking our enemy" */;
      uVar13 = 1;
      CINSBotBody::SetPosture();
      pCVar9 = extraout_ECX_03;
    }
    cVar2 = CINSPlayer::IsMoving(pCVar9);
    if ((cVar2 == '\0') &&
       (cVar2 = CINSPlayer::IsProned((CINSPlayer *)in_stack_0000000c), cVar2 == '\0')) {
      (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,uVar13,uVar14,uVar15,iVar5)
      ;
      fVar11 = (float10)CINSBotLocomotion::GetStillDuration(this_04);
      if (*(float *)(unaff_EBX + 0x21a99f /* 2.0f */ /* 2.0f */ /* 2.0f */) <= (float)fVar11 &&
          (float)fVar11 != *(float *)(unaff_EBX + 0x21a99f /* 2.0f */ /* 2.0f */ /* 2.0f */)) {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x273ff7 /* "Rethink, i've been still here for more than 2 seconds" */ /* "Rethink, i've been still here for more than 2 seconds" */ /* "Rethink, i've been still here for more than 2 seconds" */;
        return param_1;
      }
    }
    CINSNextBot::FireWeaponAtEnemy(in_stack_0000000c);
  }
  else {
    (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    iVar5 = unaff_EBX + 0x273f77 /* "sprinting to cover position" */ /* "sprinting to cover position" */ /* "sprinting to cover position" */;
    uVar15 = 0x3e99999a /* 0.3f */;
    uVar14 = 8;
    CINSBotBody::SetPosture();
  }
  fVar11 = (float10)CountdownTimer::Now();
  fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x21767b /* 0.25f */ /* 0.25f */ /* 0.25f */);
  if (*(float *)((int)param_2 + 0x40) != fVar12) {
    (**(code **)(*(int *)((int)param_2 + 0x38) + 4)) /* timer_0.NetworkStateChanged() */
              ((int)param_2 + 0x38,(int)param_2 + 0x40,uVar14,uVar15,iVar5);
    *(float *)((int)param_2 + 0x40) = fVar12; /* timer_0.Start(0.25f) */
  }
  if (*(int *)((int)param_2 + 0x3c) != 0x3e800000 /* 0.25f */) {
    (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c); /* timer_0.NetworkStateChanged() */
    *(undefined4 *)((int)param_2 + 0x3c) = 0x3e800000 /* 0.25f */;
  }
LAB_0070c532:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnEnd
 * Address: 0070bd20
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackIntoCover::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::GetName
 * Address: 0070d090
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::GetName() const */

int CINSBotAttackIntoCover::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2732ac /* "AttackIntoCover" */ /* "AttackIntoCover" */ /* "AttackIntoCover" */;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldHurry
 * Address: 0070c2d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackIntoCover::ShouldHurry(CINSBotAttackIntoCover *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldHurry
 * Address: 0070c2e0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldHurry(INextBot const*) const */

int __cdecl CINSBotAttackIntoCover::ShouldHurry(INextBot *param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  CINSNextBot *this;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  int iVar4;
  
  iVar2 = __i686_get_pc_thunk_bx();
  iVar4 = 2;
  iVar2 = *(int *)(iVar2 + 0x1c);
  if (iVar2 != 0) {
    iVar4 = 1;
    cVar1 = CINSNextBot::IsSuppressed(this);
    if ((cVar1 == '\0') && (iVar3 = CINSPlayer::GetActiveINSWeapon(), iVar3 != 0)) {
      iVar4 = CINSPlayer::GetWeaponInSlot(this_00,iVar2,false);
      if (iVar3 == iVar4) {
        cVar1 = *(char *)(iVar2 + 0x228c);
      }
      else {
        iVar4 = CINSPlayer::GetWeaponInSlot(this_01,iVar2,true);
        if (iVar3 == iVar4) {
          cVar1 = *(char *)(iVar2 + 0x228d);
        }
        else {
          iVar4 = CINSPlayer::GetWeaponInSlot(this_02,iVar2,true);
          if (iVar3 != iVar4) {
            iVar2 = CINSPlayer::GetWeaponInSlot(this_03,iVar2,true);
            return (iVar3 == iVar2) + 1;
          }
          cVar1 = *(char *)(iVar2 + 0x228e);
        }
      }
      iVar4 = ~-(uint)(cVar1 == '\0') + 2;
    }
  }
  return iVar4;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldRetreat
 * Address: 0070c190
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldRetreat(INextBot const*) const */

void __thiscall
CINSBotAttackIntoCover::ShouldRetreat(CINSBotAttackIntoCover *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldRetreat
 * Address: 0070c1a0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldRetreat(INextBot const*) const */

undefined1 __cdecl CINSBotAttackIntoCover::ShouldRetreat(INextBot *param_1)

{
  int *piVar1;
  char cVar2;
  undefined1 uVar3;
  CINSNextBot *this;
  CINSBotVision *this_00;
  int unaff_EBX;
  float10 fVar4;
  float local_14;
  float local_10;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(param_1 + 0x1c);
  uVar3 = 2;
  if (piVar1 != (int *)0x0) {
    cVar2 = (**(code **)(*piVar1 + 0x4ac /* CBaseCombatCharacter::HasEverBeenInjured */))(piVar1,0xffffffff);
    if (cVar2 == '\0') {
      local_14 = *(float *)(unaff_EBX + 0x2178e2 /* 0.25f */ /* 0.25f */ /* 0.25f */);
      local_10 = 0.0;
    }
    else {
      local_14 = *(float *)(unaff_EBX + 0x2178e2 /* 0.25f */ /* 0.25f */ /* 0.25f */);
      local_10 = local_14;
    }
    cVar2 = CINSNextBot::IsSuppressed(this);
    if (cVar2 != '\0') {
      local_10 = local_10 + local_14;
    }
    fVar4 = (float10)CINSNextBot::GetActiveWeaponAmmoRatio();
    if ((float)fVar4 < *(float *)(unaff_EBX + 0x1ac972 /* 0.1f */ /* 0.1f */ /* 0.1f */)) {
      local_10 = local_10 + local_14;
    }
    (**(code **)(*piVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(piVar1);
    fVar4 = (float10)CINSBotVision::GetCombatIntensity(this_00);
    if (*(float *)(&DAT_002185ae + unaff_EBX) <= (float)fVar4 &&
        (float)fVar4 != *(float *)(&DAT_002185ae + unaff_EBX)) {
      local_10 = local_10 + local_14;
    }
    uVar3 = 0;
    if (local_14 < local_10) {
      fVar4 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
      return (float)fVar4 < local_10;
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldAttack
 * Address: 0070bd50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackIntoCover::ShouldAttack
          (CINSBotAttackIntoCover *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldAttack
 * Address: 0070bd60
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackIntoCover::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnContact
 * Address: 0070bdd0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackIntoCover::OnContact
               (CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnMoveToSuccess
 * Address: 0070ccb0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotAttackIntoCover::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  float10 fVar4;
  
  iVar2 = __i686_get_pc_thunk_bx();
  fVar4 = (float10)(**(code **)(*(int *)(iVar2 + 0x2060) + 0x134))(iVar2 + 0x2060,param_2 + 0x44);
  if (*(float *)(CUtlRBTree<CUtlMap<char_const*,BasicGameStatsRecord_t,unsigned_short,bool(*)(char_const*const&,char_const*const&)>::Node_t,unsigned_short,CUtlMap<char_const*,BasicGameStatsRecord_t,unsigned_short,bool(*)(char_const*const&,char_const*const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<char_const*,BasicGameStatsRecord_t,unsigned_short,bool(*)(char_const*const&,char_const*const&)>::Node_t,unsigned_short>,unsigned_short>>
                 ::RemoveAll + unaff_EBX + 7) <= (float)fVar4) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else if (param_2[0x50] == (Path)0x0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2736be /* "Made It!" */ /* "Made It!" */ /* "Made It!" */;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar2 = *(int *)(unaff_EBX + 0x499d37 /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x41b4f7 /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4dc551 /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar2;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */; /* timer_0.Invalidate() */
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10); /* timer_0.NetworkStateChanged() */
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar2;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar2;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(int **)(param_1 + 4) = piVar3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2736a6 /* "Made it, now reloading!" */ /* "Made it, now reloading!" */ /* "Made it, now reloading!" */;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnMoveToFailure
 * Address: 0070be00
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackIntoCover::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnStuck
 * Address: 0070be30
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnStuck(CINSNextBot*) */

void CINSBotAttackIntoCover::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnUnStuck
 * Address: 0070be60
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnUnStuck(CINSNextBot*) */

void CINSBotAttackIntoCover::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnInjured
 * Address: 0070bec0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackIntoCover::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnKilled
 * Address: 0070bef0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackIntoCover::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnOtherKilled
 * Address: 0070bf20
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo
   const&) */

void CINSBotAttackIntoCover::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnSight
 * Address: 0070bf50
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackIntoCover::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnLostSight
 * Address: 0070bf80
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackIntoCover::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnWeaponFired
 * Address: 0070bfb0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackIntoCover::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnCommandApproach
 * Address: 0070c040
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackIntoCover::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnCommandApproach
 * Address: 0070c070
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackIntoCover::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnCommandString
 * Address: 0070c0d0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackIntoCover::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::IsHindrance
 * Address: 0070bd30
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::IsHindrance(INextBot const*, CBaseEntity*) const */

void __thiscall
CINSBotAttackIntoCover::IsHindrance
          (CINSBotAttackIntoCover *this,INextBot *param_1,CBaseEntity *param_2)

{
  IsHindrance(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::IsHindrance
 * Address: 0070bd40
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::IsHindrance(INextBot const*, CBaseEntity*) const */

undefined4 __cdecl CINSBotAttackIntoCover::IsHindrance(INextBot *param_1,CBaseEntity *param_2)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnBlinded
 * Address: 0070c100
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackIntoCover::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnCommandAttack
 * Address: 0070c010
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackIntoCover::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnCommandRetreat
 * Address: 0070c0a0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackIntoCover::OnCommandRetreat
               (CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnHeardFootsteps
 * Address: 0070c130
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackIntoCover::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnNavAreaChanged
 * Address: 0070bfe0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackIntoCover::OnNavAreaChanged
               (CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnPostureChanged
 * Address: 0070be90
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackIntoCover::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::OnSeeSomethingSuspicious
 * Address: 0070c160
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

void CINSBotAttackIntoCover::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldIronsight
 * Address: 0070bd90
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldIronsight(INextBot const*) const */

void __thiscall
CINSBotAttackIntoCover::ShouldIronsight(CINSBotAttackIntoCover *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldIronsight
 * Address: 0070bda0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackIntoCover::ShouldIronsight(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldProne
 * Address: 0070bdb0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackIntoCover::ShouldProne(CINSBotAttackIntoCover *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldProne
 * Address: 0070bdc0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackIntoCover::ShouldProne(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldWalk
 * Address: 0070bd70
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackIntoCover::ShouldWalk(CINSBotAttackIntoCover *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::ShouldWalk
 * Address: 0070bd80
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackIntoCover::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::~CINSBotAttackIntoCover
 * Address: 0070d0b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::~CINSBotAttackIntoCover() */

void __thiscall CINSBotAttackIntoCover::~CINSBotAttackIntoCover(CINSBotAttackIntoCover *this)

{
  ~CINSBotAttackIntoCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::~CINSBotAttackIntoCover
 * Address: 0070d0c0
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::~CINSBotAttackIntoCover() */

void __thiscall CINSBotAttackIntoCover::~CINSBotAttackIntoCover(CINSBotAttackIntoCover *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x488363 /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48850f /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x49a0b3 /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::~CINSBotAttackIntoCover
 * Address: 0070d0f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackIntoCover::~CINSBotAttackIntoCover() */

void __thiscall CINSBotAttackIntoCover::~CINSBotAttackIntoCover(CINSBotAttackIntoCover *this)

{
  ~CINSBotAttackIntoCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackIntoCover::~CINSBotAttackIntoCover
 * Address: 0070d100
 * ---------------------------------------- */

/* CINSBotAttackIntoCover::~CINSBotAttackIntoCover() */

void __thiscall CINSBotAttackIntoCover::~CINSBotAttackIntoCover(CINSBotAttackIntoCover *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48831a /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */ /* vtable for CINSBotAttackIntoCover+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4884c6 /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */ /* vtable for CINSBotAttackIntoCover+0x1b4 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



