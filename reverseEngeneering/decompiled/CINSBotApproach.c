/*
 * CINSBotApproach -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 27
 */

/* ----------------------------------------
 * CINSBotApproach::CINSBotApproach
 * Address: 006f7490
 * ---------------------------------------- */

/* CINSBotApproach::CINSBotApproach(Vector) */

void __thiscall
CINSBotApproach::CINSBotApproach
          (undefined4 param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  *param_2 = &UNK_0049d18d + unaff_EBX;
  param_2[1] = unaff_EBX + 0x49d325;
  param_2[0xe] = unaff_EBX + 0x430d1d;
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
  (*(code *)(unaff_EBX + -0x4c6d2b))(param_2 + 0xe,param_2 + 0xf);
  param_2[0x10] = 0xbf800000;
  (**(code **)(param_2[0xe] + 4))(param_2 + 0xe,param_2 + 0x10);
  param_2[0x16] = 0;
  param_2[0x15] = unaff_EBX + 0x430d1d;
  (*(code *)(unaff_EBX + -0x4c6d2b))(param_2 + 0x15,param_2 + 0x16);
  param_2[0x17] = 0xbf800000;
  (**(code **)(param_2[0x15] + 4))(param_2 + 0x15,param_2 + 0x17);
  *(undefined1 *)(param_2 + 0x14) = 0;
  *(undefined1 *)(param_2 + 0x18) = 0;
  param_2[0x11] = param_3;
  param_2[0x12] = param_4;
  param_2[0x13] = param_5;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnStart
 * Address: 006f6ec0
 * ---------------------------------------- */

/* CINSBotApproach::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall CINSBotApproach::OnStart(CINSBotApproach *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  CINSWeapon *this_00;
  CINSWeapon *this_01;
  CINSWeapon *extraout_ECX;
  CINSNextBot *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  iVar2 = CINSPlayer::GetActiveINSWeapon();
  if ((iVar2 != 0) &&
     (((cVar1 = CINSWeapon::HasLasersights(this_00), this_03 = this_01, cVar1 != '\0' &&
       (cVar1 = CINSWeapon::IsLasersightsOn(this_01), this_03 = extraout_ECX, cVar1 != '\0')) ||
      ((cVar1 = CINSWeapon::HasFlashlight(this_03), cVar1 != '\0' &&
       (cVar1 = CINSWeapon::IsFlashlightOn(this_04), cVar1 != '\0')))))) {
    param_2[0x60] = (Action)0x1;
  }
  uVar3 = (**(code **)(*in_stack_0000000c + 0x96c))(in_stack_0000000c);
  CINSBotLocomotion::AddMovementRequest
            (uVar3,*(undefined4 *)(param_2 + 0x44),*(undefined4 *)(param_2 + 0x48),
             *(undefined4 *)(param_2 + 0x4c),6,8,0x40a00000);
  CINSNextBot::ResetIdleStatus(this_02);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::Update
 * Address: 006f7060
 * ---------------------------------------- */

/* CINSBotApproach::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotApproach::Update(CINSBotApproach *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSWeapon *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar5 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar5 &&
      (float)fVar5 != *(float *)((int)param_2 + 0x40)) {
    fVar5 = (float10)CountdownTimer::Now();
    fVar6 = (float)fVar5 + *(float *)(unaff_EBX + 0x22d6ed);
    if (*(float *)((int)param_2 + 0x40) != fVar6) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40);
      *(float *)((int)param_2 + 0x40) = fVar6;
    }
    if (*(int *)((int)param_2 + 0x3c) != 0x3f000000) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c);
      *(undefined4 *)((int)param_2 + 0x3c) = 0x3f000000;
    }
    piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x974))(in_stack_0000000c);
    iVar3 = (**(code **)(*piVar2 + 0xd0))(piVar2,0);
    this_00 = extraout_ECX;
    if (iVar3 != 0) {
      piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x97c))(in_stack_0000000c);
      iVar3 = (**(code **)(*piVar2 + 0xd4))(piVar2,in_stack_0000000c + 0x818,iVar3);
      this_00 = extraout_ECX_00;
      if (iVar3 == 1) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x2889f0;
        return param_1;
      }
    }
    cVar1 = CINSNextBot::IsIdle(this_00);
    if (cVar1 != '\0') {
      uVar4 = (**(code **)(*in_stack_0000000c + 0x96c))(in_stack_0000000c);
      CINSBotLocomotion::AddMovementRequest
                (uVar4,*(undefined4 *)((int)param_2 + 0x44),*(undefined4 *)((int)param_2 + 0x48),
                 *(undefined4 *)((int)param_2 + 0x4c),6,8,0x40a00000);
    }
  }
  fVar5 = (float10)CountdownTimer::Now();
  if ((((*(float *)((int)param_2 + 0x5c) <= (float)fVar5 &&
         (float)fVar5 != *(float *)((int)param_2 + 0x5c)) &&
       (*(char *)((int)param_2 + 0x60) == '\0')) &&
      (iVar3 = TheINSNextBots(), *(char *)(iVar3 + 0x129) != '\0')) &&
     (iVar3 = CINSPlayer::GetActiveINSWeapon(), iVar3 != 0)) {
    cVar1 = CINSWeapon::HasLasersights(this_01);
    this_03 = this_02;
    if ((cVar1 != '\0') &&
       (cVar1 = CINSWeapon::IsLasersightsOn(this_02), this_03 = this_06, cVar1 != '\0')) {
      CINSWeapon::ToggleLasersights(this_06);
      this_03 = extraout_ECX_01;
    }
    cVar1 = CINSWeapon::HasFlashlight(this_03);
    if ((cVar1 != '\0') && (cVar1 = CINSWeapon::IsFlashlightOn(this_04), cVar1 != '\0')) {
      CINSWeapon::ToggleFlashlight(this_05);
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotApproach::OnEnd
 * Address: 006f69c0
 * ---------------------------------------- */

/* CINSBotApproach::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotApproach::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnSuspend
 * Address: 006f69a0
 * ---------------------------------------- */

/* CINSBotApproach::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotApproach::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnResume
 * Address: 006f6e30
 * ---------------------------------------- */

/* CINSBotApproach::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotApproach::OnResume(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  uVar2 = (**(code **)(*piVar1 + 0x96c))(piVar1);
  CINSBotLocomotion::AddMovementRequest
            (uVar2,*(undefined4 *)(param_2 + 0x44),*(undefined4 *)(param_2 + 0x48),
             *(undefined4 *)(param_2 + 0x4c),6,8,0x40a00000);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotApproach::GetName
 * Address: 006f75c0
 * ---------------------------------------- */

/* CINSBotApproach::GetName() const */

int CINSBotApproach::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x295681;
}



/* ----------------------------------------
 * CINSBotApproach::ShouldHurry
 * Address: 006f6bd0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotApproach::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotApproach::ShouldHurry(CINSBotApproach *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotApproach::ShouldHurry
 * Address: 006f6be0
 * ---------------------------------------- */

/* CINSBotApproach::ShouldHurry(INextBot const*) const */

char __thiscall CINSBotApproach::ShouldHurry(CINSBotApproach *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  char cVar4;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000008 + 0x114))();
  cVar4 = '\x02';
  if (iVar2 != 0) {
    pcVar1 = *(code **)(*in_stack_00000008 + 0x134);
    piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x114))();
    (**(code **)(*piVar3 + 0x18))(piVar3);
    fVar5 = (float10)(*pcVar1)();
    cVar4 = ((float)fVar5 < *(float *)(unaff_EBX + 0x2550a4) ||
            (float)fVar5 == *(float *)(unaff_EBX + 0x2550a4)) + '\x01';
  }
  return cVar4;
}



/* ----------------------------------------
 * CINSBotApproach::OnContact
 * Address: 006f6aa0
 * ---------------------------------------- */

/* CINSBotApproach::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotApproach::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnMoveToSuccess
 * Address: 006f6a30
 * ---------------------------------------- */

/* CINSBotApproach::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotApproach::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnMoveToFailure
 * Address: 006f6a60
 * ---------------------------------------- */

/* CINSBotApproach::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotApproach::OnMoveToFailure(undefined4 *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *param_1 = 3;
  param_1[1] = 0;
  param_1[2] = extraout_ECX + 0x28924f;
  param_1[3] = 3;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnStuck
 * Address: 006f6cf0
 * ---------------------------------------- */

/* CINSBotApproach::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotApproach::OnStuck(CINSNextBot *param_1)

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
  iVar1 = *(int *)(unaff_EBX + 0x4afcbd);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = unaff_EBX + 0x4314bd;
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x288d56;
  piVar2[0x17] = 0;
  piVar2[0x18] = 0;
  piVar2[0x19] = 0;
  piVar2[0x1a] = 0;
  *(undefined4 *)param_1 = 1;
  *(int **)(param_1 + 4) = piVar2;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotApproach::OnInjured
 * Address: 006f6ad0
 * ---------------------------------------- */

/* CINSBotApproach::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotApproach::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnOtherKilled
 * Address: 006f6b40
 * ---------------------------------------- */

/* CINSBotApproach::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotApproach::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnSight
 * Address: 006f69d0
 * ---------------------------------------- */

/* CINSBotApproach::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotApproach::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnLostSight
 * Address: 006f6a00
 * ---------------------------------------- */

/* CINSBotApproach::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotApproach::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnCommandAttack
 * Address: 006f6b00
 * ---------------------------------------- */

/* CINSBotApproach::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotApproach::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x288f2f;
  *(undefined4 *)(param_1 + 0xc) = 2;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnHeardFootsteps
 * Address: 006f6b70
 * ---------------------------------------- */

/* CINSBotApproach::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotApproach::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::OnNavAreaChanged
 * Address: 006f72a0
 * ---------------------------------------- */

/* CINSBotApproach::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

CINSNextBot * __thiscall
CINSBotApproach::OnNavAreaChanged
          (CINSBotApproach *this,CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

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
        *(float *)(unaff_EBX + 0x22c7d8) < *(float *)(unaff_EBX + 0x231f00))) {
      cVar1 = CINSPlayer::IsSprinting(this_00);
      if (cVar1 == '\0') {
        iVar2 = CINSPlayer::GetActiveINSWeapon();
        if (iVar2 != 0) {
          cVar1 = CINSWeapon::HasFlashlight(this_01);
          if (cVar1 != '\0') {
            cVar1 = CINSWeapon::IsFlashlightOn(this_02);
            if (cVar1 == '\0') {
              fVar3 = (float10)CountdownTimer::Now();
              fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x1c1cc8);
              if (*(float *)(param_2 + 0x5c) != fVar4) {
                (**(code **)(*(int *)(param_2 + 0x54) + 4))(param_2 + 0x54,param_2 + 0x5c);
                *(float *)(param_2 + 0x5c) = fVar4;
              }
              if (*(int *)(param_2 + 0x58) != 0x40400000) {
                (**(code **)(*(int *)(param_2 + 0x54) + 4))(param_2 + 0x54,param_2 + 0x58);
                *(undefined4 *)(param_2 + 0x58) = 0x40400000;
                param_2 = (CNavArea *)extraout_ECX;
              }
              CINSWeapon::ToggleFlashlight((CINSWeapon *)param_2);
            }
          }
        }
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
 * CINSBotApproach::OnSeeSomethingSuspicious
 * Address: 006f6ba0
 * ---------------------------------------- */

/* CINSBotApproach::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotApproach::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotApproach::ShouldWalk
 * Address: 006f6c60
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotApproach::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotApproach::ShouldWalk(CINSBotApproach *this,INextBot *param_1)

{
  ShouldWalk(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotApproach::ShouldWalk
 * Address: 006f6c70
 * ---------------------------------------- */

/* CINSBotApproach::ShouldWalk(INextBot const*) const */

char __thiscall CINSBotApproach::ShouldWalk(CINSBotApproach *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  char cVar4;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000008 + 0x114))();
  cVar4 = '\x02';
  if (iVar2 != 0) {
    pcVar1 = *(code **)(*in_stack_00000008 + 0x134);
    piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x114))();
    (**(code **)(*piVar3 + 0x18))(piVar3);
    fVar5 = (float10)(*pcVar1)();
    cVar4 = (*(float *)(unaff_EBX + 0x22e394) <= (float)fVar5) + '\x01';
  }
  return cVar4;
}



/* ----------------------------------------
 * CINSBotApproach::~CINSBotApproach
 * Address: 006f76b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotApproach::~CINSBotApproach() */

void __thiscall CINSBotApproach::~CINSBotApproach(CINSBotApproach *this)

{
  ~CINSBotApproach(this);
  return;
}



/* ----------------------------------------
 * CINSBotApproach::~CINSBotApproach
 * Address: 006f76c0
 * ---------------------------------------- */

/* CINSBotApproach::~CINSBotApproach() */

void __thiscall CINSBotApproach::~CINSBotApproach(CINSBotApproach *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x49cf63;
  in_stack_00000004[1] = extraout_ECX + 0x49d0fb;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4afab3));
  return;
}



/* ----------------------------------------
 * CINSBotApproach::~CINSBotApproach
 * Address: 006f8140
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotApproach::~CINSBotApproach() */

void __thiscall CINSBotApproach::~CINSBotApproach(CINSBotApproach *this)

{
  ~CINSBotApproach(this);
  return;
}



/* ----------------------------------------
 * CINSBotApproach::~CINSBotApproach
 * Address: 006f8150
 * ---------------------------------------- */

/* CINSBotApproach::~CINSBotApproach() */

void __thiscall CINSBotApproach::~CINSBotApproach(CINSBotApproach *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x49c4ca;
  in_stack_00000004[1] = unaff_EBX + 0x49c662;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



