/*
 * CINSBotEscort -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 42
 */

/* ----------------------------------------
 * CINSBotEscort::CINSBotEscort
 * Address: 0071a3e0
 * ---------------------------------------- */

/* CINSBotEscort::CINSBotEscort() */

void __thiscall CINSBotEscort::CINSBotEscort(CINSBotEscort *this)

{
  undefined *puVar1;
  code *pcVar2;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = &UNK_0047c5bd + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x47c75d /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */;
  puVar1 = &UNK_0040ddcd + unaff_EBX;
  in_stack_00000004[10] = 0;
  in_stack_00000004[3] = 0;
  pcVar2 = (code *)(unaff_EBX + -0x4e9c7b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[4] = 0;
  in_stack_00000004[5] = 0;
  in_stack_00000004[6] = 0;
  in_stack_00000004[7] = 0;
  in_stack_00000004[2] = 0;
  *(undefined1 *)(in_stack_00000004 + 0xc) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x31) = 0;
  in_stack_00000004[0xb] = 0;
  in_stack_00000004[0xd] = 0;
  in_stack_00000004[0x14] = puVar1;
  in_stack_00000004[0x15] = 0;
  (*pcVar2)(in_stack_00000004 + 0x14,in_stack_00000004 + 0x15);
  in_stack_00000004[0x16] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x14] + 4))(in_stack_00000004 + 0x14,in_stack_00000004 + 0x16);
  in_stack_00000004[0x17] = puVar1;
  in_stack_00000004[0x18] = 0;
  (*pcVar2)(in_stack_00000004 + 0x17,in_stack_00000004 + 0x18);
  in_stack_00000004[0x19] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x17] + 4))(in_stack_00000004 + 0x17,in_stack_00000004 + 0x19);
  in_stack_00000004[0x1a] = puVar1;
  in_stack_00000004[0x1b] = 0;
  (*pcVar2)(in_stack_00000004 + 0x1a,in_stack_00000004 + 0x1b);
  in_stack_00000004[0x1c] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1a] + 4))(in_stack_00000004 + 0x1a,in_stack_00000004 + 0x1c);
  in_stack_00000004[0x1d] = puVar1;
  in_stack_00000004[0x1e] = 0;
  (*pcVar2)(in_stack_00000004 + 0x1d,in_stack_00000004 + 0x1e);
  in_stack_00000004[0x1f] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x1d] + 4))(in_stack_00000004 + 0x1d,in_stack_00000004 + 0x1f);
  in_stack_00000004[0x20] = puVar1;
  in_stack_00000004[0x21] = 0;
  (*pcVar2)(in_stack_00000004 + 0x20,in_stack_00000004 + 0x21);
  in_stack_00000004[0x22] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x20] + 4))(in_stack_00000004 + 0x20,in_stack_00000004 + 0x22);
  in_stack_00000004[0x23] = puVar1;
  in_stack_00000004[0x24] = 0;
  (*pcVar2)(in_stack_00000004 + 0x23,in_stack_00000004 + 0x24);
  in_stack_00000004[0x25] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x23] + 4))(in_stack_00000004 + 0x23,in_stack_00000004 + 0x25);
  *(undefined1 *)(in_stack_00000004 + 0x12) = 0;
  *(undefined1 *)(in_stack_00000004 + 0x26) = 0;
  in_stack_00000004[0xe] = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnStart
 * Address: 0071c7f0
 * ---------------------------------------- */

/* CINSBotEscort::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotEscort::OnStart(CINSBotEscort *this,CINSNextBot *param_1,Action *param_2)

{
  int in_stack_0000000c;
  
  SetEscortTarget(this);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined1 *)(in_stack_0000000c + 0x2290) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::Update
 * Address: 0071c350
 * ---------------------------------------- */

/* CINSBotEscort::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotEscort::Update(CINSBotEscort *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  CBaseEntity *this_00;
  char cVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  void *pvVar6;
  CINSNextBot *pCVar7;
  CINSBotEscort *this_01;
  CINSBotEscort *extraout_ECX;
  CINSBotEscort *this_02;
  CINSBotCombat *this_03;
  CBaseEntity *this_04;
  CINSBotEscort *this_05;
  CINSBotEscort *this_06;
  CINSBotEscort *this_07;
  int unaff_EBX;
  float10 fVar8;
  float fVar9;
  CBaseEntity *in_stack_0000000c;
  undefined1 local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x71c35b;
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
  if (piVar3 != (int *)0x0) {
    piVar4 = (int *)(**(code **)(*piVar3 + 0x10 /* CBaseEntity::GetCollideable */))(piVar3);
    cVar2 = (**(code **)(*piVar4 + 0x158))(piVar4);
    if (cVar2 != '\0') {
      piVar4 = (int *)(**(code **)(*piVar3 + 0x10 /* CBaseEntity::GetCollideable */))(piVar3);
      cVar2 = (**(code **)(*piVar4 + 0x118))(piVar4);
      if (cVar2 != '\0') {
        piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
        iVar5 = (**(code **)(*piVar4 + 0xd4 /* IIntention::ShouldAttack */))(piVar4,in_stack_0000000c + 0x2060,piVar3);
        if (iVar5 == 1) {
          pvVar6 = ::operator_new(0x88);
          CINSBotCombat::CINSBotCombat(this_03);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(void **)(param_1 + 4) = pvVar6;
          *(int *)(param_1 + 8) = unaff_EBX + 0x264a98 /* "Combat time!" */ /* "Combat time!" */ /* "Combat time!" */;
          return param_1;
        }
      }
    }
  }
  fVar8 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 100) <= (float)fVar8 &&
      (float)fVar8 != *(float *)((int)param_2 + 100)) {
    if (((*(int *)((int)param_2 + 0x38) < 1) ||
        (this_02 = this_01,
        *(int *)(**(int **)(unaff_EBX + 0x48a545 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x14) < *(int *)((int)param_2 + 0x38))) &&
       (SetEscortTarget(this_01), this_02 = extraout_ECX, *(int *)((int)param_2 + 0x38) == -1)) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x264aa5 /* "Unable to get escort Target" */ /* "Unable to get escort Target" */ /* "Unable to get escort Target" */;
      return param_1;
    }
    piVar3 = (int *)GetEscortTarget(this_02);
    if ((piVar3 == (int *)0x0) || (cVar2 = (**(code **)(*piVar3 + 0x118 /* CBaseEntity::IsAlive */))(piVar3), cVar2 == '\0')) {
      *(undefined4 *)((int)param_2 + 0x38) = 0xffffffff;
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    pcVar1 = *(code **)(*piVar4 + 0x108);
    (**(code **)(*piVar3 + 0x20c /* CINSNextBot::EyePosition */))(local_28,piVar3);
    cVar2 = (*pcVar1)(piVar4,local_28,1);
    *(char *)((int)param_2 + 0x48) = cVar2;
    if (cVar2 == '\0') {
      if ((*(byte *)((int)piVar3 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_04);
      }
      fVar8 = (float10)CINSNextBot::GetTravelDistance
                                 (in_stack_0000000c,piVar3[0x82],piVar3[0x83],piVar3[0x84],
                                  0x469c4000 /* 20000.0f */);
    }
    else {
      this_00 = *(CBaseEntity **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134);
      if ((*(byte *)((int)piVar3 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_00);
      }
      fVar8 = (float10)(*(code *)this_00)(in_stack_0000000c + 0x2060,piVar3 + 0x82);
    }
    *(float *)((int)param_2 + 0x4c) = (float)fVar8;
    UpdateEscortFormations();
    UpdateEscortPostures(this_05,(CINSNextBot *)param_2);
    fVar8 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x7c) <= (float)fVar8 &&
        (float)fVar8 != *(float *)((int)param_2 + 0x7c)) {
      UpdateEscortLookaround(this_06,(CINSNextBot *)param_2);
      fVar8 = (float10)CountdownTimer::Now();
      fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x19c7b9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
      if (*(float *)((int)param_2 + 0x7c) != fVar9) {
        (**(code **)(*(int *)((int)param_2 + 0x74) + 4))((int)param_2 + 0x74,(int)param_2 + 0x7c);
        *(float *)((int)param_2 + 0x7c) = fVar9;
      }
      if (*(int *)((int)param_2 + 0x78) != 0x3f800000 /* 1.0f */) {
        (**(code **)(*(int *)((int)param_2 + 0x74) + 4))((int)param_2 + 0x74,(int)param_2 + 0x78);
        *(undefined4 *)((int)param_2 + 0x78) = 0x3f800000 /* 1.0f */;
      }
    }
    fVar8 = (float10)CountdownTimer::Now();
    fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x20aa9d /* 0.15f */ /* 0.15f */ /* 0.15f */);
    if (*(float *)((int)param_2 + 100) != fVar9) {
      (**(code **)(*(int *)((int)param_2 + 0x5c) + 4))((int)param_2 + 0x5c,(int)param_2 + 100);
      *(float *)((int)param_2 + 100) = fVar9;
    }
    if (*(int *)((int)param_2 + 0x60) != 0x3e19999a /* 0.15f */) {
      (**(code **)(*(int *)((int)param_2 + 0x5c) + 4))((int)param_2 + 0x5c,(int)param_2 + 0x60);
      *(undefined4 *)((int)param_2 + 0x60) = 0x3e19999a /* 0.15f */;
    }
  }
  pCVar7 = (CINSNextBot *)GetEscortFormation(in_stack_0000000c);
  UpdateFormationMovement(this_07,(INSBotEscortFormation *)param_2,pCVar7);
  if (9 < *(int *)(in_stack_0000000c + 0xb324)) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x264c15 /* "Path compute failed. Let's go back to Game Mode" */ /* "Path compute failed. Let's go back to Game Mode" */ /* "Path compute failed. Let's go back to Game Mode" */;
    return param_1;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::OnEnd
 * Address: 00719050
 * ---------------------------------------- */

/* CINSBotEscort::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotEscort::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  
  if (param_2 != (Action *)0x0) {
    cVar1 = (**(code **)(*(int *)param_2 + 0x118))(param_2);
    if (cVar1 != '\0') {
      *(undefined4 *)(param_2 + 0xb32c) = 0xffffffff;
      param_2[0x2290] = (Action)0x0;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnSuspend
 * Address: 00719030
 * ---------------------------------------- */

/* CINSBotEscort::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotEscort::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnResume
 * Address: 0071c7b0
 * ---------------------------------------- */

/* CINSBotEscort::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotEscort::OnResume(CINSBotEscort *this,CINSNextBot *param_1,Action *param_2)

{
  int in_stack_0000000c;
  
  SetEscortTarget(this);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined1 *)(in_stack_0000000c + 0x2290) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::GetName
 * Address: 0071c830
 * ---------------------------------------- */

/* CINSBotEscort::GetName() const */

int CINSBotEscort::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x26456b /* "Escort" */ /* "Escort" */ /* "Escort" */;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldHurry
 * Address: 007192a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotEscort::ShouldHurry(CINSBotEscort *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldHurry
 * Address: 007192b0
 * ---------------------------------------- */

/* CINSBotEscort::ShouldHurry(INextBot const*) const */

int __cdecl CINSBotEscort::ShouldHurry(INextBot *param_1)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CINSNextBot *extraout_ECX;
  CINSPlayer *this;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_00;
  int iVar4;
  undefined8 uVar5;
  
  uVar5 = __i686_get_pc_thunk_bx();
  iVar4 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  if ((iVar4 != 0) && (iVar4 != 0x2060)) {
    piVar2 = (int *)UTIL_PlayerByIndex(*(int *)(param_1 + 0x38));
    this_00 = extraout_ECX;
    if ((piVar2 != (int *)0x0) &&
       ((cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2), this_00 = (CINSNextBot *)this,
        cVar1 != '\0' &&
        (cVar1 = CINSPlayer::IsSprinting(this), this_00 = extraout_ECX_00, cVar1 != '\0')))) {
      return 1;
    }
    iVar3 = 1;
    if (param_1[0x48] != (INextBot)0x0) {
      cVar1 = CINSNextBot::IsInFormation(this_00);
      iVar3 = 2 - (uint)(cVar1 == '\0');
    }
  }
  return iVar3;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldRetreat
 * Address: 007196c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotEscort::ShouldRetreat(CINSBotEscort *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldRetreat
 * Address: 007196d0
 * ---------------------------------------- */

/* CINSBotEscort::ShouldRetreat(INextBot const*) const */

char __cdecl CINSBotEscort::ShouldRetreat(INextBot *param_1)

{
  int iVar1;
  char cVar2;
  CINSNextBot *this;
  CBaseEntity *this_00;
  int extraout_EDX;
  int unaff_EBX;
  float fVar3;
  float fVar4;
  float fVar5;
  
  __i686_get_pc_thunk_bx();
  iVar1 = *(int *)(extraout_EDX + 0x1c /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */);
  if (iVar1 != 0) {
    cVar2 = CINSNextBot::IsSuppressed(this);
    if (cVar2 != '\0') {
      if ((*(byte *)(iVar1 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_00);
      }
      fVar5 = *(float *)(extraout_EDX + 0x3c /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */) - *(float *)(iVar1 + 0x208);
      fVar3 = *(float *)(extraout_EDX + 0x40 /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */) - *(float *)(iVar1 + 0x20c);
      fVar4 = *(float *)(extraout_EDX + 0x44 /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */ /* CINSBotEscort::ShouldRetreat */) - *(float *)(iVar1 + 0x210);
      return (*(float *)(unaff_EBX + 0x222aaf /* 256.0f */ /* 256.0f */ /* 256.0f */) <=
             SQRT(fVar3 * fVar3 + fVar5 * fVar5 + fVar4 * fVar4)) + '\x01';
    }
  }
  return '\x02';
}



/* ----------------------------------------
 * CINSBotEscort::ShouldAttack
 * Address: 00719920
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::ShouldAttack(INextBot const*, CKnownEntity const*) const */

void __thiscall
CINSBotEscort::ShouldAttack(CINSBotEscort *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldAttack
 * Address: 00719930
 * ---------------------------------------- */

/* CINSBotEscort::ShouldAttack(INextBot const*, CKnownEntity const*) const */

uint __thiscall
CINSBotEscort::ShouldAttack(CINSBotEscort *this,INextBot *param_1,CKnownEntity *param_2)

{
  CINSWeapon *pCVar1;
  char cVar2;
  CINSNextBot *this_00;
  int iVar3;
  CINSPlayer *this_01;
  uint extraout_EDX;
  uint uVar4;
  float10 fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  int *in_stack_0000000c;
  undefined4 uVar9;
  
  __i686_get_pc_thunk_bx();
  pCVar1 = *(CINSWeapon **)(param_1 + 0x1c);
  uVar4 = extraout_EDX;
  if (((((pCVar1 != (CINSWeapon *)0x0) && (-1 < *(int *)(param_1 + 0x38))) &&
       (this_00 = (CINSNextBot *)UTIL_EntityByIndex(*(int *)(param_1 + 0x38)),
       this_00 != (CINSNextBot *)0x0)) &&
      ((cVar2 = (**(code **)(*(int *)this_00 + 0x158))(this_00), cVar2 != '\0' &&
       (cVar2 = (**(code **)(*(int *)this_00 + 0x118))(this_00), cVar2 != '\0')))) &&
     (cVar2 = (**(code **)(*(int *)this_00 + 0x158))(this_00), cVar2 != '\0')) {
    uVar9 = 0;
    fVar5 = (float10)CINSNextBot::GetMaxAttackRange(this_00,pCVar1);
    iVar3 = (**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c,uVar9);
    if ((*(byte *)(iVar3 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
    }
    if (((byte)pCVar1[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
    }
    fVar8 = *(float *)(pCVar1 + 0x208) - *(float *)(iVar3 + 0x208);
    fVar6 = *(float *)(pCVar1 + 0x20c) - *(float *)(iVar3 + 0x20c);
    fVar7 = *(float *)(pCVar1 + 0x210) - *(float *)(iVar3 + 0x210);
    if (fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7 < (float)fVar5 * (float)fVar5) {
      cVar2 = (**(code **)(*in_stack_0000000c + 0x38))(in_stack_0000000c);
      if ((cVar2 != '\0') && (cVar2 = CINSNextBot::IsSuppressed(this_00), cVar2 != '\0')) {
        fVar6 = (float)(**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c);
        cVar2 = CINSPlayer::IsThreatAimingTowardMe(this_01,(CBaseEntity *)pCVar1,fVar6);
        if (cVar2 != '\0') {
          return 1;
        }
      }
      uVar9 = 0;
      fVar5 = (float10)CINSNextBot::GetMaxHipFireAttackRange(this_00,pCVar1);
      iVar3 = (**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c,uVar9);
      if ((*(byte *)(iVar3 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
      }
      if (((byte)pCVar1[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
      }
      fVar8 = *(float *)(pCVar1 + 0x208) - *(float *)(iVar3 + 0x208);
      fVar6 = *(float *)(pCVar1 + 0x20c) - *(float *)(iVar3 + 0x20c);
      fVar7 = *(float *)(pCVar1 + 0x210) - *(float *)(iVar3 + 0x210);
      if (fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7 < (float)fVar5 * (float)fVar5) {
        return 1;
      }
    }
    cVar2 = CINSPlayer::IsSprinting((CINSPlayer *)this_00);
    if ((cVar2 != '\0') || (uVar4 = 1, param_1[0x48] == (INextBot)0x0)) {
      uVar4 = (**(code **)(*(int *)pCVar1 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(pCVar1);
      uVar4 = uVar4 & 0xff;
    }
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSBotEscort::OnContact
 * Address: 00719190
 * ---------------------------------------- */

/* CINSBotEscort::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotEscort::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnMoveToSuccess
 * Address: 00719130
 * ---------------------------------------- */

/* CINSBotEscort::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotEscort::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnMoveToFailure
 * Address: 00719160
 * ---------------------------------------- */

/* CINSBotEscort::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotEscort::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnStuck
 * Address: 00719100
 * ---------------------------------------- */

/* CINSBotEscort::OnStuck(CINSNextBot*) */

void CINSBotEscort::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnInjured
 * Address: 007191c0
 * ---------------------------------------- */

/* CINSBotEscort::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotEscort::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnOtherKilled
 * Address: 00719240
 * ---------------------------------------- */

/* CINSBotEscort::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotEscort::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnSight
 * Address: 00719be0
 * ---------------------------------------- */

/* CINSBotEscort::OnSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotEscort::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

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
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (in_stack_00000010[8] != 0) {
    iVar2 = in_stack_00000010[8] - *(int *)(**(int **)(&LAB_0048ccaa + unaff_EBX) + 0x5c) >> 4;
  }
  if (*(int *)(param_2 + 0x38) == iVar2) {
    param_2[0x48] = (CBaseEntity)0x1;
    cVar1 = (**(code **)(*in_stack_00000010 + 0x158))();
  }
  else {
    cVar1 = (**(code **)(*in_stack_00000010 + 0x158))();
  }
  if (((cVar1 != '\0') && (cVar1 = CBaseEntity::InSameTeam(in_stack_0000000c), cVar1 == '\0')) &&
     (iVar2 = CINSPlayer::GetActiveINSWeapon(), iVar2 != 0)) {
    if ((**(int **)(unaff_EBX + 0x48cac2 /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */) != 0) &&
       (iVar2 = TheINSNextBots(), *(char *)(iVar2 + 0x129) != '\0')) {
      pCVar3 = (CBaseEntity *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      iVar2 = CINSBotVision::GetSilhouetteType(this,pCVar3);
      if ((iVar2 == -1) || (iVar2 == 2)) goto LAB_00719c30;
      cVar1 = CINSWeapon::HasFlashlight(this_00);
      if ((cVar1 != '\0') && (cVar1 = CINSWeapon::IsFlashlightOn(this_01), cVar1 == '\0')) {
        fVar5 = (float10)CountdownTimer::Now();
        fVar6 = (float)fVar5 + *(float *)(unaff_EBX + 0x20ab76 /* 5.0f */ /* 5.0f */ /* 5.0f */);
        if (*(float *)(param_2 + 0x70) != fVar6) {
          (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x70);
          *(float *)(param_2 + 0x70) = fVar6;
        }
        if (*(int *)(param_2 + 0x6c) != 0x40a00000 /* 5.0f */) {
          (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x6c);
          *(undefined4 *)(param_2 + 0x6c) = 0x40a00000 /* 5.0f */;
          param_2 = (CBaseEntity *)extraout_ECX;
        }
        CINSWeapon::ToggleFlashlight((CINSWeapon *)param_2);
      }
    }
    piVar4 = (int *)TheINSNextBots();
    (**(code **)(*piVar4 + 0x38))(piVar4,in_stack_0000000c);
  }
LAB_00719c30:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::OnLostSight
 * Address: 00719090
 * ---------------------------------------- */

/* CINSBotEscort::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotEscort::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int extraout_EDX;
  int iVar1;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  iVar1 = 0;
  if (*(int *)(extraout_EDX + 0x20 /* CINSBotEscort::OnLostSight */ /* CINSBotEscort::OnLostSight */ /* CINSBotEscort::OnLostSight */) != 0) {
    iVar1 = *(int *)(extraout_EDX + 0x20 /* CINSBotEscort::OnLostSight */ /* CINSBotEscort::OnLostSight */ /* CINSBotEscort::OnLostSight */) - *(int *)(**(int **)(unaff_EBX + 0x48d7ff /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
  }
  if (*(int *)(param_2 + 0x38) == iVar1) {
    param_2[0x48] = (CBaseEntity)0x0;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnWeaponFired
 * Address: 00719dc0
 * ---------------------------------------- */

/* CINSBotEscort::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) [clone
   .part.110] */

void __fastcall
CINSBotEscort::OnWeaponFired
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  code *pcVar1;
  char cVar2;
  undefined4 *in_EAX;
  float *pfVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  CNavMesh *this;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBasePlayer *this_04;
  CNavArea *this_05;
  CNavMesh *extraout_ECX;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  undefined4 uVar13;
  Vector local_100 [12];
  float local_f4;
  undefined4 local_f0;
  undefined4 local_b4;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_6c;
  undefined1 local_68;
  undefined1 local_67;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x719dcf;
  __i686_get_pc_thunk_bx();
  pfVar3 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
  pfVar4 = (float *)(**(code **)(*(int *)param_2 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_2);
  fVar10 = SQRT((pfVar4[1] - pfVar3[1]) * (pfVar4[1] - pfVar3[1]) +
                (*pfVar4 - *pfVar3) * (*pfVar4 - *pfVar3) +
                (pfVar4[2] - pfVar3[2]) * (pfVar4[2] - pfVar3[2]));
  piVar5 = (int *)(**(code **)(*(int *)param_2 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_2);
  cVar2 = (**(code **)(*piVar5 + 300))(piVar5,param_3,0);
  if (cVar2 != '\0') {
    iVar6 = CBaseEntity::GetTeamNumber(this_00);
    iVar7 = CBaseEntity::GetTeamNumber(this_01);
    if ((iVar6 == iVar7) || (*(float *)(unaff_EBX + 0x267201 /* 6000.0f */ /* 6000.0f */ /* 6000.0f */) <= fVar10)) {
      iVar6 = CBaseEntity::GetTeamNumber(this_02);
      iVar7 = CBaseEntity::GetTeamNumber(this_03);
      if (iVar6 == iVar7) {
        iVar6 = (**(code **)(*(int *)param_2 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_2);
        fVar11 = *(float *)(**(int **)(unaff_EBX + 0x48cad1 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc) - *(float *)(iVar6 + 600);
        if ((*(float *)(&DAT_0020a99d + unaff_EBX) <= fVar11 &&
             fVar11 != *(float *)(&DAT_0020a99d + unaff_EBX)) &&
           (fVar10 < *(float *)(unaff_EBX + 0x20b241 /* 1000.0f */ /* 1000.0f */ /* 1000.0f */))) {
          cVar2 = (**(code **)(*(int *)param_3 + 0x158 /* CBasePlayer::IsPlayer */))(param_3);
          if (cVar2 != '\0') {
            local_b4 = 0;
            pfVar3 = *(float **)(unaff_EBX + 0x48c7fd /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
            local_40 = *pfVar3;
            local_3c = pfVar3[1];
            local_38 = pfVar3[2];
            uVar13 = 0;
            uVar8 = 0;
            CBasePlayer::EyeVectors(this_04,(Vector *)param_3,(Vector *)&local_40,(Vector *)0x0);
            fVar10 = *(float *)(unaff_EBX + 0x20b249 /* 400.0f */ /* 400.0f */ /* 400.0f */);
            fVar12 = local_40 * fVar10;
            fVar11 = local_3c * fVar10;
            fVar10 = fVar10 * local_38;
            (**(code **)(*(int *)param_3 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,param_3,uVar8,uVar13);
            local_3c = fVar11 + local_24;
            local_38 = fVar10 + local_20;
            local_40 = fVar12 + local_28;
            (**(code **)(*(int *)param_3 + 0x20c /* CINSNextBot::EyePosition */))(&local_34,param_3);
            local_6c = 0;
            local_ac = local_34;
            local_a8 = local_30;
            local_9c = local_40 - local_34;
            local_98 = local_3c - local_30;
            local_68 = 1;
            local_a4 = local_2c;
            local_94 = local_38 - local_2c;
            local_74 = 0;
            local_78 = 0;
            local_7c = 0;
            local_67 = local_98 * local_98 + local_9c * local_9c + local_94 * local_94 != 0.0;
            local_84 = 0;
            local_88 = 0;
            local_8c = 0;
            CTraceFilterSimple::CTraceFilterSimple
                      ((CTraceFilterSimple *)&local_50,(IHandleEntity *)&local_50,(int)param_3,
                       (_func_bool_IHandleEntity_ptr_int *)0x0);
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x48c9a9 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x48c9a9 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_ac,0x2006241,&local_50,
                       local_100);
            piVar5 = *(int **)(&DAT_0048cc71 + unaff_EBX);
            this = (CNavMesh *)(**(code **)(*piVar5 + 0x40))(piVar5);
            if (this != (CNavMesh *)0x0) {
              iVar6 = (**(code **)(*piVar5 + 0x40))(piVar5);
              fVar10 = 0.5;
              if (iVar6 != 0) {
                fVar10 = -1.0;
              }
              DebugDrawLine(local_100,(Vector *)&local_f4,0xff,0,0,true,fVar10);
              this = extraout_ECX;
            }
            fVar10 = (float)CNavMesh::GetNearestNavAreaFast
                                      (this,(Vector *)**(undefined4 **)(&DAT_0048c8e9 + unaff_EBX),
                                       SUB41(&local_f4,0));
            if (fVar10 != 0.0) {
              fVar11 = local_f4;
              uVar8 = local_f0;
              fVar9 = (float10)CNavArea::GetZ(this_05,fVar10,local_f4);
              local_50 = local_f4;
              local_48 = (float)fVar9 + *(float *)(unaff_EBX + 0x2442a9 /* 69.0f */ /* 69.0f */ /* 69.0f */);
              local_4c = local_f0;
              piVar5 = (int *)(**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2,fVar11,uVar8);
              (**(code **)(*piVar5 + 0xd4 /* PlayerBody::AimHeadTowards */))(piVar5,&local_50,3,0x3f19999a /* 0.6f */,0,unaff_EBX + 0x267075 /* "Looking at where friendly shooter is aiming" */ /* "Looking at where friendly shooter is aiming" */ /* "Looking at where friendly shooter is aiming" */);
            }
          }
        }
      }
    }
    else {
      piVar5 = (int *)(**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
      pcVar1 = *(code **)(*piVar5 + 0xd4);
      uVar8 = (**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
      (*pcVar1)(piVar5,uVar8,3,0x3ecccccd /* 0.4f */,0,unaff_EBX + 0x26704d /* "Looking in direction of enemy gun fire" */ /* "Looking in direction of enemy gun fire" */ /* "Looking in direction of enemy gun fire" */);
    }
  }
  *in_EAX = 0;
  in_EAX[1] = 0;
  in_EAX[2] = 0;
  in_EAX[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::OnWeaponFired
 * Address: 0071a2e0
 * ---------------------------------------- */

/* CINSBotEscort::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

CINSNextBot * __thiscall
CINSBotEscort::OnWeaponFired
          (CINSBotEscort *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CBaseCombatWeapon *param_3)

{
  char cVar1;
  CINSNextBot *extraout_ECX;
  CBaseCombatWeapon *in_stack_00000010;
  
  if ((in_stack_00000010 != (CBaseCombatWeapon *)0x0) && (param_3 != (CBaseCombatWeapon *)0x0)) {
    cVar1 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3);
    if (cVar1 == '\0') {
      OnWeaponFired(extraout_ECX,(CBaseCombatCharacter *)param_3,in_stack_00000010);
      return param_1;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::AddToEscortFormation
 * Address: 0071b5c0
 * ---------------------------------------- */

/* CINSBotEscort::AddToEscortFormation(CINSNextBot*) */

int __cdecl CINSBotEscort::AddToEscortFormation(CINSNextBot *param_1)

{
  CBaseEntity *this;
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int unaff_EBX;
  int iVar7;
  int iVar8;
  
  __i686_get_pc_thunk_bx();
  if (0 < *(int *)(unaff_EBX + 0x5d0f7c /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */)) {
    iVar8 = 0;
    do {
      this = (CBaseEntity *)(iVar8 * 4);
      iVar7 = *(int *)(*(int *)(unaff_EBX + 0x5d0f70 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */) + iVar8 * 4);
      piVar3 = (int *)UTIL_PlayerByIndex(*(int *)(iVar7 + 8));
      if (((piVar3 != (int *)0x0) &&
          (cVar2 = (**(code **)(*piVar3 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar3),
          *(int *)(iVar7 + 0x2c) < (int)((-(uint)(cVar2 == '\0') & 2) + 3))) &&
         (iVar7 = *(int *)(*(int *)(this + *(int *)(unaff_EBX + 0x5d0f70 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */)) + 4),
         iVar4 = CBaseEntity::GetTeamNumber(this), iVar7 == iVar4)) {
        iVar7 = 0;
        if (*(int *)(param_1 + 0x20) != 0) {
          iVar7 = *(int *)(param_1 + 0x20) -
                  *(int *)(**(int **)(CGameWeaponManager::~CGameWeaponManager + unaff_EBX) + 0x5c)
                  >> 4;
        }
        iVar4 = *(int *)(this + *(int *)(unaff_EBX + 0x5d0f70 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */));
        if (iVar7 == *(int *)(iVar4 + 8)) {
          return -1;
        }
        if (0 < *(int *)(iVar4 + 0x2c)) {
          iVar5 = 0;
          iVar6 = 0x18;
          iVar1 = **(int **)(iVar4 + 0x20);
          while( true ) {
            if (iVar7 == iVar1) {
              return -1;
            }
            iVar5 = iVar5 + 1;
            if (iVar5 == *(int *)(iVar4 + 0x2c)) break;
            iVar1 = *(int *)((int)*(int **)(iVar4 + 0x20) + iVar6);
            iVar6 = iVar6 + 0x18;
          }
        }
        piVar3 = (int *)UTIL_PlayerByIndex(*(int *)(iVar4 + 8));
        if (piVar3 == (int *)0x0) {
          return -1;
        }
        cVar2 = (**(code **)(*piVar3 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar3);
        if ((int)((-(uint)(cVar2 == '\0') & 2) + 3) <= (int)*(t_INSBotEscortMember **)(iVar4 + 0x2c)
           ) {
          return -1;
        }
        iVar7 = CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::InsertBefore
                          (*(CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>
                             **)(*(int *)(unaff_EBX + 0x48affc /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4),iVar4 + 0x20,
                           *(t_INSBotEscortMember **)(iVar4 + 0x2c));
        if (iVar7 == -1) {
          return -1;
        }
        CINSNextBot::SetEscortFormation(param_1,(INSBotEscortFormation *)param_1);
        return iVar8;
      }
      iVar8 = iVar8 + 1;
    } while (iVar8 < *(int *)(unaff_EBX + 0x5d0f7c /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */));
  }
  return -1;
}



/* ----------------------------------------
 * CINSBotEscort::GetEscortFormation
 * Address: 0071a620
 * ---------------------------------------- */

/* CINSBotEscort::GetEscortFormation(CBaseEntity*) */

int __cdecl CINSBotEscort::GetEscortFormation(CBaseEntity *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int unaff_EBX;
  int iVar6;
  int local_1c;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x5d1f21 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
  if ((iVar2 != 0) && (0 < iVar2)) {
    local_1c = 0;
    do {
      iVar6 = 0;
      if (*(int *)(param_1 + 0x20) != 0) {
        iVar6 = *(int *)(param_1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48c275 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
      }
      iVar3 = *(int *)(*(int *)(unaff_EBX + 0x5d1f15 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */) + local_1c * 4);
      if (iVar6 == *(int *)(iVar3 + 8)) {
        return iVar3;
      }
      if (0 < *(int *)(iVar3 + 0x2c)) {
        if (iVar6 == **(int **)(iVar3 + 0x20)) {
          return iVar3;
        }
        iVar5 = 0x18;
        iVar4 = 0;
        while (iVar4 = iVar4 + 1, iVar4 != *(int *)(iVar3 + 0x2c)) {
          piVar1 = (int *)((int)*(int **)(iVar3 + 0x20) + iVar5);
          iVar5 = iVar5 + 0x18;
          if (iVar6 == *piVar1) {
            return iVar3;
          }
        }
      }
      local_1c = local_1c + 1;
    } while (local_1c != iVar2);
  }
  return 0;
}



/* ----------------------------------------
 * CINSBotEscort::GetEscortTarget
 * Address: 0071a850
 * ---------------------------------------- */

/* CINSBotEscort::GetEscortTarget() */

void __thiscall CINSBotEscort::GetEscortTarget(CINSBotEscort *this)

{
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  UTIL_PlayerByIndex(*(int *)(in_stack_00000004 + 0x38));
  return;
}



/* ----------------------------------------
 * CINSBotEscort::HasEscortTarget
 * Address: 0071a700
 * ---------------------------------------- */

/* CINSBotEscort::HasEscortTarget(CINSNextBot*) */

bool __cdecl CINSBotEscort::HasEscortTarget(CINSNextBot *param_1)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  CBaseEntity *pCVar5;
  int *piVar6;
  CBaseEntity *this;
  CINSRules *this_00;
  bool bVar7;
  int iVar8;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  iVar3 = CBaseEntity::GetTeamNumber(this);
  iVar4 = CINSRules::GetHumanTeam(this_00);
  if (iVar3 != iVar4) {
    return false;
  }
  pcVar1 = *(char **)(param_1 + 0xb334);
  if ((pcVar1 != (char *)0x0) && (*pcVar1 != '\0')) {
    iVar3 = 0;
    if (*(int *)(param_1 + 0x20) != 0) {
      iVar3 = *(int *)(param_1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48c18f /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    if (iVar3 == *(int *)(pcVar1 + 8)) {
      return true;
    }
    if (0 < *(int *)(pcVar1 + 0x2c)) {
      if (iVar3 == **(int **)(pcVar1 + 0x20)) {
        return true;
      }
      iVar8 = 0x18;
      iVar4 = 0;
      while (iVar4 = iVar4 + 1, iVar4 != *(int *)(pcVar1 + 0x2c)) {
        piVar6 = (int *)((int)*(int **)(pcVar1 + 0x20) + iVar8);
        iVar8 = iVar8 + 0x18;
        if (iVar3 == *piVar6) {
          return true;
        }
      }
    }
    CINSNextBot::SetEscortFormation(param_1,(INSBotEscortFormation *)param_1);
  }
  pCVar5 = (CBaseEntity *)UTIL_INSGetHumanTeammate((CINSPlayer *)param_1);
  bVar7 = false;
  if (pCVar5 != (CBaseEntity *)0x0) {
    iVar3 = GetEscortFormation(pCVar5);
    bVar7 = true;
    if (iVar3 != 0) {
      piVar6 = (int *)UTIL_PlayerByIndex(*(int *)(iVar3 + 8));
      bVar7 = false;
      if (piVar6 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar6 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar6);
        return *(int *)(iVar3 + 0x2c) < (int)((-(uint)(cVar2 == '\0') & 2) + 3);
      }
    }
  }
  return bVar7;
}



/* ----------------------------------------
 * CINSBotEscort::OnCommandAttack
 * Address: 007191f0
 * ---------------------------------------- */

/* CINSBotEscort::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotEscort::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int *piVar1;
  int *in_stack_0000000c;
  undefined4 in_stack_00000010;
  
  piVar1 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  (**(code **)(*piVar1 + 0xe8 /* IVision::AddKnownEntity */))(piVar1,in_stack_00000010);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotEscort::OnHeardFootsteps
 * Address: 007194c0
 * ---------------------------------------- */

/* CINSBotEscort::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

CINSNextBot * __thiscall
CINSBotEscort::OnHeardFootsteps
          (CINSBotEscort *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

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
         (iVar2 = **(int **)(unaff_EBX + 0x48d1e4 /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */), iVar2 != 0)) &&
        (iVar3 = TheINSNextBots(), *(char *)(iVar3 + 0x129) != '\0')))) {
      pCVar4 = (CNavMesh *)param_3;
      if (((byte)param_3[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)param_3);
        pCVar4 = extraout_ECX;
      }
      iVar2 = CNavMesh::GetNearestNavArea(pCVar4,iVar2,param_3 + 0x208,0,0x461c4000 /* 10000.0f */,0,1,0);
      if (((iVar2 != 0) &&
          ((*(float *)(iVar2 + 0xe4) + *(float *)(iVar2 + 0xe0) + *(float *)(iVar2 + 0xe8) +
           *(float *)(iVar2 + 0xec)) * *(float *)(unaff_EBX + 0x20a5b8 /* 0.25f */ /* 0.25f */ /* 0.25f */) <
           *(float *)(unaff_EBX + 0x20b284 /* 0.5f */ /* 0.5f */ /* 0.5f */))) &&
         ((cVar1 = CINSWeapon::HasFlashlight(this_01), cVar1 != '\0' &&
          (cVar1 = CINSWeapon::IsFlashlightOn(this_02), cVar1 == '\0')))) {
        fVar5 = (float10)CountdownTimer::Now();
        fVar6 = (float)fVar5 + *(float *)(unaff_EBX + 0x20b298 /* 5.0f */ /* 5.0f */ /* 5.0f */);
        if (*(float *)(param_2 + 0x70) != fVar6) {
          (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x70);
          *(float *)(param_2 + 0x70) = fVar6;
        }
        if (*(int *)(param_2 + 0x6c) != 0x40a00000 /* 5.0f */) {
          (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x6c);
          *(undefined4 *)(param_2 + 0x6c) = 0x40a00000 /* 5.0f */;
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
 * CINSBotEscort::OnNavAreaChanged
 * Address: 007197b0
 * ---------------------------------------- */

/* CINSBotEscort::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

CINSNextBot * __thiscall
CINSBotEscort::OnNavAreaChanged
          (CINSBotEscort *this,CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

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
        *(float *)(unaff_EBX + 0x20a2c8 /* 0.25f */ /* 0.25f */ /* 0.25f */) < *(float *)(unaff_EBX + 0x20f9f0 /* 0.35f */ /* 0.35f */ /* 0.35f */))) {
      cVar1 = CINSPlayer::IsSprinting(this_00);
      if (cVar1 == '\0') {
        iVar2 = CINSPlayer::GetActiveINSWeapon();
        if (iVar2 != 0) {
          cVar1 = CINSWeapon::HasFlashlight(this_01);
          if (cVar1 != '\0') {
            cVar1 = CINSWeapon::IsFlashlightOn(this_02);
            if (cVar1 == '\0') {
              fVar3 = (float10)CountdownTimer::Now();
              fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x19f7b8 /* 3.0f */ /* 3.0f */ /* 3.0f */);
              if (*(float *)(param_2 + 0x70) != fVar4) {
                (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x70);
                *(float *)(param_2 + 0x70) = fVar4;
              }
              if (*(int *)(param_2 + 0x6c) != 0x40400000 /* 3.0f */) {
                (**(code **)(*(int *)(param_2 + 0x68) + 4))(param_2 + 0x68,param_2 + 0x6c);
                *(undefined4 *)(param_2 + 0x6c) = 0x40400000 /* 3.0f */;
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
 * CINSBotEscort::OnSeeSomethingSuspicious
 * Address: 00719270
 * ---------------------------------------- */

/* CINSBotEscort::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotEscort::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotEscort::SetEscortTarget
 * Address: 0071b790
 * ---------------------------------------- */

/* CINSBotEscort::SetEscortTarget() */

void __thiscall CINSBotEscort::SetEscortTarget(CINSBotEscort *this)

{
  CBaseEntity *pCVar1;
  CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>> *pCVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  CINSNextBot *pCVar6;
  int *piVar7;
  CINSNextBot *pCVar8;
  int iVar9;
  undefined1 *puVar10;
  int iVar11;
  undefined4 uVar12;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CBaseEntity *this_03;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *this_06;
  CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *pCVar13;
  CBaseEntity *this_07;
  CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *extraout_ECX_03;
  CBaseEntity *this_08;
  CBaseEntity *this_09;
  CINSNextBot *extraout_ECX_04;
  CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *extraout_ECX_05;
  CBaseEntity *this_10;
  int iVar14;
  int unaff_EBX;
  CINSNextBot *pCVar15;
  int iVar16;
  CINSNextBot *in_stack_00000004;
  INSBotEscortFormation **ppIVar17;
  undefined1 **ppuVar18;
  int local_98;
  CINSNextBot *local_94;
  undefined1 *local_24;
  undefined1 *local_20 [3];
  undefined4 uStack_14;
  
  uStack_14 = 0x71b79b;
  __i686_get_pc_thunk_bx();
  pCVar1 = *(CBaseEntity **)(in_stack_00000004 + 0x1c);
  if (pCVar1 == (CBaseEntity *)0x0) {
    return;
  }
  local_94 = (CINSNextBot *)CINSNextBot::GetEscortTarget(this_00);
  if (local_94 == (CINSNextBot *)0x0) {
    local_94 = (CINSNextBot *)UTIL_INSGetHumanTeammate((CINSPlayer *)pCVar1);
    iVar4 = GetEscortFormation(pCVar1);
    if (local_94 == (CINSNextBot *)0x0) {
      return;
    }
  }
  else {
    iVar4 = GetEscortFormation(pCVar1);
  }
  iVar5 = *(int *)(unaff_EBX + 0x5d0db1 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
  if (iVar5 == 0) {
    iVar4 = (**(code **)(*(int *)(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */) + 0x40))(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */);
    if (iVar4 != 0) {
      CBaseEntity::GetDebugName(this_03);
      CBaseEntity::GetDebugName(this_07);
      DevMsg((char *)(unaff_EBX + 0x265711 /* "Bot%s Creating first formation for nearest player: %s" */ /* "Bot%s Creating first formation for nearest player: %s" */ /* "Bot%s Creating first formation for nearest player: %s" */));
    }
    iVar4 = 0;
    if (*(int *)(local_94 + 0x20) != 0) {
      iVar4 = *(int *)(local_94 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    puVar10 = (undefined1 *)::operator_new(0x40);
    *(int *)(puVar10 + 8) = iVar4;
    pCVar2 = *(CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>> **)
              (unaff_EBX + 0x48ae31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    *(undefined4 *)(puVar10 + 0x20) = 0;
    *(undefined4 *)(puVar10 + 0x24) = 0;
    *(undefined4 *)(puVar10 + 0x28) = 0;
    uVar12 = *(undefined4 *)pCVar2;
    *(undefined4 *)(puVar10 + 0x2c) = 0;
    *(undefined4 *)(puVar10 + 0x30) = 0;
    *(undefined4 *)(puVar10 + 0x38) = 0;
    *(undefined4 *)(puVar10 + 0x14) = uVar12;
    *(undefined4 *)(puVar10 + 0x18) = *(undefined4 *)(pCVar2 + 4);
    *(undefined4 *)(puVar10 + 0x1c) = *(undefined4 *)(pCVar2 + 8);
    *(int *)(puVar10 + 0x34) = unaff_EBX + 0x40ca1d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    CountdownTimer::NetworkStateChanged(puVar10 + 0x34);
    *(undefined4 *)(puVar10 + 0x3c) = 0xbf800000 /* -1.0f */;
    (**(code **)(*(int *)(puVar10 + 0x34) + 4))(puVar10 + 0x34,puVar10 + 0x3c);
    piVar7 = (int *)UTIL_PlayerByIndex(iVar4);
    pCVar13 = (CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *)
              extraout_ECX_01;
    if ((piVar7 == (int *)0x0) ||
       (cVar3 = (**(code **)(*piVar7 + 0x118 /* CBaseEntity::IsAlive */))(piVar7),
       pCVar13 = (CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *)
                 this_04, cVar3 == '\0')) {
      *puVar10 = 0;
    }
    else {
      uVar12 = CBaseEntity::GetTeamNumber(this_04);
      *(undefined4 *)(puVar10 + 4) = uVar12;
      *puVar10 = 1;
      pCVar13 = extraout_ECX_03;
    }
    ppuVar18 = &local_24;
    ppIVar17 = *(INSBotEscortFormation ***)(unaff_EBX + 0x5d0db1 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
    local_24 = puVar10;
    CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>>::InsertBefore
              (pCVar13,unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */,ppIVar17);
    iVar4 = GetEscortFormation((CBaseEntity *)local_94);
    if (iVar4 == 0) {
      return;
    }
    iVar5 = 0;
    if (*(int *)(pCVar1 + 0x20) != 0) {
      iVar5 = *(int *)(pCVar1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    if (iVar5 == *(int *)(iVar4 + 8)) {
      return;
    }
    if (0 < *(int *)(iVar4 + 0x2c)) {
      iVar9 = 0x18;
      iVar14 = 0;
      iVar16 = **(int **)(iVar4 + 0x20);
      while( true ) {
        if (iVar5 == iVar16) {
          return;
        }
        iVar14 = iVar14 + 1;
        if (iVar14 == *(int *)(iVar4 + 0x2c)) break;
        iVar16 = *(int *)((int)*(int **)(iVar4 + 0x20) + iVar9);
        iVar9 = iVar9 + 0x18;
      }
    }
    piVar7 = (int *)UTIL_PlayerByIndex(*(int *)(iVar4 + 8));
    if (piVar7 == (int *)0x0) {
      return;
    }
    cVar3 = (**(code **)(*piVar7 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar7,ppIVar17,ppuVar18);
    if ((int)((-(uint)(cVar3 == '\0') & 2) + 3) <= (int)*(t_INSBotEscortMember **)(iVar4 + 0x2c)) {
      return;
    }
    iVar5 = CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::InsertBefore
                      (pCVar2,iVar4 + 0x20,*(t_INSBotEscortMember **)(iVar4 + 0x2c));
    if (iVar5 == -1) {
      return;
    }
    *(undefined4 *)(in_stack_00000004 + 0x38) = *(undefined4 *)(iVar4 + 8);
    CINSNextBot::SetEscortFormation(in_stack_00000004,(INSBotEscortFormation *)pCVar1);
    return;
  }
  if (iVar4 == 0) {
    if (iVar5 < 1) {
      return;
    }
    local_98 = 0;
    while( true ) {
      iVar4 = 0;
      if (*(int *)(local_94 + 0x20) != 0) {
        iVar4 = *(int *)(local_94 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
      }
      iVar16 = *(int *)(*(int *)(unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */) + local_98 * 4);
      if (iVar4 == *(int *)(iVar16 + 8)) break;
      if (0 < *(int *)(iVar16 + 0x2c)) {
        if (iVar4 == **(int **)(iVar16 + 0x20)) break;
        iVar14 = 0x18;
        iVar9 = 0;
        while (iVar9 = iVar9 + 1, iVar9 != *(int *)(iVar16 + 0x2c)) {
          piVar7 = (int *)((int)*(int **)(iVar16 + 0x20) + iVar14);
          iVar14 = iVar14 + 0x18;
          if (iVar4 == *piVar7) goto LAB_0071c050;
        }
      }
      local_98 = local_98 + 1;
      if (local_98 == iVar5) {
        return;
      }
    }
LAB_0071c050:
    iVar4 = (**(code **)(*(int *)(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */) + 0x40))(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */);
    if (iVar4 != 0) {
      CBaseEntity::GetDebugName(this_08);
      CBaseEntity::GetDebugName(this_09);
      DevMsg((char *)(unaff_EBX + 0x2657a9 /* "Bot%s Joining nearest players formation: %s" */ /* "Bot%s Joining nearest players formation: %s" */ /* "Bot%s Joining nearest players formation: %s" */));
    }
    iVar4 = 0;
    if (*(int *)(pCVar1 + 0x20) != 0) {
      iVar4 = *(int *)(pCVar1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    local_94 = *(CINSNextBot **)(unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */);
    iVar5 = *(int *)((int)local_94 + local_98 * 4);
    if (iVar4 != *(int *)(iVar5 + 8)) {
      if (*(int *)(iVar5 + 0x2c) < 1) {
LAB_0071c121:
        piVar7 = (int *)UTIL_PlayerByIndex(*(int *)(iVar5 + 8));
        local_94 = *(CINSNextBot **)(unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */);
        if (piVar7 != (int *)0x0) {
          cVar3 = (**(code **)(*piVar7 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar7);
          if ((int)*(t_INSBotEscortMember **)(iVar5 + 0x2c) <
              (int)((-(uint)(cVar3 == '\0') & 2) + 3)) {
            CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::InsertBefore
                      (*(CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>> **)
                        (*(int *)(unaff_EBX + 0x48ae31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4),iVar5 + 0x20,
                       *(t_INSBotEscortMember **)(iVar5 + 0x2c));
            local_94 = *(CINSNextBot **)(unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */);
          }
          else {
            local_94 = *(CINSNextBot **)(unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */);
          }
        }
      }
      else {
        iVar9 = 0;
        iVar14 = 0x18;
        iVar16 = **(int **)(iVar5 + 0x20);
        while (iVar4 != iVar16) {
          iVar9 = iVar9 + 1;
          if (iVar9 == *(int *)(iVar5 + 0x2c)) goto LAB_0071c121;
          piVar7 = (int *)((int)*(int **)(iVar5 + 0x20) + iVar14);
          iVar14 = iVar14 + 0x18;
          iVar16 = *piVar7;
        }
      }
    }
    *(undefined4 *)(in_stack_00000004 + 0x38) =
         *(undefined4 *)(*(int *)((int)local_94 + local_98 * 4) + 8);
    return;
  }
  iVar5 = 0;
  if (*(int *)(local_94 + 0x20) != 0) {
    iVar5 = *(int *)(local_94 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
  }
  if (*(int *)(iVar4 + 8) == iVar5) {
    *(int *)(in_stack_00000004 + 0x38) = *(int *)(iVar4 + 8);
    return;
  }
  pCVar6 = (CINSNextBot *)GetEscortFormation((CBaseEntity *)local_94);
  if (pCVar6 == (CINSNextBot *)0x0) {
    iVar4 = (**(code **)(*(int *)(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */) + 0x40))(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */);
    if (iVar4 != 0) {
      CBaseEntity::GetDebugName(this_05);
      CBaseEntity::GetDebugName(this_10);
      DevMsg(&UNK_00265779 + unaff_EBX);
    }
    iVar4 = 0;
    if (*(int *)(local_94 + 0x20) != 0) {
      iVar4 = *(int *)(local_94 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    puVar10 = (undefined1 *)::operator_new(0x40);
    *(int *)(puVar10 + 8) = iVar4;
    pCVar2 = *(CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>> **)
              (unaff_EBX + 0x48ae31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    *(undefined4 *)(puVar10 + 0x20) = 0;
    *(undefined4 *)(puVar10 + 0x24) = 0;
    *(undefined4 *)(puVar10 + 0x28) = 0;
    uVar12 = *(undefined4 *)pCVar2;
    *(undefined4 *)(puVar10 + 0x2c) = 0;
    *(undefined4 *)(puVar10 + 0x30) = 0;
    *(undefined4 *)(puVar10 + 0x38) = 0;
    *(undefined4 *)(puVar10 + 0x14) = uVar12;
    *(undefined4 *)(puVar10 + 0x18) = *(undefined4 *)(pCVar2 + 4);
    *(undefined4 *)(puVar10 + 0x1c) = *(undefined4 *)(pCVar2 + 8);
    *(int *)(puVar10 + 0x34) = unaff_EBX + 0x40ca1d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    CountdownTimer::NetworkStateChanged(puVar10 + 0x34);
    *(undefined4 *)(puVar10 + 0x3c) = 0xbf800000 /* -1.0f */;
    (**(code **)(*(int *)(puVar10 + 0x34) + 4))(puVar10 + 0x34,puVar10 + 0x3c);
    piVar7 = (int *)UTIL_PlayerByIndex(iVar4);
    pCVar13 = (CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *)
              extraout_ECX_02;
    if ((piVar7 == (int *)0x0) ||
       (cVar3 = (**(code **)(*piVar7 + 0x118 /* CBaseEntity::IsAlive */))(piVar7),
       pCVar13 = (CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>> *)
                 this_06, cVar3 == '\0')) {
      *puVar10 = 0;
    }
    else {
      uVar12 = CBaseEntity::GetTeamNumber(this_06);
      *(undefined4 *)(puVar10 + 4) = uVar12;
      *puVar10 = 1;
      pCVar13 = extraout_ECX_05;
    }
    ppuVar18 = local_20;
    local_20[0] = puVar10;
    CUtlVector<INSBotEscortFormation*,CUtlMemory<INSBotEscortFormation*,int>>::InsertBefore
              (pCVar13,unaff_EBX + 0x5d0da5 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */,*(INSBotEscortFormation ***)(unaff_EBX + 0x5d0db1 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */));
    iVar4 = GetEscortFormation((CBaseEntity *)local_94);
    if (iVar4 == 0) {
      return;
    }
    iVar16 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x38) = *(undefined4 *)(iVar4 + 8);
    iVar5 = iVar4;
    CINSNextBot::SetEscortFormation(in_stack_00000004,(INSBotEscortFormation *)pCVar1);
    if (*(int *)(pCVar1 + 0x20) != 0) {
      iVar16 = *(int *)(pCVar1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    if (iVar16 == *(int *)(iVar4 + 8)) {
      return;
    }
    if (0 < *(int *)(iVar4 + 0x2c)) {
      iVar14 = 0x18;
      iVar11 = 0;
      iVar9 = **(int **)(iVar4 + 0x20);
      while( true ) {
        if (iVar16 == iVar9) {
          return;
        }
        iVar11 = iVar11 + 1;
        if (iVar11 == *(int *)(iVar4 + 0x2c)) break;
        iVar9 = *(int *)((int)*(int **)(iVar4 + 0x20) + iVar14);
        iVar14 = iVar14 + 0x18;
      }
    }
    piVar7 = (int *)UTIL_PlayerByIndex(*(int *)(iVar4 + 8));
    if (piVar7 == (int *)0x0) {
      return;
    }
    cVar3 = (**(code **)(*piVar7 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar7,iVar5,ppuVar18);
    if ((int)((-(uint)(cVar3 == '\0') & 2) + 3) <= (int)*(t_INSBotEscortMember **)(iVar4 + 0x2c)) {
      return;
    }
    CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::InsertBefore
              (pCVar2,iVar4 + 0x20,*(t_INSBotEscortMember **)(iVar4 + 0x2c));
    return;
  }
  piVar7 = (int *)UTIL_PlayerByIndex(*(int *)(pCVar6 + 8));
  if (piVar7 == (int *)0x0) {
    return;
  }
  cVar3 = (**(code **)(*piVar7 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar7);
  if ((int)((-(uint)(cVar3 == '\0') & 2) + 3) <= *(int *)(pCVar6 + 0x2c)) {
    return;
  }
  iVar5 = (**(code **)(*(int *)(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */) + 0x40))(unaff_EBX + 0x5d0dc5 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */);
  if (iVar5 != 0) {
    CBaseEntity::GetDebugName(this_01);
    DevMsg((char *)(unaff_EBX + 0x265749 /* "Bot:%s leaving old and joining new Formation" */ /* "Bot:%s leaving old and joining new Formation" */ /* "Bot:%s leaving old and joining new Formation" */));
  }
  local_94 = (CINSNextBot *)0x0;
  local_98 = *(int *)(pCVar1 + 0x20);
  if (local_98 != 0) {
    local_94 = (CINSNextBot *)(local_98 - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4);
  }
  pCVar15 = *(CINSNextBot **)(iVar4 + 0x2c);
  this_02 = pCVar15;
  if (0 < (int)pCVar15) {
    if (local_94 != (CINSNextBot *)**(int **)(iVar4 + 0x20)) {
      iVar5 = 0x18;
      pCVar8 = (CINSNextBot *)0x0;
      do {
        pCVar8 = pCVar8 + 1;
        if (pCVar8 == pCVar15) goto LAB_0071b909;
        this_02 = *(CINSNextBot **)((int)*(int **)(iVar4 + 0x20) + iVar5);
        iVar5 = iVar5 + 0x18;
      } while (local_94 != this_02);
    }
    CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::Remove(iVar4 + 0x20);
    local_98 = *(int *)(pCVar1 + 0x20);
    this_02 = extraout_ECX_04;
  }
LAB_0071b909:
  pCVar15 = (CINSNextBot *)0x0;
  if (local_98 != 0) {
    pCVar15 = (CINSNextBot *)(local_98 - *(int *)(**(int **)(unaff_EBX + 0x48b105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4);
  }
  if (pCVar15 != *(CINSNextBot **)(pCVar6 + 8)) {
    if (*(int *)(pCVar6 + 0x2c) < 1) {
LAB_0071b985:
      piVar7 = (int *)UTIL_PlayerByIndex((int)*(CINSNextBot **)(pCVar6 + 8));
      this_02 = extraout_ECX;
      if (piVar7 != (int *)0x0) {
        cVar3 = (**(code **)(*piVar7 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar7);
        this_02 = pCVar6;
        if ((int)*(t_INSBotEscortMember **)(pCVar6 + 0x2c) < (int)((-(uint)(cVar3 == '\0') & 2) + 3)
           ) {
          CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>>::InsertBefore
                    (*(CUtlVector<t_INSBotEscortMember,CUtlMemory<t_INSBotEscortMember,int>> **)
                      (*(int *)(unaff_EBX + 0x48ae31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4),(int)(pCVar6 + 0x20),
                     *(t_INSBotEscortMember **)(pCVar6 + 0x2c));
          this_02 = extraout_ECX_00;
        }
      }
    }
    else {
      iVar4 = 0x18;
      iVar5 = 0;
      pCVar8 = (CINSNextBot *)**(int **)(pCVar6 + 0x20);
      while (pCVar15 != pCVar8) {
        iVar5 = iVar5 + 1;
        if (iVar5 == *(int *)(pCVar6 + 0x2c)) goto LAB_0071b985;
        piVar7 = (int *)((int)*(int **)(pCVar6 + 0x20) + iVar4);
        iVar4 = iVar4 + 0x18;
        this_02 = (CINSNextBot *)*piVar7;
        pCVar8 = this_02;
      }
    }
  }
  CINSNextBot::SetEscortFormation(this_02,(INSBotEscortFormation *)pCVar1);
  *(undefined4 *)(in_stack_00000004 + 0x38) = *(undefined4 *)(pCVar6 + 8);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldWalk
 * Address: 00719350
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotEscort::ShouldWalk(CINSBotEscort *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::ShouldWalk
 * Address: 00719360
 * ---------------------------------------- */

/* CINSBotEscort::ShouldWalk(INextBot const*) const */

char __cdecl CINSBotEscort::ShouldWalk(INextBot *param_1)

{
  char cVar1;
  int *piVar2;
  CINSPlayer *this;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)UTIL_PlayerByIndex(*(int *)(param_1 + 0x38));
  if (piVar2 != (int *)0x0) {
    cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2);
    if (cVar1 != '\0') {
      cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2);
      if (cVar1 != '\0') {
        cVar1 = CINSPlayer::IsWalking(this);
        if (cVar1 != '\0') {
          return '\x01';
        }
      }
    }
  }
  if (param_1[0x48] == (INextBot)0x0) {
    return '\x02';
  }
  return (*(float *)(unaff_EBX + 0x222e1c /* 256.0f */ /* 256.0f */ /* 256.0f */) < *(float *)(param_1 + 0x4c) ||
         *(float *)(unaff_EBX + 0x222e1c /* 256.0f */ /* 256.0f */ /* 256.0f */) == *(float *)(param_1 + 0x4c)) + '\x01';
}



/* ----------------------------------------
 * CINSBotEscort::UpdateEscortFormations
 * Address: 0071b3c0
 * ---------------------------------------- */

/* CINSBotEscort::UpdateEscortFormations() */

void CINSBotEscort::UpdateEscortFormations(void)

{
  CUtlMemory<t_INSBotEscortMember,int> *pCVar1;
  int iVar2;
  void *pvVar3;
  int iVar4;
  INSBotEscortFormation *pIVar5;
  undefined4 uVar6;
  CINSNextBot *this;
  CUtlMemory<t_INSBotEscortMember,int> *extraout_ECX;
  CUtlMemory<t_INSBotEscortMember,int> *this_00;
  int unaff_EBX;
  int iVar7;
  INSBotEscortFormation *local_2c;
  int local_28;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x5d1181 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
  if (0 < iVar2) {
    local_28 = iVar2 + -1;
    local_2c = (INSBotEscortFormation *)(iVar2 << 2);
    do {
      while (pCVar1 = (CUtlMemory<t_INSBotEscortMember,int> *)(local_2c + -4),
            **(char **)(local_2c + *(int *)(unaff_EBX + 0x5d1175 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */) + -4) == '\0') {
        iVar2 = (**(code **)(*(int *)(unaff_EBX + 0x5d1195 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */) + 0x40))(unaff_EBX + 0x5d1195 /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */ /* ins_bot_debug_escort_formations */);
        if (iVar2 != 0) {
          DevMsg((char *)(unaff_EBX + 0x265a11 /* "Removing Formation: %i" */ /* "Removing Formation: %i" */ /* "Removing Formation: %i" */));
        }
        pvVar3 = *(void **)(pCVar1 + *(int *)(unaff_EBX + 0x5d1175 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */));
        this_00 = pCVar1;
        if (0 < *(int *)((int)pvVar3 + 0x2c)) {
          iVar7 = 0;
          iVar2 = 0;
          do {
            iVar4 = UTIL_PlayerByIndex(*(int *)(*(int *)((int)pvVar3 + 0x20) + iVar2));
            if ((iVar4 != 0) &&
               (pIVar5 = (INSBotEscortFormation *)
                         __dynamic_cast(iVar4,*(undefined4 *)(unaff_EBX + 0x48bd39 /* &typeinfo for CBaseEntity */ /* &typeinfo for CBaseEntity */ /* &typeinfo for CBaseEntity */),
                                        *(undefined4 *)(unaff_EBX + 0x48b65d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0),
               pIVar5 != (INSBotEscortFormation *)0x0)) {
              CINSNextBot::SetEscortFormation(this,pIVar5);
            }
            this_00 = (CUtlMemory<t_INSBotEscortMember,int> *)0x1453c8;
            iVar7 = iVar7 + 1;
            iVar2 = iVar2 + 0x18;
            pvVar3 = *(void **)(pCVar1 + *(int *)(unaff_EBX + 0x5d1175 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */));
          } while (iVar7 < *(int *)((int)pvVar3 + 0x2c));
        }
        *(undefined4 *)((int)pvVar3 + 0x2c) = 0;
        if (*(int *)((int)pvVar3 + 0x28) < 0) {
          uVar6 = *(undefined4 *)((int)pvVar3 + 0x20);
        }
        else {
          this_00 = *(CUtlMemory<t_INSBotEscortMember,int> **)((int)pvVar3 + 0x20);
          if (this_00 != (CUtlMemory<t_INSBotEscortMember,int> *)0x0) {
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x48b4ad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x48b4ad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),this_00);
            *(undefined4 *)((int)pvVar3 + 0x20) = 0;
            this_00 = extraout_ECX;
          }
          *(undefined4 *)((int)pvVar3 + 0x24) = 0;
          uVar6 = 0;
        }
        *(undefined4 *)((int)pvVar3 + 0x30) = uVar6;
        CUtlMemory<t_INSBotEscortMember,int>::~CUtlMemory(this_00);
        operator_delete(pvVar3);
        iVar2 = *(int *)(unaff_EBX + 0x5d1181 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
        iVar7 = (iVar2 - local_28) + -1;
        if (0 < iVar7) {
          _V_memmove(pCVar1 + *(int *)(unaff_EBX + 0x5d1175 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */),
                     local_2c + *(int *)(unaff_EBX + 0x5d1175 /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */ /* CINSBotEscort::m_escortFormations */),iVar7 * 4);
          iVar2 = *(int *)(unaff_EBX + 0x5d1181 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */);
        }
        local_28 = local_28 + -1;
        *(int *)(unaff_EBX + 0x5d1181 /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */ /* CINSBotEscort::m_escortFormations+0xc */) = iVar2 + -1;
        local_2c = (INSBotEscortFormation *)pCVar1;
        if (local_28 == -1) {
          return;
        }
      }
      INSBotEscortFormation::UpdatePositions(local_2c);
      local_28 = local_28 + -1;
      local_2c = (INSBotEscortFormation *)pCVar1;
    } while (local_28 != -1);
  }
  return;
}



/* ----------------------------------------
 * CINSBotEscort::UpdateEscortLookaround
 * Address: 0071ae80
 * ---------------------------------------- */

/* CINSBotEscort::UpdateEscortLookaround(CINSNextBot*) */

void __thiscall CINSBotEscort::UpdateEscortLookaround(CINSBotEscort *this,CINSNextBot *param_1)

{
  float *pfVar1;
  char cVar2;
  int iVar3;
  Vector *pVVar4;
  int *piVar5;
  CNavMesh *this_00;
  CINSBotEscort *this_01;
  CBasePlayer *this_02;
  CINSBotEscort *this_03;
  CINSBotEscort *this_04;
  CINSPlayer *this_05;
  CINSBotEscort *this_06;
  CTraceFilterSimple *this_07;
  CNavArea *this_08;
  CNavMesh *extraout_ECX;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  int *in_stack_00000008;
  Vector *pVVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  Vector local_100 [12];
  float local_f4;
  undefined4 local_f0;
  undefined4 local_b4;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_6c;
  undefined1 local_68;
  undefined1 local_67;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar3 = (**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))();
  fVar7 = *(float *)(**(int **)(unaff_EBX + 0x48ba09 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc) - *(float *)(iVar3 + 600);
  if (*(float *)(unaff_EBX + 0x20aeb9 /* 6.0f */ /* 6.0f */ /* 6.0f */) <= fVar7 && fVar7 != *(float *)(unaff_EBX + 0x20aeb9 /* 6.0f */ /* 6.0f */ /* 6.0f */)) {
    cVar2 = (**(code **)(*in_stack_00000008 + 0x8ac /* CINSNextBot::IsInCombat */))();
    if ((cVar2 == '\0') && (param_1[0x48] != (CINSNextBot)0x0)) {
      local_b4 = 0;
      pfVar1 = *(float **)(unaff_EBX + 0x48b735 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
      local_40 = *pfVar1;
      local_3c = pfVar1[1];
      local_38 = pfVar1[2];
      pVVar4 = (Vector *)GetEscortTarget(this_01);
      pVVar10 = (Vector *)&local_40;
      uVar12 = 0;
      uVar11 = 0;
      CBasePlayer::EyeVectors(this_02,pVVar4,pVVar10,(Vector *)0x0);
      fVar6 = (float10)CountdownTimer::Now();
      if (*(float *)(param_1 + 0x88) <= (float)fVar6 && (float)fVar6 != *(float *)(param_1 + 0x88))
      {
        piVar5 = (int *)GetEscortTarget(this_03);
        cVar2 = (**(code **)(*piVar5 + 0x158 /* CBasePlayer::IsPlayer */))(piVar5,pVVar10,uVar11,uVar12);
        if (cVar2 != '\0') {
          fVar6 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
          if (*(float *)(unaff_EBX + 0x208bf5 /* 0.25f */ /* 0.25f */ /* 0.25f */) <= (float)fVar6 &&
              (float)fVar6 != *(float *)(unaff_EBX + 0x208bf5 /* 0.25f */ /* 0.25f */ /* 0.25f */)) {
            piVar5 = (int *)GetEscortTarget(this_04);
            if (piVar5 != (int *)0x0) {
              cVar2 = (**(code **)(*piVar5 + 0x158 /* CBasePlayer::IsPlayer */))(piVar5);
              if (cVar2 != '\0') {
                cVar2 = CINSPlayer::IsSprinting(this_05);
                if (cVar2 == '\0') {
                  fVar7 = *(float *)(unaff_EBX + 0x245169 /* CSWTCH.586+0x1c */ /* CSWTCH.586+0x1c */ /* CSWTCH.586+0x1c */);
                  fVar9 = local_40 * fVar7;
                  fVar8 = local_3c * fVar7;
                  fVar7 = fVar7 * local_38;
                  (**(code **)(*piVar5 + 0x20c /* CINSNextBot::EyePosition */))(&local_34,piVar5);
                  local_3c = fVar8 + local_30;
                  local_38 = fVar7 + local_2c;
                  local_40 = fVar9 + local_34;
                  iVar3 = GetEscortTarget(this_06);
                  (**(code **)(*piVar5 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar5);
                  local_6c = 0;
                  local_ac = local_28;
                  local_a8 = local_24;
                  local_9c = local_40 - local_28;
                  local_98 = local_3c - local_24;
                  local_68 = 1;
                  local_a4 = local_20;
                  local_94 = local_38 - local_20;
                  local_74 = 0;
                  local_78 = 0;
                  local_7c = 0;
                  local_67 = local_98 * local_98 + local_9c * local_9c + local_94 * local_94 != 0.0;
                  local_84 = 0;
                  local_88 = 0;
                  local_8c = 0;
                  CTraceFilterSimple::CTraceFilterSimple
                            (this_07,(IHandleEntity *)&local_50,iVar3,
                             (_func_bool_IHandleEntity_ptr_int *)0x0);
                  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x48b8e1 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
                            ((int *)**(undefined4 **)(unaff_EBX + 0x48b8e1 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_ac,0x2006241,
                             &local_50,local_100);
                  piVar5 = *(int **)(unaff_EBX + 0x48bba9 /* &r_visualizetraces */ /* &r_visualizetraces */ /* &r_visualizetraces */);
                  this_00 = (CNavMesh *)(**(code **)(*piVar5 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar5);
                  if (this_00 != (CNavMesh *)0x0) {
                    iVar3 = (**(code **)(*piVar5 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar5);
                    fVar7 = 0.5;
                    if (iVar3 != 0) {
                      fVar7 = -1.0;
                    }
                    DebugDrawLine(local_100,(Vector *)&local_f4,0xff,0,0,true,fVar7);
                    this_00 = extraout_ECX;
                  }
                  uVar11 = 0;
                  fVar7 = (float)CNavMesh::GetNearestNavAreaFast
                                           (this_00,(Vector *)
                                                    **(undefined4 **)(unaff_EBX + 0x48b821 /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */),
                                            SUB41(&local_f4,0));
                  if (fVar7 != 0.0) {
                    fVar6 = (float10)CNavArea::GetZ(this_08,fVar7,local_f4);
                    local_50 = local_f4;
                    local_48 = (float)fVar6 + *(float *)(unaff_EBX + 0x2431e1 /* 69.0f */ /* 69.0f */ /* 69.0f */);
                    local_4c = local_f0;
                    piVar5 = (int *)(**(code **)(*in_stack_00000008 + 0x970 /* CINSNextBot::GetBodyInterface */))();
                    uVar11 = 3;
                    (**(code **)(*piVar5 + 0xd4 /* PlayerBody::AimHeadTowards */))
                              (piVar5,&local_50,3,0x3f19999a /* 0.6f */,0,unaff_EBX + 0x265fd9 /* "Looking at whatever Escort Target is paying attention to" */ /* "Looking at whatever Escort Target is paying attention to" */ /* "Looking at whatever Escort Target is paying attention to" */);
                  }
                }
              }
            }
          }
          fVar6 = (float10)RandomFloat(0x3fc00000 /* 1.5f */,0x40800000 /* 4.0f */,uVar11);
          fVar7 = (float)fVar6;
          fVar6 = (float10)CountdownTimer::Now();
          if (*(float *)(param_1 + 0x88) != (float)fVar6 + fVar7) {
            (**(code **)(*(int *)(param_1 + 0x80) + 4))(param_1 + 0x80,param_1 + 0x88);
            *(float *)(param_1 + 0x88) = (float)fVar6 + fVar7;
          }
          if (*(float *)(param_1 + 0x84) != fVar7) {
            (**(code **)(*(int *)(param_1 + 0x80) + 4))(param_1 + 0x80,param_1 + 0x84);
            *(float *)(param_1 + 0x84) = fVar7;
          }
        }
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotEscort::UpdateEscortPostures
 * Address: 0071a880
 * ---------------------------------------- */

/* CINSBotEscort::UpdateEscortPostures(CINSNextBot*) */

void __thiscall CINSBotEscort::UpdateEscortPostures(CINSBotEscort *this,CINSNextBot *param_1)

{
  float fVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  uint uVar5;
  int *piVar6;
  undefined4 uVar7;
  int iVar8;
  CINSBotEscort *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEntity *extraout_ECX;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_03;
  CINSPlayer *this_04;
  CINSPlayer *this_05;
  CINSPlayer *extraout_ECX_01;
  CINSBotEscort *this_06;
  CBaseEntity *extraout_ECX_02;
  CINSPlayer *this_07;
  CBaseEntity *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)GetEscortTarget(this_00);
  if (piVar4 == (int *)0x0) {
    return;
  }
  cVar3 = (**(code **)(*piVar4 + 0x158))(piVar4);
  if (cVar3 == '\0') {
    return;
  }
  if (param_1[0x48] == (CINSNextBot)0x0) {
    return;
  }
  this_02 = this_01;
  if ((*(byte *)((int)in_stack_00000008 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_01);
    this_02 = (CBaseEntity *)extraout_ECX_01;
  }
  if (*(float *)(unaff_EBX + 0x266746 /* rodata:0x47FD2000 */ /* rodata:0x47FD2000 */ /* rodata:0x47FD2000 */) <=
      ((float)in_stack_00000008[0x83] - *(float *)(param_1 + 0x40)) *
      ((float)in_stack_00000008[0x83] - *(float *)(param_1 + 0x40)) +
      ((float)in_stack_00000008[0x82] - *(float *)(param_1 + 0x3c)) *
      ((float)in_stack_00000008[0x82] - *(float *)(param_1 + 0x3c)) +
      ((float)in_stack_00000008[0x84] - *(float *)(param_1 + 0x44)) *
      ((float)in_stack_00000008[0x84] - *(float *)(param_1 + 0x44))) {
    return;
  }
  uVar5 = CINSPlayer::GetPlayerFlags((CINSPlayer *)this_02);
  this_03 = (CINSPlayer *)extraout_ECX;
  if ((uVar5 & 1) != 0) {
    piVar6 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
    pcVar2 = *(code **)(*piVar6 + 0x118);
    uVar7 = GetEscortTarget(this_06);
    cVar3 = (*pcVar2)(piVar6,uVar7);
    if ((cVar3 != '\0') ||
       (fVar9 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */), this_03 = (CINSPlayer *)extraout_ECX_03,
       *(float *)(unaff_EBX + 0x20a77a /* 0.7f */ /* 0.7f */ /* 0.7f */) <= (float)fVar9 &&
       (float)fVar9 != *(float *)(unaff_EBX + 0x20a77a /* 0.7f */ /* 0.7f */ /* 0.7f */))) {
      (**(code **)(*in_stack_00000008 + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_00000008,0x3f19999a /* 0.6f */);
      this_03 = (CINSPlayer *)extraout_ECX_02;
    }
  }
  if ((*(byte *)((int)piVar4 + 0xd1) & 0x10) != 0) {
    CBaseEntity::CalcAbsoluteVelocity((CBaseEntity *)this_03);
    this_03 = extraout_ECX_00;
  }
  fVar10 = SQRT((float)piVar4[0x6b] * (float)piVar4[0x6b] +
                (float)piVar4[0x6a] * (float)piVar4[0x6a]);
  if (((*(float *)(unaff_EBX + 0x209ece /* 30.0f */ /* 30.0f */ /* 30.0f */) <= fVar10 && fVar10 != *(float *)(unaff_EBX + 0x209ece /* 30.0f */ /* 30.0f */ /* 30.0f */)) &&
      (cVar3 = CINSPlayer::IsCrouched(this_03), cVar3 == '\0')) &&
     (cVar3 = CINSPlayer::IsProned(this_07), cVar3 == '\0')) {
    piVar4 = (int *)(**(code **)(*in_stack_00000008 + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_00000008);
    cVar3 = (**(code **)(*piVar4 + 0x128 /* CINSBotBody::IsPostureMobile */))(piVar4);
    if (cVar3 != '\0') {
      return;
    }
    (**(code **)(*in_stack_00000008 + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_00000008);
    CINSBotBody::SetPosture();
    return;
  }
  fVar9 = (float10)RandomFloat(0x40800000 /* 4.0f */,0x41000000 /* 8.0f */);
  fVar10 = (float)fVar9;
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < *(float *)(param_1 + 0x94) || (float)fVar9 == *(float *)(param_1 + 0x94)) {
    return;
  }
  fVar9 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
  fVar1 = (float)fVar9;
  cVar3 = CINSPlayer::IsCrouched(this_04);
  if (cVar3 == '\0') {
    cVar3 = CINSPlayer::IsProned(this_05);
    if (cVar3 != '\0') {
      if (*(float *)(unaff_EBX + 0x209eca /* 0.5f */ /* 0.5f */ /* 0.5f */) <= fVar1 && fVar1 != *(float *)(unaff_EBX + 0x209eca /* 0.5f */ /* 0.5f */ /* 0.5f */))
      goto LAB_0071ab90;
      if (fVar1 < *(float *)(unaff_EBX + 0x19e28e /* 0.1f */ /* 0.1f */ /* 0.1f */) || fVar1 == *(float *)(unaff_EBX + 0x19e28e /* 0.1f */ /* 0.1f */ /* 0.1f */))
      goto LAB_0071aa16;
      goto LAB_0071ac30;
    }
    iVar8 = *in_stack_00000008;
    if (*(float *)(unaff_EBX + 0x212e06 /* 0.33f */ /* 0.33f */ /* 0.33f */) <= fVar1 && fVar1 != *(float *)(unaff_EBX + 0x212e06 /* 0.33f */ /* 0.33f */ /* 0.33f */)) {
      (**(code **)(iVar8 + 0x970))(in_stack_00000008);
      CINSBotBody::SetPosture();
      goto LAB_0071aa16;
    }
  }
  else {
    if (*(float *)(unaff_EBX + 0x20c55a /* 0.85f */ /* 0.85f */ /* 0.85f */) <= fVar1 && fVar1 != *(float *)(unaff_EBX + 0x20c55a /* 0.85f */ /* 0.85f */ /* 0.85f */)) {
LAB_0071ab90:
      (**(code **)(*in_stack_00000008 + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_00000008);
      CINSBotBody::SetPosture();
      goto LAB_0071aa16;
    }
    if (fVar1 < *(float *)(CGameMovement::ReduceTimers + unaff_EBX + 6) ||
        fVar1 == *(float *)(CGameMovement::ReduceTimers + unaff_EBX + 6)) goto LAB_0071aa16;
LAB_0071ac30:
    iVar8 = *in_stack_00000008;
  }
  (**(code **)(iVar8 + 0x970))(in_stack_00000008);
  CINSBotBody::SetPosture();
LAB_0071aa16:
  fVar9 = (float10)CountdownTimer::Now();
  if (*(float *)(param_1 + 0x94) != (float)fVar9 + fVar10) {
    (**(code **)(*(int *)(param_1 + 0x8c) + 4))(param_1 + 0x8c,param_1 + 0x94);
    *(float *)(param_1 + 0x94) = (float)fVar9 + fVar10;
  }
  if (*(float *)(param_1 + 0x90) != fVar10) {
    (**(code **)(*(int *)(param_1 + 0x8c) + 4))(param_1 + 0x8c,param_1 + 0x90);
    *(float *)(param_1 + 0x90) = fVar10;
  }
  return;
}



/* ----------------------------------------
 * CINSBotEscort::UpdateFormationMovement
 * Address: 0071acc0
 * ---------------------------------------- */

/* CINSBotEscort::UpdateFormationMovement(INSBotEscortFormation*, CINSNextBot*) */

void __thiscall
CINSBotEscort::UpdateFormationMovement
          (CINSBotEscort *this,INSBotEscortFormation *param_1,CINSNextBot *param_2)

{
  CBaseEntity *pCVar1;
  int iVar2;
  float *pfVar3;
  CBaseEntity *pCVar4;
  int iVar5;
  int *piVar6;
  CINSNextBot *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_01;
  CINSNextBot *this_02;
  CINSBotEscort *extraout_ECX_00;
  int iVar7;
  int unaff_EBX;
  int iVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  INSBotEscortFormation *in_stack_0000000c;
  CINSNextBot *pCVar12;
  
  __i686_get_pc_thunk_bx();
  if (param_2 != (CINSNextBot *)0x0) {
    iVar8 = 0;
    pCVar12 = param_2;
    CINSNextBot::SetEscortFormation(this_00,in_stack_0000000c);
    if (*(int *)(in_stack_0000000c + 0x20) != 0) {
      iVar8 = *(int *)(in_stack_0000000c + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x48bbd5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c)
              >> 4;
    }
    pfVar3 = *(float **)(unaff_EBX + 0x48b901 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    fVar10 = *pfVar3;
    fVar9 = pfVar3[1];
    fVar11 = pfVar3[2];
    this_01 = extraout_ECX;
    if (0 < *(int *)(param_2 + 0x2c)) {
      pCVar4 = *(CBaseEntity **)(param_2 + 0x20);
      iVar5 = 0;
      iVar7 = 0x18;
      iVar2 = *(int *)pCVar4;
      pCVar1 = pCVar4;
      this_01 = extraout_ECX;
      while (iVar8 != iVar2) {
        iVar5 = iVar5 + 1;
        if (iVar5 == *(int *)(param_2 + 0x2c)) goto LAB_0071ad56;
        pCVar1 = pCVar4 + iVar7;
        iVar7 = iVar7 + 0x18;
        this_01 = pCVar1;
        iVar2 = *(int *)pCVar1;
      }
      fVar10 = *(float *)(pCVar1 + 0xc);
      fVar9 = *(float *)(pCVar1 + 0x10);
      fVar11 = *(float *)(pCVar1 + 0x14);
      this_01 = pCVar1;
    }
LAB_0071ad56:
    *(float *)(param_1 + 0x3c) = fVar10;
    *(float *)(param_1 + 0x40) = fVar9;
    *(float *)(param_1 + 0x44) = fVar11;
    if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_01);
      fVar10 = *(float *)(param_1 + 0x3c);
      fVar9 = *(float *)(param_1 + 0x40);
      fVar11 = *(float *)(param_1 + 0x44);
      this_01 = (CBaseEntity *)extraout_ECX_00;
    }
    fVar10 = SQRT((fVar9 - *(float *)(in_stack_0000000c + 0x20c)) *
                  (fVar9 - *(float *)(in_stack_0000000c + 0x20c)) +
                  (fVar10 - *(float *)(in_stack_0000000c + 0x208)) *
                  (fVar10 - *(float *)(in_stack_0000000c + 0x208)) +
                  (fVar11 - *(float *)(in_stack_0000000c + 0x210)) *
                  (fVar11 - *(float *)(in_stack_0000000c + 0x210)));
    if ((*(float *)(unaff_EBX + 0x2129b9 /* 500.0f */ /* 500.0f */ /* 500.0f */) <= fVar10) ||
       (param_1[0x48] == (INSBotEscortFormation)0x0)) {
      if (*(int *)(in_stack_0000000c + 0xb324) < 10) {
        GetEscortTarget((CINSBotEscort *)this_01);
        CINSNextBot::UpdateChasePath(this_02,(CBaseEntity *)in_stack_0000000c);
        return;
      }
    }
    else if (*(float *)(unaff_EBX + 0x231a89 /* 128.0f */ /* 128.0f */ /* 128.0f */) <= fVar10 &&
             fVar10 != *(float *)(unaff_EBX + 0x231a89 /* 128.0f */ /* 128.0f */ /* 128.0f */)) {
      piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,pCVar12);
      (**(code **)(*piVar6 + 200))(piVar6,param_1 + 0x3c,0x3f800000 /* 1.0f */);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotEscort::~CINSBotEscort
 * Address: 0071c850
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::~CINSBotEscort() */

void __thiscall CINSBotEscort::~CINSBotEscort(CINSBotEscort *this)

{
  ~CINSBotEscort(this);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::~CINSBotEscort
 * Address: 0071c860
 * ---------------------------------------- */

/* CINSBotEscort::~CINSBotEscort() */

void __thiscall CINSBotEscort::~CINSBotEscort(CINSBotEscort *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x47a143 /* vtable for CINSBotEscort+0x8 */ /* vtable for CINSBotEscort+0x8 */ /* vtable for CINSBotEscort+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x47a2e3 /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x48a913 /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotEscort::~CINSBotEscort
 * Address: 0071c950
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotEscort::~CINSBotEscort() */

void __thiscall CINSBotEscort::~CINSBotEscort(CINSBotEscort *this)

{
  ~CINSBotEscort(this);
  return;
}



/* ----------------------------------------
 * CINSBotEscort::~CINSBotEscort
 * Address: 0071c960
 * ---------------------------------------- */

/* CINSBotEscort::~CINSBotEscort() */

void __thiscall CINSBotEscort::~CINSBotEscort(CINSBotEscort *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47a03a /* vtable for CINSBotEscort+0x8 */ /* vtable for CINSBotEscort+0x8 */ /* vtable for CINSBotEscort+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x47a1da /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */ /* vtable for CINSBotEscort+0x1a8 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



