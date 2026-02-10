/*
 * CINSBotMainAction -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 21
 */

/* ----------------------------------------
 * CINSBotMainAction::OnStart
 * Address: 00753730
 * ---------------------------------------- */

/* CINSBotMainAction::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotMainAction::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::InitialContainedAction
 * Address: 00753800
 * ---------------------------------------- */

/* CINSBotMainAction::InitialContainedAction(CINSNextBot*) */

int * __cdecl CINSBotMainAction::InitialContainedAction(CINSNextBot *param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)::operator_new(0x98);
  iVar1 = unaff_EBX + 0x3d49ad /* vtable for CountdownTimer+0x8 */;
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
  iVar3 = *(int *)(unaff_EBX + 0x453111 /* &vtable for CINSBotTacticalMonitor */);
  piVar4[0xe] = iVar1;
  piVar4[0xf] = 0;
  piVar4[1] = iVar3 + 0x1a0;
  *piVar4 = iVar3 + 8;
  pcVar2 = (code *)(unaff_EBX + -0x52309b /* CountdownTimer::NetworkStateChanged */);
  (*pcVar2)(piVar4 + 0xe,piVar4 + 0xf);
  piVar4[0x10] = -0x40800000;
  (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
  piVar4[0x11] = iVar1;
  piVar4[0x12] = 0;
  (*pcVar2)(piVar4 + 0x11,piVar4 + 0x12);
  piVar4[0x13] = -0x40800000;
  (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
  piVar4[0x14] = iVar1;
  piVar4[0x15] = 0;
  (*pcVar2)(piVar4 + 0x14,piVar4 + 0x15);
  piVar4[0x16] = -0x40800000;
  (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
  piVar4[0x17] = iVar1;
  piVar4[0x18] = 0;
  (*pcVar2)(piVar4 + 0x17,piVar4 + 0x18);
  piVar4[0x19] = -0x40800000;
  (**(code **)(piVar4[0x17] + 4))(piVar4 + 0x17,piVar4 + 0x19);
  piVar4[0x1a] = iVar1;
  piVar4[0x1b] = 0;
  (*pcVar2)(piVar4 + 0x1a,piVar4 + 0x1b);
  piVar4[0x1c] = -0x40800000;
  (**(code **)(piVar4[0x1a] + 4))(piVar4 + 0x1a,piVar4 + 0x1c);
  piVar4[0x1d] = iVar1;
  piVar4[0x1e] = 0;
  (*pcVar2)(piVar4 + 0x1d,piVar4 + 0x1e);
  piVar4[0x1f] = -0x40800000;
  (**(code **)(piVar4[0x1d] + 4))(piVar4 + 0x1d,piVar4 + 0x1f);
  iVar3 = *(int *)(unaff_EBX + 0x453445 /* &vtable for IntervalTimer */);
  piVar4[0x21] = -0x40800000;
  piVar4[0x20] = iVar3 + 8;
  (**(code **)(iVar3 + 0x10))(piVar4 + 0x20,piVar4 + 0x21);
  piVar4[0x22] = iVar1;
  piVar4[0x23] = 0;
  (*pcVar2)(piVar4 + 0x22,piVar4 + 0x23);
  piVar4[0x24] = -0x40800000;
  (**(code **)(piVar4[0x22] + 4))(piVar4 + 0x22,piVar4 + 0x24);
  return piVar4;
}



/* ----------------------------------------
 * CINSBotMainAction::Update
 * Address: 00753aa0
 * ---------------------------------------- */

/* CINSBotMainAction::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotMainAction::Update(CINSBotMainAction *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CBaseEntity *this_02;
  CINSPlayer *this_03;
  int unaff_EBX;
  float10 fVar6;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x452e4a /* &g_pGameRules */) != 0) {
    cVar3 = (**(code **)(*in_stack_0000000c + 0x118))(in_stack_0000000c);
    if (cVar3 == '\0') {
      piVar4 = (int *)::operator_new(0x40);
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
      iVar5 = *(int *)(unaff_EBX + 0x453296 /* &vtable for CINSBotDead */);
      piVar4[0xf] = -0x40800000;
      piVar4[1] = iVar5 + 0x198;
      iVar2 = *(int *)(unaff_EBX + 0x4531a2 /* &vtable for IntervalTimer */);
      *piVar4 = iVar5 + 8;
      piVar4[0xe] = iVar2 + 8;
      (**(code **)(iVar2 + 0x10))(piVar4 + 0xe,piVar4 + 0xf);
      *(undefined4 *)param_1 = 1;
      *(int **)(param_1 + 4) = piVar4;
      *(int *)(param_1 + 8) = unaff_EBX + 0x1d578b /* "Dead" */;
      return param_1;
    }
    this_00 = extraout_ECX;
    if ((0.0 < (float)in_stack_0000000c[0x608]) &&
       (fVar6 = (float10)CountdownTimer::Now(), this_00 = extraout_ECX_00,
       (float)fVar6 < (float)in_stack_0000000c[0x608] ||
       (float)fVar6 == (float)in_stack_0000000c[0x608])) {
      piVar4 = (int *)::operator_new(0x48);
      iVar5 = *(int *)(unaff_EBX + 0x452b6e /* &vtable for CINSBotFlashed */);
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
      piVar4[1] = iVar5 + 0x198;
      *piVar4 = iVar5 + 8;
      piVar4[0xd] = 0;
      *(int **)(param_1 + 4) = piVar4;
      *(undefined4 *)param_1 = 2;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x22d756 /* "Flashed" */;
      return param_1;
    }
    cVar3 = CINSNextBot::IsIdle(this_00);
    if (((cVar3 != '\0') &&
        (fVar6 = (float10)CINSNextBot::GetIdleDuration(this_01),
        *(float *)(&DAT_001d331a + unaff_EBX) <= (float)fVar6 &&
        (float)fVar6 != *(float *)(&DAT_001d331a + unaff_EBX))) &&
       (iVar5 = (**(code **)(*in_stack_0000000c + 0x548))(in_stack_0000000c), iVar5 != 0)) {
      piVar4 = (int *)(**(code **)(*in_stack_0000000c + 0x548))(in_stack_0000000c);
      pcVar1 = *(code **)(*piVar4 + 0x88);
      iVar5 = CBaseEntity::GetTeamNumber(this_02);
      cVar3 = (*pcVar1)(piVar4,(iVar5 == 2) + '\x02');
      if (cVar3 == '\0') {
        Warning(unaff_EBX + 0x22fb06 /* "commiting suicide and respawning a stuck/Idle bot
" */);
        CINSPlayer::CommitSuicide(this_03,SUB41(in_stack_0000000c,0),1);
        *(undefined1 *)(in_stack_0000000c + 0x4a5) = 1;
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotMainAction::GetName
 * Address: 007547a0
 * ---------------------------------------- */

/* CINSBotMainAction::GetName() const */

int CINSBotMainAction::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2089b5 /* "Behavior" */;
}



/* ----------------------------------------
 * CINSBotMainAction::OnContact
 * Address: 00754050
 * ---------------------------------------- */

/* CINSBotMainAction::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

CINSNextBot *
CINSBotMainAction::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  char cVar1;
  char *pcVar2;
  CBaseEntity *this;
  int unaff_EBX;
  
  pcVar2 = (char *)__i686_get_pc_thunk_bx();
  if (pcVar2 != (char *)0x0) {
    if (*(int *)(pcVar2 + 100) != unaff_EBX + 0x1d52e5 /* "prop_door*" */) {
      cVar1 = CBaseEntity::ClassMatchesComplex(this,pcVar2);
      if (cVar1 == '\0') goto LAB_00754092;
    }
    (**(code **)(*(int *)param_3 + 0x8d8))(param_3,0x3dcccccd);
  }
LAB_00754092:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotMainAction::OnStuck
 * Address: 00753e10
 * ---------------------------------------- */

/* CINSBotMainAction::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotMainAction::OnStuck(CINSNextBot *param_1)

{
  float fVar1;
  float fVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CBasePlayer *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBaseEntity *extraout_ECX;
  int unaff_EBX;
  float10 fVar9;
  double dVar10;
  double dVar11;
  int *in_stack_0000000c;
  undefined8 uVar12;
  undefined8 uVar13;
  double local_3c;
  double local_34;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x96c))(in_stack_0000000c);
  fVar9 = (float10)(**(code **)(*piVar3 + 400))(piVar3);
  dVar10 = (double)(float)fVar9;
  if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) == 0) {
    local_34 = (double)(float)in_stack_0000000c[0x84];
    this_00 = this;
LAB_00753e73:
    local_3c = (double)(float)in_stack_0000000c[0x83];
  }
  else {
    CBaseEntity::CalcAbsolutePosition(this);
    local_34 = (double)(float)in_stack_0000000c[0x84];
    this_00 = this_02;
    if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) == 0) goto LAB_00753e73;
    CBaseEntity::CalcAbsolutePosition(this_02);
    local_3c = (double)(float)in_stack_0000000c[0x83];
    this_00 = this_03;
    if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_03);
      this_00 = extraout_ECX;
    }
  }
  dVar11 = (double)(float)in_stack_0000000c[0x82];
  uVar4 = CBaseEntity::GetTeamNumber(this_00);
  uVar5 = CBasePlayer::GetNetworkIDString(this_01);
  uVar6 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x45280d /* &engine */) + 0x40))
                    ((int *)**(undefined4 **)(unaff_EBX + 0x45280d /* &engine */),in_stack_0000000c[8]);
  uVar7 = (**(code **)(*in_stack_0000000c + 0xa8))(in_stack_0000000c);
  uVar12 = CONCAT44(uVar6,uVar7);
  uVar13 = CONCAT44(uVar4,uVar5);
  UTIL_LogPrintf((char *)(unaff_EBX + 0x22f7cd /* "\"%s<%i><%s><%i>\" stuck (position \"%3.2f %3.2f %3.2f\") (duration \"%3.2f\") " */),uVar7,uVar6,uVar5,uVar4,dVar11,local_3c,local_34,
                 dVar10);
  piVar3 = (int *)(**(code **)(in_stack_0000000c[0x818] + 0x114))(in_stack_0000000c + 0x818);
  if (piVar3 != (int *)0x0) {
    iVar8 = (**(code **)(*piVar3 + 0x20))(piVar3);
    if (iVar8 != 0) {
      iVar8 = (**(code **)(*piVar3 + 0x20))(piVar3);
      fVar1 = *(float *)(iVar8 + 0x10);
      iVar8 = (**(code **)(*piVar3 + 0x20))(piVar3);
      fVar2 = *(float *)(iVar8 + 0xc);
      iVar8 = (**(code **)(*piVar3 + 0x20))(piVar3);
      UTIL_LogPrintf((char *)(unaff_EBX + 0x22f819 /* "   path_goal ( \"%3.2f %3.2f %3.2f\" )
" */),(double)*(float *)(iVar8 + 8),(double)fVar2,
                     (double)fVar1);
      goto LAB_00753fb6;
    }
  }
  UTIL_LogPrintf((char *)(unaff_EBX + 0x22f77d /* "   path_goal ( \"NULL\" )
" */),uVar12,uVar13,dVar11,local_3c,local_34,dVar10);
LAB_00753fb6:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotMainAction::OnUnStuck
 * Address: 00753750
 * ---------------------------------------- */

/* CINSBotMainAction::OnUnStuck(CINSNextBot*) */

void CINSBotMainAction::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::OnInjured
 * Address: 007540e0
 * ---------------------------------------- */

/* CINSBotMainAction::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

CINSNextBot * CINSBotMainAction::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *extraout_EDX;
  int unaff_EBX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  uVar2 = *(uint *)(in_stack_00000010 + 0x28);
  if (((uVar2 != 0xffffffff) &&
      (iVar1 = **(int **)(unaff_EBX + 0x4526e7 /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
      *(uint *)(iVar1 + 8) == uVar2 >> 0x10)) && (iVar1 = *(int *)(iVar1 + 4), iVar1 != 0)) {
    piVar3 = (int *)(**(code **)(*extraout_EDX + 0x974 /* CINSBotBody::IsActualPosture */))(extraout_EDX);
    (**(code **)(*piVar3 + 0xe8))(piVar3,iVar1);
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectMoreDangerousThreat
 * Address: 00754750
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotMainAction::SelectMoreDangerousThreat(INextBot const*,
   CBaseCombatCharacter const*, CKnownEntity const*, CKnownEntity const*) const */

void __thiscall
CINSBotMainAction::SelectMoreDangerousThreat
          (CINSBotMainAction *this,INextBot *param_1,CBaseCombatCharacter *param_2,
          CKnownEntity *param_3,CKnownEntity *param_4)

{
  SelectMoreDangerousThreat(this,param_1 + -4,param_2,param_3,param_4);
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectMoreDangerousThreat
 * Address: 00754760
 * ---------------------------------------- */

/* CINSBotMainAction::SelectMoreDangerousThreat(INextBot const*, CBaseCombatCharacter const*,
   CKnownEntity const*, CKnownEntity const*) const */

undefined4 __thiscall
CINSBotMainAction::SelectMoreDangerousThreat
          (CINSBotMainAction *this,INextBot *param_1,CBaseCombatCharacter *param_2,
          CKnownEntity *param_3,CKnownEntity *param_4)

{
  undefined4 uVar1;
  
  if ((param_2 != (CBaseCombatCharacter *)0x0) && (param_2 != (CBaseCombatCharacter *)0x2060)) {
    uVar1 = SelectMoreDangerousThreatInternal(this,param_1,param_2,param_3,param_4);
    return uVar1;
  }
  return 0;
}



/* ----------------------------------------
 * CINSBotMainAction::IsImmediateThreat
 * Address: 00754200
 * ---------------------------------------- */

/* CINSBotMainAction::IsImmediateThreat(CBaseCombatCharacter const*, CKnownEntity const*) const */

undefined1 __thiscall
CINSBotMainAction::IsImmediateThreat
          (CINSBotMainAction *this,CBaseCombatCharacter *param_1,CKnownEntity *param_2)

{
  CBaseEntity *pCVar1;
  char cVar2;
  undefined1 uVar3;
  int iVar4;
  undefined4 uVar5;
  int *piVar6;
  float *pfVar7;
  CBaseEntity *this_00;
  CINSPlayer *this_01;
  int unaff_EBX;
  float10 fVar8;
  float10 fVar9;
  float10 extraout_ST0;
  int *in_stack_0000000c;
  float local_28;
  float local_24;
  float local_20;
  
  iVar4 = __i686_get_pc_thunk_bx();
  uVar3 = 0;
  pCVar1 = *(CBaseEntity **)(iVar4 + 0x1c);
  if ((pCVar1 != (CBaseEntity *)0x0) &&
     (cVar2 = (**(code **)(*(int *)(pCVar1 + 0x2060) + 0xf0))(pCVar1 + 0x2060,param_2),
     cVar2 != '\0')) {
    uVar5 = (**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c);
    cVar2 = CBaseEntity::InSameTeam(pCVar1);
    if (cVar2 == '\0') {
      piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c,uVar5);
      cVar2 = (**(code **)(*piVar6 + 0x118))(piVar6);
      uVar3 = 0;
      if (cVar2 != '\0') {
        cVar2 = (**(code **)(*in_stack_0000000c + 0x3c))(in_stack_0000000c);
        uVar3 = 0;
        if (cVar2 != '\0') {
          pfVar7 = (float *)(**(code **)(*in_stack_0000000c + 0x14))(in_stack_0000000c);
          if (((byte)pCVar1[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_00);
          }
          local_28 = *(float *)(pCVar1 + 0x208) - *pfVar7;
          local_24 = *(float *)(pCVar1 + 0x20c) - pfVar7[1];
          local_20 = *(float *)(pCVar1 + 0x210) - pfVar7[2];
          fVar8 = (float10)VectorNormalize((Vector *)&local_28);
          iVar4 = (**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c);
          if ((iVar4 != 0) &&
             (iVar4 = __dynamic_cast(iVar4,*(undefined4 *)(unaff_EBX + 0x452ef3 /* &typeinfo for CBaseEntity */),
                                     *(undefined4 *)(unaff_EBX + 0x452a1b /* &typeinfo for CBaseDetonator */),0), iVar4 != 0)) {
            fVar9 = (float10)CBaseDetonator::GetDetonateDamage();
            if (*(float *)(unaff_EBX + 0x1648f7 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar9 &&
                (float)fVar9 != *(float *)(unaff_EBX + 0x1648f7 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
              CBaseDetonator::GetDetonateDamageRadius();
              return (float)fVar8 < (float)extraout_ST0 * *(float *)(unaff_EBX + 0x1d0f53 /* typeinfo name for CEntityFactory<CBaseViewModel>+0x24 */);
            }
            return false;
          }
          (**(code **)(*in_stack_0000000c + 0x10))(in_stack_0000000c);
          uVar3 = CINSPlayer::IsThreatFiringAtMe(this_01,pCVar1);
        }
      }
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectCloserThreat
 * Address: 007543b0
 * ---------------------------------------- */

/* CINSBotMainAction::SelectCloserThreat(CINSNextBot*, CKnownEntity const*, CKnownEntity const*)
   const */

CKnownEntity * __thiscall
CINSBotMainAction::SelectCloserThreat
          (CINSBotMainAction *this,CINSNextBot *param_1,CKnownEntity *param_2,CKnownEntity *param_3)

{
  code *pcVar1;
  char cVar2;
  undefined4 uVar3;
  int *piVar4;
  uint uVar5;
  CINSWeapon *this_00;
  CINSWeapon *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  int extraout_EDX;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  CKnownEntity *in_stack_00000010;
  int *local_28;
  int *local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  pcVar1 = *(code **)(*(int *)(extraout_EDX + 0x2060 /* CINSBotBody::CheckBadViewTarget */) + 0x130);
  uVar3 = (**(code **)(*(int *)param_3 + 0x10))(param_3);
  fVar6 = (float10)(*pcVar1)(extraout_EDX + 0x2060 /* CINSBotBody::CheckBadViewTarget */,uVar3);
  local_20 = (float)fVar6;
  pcVar1 = *(code **)(*(int *)(extraout_EDX + 0x2060 /* CINSBotBody::CheckBadViewTarget */) + 0x130);
  uVar3 = (**(code **)(*(int *)in_stack_00000010 + 0x10))(in_stack_00000010);
  fVar6 = (float10)(*pcVar1)(extraout_EDX + 0x2060 /* CINSBotBody::CheckBadViewTarget */,uVar3);
  fVar7 = (float)fVar6;
  if ((local_20 < *(float *)(&DAT_001d1ec7 + unaff_EBX)) ||
     (fVar7 < *(float *)(&DAT_001d1ec7 + unaff_EBX))) goto LAB_00754448;
  local_24 = (int *)(**(code **)(*(int *)param_3 + 0x10))(param_3);
  if (local_24 == (int *)0x0) {
LAB_00754497:
    local_24 = (int *)0x0;
  }
  else {
    cVar2 = (**(code **)(*local_24 + 0x158))(local_24);
    if (cVar2 == '\0') goto LAB_00754497;
  }
  local_28 = (int *)(**(code **)(*(int *)in_stack_00000010 + 0x10))(in_stack_00000010);
  if (local_28 == (int *)0x0) {
LAB_007544cd:
    local_28 = (int *)0x0;
  }
  else {
    cVar2 = (**(code **)(*local_28 + 0x158))(local_28);
    if (cVar2 == '\0') goto LAB_007544cd;
  }
  if (local_24 != (int *)0x0) {
    piVar4 = (int *)CINSPlayer::GetActiveINSWeapon();
    if (piVar4 != (int *)0x0) {
      cVar2 = (**(code **)(*piVar4 + 0x620))(piVar4);
      if (cVar2 != '\0') {
        fVar6 = (float10)CINSWeapon::GetFOVWeaponScope(this_00);
        if (*(float *)(unaff_EBX + 0x1d03a3 /* typeinfo name for CBaseGameSystem+0x2a */) <= (float)fVar6) {
          uVar5 = CINSPlayer::GetPlayerFlags(this_03);
          if ((uVar5 & 1) != 0) {
            local_20 = local_20 * *(float *)(unaff_EBX + 0x1cf6cf /* typeinfo name for ISaveRestoreOps+0x6b */);
          }
        }
        else {
          local_20 = local_20 * *(float *)(unaff_EBX + 0x1cf6cb /* typeinfo name for ISaveRestoreOps+0x67 */);
        }
      }
    }
  }
  if (local_28 != (int *)0x0) {
    piVar4 = (int *)CINSPlayer::GetActiveINSWeapon();
    if (piVar4 != (int *)0x0) {
      cVar2 = (**(code **)(*piVar4 + 0x620))(piVar4);
      if (cVar2 != '\0') {
        fVar6 = (float10)CINSWeapon::GetFOVWeaponScope(this_01);
        if (*(float *)(unaff_EBX + 0x1d03a3 /* typeinfo name for CBaseGameSystem+0x2a */) <= (float)fVar6) {
          uVar5 = CINSPlayer::GetPlayerFlags(this_02);
          if ((uVar5 & 1) != 0) {
            fVar7 = fVar7 * *(float *)(unaff_EBX + 0x1cf6cf /* typeinfo name for ISaveRestoreOps+0x6b */);
          }
        }
        else {
          fVar7 = fVar7 * *(float *)(unaff_EBX + 0x1cf6cb /* typeinfo name for ISaveRestoreOps+0x67 */);
        }
      }
    }
  }
LAB_00754448:
  if (local_20 <= fVar7) {
    param_3 = in_stack_00000010;
  }
  return param_3;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectMoreDangerousThreatInternal
 * Address: 00754640
 * ---------------------------------------- */

/* CINSBotMainAction::SelectMoreDangerousThreatInternal(INextBot const*, CBaseCombatCharacter
   const*, CKnownEntity const*, CKnownEntity const*) const */

CKnownEntity * __thiscall
CINSBotMainAction::SelectMoreDangerousThreatInternal
          (CINSBotMainAction *this,INextBot *param_1,CBaseCombatCharacter *param_2,
          CKnownEntity *param_3,CKnownEntity *param_4)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  CKnownEntity *pCVar5;
  CINSBotMainAction *extraout_ECX;
  CINSBotMainAction *extraout_ECX_00;
  CINSBotMainAction *this_00;
  CINSBotMainAction *this_01;
  CINSBotMainAction *this_02;
  bool bVar6;
  CKnownEntity *in_stack_00000014;
  bool local_d;
  
  if ((param_2 == (CBaseCombatCharacter *)0x0) ||
     ((CKnownEntity *)(param_2 + -0x2060) == (CKnownEntity *)0x0)) {
    return (CKnownEntity *)0x0;
  }
  iVar3 = (**(code **)(*(int *)param_4 + 0x10))(param_4);
  local_d = false;
  if (iVar3 != 0) {
    piVar4 = (int *)(**(code **)(*(int *)param_4 + 0x10))(param_4);
    cVar1 = (**(code **)(*piVar4 + 0x158))(piVar4);
    local_d = cVar1 != '\0';
  }
  iVar3 = (**(code **)(*(int *)in_stack_00000014 + 0x10))();
  bVar6 = false;
  this_00 = extraout_ECX;
  if (iVar3 != 0) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_00000014 + 0x10))();
    cVar1 = (**(code **)(*piVar4 + 0x158))(piVar4);
    bVar6 = cVar1 != '\0';
    this_00 = extraout_ECX_00;
  }
  if (local_d != bVar6) {
    if (local_d == false) {
      param_4 = in_stack_00000014;
    }
    return param_4;
  }
  cVar1 = IsImmediateThreat(this_00,(CBaseCombatCharacter *)param_1,param_3);
  cVar2 = IsImmediateThreat(this_01,(CBaseCombatCharacter *)param_1,param_3);
  if (cVar1 != cVar2) {
    if (cVar1 == '\0') {
      param_4 = in_stack_00000014;
    }
    return param_4;
  }
  pCVar5 = (CKnownEntity *)
           SelectCloserThreat(this_02,(CINSNextBot *)param_1,(CKnownEntity *)(param_2 + -0x2060),
                              param_4);
  return pCVar5;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectTargetPoint
 * Address: 007537a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotMainAction::SelectTargetPoint(INextBot const*, CBaseCombatCharacter
   const*) const */

void __thiscall
CINSBotMainAction::SelectTargetPoint
          (CINSBotMainAction *this,INextBot *param_1,CBaseCombatCharacter *param_2)

{
  SelectTargetPoint(param_1,param_2 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::SelectTargetPoint
 * Address: 007537b0
 * ---------------------------------------- */

/* CINSBotMainAction::SelectTargetPoint(INextBot const*, CBaseCombatCharacter const*) const */

INextBot * CINSBotMainAction::SelectTargetPoint(INextBot *param_1,CBaseCombatCharacter *param_2)

{
  __i686_get_pc_thunk_bx();
  CINSNextBot::GetTargetPosition((CBaseCombatCharacter *)param_1);
  return param_1;
}



/* ----------------------------------------
 * CINSBotMainAction::ShouldPursue
 * Address: 00753780
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotMainAction::ShouldPursue(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotMainAction::ShouldPursue(CINSBotMainAction *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldPursue(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::ShouldPursue
 * Address: 00753790
 * ---------------------------------------- */

/* CINSBotMainAction::ShouldPursue(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotMainAction::ShouldPursue(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotMainAction::~CINSBotMainAction
 * Address: 007547c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotMainAction::~CINSBotMainAction() */

void __thiscall CINSBotMainAction::~CINSBotMainAction(CINSBotMainAction *this)

{
  ~CINSBotMainAction(this);
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::~CINSBotMainAction
 * Address: 007547d0
 * ---------------------------------------- */

/* CINSBotMainAction::~CINSBotMainAction() */

void __thiscall CINSBotMainAction::~CINSBotMainAction(CINSBotMainAction *this)

{
  int extraout_ECX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = &UNK_004484d3 + extraout_ECX;
  in_stack_00000004[1] = extraout_ECX + 0x44866f /* vtable for CINSBotMainAction+0x1a4 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4529a3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::~CINSBotMainAction
 * Address: 00754800
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotMainAction::~CINSBotMainAction() */

void __thiscall CINSBotMainAction::~CINSBotMainAction(CINSBotMainAction *this)

{
  ~CINSBotMainAction(this);
  return;
}



/* ----------------------------------------
 * CINSBotMainAction::~CINSBotMainAction
 * Address: 00754810
 * ---------------------------------------- */

/* CINSBotMainAction::~CINSBotMainAction() */

void __thiscall CINSBotMainAction::~CINSBotMainAction(CINSBotMainAction *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x44848a /* vtable for CINSBotMainAction+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x448626 /* vtable for CINSBotMainAction+0x1a4 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



