/*
 * CINSBotActionHunt -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 14
 */

/* ----------------------------------------
 * CINSBotActionHunt::OnStart
 * Address: 00738d80
 * ---------------------------------------- */

/* CINSBotActionHunt::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotActionHunt::OnStart(CINSBotActionHunt *this,CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSWeapon *this_07;
  CINSWeapon *extraout_ECX;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_0000000c;
  undefined4 uVar6;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(&DAT_0046db67 + unaff_EBX);
  this_00[0x38] = *(CINSRules *)((int)in_stack_0000000c + 0x228f);
  *(undefined1 *)((int)in_stack_0000000c + 0x228f) = 0;
  iVar4 = *piVar1;
  this_00[0x39] = (CINSRules)0x0;
  if (iVar4 != 0) {
    CINSRules::GetDefendingTeam(this_00);
    uVar3 = CINSRules::GetTotalActivePlayersOnTeam(this_01,*piVar1);
    *(undefined4 *)(this_00 + 0x3c) = uVar3;
    if (*(char *)(*piVar1 + 0x40c) != '\0') {
      uVar6 = 0;
      uVar3 = 0x3f800000 /* 1.0f */;
      fVar5 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                 ((CINSNextBot *)this_00,(float)in_stack_0000000c,0x3f800000 /* 1.0f */);
      if (*(float *)(unaff_EBX + 0x1f0423 /* 0.35f */ /* 0.35f */) <= (float)fVar5 &&
          (float)fVar5 != *(float *)(unaff_EBX + 0x1f0423 /* 0.35f */ /* 0.35f */)) {
        cVar2 = (**(code **)(*in_stack_0000000c + 0x158))(in_stack_0000000c,uVar3,uVar6);
        if (cVar2 != '\0') {
          iVar4 = CINSPlayer::GetActiveINSWeapon();
          if (iVar4 != 0) {
            cVar2 = CINSWeapon::HasLasersights(this_02);
            this_04 = this_03;
            if (cVar2 != '\0') {
              cVar2 = CINSWeapon::IsLasersightsOn(this_03);
              this_04 = this_07;
              if (cVar2 == '\0') {
                CINSWeapon::ToggleLasersights(this_07);
                this_04 = extraout_ECX;
              }
            }
            cVar2 = CINSWeapon::HasFlashlight(this_04);
            if (cVar2 != '\0') {
              cVar2 = CINSWeapon::IsFlashlightOn(this_05);
              if (cVar2 == '\0') {
                CINSWeapon::ToggleFlashlight(this_06);
              }
            }
          }
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionHunt::Update
 * Address: 00738f60
 * ---------------------------------------- */

/* CINSBotActionHunt::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionHunt::Update(CINSBotActionHunt *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  float fVar2;
  char cVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  void *pvVar8;
  CNavArea *pCVar9;
  CINSNextBot *this_00;
  CINSBotPatrol *this_01;
  CINSBotEscort *this_02;
  CINSBotCombat *this_03;
  CINSBotInvestigate *this_04;
  int unaff_EBX;
  float fVar10;
  CINSNextBot *in_stack_0000000c;
  undefined4 uVar11;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(&DAT_0046d98d + unaff_EBX) == 0) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  cVar3 = CINSBotEscort::HasEscortTarget(in_stack_0000000c);
  if (cVar3 == '\0') {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    uVar11 = 0;
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (piVar4 != (int *)0x0) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar6 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,in_stack_0000000c + 0x2060,piVar4);
      if (iVar6 == 1) {
        pvVar8 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_03);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar8;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(int *)(param_1 + 8) = unaff_EBX + 0x247652 /* "Attacking nearby threats" */ /* "Attacking nearby threats" */;
        return param_1;
      }
      uVar11 = (**(code **)(*piVar4 + 0x10))(piVar4);
      CINSNextBot::AddInvestigation();
    }
    cVar3 = CINSNextBot::HasInvestigations(in_stack_0000000c);
    if (cVar3 == '\0') {
      iVar6 = *(int *)(**(int **)(&DAT_0046ddb1 + unaff_EBX) + 0x770);
      if (-1 < iVar6) {
        pfVar7 = (float *)(**(int **)(&DAT_0046ddb1 + unaff_EBX) + 0x5d0 + iVar6 * 0xc);
        fVar10 = *pfVar7;
        fVar1 = pfVar7[1];
        fVar2 = pfVar7[2];
        pfVar7 = (float *)(**(code **)(*(int *)in_stack_0000000c + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_0000000c,uVar11)
        ;
        fVar10 = SQRT((pfVar7[1] - fVar1) * (pfVar7[1] - fVar1) +
                      (*pfVar7 - fVar10) * (*pfVar7 - fVar10) +
                      (pfVar7[2] - fVar2) * (pfVar7[2] - fVar2));
        if (*(float *)(unaff_EBX + 0x1ec0a5 /* 1000.0f */ /* 1000.0f */) <= fVar10 && fVar10 != *(float *)(unaff_EBX + 0x1ec0a5 /* 1000.0f */ /* 1000.0f */)
           ) {
          pvVar8 = ::operator_new(100);
          CINSBotApproach::CINSBotApproach();
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(void **)(param_1 + 4) = pvVar8;
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(int *)(param_1 + 8) = unaff_EBX + 0x249416 /* "Moving to recently lost cache" */ /* "Moving to recently lost cache" */;
          return param_1;
        }
      }
      pvVar8 = ::operator_new(0x4934);
      CINSBotPatrol::CINSBotPatrol(this_01);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar8;
      *(int *)(param_1 + 8) = unaff_EBX + 0x249322 /* "My Job is to Patrol" */ /* "My Job is to Patrol" */;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      return param_1;
    }
    CINSNextBot::GetCurrentInvestigationArea(this_00);
    pCVar9 = (CNavArea *)::operator_new(0x4900);
    CINSBotInvestigate::CINSBotInvestigate(this_04,pCVar9);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(CNavArea **)(param_1 + 4) = pCVar9;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(undefined **)(param_1 + 8) = &UNK_00249339 + unaff_EBX;
  }
  else {
    pvVar8 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_02);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar8;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(undefined **)(param_1 + 8) = &UNK_002492ed + unaff_EBX;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionHunt::OnEnd
 * Address: 00738bd0
 * ---------------------------------------- */

/* CINSBotActionHunt::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionHunt::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::GetName
 * Address: 007393a0
 * ---------------------------------------- */

/* CINSBotActionHunt::GetName() const */

int CINSBotActionHunt::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6f0e /* "Hunt" */ /* "Hunt" */;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldHurry
 * Address: 00738bf0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionHunt::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotActionHunt::ShouldHurry(CINSBotActionHunt *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldHurry
 * Address: 00738c00
 * ---------------------------------------- */

/* CINSBotActionHunt::ShouldHurry(INextBot const*) const */

uint __cdecl CINSBotActionHunt::ShouldHurry(INextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  uint uVar3;
  float10 fVar4;
  
  __i686_get_pc_thunk_bx();
  uVar3 = 0;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (iVar1 != 0) {
    iVar1 = (**(code **)(*(int *)(iVar1 + 0x2060) + 0x114))(iVar1 + 0x2060);
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x114))
                                (*(int *)(param_1 + 0x1c) + 0x2060);
      if (*(int *)(param_1 + 0x1c) != 0) {
        uVar3 = *(int *)(param_1 + 0x1c) + 0x2060;
      }
      fVar4 = (float10)(**(code **)(*piVar2 + 0x74))(piVar2,uVar3);
      uVar3 = (uint)(*(float *)(unaff_EBX + 0x213084 /* 2000.0f */ /* 2000.0f */) <= (float)fVar4 &&
                    (float)fVar4 != *(float *)(unaff_EBX + 0x213084 /* 2000.0f */ /* 2000.0f */));
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldAttack
 * Address: 00738d60
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionHunt::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotActionHunt::ShouldAttack(CINSBotActionHunt *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldAttack
 * Address: 00738d70
 * ---------------------------------------- */

/* CINSBotActionHunt::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionHunt::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldWalk
 * Address: 00738ca0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionHunt::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotActionHunt::ShouldWalk(CINSBotActionHunt *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::ShouldWalk
 * Address: 00738cb0
 * ---------------------------------------- */

/* CINSBotActionHunt::ShouldWalk(INextBot const*) const */

char __cdecl CINSBotActionHunt::ShouldWalk(INextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  char cVar3;
  float10 fVar4;
  
  __i686_get_pc_thunk_bx();
  cVar3 = '\x02';
  iVar1 = *(int *)(param_1 + 0x1c);
  if (iVar1 != 0) {
    iVar1 = (**(code **)(*(int *)(iVar1 + 0x2060) + 0x114))(iVar1 + 0x2060);
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x114))
                                (*(int *)(param_1 + 0x1c) + 0x2060);
      iVar1 = 0;
      if (*(int *)(param_1 + 0x1c) != 0) {
        iVar1 = *(int *)(param_1 + 0x1c) + 0x2060;
      }
      fVar4 = (float10)(**(code **)(*piVar2 + 0x74))(piVar2,iVar1);
      cVar3 = (*(float *)(unaff_EBX + 0x1ec358 /* 300.0f */ /* 300.0f */) <= (float)fVar4) + '\x01';
    }
  }
  return cVar3;
}



/* ----------------------------------------
 * CINSBotActionHunt::~CINSBotActionHunt
 * Address: 007393c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionHunt::~CINSBotActionHunt() */

void __thiscall CINSBotActionHunt::~CINSBotActionHunt(CINSBotActionHunt *this)

{
  ~CINSBotActionHunt(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::~CINSBotActionHunt
 * Address: 007393d0
 * ---------------------------------------- */

/* CINSBotActionHunt::~CINSBotActionHunt() */

void __thiscall CINSBotActionHunt::~CINSBotActionHunt(CINSBotActionHunt *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x460493 /* vtable for CINSBotActionHunt+0x8 */ /* vtable for CINSBotActionHunt+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_0046062f + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(&UNK_0046dda3 + extraout_ECX));
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::~CINSBotActionHunt
 * Address: 00739400
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionHunt::~CINSBotActionHunt() */

void __thiscall CINSBotActionHunt::~CINSBotActionHunt(CINSBotActionHunt *this)

{
  ~CINSBotActionHunt(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionHunt::~CINSBotActionHunt
 * Address: 00739410
 * ---------------------------------------- */

/* CINSBotActionHunt::~CINSBotActionHunt() */

void __thiscall CINSBotActionHunt::~CINSBotActionHunt(CINSBotActionHunt *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0046044a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x4605e6 /* vtable for CINSBotActionHunt+0x1a4 */ /* vtable for CINSBotActionHunt+0x1a4 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



