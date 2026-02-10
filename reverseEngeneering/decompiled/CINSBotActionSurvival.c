/*
 * CINSBotActionSurvival -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionSurvival::OnStart
 * Address: 0073ca70
 * ---------------------------------------- */

/* CINSBotActionSurvival::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotActionSurvival::OnStart(CINSBotActionSurvival *this,CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  CINSNextBot *extraout_ECX;
  CINSWeapon *this_00;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar4;
  CINSNextBot *this_06;
  int *in_stack_0000000c;
  undefined4 uVar5;
  undefined4 uVar6;
  
  iVar3 = __i686_get_pc_thunk_bx();
  fVar4 = (float10)CountdownTimer::Now();
  this_06 = (CINSNextBot *)((float)fVar4 + *(float *)(iVar3 + 0x40));
  if (*(CINSNextBot **)(iVar3 + 0x44) != this_06) {
    (**(code **)(*(int *)(iVar3 + 0x3c) + 4))(iVar3 + 0x3c,iVar3 + 0x44);
    *(CINSNextBot **)(iVar3 + 0x44) = this_06;
    this_06 = extraout_ECX;
  }
  *(undefined1 *)(iVar3 + 0x38) = *(undefined1 *)((int)in_stack_0000000c + 0x228f);
  piVar1 = *(int **)(unaff_EBX + 0x469e77);
  *(undefined1 *)((int)in_stack_0000000c + 0x228f) = 0;
  if (*(char *)(*piVar1 + 0x40c) != '\0') {
    uVar6 = 0;
    uVar5 = 0x3f800000;
    fVar4 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_06,(float)in_stack_0000000c,0x3f800000);
    if (*(float *)(unaff_EBX + 0x1ec733) <= (float)fVar4 &&
        (float)fVar4 != *(float *)(unaff_EBX + 0x1ec733)) {
      cVar2 = (**(code **)(*in_stack_0000000c + 0x158))(in_stack_0000000c,uVar5,uVar6);
      if (cVar2 != '\0') {
        iVar3 = CINSPlayer::GetActiveINSWeapon();
        if (iVar3 != 0) {
          cVar2 = CINSWeapon::HasLasersights(this_00);
          this_02 = this_01;
          if (cVar2 != '\0') {
            cVar2 = CINSWeapon::IsLasersightsOn(this_01);
            this_02 = this_05;
            if (cVar2 == '\0') {
              CINSWeapon::ToggleLasersights(this_05);
              this_02 = extraout_ECX_00;
            }
          }
          cVar2 = CINSWeapon::HasFlashlight(this_02);
          if (cVar2 != '\0') {
            cVar2 = CINSWeapon::IsFlashlightOn(this_03);
            if (cVar2 == '\0') {
              CINSWeapon::ToggleFlashlight(this_04);
            }
          }
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionSurvival::Update
 * Address: 0073c620
 * ---------------------------------------- */

/* CINSBotActionSurvival::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionSurvival::Update(CINSBotActionSurvival *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  void *pvVar6;
  int iVar7;
  CNavArea *pCVar8;
  CBaseEntity *this_00;
  CINSRules *this_01;
  CINSNextBot *extraout_ECX;
  CINSBotCombat *this_02;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_03;
  CINSNextBot *this_04;
  CBaseEntity *this_05;
  CINSBotCaptureCP *this_06;
  CINSNextBot *this_07;
  CINSBotPatrol *this_08;
  CINSBotEscort *this_09;
  CINSBotCombat *this_10;
  CINSNextBot *this_11;
  CINSBotInvestigate *this_12;
  int unaff_EBX;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x46a2cd) != 0) {
    piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
    piVar2 = (int *)(**(code **)(*piVar2 + 0xd0))(piVar2,0);
    iVar3 = CBaseEntity::GetTeamNumber(this_00);
    iVar4 = CINSRules::GetBotTeam(this_01);
    if (iVar3 == iVar4) {
      this_03 = extraout_ECX;
      if (piVar2 != (int *)0x0) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
        iVar3 = (**(code **)(*piVar5 + 0xd4))(piVar5,in_stack_0000000c + 0x2060,piVar2);
        if (iVar3 == 1) {
          pvVar6 = ::operator_new(0x88);
          CINSBotCombat::CINSBotCombat(this_10);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          goto LAB_0073c706;
        }
        (**(code **)(*piVar2 + 0x10))(piVar2);
        CINSNextBot::AddInvestigation();
        this_03 = extraout_ECX_00;
      }
      cVar1 = CINSNextBot::IsInvestigating(this_03);
      if (cVar1 == '\0') {
        cVar1 = CINSNextBot::HasInvestigations(this_04);
        if ((cVar1 != '\0') &&
           (iVar3 = CINSNextBot::GetCurrentInvestigationArea(this_07), iVar3 != 0)) {
          CINSNextBot::GetCurrentInvestigationArea(this_11);
          pCVar8 = (CNavArea *)::operator_new(0x4900);
          CINSBotInvestigate::CINSBotInvestigate(this_12,pCVar8);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(undefined4 *)param_1 = 2;
          *(CNavArea **)(param_1 + 4) = pCVar8;
          *(int *)(param_1 + 8) = unaff_EBX + 0x245b23;
          return param_1;
        }
        pvVar6 = ::operator_new(0x4934);
        CINSBotPatrol::CINSBotPatrol(this_08);
        *(undefined4 *)param_1 = 2;
        *(void **)(param_1 + 4) = pvVar6;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x246117;
        return param_1;
      }
    }
    else {
      cVar1 = CINSBotEscort::HasEscortTarget(in_stack_0000000c);
      if (cVar1 != '\0') {
        pvVar6 = ::operator_new(0x9c);
        CINSBotEscort::CINSBotEscort(this_09);
        *(undefined4 *)param_1 = 2;
        *(void **)(param_1 + 4) = pvVar6;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24612c;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        return param_1;
      }
      if (piVar2 != (int *)0x0) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
        iVar3 = (**(code **)(*piVar5 + 0xd4))(piVar5,in_stack_0000000c + 0x2060,piVar2);
        if (iVar3 == 1) {
          pvVar6 = ::operator_new(0x88);
          CINSBotCombat::CINSBotCombat(this_02);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
LAB_0073c706:
          *(undefined4 *)param_1 = 2;
          *(void **)(param_1 + 4) = pvVar6;
          *(undefined **)(param_1 + 8) = &UNK_00243f92 + unaff_EBX;
          return param_1;
        }
      }
      iVar4 = 1;
      iVar3 = **(int **)(unaff_EBX + 0x46a6f1);
      if (1 < *(int *)(iVar3 + 0x37c)) {
        do {
          iVar3 = *(int *)(iVar3 + 0x490 + iVar4 * 4);
          iVar7 = CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_0000000c);
          if (iVar7 == iVar3) {
            iVar3 = **(int **)(unaff_EBX + 0x46a6f1);
          }
          else {
            iVar7 = CBaseEntity::GetTeamNumber(this_05);
            iVar3 = **(int **)(unaff_EBX + 0x46a6f1);
            if (iVar7 == 2) {
              cVar1 = *(char *)(iVar3 + 0x690 + iVar4);
            }
            else {
              if (iVar7 != 3) goto LAB_0073c81f;
              cVar1 = *(char *)(iVar3 + 0x6a0 + iVar4);
            }
            if (cVar1 == '\0') {
LAB_0073c81f:
              pvVar6 = ::operator_new(0x88);
              CINSBotCaptureCP::CINSBotCaptureCP(this_06,(int)pvVar6,SUB41(iVar4,0));
              *(undefined4 *)((int)param_2 + 0x20) = 0;
              *(undefined4 *)((int)param_2 + 0x24) = 0;
              *(undefined4 *)((int)param_2 + 0x28) = 0;
              *(undefined4 *)((int)param_2 + 0x2c) = 0;
              *(undefined4 *)param_1 = 2;
              *(void **)(param_1 + 4) = pvVar6;
              *(int *)(param_1 + 8) = unaff_EBX + 0x246148;
              return param_1;
            }
          }
          iVar4 = iVar4 + 1;
        } while (iVar4 < *(int *)(iVar3 + 0x37c));
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionSurvival::OnEnd
 * Address: 0073c5e0
 * ---------------------------------------- */

/* CINSBotActionSurvival::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionSurvival::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::GetName
 * Address: 0073cde0
 * ---------------------------------------- */

/* CINSBotActionSurvival::GetName() const */

int CINSBotActionSurvival::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f60c0;
}



/* ----------------------------------------
 * CINSBotActionSurvival::ShouldHurry
 * Address: 0073cc70
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSurvival::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotActionSurvival::ShouldHurry(CINSBotActionSurvival *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::ShouldHurry
 * Address: 0073cc80
 * ---------------------------------------- */

/* CINSBotActionSurvival::ShouldHurry(INextBot const*) const */

char __thiscall CINSBotActionSurvival::ShouldHurry(CINSBotActionSurvival *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  char cVar4;
  float10 fVar5;
  float fVar6;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  cVar4 = '\x02';
  if (in_stack_00000008 != (int *)0x0) {
    iVar2 = (**(code **)(*in_stack_00000008 + 200))();
    if (iVar2 != 0) {
      iVar2 = (**(code **)(*in_stack_00000008 + 0x114))();
      if (iVar2 != 0) {
        pcVar1 = *(code **)(*in_stack_00000008 + 0x134);
        piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x114))();
        (**(code **)(*piVar3 + 0x18))(piVar3);
        fVar5 = (float10)(*pcVar1)();
        fVar6 = ((float)*(int *)(**(int **)(unaff_EBX + 0x469c64) + 1000) +
                *(float *)(unaff_EBX + 0x17be7c)) * *(float *)(unaff_EBX + 0x1f6eac);
        if (*(float *)(unaff_EBX + 0x17be80) <= fVar6) {
          fVar6 = *(float *)(unaff_EBX + 0x17be80);
        }
        if (fVar6 <= *(float *)(unaff_EBX + 0x17be74)) {
          fVar6 = *(float *)(unaff_EBX + 0x17be74);
        }
        cVar4 = ((float)fVar5 <=
                fVar6 * *(float *)(&DAT_00244a0c + unaff_EBX) +
                *(float *)(&DAT_001e837c + unaff_EBX)) + '\x01';
      }
    }
  }
  return cVar4;
}



/* ----------------------------------------
 * CINSBotActionSurvival::ShouldAttack
 * Address: 0073c600
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSurvival::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionSurvival::ShouldAttack
          (CINSBotActionSurvival *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::ShouldAttack
 * Address: 0073c610
 * ---------------------------------------- */

/* CINSBotActionSurvival::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionSurvival::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotActionSurvival::~CINSBotActionSurvival
 * Address: 0073ce00
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSurvival::~CINSBotActionSurvival() */

void __thiscall CINSBotActionSurvival::~CINSBotActionSurvival(CINSBotActionSurvival *this)

{
  ~CINSBotActionSurvival(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::~CINSBotActionSurvival
 * Address: 0073ce10
 * ---------------------------------------- */

/* CINSBotActionSurvival::~CINSBotActionSurvival() */

void __thiscall CINSBotActionSurvival::~CINSBotActionSurvival(CINSBotActionSurvival *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45d7b3;
  in_stack_00000004[1] = extraout_ECX + 0x45d94b;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46a363));
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::~CINSBotActionSurvival
 * Address: 0073ce40
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSurvival::~CINSBotActionSurvival() */

void __thiscall CINSBotActionSurvival::~CINSBotActionSurvival(CINSBotActionSurvival *this)

{
  ~CINSBotActionSurvival(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionSurvival::~CINSBotActionSurvival
 * Address: 0073ce50
 * ---------------------------------------- */

/* CINSBotActionSurvival::~CINSBotActionSurvival() */

void __thiscall CINSBotActionSurvival::~CINSBotActionSurvival(CINSBotActionSurvival *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45d76a;
  in_stack_00000004[1] = unaff_EBX + 0x45d902;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



