/*
 * CINSBotActionOccupy -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 10
 */

/* ----------------------------------------
 * CINSBotActionOccupy::OnStart
 * Address: 00739c40
 * ---------------------------------------- */

/* CINSBotActionOccupy::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall
CINSBotActionOccupy::OnStart(CINSBotActionOccupy *this,CINSNextBot *param_1,Action *param_2)

{
  Action AVar1;
  int in_stack_0000000c;
  
  AVar1 = *(Action *)(in_stack_0000000c + 0x228f);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  param_2[0x38] = AVar1;
  *(undefined1 *)(in_stack_0000000c + 0x228f) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::Update
 * Address: 00739cc0
 * ---------------------------------------- */

/* CINSBotActionOccupy::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionOccupy::Update(CINSBotActionOccupy *this,CINSNextBot *param_1,float param_2)

{
  int iVar1;
  int iVar2;
  char cVar3;
  void *pvVar4;
  int *piVar5;
  int iVar6;
  CNavArea *pCVar7;
  int iVar8;
  undefined4 uVar9;
  CINSBotEscort *this_00;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSBotCombat *this_03;
  CBaseEntity *this_04;
  CINSBotInvestigate *this_05;
  int iVar10;
  CINSNextBotManager *this_06;
  CINSBotCaptureCP *this_07;
  CINSBotInvestigate *this_08;
  CINSBotInvestigate *this_09;
  CINSNextBot *extraout_EDX;
  int unaff_EBX;
  bool bVar11;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar3 = CINSBotEscort::HasEscortTarget(extraout_EDX);
  if (cVar3 != '\0') {
    pvVar4 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_00);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar4;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x248587;
    return param_1;
  }
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
  iVar6 = (**(code **)(*piVar5 + 0xd0))(piVar5,0);
  this_01 = extraout_ECX;
  if (iVar6 != 0) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
    iVar6 = (**(code **)(*piVar5 + 0xd4))(piVar5,in_stack_0000000c + 0x2060,iVar6);
    this_01 = extraout_ECX_00;
    if (iVar6 == 1) {
      pvVar4 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_03);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar4;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2468ec;
      return param_1;
    }
  }
  cVar3 = CINSNextBot::IsInvestigating(this_01);
  if (cVar3 == '\0') {
    cVar3 = CINSNextBot::HasInvestigations(this_02);
    if (cVar3 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea(in_stack_0000000c);
      pCVar7 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_05,pCVar7);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(CNavArea **)(param_1 + 4) = pCVar7;
      *(undefined4 *)param_1 = 2;
      *(undefined **)(param_1 + 8) = &UNK_0024847d + unaff_EBX;
      return param_1;
    }
    iVar6 = CBaseEntity::GetTeamNumber(this_04);
    if (1 < iVar6 - 2U) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x246905;
      return param_1;
    }
    iVar1 = **(int **)(unaff_EBX + 0x46d04b);
    if (0 < *(int *)(iVar1 + 0x37c)) {
      bVar11 = false;
      iVar10 = (iVar6 == 2) + 2;
      iVar2 = *(int *)(iVar1 + 0x490);
      if (iVar6 == iVar2) {
        bVar11 = iVar10 == *(int *)(iVar1 + 0x450);
      }
      iVar1 = **(int **)(unaff_EBX + 0x46c9e7);
      if ((iVar1 == -0x834) || (*(int *)(iVar1 + 0x840) < 1)) {
        DevWarning((char *)(unaff_EBX + 0x2487ab));
      }
      else {
        iVar8 = RandomInt(0,*(int *)(iVar1 + 0x840) + -1);
        iVar1 = *(int *)(*(int *)(iVar1 + 0x834) + iVar8 * 4);
        if (iVar1 != 0) {
          iVar8 = TheINSNextBots();
          CINSNextBotManager::GenerateCPGrenadeTargets(this_06,iVar8,0);
          if (((bVar11) &&
              (piVar5 = (int *)UTIL_INSGetClosestPlayer
                                         ((Vector *)(iVar1 + 0x2c),iVar10,(float *)0x0),
              piVar5 != (int *)0x0)) &&
             (iVar10 = (**(code **)(*piVar5 + 0x548))(piVar5), iVar10 != 0)) {
            uVar9 = (**(code **)(*piVar5 + 0x548))(piVar5);
            CINSNextBot::AddInvestigation(in_stack_0000000c,in_stack_0000000c,uVar9,0);
            (**(code **)(*piVar5 + 0x548))(piVar5);
            pCVar7 = (CNavArea *)::operator_new(0x4900);
            CINSBotInvestigate::CINSBotInvestigate(this_08,pCVar7);
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(CNavArea **)(param_1 + 4) = pCVar7;
            *(undefined4 *)param_1 = 2;
            *(int *)(param_1 + 8) = unaff_EBX + 0x248771;
            return param_1;
          }
          if (iVar6 != iVar2) {
            pvVar4 = ::operator_new(0x88);
            CINSBotCaptureCP::CINSBotCaptureCP(this_07,(int)pvVar4,false);
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(void **)(param_1 + 4) = pvVar4;
            *(undefined4 *)param_1 = 2;
            *(int *)(param_1 + 8) = unaff_EBX + 0x24878a;
            return param_1;
          }
          CINSNextBot::AddInvestigation(in_stack_0000000c,in_stack_0000000c,iVar1,0);
          pCVar7 = (CNavArea *)::operator_new(0x4900);
          CINSBotInvestigate::CINSBotInvestigate(this_09,pCVar7);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(CNavArea **)(param_1 + 4) = pCVar7;
          *(undefined4 *)param_1 = 2;
          *(int *)(param_1 + 8) = unaff_EBX + 0x24879a;
          return param_1;
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
 * CINSBotActionOccupy::OnEnd
 * Address: 00739c80
 * ---------------------------------------- */

/* CINSBotActionOccupy::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionOccupy::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::GetName
 * Address: 0073a2a0
 * ---------------------------------------- */

/* CINSBotActionOccupy::GetName() const */

int CINSBotActionOccupy::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f72ec;
}



/* ----------------------------------------
 * CINSBotActionOccupy::ShouldAttack
 * Address: 00739ca0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOccupy::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionOccupy::ShouldAttack(CINSBotActionOccupy *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::ShouldAttack
 * Address: 00739cb0
 * ---------------------------------------- */

/* CINSBotActionOccupy::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionOccupy::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionOccupy::~CINSBotActionOccupy
 * Address: 0073a2c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOccupy::~CINSBotActionOccupy() */

void __thiscall CINSBotActionOccupy::~CINSBotActionOccupy(CINSBotActionOccupy *this)

{
  ~CINSBotActionOccupy(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::~CINSBotActionOccupy
 * Address: 0073a2d0
 * ---------------------------------------- */

/* CINSBotActionOccupy::~CINSBotActionOccupy() */

void __thiscall CINSBotActionOccupy::~CINSBotActionOccupy(CINSBotActionOccupy *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45f973;
  in_stack_00000004[1] = extraout_ECX + 0x45fb07;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46cea3));
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::~CINSBotActionOccupy
 * Address: 0073a300
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOccupy::~CINSBotActionOccupy() */

void __thiscall CINSBotActionOccupy::~CINSBotActionOccupy(CINSBotActionOccupy *this)

{
  ~CINSBotActionOccupy(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionOccupy::~CINSBotActionOccupy
 * Address: 0073a310
 * ---------------------------------------- */

/* CINSBotActionOccupy::~CINSBotActionOccupy() */

void __thiscall CINSBotActionOccupy::~CINSBotActionOccupy(CINSBotActionOccupy *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45f92a;
  in_stack_00000004[1] = (int)(&UNK_0045fabe + unaff_EBX);
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



