/*
 * CINSBotActionStrike -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 10
 */

/* ----------------------------------------
 * CINSBotActionStrike::CINSBotActionStrike
 * Address: 0073c020
 * ---------------------------------------- */

/* CINSBotActionStrike::CINSBotActionStrike() */

void __thiscall CINSBotActionStrike::CINSBotActionStrike(CINSBotActionStrike *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  in_stack_00000004[8] = 0;
  *in_stack_00000004 = extraout_ECX + 0x45e3c3;
  in_stack_00000004[9] = 0;
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
  in_stack_00000004[1] = extraout_ECX + 0x45e553;
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::OnStart
 * Address: 0073bed0
 * ---------------------------------------- */

/* CINSBotActionStrike::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotActionStrike::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::Update
 * Address: 0073c240
 * ---------------------------------------- */

/* CINSBotActionStrike::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionStrike::Update(CINSBotActionStrike *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CNavArea *pCVar4;
  int iVar5;
  float fVar6;
  void *pvVar7;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSBotInvestigate *this_02;
  CINSRules *this_03;
  CBaseEntity *this_04;
  CINSRules *this_05;
  CBaseEntity *this_06;
  CINSBotGuardCP *this_07;
  CINSBotCombat *this_08;
  CINSBotDestroyCache *this_09;
  int unaff_EBX;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x974))(in_stack_0000000c);
  iVar3 = (**(code **)(*piVar2 + 0xd0))(piVar2,0);
  this_00 = extraout_ECX;
  if (iVar3 != 0) {
    piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x97c))(in_stack_0000000c);
    iVar3 = (**(code **)(*piVar2 + 0xd4))(piVar2,in_stack_0000000c + 0x818,iVar3);
    this_00 = extraout_ECX_00;
    if (iVar3 == 1) {
      pvVar7 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_08);
      *(undefined4 *)param_1 = 2;
      *(void **)(param_1 + 4) = pvVar7;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x244372;
      return param_1;
    }
  }
  cVar1 = CINSNextBot::HasInvestigations(this_00);
  if (cVar1 == '\0') {
    iVar3 = CBaseEntity::GetTeamNumber(this_01);
    iVar5 = CINSRules::GetDefendingTeam(this_03);
    if (iVar3 == iVar5) {
      CBaseEntity::GetTeamNumber(this_04);
      fVar6 = (float)GetDesiredObjective((CINSNextBot *)param_2,(int)in_stack_0000000c);
      pvVar7 = ::operator_new(0x48fc);
      CINSBotGuardCP::CINSBotGuardCP(this_07,(int)pvVar7,fVar6);
      *(undefined4 *)param_1 = 2;
      *(void **)(param_1 + 4) = pvVar7;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2464bd;
    }
    else {
      iVar3 = CBaseEntity::GetTeamNumber(this_04);
      iVar5 = CINSRules::GetAttackingTeam(this_05);
      if (iVar3 != iVar5) {
        *(undefined4 *)param_1 = 0;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
      CBaseEntity::GetTeamNumber(this_06);
      GetDesiredObjective((CINSNextBot *)param_2,(int)in_stack_0000000c);
      pvVar7 = ::operator_new(0x4900);
      CINSBotDestroyCache::CINSBotDestroyCache(this_09,(int)pvVar7);
      *(undefined4 *)param_1 = 2;
      *(void **)(param_1 + 4) = pvVar7;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2464cf;
    }
  }
  else {
    CINSNextBot::GetCurrentInvestigationArea((CINSNextBot *)this_01);
    pCVar4 = (CNavArea *)::operator_new(0x4900);
    CINSBotInvestigate::CINSBotInvestigate(this_02,pCVar4);
    *(undefined4 *)param_1 = 2;
    *(CNavArea **)(param_1 + 4) = pCVar4;
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x245f03;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionStrike::OnEnd
 * Address: 0073bef0
 * ---------------------------------------- */

/* CINSBotActionStrike::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionStrike::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::GetName
 * Address: 0073c500
 * ---------------------------------------- */

/* CINSBotActionStrike::GetName() const */

int CINSBotActionStrike::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f65c5;
}



/* ----------------------------------------
 * CINSBotActionStrike::GetDesiredObjective
 * Address: 0073c0a0
 * ---------------------------------------- */

/* CINSBotActionStrike::GetDesiredObjective(CINSNextBot*, int) const */

undefined4 __cdecl CINSBotActionStrike::GetDesiredObjective(CINSNextBot *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  CINSRules *extraout_ECX;
  CINSRules *this;
  int unaff_EBX;
  undefined4 uVar3;
  int local_3c [3];
  int *local_30;
  undefined4 local_2c;
  int local_20 [3];
  undefined4 uStack_14;
  
  uStack_14 = 0x73c0ab;
  __i686_get_pc_thunk_bx();
  if (param_2 == 0) {
    return 0;
  }
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_30 = (int *)0x0;
  iVar2 = **(int **)(unaff_EBX + 0x46ac71);
  local_2c = 0;
  local_20[0] = 0;
  this = extraout_ECX;
  if (0 < *(int *)(iVar2 + 0x37c)) {
    do {
      iVar2 = *(int *)(iVar2 + 0x490 + local_20[0] * 4);
      iVar1 = CINSRules::GetDefendingTeam(this);
      if (iVar1 == iVar2) {
        CUtlVector<int,CUtlMemory<int,int>>::InsertBefore
                  ((CUtlVector<int,CUtlMemory<int,int>> *)local_20,(int)local_3c,local_30);
      }
      this = *(CINSRules **)(unaff_EBX + 0x46ac71);
      iVar2 = *(int *)this;
      local_20[0] = local_20[0] + 1;
    } while (local_20[0] < *(int *)(iVar2 + 0x37c));
    if (local_30 != (int *)0x0) {
      iVar2 = RandomInt(0,(int)local_30 + -1);
      uVar3 = *(undefined4 *)(local_3c[0] + iVar2 * 4);
      goto LAB_0073c180;
    }
  }
  uVar3 = 0;
LAB_0073c180:
  local_30 = (int *)0x0;
  if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x46a7cd) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x46a7cd),local_3c[0]);
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSBotActionStrike::~CINSBotActionStrike
 * Address: 0073c520
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionStrike::~CINSBotActionStrike() */

void __thiscall CINSBotActionStrike::~CINSBotActionStrike(CINSBotActionStrike *this)

{
  ~CINSBotActionStrike(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::~CINSBotActionStrike
 * Address: 0073c530
 * ---------------------------------------- */

/* CINSBotActionStrike::~CINSBotActionStrike() */

void __thiscall CINSBotActionStrike::~CINSBotActionStrike(CINSBotActionStrike *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45deb3;
  in_stack_00000004[1] = extraout_ECX + 0x45e043;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46ac43));
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::~CINSBotActionStrike
 * Address: 0073c560
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionStrike::~CINSBotActionStrike() */

void __thiscall CINSBotActionStrike::~CINSBotActionStrike(CINSBotActionStrike *this)

{
  ~CINSBotActionStrike(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionStrike::~CINSBotActionStrike
 * Address: 0073c570
 * ---------------------------------------- */

/* CINSBotActionStrike::~CINSBotActionStrike() */

void __thiscall CINSBotActionStrike::~CINSBotActionStrike(CINSBotActionStrike *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45de6a;
  in_stack_00000004[1] = unaff_EBX + 0x45dffa;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



