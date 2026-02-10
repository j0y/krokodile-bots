/*
 * CINSBotActionPush -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 10
 */

/* ----------------------------------------
 * CINSBotActionPush::OnStart
 * Address: 0073ae70
 * ---------------------------------------- */

/* CINSBotActionPush::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall
CINSBotActionPush::OnStart(CINSBotActionPush *this,CINSNextBot *param_1,Action *param_2)

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
 * CINSBotActionPush::Update
 * Address: 0073aef0
 * ---------------------------------------- */

/* CINSBotActionPush::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionPush::Update(CINSBotActionPush *this,CINSNextBot *param_1,float param_2)

{
  int iVar1;
  char cVar2;
  void *pvVar3;
  int *piVar4;
  int iVar5;
  CNavArea *pCVar6;
  CINSNextBot *pCVar7;
  CINSBotCaptureCP *this_00;
  CINSBotEscort *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CINSBotCombat *this_03;
  CBaseEntity *this_04;
  CINSBotInvestigate *this_05;
  CINSNextBot *extraout_EDX;
  int unaff_EBX;
  CINSNextBot *in_stack_0000000c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  cVar2 = CINSBotEscort::HasEscortTarget(extraout_EDX);
  if (cVar2 != '\0') {
    pvVar3 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_01);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar3;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x247357 /* "Escorting " */;
    return param_1;
  }
  piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
  iVar5 = (**(code **)(*piVar4 + 0xd0))(piVar4,0);
  pCVar7 = extraout_ECX;
  if (iVar5 != 0) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
    iVar5 = (**(code **)(*piVar4 + 0xd4))(piVar4,in_stack_0000000c + 0x2060,iVar5);
    pCVar7 = extraout_ECX_00;
    if (iVar5 == 1) {
      pvVar3 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_03);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar3;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2456bc /* "Attacking nearby threats" */;
      return param_1;
    }
  }
  cVar2 = CINSNextBot::IsInvestigating(pCVar7);
  if (cVar2 == '\0') {
    cVar2 = CINSNextBot::HasInvestigations(this_02);
    if (cVar2 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea(in_stack_0000000c);
      pCVar6 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_05,pCVar6);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(CNavArea **)(param_1 + 4) = pCVar6;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24724d /* "I have an investigation!" */;
      return param_1;
    }
    iVar5 = CBaseEntity::GetTeamNumber(this_04);
    if (1 < iVar5 - 2U) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2456d5 /* "Bot is not on a playteam" */;
      return param_1;
    }
    pCVar7 = (CINSNextBot *)TheINSNextBots();
    this_00 = (CINSBotCaptureCP *)CINSNextBotManager::GetDesiredPushTypeObjective(pCVar7);
    iVar1 = *(int *)(**(int **)(unaff_EBX + 0x46be1b /* &g_pObjectiveResource */) + 0x490 + (int)this_00 * 4);
    if ((iVar5 == 2) + 2 == iVar1) {
      iVar5 = TheINSNextBots();
      CINSNextBotManager::GenerateCPGrenadeTargets((CINSNextBotManager *)this_00,iVar5,(int)this_00)
      ;
      pvVar3 = ::operator_new(0x88);
      CINSBotCaptureCP::CINSBotCaptureCP(this_00,(int)pvVar3,SUB41(this_00,0));
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar3;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2473eb /* "Attacking enemy controlled point" */;
      return param_1;
    }
    if (1 < iVar1 - 2U) {
      pvVar3 = ::operator_new(0x88);
      CINSBotCaptureCP::CINSBotCaptureCP(this_00,(int)pvVar3,SUB41(this_00,0));
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar3;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24740f /* "Capturing neutral controlled point" */;
      return param_1;
    }
    iVar5 = CINSNavMesh::GetRandomControlPointArea(**(int **)(unaff_EBX + 0x46b7b7 /* &TheNavMesh */));
    if (iVar5 == 0) {
      Warning(unaff_EBX + 0x2474cb /* "NAVMESH ERROR: Unable to find any navmesh areas for CP %i, navmesh probably o..." */,this_00);
    }
    else {
      CNavArea::GetRandomPoint();
      CINSNextBot::AddInvestigation(in_stack_0000000c,local_28,local_24,local_20,0);
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionPush::OnEnd
 * Address: 0073aeb0
 * ---------------------------------------- */

/* CINSBotActionPush::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionPush::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionPush::GetName
 * Address: 0073b3e0
 * ---------------------------------------- */

/* CINSBotActionPush::GetName() const */

int CINSBotActionPush::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6fa6 /* "Push" */;
}



/* ----------------------------------------
 * CINSBotActionPush::ShouldAttack
 * Address: 0073aed0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionPush::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotActionPush::ShouldAttack(CINSBotActionPush *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionPush::ShouldAttack
 * Address: 0073aee0
 * ---------------------------------------- */

/* CINSBotActionPush::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionPush::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionPush::~CINSBotActionPush
 * Address: 0073b400
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionPush::~CINSBotActionPush() */

void __thiscall CINSBotActionPush::~CINSBotActionPush(CINSBotActionPush *this)

{
  ~CINSBotActionPush(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionPush::~CINSBotActionPush
 * Address: 0073b410
 * ---------------------------------------- */

/* CINSBotActionPush::~CINSBotActionPush() */

void __thiscall CINSBotActionPush::~CINSBotActionPush(CINSBotActionPush *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45ec13 /* vtable for CINSBotActionPush+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x45eda7 /* vtable for CINSBotActionPush+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46bd63 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionPush::~CINSBotActionPush
 * Address: 0073b440
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionPush::~CINSBotActionPush() */

void __thiscall CINSBotActionPush::~CINSBotActionPush(CINSBotActionPush *this)

{
  ~CINSBotActionPush(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionPush::~CINSBotActionPush
 * Address: 0073b450
 * ---------------------------------------- */

/* CINSBotActionPush::~CINSBotActionPush() */

void __thiscall CINSBotActionPush::~CINSBotActionPush(CINSBotActionPush *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45ebca /* vtable for CINSBotActionPush+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45ed5e /* vtable for CINSBotActionPush+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



