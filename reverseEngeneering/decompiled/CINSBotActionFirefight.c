/*
 * CINSBotActionFirefight -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 11
 */

/* ----------------------------------------
 * CINSBotActionFirefight::OnStart
 * Address: 00737bc0
 * ---------------------------------------- */

/* CINSBotActionFirefight::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall
CINSBotActionFirefight::OnStart(CINSBotActionFirefight *this,CINSNextBot *param_1,Action *param_2)

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
 * CINSBotActionFirefight::Update
 * Address: 00737e70
 * ---------------------------------------- */

/* CINSBotActionFirefight::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionFirefight::Update(CINSBotActionFirefight *this,CINSNextBot *param_1,float param_2)

{
  CINSBotActionFirefight *pCVar1;
  char cVar2;
  void *pvVar3;
  int *piVar4;
  int iVar5;
  CNavArea *pCVar6;
  CINSBotCaptureCP *this_00;
  CINSBotEscort *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSBotCombat *this_04;
  CBaseEntity *this_05;
  CINSBotInvestigate *this_06;
  CINSBotActionFirefight *this_07;
  CINSBotInvestigate *this_08;
  CINSNextBot *extraout_EDX;
  int unaff_EBX;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar2 = CINSBotEscort::HasEscortTarget(extraout_EDX);
  if (cVar2 == '\0') {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
    iVar5 = (**(code **)(*piVar4 + 0xd0))(piVar4,0);
    this_02 = extraout_ECX;
    if (iVar5 != 0) {
      piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
      iVar5 = (**(code **)(*piVar4 + 0xd4))(piVar4,in_stack_0000000c + 0x2060,iVar5);
      this_02 = extraout_ECX_00;
      if (iVar5 == 1) {
        pvVar3 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_04);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar3;
        *(undefined4 *)param_1 = 2;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24873c /* "Attacking nearby threats" */;
        return param_1;
      }
    }
    cVar2 = CINSNextBot::IsInvestigating(this_02);
    if (cVar2 == '\0') {
      cVar2 = CINSNextBot::HasInvestigations(this_03);
      if (cVar2 == '\0') {
        iVar5 = CBaseEntity::GetTeamNumber(this_05);
        if (iVar5 - 2U < 2) {
          this_07 = (CINSBotActionFirefight *)((iVar5 == 2) + 2);
          this_00 = (CINSBotCaptureCP *)GetTargetObjective(this_07,(int)param_2);
          pCVar1 = *(CINSBotActionFirefight **)
                    (**(int **)(unaff_EBX + 0x46ee9b /* &g_pObjectiveResource */) + 0x490 + (int)this_00 * 4);
          if (this_07 == pCVar1) {
            iVar5 = TheINSNextBots();
            CINSNextBotManager::GenerateCPGrenadeTargets
                      ((CINSNextBotManager *)this_00,iVar5,(int)this_00);
            pvVar3 = ::operator_new(0x88);
            CINSBotCaptureCP::CINSBotCaptureCP(this_00,(int)pvVar3,SUB41(this_00,0));
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(void **)(param_1 + 4) = pvVar3;
            *(undefined4 *)param_1 = 2;
            *(undefined **)(param_1 + 8) = &UNK_0024a46b + unaff_EBX;
          }
          else if (pCVar1 + -2 < (CINSBotActionFirefight *)0x2) {
            CINSNavMesh::GetRandomControlPointArea(**(int **)(unaff_EBX + 0x46e837 /* &TheNavMesh */));
            pCVar6 = (CNavArea *)::operator_new(0x4900);
            CINSBotInvestigate::CINSBotInvestigate(this_08,pCVar6);
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(CNavArea **)(param_1 + 4) = pCVar6;
            *(undefined4 *)param_1 = 2;
            *(int *)(param_1 + 8) = unaff_EBX + 0x24a45a /* "Defending our CP" */;
          }
          else {
            pvVar3 = ::operator_new(0x88);
            CINSBotCaptureCP::CINSBotCaptureCP(this_00,(int)pvVar3,SUB41(this_00,0));
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(void **)(param_1 + 4) = pvVar3;
            *(undefined4 *)param_1 = 2;
            *(undefined **)(param_1 + 8) = &UNK_0024a48f + unaff_EBX;
          }
        }
        else {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x248755 /* "Bot is not on a playteam" */;
        }
      }
      else {
        CINSNextBot::GetCurrentInvestigationArea(in_stack_0000000c);
        pCVar6 = (CNavArea *)::operator_new(0x4900);
        CINSBotInvestigate::CINSBotInvestigate(this_06,pCVar6);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(CNavArea **)(param_1 + 4) = pCVar6;
        *(undefined4 *)param_1 = 2;
        *(undefined **)(param_1 + 8) = &UNK_0024a2cd + unaff_EBX;
      }
    }
    else {
      *(undefined4 *)param_1 = 0;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
    }
  }
  else {
    pvVar3 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_01);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar3;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24a3d7 /* "Escorting " */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionFirefight::OnEnd
 * Address: 00737c00
 * ---------------------------------------- */

/* CINSBotActionFirefight::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionFirefight::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionFirefight::GetName
 * Address: 00738230
 * ---------------------------------------- */

/* CINSBotActionFirefight::GetName() const */

int CINSBotActionFirefight::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f7ccc /* "Firefight" */;
}



/* ----------------------------------------
 * CINSBotActionFirefight::ShouldAttack
 * Address: 00737c20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFirefight::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionFirefight::ShouldAttack
          (CINSBotActionFirefight *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionFirefight::ShouldAttack
 * Address: 00737c30
 * ---------------------------------------- */

/* CINSBotActionFirefight::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionFirefight::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionFirefight::GetTargetObjective
 * Address: 00737d60
 * ---------------------------------------- */

/* CINSBotActionFirefight::GetTargetObjective(int) */

int __thiscall CINSBotActionFirefight::GetTargetObjective(CINSBotActionFirefight *this,int param_1)

{
  int iVar1;
  int unaff_EBX;
  float10 fVar2;
  int in_stack_00000008;
  
  iVar1 = __i686_get_pc_thunk_bx();
  if (1 < in_stack_00000008 - 2U) {
    return iVar1;
  }
  iVar1 = **(int **)(unaff_EBX + 0x46efa3 /* &g_pObjectiveResource */);
  if (*(int *)(iVar1 + 0x494) - 2U < 2) {
    if (in_stack_00000008 == 2) {
      if (*(int *)(iVar1 + 0x490) != 2) {
        return 0;
      }
    }
    else if (*(int *)(iVar1 + 0x498) != 3) {
      return 2;
    }
    if ((in_stack_00000008 != *(int *)(iVar1 + 0x494)) &&
       (fVar2 = (float10)RandomFloat(0,0x3f800000),
       (float)fVar2 < *(float *)(unaff_EBX + 0x1ec9df /* typeinfo name for CBaseGameSystem+0x1e */) ||
       (float)fVar2 == *(float *)(unaff_EBX + 0x1ec9df /* typeinfo name for CBaseGameSystem+0x1e */))) {
      return 1;
    }
  }
  else {
    fVar2 = (float10)RandomFloat(0,0x3f800000);
    if (*(double *)(unaff_EBX + 0x1eca07 /* typeinfo name for CBaseGameSystem+0x46 */) <= (double)(float)fVar2) {
      return 1;
    }
  }
  return (uint)(in_stack_00000008 == 2) * 2;
}



/* ----------------------------------------
 * CINSBotActionFirefight::~CINSBotActionFirefight
 * Address: 00738250
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFirefight::~CINSBotActionFirefight() */

void __thiscall CINSBotActionFirefight::~CINSBotActionFirefight(CINSBotActionFirefight *this)

{
  ~CINSBotActionFirefight(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionFirefight::~CINSBotActionFirefight
 * Address: 00738260
 * ---------------------------------------- */

/* CINSBotActionFirefight::~CINSBotActionFirefight() */

void __thiscall CINSBotActionFirefight::~CINSBotActionFirefight(CINSBotActionFirefight *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x461243 /* vtable for CINSBotActionFirefight+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x4613d7 /* vtable for CINSBotActionFirefight+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46ef13 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionFirefight::~CINSBotActionFirefight
 * Address: 00738290
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFirefight::~CINSBotActionFirefight() */

void __thiscall CINSBotActionFirefight::~CINSBotActionFirefight(CINSBotActionFirefight *this)

{
  ~CINSBotActionFirefight(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionFirefight::~CINSBotActionFirefight
 * Address: 007382a0
 * ---------------------------------------- */

/* CINSBotActionFirefight::~CINSBotActionFirefight() */

void __thiscall CINSBotActionFirefight::~CINSBotActionFirefight(CINSBotActionFirefight *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4611fa /* vtable for CINSBotActionFirefight+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46138e /* vtable for CINSBotActionFirefight+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



