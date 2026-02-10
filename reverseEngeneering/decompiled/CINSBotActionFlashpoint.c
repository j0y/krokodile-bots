/*
 * CINSBotActionFlashpoint -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionFlashpoint::CINSBotActionFlashpoint
 * Address: 00738480
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::CINSBotActionFlashpoint() */

void __thiscall CINSBotActionFlashpoint::CINSBotActionFlashpoint(CINSBotActionFlashpoint *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  in_stack_00000004[8] = 0;
  *in_stack_00000004 = extraout_ECX + 0x461203 /* vtable for CINSBotActionFlashpoint+0x8 */;
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
  in_stack_00000004[1] = extraout_ECX + 0x461397 /* vtable for CINSBotActionFlashpoint+0x19c */;
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::OnStart
 * Address: 00738310
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotActionFlashpoint::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::Update
 * Address: 00738700
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionFlashpoint::Update(CINSBotActionFlashpoint *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CNavArea *pCVar4;
  CFmtStrN<256,false> *this_00;
  void *pvVar5;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSBotInvestigate *this_04;
  CINSBotCombat *this_05;
  CBaseEntity *this_06;
  int unaff_EBX;
  float10 fVar6;
  CINSNextBot *in_stack_0000000c;
  int local_24c;
  char local_234 [5];
  undefined1 local_22f [263];
  char local_128 [5];
  undefined1 local_123 [271];
  undefined4 uStack_14;
  
  uStack_14 = 0x73870b;
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
  iVar3 = (**(code **)(*piVar2 + 0xd0))(piVar2,0);
  this_01 = extraout_ECX;
  if (iVar3 != 0) {
    piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
    iVar3 = (**(code **)(*piVar2 + 0xd4))(piVar2,in_stack_0000000c + 0x2060,iVar3);
    this_01 = extraout_ECX_00;
    if (iVar3 == 1) {
      pvVar5 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_05);
      *(undefined4 *)param_1 = 2;
      *(void **)(param_1 + 4) = pvVar5;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x247eb2 /* "Attacking nearby threats" */;
      return param_1;
    }
  }
  cVar1 = CINSNextBot::IsInvestigating(this_01);
  if (cVar1 == '\0') {
    cVar1 = CINSNextBot::HasInvestigations(this_02);
    if (cVar1 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea(this_03);
      pCVar4 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_04,pCVar4);
      *(undefined4 *)param_1 = 2;
      *(CNavArea **)(param_1 + 4) = pCVar4;
      *(int *)(param_1 + 8) = unaff_EBX + 0x249a43 /* "I have an investigation!" */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
    fVar6 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_03,(float)in_stack_0000000c,0x42480000);
    *(bool *)((int)param_2 + 0x38) = (float)fVar6 < *(float *)(unaff_EBX + 0x1eb381 /* typeinfo name for ISaveRestoreOps+0x67 */);
    this_00 = (CFmtStrN<256,false> *)GetDesiredObjective((CINSNextBot *)param_2);
    iVar3 = CBaseEntity::GetTeamNumber(this_06);
    if (this_00 != (CFmtStrN<256,false> *)0xffffffff) {
      local_24c = **(int **)(CBreakable::SetBasePropData + unaff_EBX + 1);
      if ((*(char *)((int)param_2 + 0x38) != '\0') ||
         ((iVar3 == 2) + 2 == *(int *)(local_24c + 0x450 + (int)this_00 * 4))) {
        CINSNavMesh::GetRandomControlPointSurroundingArea(**(int **)(&DAT_0046dfad + unaff_EBX));
        CINSNextBot::AddInvestigation();
        local_24c = **(int **)(CBreakable::SetBasePropData + unaff_EBX + 1);
      }
      if (*(int *)(local_24c + 0x6f0 + (int)this_00 * 4) == 0) {
        cVar1 = CINSBotDestroyCache::CanIDestroyCache(in_stack_0000000c);
        if ((cVar1 != '\0') && (*(int *)(*(int *)(unaff_EBX + 0x46e901 /* &CINSBotDestroyCache::m_nTotalDestroyers */) + (int)this_00 * 4) < 1)) {
          CFmtStrN<256,false>::CFmtStrN(this_00,local_234,unaff_EBX + 0x249c41 /* "Destroying %i" */,this_00);
          pvVar5 = ::operator_new(0x4900);
          CINSBotDestroyCache::CINSBotDestroyCache((CINSBotDestroyCache *)this_00,(int)pvVar5);
          *(undefined4 *)param_1 = 2;
          *(void **)(param_1 + 4) = pvVar5;
          *(undefined1 **)(param_1 + 8) = local_22f;
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          return param_1;
        }
        CINSNavMesh::GetRandomControlPointSurroundingArea(**(int **)(&DAT_0046dfad + unaff_EBX));
        CINSNextBot::AddInvestigation();
      }
      CFmtStrN<256,false>::CFmtStrN(this_00,local_128,unaff_EBX + 0x249c4f /* "Capturing %i" */,this_00);
      pvVar5 = ::operator_new(0x88);
      CINSBotCaptureCP::CINSBotCaptureCP((CINSBotCaptureCP *)this_00,(int)pvVar5,SUB41(this_00,0));
      *(undefined4 *)param_1 = 2;
      *(void **)(param_1 + 4) = pvVar5;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(undefined1 **)(param_1 + 8) = local_123;
      return param_1;
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::OnEnd
 * Address: 00738330
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionFlashpoint::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::GetName
 * Address: 00738af0
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::GetName() const */

int CINSBotActionFlashpoint::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f75e0 /* "Flashpoint" */;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::ShouldAttack
 * Address: 00738340
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFlashpoint::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionFlashpoint::ShouldAttack
          (CINSBotActionFlashpoint *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::ShouldAttack
 * Address: 00738350
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionFlashpoint::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::GetDesiredObjective
 * Address: 00738500
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::GetDesiredObjective(CINSNextBot*) */

uint __cdecl CINSBotActionFlashpoint::GetDesiredObjective(CINSNextBot *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  CBaseEntity *this;
  int unaff_EBX;
  int iVar5;
  
  __i686_get_pc_thunk_bx();
  iVar2 = CBaseEntity::GetTeamNumber(this);
  piVar1 = *(int **)(unaff_EBX + 0x46e80b /* &g_pObjectiveResource */);
  iVar5 = (iVar2 == 2) + 2;
  if (param_1[0x38] == (CINSNextBot)0x0) {
    if (iVar2 != 2) goto LAB_00738580;
  }
  else {
    iVar4 = *piVar1;
    if (iVar2 != 2) {
      if (iVar2 == *(int *)(iVar4 + 0x498)) {
        return 2;
      }
      if (iVar2 == *(int *)(iVar4 + 0x49c)) {
        if (iVar2 != *(int *)(iVar4 + 0x4a0)) {
          return 3;
        }
        goto LAB_00738676;
      }
      if (iVar2 == *(int *)(iVar4 + 0x4a0)) {
        return 4;
      }
LAB_00738580:
      iVar3 = RandomInt(0,1);
      iVar4 = *piVar1;
      if ((iVar2 != *(int *)(iVar4 + 0x498)) && (iVar3 < 1)) {
        return 2;
      }
      if (iVar5 != *(int *)(iVar4 + 0x490)) {
        return (uint)(iVar5 == *(int *)(iVar4 + 0x494)) * 2 - 1;
      }
      if (iVar5 != *(int *)(iVar4 + 0x494)) {
        return 0;
      }
LAB_007386ae:
      iVar2 = RandomInt(0,1);
      return (uint)(iVar2 < 1);
    }
    if (*(int *)(iVar4 + 0x498) == 2) {
      return 2;
    }
    if (*(int *)(iVar4 + 0x490) == 2) {
      if (*(int *)(iVar4 + 0x494) != 2) {
        return 0;
      }
      goto LAB_007386ae;
    }
    if (*(int *)(iVar4 + 0x494) == 2) {
      return 1;
    }
  }
  iVar4 = RandomInt(0,1);
  iVar2 = *piVar1;
  if ((*(int *)(iVar2 + 0x498) != 2) && (iVar4 < 1)) {
    return 2;
  }
  if (iVar5 != *(int *)(iVar2 + 0x49c)) {
    return (uint)(iVar5 == *(int *)(iVar2 + 0x4a0)) * 5 - 1;
  }
  if (iVar5 != *(int *)(iVar2 + 0x4a0)) {
    return 3;
  }
LAB_00738676:
  iVar2 = RandomInt(0,1);
  return (iVar2 < 1) + 3;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::~CINSBotActionFlashpoint
 * Address: 00738b10
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFlashpoint::~CINSBotActionFlashpoint() */

void __thiscall CINSBotActionFlashpoint::~CINSBotActionFlashpoint(CINSBotActionFlashpoint *this)

{
  ~CINSBotActionFlashpoint(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::~CINSBotActionFlashpoint
 * Address: 00738b20
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::~CINSBotActionFlashpoint() */

void __thiscall CINSBotActionFlashpoint::~CINSBotActionFlashpoint(CINSBotActionFlashpoint *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x460b63 /* vtable for CINSBotActionFlashpoint+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x460cf7 /* vtable for CINSBotActionFlashpoint+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46e653 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::~CINSBotActionFlashpoint
 * Address: 00738b50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionFlashpoint::~CINSBotActionFlashpoint() */

void __thiscall CINSBotActionFlashpoint::~CINSBotActionFlashpoint(CINSBotActionFlashpoint *this)

{
  ~CINSBotActionFlashpoint(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionFlashpoint::~CINSBotActionFlashpoint
 * Address: 00738b60
 * ---------------------------------------- */

/* CINSBotActionFlashpoint::~CINSBotActionFlashpoint() */

void __thiscall CINSBotActionFlashpoint::~CINSBotActionFlashpoint(CINSBotActionFlashpoint *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x460b1a /* vtable for CINSBotActionFlashpoint+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x460cae /* vtable for CINSBotActionFlashpoint+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



