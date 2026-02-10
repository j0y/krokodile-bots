/*
 * CINSBotActionSkirmish -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionSkirmish::CINSBotActionSkirmish
 * Address: 0073b630
 * ---------------------------------------- */

/* CINSBotActionSkirmish::CINSBotActionSkirmish() */

void __thiscall CINSBotActionSkirmish::CINSBotActionSkirmish(CINSBotActionSkirmish *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  in_stack_00000004[8] = 0;
  *in_stack_00000004 = extraout_ECX + 0x45ebd3 /* vtable for CINSBotActionSkirmish+0x8 */ /* vtable for CINSBotActionSkirmish+0x8 */;
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
  in_stack_00000004[1] = extraout_ECX + 0x45ed67 /* vtable for CINSBotActionSkirmish+0x19c */ /* vtable for CINSBotActionSkirmish+0x19c */;
  *(undefined1 *)(in_stack_00000004 + 0xe) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::OnStart
 * Address: 0073b4c0
 * ---------------------------------------- */

/* CINSBotActionSkirmish::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotActionSkirmish::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::Update
 * Address: 0073b910
 * ---------------------------------------- */

/* CINSBotActionSkirmish::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionSkirmish::Update(CINSBotActionSkirmish *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  void *pvVar2;
  int *piVar3;
  int iVar4;
  CNavArea *pCVar5;
  CFmtStrN<256,false> *this_00;
  CINSBotEscort *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSBotInvestigate *this_04;
  CBaseEntity *this_05;
  CINSBotDestroyCache *this_06;
  CINSBotCombat *this_07;
  CFmtStrN<256,false> *extraout_ECX_01;
  CFmtStrN<256,false> *extraout_ECX_02;
  CFmtStrN<256,false> *this_08;
  CINSBotCaptureCP *this_09;
  int iVar6;
  int unaff_EBX;
  float10 fVar7;
  CINSBotActionSkirmish *in_stack_0000000c;
  char local_24c [5];
  undefined1 local_247 [263];
  char local_140 [5];
  undefined1 local_13b [263];
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x73b91b;
  __i686_get_pc_thunk_bx();
  cVar1 = CINSBotEscort::HasEscortTarget((CINSNextBot *)in_stack_0000000c);
  if (cVar1 == '\0') {
    piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    iVar4 = (**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
    this_02 = extraout_ECX;
    if (iVar4 != 0) {
      piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar4 = (**(code **)(*piVar3 + 0xd4 /* IIntention::ShouldAttack */))(piVar3,in_stack_0000000c + 0x2060,iVar4);
      this_02 = extraout_ECX_00;
      if (iVar4 == 1) {
        pvVar2 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_07);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar2;
        *(int *)(param_1 + 8) = unaff_EBX + 0x244ca2 /* "Attacking nearby threats" */ /* "Attacking nearby threats" */;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        return param_1;
      }
    }
    cVar1 = CINSNextBot::HasInvestigations(this_02);
    if (cVar1 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea(this_03);
      pCVar5 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_04,pCVar5);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(CNavArea **)(param_1 + 4) = pCVar5;
      *(undefined **)(param_1 + 8) = &UNK_00246833 + unaff_EBX;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      return param_1;
    }
    fVar7 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_03,(float)in_stack_0000000c,0x42480000 /* 50.0f */);
    *(bool *)((int)param_2 + 0x38) = (float)fVar7 < *(float *)(unaff_EBX + 0x1e8171 /* 0.25f */ /* 0.25f */);
    this_00 = (CFmtStrN<256,false> *)GetDesiredObjective(in_stack_0000000c,(CINSNextBot *)param_2);
    iVar4 = CBaseEntity::GetTeamNumber(this_05);
    if (this_00 == (CFmtStrN<256,false> *)0xffffffff) {
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
    }
    else {
      iVar6 = **(int **)(unaff_EBX + 0x46b401 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
      this_08 = *(CFmtStrN<256,false> **)(iVar6 + 0x450 + (int)this_00 * 4);
      if ((*(char *)((int)param_2 + 0x38) != '\0') ||
         ((CFmtStrN<256,false> *)((iVar4 == 2) + 2) == this_08)) {
        iVar4 = CINSNavMesh::GetRandomControlPointSurroundingArea(**(int **)(unaff_EBX + 0x46ad9d /* &TheNavMesh */ /* &TheNavMesh */));
        if (iVar4 != 0) {
          CNavArea::GetRandomPoint();
          CINSNextBot::AddInvestigation(in_stack_0000000c,local_34,local_30,local_2c,0);
        }
        this_08 = *(CFmtStrN<256,false> **)(unaff_EBX + 0x46b401 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
        iVar6 = *(int *)this_08;
      }
      if (*(int *)(iVar6 + 0x6f0 + (int)this_00 * 4) == 0) {
        cVar1 = CINSBotDestroyCache::CanIDestroyCache((CINSNextBot *)in_stack_0000000c);
        if ((cVar1 != '\0') && (*(int *)(*(int *)(unaff_EBX + 0x46b6f1 /* &CINSBotDestroyCache::m_nTotalDestroyers */ /* &CINSBotDestroyCache::m_nTotalDestroyers */) + (int)this_00 * 4) < 1)) {
          CFmtStrN<256,false>::CFmtStrN(this_00,local_24c,unaff_EBX + 0x246a31 /* "Destroying %i" */ /* "Destroying %i" */,this_00);
          pvVar2 = ::operator_new(0x4900);
          CINSBotDestroyCache::CINSBotDestroyCache(this_06,(int)pvVar2);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(void **)(param_1 + 4) = pvVar2;
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(undefined1 **)(param_1 + 8) = local_247;
          return param_1;
        }
        iVar4 = CINSNavMesh::GetRandomControlPointSurroundingArea(**(int **)(unaff_EBX + 0x46ad9d /* &TheNavMesh */ /* &TheNavMesh */));
        this_08 = extraout_ECX_01;
        if (iVar4 != 0) {
          CNavArea::GetRandomPoint();
          CINSNextBot::AddInvestigation(in_stack_0000000c,local_28,local_24,local_20,0);
          this_08 = extraout_ECX_02;
        }
      }
      CFmtStrN<256,false>::CFmtStrN(this_08,local_140,unaff_EBX + 0x246a3f /* "Capturing %i" */ /* "Capturing %i" */,this_00);
      pvVar2 = ::operator_new(0x88);
      CINSBotCaptureCP::CINSBotCaptureCP(this_09,(int)pvVar2,SUB41(this_00,0));
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(void **)(param_1 + 4) = pvVar2;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(undefined1 **)(param_1 + 8) = local_13b;
    }
  }
  else {
    pvVar2 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_01);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar2;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24693d /* "Escorting " */ /* "Escorting " */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::OnEnd
 * Address: 0073b4e0
 * ---------------------------------------- */

/* CINSBotActionSkirmish::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionSkirmish::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::GetName
 * Address: 0073bdf0
 * ---------------------------------------- */

/* CINSBotActionSkirmish::GetName() const */

int CINSBotActionSkirmish::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6ae6 /* "Skirmish" */ /* "Skirmish" */;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::ShouldAttack
 * Address: 0073b4f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSkirmish::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionSkirmish::ShouldAttack
          (CINSBotActionSkirmish *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::ShouldAttack
 * Address: 0073b500
 * ---------------------------------------- */

/* CINSBotActionSkirmish::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionSkirmish::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::GetDesiredObjective
 * Address: 0073b6b0
 * ---------------------------------------- */

/* CINSBotActionSkirmish::GetDesiredObjective(CINSNextBot*) */

int __thiscall
CINSBotActionSkirmish::GetDesiredObjective(CINSBotActionSkirmish *this,CINSNextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  CBaseEntity *this_00;
  int iVar6;
  int iVar7;
  int iVar8;
  int unaff_EBX;
  int *piVar9;
  int *piVar10;
  float10 fVar11;
  CINSNextBot *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar4 = CBaseEntity::GetTeamNumber(this_00);
  iVar6 = (iVar4 == 2) + 2;
  if (param_1[0x38] != (CINSNextBot)0x0) {
    if (iVar4 == 2) {
      piVar9 = (int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x450);
      piVar10 = (int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490);
      iVar1 = *piVar10;
      iVar8 = *piVar9;
      iVar7 = 0;
      iVar5 = -1;
      while ((iVar2 = iVar7, iVar1 == 2 || (iVar6 == iVar8))) {
        iVar7 = iVar2 + 1;
        if (iVar7 == 5) {
          return iVar2;
        }
        iVar1 = piVar10[iVar7];
        iVar8 = piVar9[iVar7];
        iVar5 = iVar2;
      }
    }
    else {
      iVar1 = **(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
      iVar8 = *(int *)(iVar1 + 0x4a0);
      iVar2 = *(int *)(iVar1 + 0x460);
      iVar7 = 4;
      iVar5 = -1;
      while ((iVar3 = iVar7, iVar4 == iVar8 || (iVar6 == iVar2))) {
        iVar7 = iVar3 + -1;
        if (iVar7 == -1) {
          return iVar3;
        }
        iVar8 = *(int *)(iVar1 + 0x490 + iVar7 * 4);
        iVar2 = *(int *)(iVar1 + 0x450 + iVar7 * 4);
        iVar5 = iVar3;
      }
    }
    if (iVar5 != -1) {
      return iVar5;
    }
  }
  if (iVar4 == 2) {
    iVar7 = 0;
    do {
      if ((*(int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490 + iVar7 * 4) != 2) ||
         (iVar6 == *(int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x450 + iVar7 * 4)))
      goto LAB_0073b7b6;
      iVar7 = iVar7 + 1;
    } while (iVar7 != 5);
    iVar7 = -1;
  }
  else {
    iVar7 = 4;
    do {
      if ((iVar4 != *(int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490 + iVar7 * 4)) ||
         (iVar6 == *(int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x450 + iVar7 * 4)))
      goto LAB_0073b7b6;
      iVar7 = iVar7 + -1;
    } while (iVar7 != -1);
    iVar7 = -1;
  }
LAB_0073b7b6:
  fVar11 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                              (in_stack_00000008,(float)in_stack_00000008,0x42480000 /* 50.0f */);
  iVar6 = iVar7;
  if (((double)(float)fVar11 < *(double *)(unaff_EBX + 0x245c65 /* rodata:0x66666666 */ /* rodata:0x66666666 */)) && (iVar6 = -1, iVar7 != -1)) {
    iVar6 = (uint)(iVar4 == 2) * 2 + -1 + iVar7;
    iVar8 = 4;
    if (iVar6 < 5) {
      iVar8 = iVar6;
    }
    iVar6 = 0;
    if (-1 < iVar8) {
      iVar6 = iVar8;
    }
    if (iVar4 == *(int *)(**(int **)(unaff_EBX + 0x46b661 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490 + iVar6 * 4)) {
      iVar6 = iVar7;
    }
  }
  return iVar6;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::~CINSBotActionSkirmish
 * Address: 0073be10
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSkirmish::~CINSBotActionSkirmish() */

void __thiscall CINSBotActionSkirmish::~CINSBotActionSkirmish(CINSBotActionSkirmish *this)

{
  ~CINSBotActionSkirmish(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::~CINSBotActionSkirmish
 * Address: 0073be20
 * ---------------------------------------- */

/* CINSBotActionSkirmish::~CINSBotActionSkirmish() */

void __thiscall CINSBotActionSkirmish::~CINSBotActionSkirmish(CINSBotActionSkirmish *this)

{
  int extraout_ECX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = &UNK_0045e3e3 + extraout_ECX;
  in_stack_00000004[1] = extraout_ECX + 0x45e577 /* vtable for CINSBotActionSkirmish+0x19c */ /* vtable for CINSBotActionSkirmish+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46b353 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::~CINSBotActionSkirmish
 * Address: 0073be50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionSkirmish::~CINSBotActionSkirmish() */

void __thiscall CINSBotActionSkirmish::~CINSBotActionSkirmish(CINSBotActionSkirmish *this)

{
  ~CINSBotActionSkirmish(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionSkirmish::~CINSBotActionSkirmish
 * Address: 0073be60
 * ---------------------------------------- */

/* CINSBotActionSkirmish::~CINSBotActionSkirmish() */

void __thiscall CINSBotActionSkirmish::~CINSBotActionSkirmish(CINSBotActionSkirmish *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45e39a /* vtable for CINSBotActionSkirmish+0x8 */ /* vtable for CINSBotActionSkirmish+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45e52e /* vtable for CINSBotActionSkirmish+0x19c */ /* vtable for CINSBotActionSkirmish+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



