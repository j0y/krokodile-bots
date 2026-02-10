/*
 * CINSBotActionAmbush -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionAmbush::CINSBotActionAmbush
 * Address: 007367a0
 * ---------------------------------------- */

/* CINSBotActionAmbush::CINSBotActionAmbush() */

void __thiscall CINSBotActionAmbush::CINSBotActionAmbush(CINSBotActionAmbush *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  in_stack_00000004[8] = 0;
  *in_stack_00000004 = extraout_ECX + 0x462743 /* vtable for CINSBotActionAmbush+0x8 */;
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
  in_stack_00000004[1] = extraout_ECX + 0x4628d7 /* vtable for CINSBotActionAmbush+0x19c */;
  in_stack_00000004[0xf] = -1;
  *(undefined1 *)(in_stack_00000004 + 0xe) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x39) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::OnStart
 * Address: 007362a0
 * ---------------------------------------- */

/* CINSBotActionAmbush::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotActionAmbush::OnStart(CINSBotActionAmbush *this,CINSNextBot *param_1,Action *param_2)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  iVar1 = UTIL_INSGetVip();
  param_2[0x39] = (Action)(iVar1 == in_stack_0000000c);
  piVar2 = (int *)UTIL_INSGetVip();
  if (piVar2 == (int *)0x0) {
    *(undefined4 *)(param_2 + 0x3c) = 0xffffffff;
  }
  else {
    puVar3 = (undefined4 *)(**(code **)(*piVar2 + 0xc))(piVar2);
    *(undefined4 *)(param_2 + 0x3c) = *puVar3;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionAmbush::Update
 * Address: 00736320
 * ---------------------------------------- */

/* CINSBotActionAmbush::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionAmbush::Update(CINSBotActionAmbush *this,CINSNextBot *param_1,float param_2)

{
  uint uVar1;
  char cVar2;
  undefined4 uVar3;
  void *pvVar4;
  int *piVar5;
  CNavArea *pCVar6;
  CINSNextBot *this_00;
  CINSRules *this_01;
  CINSBotCaptureCP *this_02;
  CBaseEntity *this_03;
  CINSNextBot *pCVar7;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_04;
  CINSBotInvestigate *this_05;
  CINSBotCombat *this_06;
  int iVar8;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  CBaseEntity *in_stack_0000000c;
  undefined4 uVar13;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  uVar13 = 0;
  fVar9 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                             (this_00,(float)in_stack_0000000c,0x42480000);
  *(bool *)((int)param_2 + 0x38) = (float)fVar9 < *(float *)(unaff_EBX + 0x1ed761 /* typeinfo name for ISaveRestoreOps+0x67 */);
  uVar3 = CBaseEntity::GetTeamNumber(in_stack_0000000c);
  cVar2 = CINSRules::IsAttackingTeam(this_01,**(int **)(unaff_EBX + 0x4705cd /* &g_pGameRules */));
  if (cVar2 != '\0') {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c,uVar3,uVar13)
    ;
    iVar8 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    pCVar7 = extraout_ECX;
    if (iVar8 != 0) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar8 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,in_stack_0000000c + 0x2060,iVar8);
      pCVar7 = extraout_ECX_00;
      if (iVar8 == 1) {
        pvVar4 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_06);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar4;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24a292 /* "Attacking nearby threats" */;
        *(undefined4 *)param_1 = 2;
        return param_1;
      }
    }
    cVar2 = CINSNextBot::IsInvestigating(pCVar7);
    if (cVar2 == '\0') {
      cVar2 = CINSNextBot::HasInvestigations(this_04);
      if (cVar2 != '\0') {
        CINSNextBot::GetCurrentInvestigationArea((CINSNextBot *)in_stack_0000000c);
        pCVar6 = (CNavArea *)::operator_new(0x4900);
        CINSBotInvestigate::CINSBotInvestigate(this_05,pCVar6);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(CNavArea **)(param_1 + 4) = pCVar6;
        *(undefined4 *)param_1 = 2;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24be23 /* "I have an investigation!" */;
        return param_1;
      }
      iVar8 = CINSNavMesh::GetRandomControlPointSurroundingArea(**(int **)(unaff_EBX + 0x47038d /* &TheNavMesh */));
      if (iVar8 != 0) {
        CNavArea::GetRandomPoint();
        CINSNextBot::AddInvestigation(in_stack_0000000c,local_28,local_24,local_20,0);
      }
    }
    goto LAB_007364f5;
  }
  if ((*(char *)((int)param_2 + 0x39) != '\0') ||
     (uVar1 = *(uint *)((int)param_2 + 0x3c), uVar1 == 0xffffffff)) {
LAB_00736395:
    pvVar4 = ::operator_new(0x88);
    CINSBotCaptureCP::CINSBotCaptureCP(this_02,(int)pvVar4,false);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar4;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24be11 /* "Moving to capture" */;
    return param_1;
  }
  iVar8 = (uVar1 & 0xffff) * 0x18 + **(int **)(&DAT_004704ad + unaff_EBX);
  this_03 = (CBaseEntity *)(iVar8 + 4);
  if ((*(uint *)(iVar8 + 8) != uVar1 >> 0x10) || (*(int *)(iVar8 + 4) == 0)) goto LAB_00736395;
  if (((byte)in_stack_0000000c[0xd1] & 8) == 0) {
LAB_00736443:
    iVar8 = *(int *)this_03;
  }
  else {
    CBaseEntity::CalcAbsolutePosition(this_03);
    uVar1 = *(uint *)((int)param_2 + 0x3c);
    this_03 = (CBaseEntity *)**(int **)(&DAT_004704ad + unaff_EBX);
    iVar8 = 0;
    if ((uVar1 != 0xffffffff) &&
       (this_03 = this_03 + (uVar1 & 0xffff) * 0x18 + 4, *(uint *)(this_03 + 4) == uVar1 >> 0x10))
    goto LAB_00736443;
  }
  if ((*(byte *)(iVar8 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_03);
  }
  fVar12 = *(float *)(iVar8 + 0x208) - *(float *)(in_stack_0000000c + 0x208);
  fVar10 = *(float *)(iVar8 + 0x20c) - *(float *)(in_stack_0000000c + 0x20c);
  fVar11 = *(float *)(iVar8 + 0x210) - *(float *)(in_stack_0000000c + 0x210);
  fVar10 = SQRT(fVar10 * fVar10 + fVar12 * fVar12 + fVar11 * fVar11);
  if (*(float *)(&DAT_001827f5 + unaff_EBX) <= fVar10 &&
      fVar10 != *(float *)(&DAT_001827f5 + unaff_EBX)) {
    pCVar7 = (CINSNextBot *)in_stack_0000000c;
    if (*(uint *)((int)param_2 + 0x3c) != 0xffffffff) {
      pCVar7 = (CINSNextBot *)
               (**(int **)(&DAT_004704ad + unaff_EBX) +
               (*(uint *)((int)param_2 + 0x3c) & 0xffff) * 0x18);
    }
    CINSNextBot::UpdateChasePath(pCVar7,in_stack_0000000c);
  }
LAB_007364f5:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionAmbush::OnEnd
 * Address: 007361d0
 * ---------------------------------------- */

/* CINSBotActionAmbush::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionAmbush::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::GetName
 * Address: 00736840
 * ---------------------------------------- */

/* CINSBotActionAmbush::GetName() const */

int CINSBotActionAmbush::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6f62 /* "Ambush" */;
}



/* ----------------------------------------
 * CINSBotActionAmbush::ShouldAttack
 * Address: 007361e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionAmbush::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionAmbush::ShouldAttack(CINSBotActionAmbush *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::ShouldAttack
 * Address: 007361f0
 * ---------------------------------------- */

/* CINSBotActionAmbush::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionAmbush::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionAmbush::GetDesiredObjective
 * Address: 00736830
 * ---------------------------------------- */

/* CINSBotActionAmbush::GetDesiredObjective(CINSNextBot*) */

undefined4 __cdecl CINSBotActionAmbush::GetDesiredObjective(CINSNextBot *param_1)

{
  return 0xffffffff;
}



/* ----------------------------------------
 * CINSBotActionAmbush::~CINSBotActionAmbush
 * Address: 00736860
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionAmbush::~CINSBotActionAmbush() */

void __thiscall CINSBotActionAmbush::~CINSBotActionAmbush(CINSBotActionAmbush *this)

{
  ~CINSBotActionAmbush(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::~CINSBotActionAmbush
 * Address: 00736870
 * ---------------------------------------- */

/* CINSBotActionAmbush::~CINSBotActionAmbush() */

void __thiscall CINSBotActionAmbush::~CINSBotActionAmbush(CINSBotActionAmbush *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x462673 /* vtable for CINSBotActionAmbush+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x462807 /* vtable for CINSBotActionAmbush+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x470903 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::~CINSBotActionAmbush
 * Address: 007368a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionAmbush::~CINSBotActionAmbush() */

void __thiscall CINSBotActionAmbush::~CINSBotActionAmbush(CINSBotActionAmbush *this)

{
  ~CINSBotActionAmbush(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionAmbush::~CINSBotActionAmbush
 * Address: 007368b0
 * ---------------------------------------- */

/* CINSBotActionAmbush::~CINSBotActionAmbush() */

void __thiscall CINSBotActionAmbush::~CINSBotActionAmbush(CINSBotActionAmbush *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0046262a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x4627be /* vtable for CINSBotActionAmbush+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



