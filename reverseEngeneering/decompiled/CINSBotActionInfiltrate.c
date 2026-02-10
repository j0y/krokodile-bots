/*
 * CINSBotActionInfiltrate -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 11
 */

/* ----------------------------------------
 * CINSBotActionInfiltrate::OnStart
 * Address: 00739480
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotActionInfiltrate::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::Update
 * Address: 00739660
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionInfiltrate::Update(CINSBotActionInfiltrate *this,CINSNextBot *param_1,float param_2)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  CNavArea *pCVar6;
  void *pvVar7;
  int iVar8;
  CINSPlayer *pCVar9;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSBotInvestigate *this_02;
  CINSBotCombat *this_03;
  CINSNextBot *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *pCVar10;
  CINSBotCaptureFlag *this_06;
  int unaff_EBX;
  bool bVar11;
  float10 fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  CBaseEntity *in_stack_0000000c;
  undefined4 uVar16;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  iVar5 = (**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
  pCVar10 = extraout_ECX;
  if (iVar5 != 0) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar5 = (**(code **)(*piVar4 + 0xd4 /* IIntention::ShouldAttack */))(piVar4,in_stack_0000000c + 0x2060,iVar5);
    pCVar10 = extraout_ECX_00;
    if (iVar5 == 1) {
      pvVar7 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_03);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar7;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x246f52 /* "Attacking nearby threats" */;
      return param_1;
    }
  }
  cVar3 = CINSNextBot::IsInvestigating(pCVar10);
  if (cVar3 == '\0') {
    cVar3 = CINSNextBot::HasInvestigations(this_00);
    if (cVar3 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea((CINSNextBot *)this_01);
      pCVar6 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_02,pCVar6);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(CNavArea **)(param_1 + 4) = pCVar6;
      *(int *)(param_1 + 8) = unaff_EBX + 0x248ae3 /* "I have an investigation!" */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
    iVar5 = CBaseEntity::GetTeamNumber(this_01);
    if (1 < iVar5 - 2U) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x246f6b /* "Bot is not on a playteam" */;
      return param_1;
    }
    uVar16 = 0;
    fVar12 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                (this_04,(float)in_stack_0000000c,0x41f00000 /* 30.0f */);
    *(bool *)((int)param_2 + 0x38) = (float)fVar12 < *(float *)(unaff_EBX + 0x1ea421 /* typeinfo name for ISaveRestoreOps+0x67 */);
    iVar8 = GetTargetObjective((CINSNextBot *)param_2);
    bVar11 = *(int *)(**(int **)(unaff_EBX + 0x46d6b1 /* &g_pObjectiveResource */) + 0x6f0 + iVar8 * 4) == 5;
    if (*(char *)((int)param_2 + 0x38) == '\0') {
      if (!bVar11) {
        uVar2 = *(uint *)(*(int *)(unaff_EBX + 0x46d231 /* &CINSBotCaptureFlag::m_pCapturer */) + iVar8 * 4);
        if ((((uVar2 == 0xffffffff) ||
             (iVar1 = **(int **)(unaff_EBX + 0x46d16d /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
             *(uint *)(iVar1 + 8) != uVar2 >> 0x10)) || (*(int *)(iVar1 + 4) == 0)) ||
           (*(int *)(*(int *)(unaff_EBX + 0x46d231 /* &CINSBotCaptureFlag::m_pCapturer */) + iVar8 * 4) == -1)) {
          pCVar9 = (CINSPlayer *)::operator_new(0x4900);
          CINSBotCaptureFlag::CINSBotCaptureFlag(this_06,pCVar9,(int)in_stack_0000000c);
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(CINSPlayer **)(param_1 + 4) = pCVar9;
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x248d48 /* "Moving to capture flag." */;
          return param_1;
        }
        iVar5 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x46d28d /* &g_pGameRules */) + 0x334))
                          ((int *)**(undefined4 **)(unaff_EBX + 0x46d28d /* &g_pGameRules */),iVar5,uVar16);
        if (iVar5 != 0) {
          pCVar10 = (CINSNextBot *)this_05;
          if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_05);
            pCVar10 = (CINSNextBot *)extraout_ECX_01;
          }
          if ((*(byte *)(iVar5 + 0xd1) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition((CBaseEntity *)pCVar10);
            pCVar10 = extraout_ECX_02;
          }
          fVar15 = *(float *)(iVar5 + 0x208) - *(float *)(in_stack_0000000c + 0x208);
          fVar13 = *(float *)(iVar5 + 0x20c) - *(float *)(in_stack_0000000c + 0x20c);
          fVar14 = *(float *)(iVar5 + 0x210) - *(float *)(in_stack_0000000c + 0x210);
          fVar13 = SQRT(fVar13 * fVar13 + fVar15 * fVar15 + fVar14 * fVar14);
          if (*(float *)(unaff_EBX + 0x1ed749 /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x34 */) <= fVar13 &&
              fVar13 != *(float *)(unaff_EBX + 0x1ed749 /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x34 */)) {
            CINSNextBot::UpdateChasePath(pCVar10,in_stack_0000000c);
            goto LAB_007396dd;
          }
        }
      }
      iVar5 = CINSNavMesh::GetRandomControlPointArea(**(int **)(unaff_EBX + 0x46d04d /* &TheNavMesh */));
      if (iVar5 != 0) {
        CNavArea::GetRandomPoint();
        CINSNextBot::AddInvestigation(in_stack_0000000c,local_28,local_24,local_20,0);
        goto LAB_007396dd;
      }
    }
    else {
      piVar4 = *(int **)(unaff_EBX + 0x46d04d /* &TheNavMesh */);
      if (bVar11) {
        iVar5 = CINSNavMesh::GetRandomControlPointArea(*piVar4);
        if (iVar5 == 0) {
          Warning(unaff_EBX + 0x248d61 /* "NAVMESH ERROR: Unable to find any navmesh areas for CP %i, navmesh probably o..." */,iVar8 == 0);
        }
        else {
          CNavArea::GetRandomPoint();
          CINSNextBot::AddInvestigation(in_stack_0000000c,local_40,local_3c,local_38,0);
        }
      }
      iVar5 = CINSNavMesh::GetRandomControlPointSurroundingArea(*piVar4);
      if (iVar5 != 0) {
        CNavArea::GetRandomPoint();
        CINSNextBot::AddInvestigation(in_stack_0000000c,local_34,local_30,local_2c,0);
        goto LAB_007396dd;
      }
    }
    Warning(unaff_EBX + 0x248d61 /* "NAVMESH ERROR: Unable to find any navmesh areas for CP %i, navmesh probably o..." */,iVar8);
  }
LAB_007396dd:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::OnEnd
 * Address: 007394a0
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionInfiltrate::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::GetName
 * Address: 00739b60
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::GetName() const */

int CINSBotActionInfiltrate::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6dd9 /* "Infiltrate" */;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::ShouldAttack
 * Address: 007394b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionInfiltrate::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionInfiltrate::ShouldAttack
          (CINSBotActionInfiltrate *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::ShouldAttack
 * Address: 007394c0
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionInfiltrate::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::GetTargetObjective
 * Address: 007395f0
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::GetTargetObjective(CINSNextBot*) */

uint __cdecl CINSBotActionInfiltrate::GetTargetObjective(CINSNextBot *param_1)

{
  int iVar1;
  CBaseEntity *this;
  uint uVar2;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CBaseEntity::GetTeamNumber(this);
  uVar2 = 0xffffffff;
  if (iVar1 - 2U < 2) {
    if (iVar1 == 2) {
      return (uint)((byte)param_1[0x38] ^ 1);
    }
    uVar2 = (uint)(byte)param_1[0x38];
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::~CINSBotActionInfiltrate
 * Address: 00739b80
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionInfiltrate::~CINSBotActionInfiltrate() */

void __thiscall CINSBotActionInfiltrate::~CINSBotActionInfiltrate(CINSBotActionInfiltrate *this)

{
  ~CINSBotActionInfiltrate(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::~CINSBotActionInfiltrate
 * Address: 00739b90
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::~CINSBotActionInfiltrate() */

void __thiscall CINSBotActionInfiltrate::~CINSBotActionInfiltrate(CINSBotActionInfiltrate *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45fed3 /* vtable for CINSBotActionInfiltrate+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x460067 /* vtable for CINSBotActionInfiltrate+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46d5e3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::~CINSBotActionInfiltrate
 * Address: 00739bc0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionInfiltrate::~CINSBotActionInfiltrate() */

void __thiscall CINSBotActionInfiltrate::~CINSBotActionInfiltrate(CINSBotActionInfiltrate *this)

{
  ~CINSBotActionInfiltrate(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionInfiltrate::~CINSBotActionInfiltrate
 * Address: 00739bd0
 * ---------------------------------------- */

/* CINSBotActionInfiltrate::~CINSBotActionInfiltrate() */

void __thiscall CINSBotActionInfiltrate::~CINSBotActionInfiltrate(CINSBotActionInfiltrate *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45fe8a /* vtable for CINSBotActionInfiltrate+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46001e /* vtable for CINSBotActionInfiltrate+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



