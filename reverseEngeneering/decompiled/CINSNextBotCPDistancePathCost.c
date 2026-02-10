/*
 * CINSNextBotCPDistancePathCost -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 1
 */

/* ----------------------------------------
 * CINSNextBotCPDistancePathCost::operator()
 * Address: 006ecb90
 * ---------------------------------------- */

/* CINSNextBotCPDistancePathCost::TEMPNAMEPLACEHOLDERVALUE(CNavArea*, CNavArea*, CNavLadder const*,
   CFuncElevator const*, float) const */

float10 __cdecl
CINSNextBotCPDistancePathCost::operator()
          (CNavArea *param_1,CNavArea *param_2,CNavLadder *param_3,CFuncElevator *param_4,
          float param_5)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  CNavArea *extraout_ECX;
  CNavArea *this;
  CNavArea *extraout_ECX_00;
  int unaff_EBX;
  bool bVar7;
  float10 fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float local_30;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x4b9dd9 /* &GCSDK::GetPchTempTextBuffer */);
  this = *(CNavArea **)(iVar2 + 0x100c);
  bVar7 = this != (CNavArea *)0x0;
  if ((bVar7) &&
     (iVar5 = *(int *)(iVar2 + 0x19b8), iVar4 = ThreadGetCurrentId(), this = extraout_ECX,
     iVar5 == iVar4)) {
    piVar6 = *(int **)(iVar2 + 0x1014);
    if (*piVar6 != unaff_EBX + 0x2921a1 /* "CINSNextBotCPDistancePathCost::operator()" */) {
      piVar6 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar6,unaff_EBX + 0x2921a1 /* "CINSNextBotCPDistancePathCost::operator()" */,(char *)0x0,
                                 unaff_EBX + 0x2940ce /* "NextBot" */);
      *(int **)(iVar2 + 0x1014) = piVar6;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar6[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
    this = extraout_ECX_00;
  }
  if (param_3 == (CNavLadder *)0x0) {
    fVar9 = 0.0;
    goto LAB_006ecd5a;
  }
  local_30 = *(float *)(unaff_EBX + 0x23c611 /* typeinfo name for CTraceFilterIgnoreWeapons+0x21 */);
  iVar5 = 0;
  do {
    if (iVar5 == 2) {
      fVar9 = *(float *)(param_2 + 0x10);
      fVar10 = *(float *)(param_2 + 0x14);
      fVar11 = *(float *)(param_2 + 0x18);
    }
    else if (iVar5 == 3) {
      fVar9 = *(float *)(param_2 + 4);
      fVar10 = *(float *)(param_2 + 0x14);
      fVar11 = *(float *)(param_2 + 0x28);
    }
    else if (iVar5 == 1) {
      fVar9 = *(float *)(param_2 + 0x10);
      fVar10 = *(float *)(param_2 + 8);
      fVar11 = *(float *)(param_2 + 0x24);
    }
    else {
      fVar9 = *(float *)(param_2 + 4);
      fVar10 = *(float *)(param_2 + 8);
      fVar11 = *(float *)(param_2 + 0xc);
    }
    fVar9 = *(float *)(param_1 + 4) - fVar9;
    fVar10 = *(float *)(param_1 + 8) - fVar10;
    fVar11 = *(float *)(param_1 + 0xc) - fVar11;
    if (SQRT(fVar10 * fVar10 + fVar9 * fVar9 + fVar11 * fVar11) <= local_30) {
      if (iVar5 == 2) {
        fVar9 = *(float *)(param_2 + 0x10);
        fVar10 = *(float *)(param_2 + 0x14);
        fVar11 = *(float *)(param_2 + 0x18);
      }
      else if (iVar5 == 3) {
        fVar9 = *(float *)(param_2 + 4);
        fVar10 = *(float *)(param_2 + 0x14);
        fVar11 = *(float *)(param_2 + 0x28);
      }
      else if (iVar5 == 1) {
        fVar9 = *(float *)(param_2 + 0x10);
        fVar10 = *(float *)(param_2 + 8);
        fVar11 = *(float *)(param_2 + 0x24);
      }
      else {
        fVar9 = *(float *)(param_2 + 4);
        fVar10 = *(float *)(param_2 + 8);
        fVar11 = *(float *)(param_2 + 0xc);
      }
      fVar9 = *(float *)(param_1 + 4) - fVar9;
      fVar10 = *(float *)(param_1 + 8) - fVar10;
      fVar11 = *(float *)(param_1 + 0xc) - fVar11;
      local_30 = SQRT(fVar10 * fVar10 + fVar9 * fVar9 + fVar11 * fVar11);
    }
    iVar5 = iVar5 + 1;
  } while (iVar5 != 4);
  if (param_4 != (CFuncElevator *)0x0) {
    local_30 = *(float *)(param_4 + 0x18);
  }
  fVar8 = (float10)CNavArea::ComputeAdjacentConnectionHeightChange(this,(CNavArea *)param_3);
  fVar10 = (float)fVar8;
  if (fVar10 < *(float *)(param_1 + 0x10)) {
    if (fVar10 <= (float)((uint)*(float *)(param_1 + 0x10) ^ *(uint *)(unaff_EBX + 0x238065 /* typeinfo name for CBroadcastRecipientFilter+0x44 */))) {
      fVar9 = *(float *)(CBaseAchievement::~CBaseAchievement + unaff_EBX + 5);
      if (fVar10 <= (float)(*(uint *)(param_1 + 0x18) ^ *(uint *)(unaff_EBX + 0x238065 /* typeinfo name for CBroadcastRecipientFilter+0x44 */)))
      goto LAB_006ecd5a;
      goto LAB_006ecd3b;
    }
  }
  else {
    fVar9 = *(float *)(CBaseAchievement::~CBaseAchievement + unaff_EBX + 5);
    if (*(float *)(param_1 + 0x14) <= fVar10) goto LAB_006ecd5a;
LAB_006ecd3b:
    local_30 = local_30 * *(float *)(unaff_EBX + 0x1cc3e1 /* typeinfo name for IServerBenchmark+0x13 */);
  }
  fVar9 = local_30 + *(float *)(param_3 + 0x54);
LAB_006ecd5a:
  if ((bVar7) &&
     (((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)) &&
      (iVar5 = *(int *)(iVar2 + 0x19b8), iVar4 = ThreadGetCurrentId(), iVar5 == iVar4)))) {
    cVar3 = CVProfNode::ExitScope();
    iVar5 = *(int *)(iVar2 + 0x1014);
    if (cVar3 != '\0') {
      iVar5 = *(int *)(iVar5 + 100);
      *(int *)(iVar2 + 0x1014) = iVar5;
    }
    *(bool *)(iVar2 + 0x1010) = iVar5 == iVar2 + 0x1018;
    return (float10)fVar9;
  }
  return (float10)fVar9;
}



