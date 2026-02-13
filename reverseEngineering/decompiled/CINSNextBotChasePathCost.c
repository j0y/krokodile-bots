/*
 * CINSNextBotChasePathCost -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 1
 */

/* ----------------------------------------
 * CINSNextBotChasePathCost::operator()
 * Address: 006f5230
 * ---------------------------------------- */

/* CINSNextBotChasePathCost::TEMPNAMEPLACEHOLDERVALUE(CNavArea*, CNavArea*, CNavLadder const*,
   CFuncElevator const*, float) const */

float10 __cdecl
CINSNextBotChasePathCost::operator()
          (CNavArea *param_1,CNavArea *param_2,CNavLadder *param_3,CFuncElevator *param_4,
          float param_5)

{
  uint *puVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  uint uVar9;
  CNavArea *this;
  CBaseEntity *this_00;
  int unaff_EBX;
  bool bVar10;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  CNavArea *pCVar16;
  float local_34;
  
  __i686_get_pc_thunk_bx();
  iVar4 = *(int *)(unaff_EBX + 0x4b1739 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar10 = *(int *)(iVar4 + 0x100c) != 0;
  if ((bVar10) && (iVar8 = *(int *)(iVar4 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar8 == iVar6))
  {
    piVar7 = *(int **)(iVar4 + 0x1014);
    if (*piVar7 != unaff_EBX + 0x28a3f5 /* "CINSNextBotChasePathCost::operator()" */ /* "CINSNextBotChasePathCost::operator()" */) {
      piVar7 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar7,unaff_EBX + 0x28a3f5 /* "CINSNextBotChasePathCost::operator()" */ /* "CINSNextBotChasePathCost::operator()" */,(char *)0x0,
                                 unaff_EBX + 0x28ba2e /* "NextBot" */ /* "NextBot" */);
      *(int **)(iVar4 + 0x1014) = piVar7;
    }
    puVar1 = (uint *)(*(int *)(iVar4 + 0x10a0) + piVar7[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar4 + 0x1010) = 0;
  }
  if (param_3 == (CNavLadder *)0x0) {
    local_34 = 0.0;
    goto joined_r0x006f5534;
  }
  piVar7 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4));
  cVar5 = (**(code **)(*piVar7 + 0x174))(piVar7,param_2);
  if (cVar5 == '\0') {
LAB_006f5528:
    local_34 = *(float *)(unaff_EBX + 0x1c38d5 /* -1.0f */ /* -1.0f */);
  }
  else {
    local_34 = *(float *)(unaff_EBX + 0x233f71 /* FLT_MAX */ /* FLT_MAX */);
    fVar13 = *(float *)(param_1 + 0xc);
    fVar2 = *(float *)(param_1 + 0x10);
    fVar3 = *(float *)(param_1 + 0x14);
    iVar8 = 0;
    do {
      if (iVar8 == 2) {
        fVar15 = *(float *)(param_2 + 0x10);
        fVar12 = *(float *)(param_2 + 0x14);
        fVar14 = *(float *)(param_2 + 0x18);
      }
      else if (iVar8 == 3) {
        fVar15 = *(float *)(param_2 + 4);
        fVar12 = *(float *)(param_2 + 0x14);
        fVar14 = *(float *)(param_2 + 0x28);
      }
      else if (iVar8 == 1) {
        fVar15 = *(float *)(param_2 + 0x10);
        fVar12 = *(float *)(param_2 + 8);
        fVar14 = *(float *)(param_2 + 0x24);
      }
      else {
        fVar15 = *(float *)(param_2 + 4);
        fVar12 = *(float *)(param_2 + 8);
        fVar14 = *(float *)(param_2 + 0xc);
      }
      if (SQRT((fVar2 - fVar12) * (fVar2 - fVar12) + (fVar13 - fVar15) * (fVar13 - fVar15) +
               (fVar3 - fVar14) * (fVar3 - fVar14)) <= local_34) {
        if (iVar8 == 2) {
          fVar15 = *(float *)(param_2 + 0x10);
          fVar12 = *(float *)(param_2 + 0x14);
          fVar14 = *(float *)(param_2 + 0x18);
        }
        else if (iVar8 == 3) {
          fVar15 = *(float *)(param_2 + 4);
          fVar12 = *(float *)(param_2 + 0x14);
          fVar14 = *(float *)(param_2 + 0x28);
        }
        else if (iVar8 == 1) {
          fVar15 = *(float *)(param_2 + 0x10);
          fVar12 = *(float *)(param_2 + 8);
          fVar14 = *(float *)(param_2 + 0x24);
        }
        else {
          fVar15 = *(float *)(param_2 + 4);
          fVar12 = *(float *)(param_2 + 8);
          fVar14 = *(float *)(param_2 + 0xc);
        }
        local_34 = SQRT((fVar2 - fVar12) * (fVar2 - fVar12) + (fVar13 - fVar15) * (fVar13 - fVar15)
                        + (fVar3 - fVar14) * (fVar3 - fVar14));
      }
      iVar8 = iVar8 + 1;
    } while (iVar8 != 4);
    fVar13 = SQRT((*(float *)(param_3 + 0x30) - fVar2) * (*(float *)(param_3 + 0x30) - fVar2) +
                  (*(float *)(param_3 + 0x2c) - fVar13) * (*(float *)(param_3 + 0x2c) - fVar13) +
                  (*(float *)(param_3 + 0x34) - fVar3) * (*(float *)(param_3 + 0x34) - fVar3));
    if (fVar13 < local_34) {
      local_34 = local_34 - fVar13;
    }
    else {
      fVar13 = (fVar13 - local_34) * *(float *)(unaff_EBX + 0x22fdf1 /* 0.001f */ /* 0.001f */);
      local_34 = *(float *)(unaff_EBX + 0x1c38d9 /* 1.0f */ /* 1.0f */);
      if (local_34 <= fVar13) {
        fVar13 = local_34;
      }
      if (fVar13 <= *(float *)(unaff_EBX + 0x1c38cd /* 0.0f */ /* 0.0f */)) {
        fVar13 = *(float *)(unaff_EBX + 0x1c38cd /* 0.0f */ /* 0.0f */);
      }
      local_34 = local_34 + fVar13 * *(float *)(unaff_EBX + 0x28a7f1 /* -0.9f */ /* -0.9f */);
    }
    pCVar16 = param_2;
    fVar11 = (float10)CNavArea::ComputeAdjacentConnectionHeightChange(this,(CNavArea *)param_3);
    fVar13 = (float)fVar11;
    if (*(float *)(param_1 + 0x18) <= fVar13) {
      piVar7 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4),pCVar16);
      cVar5 = (**(code **)(*piVar7 + 0x144))(piVar7);
      if ((cVar5 == '\0') || (*(float *)(param_1 + 0x1c) <= fVar13)) goto LAB_006f5528;
      local_34 = local_34 * *(float *)(unaff_EBX + 0x1c3d41 /* 3.0f */ /* 3.0f */);
    }
    else if (fVar13 <= (float)((uint)*(float *)(param_1 + 0x18) ^ *(uint *)(unaff_EBX + 0x22f9c5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */)))
    {
      if (fVar13 <= (float)(*(uint *)(param_1 + 0x20) ^ *(uint *)(unaff_EBX + 0x22f9c5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */)))
      goto LAB_006f5528;
      local_34 = local_34 * *(float *)(unaff_EBX + 0x1c3d41 /* 3.0f */ /* 3.0f */);
    }
    (**(code **)(**(int **)(param_1 + 4) + 200))(*(int **)(param_1 + 4));
    iVar8 = CBaseEntity::GetTeamNumber(this_00);
    uVar9 = iVar8 - 2;
    if (1 < uVar9) {
      uVar9 = 2;
    }
    iVar8 = 3;
    if (*(int *)(param_2 + uVar9 * 0x14 + 0x23c) < 4) {
      iVar8 = *(int *)(param_2 + uVar9 * 0x14 + 0x23c);
    }
    iVar6 = 0;
    if (-1 < iVar8) {
      iVar6 = iVar8;
    }
    local_34 = (float)iVar6 + local_34;
    if (((byte)param_2[0x68] & 0x80) != 0) {
      local_34 = local_34 * *(float *)(unaff_EBX + 0x22ef75 /* 10.0f */ /* 10.0f */);
    }
  }
joined_r0x006f5534:
  if ((bVar10) &&
     (((*(char *)(iVar4 + 0x1010) == '\0' || (*(int *)(iVar4 + 0x100c) != 0)) &&
      (iVar8 = *(int *)(iVar4 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar8 == iVar6)))) {
    cVar5 = CVProfNode::ExitScope();
    iVar8 = *(int *)(iVar4 + 0x1014);
    if (cVar5 != '\0') {
      iVar8 = *(int *)(iVar8 + 100);
      *(int *)(iVar4 + 0x1014) = iVar8;
    }
    *(bool *)(iVar4 + 0x1010) = iVar8 == iVar4 + 0x1018;
    return (float10)local_34;
  }
  return (float10)local_34;
}



