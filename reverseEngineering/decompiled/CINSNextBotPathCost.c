/*
 * CINSNextBotPathCost -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 1
 */

/* ----------------------------------------
 * CINSNextBotPathCost::operator()
 * Address: 006f4840
 * ---------------------------------------- */

/* CINSNextBotPathCost::TEMPNAMEPLACEHOLDERVALUE(CNavArea*, CNavArea*, CNavLadder const*,
   CFuncElevator const*, float) const */

float10 __thiscall
CINSNextBotPathCost::operator()
          (CINSNextBotPathCost *this,CNavArea *param_1,CNavArea *param_2,CNavLadder *param_3,
          CFuncElevator *param_4,float param_5)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  CNavArea CVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  uint uVar9;
  CBaseEntity *this_00;
  CNavArea *this_01;
  CNavArea *extraout_ECX;
  CNavArea *extraout_ECX_00;
  CINSNavArea *this_02;
  CINSNavArea *this_03;
  CINSNavArea *extraout_ECX_01;
  CINSNavArea *this_04;
  CINSNavArea *extraout_ECX_02;
  int unaff_EBX;
  bool bVar10;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float in_stack_00000018;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x4b2129 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar10 = *(int *)(iVar2 + 0x100c) != 0;
  if (bVar10) {
    iVar7 = *(int *)(iVar2 + 0x19b8);
    iVar6 = ThreadGetCurrentId();
    if (iVar7 == iVar6) {
      piVar8 = *(int **)(iVar2 + 0x1014);
      if (*piVar8 != unaff_EBX + 0x28adc5 /* "CINSNextBotPathCost::operator()" */ /* "CINSNextBotPathCost::operator()" */) {
        piVar8 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar8,unaff_EBX + 0x28adc5 /* "CINSNextBotPathCost::operator()" */ /* "CINSNextBotPathCost::operator()" */,(char *)0x0,
                                   unaff_EBX + 0x28c41e /* "NextBot" */ /* "NextBot" */);
        *(int **)(iVar2 + 0x1014) = piVar8;
      }
      puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar8[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar2 + 0x1010) = 0;
    }
  }
  (**(code **)(**(int **)(param_1 + 4) + 200))(*(int **)(param_1 + 4));
  iVar7 = CBaseEntity::GetTeamNumber(this_00);
  iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4b24a5 /* &ins_nav_enable_pathfinding_updates */ /* &ins_nav_enable_pathfinding_updates */) + 0x40))(*(int **)(unaff_EBX + 0x4b24a5 /* &ins_nav_enable_pathfinding_updates */ /* &ins_nav_enable_pathfinding_updates */));
  if (iVar6 == 0) {
    if (param_3 != (CNavLadder *)0x0) {
      piVar8 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4));
      cVar4 = (**(code **)(*piVar8 + 0x174))(piVar8);
      if (cVar4 == '\0') goto LAB_006f4c30;
      if (param_4 == (CFuncElevator *)0x0) {
        local_34 = in_stack_00000018;
        if (in_stack_00000018 < *(float *)(unaff_EBX + 0x1c42bd /* 0.0f */ /* 0.0f */) ||
            in_stack_00000018 == *(float *)(unaff_EBX + 0x1c42bd /* 0.0f */ /* 0.0f */)) {
          local_34 = SQRT((*(float *)(param_2 + 0x30) - *(float *)(param_3 + 0x30)) *
                          (*(float *)(param_2 + 0x30) - *(float *)(param_3 + 0x30)) +
                          (*(float *)(param_2 + 0x2c) - *(float *)(param_3 + 0x2c)) *
                          (*(float *)(param_2 + 0x2c) - *(float *)(param_3 + 0x2c)) +
                          (*(float *)(param_2 + 0x34) - *(float *)(param_3 + 0x34)) *
                          (*(float *)(param_2 + 0x34) - *(float *)(param_3 + 0x34)));
        }
      }
      else {
        local_34 = *(float *)(param_4 + 0x18);
      }
      fVar12 = *(float *)(param_3 + 0x54);
      piVar8 = (int *)(*(int **)(unaff_EBX + 0x4b23b9 /* &ins_bot_path_simplify_range */ /* &ins_bot_path_simplify_range */))[7];
      if (piVar8 == *(int **)(unaff_EBX + 0x4b23b9 /* &ins_bot_path_simplify_range */ /* &ins_bot_path_simplify_range */)) {
        fVar13 = (float)((uint)piVar8 ^ piVar8[0xb]);
      }
      else {
        fVar11 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
        fVar13 = (float)fVar11;
        param_4 = (CFuncElevator *)extraout_ECX;
      }
      if (fVar13 < fVar12) {
        local_30 = local_34 + *(float *)(param_3 + 0x54);
        goto LAB_006f48f0;
      }
      local_38 = 0.0;
      uVar9 = iVar7 - 2;
      if (1 < uVar9) {
        uVar9 = 2;
      }
      iVar6 = *(int *)(param_2 + uVar9 * 0x14 + 0x23c);
      if (-1 < iVar6) {
        if (iVar6 < 4) {
          if (iVar6 == 0) goto LAB_006f4a51;
        }
        else {
          iVar6 = 3;
        }
        iVar3 = *(int *)(param_1 + 8);
        if (iVar3 < 1) {
LAB_006f4a18:
          fVar11 = (float10)__pow_finite((double)local_34,(double)iVar6);
          local_38 = (float)((double)fVar11 * *(double *)(&DAT_001c42f5 + unaff_EBX));
          param_4 = (CFuncElevator *)extraout_ECX_00;
        }
        else if (iVar3 < 3) {
          local_38 = (float)iVar6 * local_34 * *(float *)(unaff_EBX + 0x22ff0d /* 0.5f */ /* 0.5f */);
        }
        else {
          if (iVar3 != 3) goto LAB_006f4a18;
          local_38 = (float)iVar6 * local_34;
        }
      }
LAB_006f4a51:
      fVar11 = (float10)CNavArea::ComputeAdjacentConnectionHeightChange
                                  ((CNavArea *)param_4,(CNavArea *)param_3);
      fVar12 = (float)fVar11;
      if (*(float *)(param_1 + 0x1c) <= fVar12) {
        piVar8 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4));
        cVar4 = (**(code **)(*piVar8 + 0x144))(piVar8);
        if ((cVar4 == '\0') || (*(float *)(param_1 + 0x20) <= fVar12)) {
LAB_006f4c30:
          local_30 = *(float *)(unaff_EBX + 0x1c42c5 /* -1.0f */ /* -1.0f */);
          goto LAB_006f48f0;
        }
        local_34 = local_34 * *(float *)(&DAT_001c4731 + unaff_EBX);
      }
      else if (fVar12 <= (float)((uint)*(float *)(param_1 + 0x1c) ^ *(uint *)(unaff_EBX + 0x2303b5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */))
              ) {
        if (fVar12 <= (float)(*(uint *)(param_1 + 0x24) ^ *(uint *)(unaff_EBX + 0x2303b5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */)))
        goto LAB_006f4c30;
        local_34 = local_34 * *(float *)(&DAT_001c4731 + unaff_EBX);
      }
      if (((byte)param_2[0x68] & 0x80) != 0) {
        local_34 = local_34 * *(float *)(unaff_EBX + 0x22f965 /* 10.0f */ /* 10.0f */);
      }
      iVar6 = *(int *)(**(int **)(&LAB_004b2055 + unaff_EBX) + 0x18);
      if (iVar6 <= *(int *)(param_2 + 0x48)) {
        local_34 = local_34 * *(float *)(unaff_EBX + 0x22f965 /* 10.0f */ /* 10.0f */);
      }
      if (iVar6 <= *(int *)(param_2 + 0x22c)) {
        local_34 = local_34 * *(float *)(unaff_EBX + 0x22ff11 /* 30.0f */ /* 30.0f */);
      }
      iVar6 = *(int *)(param_1 + 8);
      local_3c = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */);
      this_02 = (CINSNavArea *)param_2;
      if (iVar6 == 0) {
        fVar12 = *(float *)(**(int **)(&LAB_004b2055 + unaff_EBX) + 0xc);
        iVar6 = (**(code **)(**(int **)(param_1 + 4) + 200))(*(int **)(param_1 + 4));
        fVar13 = 0.0;
        if (*(int *)(iVar6 + 0x20) != 0) {
          uVar9 = ((int)(fVar12 * *(float *)(unaff_EBX + 0x1c42d1 /* 0.1f */ /* 0.1f */)) + 1) * *(int *)(param_2 + 0x9c)
                  * (*(int *)(iVar6 + 0x20) - *(int *)(**(int **)(&LAB_004b2055 + unaff_EBX) + 0x5c)
                    >> 4);
          fVar13 = (float)(uVar9 >> 0x10) * *(float *)(unaff_EBX + 0x231501 /* 65536.0f */ /* 65536.0f */) +
                   (float)(uVar9 & 0xffff);
        }
        fVar11 = (float10)FastCos(fVar13);
        iVar6 = *(int *)(param_1 + 8);
        local_3c = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */) +
                   ((float)fVar11 + *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */)) *
                   *(float *)(&DAT_001c4735 + unaff_EBX);
        this_02 = extraout_ECX_01;
      }
      local_40 = *(float *)(&DAT_001c4731 + unaff_EBX);
      if (iVar6 == 2) {
        cVar4 = CINSNavArea::IsInCombat();
        local_40 = *(float *)(unaff_EBX + 0x28b1d9 /* 6.5f */ /* 6.5f */);
        this_02 = this_04;
        if (cVar4 != '\0') {
          fVar11 = (float10)CINSNavArea::GetCombatIntensity(this_04);
          local_40 = *(float *)(unaff_EBX + 0x28b1d9 /* 6.5f */ /* 6.5f */);
          local_34 = (float)fVar11 * local_34 * *(float *)(&DAT_001c4731 + unaff_EBX);
          this_02 = extraout_ECX_02;
        }
      }
      fVar11 = (float10)CINSNavArea::GetDeathIntensity(this_02,(int)param_2);
      if (*(float *)(unaff_EBX + 0x1c42bd /* 0.0f */ /* 0.0f */) <= (float)fVar11 &&
          (float)fVar11 != *(float *)(unaff_EBX + 0x1c42bd /* 0.0f */ /* 0.0f */)) {
        fVar11 = (float10)CINSNavArea::GetDeathIntensity(this_03,(int)param_2);
        local_34 = (float)fVar11 * local_40 * local_34;
      }
      if (iVar7 == 0) {
        CVar5 = (CNavArea)((char)param_2[0x4d] + (char)param_2[0x4c]);
      }
      else {
        CVar5 = param_2[iVar7 % 2 + 0x4c];
      }
      local_30 = local_38 + *(float *)(param_3 + 0x54) +
                 (local_34 * *(float *)(unaff_EBX + 0x22ff21 /* 5.0f */ /* 5.0f */) * (float)(byte)CVar5 + local_34) *
                 local_3c;
      goto LAB_006f48f0;
    }
  }
  else if (param_3 != (CNavLadder *)0x0) {
    piVar8 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4));
    cVar4 = (**(code **)(*piVar8 + 0x174))(piVar8);
    local_30 = *(float *)(unaff_EBX + 0x1c42c5 /* -1.0f */ /* -1.0f */);
    if (cVar4 == '\0') goto LAB_006f48f0;
    fVar11 = (float10)CNavArea::ComputeAdjacentConnectionHeightChange(this_01,(CNavArea *)param_3);
    fVar12 = (float)fVar11;
    if (*(float *)(param_1 + 0x1c) <= fVar12) {
      piVar8 = (int *)(**(code **)(**(int **)(param_1 + 4) + 0xd0))(*(int **)(param_1 + 4));
      cVar4 = (**(code **)(*piVar8 + 0x144))(piVar8);
      if ((cVar4 == '\0') || (*(float *)(param_1 + 0x20) <= fVar12)) goto LAB_006f4c30;
      local_34 = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */);
      local_30 = *(float *)(unaff_EBX + 0x22ff15 /* 4.0f */ /* 4.0f */);
    }
    else if ((float)((uint)*(float *)(param_1 + 0x1c) ^ *(uint *)(unaff_EBX + 0x2303b5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */)) < fVar12) {
      local_30 = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */);
      local_34 = local_30;
    }
    else {
      if (fVar12 <= (float)(*(uint *)(param_1 + 0x24) ^ *(uint *)(unaff_EBX + 0x2303b5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */)))
      goto LAB_006f4c30;
      local_30 = *(float *)(unaff_EBX + 0x22ff15 /* 4.0f */ /* 4.0f */);
      local_34 = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */);
    }
    uVar9 = iVar7 - 2;
    if (1 < uVar9) {
      uVar9 = 2;
    }
    iVar7 = 3;
    if (*(int *)(param_2 + uVar9 * 0x14 + 0x23c) < 4) {
      iVar7 = *(int *)(param_2 + uVar9 * 0x14 + 0x23c);
    }
    iVar6 = 0;
    if (-1 < iVar7) {
      iVar6 = iVar7;
    }
    local_30 = local_30 + (float)(iVar6 * iVar6);
    if ((*(uint *)(param_2 + 0x68) & 0x1000) != 0) {
      local_30 = local_30 + local_34;
    }
    iVar7 = 0;
    do {
      if (**(int **)(param_2 + iVar7 * 4 + 0x6c) == 0) {
        local_30 = local_30 + local_34;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 != 4);
    if ((*(uint *)(param_2 + 0x68) & 0x80) != 0) {
      local_30 = local_30 + *(float *)(unaff_EBX + 0x22ff21 /* 5.0f */ /* 5.0f */);
    }
    if (*(int *)(**(int **)(&LAB_004b2055 + unaff_EBX) + 0x18) <= *(int *)(param_2 + 0x48)) {
      local_30 = local_30 + *(float *)(unaff_EBX + 0x22ff21 /* 5.0f */ /* 5.0f */);
    }
    if (*(int *)(**(int **)(&LAB_004b2055 + unaff_EBX) + 0x18) <= *(int *)(param_2 + 0x22c)) {
      local_30 = local_30 + *(float *)(unaff_EBX + 0x22ff21 /* 5.0f */ /* 5.0f */);
    }
    iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4b28b1 /* &ins_nav_enable_distancetocp_pathing */ /* &ins_nav_enable_distancetocp_pathing */) + 0x40))(*(int **)(unaff_EBX + 0x4b28b1 /* &ins_nav_enable_distancetocp_pathing */ /* &ins_nav_enable_distancetocp_pathing */));
    if (iVar7 == 0) {
      fVar12 = *(float *)(param_2 + 0x2c);
      fVar13 = *(float *)(param_2 + 0x30);
    }
    else {
      iVar7 = *(int *)(param_1 + 0x18);
      if (iVar7 == -1) {
        fVar12 = *(float *)(param_2 + 0x2c);
        fVar13 = *(float *)(param_2 + 0x30);
      }
      else {
        fVar12 = *(float *)(param_2 + 0x2c);
        fVar13 = *(float *)(param_2 + 0x30);
        fVar14 = SQRT((fVar13 - *(float *)(param_1 + 0x10)) * (fVar13 - *(float *)(param_1 + 0x10))
                      + (fVar12 - *(float *)(param_1 + 0xc)) * (fVar12 - *(float *)(param_1 + 0xc))
                      + (*(float *)(param_2 + 0x34) - *(float *)(param_1 + 0x14)) *
                        (*(float *)(param_2 + 0x34) - *(float *)(param_1 + 0x14)));
        if (*(float *)(unaff_EBX + 0x2307c5 /* 1000.0f */ /* 1000.0f */) <= fVar14 && fVar14 != *(float *)(unaff_EBX + 0x2307c5 /* 1000.0f */ /* 1000.0f */)
           ) {
          fVar12 = *(float *)(param_3 + iVar7 * 4 + 0x1ac) - *(float *)(param_2 + iVar7 * 4 + 0x1ac)
          ;
          if (fVar12 < 0.0) {
            local_30 = (float)((double)local_30 +
                              (double)((ulonglong)(double)fVar12 &
                                      *(ulonglong *)(unaff_EBX + 0x1c42e5 /* NaN / -1 */ /* NaN / -1 */)));
          }
          else {
            fVar12 = (fVar12 + *(float *)(unaff_EBX + 0x1c42c5 /* -1.0f */ /* -1.0f */)) * *(float *)(unaff_EBX + 0x28b1dd /* rodata:0x3A833405 */ /* rodata:0x3A833405 */);
            if (local_34 <= fVar12) {
              fVar12 = local_34;
            }
            if (fVar12 <= 0.0) {
              fVar12 = 0.0;
            }
            local_30 = fVar12 * *(float *)(unaff_EBX + 0x230395 /* -4.0f */ /* -4.0f */) + *(float *)(unaff_EBX + 0x22ff21 /* 5.0f */ /* 5.0f */)
                       + local_30;
          }
          goto LAB_006f48f0;
        }
      }
    }
    local_30 = ((float)((uint)(fVar12 - *(float *)(param_1 + 0xc)) & *(uint *)(unaff_EBX + 0x230805 /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */)
                       ) +
               (float)((uint)(fVar13 - *(float *)(param_1 + 0x10)) & *(uint *)(unaff_EBX + 0x230805 /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */)
                      )) * local_30;
    goto LAB_006f48f0;
  }
  local_30 = *(float *)(unaff_EBX + 0x1c42c9 /* 1.0f */ /* 1.0f */);
LAB_006f48f0:
  if ((bVar10) && ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) {
    iVar7 = *(int *)(iVar2 + 0x19b8);
    iVar6 = ThreadGetCurrentId();
    if (iVar7 == iVar6) {
      cVar4 = CVProfNode::ExitScope();
      iVar7 = *(int *)(iVar2 + 0x1014);
      if (cVar4 != '\0') {
        iVar7 = *(int *)(iVar7 + 100);
        *(int *)(iVar2 + 0x1014) = iVar7;
      }
      *(bool *)(iVar2 + 0x1010) = iVar7 == iVar2 + 0x1018;
      return (float10)local_30;
    }
  }
  return (float10)local_30;
}



