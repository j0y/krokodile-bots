/*
 * CINSNextBotSurvivalCacheNotify -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 1
 */

/* ----------------------------------------
 * CINSNextBotSurvivalCacheNotify::operator()
 * Address: 00767090
 * ---------------------------------------- */

/* CINSNextBotSurvivalCacheNotify::TEMPNAMEPLACEHOLDERVALUE(INextBot*) */

undefined4 __thiscall
CINSNextBotSurvivalCacheNotify::operator()(CINSNextBotSurvivalCacheNotify *this,INextBot *param_1)

{
  float *pfVar1;
  float *pfVar2;
  undefined4 *puVar3;
  char cVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  float fVar9;
  float fVar10;
  CINSRules *this_00;
  int iVar11;
  int unaff_EBX;
  int iVar12;
  undefined4 uVar13;
  float10 fVar14;
  float fVar15;
  int *in_stack_00000008;
  int local_30;
  
  uVar13 = 0;
  __i686_get_pc_thunk_bx();
  if ((**(int **)(unaff_EBX + 0x43f85b /* &g_pGameRules */) != 0) && (**(int **)(unaff_EBX + 0x43fc7f /* &g_pObjectiveResource */) != 0)) {
    if (in_stack_00000008 == (int *)0x0) {
      return 1;
    }
    uVar13 = 1;
    iVar5 = (**(code **)(*in_stack_00000008 + 200))(in_stack_00000008);
    if (iVar5 != 0) {
      piVar6 = (int *)(**(code **)(*in_stack_00000008 + 200))(in_stack_00000008);
      cVar4 = (**(code **)(*piVar6 + 0x118))(piVar6);
      if (cVar4 != '\0') {
        pfVar1 = *(float **)param_1;
        pfVar2 = *(float **)(unaff_EBX + 0x43f52f /* &vec3_origin */);
        if (((*pfVar2 != *pfVar1) || (pfVar2[1] != pfVar1[1])) || (pfVar2[2] != pfVar1[2])) {
          uVar13 = 1;
          iVar5 = __dynamic_cast(in_stack_00000008,*(undefined4 *)(unaff_EBX + 0x43ff33 /* &typeinfo for INextBot */),
                                 *(undefined4 *)(unaff_EBX + 0x43f98b /* &typeinfo for CINSNextBot */),0x2060);
          if (iVar5 != 0) {
            piVar6 = (int *)(*(int **)(unaff_EBX + 0x43fd5b /* &ins_bot_survival_cache_notify_radius_max */))[7];
            if (piVar6 == *(int **)(unaff_EBX + 0x43fd5b /* &ins_bot_survival_cache_notify_radius_max */)) {
              fVar10 = (float)((uint)piVar6 ^ piVar6[0xb]);
            }
            else {
              fVar14 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
              fVar10 = (float)fVar14;
            }
            piVar6 = (int *)(*(int **)(unaff_EBX + 0x43fd4b /* &ins_bot_survival_cache_notify_radius_min */))[7];
            if (piVar6 == *(int **)(unaff_EBX + 0x43fd4b /* &ins_bot_survival_cache_notify_radius_min */)) {
              fVar9 = (float)((uint)piVar6 ^ piVar6[0xb]);
            }
            else {
              fVar14 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
              fVar9 = (float)fVar14;
            }
            fVar15 = ((float)*(int *)(**(int **)(unaff_EBX + 0x43f85b /* &g_pGameRules */) + 1000) +
                     *(float *)(unaff_EBX + 0x21fec3 /* CSWTCH.989+0x1c */)) * *(float *)(unaff_EBX + 0x21fec7 /* CSWTCH.989+0x20 */);
            if (*(float *)(unaff_EBX + 0x151a77 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar15) {
              fVar15 = *(float *)(unaff_EBX + 0x151a77 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
            }
            if (fVar15 <= *(float *)(unaff_EBX + 0x151a6b /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
              fVar15 = *(float *)(unaff_EBX + 0x151a6b /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
            }
            cVar4 = (**(code **)(*in_stack_00000008 + 0x124))
                              (in_stack_00000008,*(undefined4 *)param_1,
                               (fVar10 - fVar9) * fVar15 + fVar9);
            if (cVar4 == '\0') {
              iVar12 = 0;
              local_30 = -1;
              iVar11 = **(int **)(unaff_EBX + 0x43fc7f /* &g_pObjectiveResource */);
              do {
                iVar7 = RandomInt(0,*(int *)(iVar11 + 0x37c) + -1);
                iVar8 = CINSRules::GetHumanTeam(this_00);
                iVar11 = **(int **)(unaff_EBX + 0x43fc7f /* &g_pObjectiveResource */);
                if (iVar8 == 2) {
                  cVar4 = *(char *)(iVar11 + 0x690 + iVar7);
LAB_0076727b:
                  if (cVar4 != '\0') {
                    iVar12 = iVar12 + 1;
                    iVar7 = local_30;
                  }
                }
                else if (iVar8 == 3) {
                  cVar4 = *(char *)(iVar11 + 0x6a0 + iVar7);
                  goto LAB_0076727b;
                }
                local_30 = iVar7;
              } while ((iVar12 < 8) && (local_30 < 0));
              if (-1 < local_30) {
                iVar11 = iVar11 + local_30 * 0xc;
                CINSNextBot::AddInvestigation
                          (iVar5,*(undefined4 *)(iVar11 + 0x5d0),*(undefined4 *)(iVar11 + 0x5d4),
                           *(undefined4 *)(iVar11 + 0x5d8),7);
                return 1;
              }
            }
            puVar3 = *(undefined4 **)param_1;
            CINSNextBot::AddInvestigation(iVar5,*puVar3,puVar3[1],puVar3[2],7);
            return 1;
          }
        }
      }
    }
  }
  return uVar13;
}



