/*
 * CINSBotInvestigationMonitor -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 14
 */

/* ----------------------------------------
 * CINSBotInvestigationMonitor::OnStart
 * Address: 0073ed50
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotInvestigationMonitor::OnStart(CINSNextBot *param_1,Action *param_2)

{
  uint uVar1;
  int *piVar2;
  char cVar3;
  undefined4 *puVar4;
  CINSRules *this;
  CINSRules *this_00;
  CINSRules *extraout_ECX;
  int unaff_EBX;
  int iVar5;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
  if ((**(int **)(&DAT_00467b9d + unaff_EBX) != 0) &&
     ((CINSRules *)**(undefined4 **)(CheckInFoundryMode + unaff_EBX + 1) != (CINSRules *)0x0)) {
    cVar3 = CINSRules::IsHunt((CINSRules *)**(undefined4 **)(CheckInFoundryMode + unaff_EBX + 1));
    if (cVar3 == '\0') {
      cVar3 = CINSRules::IsCheckpoint(this);
      this_00 = extraout_ECX;
      if (cVar3 != '\0') {
        uVar1 = *(uint *)(**(int **)(CheckInFoundryMode + unaff_EBX + 1) + 0x7cc +
                         *(int *)(**(int **)(CheckInFoundryMode + unaff_EBX + 1) + 0x770) * 4);
        if (((uVar1 == 0xffffffff) ||
            (iVar5 = **(int **)(&DAT_00467a7d + unaff_EBX) + (uVar1 & 0xffff) * 0x18,
            *(uint *)(iVar5 + 8) != uVar1 >> 0x10)) ||
           (piVar2 = *(int **)(iVar5 + 4), piVar2 == (int *)0x0)) {
          *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
          this_00 = (CINSRules *)param_2;
        }
        else {
          puVar4 = (undefined4 *)(**(code **)(*piVar2 + 0xc))(piVar2);
          *(undefined4 *)(param_2 + 0x5c) = *puVar4;
          this_00 = (CINSRules *)param_2;
        }
      }
    }
    else {
      iVar5 = 0;
      this_00 = this;
      do {
        if (*(int *)(**(int **)(CheckInFoundryMode + unaff_EBX + 1) + 0x6f0 + iVar5 * 4) != 1) {
          uVar1 = *(uint *)(**(int **)(CheckInFoundryMode + unaff_EBX + 1) + 0x7cc + iVar5 * 4);
          this_00 = (CINSRules *)**(int **)(&DAT_00467a7d + unaff_EBX);
          if (((uVar1 == 0xffffffff) ||
              (this_00 = this_00 + (uVar1 & 0xffff) * 0x18, *(uint *)(this_00 + 8) != uVar1 >> 0x10)
              ) || (piVar2 = *(int **)(this_00 + 4), piVar2 == (int *)0x0)) {
            *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
          }
          else {
            puVar4 = (undefined4 *)(**(code **)(*piVar2 + 0xc))(piVar2);
            *(undefined4 *)(param_2 + 0x5c) = *puVar4;
            this_00 = (CINSRules *)param_2;
          }
        }
        iVar5 = iVar5 + 1;
      } while (iVar5 != 3);
    }
    cVar3 = CINSRules::IsCheckpoint(this_00);
    if (cVar3 != '\0') {
      uVar1 = *(uint *)(param_2 + 0x5c);
      if (((uVar1 == 0xffffffff) ||
          (iVar5 = **(int **)(&DAT_00467a7d + unaff_EBX) + (uVar1 & 0xffff) * 0x18,
          *(uint *)(iVar5 + 8) != uVar1 >> 0x10)) || (*(int *)(iVar5 + 4) == 0)) {
        Warning(unaff_EBX + 0x243b69 /* "Investigation state could not locate objective
" */);
      }
    }
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  Warning(unaff_EBX + 0x243b3d /* "Could not initialize investigation data
" */);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::InitialContainedAction
 * Address: 0073ea40
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::InitialContainedAction(CINSNextBot*) */

void __cdecl CINSBotInvestigationMonitor::InitialContainedAction(CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)::operator_new(0x38);
  iVar1 = *(int *)(unaff_EBX + 0x468323 /* &vtable for CINSBotGamemodeMonitor */);
  piVar2[8] = 0;
  piVar2[9] = 0;
  piVar2[10] = 0;
  piVar2[3] = 0;
  piVar2[4] = 0;
  piVar2[5] = 0;
  piVar2[6] = 0;
  piVar2[7] = 0;
  piVar2[2] = 0;
  *(undefined1 *)(piVar2 + 0xc) = 0;
  *(undefined1 *)((int)piVar2 + 0x31) = 0;
  piVar2[0xb] = 0;
  piVar2[0xd] = 0;
  *piVar2 = iVar1 + 8;
  piVar2[1] = iVar1 + 0x198;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::Update
 * Address: 0073ef60
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::Update(CINSNextBot*, float) */

CINSNextBot * CINSBotInvestigationMonitor::Update(CINSNextBot *param_1,float param_2)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  undefined4 *puVar6;
  CINSRules *this;
  int unaff_EBX;
  float10 fVar7;
  float fVar8;
  
  piVar4 = (int *)__i686_get_pc_thunk_bx();
  piVar4 = (int *)(**(code **)(*piVar4 + 0x974 /* CINSNextBot::GetVisionInterface */))(piVar4);
  iVar5 = (**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
  if (((iVar5 == 0) && (**(int **)(&DAT_00467987 + unaff_EBX) != 0)) &&
     (**(int **)(unaff_EBX + 0x467dab /* &g_pObjectiveResource */) != 0)) {
    cVar3 = CINSRules::IsCheckpoint(this);
    if (cVar3 != '\0') {
      fVar7 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x58) <= (float)fVar7 &&
          (float)fVar7 != *(float *)((int)param_2 + 0x58)) {
        iVar5 = 0;
        uVar2 = *(uint *)((int)param_2 + 0x5c);
        if ((uVar2 != 0xffffffff) &&
           (iVar1 = **(int **)(unaff_EBX + 0x467867 /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
           *(uint *)(iVar1 + 8) == uVar2 >> 0x10)) {
          iVar5 = *(int *)(iVar1 + 4);
        }
        iVar1 = *(int *)(**(int **)(unaff_EBX + 0x467dab /* &g_pObjectiveResource */) + 0x770);
        if (*(int *)(iVar5 + 900) != iVar1) {
          uVar2 = *(uint *)(**(int **)(unaff_EBX + 0x467dab /* &g_pObjectiveResource */) + 0x7cc + iVar1 * 4);
          if (((uVar2 == 0xffffffff) ||
              (iVar5 = **(int **)(unaff_EBX + 0x467867 /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
              *(uint *)(iVar5 + 8) != uVar2 >> 0x10)) ||
             (piVar4 = *(int **)(iVar5 + 4), piVar4 == (int *)0x0)) {
            *(undefined4 *)((int)param_2 + 0x5c) = 0xffffffff;
          }
          else {
            puVar6 = (undefined4 *)(**(code **)(*piVar4 + 0xc /* CBaseEntity::GetRefEHandle */))(piVar4);
            *(undefined4 *)((int)param_2 + 0x5c) = *puVar6;
          }
        }
        fVar7 = (float10)CountdownTimer::Now();
        fVar8 = (float)fVar7 + *(float *)(unaff_EBX + 0x1e57fb /* typeinfo name for CBaseGameSystem+0x32 */);
        if (*(float *)((int)param_2 + 0x58) != fVar8) {
          (**(code **)(*(int *)((int)param_2 + 0x50) + 4))((int)param_2 + 0x50,(int)param_2 + 0x58);
          *(float *)((int)param_2 + 0x58) = fVar8;
        }
        if (*(int *)((int)param_2 + 0x54) != 0x40a00000 /* 5.0f */) {
          (**(code **)(*(int *)((int)param_2 + 0x50) + 4))((int)param_2 + 0x50,(int)param_2 + 0x54);
          *(undefined4 *)((int)param_2 + 0x54) = 0x40a00000 /* 5.0f */;
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::GetName
 * Address: 0073fbe0
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::GetName() const */

int CINSBotInvestigationMonitor::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x242c4d /* "Investigations" */;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::OnOtherKilled
 * Address: 0073f120
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo
   const&) */

CINSNextBot *
CINSBotInvestigationMonitor::OnOtherKilled
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  CTakeDamageInfo CVar7;
  uint uVar8;
  char cVar9;
  int *piVar10;
  int iVar11;
  float fVar12;
  CINSNextBot *this;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar13;
  CBaseEntity *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar14;
  CBaseEntity *in_stack_00000010;
  int in_stack_00000014;
  undefined4 uVar15;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000010 != (CBaseEntity *)0x0) {
    if (((byte)in_stack_00000010[0xd1] & 8) == 0) {
      CVar7 = param_3[0xd1];
      pCVar13 = in_stack_00000010;
    }
    else {
      CBaseEntity::CalcAbsolutePosition(in_stack_00000010);
      CVar7 = param_3[0xd1];
      pCVar13 = extraout_ECX_00;
    }
    if (((byte)CVar7 & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar13);
    }
    fVar1 = *(float *)(param_3 + 0x208);
    fVar2 = *(float *)(param_3 + 0x20c);
    fVar3 = *(float *)(param_3 + 0x210);
    fVar4 = *(float *)(in_stack_00000010 + 0x208);
    fVar5 = *(float *)(in_stack_00000010 + 0x20c);
    fVar6 = *(float *)(in_stack_00000010 + 0x210);
    piVar10 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    cVar9 = (**(code **)(*piVar10 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar10,in_stack_00000010,0,0);
    if (cVar9 == '\0') {
      piVar10 = (int *)(*(int **)(unaff_EBX + 0x467f29 /* &ins_bot_friendly_death_hearing_distance */))[7];
      if (piVar10 == *(int **)(unaff_EBX + 0x467f29 /* &ins_bot_friendly_death_hearing_distance */)) {
        fVar12 = (float)((uint)piVar10 ^ piVar10[0xb]);
      }
      else {
        fVar14 = (float10)(**(code **)(*piVar10 + 0x3c))(piVar10);
        fVar12 = (float)fVar14;
      }
      if (fVar12 <= SQRT((fVar2 - fVar5) * (fVar2 - fVar5) + (fVar1 - fVar4) * (fVar1 - fVar4) +
                         (fVar3 - fVar6) * (fVar3 - fVar6))) goto LAB_0073f330;
    }
    fVar14 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
    if (*(float *)(&DAT_001e562d + unaff_EBX) <= (float)fVar14 &&
        (float)fVar14 != *(float *)(&DAT_001e562d + unaff_EBX)) {
      uVar15 = 0;
      CINSNextBot::BotSpeakConceptIfAllowed
                (this,(int)param_3,(char *)0x49,(char *)0x0,0,(IRecipientFilter *)0x0);
      fVar14 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
      if ((float)fVar14 < *(float *)(unaff_EBX + 0x1f8bb5 /* typeinfo name for NetworkVarEmbedded<CountdownTimer, CINSPlayerShared, CINSPlayerShared::GetOffset_m_StanceTransitionTimer>+0xa0 */) ||
          (float)fVar14 == *(float *)(unaff_EBX + 0x1f8bb5 /* typeinfo name for NetworkVarEmbedded<CountdownTimer, CINSPlayerShared, CINSPlayerShared::GetOffset_m_StanceTransitionTimer>+0xa0 */)) {
        CINSNextBot::AddInvestigation();
      }
      else {
        uVar8 = *(uint *)(in_stack_00000014 + 0x28);
        iVar11 = 0;
        pCVar13 = extraout_ECX;
        if ((uVar8 != 0xffffffff) &&
           (pCVar13 = (CBaseEntity *)(**(int **)(unaff_EBX + 0x4676ad /* &g_pEntityList */) + (uVar8 & 0xffff) * 0x18),
           *(uint *)(pCVar13 + 8) == uVar8 >> 0x10)) {
          iVar11 = *(int *)(pCVar13 + 4);
        }
        if ((*(byte *)(iVar11 + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(pCVar13);
        }
        CINSNextBot::AddInvestigation
                  (param_3,*(undefined4 *)(iVar11 + 0x208),*(undefined4 *)(iVar11 + 0x20c),
                   *(undefined4 *)(iVar11 + 0x210),2,uVar15);
      }
    }
  }
LAB_0073f330:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::OnWeaponFired
 * Address: 0073f700
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*,
   CBaseCombatWeapon*) */

CINSNextBot * __thiscall
CINSBotInvestigationMonitor::OnWeaponFired
          (CINSBotInvestigationMonitor *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CBaseCombatWeapon *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  char cVar6;
  char cVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  float *pfVar11;
  float *pfVar12;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CINSNextBot *this_02;
  CINSNextBot *extraout_ECX;
  CBaseCombatCharacter *pCVar13;
  int unaff_EBX;
  float10 fVar14;
  float fVar15;
  CINSNextBot *in_stack_00000010;
  undefined4 uVar16;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000010 != (CINSNextBot *)param_3) && (in_stack_00000010 != (CINSNextBot *)0x0)) {
    cVar6 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3);
    if (cVar6 == '\0') {
      iVar8 = CBaseEntity::GetTeamNumber(this_00);
      iVar9 = CBaseEntity::GetTeamNumber(this_01);
      if (iVar8 != iVar9) {
        piVar10 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        cVar6 = (**(code **)(*piVar10 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar10,in_stack_00000010,0,0);
        piVar10 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        cVar7 = (**(code **)(*piVar10 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar10,in_stack_00000010,1,0);
        piVar10 = (int *)(**(code **)(*(int *)param_3 + 0x97c /* CINSNextBot::GetIntentionInterface */))(param_3);
        iVar8 = (**(code **)(*piVar10 + 0xcc /* IIntention::ShouldHurry */))(piVar10,param_3 + 0x2060);
        pfVar11 = (float *)(**(code **)(*(int *)in_stack_00000010 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000010);
        pfVar12 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
        fVar15 = *pfVar12;
        fVar1 = pfVar12[1];
        fVar2 = pfVar12[2];
        fVar3 = *pfVar11;
        fVar4 = pfVar11[1];
        fVar5 = pfVar11[2];
        pCVar13 = param_2 + 0x38;
        fVar14 = (float10)CountdownTimer::Now();
        if (*(float *)(param_2 + 0x40) <= (float)fVar14 &&
            (float)fVar14 != *(float *)(param_2 + 0x40)) {
          this_02 = (CINSNextBot *)param_2;
          if (cVar6 != '\0') {
            fVar14 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
            this_02 = extraout_ECX;
            if (*(float *)(unaff_EBX + 0x179408 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */) <= (float)fVar14 &&
                (float)fVar14 != *(float *)(unaff_EBX + 0x179408 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */)) {
              CINSNextBot::AddInvestigation(in_stack_00000010,param_3,in_stack_00000010,2);
              fVar14 = (float10)CountdownTimer::Now();
              fVar15 = (float)fVar14 + *(float *)(unaff_EBX + 0x1e5058 /* typeinfo name for CBaseGameSystem+0x32 */);
              if (*(float *)(param_2 + 0x40) != fVar15) {
                (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x40);
                *(float *)(param_2 + 0x40) = fVar15;
              }
              if (*(int *)(param_2 + 0x3c) != 0x40a00000 /* 5.0f */) {
                (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x3c);
                *(undefined4 *)(param_2 + 0x3c) = 0x40a00000 /* 5.0f */;
              }
              goto LAB_0073f725;
            }
          }
          if (cVar7 != '\0') {
            cVar6 = CINSNextBot::HasInvestigations(this_02);
            if ((cVar6 == '\0') && (iVar8 != 1)) {
              fVar14 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
              if (*(float *)(unaff_EBX + 0x1e4378 /* typeinfo name for ISaveRestoreOps+0x67 */) <= (float)fVar14 &&
                  (float)fVar14 != *(float *)(unaff_EBX + 0x1e4378 /* typeinfo name for ISaveRestoreOps+0x67 */)) {
                uVar16 = 2;
                CINSNextBot::AddInvestigation();
                fVar14 = (float10)CountdownTimer::Now();
                fVar15 = (float)fVar14 + *(float *)(unaff_EBX + 0x1e5058 /* typeinfo name for CBaseGameSystem+0x32 */);
                if (*(float *)(param_2 + 0x40) != fVar15) {
                  (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x40,uVar16);
                  *(float *)(param_2 + 0x40) = fVar15;
                }
                if (*(int *)(param_2 + 0x3c) != 0x40a00000 /* 5.0f */) {
                  (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x3c);
                  *(undefined4 *)(param_2 + 0x3c) = 0x40a00000 /* 5.0f */;
                }
                goto LAB_0073f725;
              }
            }
          }
          if (SQRT((fVar1 - fVar4) * (fVar1 - fVar4) + (fVar15 - fVar3) * (fVar15 - fVar3) +
                   (fVar2 - fVar5) * (fVar2 - fVar5)) < *(float *)(unaff_EBX + 0x1e58fc /* typeinfo name for ITraceFilter+0x20 */)) {
            fVar14 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
            if (*(float *)(unaff_EBX + 0x1edf80 /* typeinfo name for CEntityFactory<CINSRulesProxy>+0x34 */) <= (float)fVar14 &&
                (float)fVar14 != *(float *)(unaff_EBX + 0x1edf80 /* typeinfo name for CEntityFactory<CINSRulesProxy>+0x34 */)) {
              CINSNextBot::AddInvestigation(in_stack_00000010,param_3,in_stack_00000010,2);
              fVar14 = (float10)CountdownTimer::Now();
              fVar15 = (float)fVar14 + *(float *)(unaff_EBX + 0x1e4a9c /* typeinfo name for CTraceFilterNoCombatCharacters+0x30 */);
              if (*(float *)(param_2 + 0x40) != fVar15) {
                (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x40);
                *(float *)(param_2 + 0x40) = fVar15;
              }
              if (*(int *)(param_2 + 0x3c) != 0x41200000 /* 10.0f */) {
                (**(code **)(*(int *)(param_2 + 0x38) + 4))(pCVar13,param_2 + 0x3c);
                *(undefined4 *)(param_2 + 0x3c) = 0x41200000 /* 10.0f */;
              }
            }
          }
        }
      }
    }
  }
LAB_0073f725:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::AddInvestigationArea
 * Address: 0073fbc0
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::AddInvestigationArea(CINSNextBot*, Vector, bool, bool) */

void __cdecl CINSBotInvestigationMonitor::AddInvestigationArea(void)

{
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::OnHeardFootsteps
 * Address: 0073f3c0
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

CINSNextBot *
CINSBotInvestigationMonitor::OnHeardFootsteps
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  code *pcVar1;
  char cVar2;
  float *pfVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  undefined4 extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this;
  CINSNextBot *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar7;
  float fVar8;
  int *in_stack_00000010;
  undefined4 *in_stack_00000014;
  undefined4 uVar9;
  undefined4 uVar10;
  CBaseCombatCharacter local_28 [24];
  
  __i686_get_pc_thunk_bx();
  cVar2 = (**(code **)(*(int *)(param_3 + 0x2060) + 0xe8))(param_3 + 0x2060,extraout_ECX);
  if ((cVar2 == '\0') || (cVar2 = (**(code **)(*(int *)param_3 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(param_3), cVar2 != '\0'))
  goto LAB_0073f403;
  pfVar3 = (float *)(**(code **)(*(int *)param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3);
  pfVar4 = (float *)(**(code **)(*in_stack_00000010 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000010);
  fVar8 = SQRT((pfVar4[1] - pfVar3[1]) * (pfVar4[1] - pfVar3[1]) +
               (*pfVar4 - *pfVar3) * (*pfVar4 - *pfVar3) +
               (pfVar4[2] - pfVar3[2]) * (pfVar4[2] - pfVar3[2]));
  this = extraout_ECX_00;
  if (*(float *)(unaff_EBX + 0x20d37d /* typeinfo name for CEntityFactory<CBaseFlex>+0x20 */) <= fVar8 && fVar8 != *(float *)(unaff_EBX + 0x20d37d /* typeinfo name for CEntityFactory<CBaseFlex>+0x20 */)) {
    piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    iVar6 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    if (iVar6 != 0) goto LAB_0073f403;
    piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x97c /* CINSNextBot::GetIntentionInterface */))(param_3);
    iVar6 = (**(code **)(*piVar5 + 0xcc /* IIntention::ShouldHurry */))(piVar5,param_3 + 0x2060);
    this = extraout_ECX_01;
    if (iVar6 == 1) goto LAB_0073f403;
  }
  uVar10 = 0;
  uVar9 = 0;
  CINSNextBot::BotSpeakConceptIfAllowed
            (this,(int)param_3,(char *)0x3f,(char *)0x0,0,(IRecipientFilter *)0x0);
  piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
  cVar2 = (**(code **)(*piVar5 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar5,in_stack_00000010,1,0,uVar9,uVar10);
  if ((cVar2 == '\0') || (cVar2 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3), cVar2 != '\0')) {
    fVar7 = (float10)CountdownTimer::Now();
    if (*(float *)(param_2 + 0x40) <= (float)fVar7 && (float)fVar7 != *(float *)(param_2 + 0x40)) {
      iVar6 = RandomInt(4,7);
      fVar8 = (float)iVar6;
      fVar7 = (float10)CountdownTimer::Now();
      if (*(float *)(param_2 + 0x40) != (float)fVar7 + fVar8) {
        (**(code **)(*(int *)(param_2 + 0x38) + 4))(param_2 + 0x38,param_2 + 0x40);
        *(float *)(param_2 + 0x40) = (float)fVar7 + fVar8;
      }
      if (*(float *)(param_2 + 0x3c) != fVar8) {
        (**(code **)(*(int *)(param_2 + 0x38) + 4))(param_2 + 0x38,param_2 + 0x3c);
        *(float *)(param_2 + 0x3c) = fVar8;
      }
      CINSNextBot::AddInvestigation
                (param_3,*in_stack_00000014,in_stack_00000014[1],in_stack_00000014[2],6);
      cVar2 = (**(code **)(*(int *)param_3 + 0x980 /* CINSNextBot::IsDebugging */))(param_3,1);
      if (cVar2 != '\0') {
        DevMsg((char *)(unaff_EBX + 0x24346d /* "Adding new investigation area for OnHeardFootsteps
" */));
      }
    }
  }
  else {
    piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
    pcVar1 = *(code **)(*piVar5 + 0xd4);
    CINSNextBot::GetTargetPosition(local_28);
    (*pcVar1)(piVar5,local_28,2,0x3f400000 /* 0.75f */,0,unaff_EBX + 0x24351d /* "Looking at source of footsteps" */);
  }
LAB_0073f403:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::OnSeeSomethingSuspicious
 * Address: 0073ead0
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

CINSNextBot *
CINSBotInvestigationMonitor::OnSeeSomethingSuspicious
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  undefined4 *in_stack_00000014;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*(int *)param_3 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(param_3);
  if ((cVar1 == '\0') &&
     ((*(int *)(param_3 + 0xb338) == -1 ||
      (iVar2 = UTIL_EntityByIndex(*(int *)(param_3 + 0xb338)), iVar2 == 0)))) {
    piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
    if ((piVar3 == (int *)0x0) || (iVar2 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar2 == 0)) {
      piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x97c /* CINSNextBot::GetIntentionInterface */))(param_3);
      iVar2 = (**(code **)(*piVar3 + 0xcc /* IIntention::ShouldHurry */))(piVar3,param_3 + 0x2060);
      if (iVar2 != 1) {
        piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        cVar1 = (**(code **)(*piVar3 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar3,in_stack_00000014,1);
        if ((cVar1 == '\0') ||
           (cVar1 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3), cVar1 != '\0')) {
          fVar4 = (float10)CountdownTimer::Now();
          if (*(float *)(param_2 + 0x40) <= (float)fVar4 &&
              (float)fVar4 != *(float *)(param_2 + 0x40)) {
            iVar2 = RandomInt(4,7);
            fVar5 = (float)iVar2;
            fVar4 = (float10)CountdownTimer::Now();
            if (*(float *)(param_2 + 0x40) != (float)fVar4 + fVar5) {
              (**(code **)(*(int *)(param_2 + 0x38) + 4))(param_2 + 0x38,param_2 + 0x40);
              *(float *)(param_2 + 0x40) = (float)fVar4 + fVar5;
            }
            if (*(float *)(param_2 + 0x3c) != fVar5) {
              (**(code **)(*(int *)(param_2 + 0x38) + 4))(param_2 + 0x38,param_2 + 0x3c);
              *(float *)(param_2 + 0x3c) = fVar5;
            }
            CINSNextBot::AddInvestigation
                      (param_3,*in_stack_00000014,in_stack_00000014[1],in_stack_00000014[2],5);
            cVar1 = (**(code **)(*(int *)param_3 + 0x980 /* CINSNextBot::IsDebugging */))(param_3,1);
            if (cVar1 != '\0') {
              DevMsg((char *)(unaff_EBX + 0x243d60 /* "Adding new investigation area for OnHeardFootsteps
" */));
            }
          }
        }
        else {
          piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
          (**(code **)(*piVar3 + 0xd4 /* PlayerBody::AimHeadTowards */))
                    (piVar3,in_stack_00000014,2,0x3f400000 /* 0.75f */,0,unaff_EBX + 0x243d94 /* "Looking at something suspicious" */);
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::SortAndRemoveInvestigations
 * Address: 0073fbd0
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::SortAndRemoveInvestigations(CINSNextBot*) */

void __cdecl CINSBotInvestigationMonitor::SortAndRemoveInvestigations(CINSNextBot *param_1)

{
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor
 * Address: 0073fc00
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor() */

void __thiscall
CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor(CINSBotInvestigationMonitor *this)

{
  ~CINSBotInvestigationMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor
 * Address: 0073fc10
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor() */

void __thiscall
CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor(CINSBotInvestigationMonitor *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45af73 /* vtable for CINSBotInvestigationMonitor+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x45b103 /* vtable for CINSBotInvestigationMonitor+0x198 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(CFogVolume::InputDisable + extraout_ECX + 3))
  ;
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor
 * Address: 0073fc40
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor() */

void __thiscall
CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor(CINSBotInvestigationMonitor *this)

{
  ~CINSBotInvestigationMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor
 * Address: 0073fc50
 * ---------------------------------------- */

/* CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor() */

void __thiscall
CINSBotInvestigationMonitor::~CINSBotInvestigationMonitor(CINSBotInvestigationMonitor *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45af2a /* vtable for CINSBotInvestigationMonitor+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45b0ba /* vtable for CINSBotInvestigationMonitor+0x198 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



