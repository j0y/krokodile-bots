/*
 * CINSBotTacticalMonitor -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 20
 */

/* ----------------------------------------
 * CINSBotTacticalMonitor::OnStart
 * Address: 0073fe70
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotTacticalMonitor::OnStart(CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  float10 fVar2;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_2 + 0x94) = 0xffffffff;
  fVar2 = (float10)CountdownTimer::Now();
  fVar1 = *(float *)(param_2 + 0x78);
  if (*(float *)(param_2 + 0x7c) != (float)fVar2 + fVar1) {
    (**(code **)(*(int *)(param_2 + 0x74) + 4))(param_2 + 0x74,param_2 + 0x7c);
    *(float *)(param_2 + 0x7c) = (float)fVar2 + fVar1;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::InitialContainedAction
 * Address: 0073fd40
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::InitialContainedAction(CINSNextBot*) */

int * __cdecl CINSBotTacticalMonitor::InitialContainedAction(CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)::operator_new(0x60);
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
  iVar1 = *(int *)(unaff_EBX + 0x466dc5 /* &vtable for CINSBotInvestigationMonitor */);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  piVar2[0xe] = (int)(&UNK_003e846d + unaff_EBX);
  *piVar2 = iVar1 + 8;
  (*(code *)(unaff_EBX + -0x50f5db /* CountdownTimer::NetworkStateChanged */))(piVar2 + 0xe,piVar2 + 0xf);
  piVar2[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x15] = 0;
  piVar2[0x14] = (int)(&UNK_003e846d + unaff_EBX);
  (*(code *)(unaff_EBX + -0x50f5db /* CountdownTimer::NetworkStateChanged */))(piVar2 + 0x14,piVar2 + 0x15);
  piVar2[0x16] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar2[0x14] + 4))(piVar2 + 0x14,piVar2 + 0x16);
  piVar2[0x17] = -1;
  return piVar2;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::Update
 * Address: 00741bc0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotTacticalMonitor::Update(CINSBotTacticalMonitor *this,CINSNextBot *param_1,float param_2)

{
  float *pfVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  undefined4 uVar7;
  CBaseEntity *pCVar8;
  int iVar9;
  Vector *pVVar10;
  void *pvVar11;
  int iVar12;
  CINSNextBot *extraout_ECX;
  CBaseEntity *this_00;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *this_01;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *extraout_ECX_04;
  CINSNextBot *extraout_ECX_05;
  CINSNextBot *extraout_ECX_06;
  CINSNextBot *extraout_ECX_07;
  CINSNextBot *extraout_ECX_08;
  CINSBotVision *this_02;
  CINSPlayer *this_03;
  CINSNextBot *extraout_ECX_09;
  CINSNextBot *extraout_ECX_10;
  CINSRules *extraout_ECX_11;
  CINSRules *extraout_ECX_12;
  CINSRules *this_04;
  CINSRules *this_05;
  CINSPlayer *this_06;
  CINSPlayer *this_07;
  int unaff_EBX;
  bool bVar13;
  float10 fVar14;
  CINSNextBot *this_08;
  float fVar15;
  CINSBotThrowGrenade *in_stack_0000000c;
  float local_50;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x741bcb;
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)CINSPlayer::GetActiveINSWeapon();
  if (piVar4 == (int *)0x0) goto LAB_00741de8;
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
  bVar13 = false;
  if (piVar5 != (int *)0x0) {
    cVar3 = (**(code **)(*piVar5 + 0x3c))(piVar5);
    bVar13 = cVar3 != '\0';
  }
  iVar9 = (int)param_2 + 0x38;
  fVar14 = (float10)CountdownTimer::Now();
  this_08 = extraout_ECX;
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar14 &&
      (float)fVar14 != *(float *)((int)param_2 + 0x40)) {
    if (bVar13) {
      pcVar2 = *(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x130);
      uVar7 = (**(code **)(*piVar5 + 0x10))(piVar5);
      fVar14 = (float10)(*pcVar2)(in_stack_0000000c + 0x2060,uVar7);
      if (*(float *)(unaff_EBX + 0x1f1f71 /* typeinfo name for CINSRules_Survival+0x1c */) <= (float)fVar14 &&
          (float)fVar14 != *(float *)(unaff_EBX + 0x1f1f71 /* typeinfo name for CINSRules_Survival+0x1c */)) {
        fVar15 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
        cVar3 = CINSPlayer::IsThreatAimingTowardMe(this_06,(CBaseEntity *)in_stack_0000000c,fVar15);
        if (cVar3 == '\0') goto LAB_00741c53;
      }
LAB_0074218d:
      pcVar2 = *(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x130);
      pVVar10 = (Vector *)(**(code **)(*piVar5 + 0x10))(piVar5);
      fVar14 = (float10)(*pcVar2)(in_stack_0000000c + 0x2060,pVVar10);
      if (*(float *)(unaff_EBX + 0x23fad9 /* typeinfo name for CollectIdealPatrolAreas+0x20 */) <= (float)fVar14 &&
          (float)fVar14 != *(float *)(unaff_EBX + 0x23fad9 /* typeinfo name for CollectIdealPatrolAreas+0x20 */)) {
        pVVar10 = local_28;
        cVar3 = CINSBotFireRPG::HasRPGTarget((CINSNextBot *)in_stack_0000000c,pVVar10);
        if (cVar3 != '\0') {
          piVar6 = (int *)(*(int **)(unaff_EBX + 0x464ce5 /* &bot_rpg_spawn_attackdelay */))[7];
          if (piVar6 == *(int **)(unaff_EBX + 0x464ce5 /* &bot_rpg_spawn_attackdelay */)) {
            local_50 = (float)((uint)piVar6 ^ piVar6[0xb]);
            this_04 = extraout_ECX_11;
          }
          else {
            fVar14 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
            local_50 = (float)fVar14;
            this_04 = extraout_ECX_12;
          }
          piVar6 = *(int **)(unaff_EBX + 0x464d2d /* &g_pGameRules */);
          pVVar10 = (Vector *)CINSRules::GetHumanTeam(this_04);
          fVar14 = (float10)CINSRules::GetLastDeploymentTime(this_05,*piVar6);
          pfVar1 = (float *)(**(int **)(unaff_EBX + 0x464cd5 /* &gpGlobals */) + 0xc);
          if ((float)fVar14 + local_50 < *pfVar1 || (float)fVar14 + local_50 == *pfVar1) {
            if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition((CBaseEntity *)in_stack_0000000c);
            }
            pvVar11 = ::operator_new(0x70);
            CINSBotFireRPG::CINSBotFireRPG();
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(undefined4 *)param_1 = 2 /* SuspendFor */;
            *(void **)(param_1 + 4) = pvVar11;
            *(int *)(param_1 + 8) = unaff_EBX + 0x240dda /* "Firing an RPG!" */;
            return param_1;
          }
        }
      }
    }
    else {
LAB_00741c53:
      pVVar10 = (Vector *)&local_34;
      cVar3 = CINSBotThrowGrenade::CanIThrowGrenade((CINSNextBot *)in_stack_0000000c,pVVar10);
      if (cVar3 != '\0') {
        if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_00);
        }
        pvVar11 = ::operator_new(0x6c);
        CINSBotThrowGrenade::CINSBotThrowGrenade
                  (in_stack_0000000c,pvVar11,*(undefined4 *)(in_stack_0000000c + 0x208),
                   *(undefined4 *)(in_stack_0000000c + 0x20c),
                   *(undefined4 *)(in_stack_0000000c + 0x210),local_34,local_30,local_2c);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(void **)(param_1 + 4) = pvVar11;
        *(int *)(param_1 + 8) = unaff_EBX + 0x240dc6 /* "Throwing a grenade!" */;
        return param_1;
      }
      if (bVar13) goto LAB_0074218d;
    }
    cVar3 = (**(code **)(*(int *)in_stack_0000000c + 0x8ac /* CINSNextBot::IsInCombat */))(in_stack_0000000c,pVVar10);
    if (cVar3 == '\0') {
      fVar14 = (float10)CountdownTimer::Now();
      this_08 = (CINSNextBot *)((float)fVar14 + *(float *)(unaff_EBX + 0x1e2b95 /* typeinfo name for CBaseGameSystem+0x26 */));
      if (*(CINSNextBot **)((int)param_2 + 0x40) != this_08) {
        (**(code **)(*(int *)((int)param_2 + 0x38) + 4))(iVar9,(int)param_2 + 0x40);
        *(CINSNextBot **)((int)param_2 + 0x40) = this_08;
        this_08 = extraout_ECX_03;
      }
      if (*(int *)((int)param_2 + 0x3c) != 0x40800000 /* 4.0f */) {
        (**(code **)(*(int *)((int)param_2 + 0x38) + 4))(iVar9,(int)param_2 + 0x3c);
        *(undefined4 *)((int)param_2 + 0x3c) = 0x40800000 /* 4.0f */;
        this_08 = extraout_ECX_04;
      }
    }
    else {
      fVar14 = (float10)CountdownTimer::Now();
      this_08 = (CINSNextBot *)((float)fVar14 + *(float *)(unaff_EBX + 0x176f49 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */));
      if (*(CINSNextBot **)((int)param_2 + 0x40) != this_08) {
        (**(code **)(*(int *)((int)param_2 + 0x38) + 4))(iVar9,(int)param_2 + 0x40);
        *(CINSNextBot **)((int)param_2 + 0x40) = this_08;
        this_08 = extraout_ECX_00;
      }
      if (*(int *)((int)param_2 + 0x3c) != 0x3f800000 /* 1.0f */) {
        (**(code **)(*(int *)((int)param_2 + 0x38) + 4))(iVar9,(int)param_2 + 0x3c);
        *(undefined4 *)((int)param_2 + 0x3c) = 0x3f800000 /* 1.0f */;
        this_08 = extraout_ECX_01;
      }
    }
  }
  if (piVar5 == (int *)0x0) {
LAB_00741d1f:
    *(undefined4 *)((int)param_2 + 0x94) = 0xffffffff;
  }
  else {
    piVar6 = (int *)(**(code **)(*piVar5 + 0x10))(piVar5);
    cVar3 = (**(code **)(*piVar6 + 0x118))(piVar6);
    this_08 = extraout_ECX_02;
    if (((cVar3 == '\0') ||
        (cVar3 = (**(code **)(*piVar5 + 0x54))(piVar5), this_08 = extraout_ECX_05, cVar3 != '\0'))
       || (cVar3 = (**(code **)(*piVar5 + 0x38))(piVar5), this_08 = extraout_ECX_06, cVar3 == '\0'))
    goto LAB_00741d1f;
    fVar14 = (float10)CountdownTimer::Now();
    this_08 = extraout_ECX_07;
    if (*(float *)((int)param_2 + 0x7c) <= (float)fVar14 &&
        (float)fVar14 != *(float *)((int)param_2 + 0x7c)) {
      piVar6 = (int *)(**(code **)(*piVar5 + 0x10))(piVar5);
      cVar3 = (**(code **)(*piVar6 + 0x118))(piVar6);
      this_08 = extraout_ECX_08;
      if (cVar3 != '\0') {
        uVar7 = (**(code **)(*piVar5 + 0x10))(piVar5);
        pCVar8 = (CBaseEntity *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        iVar9 = CINSBotVision::GetSilhouetteType(this_02,pCVar8);
        if (((iVar9 != *(int *)((int)param_2 + 0x94)) && (bVar13)) &&
           ((cVar3 = CINSPlayer::IsProned(this_03), cVar3 == '\0' &&
            (cVar3 = CINSPlayer::IsCrouched(this_07), cVar3 == '\0')))) {
          piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c,uVar7);
          iVar12 = (**(code **)(*piVar5 + 0xcc /* IIntention::ShouldHurry */))(piVar5,in_stack_0000000c + 0x2060);
          if (iVar12 != 1) {
            *(int *)((int)param_2 + 0x94) = iVar9;
            CheckPosture((CINSBotTacticalMonitor *)in_stack_0000000c,(CINSNextBot *)param_2,
                         (CKnownEntity *)in_stack_0000000c);
          }
        }
        fVar14 = (float10)CountdownTimer::Now();
        this_08 = (CINSNextBot *)((float)fVar14 + *(float *)(unaff_EBX + 0x1e25e5 /* typeinfo name for CTraceFilterNoCombatCharacters+0x30 */));
        if (*(CINSNextBot **)((int)param_2 + 0x7c) != this_08) {
          (**(code **)(*(int *)((int)param_2 + 0x74) + 4))((int)param_2 + 0x74,(int)param_2 + 0x7c);
          *(CINSNextBot **)((int)param_2 + 0x7c) = this_08;
          this_08 = extraout_ECX_09;
        }
        if (*(int *)((int)param_2 + 0x78) != 0x41200000 /* 10.0f */) {
          (**(code **)(*(int *)((int)param_2 + 0x74) + 4))((int)param_2 + 0x74,(int)param_2 + 0x78);
          *(undefined4 *)((int)param_2 + 0x78) = 0x41200000 /* 10.0f */;
          this_08 = extraout_ECX_10;
        }
      }
    }
  }
  if (((!bVar13) && (cVar3 = CINSNextBot::ShouldReload(this_08), cVar3 != '\0')) &&
     ((cVar3 = (**(code **)(*piVar4 + 0x658 /* NextBotPlayer::OnMainActivityInterrupted */))(piVar4), cVar3 != '\0' &&
      (cVar3 = CINSNextBot::ShouldOpportunisticReload(this_01), cVar3 != '\0')))) {
    piVar4 = (int *)::operator_new(0x5c);
    piVar4[8] = 0;
    piVar4[9] = 0;
    piVar4[10] = 0;
    piVar4[3] = 0;
    piVar4[4] = 0;
    piVar4[5] = 0;
    piVar4[6] = 0;
    piVar4[7] = 0;
    piVar4[2] = 0;
    *(undefined1 *)(piVar4 + 0xc) = 0;
    *(undefined1 *)((int)piVar4 + 0x31) = 0;
    piVar4[0xb] = 0;
    piVar4[0xd] = 0;
    iVar12 = *(int *)(unaff_EBX + 0x464e2d /* &vtable for CINSBotReload */);
    piVar4[0xf] = 0;
    piVar4[1] = iVar12 + 0x198;
    iVar9 = unaff_EBX + 0x3e65ed /* vtable for CountdownTimer+0x8 */;
    *piVar4 = iVar12 + 8;
    pcVar2 = (code *)(unaff_EBX + -0x51145b /* CountdownTimer::NetworkStateChanged */);
    piVar4[0xe] = iVar9;
    (*pcVar2)(piVar4 + 0xe,piVar4 + 0xf);
    piVar4[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
    piVar4[0x12] = 0;
    piVar4[0x11] = iVar9;
    (*pcVar2)(piVar4 + 0x11,piVar4 + 0x12);
    piVar4[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
    piVar4[0x15] = 0;
    piVar4[0x14] = iVar9;
    (*pcVar2)(piVar4 + 0x14,piVar4 + 0x15);
    piVar4[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(int **)(param_1 + 4) = piVar4;
    *(int *)(param_1 + 8) = unaff_EBX + 0x240de9 /* "Opportunistic reload in-place" */;
    return param_1;
  }
  fVar14 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x90) <= (float)fVar14 &&
      (float)fVar14 != *(float *)((int)param_2 + 0x90)) {
    CINSNextBot::ChooseBestWeapon
              ((CINSNextBot *)in_stack_0000000c,(CKnownEntity *)in_stack_0000000c);
    fVar14 = (float10)CountdownTimer::Now();
    fVar15 = (float)fVar14 + *(float *)(unaff_EBX + 0x1e2b8d /* typeinfo name for CBaseGameSystem+0x1e */);
    if (*(float *)((int)param_2 + 0x90) != fVar15) {
      (**(code **)(*(int *)((int)param_2 + 0x88) + 4))((int)param_2 + 0x88,(int)param_2 + 0x90);
      *(float *)((int)param_2 + 0x90) = fVar15;
    }
    if (*(int *)((int)param_2 + 0x8c) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x88) + 4))((int)param_2 + 0x88,(int)param_2 + 0x8c);
      *(undefined4 *)((int)param_2 + 0x8c) = 0x3f000000 /* 0.5f */;
    }
  }
LAB_00741de8:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::GetName
 * Address: 00742c70
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::GetName() const */

int CINSBotTacticalMonitor::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x23fcbc /* "Tactics" */;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::ShouldAttack
 * Address: 0073ffb0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotTacticalMonitor::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotTacticalMonitor::ShouldAttack
          (CINSBotTacticalMonitor *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::ShouldAttack
 * Address: 0073ffc0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::ShouldAttack(INextBot const*, CKnownEntity const*) const */

uint __thiscall
CINSBotTacticalMonitor::ShouldAttack
          (CINSBotTacticalMonitor *this,INextBot *param_1,CKnownEntity *param_2)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  CINSNextBot *this_00;
  float10 fVar5;
  float10 fVar6;
  int *in_stack_0000000c;
  
  uVar2 = __i686_get_pc_thunk_bx();
  if (*(int *)(param_1 + 0x1c) != 0) {
    iVar3 = CINSPlayer::GetActiveINSWeapon();
    uVar2 = 0;
    if (iVar3 != 0) {
      pcVar1 = *(code **)(*(int *)param_2 + 0x134);
      uVar4 = (**(code **)(*in_stack_0000000c + 0x14))(in_stack_0000000c);
      fVar5 = (float10)(*pcVar1)(param_2,uVar4);
      fVar6 = (float10)CINSNextBot::GetMaxAttackRange(this_00,*(CINSWeapon **)(param_1 + 0x1c));
      uVar2 = (uint)((float)fVar5 <= (float)fVar6);
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnInjured
 * Address: 00740bf0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

CINSNextBot * CINSBotTacticalMonitor::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  CBaseEntity *pCVar1;
  code *pcVar2;
  char cVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  void *pvVar8;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CINSBotRetreatToCover *this_01;
  CBaseEntity *pCVar9;
  CBaseEntity *extraout_ECX;
  CINSRules *this_02;
  int unaff_EBX;
  float fVar10;
  float fVar11;
  float fVar12;
  int *in_stack_0000000c;
  int in_stack_00000010;
  undefined4 local_3c;
  CBaseEntity *local_38;
  undefined4 local_34;
  undefined1 local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x740bfb;
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c == (int *)0x0) goto LAB_00740fb0;
  uVar4 = *(uint *)(in_stack_00000010 + 0x28);
  local_38 = (CBaseEntity *)**(int **)(&DAT_00465bdd + unaff_EBX);
  if (uVar4 == 0xffffffff) goto LAB_00740fb0;
  if ((*(uint *)(local_38 + (uVar4 & 0xffff) * 0x18 + 8) == uVar4 >> 0x10) &&
     (*(int *)(local_38 + (uVar4 & 0xffff) * 0x18 + 4) != 0)) {
    cVar3 = CINSRules::IsSoloMode();
    if (cVar3 != '\0') {
      iVar5 = CBaseEntity::GetTeamNumber(this);
      iVar6 = CINSRules::GetHumanTeam(this_02);
      if (iVar5 == iVar6) {
        piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        uVar4 = *(uint *)(in_stack_00000010 + 0x28);
        iVar5 = 0;
        if ((uVar4 != 0xffffffff) &&
           (iVar6 = **(int **)(&DAT_00465bdd + unaff_EBX) + (uVar4 & 0xffff) * 0x18,
           *(uint *)(iVar6 + 8) == uVar4 >> 0x10)) {
          iVar5 = *(int *)(iVar6 + 4);
        }
        iVar6 = 0;
        if (*(int *)(iVar5 + 0x20) != 0) {
          iVar6 = *(int *)(iVar5 + 0x20) -
                  *(int *)(**(int **)(CFogController::CFogController + unaff_EBX + 5) + 0x5c) >> 4;
        }
        (**(code **)(*piVar7 + 0xec /* IVision::AddKnownEntity */))(piVar7,iVar6);
        local_38 = (CBaseEntity *)**(undefined4 **)(&DAT_00465bdd + unaff_EBX);
        uVar4 = *(uint *)(in_stack_00000010 + 0x28);
        goto LAB_00740c78;
      }
    }
    local_38 = (CBaseEntity *)**(undefined4 **)(&DAT_00465bdd + unaff_EBX);
    uVar4 = *(uint *)(in_stack_00000010 + 0x28);
  }
LAB_00740c78:
  if (((uVar4 != 0xffffffff) && (*(uint *)(local_38 + (uVar4 & 0xffff) * 0x18 + 8) == uVar4 >> 0x10)
      ) && (*(int *)(local_38 + (uVar4 & 0xffff) * 0x18 + 4) != 0)) {
    iVar5 = CBaseEntity::GetTeamNumber(local_38);
    iVar6 = CBaseEntity::GetTeamNumber(this_00);
    if (iVar5 != iVar6) {
      if ((*(byte *)(in_stack_00000010 + 0x3c) & 8) != 0) {
        uVar4 = *(uint *)(in_stack_00000010 + 0x28);
        if (((uVar4 != 0xffffffff) &&
            (iVar5 = **(int **)(&DAT_00465bdd + unaff_EBX) + (uVar4 & 0xffff) * 0x18,
            *(uint *)(iVar5 + 8) == uVar4 >> 0x10)) && (*(int *)(iVar5 + 4) != 0)) {
          piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          local_3c = 0;
          uVar4 = *(uint *)(in_stack_00000010 + 0x28);
          if ((uVar4 != 0xffffffff) &&
             (iVar5 = **(int **)(&DAT_00465bdd + unaff_EBX) + (uVar4 & 0xffff) * 0x18,
             *(uint *)(iVar5 + 8) == uVar4 >> 0x10)) {
            local_3c = *(undefined4 *)(iVar5 + 4);
          }
          (**(code **)(*piVar7 + 0xe8 /* IVision::AddKnownEntity */))(piVar7,local_3c);
        }
        pvVar8 = ::operator_new(100);
        CINSBotRetreatToCover::CINSBotRetreatToCover(this_01,SUB41(pvVar8,0),0.0);
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(int *)(param_1 + 8) = unaff_EBX + 0x241e31 /* "We're in fire, get out of here!" */;
        *(void **)(param_1 + 4) = pvVar8;
        *(undefined4 *)(param_1 + 0xc) = 2;
        return param_1;
      }
      piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      iVar5 = (**(code **)(*piVar7 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar7,0);
      if ((iVar5 != 0) ||
         (cVar3 = (**(code **)(*in_stack_0000000c + 0x8ac /* CINSNextBot::IsInCombat */))(in_stack_0000000c), cVar3 != '\0')) {
        uVar4 = *(uint *)(in_stack_00000010 + 0x28);
        pCVar1 = (CBaseEntity *)**(int **)(&DAT_00465bdd + unaff_EBX);
        iVar5 = 0;
        pCVar9 = pCVar1;
        if (uVar4 != 0xffffffff) {
          pCVar9 = (CBaseEntity *)(uVar4 >> 0x10);
          if (*(CBaseEntity **)(pCVar1 + (uVar4 & 0xffff) * 0x18 + 8) == pCVar9) {
            iVar5 = *(int *)(pCVar1 + (uVar4 & 0xffff) * 0x18 + 4);
          }
        }
        if ((*(byte *)(iVar5 + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(pCVar9);
          pCVar9 = extraout_ECX;
        }
        if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(pCVar9);
        }
        fVar12 = (float)in_stack_0000000c[0x82] - *(float *)(iVar5 + 0x208);
        fVar10 = (float)in_stack_0000000c[0x83] - *(float *)(iVar5 + 0x20c);
        fVar11 = (float)in_stack_0000000c[0x84] - *(float *)(iVar5 + 0x210);
        if (*(float *)(unaff_EBX + 0x20b091 /* "@T	J" */) <= fVar10 * fVar10 + fVar12 * fVar12 + fVar11 * fVar11)
        {
          piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          local_34 = 0;
          uVar4 = *(uint *)(in_stack_00000010 + 0x28);
          if ((uVar4 != 0xffffffff) &&
             (iVar5 = **(int **)(&DAT_00465bdd + unaff_EBX) + (uVar4 & 0xffff) * 0x18,
             *(uint *)(iVar5 + 8) == uVar4 >> 0x10)) {
            local_34 = *(undefined4 *)(iVar5 + 4);
          }
          cVar3 = (**(code **)(*piVar7 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar7,local_34,1,0);
          if (cVar3 == '\0') goto LAB_00740fb0;
        }
      }
      piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      local_34 = 0;
      uVar4 = *(uint *)(in_stack_00000010 + 0x28);
      if ((uVar4 != 0xffffffff) &&
         (iVar5 = **(int **)(&DAT_00465bdd + unaff_EBX) + (uVar4 & 0xffff) * 0x18,
         *(uint *)(iVar5 + 8) == uVar4 >> 0x10)) {
        local_34 = *(undefined4 *)(iVar5 + 4);
      }
      (**(code **)(*piVar7 + 0xe8 /* IVision::AddKnownEntity */))(piVar7,local_34);
      piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      pCVar1 = (CBaseEntity *)**(int **)(&DAT_00465bdd + unaff_EBX);
      pcVar2 = *(code **)(*piVar7 + 0xd4);
      uVar4 = *(uint *)(in_stack_00000010 + 0x28);
      iVar5 = 0;
      pCVar9 = pCVar1;
      if (uVar4 != 0xffffffff) {
        pCVar9 = (CBaseEntity *)(uVar4 >> 0x10);
        if (*(CBaseEntity **)(pCVar1 + (uVar4 & 0xffff) * 0x18 + 8) == pCVar9) {
          iVar5 = *(int *)(pCVar1 + (uVar4 & 0xffff) * 0x18 + 4);
        }
      }
      if ((*(byte *)(iVar5 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(pCVar9);
      }
      CINSNextBot::GetViewPosition(local_28);
      (*pcVar2)(piVar7,local_28,3,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x241e51 /* "Looking at attacker who just injured me" */);
    }
  }
LAB_00740fb0:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnSight
 * Address: 00740a40
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotTacticalMonitor::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  char cVar1;
  int iVar2;
  void *pvVar3;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CINSBotRetreatToCover *this_01;
  CBaseEntity *extraout_ECX;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  int in_stack_0000000c;
  int *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_00000010 + 0x158))();
  if (((cVar1 == '\0') && (iVar2 = __dynamic_cast(), iVar2 != 0)) &&
     (fVar4 = (float10)CBaseDetonator::GetDetonateDamage(),
     *(float *)(unaff_EBX + 0x1780b4 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar4 &&
     (float)fVar4 != *(float *)(unaff_EBX + 0x1780b4 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */))) {
    this_00 = this;
    if ((*(byte *)(iVar2 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
      this_00 = extraout_ECX;
    }
    if ((*(byte *)(in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
    }
    fVar7 = *(float *)(in_stack_0000000c + 0x208) - *(float *)(iVar2 + 0x208);
    fVar5 = *(float *)(in_stack_0000000c + 0x20c) - *(float *)(iVar2 + 0x20c);
    fVar6 = *(float *)(in_stack_0000000c + 0x210) - *(float *)(iVar2 + 0x210);
    fVar4 = (float10)CBaseDetonator::GetDetonateDamageRadius();
    if (SQRT(fVar5 * fVar5 + fVar7 * fVar7 + fVar6 * fVar6) < (float)fVar4) {
      pvVar3 = ::operator_new(100);
      CINSBotRetreatToCover::CINSBotRetreatToCover(this_01,SUB41(pvVar3,0),0.0);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar3;
      *(int *)(param_1 + 8) = unaff_EBX + 0x241f1d /* "Fleeing from nade" */;
      *(undefined4 *)(param_1 + 0xc) = 1;
      return param_1;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnLostSight
 * Address: 0073ff10
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnLostSight(CINSNextBot*, CBaseEntity*) */

CINSNextBot * CINSBotTacticalMonitor::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  int *piVar1;
  int iVar2;
  int *in_stack_0000000c;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  piVar1 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  piVar1 = (int *)(**(code **)(*piVar1 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar1,0);
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(*piVar1 + 0x10))(piVar1);
    if (iVar2 == in_stack_00000010) {
      CINSNextBot::AddInvestigation();
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnWeaponFired
 * Address: 00740730
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

CINSNextBot * __thiscall
CINSBotTacticalMonitor::OnWeaponFired
          (CINSBotTacticalMonitor *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CBaseCombatWeapon *param_3)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSRules *this_03;
  int unaff_EBX;
  CBaseEntity *in_stack_00000010;
  undefined1 local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x74073b;
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000010 != (CBaseEntity *)0x0) && (param_3 != (CBaseCombatWeapon *)0x0)) {
    cVar2 = CINSRules::IsSoloMode();
    if (cVar2 != '\0') {
      iVar4 = CBaseEntity::GetTeamNumber(this_00);
      iVar5 = CINSRules::GetHumanTeam(this_03);
      if (iVar4 == iVar5) {
        piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        iVar4 = 0;
        if (*(int *)(in_stack_00000010 + 0x20) != 0) {
          iVar4 = *(int *)(in_stack_00000010 + 0x20) -
                  *(int *)(**(int **)(unaff_EBX + 0x466165 /* &gpGlobals */) + 0x5c) >> 4;
        }
        (**(code **)(*piVar3 + 0xec /* IVision::AddKnownEntity */))(piVar3,iVar4);
      }
    }
    piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,1);
    iVar4 = CBaseEntity::GetTeamNumber(this_01);
    iVar5 = CBaseEntity::GetTeamNumber(in_stack_00000010);
    if (iVar4 == iVar5) {
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      *(undefined4 *)(param_1 + 0xc) = 1;
      return param_1;
    }
    if (piVar3 != (int *)0x0) {
      cVar2 = (**(code **)(*piVar3 + 0x38))(piVar3);
      if (cVar2 != '\0') {
        piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        (**(code **)(*piVar3 + 0xe8 /* IVision::AddKnownEntity */))(piVar3,in_stack_00000010);
        *(undefined4 *)param_1 = 0 /* Continue */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        *(undefined4 *)(param_1 + 0xc) = 1;
        return param_1;
      }
    }
    iVar4 = (**(code **)(*(int *)param_3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(param_3);
    if (iVar4 != 0) {
      iVar4 = (**(code **)(*(int *)in_stack_00000010 + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_00000010);
      if (iVar4 != 0) {
        piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(param_3);
        pcVar1 = *(code **)(*piVar3 + 0x84);
        uVar6 = (**(code **)(*(int *)in_stack_00000010 + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_00000010);
        cVar2 = (*pcVar1)(piVar3,uVar6);
        if (cVar2 != '\0') {
          piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
          (**(code **)(*piVar3 + 0xe8 /* IVision::AddKnownEntity */))(piVar3,in_stack_00000010);
        }
      }
    }
    cVar2 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3);
    if (cVar2 == '\0') {
      piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
      cVar2 = (**(code **)(*piVar3 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar3,in_stack_00000010,1,0);
      if (cVar2 != '\0') {
        piVar3 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
        pcVar1 = *(code **)(*piVar3 + 0xd4);
        if (((byte)in_stack_00000010[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_02);
        }
        CINSNextBot::GetViewPosition(local_28);
        (*pcVar1)(piVar3,local_28,3,0x3f400000 /* 0.75f */,0,unaff_EBX + 0x24221f /* "Looking at Weapon Fire" */);
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnCommandApproach
 * Address: 0073fd10
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotTacticalMonitor::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::CheckPosture
 * Address: 007416a0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::CheckPosture(CINSNextBot*, CKnownEntity const*) */

void __thiscall
CINSBotTacticalMonitor::CheckPosture
          (CINSBotTacticalMonitor *this,CINSNextBot *param_1,CKnownEntity *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int *piVar7;
  bool bVar8;
  bool bVar9;
  int iVar10;
  float *pfVar11;
  float *pfVar12;
  float fVar13;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  int unaff_EBX;
  float10 fVar14;
  int *in_stack_0000000c;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  
  __i686_get_pc_thunk_bx();
  iVar10 = (**(code **)(**(int **)(CFogController::Spawn + unaff_EBX + 1) + 0x40))
                     (*(int **)(CFogController::Spawn + unaff_EBX + 1));
  if (iVar10 != 0) {
    return;
  }
  pfVar11 = (float *)(**(code **)(*in_stack_0000000c + 0x14))(in_stack_0000000c);
  pfVar12 = (float *)(**(code **)(*(int *)param_2 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_2);
  fVar1 = *pfVar12;
  fVar2 = pfVar12[1];
  fVar3 = pfVar12[2];
  fVar4 = *pfVar11;
  fVar5 = pfVar11[1];
  fVar6 = pfVar11[2];
  piVar7 = (int *)(*(int **)(unaff_EBX + 0x464f81 /* &bot_silhouette_range_close */))[7];
  if (piVar7 == *(int **)(unaff_EBX + 0x464f81 /* &bot_silhouette_range_close */)) {
    fVar13 = (float)((uint)piVar7 ^ piVar7[0xb]);
  }
  else {
    fVar14 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7);
    fVar13 = (float)fVar14;
  }
  bVar8 = SQRT((fVar2 - fVar5) * (fVar2 - fVar5) + (fVar1 - fVar4) * (fVar1 - fVar4) +
               (fVar3 - fVar6) * (fVar3 - fVar6)) < fVar13;
  pfVar11 = (float *)(**(code **)(*in_stack_0000000c + 0x14))(in_stack_0000000c);
  pfVar12 = (float *)(**(code **)(*(int *)param_2 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_2);
  fVar1 = *pfVar12;
  fVar2 = pfVar12[1];
  fVar3 = *pfVar11;
  fVar4 = pfVar11[1];
  fVar5 = pfVar12[2];
  piVar7 = (int *)(*(int **)(unaff_EBX + 0x465049 /* &bot_silhouette_range_far */))[7];
  fVar6 = pfVar11[2];
  if (piVar7 == *(int **)(unaff_EBX + 0x465049 /* &bot_silhouette_range_far */)) {
    fVar13 = (float)((uint)piVar7 ^ piVar7[0xb]);
    this_00 = extraout_ECX;
  }
  else {
    fVar14 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7);
    fVar13 = (float)fVar14;
    this_00 = extraout_ECX_00;
  }
  iVar10 = *(int *)(param_1 + 0x94);
  if (iVar10 == 0) {
    uVar17 = 0;
    if (bVar8) {
      fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                  (this_00,(float)param_2,0x3f800000 /* 1.0f */);
      if (*(float *)(unaff_EBX + 0x1f6635 /* typeinfo name for NetworkVarEmbedded<CountdownTimer, CINSPlayerShared, CINSPlayerShared::GetOffset_m_StanceTransitionTimer>+0xa0 */) <= (float)fVar14 &&
          (float)fVar14 != *(float *)(unaff_EBX + 0x1f6635 /* typeinfo name for NetworkVarEmbedded<CountdownTimer, CINSPlayerShared, CINSPlayerShared::GetOffset_m_StanceTransitionTimer>+0xa0 */)) {
        RandomFloat(0x40a00000 /* 5.0f */,0x41200000 /* 10.0f */,uVar17);
        (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
        CINSBotBody::SetPosture();
        return;
      }
      RandomFloat(0x40a00000 /* 5.0f */,0x41000000 /* 8.0f */,uVar17);
      (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
      CINSBotBody::SetPosture();
      return;
    }
    fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                (this_00,(float)param_2,0x3f800000 /* 1.0f */);
    if (*(float *)(unaff_EBX + 0x1e30a1 /* typeinfo name for CBaseGameSystem+0x12 */) <= (float)fVar14 &&
        (float)fVar14 != *(float *)(unaff_EBX + 0x1e30a1 /* typeinfo name for CBaseGameSystem+0x12 */)) {
      RandomFloat(0x41000000 /* 8.0f */,0x41400000 /* 12.0f */,uVar17);
      (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
      goto LAB_007418a7;
    }
    RandomFloat(0x41000000 /* 8.0f */,0x41400000 /* 12.0f */,uVar17);
    (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
  }
  else {
    bVar9 = fVar13 < SQRT((fVar2 - fVar4) * (fVar2 - fVar4) + (fVar1 - fVar3) * (fVar1 - fVar3) +
                          (fVar5 - fVar6) * (fVar5 - fVar6));
    if (iVar10 == 1) {
      uVar17 = 0;
      if (bVar8) {
        fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                    (this_00,(float)param_2,0x3f800000 /* 1.0f */);
        if ((float)fVar14 < *(float *)(unaff_EBX + 0x1e23e1 /* typeinfo name for ISaveRestoreOps+0x67 */) ||
            (float)fVar14 == *(float *)(unaff_EBX + 0x1e23e1 /* typeinfo name for ISaveRestoreOps+0x67 */)) {
          return;
        }
        uVar16 = 0x40c00000 /* 6.0f */;
        uVar15 = 0x40400000 /* 3.0f */;
      }
      else {
        fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                    (this_00,(float)param_2,0x3f800000 /* 1.0f */);
        if (*(float *)(unaff_EBX + 0x1e30a5 /* typeinfo name for CBaseGameSystem+0x16 */) <= (float)fVar14 &&
            (float)fVar14 != *(float *)(unaff_EBX + 0x1e30a5 /* typeinfo name for CBaseGameSystem+0x16 */)) {
          RandomFloat(0x40400000 /* 3.0f */,0x40c00000 /* 6.0f */,uVar17);
          (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
LAB_007418a7:
          CINSBotBody::SetPosture();
          return;
        }
        if (bVar9) {
          uVar17 = 0;
          fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                      (this_01,(float)param_2,0x3f800000 /* 1.0f */);
          if (*(float *)(unaff_EBX + 0x1e7b09 /* typeinfo name for CTraceFilterIgnoreWeapons+0x29 */) <= (float)fVar14 &&
              (float)fVar14 != *(float *)(unaff_EBX + 0x1e7b09 /* typeinfo name for CTraceFilterIgnoreWeapons+0x29 */)) {
            RandomFloat(0x40400000 /* 3.0f */,0x40c00000 /* 6.0f */,uVar17);
            (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
            goto LAB_007418a7;
          }
        }
        uVar16 = 0x41000000 /* 8.0f */;
        uVar15 = 0x40800000 /* 4.0f */;
      }
      RandomFloat(uVar15,uVar16,uVar17);
      (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
    }
    else {
      if (iVar10 != 2) {
        return;
      }
      if (bVar8) {
        fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                    (this_00,(float)param_2,0x3f800000 /* 1.0f */);
        if ((float)fVar14 < *(float *)(unaff_EBX + 0x1e30ad /* typeinfo name for CBaseGameSystem+0x1e */) ||
            (float)fVar14 == *(float *)(unaff_EBX + 0x1e30ad /* typeinfo name for CBaseGameSystem+0x1e */)) {
          return;
        }
      }
      else if (bVar9) {
        uVar17 = 0;
        fVar14 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                    (this_00,(float)param_2,0x3f800000 /* 1.0f */);
        if (*(float *)(unaff_EBX + 0x1e30ad /* typeinfo name for CBaseGameSystem+0x1e */) <= (float)fVar14 &&
            (float)fVar14 != *(float *)(unaff_EBX + 0x1e30ad /* typeinfo name for CBaseGameSystem+0x1e */)) {
          RandomFloat(0x40400000 /* 3.0f */,0x40c00000 /* 6.0f */,uVar17);
          (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
          goto LAB_007418a7;
        }
      }
      RandomFloat(0x40400000 /* 3.0f */,0x40c00000 /* 6.0f */);
      (**(code **)(*(int *)param_2 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_2);
    }
  }
  CINSBotBody::SetPosture();
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnHeardFootsteps
 * Address: 007402a0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

CINSNextBot *
CINSBotTacticalMonitor::OnHeardFootsteps
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CINSRules *this_02;
  int unaff_EBX;
  int in_stack_00000010;
  undefined4 *in_stack_00000014;
  undefined1 local_28 [24];
  
  iVar3 = __i686_get_pc_thunk_bx();
  if ((iVar3 != 0) && (param_3 != (Vector *)0x0)) {
    iVar3 = CBaseEntity::GetTeamNumber(this);
    iVar4 = CBaseEntity::GetTeamNumber(this_00);
    if (iVar3 != iVar4) {
      cVar2 = CINSRules::IsSoloMode();
      if (cVar2 != '\0') {
        iVar3 = CBaseEntity::GetTeamNumber(this_01);
        iVar4 = CINSRules::GetHumanTeam(this_02);
        if (iVar3 == iVar4) {
          piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
          iVar3 = 0;
          if (*(int *)(in_stack_00000010 + 0x20) != 0) {
            iVar3 = *(int *)(in_stack_00000010 + 0x20) -
                    *(int *)(**(int **)(&DAT_004665ef + unaff_EBX) + 0x5c) >> 4;
          }
          (**(code **)(*piVar5 + 0xec /* IVision::AddKnownEntity */))(piVar5,iVar3);
        }
      }
      cVar2 = (**(code **)(*(int *)param_3 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(param_3);
      if (cVar2 == '\0') {
        piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        iVar3 = (**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
        if (iVar3 == 0) {
          piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
          cVar2 = (**(code **)(*piVar5 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar5,in_stack_00000010,1,0);
          if (cVar2 != '\0') {
            cVar2 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3);
            if (cVar2 == '\0') {
              piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
              pcVar1 = *(code **)(*piVar5 + 0xd4);
              CINSNextBot::GetViewPosition(local_28);
              (*pcVar1)(piVar5,local_28,2,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x242694 /* "Looking at footsteps" */);
              goto LAB_007402c7;
            }
          }
          CINSNextBot::AddInvestigation
                    (param_3,*in_stack_00000014,in_stack_00000014[1],in_stack_00000014[2],6);
        }
        else {
          piVar5 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))();
          (**(code **)(*piVar5 + 0xe8 /* IVision::AddKnownEntity */))(piVar5,in_stack_00000010);
        }
      }
    }
  }
LAB_007402c7:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::OnSeeSomethingSuspicious
 * Address: 00740060
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

CINSNextBot *
CINSBotTacticalMonitor::OnSeeSomethingSuspicious
          (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  CBaseEntity *this;
  CINSRules *this_00;
  int unaff_EBX;
  int in_stack_00000010;
  undefined4 *in_stack_00000014;
  undefined1 local_28 [24];
  
  iVar3 = __i686_get_pc_thunk_bx();
  if ((iVar3 != 0) && (param_3 != (Vector *)0x0)) {
    cVar2 = (**(code **)(*(int *)(param_3 + 0x2060) + 0xe8))(param_3 + 0x2060,in_stack_00000010);
    if (cVar2 != '\0') {
      cVar2 = CINSRules::IsSoloMode();
      if (cVar2 != '\0') {
        iVar3 = CBaseEntity::GetTeamNumber(this);
        iVar5 = CINSRules::GetHumanTeam(this_00);
        if (iVar3 == iVar5) {
          piVar4 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
          iVar3 = 0;
          if (*(int *)(in_stack_00000010 + 0x20) != 0) {
            iVar3 = *(int *)(in_stack_00000010 + 0x20) -
                    *(int *)(**(int **)(unaff_EBX + 0x46682f /* &gpGlobals */) + 0x5c) >> 4;
          }
          (**(code **)(*piVar4 + 0xec /* IVision::AddKnownEntity */))(piVar4,iVar3);
        }
      }
      cVar2 = (**(code **)(*(int *)param_3 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(param_3);
      if (cVar2 == '\0') {
        piVar4 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
        cVar2 = (**(code **)(*piVar4 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar4,in_stack_00000010,0,0);
        if (cVar2 == '\0') {
          CINSNextBot::AddInvestigation
                    (param_3,*in_stack_00000014,in_stack_00000014[1],in_stack_00000014[2],5);
        }
        else {
          piVar4 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
          iVar3 = (**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
          if (iVar3 == 0) {
            cVar2 = (**(code **)(*(int *)param_3 + 0x8ac /* CINSNextBot::IsInCombat */))(param_3);
            if (cVar2 == '\0') {
              piVar4 = (int *)(**(code **)(*(int *)param_3 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_3);
              pcVar1 = *(code **)(*piVar4 + 0xd4);
              CINSNextBot::GetViewPosition(local_28);
              (*pcVar1)(piVar4,local_28,2,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x242997 /* "Looking at footsteps in Tac Monitor" */);
            }
          }
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::ShouldWalk
 * Address: 0073fcc0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotTacticalMonitor::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotTacticalMonitor::ShouldWalk(CINSBotTacticalMonitor *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::ShouldWalk
 * Address: 0073fcd0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotTacticalMonitor::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::~CINSBotTacticalMonitor
 * Address: 00742cc0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotTacticalMonitor::~CINSBotTacticalMonitor() */

void __thiscall CINSBotTacticalMonitor::~CINSBotTacticalMonitor(CINSBotTacticalMonitor *this)

{
  ~CINSBotTacticalMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::~CINSBotTacticalMonitor
 * Address: 00742cd0
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::~CINSBotTacticalMonitor() */

void __thiscall CINSBotTacticalMonitor::~CINSBotTacticalMonitor(CINSBotTacticalMonitor *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4580b3 /* vtable for CINSBotTacticalMonitor+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x45824b /* vtable for CINSBotTacticalMonitor+0x1a0 */;
  Action<CINSNextBot>::~Action
            ((Action<CINSNextBot> *)(CFogController::InputStartFogTransition + extraout_ECX + 3));
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::~CINSBotTacticalMonitor
 * Address: 00742d70
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotTacticalMonitor::~CINSBotTacticalMonitor() */

void __thiscall CINSBotTacticalMonitor::~CINSBotTacticalMonitor(CINSBotTacticalMonitor *this)

{
  ~CINSBotTacticalMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotTacticalMonitor::~CINSBotTacticalMonitor
 * Address: 00742d80
 * ---------------------------------------- */

/* CINSBotTacticalMonitor::~CINSBotTacticalMonitor() */

void __thiscall CINSBotTacticalMonitor::~CINSBotTacticalMonitor(CINSBotTacticalMonitor *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x457ffa /* vtable for CINSBotTacticalMonitor+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x458192 /* vtable for CINSBotTacticalMonitor+0x1a0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



