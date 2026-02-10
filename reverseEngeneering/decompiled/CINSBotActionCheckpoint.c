/*
 * CINSBotActionCheckpoint -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionCheckpoint::OnStart
 * Address: 00736920
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall
CINSBotActionCheckpoint::OnStart(CINSBotActionCheckpoint *this,CINSNextBot *param_1,Action *param_2)

{
  Action AVar1;
  int in_stack_0000000c;
  
  AVar1 = *(Action *)(in_stack_0000000c + 0x228f);
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  param_2[0x38] = AVar1;
  *(undefined1 *)(in_stack_0000000c + 0x228f) = 0;
  *(undefined4 *)(param_2 + 0x3c) = 0xbf800000 /* -1.0f */;
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::Update
 * Address: 00736a50
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionCheckpoint::Update(CINSBotActionCheckpoint *this,CINSNextBot *param_1,float param_2)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  void *pvVar6;
  undefined4 uVar7;
  CNavArea *pCVar8;
  CINSNextBot *pCVar9;
  float fVar10;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_00;
  CINSRules *this_01;
  CINSNextBot *this_02;
  CINSBotEscort *this_03;
  CINSBotCombat *this_04;
  CINSNextBot *this_05;
  CINSNextBot *this_06;
  CBaseEntity *this_07;
  CBaseEntity *this_08;
  CINSBotInvestigate *this_09;
  CINSBotInvestigate *this_10;
  CINSBotInvestigate *this_11;
  CINSBotGuardDefensive *this_12;
  CINSNextBotManager *this_13;
  CINSBotInvestigate *this_14;
  CINSBotGuardCP *this_15;
  CINSBotCaptureCP *this_16;
  int unaff_EBX;
  float10 fVar11;
  float fVar12;
  float fVar13;
  int *in_stack_0000000c;
  undefined4 uVar14;
  int local_34;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x736a5b;
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  iVar4 = (**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
  this_00 = extraout_ECX;
  if (iVar4 != 0) {
    piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar4 = (**(code **)(*piVar3 + 0xd4 /* IIntention::ShouldAttack */))(piVar3,in_stack_0000000c + 0x818,iVar4);
    this_00 = extraout_ECX_00;
    if (iVar4 == 1) {
      pvVar6 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_04);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar6;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x249b62 /* "Attacking nearby threats" */ /* "Attacking nearby threats" */;
      return param_1;
    }
  }
  iVar4 = CBaseEntity::GetTeamNumber(this_00);
  iVar5 = CINSRules::GetBotTeam(this_01);
  if (iVar4 != iVar5) {
    pvVar6 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_03);
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(void **)(param_1 + 4) = pvVar6;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24b74b /* "Escorting nearest Human" */ /* "Escorting nearest Human" */;
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    return param_1;
  }
  cVar2 = CINSNextBot::IsInvestigating(this_02);
  if (cVar2 == '\0') {
    cVar2 = CINSNextBot::HasInvestigations(this_05);
    if (cVar2 != '\0') {
      CINSNextBot::GetCurrentInvestigationArea(this_06);
      pCVar8 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_10,pCVar8);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(CNavArea **)(param_1 + 4) = pCVar8;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24b6f3 /* "I have an investigation!" */ /* "I have an investigation!" */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
    iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x46faf1 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */) + 0x40))(*(int **)(unaff_EBX + 0x46faf1 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */));
    if (iVar4 != 0) {
      iVar4 = CBaseEntity::GetTeamNumber(this_07);
      if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_08);
      }
      piVar3 = (int *)UTIL_INSGetClosestPlayer
                                ((Vector *)(in_stack_0000000c + 0x82),(iVar4 == 2) + 2,(float *)0x0)
      ;
      if (((piVar3 != (int *)0x0) && (cVar2 = (**(code **)(*piVar3 + 0x158 /* CBasePlayer::IsPlayer */))(piVar3), cVar2 != '\0')
          ) && (iVar4 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3), iVar4 != 0)) {
        uVar7 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3);
        uVar14 = 7;
        CINSNextBot::AddInvestigation();
        (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3,uVar7,uVar14);
        pCVar8 = (CNavArea *)::operator_new(0x4900);
        CINSBotInvestigate::CINSBotInvestigate(this_09,pCVar8);
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(CNavArea **)(param_1 + 4) = pCVar8;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24b722 /* "Knifing a player" */ /* "Knifing a player" */;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        return param_1;
      }
    }
    pCVar9 = (CINSNextBot *)TheINSNextBots();
    fVar10 = (float)CINSNextBotManager::GetDesiredPushTypeObjective(pCVar9);
    iVar4 = **(int **)(unaff_EBX + 0x4702c1 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
    iVar5 = *(int *)(iVar4 + 0x770);
    iVar1 = *(int *)(iVar4 + 0x450 + iVar5 * 4);
    if (iVar1 == 2) {
      local_34 = *(int *)(iVar4 + 0x590 + iVar5 * 4);
    }
    else {
      local_34 = 0;
      if (iVar1 == 3) {
        local_34 = *(int *)(iVar4 + 0x550 + iVar5 * 4);
      }
    }
    pCVar9 = *(CINSNextBot **)(unaff_EBX + 0x46fe9d /* &g_pGameRules */ /* &g_pGameRules */);
    if (*(char *)(*(int *)pCVar9 + 0x3ac) != '\0') {
      uVar7 = CBaseEntity::GetTeamNumber((CBaseEntity *)pCVar9);
      iVar4 = TheINSNextBots();
      CINSNextBotManager::GenerateCPGrenadeTargets(this_13,iVar4,(int)fVar10);
      piVar3 = *(int **)(unaff_EBX + 0x46fe45 /* &gpGlobals */ /* &gpGlobals */);
      fVar12 = *(float *)((int)param_2 + 0x3c);
      if (fVar12 < 0.0) {
        fVar12 = *(float *)(*piVar3 + 0xc);
        *(float *)((int)param_2 + 0x3c) = fVar12;
      }
      fVar13 = *(float *)(unaff_EBX + 0x1820b9 /* 1.0f */ /* 1.0f */);
      fVar12 = ((*(float *)(unaff_EBX + 0x201281 /* -20.0f */ /* -20.0f */) + *(float *)(*piVar3 + 0xc)) - fVar12) *
               *(float *)(unaff_EBX + 0x241491 /* 0.025f */ /* 0.025f */);
      if (fVar13 <= fVar12) {
        fVar12 = fVar13;
      }
      fVar11 = (float10)RandomFloat(0,fVar13,uVar7);
      fVar13 = 0.0;
      if (0.0 <= fVar12) {
        fVar13 = fVar12;
      }
      if ((float)fVar11 < fVar13) {
        iVar4 = (int)fVar10 * 0xc + **(int **)(unaff_EBX + 0x4702c1 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
        local_28 = *(undefined4 *)(iVar4 + 0x5d0);
        local_24 = *(undefined4 *)(iVar4 + 0x5d4);
        local_20 = *(undefined4 *)(iVar4 + 0x5d8);
        piVar3 = (int *)UTIL_INSGetClosestPlayer((Vector *)&local_28,2,(float *)0x0);
        if ((piVar3 != (int *)0x0) && (iVar4 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3), iVar4 != 0))
        {
          uVar7 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3);
          uVar14 = 7;
          CINSNextBot::AddInvestigation();
          (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3,uVar7,uVar14);
          pCVar8 = (CNavArea *)::operator_new(0x4900);
          CINSBotInvestigate::CINSBotInvestigate(this_14,pCVar8);
          *(undefined4 *)param_1 = 2 /* SuspendFor */;
          *(CNavArea **)(param_1 + 4) = pCVar8;
          *(int *)(param_1 + 8) = unaff_EBX + 0x24b765 /* "Counter-attacking enemy directly" */ /* "Counter-attacking enemy directly" */;
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          return param_1;
        }
      }
      pvVar6 = ::operator_new(0x88);
      CINSBotCaptureCP::CINSBotCaptureCP(this_16,(int)pvVar6,SUB41(fVar10,0));
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar6;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24b789 /* "It's a counter-attack and we're not hunting, re-cap" */ /* "It's a counter-attack and we're not hunting, re-cap" */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
    *(undefined4 *)((int)param_2 + 0x3c) = 0xbf800000 /* -1.0f */;
    if (((0 < local_34) && ((uint)fVar10 < 0x10)) &&
       ((pCVar9 = (CINSNextBot *)
                  (**(int **)(&LAB_0046fc5d + unaff_EBX) + 0x830 + (int)fVar10 * 0x14),
        pCVar9 != (CINSNextBot *)0xfffffffc && (0 < *(int *)(pCVar9 + 0x10))))) {
      iVar4 = RandomInt(0,*(int *)(pCVar9 + 0x10) + -1);
      iVar4 = *(int *)(*(int *)(pCVar9 + 4) + iVar4 * 4);
      if (iVar4 != 0) {
        CINSNextBot::AddInvestigation(pCVar9,in_stack_0000000c,iVar4,0);
        pCVar8 = (CNavArea *)::operator_new(0x4900);
        CINSBotInvestigate::CINSBotInvestigate(this_11,pCVar8);
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(CNavArea **)(param_1 + 4) = pCVar8;
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24b7bd /* "Counter-attacking contested point" */ /* "Counter-attacking contested point" */;
        return param_1;
      }
    }
    if ((*(byte *)(in_stack_0000000c + 0x8a5) & 4) != 0) {
      pvVar6 = ::operator_new(0x48f4);
      CINSBotGuardDefensive::CINSBotGuardDefensive(this_12,(int)pvVar6);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar6;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24b733 /* "Defending." */ /* "Defending." */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
    uVar7 = 0;
    fVar11 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                (pCVar9,(float)in_stack_0000000c,0x40800000 /* 4.0f */);
    if ((float)fVar11 < *(float *)(unaff_EBX + 0x1edcfd /* 0.5f */ /* 0.5f */)) {
      RandomFloat(0x40a00000 /* 5.0f */,0x41700000 /* 15.0f */,uVar7);
      pvVar6 = ::operator_new(0x48fc);
      CINSBotGuardCP::CINSBotGuardCP(this_15,(int)pvVar6,fVar10);
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar6;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24b73e /* "Guarding CP." */ /* "Guarding CP." */;
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      return param_1;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::OnEnd
 * Address: 00736970
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionCheckpoint::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::GetName
 * Address: 00737300
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::GetName() const */

int CINSBotActionCheckpoint::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6e06 /* "Checkpoint" */ /* "Checkpoint" */;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::ShouldHurry
 * Address: 007369b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionCheckpoint::ShouldHurry(INextBot const*) const */

void __thiscall
CINSBotActionCheckpoint::ShouldHurry(CINSBotActionCheckpoint *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::ShouldHurry
 * Address: 007369c0
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::ShouldHurry(INextBot const*) const */

char __thiscall
CINSBotActionCheckpoint::ShouldHurry(CINSBotActionCheckpoint *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  char cVar4;
  float10 fVar5;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  cVar4 = '\x02';
  if (in_stack_00000008 != (int *)0x0) {
    iVar2 = (**(code **)(*in_stack_00000008 + 200))();
    if (iVar2 != 0) {
      iVar2 = (**(code **)(*in_stack_00000008 + 0x114))();
      if (iVar2 != 0) {
        pcVar1 = *(code **)(*in_stack_00000008 + 0x134);
        piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x114))();
        (**(code **)(*piVar3 + 0x18))(piVar3);
        fVar5 = (float10)(*pcVar1)();
        cVar4 = ((float)fVar5 < *(float *)(unaff_EBX + 0x24b880 /* 1400.0f */ /* 1400.0f */) ||
                (float)fVar5 == *(float *)(unaff_EBX + 0x24b880 /* 1400.0f */ /* 1400.0f */)) + '\x01';
      }
    }
  }
  return cVar4;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::ShouldAttack
 * Address: 00736990
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionCheckpoint::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionCheckpoint::ShouldAttack
          (CINSBotActionCheckpoint *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::ShouldAttack
 * Address: 007369a0
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionCheckpoint::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::~CINSBotActionCheckpoint
 * Address: 00737320
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionCheckpoint::~CINSBotActionCheckpoint() */

void __thiscall CINSBotActionCheckpoint::~CINSBotActionCheckpoint(CINSBotActionCheckpoint *this)

{
  ~CINSBotActionCheckpoint(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::~CINSBotActionCheckpoint
 * Address: 00737330
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::~CINSBotActionCheckpoint() */

void __thiscall CINSBotActionCheckpoint::~CINSBotActionCheckpoint(CINSBotActionCheckpoint *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x461d93 /* vtable for CINSBotActionCheckpoint+0x8 */ /* vtable for CINSBotActionCheckpoint+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x461f2b /* vtable for CINSBotActionCheckpoint+0x1a0 */ /* vtable for CINSBotActionCheckpoint+0x1a0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46fe43 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::~CINSBotActionCheckpoint
 * Address: 00737360
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionCheckpoint::~CINSBotActionCheckpoint() */

void __thiscall CINSBotActionCheckpoint::~CINSBotActionCheckpoint(CINSBotActionCheckpoint *this)

{
  ~CINSBotActionCheckpoint(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionCheckpoint::~CINSBotActionCheckpoint
 * Address: 00737370
 * ---------------------------------------- */

/* CINSBotActionCheckpoint::~CINSBotActionCheckpoint() */

void __thiscall CINSBotActionCheckpoint::~CINSBotActionCheckpoint(CINSBotActionCheckpoint *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x461d4a /* vtable for CINSBotActionCheckpoint+0x8 */ /* vtable for CINSBotActionCheckpoint+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x461ee2 /* vtable for CINSBotActionCheckpoint+0x1a0 */ /* vtable for CINSBotActionCheckpoint+0x1a0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



