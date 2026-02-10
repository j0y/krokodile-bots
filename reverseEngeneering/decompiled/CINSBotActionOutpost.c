/*
 * CINSBotActionOutpost -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 14
 */

/* ----------------------------------------
 * CINSBotActionOutpost::OnStart
 * Address: 0073a3c0
 * ---------------------------------------- */

/* CINSBotActionOutpost::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotActionOutpost::OnStart(CINSBotActionOutpost *this,CINSNextBot *param_1,Action *param_2)

{
  undefined4 *puVar1;
  float fVar2;
  int *piVar3;
  CINSNextBot *this_00;
  char cVar4;
  int iVar5;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSWeapon *extraout_ECX;
  int unaff_EBX;
  float10 fVar6;
  int *in_stack_0000000c;
  undefined4 uVar7;
  undefined4 uVar8;
  
  __i686_get_pc_thunk_bx();
  fVar6 = (float10)CountdownTimer::Now();
  fVar2 = *(float *)(param_2 + 0x40);
  if (*(float *)(param_2 + 0x44) != (float)fVar6 + fVar2) {
    (**(code **)(*(int *)(param_2 + 0x3c) + 4))(param_2 + 0x3c,param_2 + 0x44);
    *(float *)(param_2 + 0x44) = (float)fVar6 + fVar2;
  }
  param_2[0x38] = *(Action *)((int)in_stack_0000000c + 0x228f);
  piVar3 = *(int **)(unaff_EBX + 0x46c951 /* &g_pObjectiveResource */);
  *(undefined1 *)((int)in_stack_0000000c + 0x228f) = 0;
  puVar1 = (undefined4 *)(*piVar3 + 0x5d0 + *(int *)(*piVar3 + 0x770) * 0xc);
  this_00 = (CINSNextBot *)*puVar1;
  uVar7 = puVar1[2];
  *(undefined4 *)(param_2 + 0x50) = puVar1[1];
  *(CINSNextBot **)(param_2 + 0x4c) = this_00;
  *(undefined4 *)(param_2 + 0x54) = uVar7;
  if (*(char *)(**(int **)(unaff_EBX + 0x46c52d /* &g_pGameRules */) + 0x40c) != '\0') {
    uVar8 = 0;
    uVar7 = 0x3f800000 /* 1.0f */;
    fVar6 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_00,(float)in_stack_0000000c,0x3f800000 /* 1.0f */);
    if (*(float *)(unaff_EBX + 0x1eede9 /* typeinfo name for CTraceFilterIgnoreWeapons+0x29 */) <= (float)fVar6 &&
        (float)fVar6 != *(float *)(unaff_EBX + 0x1eede9 /* typeinfo name for CTraceFilterIgnoreWeapons+0x29 */)) {
      cVar4 = (**(code **)(*in_stack_0000000c + 0x158))(in_stack_0000000c,uVar7,uVar8);
      if (cVar4 != '\0') {
        iVar5 = CINSPlayer::GetActiveINSWeapon();
        if (iVar5 != 0) {
          cVar4 = CINSWeapon::HasLasersights(this_01);
          this_03 = this_02;
          if (cVar4 != '\0') {
            cVar4 = CINSWeapon::IsLasersightsOn(this_02);
            this_03 = this_06;
            if (cVar4 == '\0') {
              CINSWeapon::ToggleLasersights(this_06);
              this_03 = extraout_ECX;
            }
          }
          cVar4 = CINSWeapon::HasFlashlight(this_03);
          if (cVar4 != '\0') {
            cVar4 = CINSWeapon::IsFlashlightOn(this_04);
            if (cVar4 == '\0') {
              CINSWeapon::ToggleFlashlight(this_05);
            }
          }
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
 * CINSBotActionOutpost::Update
 * Address: 0073a8e0
 * ---------------------------------------- */

/* CINSBotActionOutpost::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionOutpost::Update(CINSBotActionOutpost *this,CINSNextBot *param_1,float param_2)

{
  float *pfVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  CFmtStrN<256,false> *this_00;
  char cVar8;
  undefined1 uVar9;
  void *pvVar10;
  int *piVar11;
  int iVar12;
  uint uVar13;
  float *pfVar14;
  CNavArea *pCVar15;
  CINSBotEscort *this_01;
  CINSBotDestroyCache *this_02;
  CINSBotCombat *this_03;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_04;
  CINSNextBot *this_05;
  CINSNextBot *extraout_ECX_00;
  CINSBotInvestigate *this_06;
  int unaff_EBX;
  float10 fVar16;
  CINSNextBot *in_stack_0000000c;
  char local_128 [5];
  undefined1 local_123 [271];
  undefined4 uStack_14;
  
  uStack_14 = 0x73a8eb;
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x46c00d /* &g_pGameRules */) == 0) {
LAB_0073aa20:
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  cVar8 = CINSBotEscort::HasEscortTarget(in_stack_0000000c);
  if (cVar8 == '\0') {
    piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    iVar12 = (**(code **)(*piVar11 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar11,0);
    if (iVar12 != 0) {
      piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar12 = (**(code **)(*piVar11 + 0xd4 /* IIntention::ShouldAttack */))(piVar11,in_stack_0000000c + 0x2060,iVar12);
      if (iVar12 == 1) {
        pvVar10 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_03);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar10;
        *(int *)(param_1 + 8) = unaff_EBX + 0x245cd2 /* "Attacking nearby threats" */;
        *(undefined4 *)param_1 = 2;
        return param_1;
      }
    }
    piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    uVar9 = (**(code **)(*piVar11 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar11,(int)param_2 + 0x4c,0);
    *(undefined1 *)((int)param_2 + 0x58) = uVar9;
    cVar8 = CINSNextBot::IsInvestigating(in_stack_0000000c);
    if (cVar8 != '\0') goto LAB_0073aa20;
    this_00 = *(CFmtStrN<256,false> **)(**(int **)(unaff_EBX + 0x46c431 /* &g_pObjectiveResource */) + 0x770);
    cVar8 = CINSBotDestroyCache::CanIDestroyCache(in_stack_0000000c);
    if (cVar8 != '\0') {
      iVar12 = *(int *)(*(int *)(&DAT_0046c721 + unaff_EBX) + (int)this_00 * 4);
      piVar11 = *(int **)(unaff_EBX + 0x5b2811 /* ins_outpost_bot_max_cache_destroyers+0x1c */);
      if (piVar11 == (int *)(unaff_EBX + 0x5b27f5 /* ins_outpost_bot_max_cache_destroyers */U)) {
        uVar13 = (uint)piVar11 ^ *(uint *)(unaff_EBX + 0x5b2825 /* ins_outpost_bot_max_cache_destroyers+0x30 */);
      }
      else {
        uVar13 = (**(code **)(*piVar11 + 0x40))(piVar11);
      }
      if (iVar12 < (int)uVar13) {
        CFmtStrN<256,false>::CFmtStrN(this_00,local_128,unaff_EBX + 0x247a61 /* "Destroying %i" */,this_00);
        pvVar10 = ::operator_new(0x4900);
        CINSBotDestroyCache::CINSBotDestroyCache(this_02,(int)pvVar10);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar10;
        *(undefined4 *)param_1 = 2;
        *(undefined1 **)(param_1 + 8) = local_123;
        return param_1;
      }
    }
    pfVar14 = (float *)(**(code **)(*(int *)in_stack_0000000c + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_0000000c);
    pfVar1 = (float *)(**(int **)(unaff_EBX + 0x46c431 /* &g_pObjectiveResource */) + 0x5d0 + (int)this_00 * 0xc);
    fVar2 = *pfVar1;
    fVar3 = pfVar1[1];
    fVar4 = *pfVar14;
    fVar5 = pfVar14[1];
    fVar6 = pfVar1[2];
    fVar7 = pfVar14[2];
    fVar16 = (float10)CINSNextBot::MaxPathLength();
    this_04 = extraout_ECX;
    if ((float)fVar16 <
        SQRT((fVar3 - fVar5) * (fVar3 - fVar5) + (fVar2 - fVar4) * (fVar2 - fVar4) +
             (fVar6 - fVar7) * (fVar6 - fVar7))) {
      Warning(unaff_EBX + 0x247be9 /* "Bot is out of pathing range to point - how did this happen?" */);
      this_04 = extraout_ECX_00;
    }
    CINSNextBot::ResetIdleStatus(this_04);
    cVar8 = CINSNextBot::HasInvestigations(in_stack_0000000c);
    if ((cVar8 != '\0') && (iVar12 = CINSNextBot::GetCurrentInvestigationArea(this_05), iVar12 != 0)
       ) {
      CINSNextBot::GetCurrentInvestigationArea(in_stack_0000000c);
      pCVar15 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_06,pCVar15);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(CNavArea **)(param_1 + 4) = pCVar15;
      *(undefined4 *)param_1 = 2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x247863 /* "I have an investigation!" */;
      return param_1;
    }
    pvVar10 = ::operator_new(0x88);
    CINSBotCaptureCP::CINSBotCaptureCP((CINSBotCaptureCP *)this_00,(int)pvVar10,SUB41(this_00,0));
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar10;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x247bd2 /* "Capturing our target" */;
  }
  else {
    pvVar10 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_01);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar10;
    *(undefined4 *)param_1 = 2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24796d /* "Escorting " */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionOutpost::OnEnd
 * Address: 0073a380
 * ---------------------------------------- */

/* CINSBotActionOutpost::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionOutpost::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x228f) = param_1[0x38];
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::GetName
 * Address: 0073ad90
 * ---------------------------------------- */

/* CINSBotActionOutpost::GetName() const */

int CINSBotActionOutpost::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6adf /* "Outpost" */;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldHurry
 * Address: 0073a720
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOutpost::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotActionOutpost::ShouldHurry(CINSBotActionOutpost *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldHurry
 * Address: 0073a730
 * ---------------------------------------- */

/* CINSBotActionOutpost::ShouldHurry(INextBot const*) const */

char __thiscall CINSBotActionOutpost::ShouldHurry(CINSBotActionOutpost *this,INextBot *param_1)

{
  int *piVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  int unaff_EBX;
  char cVar5;
  float10 fVar6;
  float fVar7;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  cVar5 = '\x02';
  if (in_stack_00000008 != (int *)0x0) {
    iVar2 = (**(code **)(*in_stack_00000008 + 200))();
    if (iVar2 != 0) {
      piVar1 = *(int **)(unaff_EBX + 0x5b2ad8 /* ins_outpost_bot_hurry_final_distance+0x1c */);
      if (piVar1 == (int *)(unaff_EBX + 0x5b2abc /* ins_outpost_bot_hurry_final_distance */U)) {
        fVar3 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x5b2ae8 /* ins_outpost_bot_hurry_final_distance+0x2c */));
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
        fVar3 = (float)fVar6;
      }
      piVar1 = *(int **)(unaff_EBX + 0x5b2b38 /* ins_outpost_bot_hurry_initial_distance+0x1c */);
      if (piVar1 == (int *)(unaff_EBX + 0x5b2b1c /* ins_outpost_bot_hurry_initial_distance */U)) {
        fVar4 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x5b2b48 /* ins_outpost_bot_hurry_initial_distance+0x2c */));
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
        fVar4 = (float)fVar6;
      }
      fVar7 = ((float)*(int *)(**(int **)(unaff_EBX + 0x46c1b4 /* &g_pGameRules */) + 1000) +
              *(float *)(unaff_EBX + 0x17e3cc /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x30 */)) * *(float *)(unaff_EBX + 0x246abc /* typeinfo name for INextBotReply+0x12 */);
      if (*(float *)(unaff_EBX + 0x17e3d0 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar7) {
        fVar7 = *(float *)(unaff_EBX + 0x17e3d0 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
      }
      if (fVar7 <= *(float *)(unaff_EBX + 0x17e3c4 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        fVar7 = *(float *)(unaff_EBX + 0x17e3c4 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
      }
      fVar6 = (float10)(**(code **)(*in_stack_00000008 + 0x134))();
      cVar5 = ((float)fVar6 <= (fVar3 - fVar4) * fVar7 + fVar4) + '\x01';
    }
  }
  return cVar5;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldAttack
 * Address: 0073a3a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOutpost::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionOutpost::ShouldAttack
          (CINSBotActionOutpost *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldAttack
 * Address: 0073a3b0
 * ---------------------------------------- */

/* CINSBotActionOutpost::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionOutpost::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldWalk
 * Address: 0073a5e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOutpost::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotActionOutpost::ShouldWalk(CINSBotActionOutpost *this,INextBot *param_1)

{
  ShouldWalk(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::ShouldWalk
 * Address: 0073a5f0
 * ---------------------------------------- */

/* CINSBotActionOutpost::ShouldWalk(INextBot const*) const */

char __thiscall CINSBotActionOutpost::ShouldWalk(CINSBotActionOutpost *this,INextBot *param_1)

{
  int *piVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  int unaff_EBX;
  char cVar5;
  float10 fVar6;
  float fVar7;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  cVar5 = '\x02';
  if (in_stack_00000008 != (int *)0x0) {
    iVar2 = (**(code **)(*in_stack_00000008 + 200))();
    if (iVar2 != 0) {
      piVar1 = *(int **)(unaff_EBX + 0x5b2b58 /* ins_outpost_bot_walk_final_distance+0x1c */);
      if (piVar1 == (int *)(unaff_EBX + 0x5b2b3c /* ins_outpost_bot_walk_final_distance */U)) {
        fVar3 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x5b2b68 /* ins_outpost_bot_walk_final_distance+0x2c */));
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
        fVar3 = (float)fVar6;
      }
      piVar1 = *(int **)(unaff_EBX + 0x5b2bb8 /* ins_outpost_bot_walk_initial_distance+0x1c */);
      if (piVar1 == (int *)(unaff_EBX + 0x5b2b9c /* ins_outpost_bot_walk_initial_distance */U)) {
        fVar4 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x5b2bc8 /* ins_outpost_bot_walk_initial_distance+0x2c */));
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
        fVar4 = (float)fVar6;
      }
      fVar7 = ((float)*(int *)(**(int **)(&DAT_0046c2f4 + unaff_EBX) + 1000) +
              *(float *)(unaff_EBX + 0x17e50c /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x30 */)) * *(float *)(&LAB_00246bfc + unaff_EBX);
      if (*(float *)(unaff_EBX + 0x17e510 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar7) {
        fVar7 = *(float *)(unaff_EBX + 0x17e510 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
      }
      if (fVar7 <= *(float *)(unaff_EBX + 0x17e504 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        fVar7 = *(float *)(unaff_EBX + 0x17e504 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
      }
      fVar6 = (float10)(**(code **)(*in_stack_00000008 + 0x134))();
      cVar5 = ((fVar3 - fVar4) * fVar7 + fVar4 <= (float)fVar6) + '\x01';
    }
  }
  return cVar5;
}



/* ----------------------------------------
 * CINSBotActionOutpost::~CINSBotActionOutpost
 * Address: 0073adb0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOutpost::~CINSBotActionOutpost() */

void __thiscall CINSBotActionOutpost::~CINSBotActionOutpost(CINSBotActionOutpost *this)

{
  ~CINSBotActionOutpost(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::~CINSBotActionOutpost
 * Address: 0073adc0
 * ---------------------------------------- */

/* CINSBotActionOutpost::~CINSBotActionOutpost() */

void __thiscall CINSBotActionOutpost::~CINSBotActionOutpost(CINSBotActionOutpost *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45f063 /* vtable for CINSBotActionOutpost+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_0045f1ff + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46c3b3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::~CINSBotActionOutpost
 * Address: 0073adf0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionOutpost::~CINSBotActionOutpost() */

void __thiscall CINSBotActionOutpost::~CINSBotActionOutpost(CINSBotActionOutpost *this)

{
  ~CINSBotActionOutpost(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionOutpost::~CINSBotActionOutpost
 * Address: 0073ae00
 * ---------------------------------------- */

/* CINSBotActionOutpost::~CINSBotActionOutpost() */

void __thiscall CINSBotActionOutpost::~CINSBotActionOutpost(CINSBotActionOutpost *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45f01a /* vtable for CINSBotActionOutpost+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45f1b6 /* vtable for CINSBotActionOutpost+0x1a4 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



