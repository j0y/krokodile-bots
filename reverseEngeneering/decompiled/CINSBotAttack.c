/*
 * CINSBotAttack -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 20
 */

/* ----------------------------------------
 * CINSBotAttack::CINSBotAttack
 * Address: 007056a0
 * ---------------------------------------- */

/* CINSBotAttack::CINSBotAttack() */

void __thiscall CINSBotAttack::CINSBotAttack(CINSBotAttack *this)

{
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  in_stack_00000004[10] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48f35a /* vtable for CINSBotAttack+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x48f4fa /* vtable for CINSBotAttack+0x1a8 */;
  in_stack_00000004[0xe] = unaff_EBX + 0x422b0a /* vtable for CountdownTimer+0x8 */;
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
  in_stack_00000004[0xf] = 0;
  CountdownTimer::NetworkStateChanged(in_stack_00000004 + 0xe);
  in_stack_00000004[0x10] = -0x40800000;
  (**(code **)(in_stack_00000004[0xe] + 4))(in_stack_00000004 + 0xe,in_stack_00000004 + 0x10);
  in_stack_00000004[0x12] = -1;
  return;
}



/* ----------------------------------------
 * CINSBotAttack::OnStart
 * Address: 00704de0
 * ---------------------------------------- */

/* CINSBotAttack::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttack::OnStart(CINSBotAttack *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int *piVar5;
  CINSNextBot *this_00;
  int unaff_EBX;
  CKnownEntity *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x4a1b0a /* &g_pGameRules */) == 0) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27b08e /* "INSRules failed to initialize." */;
    return param_1;
  }
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar2 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), iVar2 == 0)) {
    piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
    if ((piVar3 == (int *)0x0) || (iVar2 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar2 == 0)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x27af9a /* " No Active Combat Target" */;
      return param_1;
    }
  }
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (piVar3 = (int *)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), piVar3 == (int *)0x0
     )) {
    piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
    if ((piVar3 == (int *)0x0) ||
       (piVar3 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3), piVar3 == (int *)0x0))
    goto LAB_00704f14;
  }
  cVar1 = (**(code **)(*piVar3 + 0x158))(piVar3);
  if (cVar1 != '\0') {
    puVar4 = (undefined4 *)(**(code **)(*piVar3 + 0xc))(piVar3);
    *(undefined4 *)(param_2 + 0x48) = *puVar4;
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar3 = (int *)(**(code **)(*piVar5 + 0xe4 /* IVision::GetKnown */))(piVar5,piVar3);
    if (((piVar3 != (int *)0x0) && (iVar2 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar2 != 0)) &&
       (cVar1 = (**(code **)(*piVar3 + 0x54))(piVar3), cVar1 == '\0')) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar2 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,in_stack_0000000c + 0x2060,piVar3);
      if (iVar2 != 0) {
        iVar2 = CINSPlayer::GetActiveINSWeapon();
        if (iVar2 != 0) {
          CINSNextBot::ResetIdleStatus(this_00);
          *(undefined4 *)param_1 = 0;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined4 *)(param_1 + 8) = 0;
          return param_1;
        }
        CINSNextBot::ChooseBestWeapon(this_00,in_stack_0000000c);
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x27b0d2 /* "Unable to determine active weapon." */;
        return param_1;
      }
    }
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27b0ae /* "Unable to determine initial threat." */;
    return param_1;
  }
LAB_00704f14:
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x27afb3 /* "Invalid Threat" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttack::InitialContainedAction
 * Address: 007049c0
 * ---------------------------------------- */

/* CINSBotAttack::InitialContainedAction(CINSNextBot*) */

void * __thiscall CINSBotAttack::InitialContainedAction(CINSBotAttack *this,CINSNextBot *param_1)

{
  int *piVar1;
  int iVar2;
  void *pvVar3;
  uint uVar4;
  CINSNextBot *this_00;
  CINSBotAttackPistol *this_01;
  CINSBotAttackMelee *this_02;
  CINSBotAttackCQC *this_03;
  int unaff_EBX;
  CKnownEntity *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (CKnownEntity *)0x0) {
    pvVar3 = (void *)0x0;
  }
  else {
    piVar1 = (int *)CINSPlayer::GetActiveINSWeapon();
    if (piVar1 == (int *)0x0) {
      pvVar3 = (void *)0x0;
      CINSNextBot::ChooseBestWeapon(this_00,in_stack_00000008);
    }
    else {
      iVar2 = (**(code **)(**(int **)(unaff_EBX + 0x4a1b78 /* &ins_bot_knives_only */) + 0x40))
                        (*(int **)(unaff_EBX + 0x4a1b78 /* &ins_bot_knives_only */));
      if (iVar2 != 0) {
        pvVar3 = ::operator_new(0x48c0);
        CINSBotAttackMelee::CINSBotAttackMelee(this_02);
        return pvVar3;
      }
      iVar2 = (**(code **)(**(int **)(unaff_EBX + 0x4a22d8 /* &ins_bot_pistols_only */) + 0x40))
                        (*(int **)(unaff_EBX + 0x4a22d8 /* &ins_bot_pistols_only */));
      if (iVar2 == 0) {
        uVar4 = (**(code **)(*piVar1 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar1);
        if (uVar4 < 0xf) {
                    /* WARNING: Could not recover jumptable at 0x00704a99. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          pvVar3 = (void *)(*(code *)(*(int *)(unaff_EBX + 0x27b448 /* typeinfo name for Action<CINSNextBot>+0xbb */ + uVar4 * 4) +
                                     unaff_EBX + 0x4a27a4 /* &_DYNAMIC */))();
          return pvVar3;
        }
        pvVar3 = ::operator_new(0x50);
        CINSBotAttackCQC::CINSBotAttackCQC(this_03);
      }
      else {
        pvVar3 = ::operator_new(0x50);
        CINSBotAttackPistol::CINSBotAttackPistol(this_01);
      }
    }
  }
  return pvVar3;
}



/* ----------------------------------------
 * CINSBotAttack::Update
 * Address: 00705050
 * ---------------------------------------- */

/* CINSBotAttack::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttack::Update(CINSBotAttack *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  int iVar8;
  uint uVar9;
  CINSNextBot *this_00;
  CINSPlayer *extraout_ECX;
  CINSPlayer *this_01;
  CINSPlayer *extraout_ECX_00;
  CINSRules *this_02;
  CountdownTimer *this_03;
  int unaff_EBX;
  float10 fVar10;
  CINSNextBot *in_stack_0000000c;
  undefined4 uVar11;
  undefined4 uVar12;
  int local_2c;
  
  __i686_get_pc_thunk_bx();
  fVar10 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar10 &&
      (float)fVar10 != *(float *)((int)param_2 + 0x40)) {
    cVar2 = CINSNextBot::IsIdle(in_stack_0000000c);
    if ((cVar2 != '\0') &&
       (fVar10 = (float10)CINSNextBot::GetIdleDuration(this_00),
       *(float *)(unaff_EBX + 0x21f70e /* typeinfo name for CBaseGameSystem+0x32 */) <= (float)fVar10 &&
       (float)fVar10 != *(float *)(unaff_EBX + 0x21f70e /* typeinfo name for CBaseGameSystem+0x32 */))) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x27ad52 /* "Idle in attack" */;
      return param_1;
    }
    piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar4 = (**(code **)(*piVar3 + 0xd0 /* IIntention::ShouldRetreat */))(piVar3,in_stack_0000000c + 0x2060);
    if (iVar4 == 1) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x27ad61 /* "Retreating to cover" */;
      return param_1;
    }
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (piVar3 = (int *)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
       piVar3 == (int *)0x0)) {
      piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
      if ((piVar3 != (int *)0x0) &&
         (piVar3 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3), piVar3 != (int *)0x0))
      goto LAB_00705121;
    }
    else {
LAB_00705121:
      cVar2 = (**(code **)(*piVar3 + 0x158))(piVar3);
      if ((cVar2 != '\0') && (cVar2 = (**(code **)(*piVar3 + 0x118))(piVar3), cVar2 != '\0')) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        piVar5 = (int *)(**(code **)(*piVar5 + 0xe4 /* IVision::GetKnown */))(piVar5,piVar3);
        if (piVar5 == (int *)0x0) {
          piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          iVar4 = 0;
          if (piVar3[8] != 0) {
            iVar4 = piVar3[8] - *(int *)(**(int **)(unaff_EBX + 0x4a1842 /* &gpGlobals */) + 0x5c) >> 4;
          }
          (**(code **)(*piVar5 + 0xec /* IVision::AddKnownEntity */))(piVar5,iVar4);
          *(undefined4 *)param_1 = 0;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined4 *)(param_1 + 8) = 0;
          return param_1;
        }
        cVar2 = (**(code **)(*piVar5 + 0x38 /* INextBotEventResponder::OnAnimationEvent */))(piVar5);
        if ((cVar2 == '\0') &&
           (fVar10 = (float10)(**(code **)(*piVar5 + 0x48 /* INextBotEventResponder::OnOtherKilled */))(piVar5),
           *(float *)(unaff_EBX + 0x21f6fa /* typeinfo name for CBaseGameSystem+0x1e */) <= (float)fVar10 &&
           (float)fVar10 != *(float *)(unaff_EBX + 0x21f6fa /* typeinfo name for CBaseGameSystem+0x1e */))) {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x27ad75 /* "Lost sight of my threat" */;
          return param_1;
        }
        iVar4 = (**(code **)(*piVar5 + 0x10 /* INextBotEventResponder::OnLeaveGround */))(piVar5);
        uVar9 = *(uint *)((int)param_2 + 0x48);
        local_2c = 0;
        if ((uVar9 != 0xffffffff) &&
           (iVar8 = **(int **)(unaff_EBX + 0x4a177a /* &g_pEntityList */) + (uVar9 & 0xffff) * 0x18,
           *(uint *)(iVar8 + 8) == uVar9 >> 0x10)) {
          local_2c = *(int *)(iVar8 + 4);
        }
        if (iVar4 != local_2c) {
          piVar3 = (int *)(**(code **)(*piVar5 + 0x10 /* INextBotEventResponder::OnLeaveGround */))(piVar5);
          if (piVar3 == (int *)0x0) {
            *(undefined4 *)((int)param_2 + 0x48) = 0xffffffff;
          }
          else {
            puVar6 = (undefined4 *)(**(code **)(*piVar3 + 0xc))(piVar3);
            *(undefined4 *)((int)param_2 + 0x48) = *puVar6;
          }
          goto LAB_0070508c;
        }
        piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
        iVar4 = (**(code **)(*piVar3 + 0xd4 /* IIntention::ShouldAttack */))(piVar3,in_stack_0000000c + 0x2060,piVar5);
        if (iVar4 == 0) {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x27ae86 /* "I should not attack this threat" */;
          return param_1;
        }
        fVar10 = (float10)CINSNextBot::GetActiveWeaponAmmoRatio();
        if ((float)fVar10 < *(float *)(unaff_EBX + 0x1b3abe /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */)) {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x27ad8d /* "Exiting attack to Reload" */;
          return param_1;
        }
        cVar2 = (**(code **)(*piVar5 + 0x38 /* INextBotEventResponder::OnAnimationEvent */))(piVar5);
        if (cVar2 == '\0') {
          piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          uVar7 = CBaseHandle::Get((CBaseHandle *)((int)param_2 + 0x48));
          cVar2 = (**(code **)(*piVar3 + 0x104 /* CINSBotVision::IsAbleToSee */))(piVar3,uVar7,1,0);
          if (cVar2 != '\0') goto LAB_007053fc;
          piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          pcVar1 = *(code **)(*piVar3 + 0xd4);
          uVar7 = (**(code **)(*piVar5 + 0x14 /* INextBotEventResponder::OnLandOnGround */))(piVar5);
          iVar4 = 0;
          uVar12 = 0x3e99999a;
          uVar11 = 3;
          (*pcVar1)(piVar3,uVar7,3,0x3e99999a,0,&UNK_0027aea6 + unaff_EBX);
          this_01 = extraout_ECX_00;
        }
        else {
LAB_007053fc:
          piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          uVar7 = CBaseHandle::Get((CBaseHandle *)((int)param_2 + 0x48));
          iVar4 = 0;
          uVar12 = 0x3e99999a;
          uVar11 = 4;
          (**(code **)(*piVar3 + 0xd8 /* PlayerBody::AimHeadTowards */))(piVar3,uVar7,4,0x3e99999a,0,unaff_EBX + 0x27ada6 /* "Aiming at active enemy" */);
          this_01 = extraout_ECX;
        }
        cVar2 = CINSPlayer::IsProned(this_01);
        if ((cVar2 != '\0') &&
           (uVar9 = CINSPlayer::GetPlayerFlags((CINSPlayer *)in_stack_0000000c), (uVar9 & 1) == 0))
        {
          cVar2 = (**(code **)(*piVar5 + 0x38 /* INextBotEventResponder::OnAnimationEvent */))(piVar5);
          if (cVar2 == '\0') {
            (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            iVar4 = unaff_EBX + 0x254a1d /* typeinfo name for CGlobalState+0x5c */;
            uVar12 = 0x3f800000;
            uVar11 = 7;
            uVar7 = 0xd;
            CINSBotBody::SetPosture();
          }
          else {
            (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            iVar4 = unaff_EBX + 0x254a1d /* typeinfo name for CGlobalState+0x5c */;
            uVar12 = 0x3f800000;
            uVar11 = 7;
            uVar7 = 1;
            CINSBotBody::SetPosture();
          }
        }
        cVar2 = (**(code **)(*(int *)**(undefined4 **)(&DAT_004a189a + unaff_EBX) + 0xe0))
                          ((int *)**(undefined4 **)(&DAT_004a189a + unaff_EBX),uVar7,uVar11,uVar12,
                           iVar4);
        if (cVar2 != '\0') {
          iVar4 = CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_0000000c);
          iVar8 = CINSRules::GetHumanTeam(this_02);
          if (iVar4 == iVar8) {
            CountdownTimer::Start(this_03,(float)(in_stack_0000000c + 0xb388));
            *(undefined4 *)(in_stack_0000000c + 0xb344) = 0x41200000;
          }
        }
        CountdownTimer::Start((CountdownTimer *)((int)param_2 + 0x38),(float)((int)param_2 + 0x38));
        goto LAB_0070508c;
      }
    }
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27ad43 /* "Invalid Threat" */;
  }
  else {
LAB_0070508c:
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttack::OnEnd
 * Address: 007045c0
 * ---------------------------------------- */

/* CINSBotAttack::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttack::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttack::GetName
 * Address: 00705790
 * ---------------------------------------- */

/* CINSBotAttack::GetName() const */

int CINSBotAttack::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x22b4c9 /* "Attacking" */;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldHurry
 * Address: 00704730
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttack::ShouldHurry(CINSBotAttack *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldHurry
 * Address: 00704740
 * ---------------------------------------- */

/* CINSBotAttack::ShouldHurry(INextBot const*) const */

char __cdecl CINSBotAttack::ShouldHurry(INextBot *param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  float *pfVar5;
  CBaseEntity *this;
  int unaff_EBX;
  char cVar6;
  
  iVar3 = __i686_get_pc_thunk_bx();
  cVar6 = '\x02';
  piVar1 = *(int **)(iVar3 + 0x1c);
  if (piVar1 != (int *)0x0) {
    piVar4 = (int *)(**(code **)(*piVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(piVar1);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (piVar4 != (int *)0x0) {
      cVar6 = '\0';
      cVar2 = (**(code **)(*piVar4 + 0x38))(piVar4);
      if (cVar2 == '\0') {
        cVar6 = '\x02';
        iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x4a1dfb /* &ins_bot_knives_only */) + 0x40))
                          (*(int **)(unaff_EBX + 0x4a1dfb /* &ins_bot_knives_only */));
        if (iVar3 == 0) {
          pfVar5 = (float *)(**(code **)(*piVar4 + 0x14))(piVar4);
          if ((*(byte *)((int)piVar1 + 0xd1) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this);
          }
          cVar6 = (*(float *)(unaff_EBX + 0x27b7ff /* typeinfo name for CINSBotAttack+0x12 */) <=
                  ((float)piVar1[0x83] - pfVar5[1]) * ((float)piVar1[0x83] - pfVar5[1]) +
                  ((float)piVar1[0x82] - *pfVar5) * ((float)piVar1[0x82] - *pfVar5) +
                  ((float)piVar1[0x84] - pfVar5[2]) * ((float)piVar1[0x84] - pfVar5[2])) * '\x02';
        }
      }
    }
  }
  return cVar6;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldRetreat
 * Address: 00704840
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttack::ShouldRetreat(CINSBotAttack *this,INextBot *param_1)

{
  ShouldRetreat(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldRetreat
 * Address: 00704850
 * ---------------------------------------- */

/* CINSBotAttack::ShouldRetreat(INextBot const*) const */

char __thiscall CINSBotAttack::ShouldRetreat(CINSBotAttack *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSPlayer *this_02;
  CINSNextBot *this_03;
  int unaff_EBX;
  char cVar7;
  float10 fVar8;
  int *in_stack_00000008;
  
  iVar4 = __i686_get_pc_thunk_bx();
  cVar7 = '\x02';
  iVar4 = *(int *)(iVar4 + 0x1c);
  if (iVar4 != 0) {
    cVar3 = CINSNextBot::CanCheckRetreat(this_00);
    if (cVar3 != '\0') {
      cVar7 = '\0';
      iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a1ceb /* &ins_bot_knives_only */) + 0x40))
                        (*(int **)(unaff_EBX + 0x4a1ceb /* &ins_bot_knives_only */));
      if (iVar5 == 0) {
        piVar6 = (int *)(**(code **)(*in_stack_00000008 + 0xdc))(in_stack_00000008);
        pcVar1 = *(code **)(*piVar6 + 0xdc);
        iVar5 = CBaseEntity::GetTeamNumber(this_01);
        iVar5 = (*pcVar1)(piVar6,(iVar5 == 2) + '\x02',1,0xbf800000);
        fVar8 = (float10)CINSPlayer::GetHealthFraction(this_02);
        if (((*(float *)(unaff_EBX + 0x21fef7 /* typeinfo name for CBaseGameSystem+0x1e */) <= (float)fVar8) || (iVar5 < 2)) ||
           (cVar7 = '\x01', 1 < *(int *)(iVar4 + 0x1e94))) {
          cVar7 = '\x02';
          cVar3 = CINSNextBot::IsSuppressed(this_03);
          if ((cVar3 != '\0') && (iVar5 != 0)) {
            iVar2 = *(int *)(iVar4 + 0xb448) * 2;
            cVar7 = (iVar5 == iVar2 ||
                    SBORROW4(iVar5,iVar2) != iVar5 + *(int *)(iVar4 + 0xb448) * -2 < 0) + '\x01';
          }
        }
      }
    }
  }
  return cVar7;
}



/* ----------------------------------------
 * CINSBotAttack::OnStuck
 * Address: 007045f0
 * ---------------------------------------- */

/* CINSBotAttack::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotAttack::OnStuck(CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)::operator_new(0x6c);
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
  iVar1 = *(int *)(unaff_EBX + 0x4a23bd /* &vtable for CINSBotStuck */);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = unaff_EBX + 0x423bbd /* vtable for CountdownTimer+0x8 */;
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(undefined **)(param_1 + 8) = &UNK_0027b77d + unaff_EBX;
  piVar2[0x17] = 0;
  piVar2[0x18] = 0;
  piVar2[0x19] = 0;
  piVar2[0x1a] = 0;
  *(undefined4 *)param_1 = 1;
  *(int **)(param_1 + 4) = piVar2;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttack::OnOtherKilled
 * Address: 00704cb0
 * ---------------------------------------- */

/* CINSBotAttack::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

CINSNextBot * __thiscall
CINSBotAttack::OnOtherKilled
          (CINSBotAttack *this,CINSNextBot *param_1,CBaseCombatCharacter *param_2,
          CTakeDamageInfo *param_3)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  if ((*(int *)(param_3 + 0xb338) == -1) ||
     (iVar1 = UTIL_EntityByIndex(*(int *)(param_3 + 0xb338)), iVar1 == 0)) {
    piVar2 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    piVar2 = (int *)(**(code **)(*piVar2 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar2,0);
    if ((piVar2 == (int *)0x0) || (iVar1 = (**(code **)(*piVar2 + 0x10))(piVar2), iVar1 == 0))
    goto LAB_00704d0b;
  }
  if ((*(int *)(param_3 + 0xb338) == -1) ||
     (iVar1 = UTIL_EntityByIndex(*(int *)(param_3 + 0xb338)), iVar1 == 0)) {
    piVar2 = (int *)(**(code **)(*(int *)param_3 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_3);
    piVar2 = (int *)(**(code **)(*piVar2 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar2,0);
    iVar1 = 0;
    if (piVar2 != (int *)0x0) {
      iVar1 = (**(code **)(*piVar2 + 0x10))(piVar2);
    }
  }
  if (in_stack_00000010 == iVar1) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_0027b194 + unaff_EBX;
    *(undefined4 *)(param_1 + 0xc) = 1;
    return param_1;
  }
LAB_00704d0b:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldIronsight
 * Address: 00704970
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttack::ShouldIronsight(CINSBotAttack *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldIronsight
 * Address: 00704980
 * ---------------------------------------- */

/* CINSBotAttack::ShouldIronsight(INextBot const*) const */

byte __cdecl CINSBotAttack::ShouldIronsight(INextBot *param_1)

{
  byte bVar1;
  CINSPlayer *this;
  
  __i686_get_pc_thunk_bx();
  bVar1 = 2;
  if (*(int *)(param_1 + 0x1c) != 0) {
    bVar1 = CINSPlayer::IsSprinting(this);
    bVar1 = bVar1 ^ 1;
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldWalk
 * Address: 007045d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttack::ShouldWalk(CINSBotAttack *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::ShouldWalk
 * Address: 007045e0
 * ---------------------------------------- */

/* CINSBotAttack::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttack::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttack::~CINSBotAttack
 * Address: 007057b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::~CINSBotAttack() */

void __thiscall CINSBotAttack::~CINSBotAttack(CINSBotAttack *this)

{
  ~CINSBotAttack(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::~CINSBotAttack
 * Address: 007057c0
 * ---------------------------------------- */

/* CINSBotAttack::~CINSBotAttack() */

void __thiscall CINSBotAttack::~CINSBotAttack(CINSBotAttack *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x48f243 /* vtable for CINSBotAttack+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48f3e3 /* vtable for CINSBotAttack+0x1a8 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4a19b3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttack::~CINSBotAttack
 * Address: 007057f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttack::~CINSBotAttack() */

void __thiscall CINSBotAttack::~CINSBotAttack(CINSBotAttack *this)

{
  ~CINSBotAttack(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttack::~CINSBotAttack
 * Address: 00705800
 * ---------------------------------------- */

/* CINSBotAttack::~CINSBotAttack() */

void __thiscall CINSBotAttack::~CINSBotAttack(CINSBotAttack *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48f1fa /* vtable for CINSBotAttack+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x48f39a /* vtable for CINSBotAttack+0x1a8 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



