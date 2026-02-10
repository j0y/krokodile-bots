/*
 * CINSBotAttackAdvance -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 44
 */

/* ----------------------------------------
 * CINSBotAttackAdvance::CINSBotAttackAdvance
 * Address: 00705ef0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::CINSBotAttackAdvance() */

void __thiscall CINSBotAttackAdvance::CINSBotAttackAdvance(CINSBotAttackAdvance *this)

{
  int *piVar1;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48ed0d /* vtable for CINSBotAttackAdvance+0x8 */ /* vtable for CINSBotAttackAdvance+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x48eeb5 /* vtable for CINSBotAttackAdvance+0x1b0 */ /* vtable for CINSBotAttackAdvance+0x1b0 */;
  in_stack_00000004[0xe] = unaff_EBX + 0x4222bd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_0 */
  in_stack_00000004[10] = 0;
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
  (*(code *)(unaff_EBX + -0x4d578b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0xe,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0xe] + 4))(in_stack_00000004 + 0xe,in_stack_00000004 + 0x10); /* timer_0.NetworkStateChanged() */
  piVar1 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = unaff_EBX + 0x4222bd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_1 */
  (*(code *)(unaff_EBX + -0x4d578b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar1,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x11] + 4))(piVar1,in_stack_00000004 + 0x13); /* timer_1.NetworkStateChanged() */
  if (in_stack_00000004[0x13] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x11] + 4))(piVar1,in_stack_00000004 + 0x13); /* timer_1.NetworkStateChanged() */
    in_stack_00000004[0x13] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnStart
 * Address: 00705d30
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotAttackAdvance::OnStart(CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  void *pvVar2;
  CINSNextBot *this;
  CINSBotAttackInPlace *this_00;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSNextBot::IsEscorting(this);
  if (cVar1 == '\0') {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    pvVar2 = ::operator_new(0x50);
    CINSBotAttackInPlace::CINSBotAttackInPlace(this_00);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(void **)(param_1 + 4) = pvVar2;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27a221 /* "Attacking in place in escort" */ /* "Attacking in place in escort" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::Update
 * Address: 00706730
 * ---------------------------------------- */

/* CINSBotAttackAdvance::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackAdvance::Update(CINSBotAttackAdvance *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  void *pvVar7;
  int *piVar8;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_01;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_02;
  CINSBotAttackAdvance *this_03;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSBotAttackInPlace *this_04;
  CINSBotVision *this_05;
  CINSPlayer *extraout_ECX_03;
  int *extraout_EDX;
  CINSPlayer *pCVar9;
  int unaff_EBX;
  float10 fVar10;
  float10 fVar11;
  float fVar12;
  CINSPlayer *in_stack_0000000c;
  int *piVar13;
  int *local_5c;
  code *local_4c;
  float local_44;
  undefined1 local_34 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*extraout_EDX + 0x974 /* CINSNextBot::GetVisionInterface */))(extraout_EDX);
  piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
  if (((piVar3 == (int *)0x0) || (iVar4 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar4 == 0)) ||
     (cVar2 = (**(code **)(*piVar3 + 0x54))(piVar3), cVar2 != '\0')) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
  pCVar9 = in_stack_0000000c + 0x2060;
  piVar13 = piVar3;
  iVar4 = (**(code **)(*piVar5 + 0xd4 /* IIntention::ShouldAttack */))(piVar5,pCVar9,piVar3);
  if (iVar4 == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27983b /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */;
    return param_1;
  }
  fVar10 = (float10)CountdownTimer::Now();
  if ((float)fVar10 < *(float *)((int)param_2 + 0x4c) || /* !timer_1.IsElapsed() */
      (float)fVar10 == *(float *)((int)param_2 + 0x4c)) goto LAB_00706a1c;
  piVar5 = (int *)CINSPlayer::GetActiveINSWeapon();
  if (piVar5 == (int *)0x0) {
    CINSNextBot::ChooseBestWeapon(this_00,(CKnownEntity *)in_stack_0000000c);
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  pcVar1 = *(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x130);
  uVar6 = (**(code **)(*piVar3 + 0x10))(piVar3);
  fVar10 = (float10)(*pcVar1)(pCVar9,uVar6);
  this_01 = extraout_ECX;
  if (((float)fVar10 < *(float *)(unaff_EBX + 0x21e8f4 /* 180.0f */ /* 180.0f */)) &&
     (cVar2 = (**(code **)(*piVar3 + 0x38))(piVar3), this_01 = extraout_ECX_01, cVar2 != '\0')) {
    piVar13 = (int *)0x0;
    piVar8 = (int *)CINSPlayer::GetWeaponInSlot(in_stack_0000000c,(int)in_stack_0000000c,false);
    this_01 = extraout_ECX_02;
    if ((piVar5 == piVar8) && (piVar8 != (int *)0x0)) {
      pvVar7 = ::operator_new(0x50);
      CINSBotAttackInPlace::CINSBotAttackInPlace(this_04);
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(void **)(param_1 + 4) = pvVar7;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2798a4 /* "Closing in too close with primary" */ /* "Closing in too close with primary" */;
      return param_1;
    }
  }
  piVar8 = piVar5;
  fVar11 = (float10)CINSNextBot::GetMaxAttackRange(this_01,(CINSWeapon *)in_stack_0000000c);
  fVar12 = (float)fVar10 / (float)fVar11;
  if (fVar12 < *(float *)(unaff_EBX + 0x1b23d0 /* 1.0f */ /* 1.0f */) || fVar12 == *(float *)(unaff_EBX + 0x1b23d0 /* 1.0f */ /* 1.0f */)) {
LAB_00706ae4:
    local_44 = *(float *)(unaff_EBX + 0x21e014 /* 0.5f */ /* 0.5f */);
  }
  else {
    iVar4 = (**(code **)(*piVar5 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar5,piVar8,piVar13);
    if (iVar4 == 0xd) {
      local_44 = *(float *)(unaff_EBX + 0x21e014 /* 0.5f */ /* 0.5f */);
      if (fVar12 < local_44) goto LAB_00706cc4;
    }
    else {
      if (iVar4 < 0xe) {
        local_44 = *(float *)(unaff_EBX + 0x21e014 /* 0.5f */ /* 0.5f */);
        if (iVar4 < 8) goto LAB_00706910;
      }
      else if (iVar4 != 0xe) goto LAB_00706ae4;
      if (fVar12 < *(float *)(unaff_EBX + 0x21d34c /* 0.75f */ /* 0.75f */)) {
LAB_00706cc4:
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x279859 /* "Within good enough range" */ /* "Within good enough range" */;
        return param_1;
      }
      local_44 = *(float *)(unaff_EBX + 0x21e014 /* 0.5f */ /* 0.5f */);
    }
  }
LAB_00706910:
  cVar2 = (**(code **)(*piVar3 + 0x38))(piVar3);
  if (cVar2 == '\0') {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    pcVar1 = *(code **)(*piVar5 + 0x108);
    piVar8 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3);
    (**(code **)(*piVar8 + 0x20c /* CINSNextBot::EyePosition */))(local_34,piVar8);
    uVar6 = 1;
    cVar2 = (*pcVar1)(piVar5,local_34,1);
    this_02 = extraout_ECX_03;
    if (cVar2 != '\0') {
      local_5c = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      local_4c = *(code **)(*local_5c + 0xd8);
      uVar6 = (**(code **)(*piVar3 + 0x10))(piVar3);
      iVar4 = unaff_EBX + 0x279889 /* "Lost aim on our threat!" */ /* "Lost aim on our threat!" */;
      goto LAB_0070694e;
    }
  }
  else {
    local_5c = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
    local_4c = *(code **)(*local_5c + 0xd8);
    uVar6 = (**(code **)(*piVar3 + 0x10))(piVar3);
    iVar4 = unaff_EBX + 0x279872 /* "Continue aim at threat" */ /* "Continue aim at threat" */;
LAB_0070694e:
    piVar13 = (int *)0x3;
    (*local_4c)(local_5c,uVar6,3,0x3f19999a /* 0.6f */,0,iVar4);
    this_02 = extraout_ECX_00;
  }
  cVar2 = CINSPlayer::IsProned(this_02);
  if (cVar2 == '\0') {
    cVar2 = CINSNextBot::IsSuppressed((CINSNextBot *)in_stack_0000000c);
    if (cVar2 == '\0') {
      pcVar1 = *(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x130);
      uVar6 = (**(code **)(*piVar3 + 0x10))(piVar3);
      fVar10 = (float10)(*pcVar1)(pCVar9,uVar6);
      if (*(float *)(unaff_EBX + 0x21fb44 /* 120.0f */ /* 120.0f */) <= (float)fVar10 &&
          (float)fVar10 != *(float *)(unaff_EBX + 0x21fb44 /* 120.0f */ /* 120.0f */)) {
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
        pcVar1 = *(code **)(*piVar5 + 0x108);
        uVar6 = (**(code **)(*piVar3 + 0x14))(piVar3);
        piVar13 = (int *)0x1;
        cVar2 = (*pcVar1)(piVar5,uVar6,1);
        if (cVar2 != '\0') {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          piVar13 = (int *)0x7;
          CINSBotBody::SetPosture();
        }
      }
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      fVar10 = (float10)CINSBotVision::GetCombatIntensity(this_05);
      if ((float)fVar10 <= local_44) {
        RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
        (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        piVar13 = (int *)0x7;
        CINSBotBody::SetPosture();
      }
      else {
        RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
        (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        piVar13 = (int *)0x7;
        CINSBotBody::SetPosture();
      }
    }
  }
  else {
    cVar2 = (**(code **)(*piVar3 + 0x38))(piVar3);
    if ((cVar2 == '\0') &&
       (cVar2 = CINSNextBot::IsSuppressed((CINSNextBot *)in_stack_0000000c), cVar2 == '\0')) {
      iVar4 = (**(code **)(*(int *)(*(int *)((int)param_2 + 0xc) + 4) + 0xc))
                        (*(int *)((int)param_2 + 0xc) + 4,pCVar9);
      if (iVar4 == 1) {
        RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
        (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        piVar13 = (int *)0x7;
        uVar6 = 0xd;
        CINSBotBody::SetPosture();
      }
      else {
        iVar4 = (**(code **)(*(int *)(*(int *)((int)param_2 + 0xc) + 4) + 0x28))
                          (*(int *)((int)param_2 + 0xc) + 4,pCVar9);
        if (iVar4 == 1) {
          RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          piVar13 = (int *)0x7;
          uVar6 = 0xb;
          CINSBotBody::SetPosture();
        }
        else {
          RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          piVar13 = (int *)0x7;
          uVar6 = 0xc;
          CINSBotBody::SetPosture();
        }
      }
    }
    cVar2 = (**(code **)(*piVar3 + 0x38))(piVar3,uVar6,piVar13);
    if (cVar2 != '\0') {
      (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
      CINSBotLocomotion::ClearMovementRequests();
    }
  }
  fVar10 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x4c) != (float)fVar10 + local_44) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4)) /* timer_1.NetworkStateChanged() */
              ((int)param_2 + 0x44,(int)param_2 + 0x4c,piVar13);
    *(float *)((int)param_2 + 0x4c) = (float)fVar10 + local_44; /* timer_1.Start(...) */
  }
  if (*(int *)((int)param_2 + 0x48) != 0x3f000000 /* 0.5f */) {
    (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48); /* timer_1.NetworkStateChanged() */
    *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000 /* 0.5f */;
  }
LAB_00706a1c:
  CINSNextBot::FireWeaponAtEnemy((CINSNextBot *)in_stack_0000000c);
  fVar10 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar10 && /* timer_0.IsElapsed() */
      (float)fVar10 != *(float *)((int)param_2 + 0x40)) {
    cVar2 = ShouldRepath(this_03);
    if (cVar2 != '\0') {
      fVar12 = param_2;
      GetAdvancePosition();
      uVar6 = (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,fVar12);
      CINSBotLocomotion::AddMovementRequest(uVar6,local_28,local_24,local_20,2,3,0x40a00000 /* 5.0f */);
    }
    fVar10 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar10 + *(float *)(unaff_EBX + 0x1b23d0 /* 1.0f */ /* 1.0f */);
    if (*(float *)((int)param_2 + 0x40) != fVar12) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40); /* timer_0.NetworkStateChanged() */
      *(float *)((int)param_2 + 0x40) = fVar12; /* timer_0.Start(1.0f) */
    }
    if (*(int *)((int)param_2 + 0x3c) != 0x3f800000 /* 1.0f */) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c); /* timer_0.NetworkStateChanged() */
      *(undefined4 *)((int)param_2 + 0x3c) = 0x3f800000 /* 1.0f */;
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnEnd
 * Address: 00705870
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackAdvance::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::GetName
 * Address: 00706ff0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::GetName() const */

undefined * CINSBotAttackAdvance::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return &UNK_00278f5f + extraout_ECX;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldHurry
 * Address: 00705880
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackAdvance::ShouldHurry(CINSBotAttackAdvance *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldHurry
 * Address: 00705890
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldHurry(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldRetreat
 * Address: 007058a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackAdvance::ShouldRetreat(CINSBotAttackAdvance *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldRetreat
 * Address: 007058b0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldRetreat(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldAttack
 * Address: 007058c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackAdvance::ShouldAttack
          (CINSBotAttackAdvance *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldAttack
 * Address: 007058d0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnContact
 * Address: 00705940
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackAdvance::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnMoveToSuccess
 * Address: 00705970
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackAdvance::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnMoveToFailure
 * Address: 007059a0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackAdvance::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnStuck
 * Address: 007059d0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnStuck(CINSNextBot*) */

void CINSBotAttackAdvance::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnUnStuck
 * Address: 00705a00
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnUnStuck(CINSNextBot*) */

void CINSBotAttackAdvance::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnInjured
 * Address: 00705a60
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackAdvance::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnKilled
 * Address: 00705a90
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackAdvance::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnOtherKilled
 * Address: 00705ac0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&)
    */

void CINSBotAttackAdvance::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnSight
 * Address: 00705af0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackAdvance::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnLostSight
 * Address: 00705b20
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackAdvance::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnWeaponFired
 * Address: 00705b50
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackAdvance::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnCommandApproach
 * Address: 00705be0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackAdvance::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnCommandApproach
 * Address: 00705c10
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackAdvance::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnCommandString
 * Address: 00705c70
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackAdvance::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::GetAdvancePosition
 * Address: 007061b0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::GetAdvancePosition() */

float * CINSBotAttackAdvance::GetAdvancePosition(void)

{
  CINSWeapon *pCVar1;
  code *pcVar2;
  CNavArea *this;
  char cVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  float *pfVar7;
  Vector *pVVar8;
  uint uVar9;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_02;
  CNavArea *this_03;
  CNavArea *extraout_ECX_00;
  CINSWeapon *this_04;
  CBaseEntity *this_05;
  CNavArea *this_06;
  CNavArea *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *pCVar10;
  CBaseEntity *this_07;
  CNavMesh *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar11;
  float10 fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float *in_stack_00000004;
  int in_stack_00000008;
  undefined4 uVar20;
  float *pfVar21;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x7061bb;
  __i686_get_pc_thunk_bx();
  pCVar1 = *(CINSWeapon **)(in_stack_00000008 + 0x1c);
  if (pCVar1 != (CINSWeapon *)0x0) {
    piVar4 = (int *)(**(code **)(*(int *)pCVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar1);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if ((((piVar4 != (int *)0x0) && (iVar5 = (**(code **)(*piVar4 + 0x10))(piVar4), iVar5 != 0)) &&
        (cVar3 = (**(code **)(*piVar4 + 0x54))(piVar4), cVar3 == '\0')) &&
       (piVar6 = (int *)CINSPlayer::GetActiveINSWeapon(), piVar6 != (int *)0x0)) {
      uVar20 = 0;
      fVar11 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,pCVar1);
      pcVar2 = *(code **)(*(int *)(pCVar1 + 0x2060) + 0x130);
      uVar20 = (**(code **)(*piVar4 + 0x10))(piVar4,uVar20);
      fVar12 = (float10)(*pcVar2)(pCVar1 + 0x2060,uVar20);
      fVar13 = (float)fVar11 / (float)fVar12;
      pfVar7 = (float *)(**(code **)(*piVar4 + 0x14))(piVar4);
      pCVar10 = this_01;
      if (((byte)pCVar1[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_01);
        pCVar10 = extraout_ECX;
      }
      fVar17 = *(float *)(pCVar1 + 0x208);
      fVar16 = *(float *)(pCVar1 + 0x20c);
      fVar14 = fVar17 - *pfVar7;
      fVar18 = fVar16 - pfVar7[1];
      fVar15 = *(float *)(pCVar1 + 0x210);
      fVar19 = fVar15 - pfVar7[2];
      pfVar7 = *(float **)(unaff_EBX + 0x4a0411 /* &vec3_origin */ /* &vec3_origin */);
      local_2c = *pfVar7;
      local_28 = pfVar7[1];
      local_24 = pfVar7[2];
      if ((float)fVar12 <= (float)fVar11) {
        cVar3 = (**(code **)(*piVar6 + 0x620 /* CINSPlayer::FlashlightIsOn */))(piVar6);
        if ((cVar3 == '\0') ||
           (fVar11 = (float10)CINSWeapon::GetFOVWeaponScope(this_04),
           *(float *)(unaff_EBX + 0x21e5a9 /* 20.0f */ /* 20.0f */) <= (float)fVar11)) {
          uVar9 = (**(code **)(*piVar6 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar6);
          if (0xe < uVar9) {
            if (((byte)pCVar1[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_05);
            }
            *in_stack_00000004 = *(float *)(pCVar1 + 0x208);
            in_stack_00000004[1] = *(float *)(pCVar1 + 0x20c);
            in_stack_00000004[2] = *(float *)(pCVar1 + 0x210);
            return in_stack_00000004;
          }
                    /* WARNING: Could not recover jumptable at 0x007064e9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          pfVar7 = (float *)(*(code *)(&UNK_004a0fbd +
                                      *(int *)(unaff_EBX + 0x279e51 /* rodata:0xFFB5F455 */ /* rodata:0xFFB5F455 */ + uVar9 * 4) + unaff_EBX))();
          return pfVar7;
        }
        pCVar10 = this_07;
        if (((byte)pCVar1[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_07);
          pCVar10 = (CBaseEntity *)extraout_ECX_03;
        }
        local_28 = *(float *)(pCVar1 + 0x20c) - fVar13 * fVar18;
        local_24 = *(float *)(pCVar1 + 0x210) - fVar13 * fVar19;
        pfVar21 = &local_2c;
        uVar20 = 0;
        local_2c = *(float *)(pCVar1 + 0x208) - fVar13 * fVar14;
        pfVar7 = pfVar21;
        pVVar8 = (Vector *)
                 CNavMesh::GetNearestNavAreaFast
                           ((CNavMesh *)pCVar10,(Vector *)**(undefined4 **)(unaff_EBX + 0x4a04fd /* &TheNavMesh */ /* &TheNavMesh */),
                            SUB41(pfVar21,0));
        if (pVVar8 != (Vector *)0x0) {
          cVar3 = CNavArea::Contains(this_06,pVVar8);
          this = extraout_ECX_01;
          pfVar7 = pfVar21;
          goto joined_r0x007065b1;
        }
      }
      else {
        if (((byte)pCVar1[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(pCVar10);
          fVar17 = *(float *)(pCVar1 + 0x208);
          fVar16 = *(float *)(pCVar1 + 0x20c);
          fVar15 = *(float *)(pCVar1 + 0x210);
        }
        local_28 = fVar16 - fVar13 * fVar18;
        local_24 = fVar15 - fVar13 * fVar19;
        local_2c = fVar17 - fVar13 * fVar14;
        fVar11 = (float10)(**(code **)(*(int *)(pCVar1 + 0x2060) + 0x134))
                                    (pCVar1 + 0x2060,&local_2c);
        pCVar10 = this_02;
        if ((float)fVar11 < *(float *)(&LAB_0021f609 + unaff_EBX)) {
          fVar13 = fVar13 * *(float *)(unaff_EBX + 0x21d8d5 /* 0.75f */ /* 0.75f */);
          if (((byte)pCVar1[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_02);
            pCVar10 = extraout_ECX_02;
          }
          local_24 = *(float *)(pCVar1 + 0x210) - fVar19 * fVar13;
          local_28 = *(float *)(pCVar1 + 0x20c) - fVar18 * fVar13;
          local_2c = *(float *)(pCVar1 + 0x208) - fVar14 * fVar13;
        }
        pfVar7 = &local_2c;
        uVar20 = 0;
        pVVar8 = (Vector *)
                 CNavMesh::GetNearestNavAreaFast
                           ((CNavMesh *)pCVar10,(Vector *)**(undefined4 **)(unaff_EBX + 0x4a04fd /* &TheNavMesh */ /* &TheNavMesh */),
                            SUB41(pfVar7,0));
        if (pVVar8 != (Vector *)0x0) {
          pfVar7 = &local_2c;
          cVar3 = CNavArea::Contains(this_03,pVVar8);
          this = extraout_ECX_00;
joined_r0x007065b1:
          if (cVar3 != '\0') {
            fVar11 = (float10)CNavArea::GetZ(this,(float)pVVar8,local_2c);
            *in_stack_00000004 = local_2c;
            in_stack_00000004[1] = local_28;
            in_stack_00000004[2] = (float)fVar11;
            return in_stack_00000004;
          }
        }
      }
      pfVar7 = (float *)(**(code **)(*piVar4 + 0x14))(piVar4,pfVar7,uVar20);
      goto LAB_00706456;
    }
  }
  pfVar7 = *(float **)(unaff_EBX + 0x4a0411 /* &vec3_origin */ /* &vec3_origin */);
LAB_00706456:
  *in_stack_00000004 = *pfVar7;
  in_stack_00000004[1] = pfVar7[1];
  in_stack_00000004[2] = pfVar7[2];
  return in_stack_00000004;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnBlinded
 * Address: 00705ca0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackAdvance::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnCommandAttack
 * Address: 00705bb0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackAdvance::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnCommandRetreat
 * Address: 00705c40
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackAdvance::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnHeardFootsteps
 * Address: 00705cd0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackAdvance::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnNavAreaChanged
 * Address: 00705b80
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackAdvance::OnNavAreaChanged
               (CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnPostureChanged
 * Address: 00705a30
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackAdvance::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::OnSeeSomethingSuspicious
 * Address: 00705d00
 * ---------------------------------------- */

/* CINSBotAttackAdvance::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

void CINSBotAttackAdvance::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldIronsight
 * Address: 00705900
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackAdvance::ShouldIronsight(CINSBotAttackAdvance *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldIronsight
 * Address: 00705910
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldIronsight(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldProne
 * Address: 00705920
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackAdvance::ShouldProne(CINSBotAttackAdvance *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldProne
 * Address: 00705930
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldRepath
 * Address: 00706020
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldRepath() */

bool __thiscall CINSBotAttackAdvance::ShouldRepath(CINSBotAttackAdvance *this)

{
  CINSWeapon *pCVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined4 uVar7;
  CINSPathFollower *this_00;
  CINSNextBot *this_01;
  int extraout_EDX;
  int unaff_EBX;
  bool bVar8;
  float10 fVar9;
  float10 fVar10;
  int in_stack_00000004;
  CINSWeapon *pCVar11;
  
  __i686_get_pc_thunk_bx();
  bVar8 = false;
  iVar4 = *(int *)(extraout_EDX + 0x1c /* CINSBotAttackAdvance::ShouldRepath */ /* CINSBotAttackAdvance::ShouldRepath */);
  if (iVar4 != 0) {
    bVar8 = true;
    iVar4 = (**(code **)(*(int *)(iVar4 + 0x2060) + 0x114))(iVar4 + 0x2060);
    if (iVar4 != 0) {
      pIVar5 = (INextBot *)
               __dynamic_cast(iVar4,*(undefined4 *)(unaff_EBX + 0x4a0b73 /* &typeinfo for PathFollower */ /* &typeinfo for PathFollower */),
                              *(undefined4 *)(unaff_EBX + 0x4a067f /* &typeinfo for CINSPathFollower */ /* &typeinfo for CINSPathFollower */),0);
      if (pIVar5 != (INextBot *)0x0) {
        cVar3 = (**(code **)(*(int *)pIVar5 + 0x40))(pIVar5);
        if (cVar3 != '\0') {
          bVar8 = false;
          pCVar1 = *(CINSWeapon **)(in_stack_00000004 + 0x1c);
          if (pCVar1 != (CINSWeapon *)0x0) {
            bVar8 = true;
            pCVar11 = pCVar1 + 0x2060;
            cVar3 = CINSPathFollower::IsComputeExpired(this_00,pIVar5);
            if (cVar3 == '\0') {
              bVar8 = false;
              piVar6 = (int *)(**(code **)(*(int *)pCVar1 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar1,pCVar11);
              piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
              if (piVar6 != (int *)0x0) {
                iVar4 = (**(code **)(*piVar6 + 0x10))(piVar6);
                if (iVar4 != 0) {
                  cVar3 = (**(code **)(*piVar6 + 0x54))(piVar6);
                  if (cVar3 == '\0') {
                    pcVar2 = *(code **)(*(int *)(pCVar1 + 0x2060) + 0x130);
                    uVar7 = (**(code **)(*piVar6 + 0x10))(piVar6);
                    fVar9 = (float10)(*pcVar2)(pCVar1 + 0x2060,uVar7);
                    uVar7 = 0;
                    fVar10 = (float10)CINSNextBot::GetDesiredAttackRange(this_01,pCVar1);
                    if ((float)fVar10 * *(float *)(unaff_EBX + 0x21da5b /* 0.25f */ /* 0.25f */) <= (float)fVar9) {
                      bVar8 = false;
                      cVar3 = (**(code **)(*piVar6 + 0x38))(piVar6,uVar7);
                      if (cVar3 == '\0') {
                        fVar9 = (float10)(**(code **)(*piVar6 + 0x48))(piVar6);
                        bVar8 = *(float *)(unaff_EBX + 0x1b2ae3 /* 1.0f */ /* 1.0f */) <= (float)fVar9 &&
                                (float)fVar9 != *(float *)(unaff_EBX + 0x1b2ae3 /* 1.0f */ /* 1.0f */);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return bVar8;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldWalk
 * Address: 007058e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackAdvance::ShouldWalk(CINSBotAttackAdvance *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::ShouldWalk
 * Address: 007058f0
 * ---------------------------------------- */

/* CINSBotAttackAdvance::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackAdvance::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::~CINSBotAttackAdvance
 * Address: 00707010
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::~CINSBotAttackAdvance() */

void __thiscall CINSBotAttackAdvance::~CINSBotAttackAdvance(CINSBotAttackAdvance *this)

{
  ~CINSBotAttackAdvance(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::~CINSBotAttackAdvance
 * Address: 00707020
 * ---------------------------------------- */

/* CINSBotAttackAdvance::~CINSBotAttackAdvance() */

void __thiscall CINSBotAttackAdvance::~CINSBotAttackAdvance(CINSBotAttackAdvance *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x48dbe3 /* vtable for CINSBotAttackAdvance+0x8 */ /* vtable for CINSBotAttackAdvance+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48dd8b /* vtable for CINSBotAttackAdvance+0x1b0 */ /* vtable for CINSBotAttackAdvance+0x1b0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4a0153 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::~CINSBotAttackAdvance
 * Address: 00707050
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackAdvance::~CINSBotAttackAdvance() */

void __thiscall CINSBotAttackAdvance::~CINSBotAttackAdvance(CINSBotAttackAdvance *this)

{
  ~CINSBotAttackAdvance(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackAdvance::~CINSBotAttackAdvance
 * Address: 00707060
 * ---------------------------------------- */

/* CINSBotAttackAdvance::~CINSBotAttackAdvance() */

void __thiscall CINSBotAttackAdvance::~CINSBotAttackAdvance(CINSBotAttackAdvance *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0048db9a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x48dd42 /* vtable for CINSBotAttackAdvance+0x1b0 */ /* vtable for CINSBotAttackAdvance+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



