/*
 * CINSBotLocomotion -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 34
 */

/* ----------------------------------------
 * CINSBotLocomotion::CINSBotLocomotion
 * Address: 00760920
 * ---------------------------------------- */

/* CINSBotLocomotion::CINSBotLocomotion(INextBot*) */

void __thiscall CINSBotLocomotion::CINSBotLocomotion(CINSBotLocomotion *this,INextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  PlayerLocomotion *this_00;
  CINSPathFollower *this_01;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  PlayerLocomotion::PlayerLocomotion(this_00,param_1);
  *(int *)param_1 = unaff_EBX + 0x43c77d /* vtable for CINSBotLocomotion+0x8 */ /* vtable for CINSBotLocomotion+0x8 */ /* vtable for CINSBotLocomotion+0x8 */;
  CINSPathFollower::CINSPathFollower(this_01);
  pcVar1 = (code *)(unaff_EBX + -0x5301bb /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  *(undefined4 *)(param_1 + 0x491c) = 0;
  iVar2 = unaff_EBX + 0x3c788d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  *(int *)(param_1 + 0x4930) = iVar2;
  *(undefined4 *)(param_1 + 0x4920) = 0;
  *(undefined4 *)(param_1 + 0x4924) = 0;
  *(undefined4 *)(param_1 + 0x4928) = 0;
  *(undefined4 *)(param_1 + 0x492c) = 0;
  *(undefined4 *)(param_1 + 0x4934) = 0;
  (*pcVar1)(param_1 + 0x4930,param_1 + 0x4934);
  *(undefined4 *)(param_1 + 0x4938) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x4930) + 4))(param_1 + 0x4930,param_1 + 0x4938);
  *(int *)(param_1 + 0x493c) = iVar2;
  *(undefined4 *)(param_1 + 0x4940) = 0;
  (*pcVar1)(param_1 + 0x493c,param_1 + 0x4940);
  *(undefined4 *)(param_1 + 0x4944) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x493c) + 4))(param_1 + 0x493c,param_1 + 0x4944);
  *(int *)(param_1 + 0x4948) = iVar2;
  *(undefined4 *)(param_1 + 0x494c) = 0;
  (*pcVar1)(param_1 + 0x4948,param_1 + 0x494c);
  *(undefined4 *)(param_1 + 0x4950) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x4948) + 4))(param_1 + 0x4948,param_1 + 0x4950);
  *(int *)(param_1 + 0x4954) = iVar2;
  *(undefined4 *)(param_1 + 0x4958) = 0;
  (*pcVar1)(param_1 + 0x4954,param_1 + 0x4958);
  *(undefined4 *)(param_1 + 0x495c) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x4954) + 4))(param_1 + 0x4954,param_1 + 0x495c);
  *(int *)(param_1 + 0x4960) = iVar2;
  *(undefined4 *)(param_1 + 0x4964) = 0;
  (*pcVar1)(param_1 + 0x4960,param_1 + 0x4964);
  *(undefined4 *)(param_1 + 0x4968) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x4960) + 4))(param_1 + 0x4960,param_1 + 0x4968);
  *(int *)(param_1 + 0x496c) = iVar2;
  *(undefined4 *)(param_1 + 0x4970) = 0;
  (*pcVar1)(param_1 + 0x496c,param_1 + 0x4970);
  *(undefined4 *)(param_1 + 0x4974) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x496c) + 4))(param_1 + 0x496c,param_1 + 0x4974);
  *(int *)(param_1 + 0x4978) = iVar2;
  *(undefined4 *)(param_1 + 0x497c) = 0;
  (*pcVar1)(param_1 + 0x4978,param_1 + 0x497c);
  *(undefined4 *)(param_1 + 0x4980) = 0xbf800000 /* -1.0f */;
  (**(code **)(*(int *)(param_1 + 0x4978) + 4))(param_1 + 0x4978,param_1 + 0x4980);
  iVar2 = *(int *)(unaff_EBX + 0x446325 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  *(undefined4 *)(param_1 + 0x4988) = 0xbf800000 /* -1.0f */;
  *(int *)(param_1 + 0x4984) = iVar2 + 8;
  (**(code **)(iVar2 + 0x10))(param_1 + 0x4984,param_1 + 0x4988);
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::Update
 * Address: 0075d8a0
 * ---------------------------------------- */

/* CINSBotLocomotion::Update() */

void __thiscall CINSBotLocomotion::Update(CINSBotLocomotion *this)

{
  PlayerLocomotion *this_00;
  int unaff_EBX;
  float10 fVar1;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  PlayerLocomotion::Update(this_00);
  fVar1 = (float10)(**(code **)(*in_stack_00000004 + 0x16c))(in_stack_00000004);
  if ((float)fVar1 < *(float *)(unaff_EBX + 0x1c6ebe /* 5.0f */ /* 5.0f */ /* 5.0f */)) {
    if ((float)in_stack_00000004[0x1262] <= 0.0) {
      fVar1 = (float10)IntervalTimer::Now();
      if ((float)in_stack_00000004[0x1262] != (float)fVar1) {
        (**(code **)(in_stack_00000004[0x1261] + 8))
                  (in_stack_00000004 + 0x1261,in_stack_00000004 + 0x1262);
        in_stack_00000004[0x1262] = (int)(float)fVar1;
      }
    }
  }
  else if (in_stack_00000004[0x1262] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1261] + 8))
              (in_stack_00000004 + 0x1261,in_stack_00000004 + 0x1262);
    in_stack_00000004[0x1262] = -0x40800000 /* -1.0f */;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnMoveToSuccess
 * Address: 0075ec00
 * ---------------------------------------- */

/* CINSBotLocomotion::OnMoveToSuccess(Path const*) */

void __thiscall CINSBotLocomotion::OnMoveToSuccess(CINSBotLocomotion *this,Path *param_1)

{
  CINSBotLocomotion *this_00;
  int iStack00000008;
  
  iStack00000008 = GetCurrentMovementRequest(this);
  if (iStack00000008 != -1) {
    OnCompletedMovementRequest(this_00,(int)param_1);
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnMoveToFailure
 * Address: 0075ef00
 * ---------------------------------------- */

/* CINSBotLocomotion::OnMoveToFailure(Path const*, MoveToFailureType) */

void __thiscall CINSBotLocomotion::OnMoveToFailure(CINSBotLocomotion *this,int param_2)

{
  int iVar1;
  CINSBotLocomotion *this_00;
  
  iVar1 = GetCurrentMovementRequest(this);
  if (iVar1 != -1) {
    OnFailedMovementRequest(this_00,param_2);
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnStuck
 * Address: 0075ee90
 * ---------------------------------------- */

/* CINSBotLocomotion::OnStuck() */

void __thiscall CINSBotLocomotion::OnStuck(CINSBotLocomotion *this)

{
  CINSBotLocomotion *this_00;
  CINSBotLocomotion *this_01;
  CINSPathFollower *this_02;
  int unaff_EBX;
  float10 fVar1;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)(**(code **)(*in_stack_00000004 + 400))();
  if (*(float *)(unaff_EBX + 0x1c58c8 /* 5.0f */ /* 5.0f */ /* 5.0f */) <= (float)fVar1 &&
      (float)fVar1 != *(float *)(unaff_EBX + 0x1c58c8 /* 5.0f */ /* 5.0f */ /* 5.0f */)) {
    GetCurrentMovementRequest(this_00);
    OnFailedMovementRequest(this_01,(int)in_stack_00000004);
    CINSPathFollower::Invalidate(this_02);
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnUnStuck
 * Address: 0075d7a0
 * ---------------------------------------- */

/* CINSBotLocomotion::OnUnStuck() */

void CINSBotLocomotion::OnUnStuck(void)

{
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::AddMovementRequest
 * Address: 00760dd0
 * ---------------------------------------- */

/* CINSBotLocomotion::AddMovementRequest(Vector, INSBotMovementType, INSBotPriority, float) */

void __cdecl
CINSBotLocomotion::AddMovementRequest
          (int *param_1,float param_2,float param_3,float param_4,undefined4 param_5,
          undefined4 param_6,float param_7)

{
  float *pfVar1;
  CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>> *this;
  int iVar2;
  int iVar3;
  int *piVar4;
  CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>> *pCVar5;
  int unaff_EBX;
  float local_40;
  float local_3c;
  float local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x760ddb;
  __i686_get_pc_thunk_bx();
  iVar3 = unaff_EBX + 0x591005 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */;
  iVar2 = (**(code **)(*(int *)(unaff_EBX + 0x591005 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(iVar3);
  if (iVar2 != 0) {
    piVar4 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
    (**(code **)(*piVar4 + 200))(piVar4);
    DevMsg((char *)(unaff_EBX + 0x225c95 /* "Bot %i - ADD Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - ADD Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - ADD Movement Request: %3.1f , %3.1f 
" */));
  }
  this = (CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>> *)param_1[0x124a];
  if (0 < (int)this) {
    iVar2 = 0;
    pCVar5 = (CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>> *)0x0;
    do {
      pfVar1 = (float *)(param_1[0x1247] + iVar2);
      if (((param_2 == *pfVar1) && (param_3 == pfVar1[1])) && (param_4 == pfVar1[2])) {
        param_7 = param_7 + *(float *)(**(int **)(unaff_EBX + 0x445ac5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
        if (param_7 <= pfVar1[5]) {
          param_7 = pfVar1[5];
        }
        pfVar1[5] = param_7;
        iVar3 = (**(code **)(*(int *)(unaff_EBX + 0x591005 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(iVar3);
        if (iVar3 == 0) {
          return;
        }
        NDebugOverlay::Sphere((Vector *)(iVar2 + param_1[0x1247]),5.0,199,0x98,0x10,true,5.0);
        return;
      }
      pCVar5 = pCVar5 + 1;
      iVar2 = iVar2 + 0x24;
    } while (pCVar5 != this);
  }
  local_34 = 0;
  local_33 = 0;
  local_32 = 0;
  local_28 = param_5;
  local_20 = 0;
  local_24 = param_6;
  local_2c = param_7 + *(float *)(**(int **)(unaff_EBX + 0x445ac5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  local_30 = *(undefined4 *)(**(int **)(unaff_EBX + 0x445ac5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  local_40 = param_2;
  local_3c = param_3;
  local_38 = param_4;
  CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>>::InsertBefore
            (this,(int)(param_1 + 0x1247),(INSBotMovementRequest *)this);
  iVar3 = (**(code **)(*(int *)(unaff_EBX + 0x591005 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(iVar3);
  if (iVar3 == 0) {
    return;
  }
  NDebugOverlay::Sphere((Vector *)&local_40,5.0,0x6b,0xba,0x70,true,5.0);
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::AdjustPosture
 * Address: 0075f7b0
 * ---------------------------------------- */

/* CINSBotLocomotion::AdjustPosture(Vector const&) */

void __cdecl CINSBotLocomotion::AdjustPosture(Vector *param_1)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  CINSBotLocomotion *this;
  CINSBotLocomotion *this_00;
  CINSBotLocomotion *this_01;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  iVar3 = (**(code **)(*piVar2 + 200))(piVar2);
  if (iVar3 != 0) {
    piVar2 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    iVar3 = (**(code **)(*piVar2 + 200))(piVar2);
    if ((((iVar3 != 0) &&
         (piVar2 = (int *)__dynamic_cast(iVar3,*(undefined4 *)(unaff_EBX + 0x446f15 /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */),
                                         *(undefined4 *)(unaff_EBX + 0x44726d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0),
         piVar2 != (int *)0x0)) &&
        (piVar2 = (int *)(**(code **)(*piVar2 + 0x970 /* CINSNextBot::GetBodyInterface */))(piVar2), piVar2 != (int *)0x0)) &&
       (iVar3 = GetCurrentMovementRequest(this), iVar3 != -1)) {
      iVar4 = GetMovementStance(this_00,param_1);
      if (*(float *)(param_1 + 0x4974) <= 0.0) {
        if (iVar4 == 0xc) {
          uVar5 = GetDesiredPostureForRequest(this_01,(int)param_1);
          cVar1 = (**(code **)(*piVar2 + 0x11c /* CINSNextBot::Event_Killed */))(piVar2,iVar3);
          if ((cVar1 != '\0') &&
             (cVar1 = (**(code **)(*piVar2 + 0x124 /* CBaseCombatCharacter::BloodColor */))(piVar2,uVar5), cVar1 != '\0')) {
            return;
          }
          cVar1 = (**(code **)(*piVar2 + 0x118 /* CBaseEntity::IsAlive */))(piVar2,uVar5);
          if (cVar1 != '\0') {
            return;
          }
          (**(code **)(*piVar2 + 0x110 /* CINSPlayer::OnTakeDamage */))(piVar2,uVar5);
          return;
        }
      }
      else if ((iVar4 == 2) || (iVar4 == 0xc)) {
        (**(code **)(*piVar2 + 0x110 /* CINSPlayer::OnTakeDamage */))(piVar2,0xc);
        if (*(int *)(param_1 + 0x4974) == -0x40800000 /* -1.0f */) {
          return;
        }
        (**(code **)(*(int *)(param_1 + 0x496c) + 4))(param_1 + 0x496c,param_1 + 0x4974);
        *(undefined4 *)(param_1 + 0x4974) = 0xbf800000 /* -1.0f */;
        return;
      }
      (**(code **)(*piVar2 + 0x110 /* CINSPlayer::OnTakeDamage */))(piVar2,6);
      fVar6 = (float10)CountdownTimer::Now();
      fVar7 = (float)fVar6 + *(float *)(unaff_EBX + 0x1c4fa5 /* 4.0f */ /* 4.0f */ /* 4.0f */);
      if (*(float *)(param_1 + 0x4974) != fVar7) {
        (**(code **)(*(int *)(param_1 + 0x496c) + 4))(param_1 + 0x496c,param_1 + 0x4974);
        *(float *)(param_1 + 0x4974) = fVar7;
      }
      if (*(int *)(param_1 + 0x4970) != 0x40800000 /* 4.0f */) {
        (**(code **)(*(int *)(param_1 + 0x496c) + 4))(param_1 + 0x496c,param_1 + 0x4970);
        *(undefined4 *)(param_1 + 0x4970) = 0x40800000 /* 4.0f */;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::ApplyMovementRequest
 * Address: 0075ec30
 * ---------------------------------------- */

/* CINSBotLocomotion::ApplyMovementRequest(int) */

void __thiscall CINSBotLocomotion::ApplyMovementRequest(CINSBotLocomotion *this,int param_1)

{
  int iVar1;
  int *piVar2;
  CINSBotLocomotion *extraout_ECX;
  CINSBotLocomotion *this_00;
  CINSBotLocomotion *this_01;
  CINSBotLocomotion *extraout_ECX_00;
  int unaff_EBX;
  int in_stack_00000008;
  int local_20;
  
  __i686_get_pc_thunk_bx();
  if ((((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 0x4928))) &&
      (iVar1 = (**(code **)(*(int *)param_1 + 0xc4))(param_1), iVar1 != 0)) &&
     ((iVar1 = (**(code **)(*(int *)param_1 + 0xc4))(param_1), iVar1 != 0 &&
      (iVar1 = __dynamic_cast(iVar1,*(undefined4 *)(unaff_EBX + 0x44838c /* &typeinfo for INextBot */ /* &typeinfo for INextBot */ /* &typeinfo for INextBot */),
                              *(undefined4 *)(unaff_EBX + 0x447de4 /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0x2060), iVar1 != 0)))) {
    iVar1 = (**(code **)(*(int *)(unaff_EBX + 0x59319c /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(unaff_EBX + 0x59319c /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */);
    this_00 = extraout_ECX;
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
      (**(code **)(*piVar2 + 200))(piVar2);
      DevMsg((char *)(CWeaponLowerZone::StartTouch + unaff_EBX));
      this_00 = extraout_ECX_00;
    }
    local_20 = in_stack_00000008 * 0x24;
    iVar1 = GetCurrentMovementRequest(this_00);
    if ((in_stack_00000008 != iVar1) && (iVar1 != -1)) {
      OnCompletedMovementRequest(this_01,param_1);
    }
    *(undefined1 *)(*(int *)(param_1 + 0x491c) + 0xc + local_20) = 1;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::Approach
 * Address: 0075da20
 * ---------------------------------------- */

/* CINSBotLocomotion::Approach(Vector const&, float) */

void __thiscall CINSBotLocomotion::Approach(CINSBotLocomotion *this,Vector *param_1,float param_2)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  float *pfVar6;
  Vector *pVVar7;
  int *piVar8;
  float fVar9;
  CBasePlayer *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBaseEntity *pCVar10;
  CBaseEntity *this_04;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  int unaff_EBX;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  undefined4 in_stack_0000000c;
  undefined4 uVar16;
  undefined4 uVar17;
  float local_74;
  float local_70;
  float local_6c;
  float local_60;
  float local_58;
  float local_54;
  float local_4c;
  float local_48;
  undefined4 local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75da2b;
  __i686_get_pc_thunk_bx();
  iVar3 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
  if ((iVar3 != 0) && ((Vector *)(iVar3 + -0x2060) != (Vector *)0x0)) {
    ILocomotion::Approach(param_1,param_2);
    fVar11 = (float10)CountdownTimer::Now();
    if (*(float *)(param_1 + 0x4968) <= (float)fVar11 &&
        (float)fVar11 != *(float *)(param_1 + 0x4968)) {
      (**(code **)(*(int *)param_1 + 0x1a0))(param_1,param_2,in_stack_0000000c);
      fVar11 = (float10)CountdownTimer::Now();
      fVar9 = (float)fVar11 + *(float *)(unaff_EBX + 0x1c6d2d /* 0.5f */ /* 0.5f */ /* 0.5f */);
      if (*(float *)(param_1 + 0x4968) != fVar9) {
        (**(code **)(*(int *)(param_1 + 0x4960) + 4))(param_1 + 0x4960,param_1 + 0x4968);
        *(float *)(param_1 + 0x4968) = fVar9;
      }
      if (*(int *)(param_1 + 0x4964) != 0x3f000000 /* 0.5f */) {
        (**(code **)(*(int *)(param_1 + 0x4960) + 4))(param_1 + 0x4960,param_1 + 0x4964);
        *(undefined4 *)(param_1 + 0x4964) = 0x3f000000 /* 0.5f */;
      }
    }
    piVar4 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    cVar2 = (**(code **)(*piVar4 + 0x140))(piVar4,0x10);
    if (cVar2 == '\0') {
      iVar5 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
    }
    else {
      pVVar7 = (Vector *)(**(code **)(*(int *)param_1 + 0x148))(param_1);
      NDebugOverlay::Line(pVVar7,(Vector *)param_2,0xff,0xff,0,true,0.1);
      iVar5 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
    }
    if ((iVar5 == 0) ||
       (piVar4 = (int *)__dynamic_cast(iVar5,*(undefined4 *)(unaff_EBX + 0x4495a5 /* &typeinfo for INextBot */ /* &typeinfo for INextBot */ /* &typeinfo for INextBot */),
                                       unaff_EBX + 0x43e43d /* typeinfo for INextBotPlayerInput */ /* typeinfo for INextBotPlayerInput */ /* typeinfo for INextBotPlayerInput */,0xfffffffe), piVar4 == (int *)0x0)) {
      DevMsg((char *)(unaff_EBX + 0x228f49 /* "PlayerLocomotion::Approach: No INextBotPlayerInput
 " */ /* "PlayerLocomotion::Approach: No INextBotPlayerInput
 " */ /* "PlayerLocomotion::Approach: No INextBotPlayerInput
 " */));
    }
    else {
      pVVar7 = (Vector *)&local_58;
      uVar17 = 0;
      uVar16 = 0;
      CBasePlayer::EyeVectors(this_00,(Vector *)(iVar3 + -0x2060),pVVar7,(Vector *)0x0);
      local_6c = SQRT(local_54 * local_54 + local_58 * local_58);
      if (local_6c == 0.0) {
        local_74 = *(float *)(unaff_EBX + 0x1cb78d /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */);
        local_6c = 0.0;
        local_70 = 0.0;
      }
      else {
        local_6c = *(float *)(unaff_EBX + 0x15b0e9 /* 1.0f */ /* 1.0f */ /* 1.0f */) / local_6c;
        local_70 = local_58 * local_6c;
        local_6c = local_6c * local_54;
        local_74 = (float)((uint)local_70 ^ *(uint *)(unaff_EBX + 0x1c71d5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */));
      }
      pfVar6 = (float *)(**(code **)(*(int *)param_1 + 0x148))(param_1,pVVar7,uVar16,uVar17);
      fVar9 = 0.0;
      fVar13 = *(float *)param_2 - *pfVar6;
      fVar12 = *(float *)((int)param_2 + 4) - pfVar6[1];
      fVar14 = SQRT(fVar12 * fVar12 + fVar13 * fVar13);
      if (fVar14 == 0.0) {
        local_60 = 0.0;
      }
      else {
        fVar15 = *(float *)(unaff_EBX + 0x15b0e9 /* 1.0f */ /* 1.0f */ /* 1.0f */) / fVar14;
        fVar13 = fVar13 * fVar15;
        fVar15 = fVar15 * fVar12;
        fVar9 = local_6c * fVar15 + local_70 * fVar13;
        local_60 = fVar13 * local_6c + fVar15 * local_74;
      }
      iVar5 = (**(code **)(**(int **)(&DAT_00448e79 + unaff_EBX) + 0x40))
                        (*(int **)(&DAT_00448e79 + unaff_EBX));
      fVar12 = *(float *)(unaff_EBX + 0x1c6d2d /* 0.5f */ /* 0.5f */ /* 0.5f */);
      if ((iVar5 != 0) && (fVar12 < fVar14)) {
        (**(code **)(*piVar4 + 0x60))(piVar4,fVar9,local_60);
      }
      if (fVar12 < fVar9) {
        pcVar1 = *(code **)(*piVar4 + 0x28);
        piVar8 = (int *)(*(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */))[7];
        if (piVar8 == *(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */)) {
          fVar9 = (float)((uint)piVar8 ^ piVar8[0xb]);
        }
        else {
          fVar11 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
          fVar9 = (float)fVar11;
        }
        (*pcVar1)(piVar4,fVar9 + *(float *)(CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
                                            ::RotateLeft + unaff_EBX + 5));
        piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
        cVar2 = (**(code **)(*piVar8 + 0x140))(piVar8,0x10);
        fVar13 = *(float *)(unaff_EBX + 0x1caefd /* -0.5f */ /* -0.5f */ /* -0.5f */);
        if (cVar2 != '\0') {
          fVar9 = *(float *)(unaff_EBX + 0x15b555 /* 50.0f */ /* 50.0f */ /* 50.0f */);
          pCVar10 = this_02;
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_02);
            pCVar10 = extraout_ECX_01;
          }
          local_4c = local_70 * fVar9 + *(float *)(iVar3 + -0x1e58);
          local_48 = fVar9 * local_6c + *(float *)(iVar3 + -0x1e54);
          local_44 = *(undefined4 *)(iVar3 + -0x1e50);
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(pCVar10);
          }
          NDebugOverlay::HorzArrow
                    ((Vector *)(iVar3 + -0x1e58),(Vector *)&local_4c,15.0,0,0xff,0,0xff,true,0.1);
          fVar13 = *(float *)(unaff_EBX + 0x1caefd /* -0.5f */ /* -0.5f */ /* -0.5f */);
        }
      }
      else {
        fVar13 = *(float *)(unaff_EBX + 0x1caefd /* -0.5f */ /* -0.5f */ /* -0.5f */);
        if (fVar9 < fVar13) {
          pcVar1 = *(code **)(*piVar4 + 0x30);
          piVar8 = (int *)(*(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */))[7];
          if (piVar8 == *(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */)) {
            fVar9 = (float)((uint)piVar8 ^ piVar8[0xb]);
          }
          else {
            fVar11 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
            fVar9 = (float)fVar11;
          }
          (*pcVar1)(piVar4,fVar9 + *(float *)(CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
                                              ::RotateLeft + unaff_EBX + 5));
          piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
          cVar2 = (**(code **)(*piVar8 + 0x140))(piVar8,0x10);
          if (cVar2 != '\0') {
            fVar9 = *(float *)(unaff_EBX + 0x15b555 /* 50.0f */ /* 50.0f */ /* 50.0f */);
            pCVar10 = this_04;
            if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_04);
              pCVar10 = extraout_ECX;
            }
            local_40 = *(float *)(iVar3 + -0x1e58) - local_70 * fVar9;
            local_3c = *(float *)(iVar3 + -0x1e54) - fVar9 * local_6c;
            local_38 = *(undefined4 *)(iVar3 + -0x1e50);
            if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(pCVar10);
            }
            NDebugOverlay::HorzArrow
                      ((Vector *)(iVar3 + -0x1e58),(Vector *)&local_40,15.0,0xff,0,0,0xff,true,0.1);
          }
        }
      }
      if (local_60 <= fVar13) {
        pcVar1 = *(code **)(*piVar4 + 0x38);
        piVar8 = (int *)(*(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */))[7];
        if (piVar8 == *(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */)) {
          fVar9 = (float)((uint)piVar8 ^ piVar8[0xb]);
        }
        else {
          fVar11 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
          fVar9 = (float)fVar11;
        }
        (*pcVar1)(piVar4,fVar9 + *(float *)(CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
                                            ::RotateLeft + unaff_EBX + 5));
        piVar4 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
        cVar2 = (**(code **)(*piVar4 + 0x140))(piVar4,0x10);
        if (cVar2 != '\0') {
          fVar9 = *(float *)(unaff_EBX + 0x15b555 /* 50.0f */ /* 50.0f */ /* 50.0f */);
          pCVar10 = this_01;
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_01);
            pCVar10 = extraout_ECX_02;
          }
          local_34 = *(float *)(iVar3 + -0x1e58) - local_6c * fVar9;
          local_30 = *(float *)(iVar3 + -0x1e54) - local_74 * fVar9;
          local_2c = *(undefined4 *)(iVar3 + -0x1e50);
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(pCVar10);
          }
          NDebugOverlay::HorzArrow
                    ((Vector *)(iVar3 + -0x1e58),(Vector *)&local_34,15.0,0xff,0,0xff,0xff,true,0.1)
          ;
        }
      }
      else if (fVar12 <= local_60) {
        pcVar1 = *(code **)(*piVar4 + 0x40);
        piVar8 = (int *)(*(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */))[7];
        if (piVar8 == *(int **)(unaff_EBX + 0x449365 /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */ /* &ins_bot_path_update_interval */)) {
          fVar9 = (float)((uint)piVar8 ^ piVar8[0xb]);
        }
        else {
          fVar11 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
          fVar9 = (float)fVar11;
        }
        (*pcVar1)(piVar4,fVar9 + *(float *)(CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
                                            ::RotateLeft + unaff_EBX + 5));
        piVar4 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
        cVar2 = (**(code **)(*piVar4 + 0x140))(piVar4,0x10);
        if (cVar2 != '\0') {
          fVar9 = *(float *)(unaff_EBX + 0x15b555 /* 50.0f */ /* 50.0f */ /* 50.0f */);
          pCVar10 = this_03;
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_03);
            pCVar10 = extraout_ECX_00;
          }
          local_28 = local_6c * fVar9 + *(float *)(iVar3 + -0x1e58);
          local_24 = fVar9 * local_74 + *(float *)(iVar3 + -0x1e54);
          local_20 = *(undefined4 *)(iVar3 + -0x1e50);
          if ((*(byte *)(iVar3 + -0x1f8f) & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(pCVar10);
          }
          NDebugOverlay::HorzArrow
                    ((Vector *)(iVar3 + -0x1e58),(Vector *)&local_28,15.0,0,0xff,0xff,0xff,true,0.1)
          ;
        }
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::AreAdjacentAreasOccupied
 * Address: 0075e920
 * ---------------------------------------- */

/* CINSBotLocomotion::AreAdjacentAreasOccupied(CINSNavArea const*) const */

undefined4 __thiscall
CINSBotLocomotion::AreAdjacentAreasOccupied(CINSBotLocomotion *this,CINSNavArea *param_1)

{
  int iVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int unaff_EBX;
  int iVar7;
  int in_stack_00000008;
  int local_28;
  
  __i686_get_pc_thunk_bx();
  iVar4 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
  if ((iVar4 == 0) || ((CBaseEntity *)(iVar4 + -0x2060) == (CBaseEntity *)0x0)) {
    return 0;
  }
  local_28 = 0;
  do {
    iVar1 = in_stack_00000008 + 0x60 + local_28 * 4;
    piVar5 = *(int **)(iVar1 + 0xc);
    if (0 < *piVar5) {
      iVar7 = 0;
      do {
        iVar2 = piVar5[iVar7 * 2 + 1];
        iVar6 = CBaseEntity::GetTeamNumber((CBaseEntity *)(iVar4 + -0x2060));
        if (iVar6 == 0) {
          cVar3 = *(char *)(iVar2 + 0x4d) + *(char *)(iVar2 + 0x4c);
        }
        else {
          cVar3 = *(char *)(iVar2 + 0x4c + iVar6 % 2);
        }
        if (cVar3 != '\0') {
          DevMsg(&UNK_00227ff9 + unaff_EBX);
          return 1;
        }
        iVar7 = iVar7 + 1;
        piVar5 = *(int **)(iVar1 + 0xc);
      } while (iVar7 < *piVar5);
    }
    local_28 = local_28 + 1;
    if (local_28 == 4) {
      return 0;
    }
  } while( true );
}



/* ----------------------------------------
 * CINSBotLocomotion::ClearMovementRequests
 * Address: 0075fa10
 * ---------------------------------------- */

/* CINSBotLocomotion::ClearMovementRequests(INSBotPriority) */

void __thiscall CINSBotLocomotion::ClearMovementRequests(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  CINSPathFollower *extraout_ECX;
  CINSPathFollower *extraout_ECX_00;
  CINSPathFollower *this;
  int iVar2;
  int iVar3;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(param_2 + 0x4928) + -1;
  if (-1 < iVar2) {
    iVar3 = iVar2 * 0x24;
    this = extraout_ECX;
    do {
      iVar1 = iVar3 + *(int *)(param_2 + 0x491c);
      if (*(int *)(iVar1 + 0x1c) <= param_3) {
        if (*(char *)(iVar1 + 0xc) != '\0') {
          CINSPathFollower::Invalidate(this);
        }
        CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>>::Remove
                  (param_2 + 0x491c);
        this = extraout_ECX_00;
      }
      iVar2 = iVar2 + -1;
      iVar3 = iVar3 + -0x24;
    } while (iVar2 != -1);
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::FaceTowards
 * Address: 0075d6b0
 * ---------------------------------------- */

/* CINSBotLocomotion::FaceTowards(Vector const&) */

void __thiscall CINSBotLocomotion::FaceTowards(CINSBotLocomotion *this,Vector *param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int unaff_EBX;
  undefined4 *in_stack_00000008;
  undefined1 local_34 [8];
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75d6bb;
  __i686_get_pc_thunk_bx();
  piVar1 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  piVar2 = (int *)(**(code **)(*piVar1 + 200))(piVar1);
  (**(code **)(*piVar2 + 0x20c /* CINSNextBot::EyePosition */))(local_34,piVar2);
  piVar1 = (int *)(**(code **)(*piVar1 + 0xd0))(piVar1);
  iVar3 = (**(code **)(*piVar1 + 0x148))(piVar1);
  local_20 = (local_2c + (float)in_stack_00000008[2]) - *(float *)(iVar3 + 8);
  local_24 = in_stack_00000008[1];
  local_28 = *in_stack_00000008;
  piVar1 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  piVar1 = (int *)(**(code **)(*piVar1 + 0xd4))(piVar1);
  (**(code **)(*piVar1 + 0xd4))(piVar1,&local_28,0,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x22925d /* "Body facing" */ /* "Body facing" */ /* "Body facing" */);
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetBehaviorStance
 * Address: 0075fa00
 * ---------------------------------------- */

/* CINSBotLocomotion::GetBehaviorStance() */

undefined4 CINSBotLocomotion::GetBehaviorStance(void)

{
  return 0xc;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetCurrentMovementPosition
 * Address: 0075ead0
 * ---------------------------------------- */

/* CINSBotLocomotion::GetCurrentMovementPosition() */

void __thiscall CINSBotLocomotion::GetCurrentMovementPosition(CINSBotLocomotion *this)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  puVar1 = *(undefined4 **)(unaff_EBX + 0x447af3 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *in_stack_00000004 = *puVar1;
  uVar2 = puVar1[2];
  in_stack_00000004[1] = puVar1[1];
  in_stack_00000004[2] = uVar2;
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetCurrentMovementProgress
 * Address: 0075eb00
 * ---------------------------------------- */

/* CINSBotLocomotion::GetCurrentMovementProgress() */

float10 CINSBotLocomotion::GetCurrentMovementProgress(void)

{
  return (float10)0;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetCurrentMovementRequest
 * Address: 0075ea70
 * ---------------------------------------- */

/* CINSBotLocomotion::GetCurrentMovementRequest() */

int __thiscall CINSBotLocomotion::GetCurrentMovementRequest(CINSBotLocomotion *this)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_stack_00000004;
  
  iVar4 = -1;
  iVar3 = *(int *)(in_stack_00000004 + 0x4928);
  if (((iVar3 != 0) && (iVar4 = 0, iVar3 != 1)) && (iVar4 = -1, 0 < iVar3)) {
    iVar4 = 0;
    iVar5 = 0x24;
    cVar2 = *(char *)(*(int *)(in_stack_00000004 + 0x491c) + 0xc);
    while (cVar2 == '\0') {
      iVar4 = iVar4 + 1;
      if (iVar4 == iVar3) {
        return -1;
      }
      pcVar1 = (char *)(*(int *)(in_stack_00000004 + 0x491c) + 0xc + iVar5);
      iVar5 = iVar5 + 0x24;
      cVar2 = *pcVar1;
    }
  }
  return iVar4;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetDeathDropHeight
 * Address: 0075d640
 * ---------------------------------------- */

/* CINSBotLocomotion::GetDeathDropHeight() const */

float10 CINSBotLocomotion::GetDeathDropHeight(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return (float10)*(float *)(extraout_ECX + 0x2294b3 /* 260.0f */ /* 260.0f */ /* 260.0f */);
}



/* ----------------------------------------
 * CINSBotLocomotion::GetDesiredPostureForRequest
 * Address: 0075ef30
 * ---------------------------------------- */

/* CINSBotLocomotion::GetDesiredPostureForRequest(int) */

undefined4 __thiscall
CINSBotLocomotion::GetDesiredPostureForRequest(CINSBotLocomotion *this,int param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  piVar1 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  iVar2 = (**(code **)(*piVar1 + 200))(piVar1);
  if (iVar2 != 0) {
    piVar1 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    iVar2 = (**(code **)(*piVar1 + 200))(piVar1);
    if ((((iVar2 != 0) &&
         (piVar1 = (int *)__dynamic_cast(iVar2,*(undefined4 *)(unaff_EBX + 0x44778c /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */),
                                         *(undefined4 *)(unaff_EBX + 0x447ae4 /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0),
         piVar1 != (int *)0x0)) && (iVar2 = (**(code **)(*piVar1 + 0x970 /* CINSNextBot::GetBodyInterface */))(piVar1), iVar2 != 0)) &&
       (iVar2 = *(int *)(param_1 + 0x491c) + in_stack_00000008 * 0x24, *(uint *)(iVar2 + 0x18) < 9))
    {
                    /* WARNING: Could not recover jumptable at 0x0075f00c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar3 = (*(code *)(&UNK_00448234 +
                        *(int *)(unaff_EBX + 0x227b7c /* CSWTCH.663+0x1f4 */ /* CSWTCH.663+0x1f4 */ /* CSWTCH.663+0x1f4 */ + *(int *)(iVar2 + 0x18) * 4) + unaff_EBX))();
      return uVar3;
    }
  }
  return 0xc;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetMaxJumpHeight
 * Address: 0075d660
 * ---------------------------------------- */

/* CINSBotLocomotion::GetMaxJumpHeight() const */

float10 CINSBotLocomotion::GetMaxJumpHeight(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return (float10)*(float *)(extraout_ECX + 0x1e03a3 /* 48.0f */ /* 48.0f */ /* 48.0f */);
}



/* ----------------------------------------
 * CINSBotLocomotion::GetMovementStance
 * Address: 0075f0d0
 * ---------------------------------------- */

/* CINSBotLocomotion::GetMovementStance(Vector const&) */

char __thiscall CINSBotLocomotion::GetMovementStance(CINSBotLocomotion *this,Vector *param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  int *piVar8;
  float *pfVar9;
  CTraceFilterSimple *this_00;
  int unaff_EBX;
  float10 fVar10;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float *in_stack_00000008;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined1 local_f0 [44];
  float local_c4;
  char local_b9;
  undefined4 local_a4;
  float local_9c;
  float local_98;
  float local_94;
  float local_8c;
  float local_88;
  float local_84;
  uint local_7c;
  uint local_78;
  uint local_74;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_5c;
  undefined1 local_58;
  undefined1 local_57;
  undefined *local_4c [4];
  int *local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75f0db;
  __i686_get_pc_thunk_bx();
  piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  iVar6 = (**(code **)(*piVar5 + 200))(piVar5);
  cVar4 = '\f';
  if (iVar6 != 0) {
    piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    iVar6 = (**(code **)(*piVar5 + 200))(piVar5);
    if (iVar6 != 0) {
      piVar5 = (int *)__dynamic_cast(iVar6,*(undefined4 *)(unaff_EBX + 0x4475f5 /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */ /* &typeinfo for CBaseCombatCharacter */),
                                     *(undefined4 *)(unaff_EBX + 0x44794d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0);
      if (piVar5 != (int *)0x0) {
        piVar5 = (int *)(**(code **)(*piVar5 + 0x970 /* CINSNextBot::GetBodyInterface */))(piVar5);
        if (piVar5 != (int *)0x0) {
          fVar10 = (float10)(**(code **)(*(int *)param_1 + 0x14c))(param_1);
          pfVar7 = (float *)(**(code **)(*piVar5 + 0x14c /* PlayerBody::GetHullMins */))(piVar5);
          fVar13 = pfVar7[1];
          fVar16 = (float)fVar10 + pfVar7[2];
          fVar15 = *pfVar7;
          fVar10 = (float10)(**(code **)(*piVar5 + 0x13c /* CINSBotBody::GetHullWidth */))(piVar5);
          fVar19 = *(float *)(unaff_EBX + 0x1c567d /* 0.5f */ /* 0.5f */ /* 0.5f */);
          fVar12 = (float)fVar10 * fVar19;
          fVar10 = (float10)(**(code **)(*piVar5 + 0x144 /* PlayerBody::GetStandHullHeight */))(piVar5);
          local_a4 = 0;
          piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
          iVar6 = (**(code **)(*piVar8 + 200))(piVar8);
          uVar25 = 0;
          uVar24 = 0;
          CTraceFilterSimple::CTraceFilterSimple
                    (this_00,(IHandleEntity *)local_4c,iVar6,(_func_bool_IHandleEntity_ptr_int *)0x0
                    );
          local_4c[0] = &UNK_0043550d + unaff_EBX;
          local_38 = 0;
          local_3c = piVar8;
          pfVar7 = (float *)(**(code **)(*(int *)param_1 + 0x114))(param_1,iVar6,uVar24,uVar25);
          pfVar9 = (float *)(**(code **)(*(int *)param_1 + 0x148))(param_1);
          local_34 = *in_stack_00000008 - *pfVar9;
          local_30 = in_stack_00000008[1] - pfVar9[1];
          local_2c = in_stack_00000008[2] - pfVar9[2];
          fVar11 = (float10)VectorNormalize((Vector *)&local_34);
          fVar18 = (float)fVar11;
          fVar14 = (float)((uint)local_30 ^ *(uint *)(unaff_EBX + 0x1c5b25 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */));
          local_20 = pfVar7[1] * fVar14 - *pfVar7 * local_34;
          local_28 = local_34 * pfVar7[2];
          local_24 = (float)((uint)(fVar14 * pfVar7[2]) ^ *(uint *)(unaff_EBX + 0x1c5b25 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */));
          VectorNormalize((Vector *)&local_28);
          fVar14 = local_28 * fVar18 + *pfVar9;
          fVar17 = local_24 * fVar18 + pfVar9[1];
          fVar22 = fVar18 * local_20 + pfVar9[2];
          uVar24 = (**(code **)(*piVar5 + 0x154 /* PlayerBody::GetSolidMask */))(piVar5);
          local_5c = 0;
          puVar1 = (uint *)(unaff_EBX + 0x1c5b25 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */);
          local_8c = fVar14 - *pfVar9;
          local_88 = fVar17 - pfVar9[1];
          local_84 = fVar22 - pfVar9[2];
          fVar20 = (fVar12 - fVar15) * fVar19;
          local_57 = local_88 * local_88 + local_8c * local_8c + local_84 * local_84 != 0.0;
          fVar18 = (fVar12 - fVar13) * fVar19;
          local_64 = ((float)fVar10 - fVar16) * fVar19;
          fVar21 = ((float)fVar10 + fVar16) * fVar19;
          fVar23 = fVar20 * fVar20 + fVar18 * fVar18;
          local_58 = (double)(local_64 * local_64 + fVar23) < *(double *)(unaff_EBX + 0x1c7acd /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */);
          fVar15 = (fVar15 + fVar12) * fVar19;
          fVar13 = (fVar12 + fVar13) * fVar19;
          local_9c = *pfVar9 + fVar15;
          local_98 = pfVar9[1] + fVar13;
          local_94 = pfVar9[2] + fVar21;
          local_74 = (uint)fVar21 ^ *puVar1;
          uVar2 = *puVar1;
          uVar3 = *puVar1;
          local_7c = (uint)fVar15 ^ uVar2;
          local_78 = (uint)fVar13 ^ uVar3;
          local_6c = fVar20;
          local_68 = fVar18;
          (**(code **)(*(int *)**(undefined4 **)(&DAT_0044769d + unaff_EBX) + 0x14))
                    ((int *)**(undefined4 **)(&DAT_0044769d + unaff_EBX),&local_9c,uVar24,local_4c,
                     local_f0);
          if ((local_c4 < *(float *)(unaff_EBX + 0x159a39 /* 1.0f */ /* 1.0f */ /* 1.0f */)) || (local_b9 != '\0')) {
            fVar10 = (float10)(**(code **)(*piVar5 + 0x148 /* PlayerBody::GetCrouchHullHeight */))(piVar5);
            uVar24 = (**(code **)(*piVar5 + 0x154 /* PlayerBody::GetSolidMask */))(piVar5);
            local_5c = 0;
            local_8c = fVar14 - *pfVar9;
            local_88 = fVar17 - pfVar9[1];
            local_84 = fVar22 - pfVar9[2];
            local_64 = ((float)fVar10 - fVar16) * fVar19;
            local_57 = local_88 * local_88 + local_8c * local_8c + local_84 * local_84 != 0.0;
            local_58 = (double)(local_64 * local_64 + fVar23) < *(double *)(unaff_EBX + 0x1c7acd /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */);
            fVar19 = ((float)fVar10 + fVar16) * fVar19;
            local_9c = fVar15 + *pfVar9;
            local_98 = fVar13 + pfVar9[1];
            local_94 = pfVar9[2] + fVar19;
            local_74 = (uint)fVar19 ^ *(uint *)(unaff_EBX + 0x1c5b25 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */);
            local_7c = (uint)fVar15 ^ uVar2;
            local_78 = (uint)fVar13 ^ uVar3;
            local_6c = fVar20;
            local_68 = fVar18;
            (**(code **)(*(int *)**(undefined4 **)(&DAT_0044769d + unaff_EBX) + 0x14))
                      ((int *)**(undefined4 **)(&DAT_0044769d + unaff_EBX),&local_9c,uVar24,local_4c
                       ,local_f0);
            if (local_c4 < *(float *)(unaff_EBX + 0x159a39 /* 1.0f */ /* 1.0f */ /* 1.0f */)) {
              cVar4 = '\x02';
            }
            else {
              cVar4 = (-(local_b9 == '\0') & 4U) + 2;
            }
          }
        }
      }
    }
  }
  return cVar4;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetRunSpeed
 * Address: 0075d680
 * ---------------------------------------- */

/* CINSBotLocomotion::GetRunSpeed() const */

void __thiscall CINSBotLocomotion::GetRunSpeed(CINSBotLocomotion *this)

{
  int iVar1;
  int *piVar2;
  int *in_stack_00000004;
  
  iVar1 = (**(code **)(*in_stack_00000004 + 0xc4))();
  piVar2 = (int *)0x0;
  if (iVar1 != 0) {
    piVar2 = (int *)(iVar1 + -0x2060);
  }
  (**(code **)(*piVar2 + 0x7a4 /* CBasePlayer::GetPlayerMaxSpeed */))(piVar2);
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::GetStillDuration
 * Address: 0075ea00
 * ---------------------------------------- */

/* CINSBotLocomotion::GetStillDuration() */

float10 __thiscall CINSBotLocomotion::GetStillDuration(CINSBotLocomotion *this)

{
  int unaff_EBX;
  float10 fVar1;
  float fVar2;
  int in_stack_00000004;
  
  fVar2 = 0.0;
  __i686_get_pc_thunk_bx();
  if (*(float *)(in_stack_00000004 + 0x4988) <= fVar2) {
    fVar2 = *(float *)(unaff_EBX + 0x15a0f9 /* -1.0f */ /* -1.0f */ /* -1.0f */);
  }
  else {
    fVar1 = (float10)IntervalTimer::Now();
    fVar2 = (float)fVar1 - *(float *)(in_stack_00000004 + 0x4988);
  }
  return (float10)fVar2;
}



/* ----------------------------------------
 * CINSBotLocomotion::IsAreaTraversable
 * Address: 0075d7b0
 * ---------------------------------------- */

/* CINSBotLocomotion::IsAreaTraversable(CINSNavArea const*) const */

bool __thiscall CINSBotLocomotion::IsAreaTraversable(CINSBotLocomotion *this,CINSNavArea *param_1)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  CBaseEntity *this_00;
  int *in_stack_00000008;
  
  piVar3 = (int *)__i686_get_pc_thunk_bx();
  iVar4 = (**(code **)(*piVar3 + 0xc4))(piVar3);
  if ((iVar4 != 0) && (iVar4 != 0x2060)) {
    pcVar1 = *(code **)(*in_stack_00000008 + 0x48);
    uVar5 = CBaseEntity::GetTeamNumber(this_00);
    cVar2 = (*pcVar1)(in_stack_00000008,uVar5,0);
    if (cVar2 == '\0') {
      return (*(byte *)(in_stack_00000008 + 0x1a) & 0x80) == 0;
    }
  }
  return false;
}



/* ----------------------------------------
 * CINSBotLocomotion::IsClimbPossible
 * Address: 0075d790
 * ---------------------------------------- */

/* CINSBotLocomotion::IsClimbPossible(INextBot*, CBaseEntity const*) const */

undefined4 __cdecl CINSBotLocomotion::IsClimbPossible(INextBot *param_1,CBaseEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotLocomotion::IsEntityTraversable
 * Address: 0075d840
 * ---------------------------------------- */

/* CINSBotLocomotion::IsEntityTraversable(CBaseEntity*, ILocomotion::TraverseWhenType) const */

undefined4 __thiscall
CINSBotLocomotion::IsEntityTraversable
          (undefined4 param_1_00,undefined4 param_1,int *param_3,undefined4 param_4)

{
  char cVar1;
  undefined4 uVar2;
  ILocomotion *extraout_ECX;
  ILocomotion *extraout_ECX_00;
  ILocomotion *pIVar3;
  
  __i686_get_pc_thunk_bx();
  pIVar3 = extraout_ECX;
  if (param_3 != (int *)0x0) {
    cVar1 = (**(code **)(*param_3 + 0x158))(param_3);
    pIVar3 = extraout_ECX_00;
    if (cVar1 != '\0') {
      return 1;
    }
  }
  uVar2 = ILocomotion::IsEntityTraversable(pIVar3,param_1,param_3,param_4);
  return uVar2;
}



/* ----------------------------------------
 * CINSBotLocomotion::IsPotentiallyTraversable
 * Address: 0075e500
 * ---------------------------------------- */

/* CINSBotLocomotion::IsPotentiallyTraversable(Vector const&, Vector const&,
   ILocomotion::TraverseWhenType, float*) const */

byte __thiscall
CINSBotLocomotion::IsPotentiallyTraversable
          (undefined4 param_1_00,int *param_1,float *param_2,float *param_4,undefined4 param_5,
          float *param_6)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  CTraceFilterSimple *this;
  int unaff_EBX;
  float10 fVar4;
  float10 fVar5;
  float fVar6;
  float fVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  float *local_f8;
  undefined1 local_ec [44];
  float local_c0;
  byte local_b5;
  undefined4 local_a0;
  float local_8c;
  float local_88;
  float local_84;
  float local_7c;
  float local_78;
  float local_74;
  undefined4 local_6c;
  undefined4 local_68;
  uint local_64;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_4c;
  undefined1 local_48;
  undefined1 local_47;
  int local_34 [4];
  int *local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75e50b;
  __i686_get_pc_thunk_bx();
  fVar7 = param_4[2];
  fVar6 = param_2[2];
  fVar4 = (float10)(**(code **)(*param_1 + 0x150))(param_1);
  if ((float)fVar4 + *(float *)(unaff_EBX + 0x15a611 /* 0.1f */ /* 0.1f */ /* 0.1f */) < fVar7 - fVar6) {
    local_8c = *param_4 - *param_2;
    local_88 = param_4[1] - param_2[1];
    local_84 = param_4[2] - param_2[2];
    VectorNormalize((Vector *)&local_8c);
    fVar7 = local_84;
    fVar4 = (float10)(**(code **)(*param_1 + 0x178))(param_1);
    if ((float)fVar4 < fVar7) {
      if (param_6 == (float *)0x0) {
        return 0;
      }
      *param_6 = 0.0;
      return 0;
    }
  }
  local_f8 = &local_8c;
  local_a0 = 0;
  piVar2 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
  iVar3 = (**(code **)(*piVar2 + 200))(piVar2);
  uVar9 = 0;
  uVar8 = 0;
  CTraceFilterSimple::CTraceFilterSimple
            (this,(IHandleEntity *)local_34,iVar3,(_func_bool_IHandleEntity_ptr_int *)0x0);
  local_34[0] = unaff_EBX + 0x4360dd /* vtable for NextBotTraversableTraceFilter+0x8 */ /* vtable for NextBotTraversableTraceFilter+0x8 */ /* vtable for NextBotTraversableTraceFilter+0x8 */;
  local_20 = param_5;
  local_24 = piVar2;
  piVar2 = (int *)(**(code **)(*param_1 + 0xc4))(param_1,iVar3,uVar8,uVar9);
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd4))(piVar2);
  fVar4 = (float10)(**(code **)(*piVar2 + 0x13c))(piVar2);
  fVar7 = *(float *)(unaff_EBX + 0x1c624d /* 0.5f */ /* 0.5f */ /* 0.5f */);
  fVar6 = (float)fVar4 * fVar7;
  fVar4 = (float10)(**(code **)(*param_1 + 0x14c))(param_1);
  piVar2 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd4))(piVar2);
  fVar5 = (float10)(**(code **)(*piVar2 + 0x148))(piVar2);
  piVar2 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd4))(piVar2);
  uVar8 = (**(code **)(*piVar2 + 0x154))(piVar2);
  local_4c = 0;
  local_8c = *param_2;
  local_88 = param_2[1];
  local_7c = *param_4 - local_8c;
  local_78 = param_4[1] - local_88;
  local_74 = param_4[2] - param_2[2];
  local_6c = 0;
  local_68 = 0;
  local_47 = local_78 * local_78 + local_7c * local_7c + local_74 * local_74 != 0.0;
  local_54 = ((float)fVar5 - (float)fVar4) * fVar7;
  local_48 = (double)(fVar6 * fVar6 + fVar6 * fVar6 + local_54 * local_54) <
             *(double *)(unaff_EBX + 0x1c869d /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */ /* rodata:0xA0B5ED8D */);
  fVar7 = ((float)fVar5 + (float)fVar4) * fVar7;
  local_84 = param_2[2] + fVar7;
  local_64 = (uint)fVar7 ^ *(uint *)(unaff_EBX + 0x1c66f5 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */);
  local_5c = fVar6;
  local_58 = fVar6;
  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44826d /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
            ((int *)**(undefined4 **)(unaff_EBX + 0x44826d /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),local_f8,uVar8,local_34,local_ec);
  if (param_6 != (float *)0x0) {
    *param_6 = local_c0;
  }
  bVar1 = 0;
  if (*(float *)(unaff_EBX + 0x15a609 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= local_c0) {
    bVar1 = local_b5 ^ 1;
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnCompletedMovementRequest
 * Address: 0075eb10
 * ---------------------------------------- */

/* CINSBotLocomotion::OnCompletedMovementRequest(int) */

void __thiscall CINSBotLocomotion::OnCompletedMovementRequest(CINSBotLocomotion *this,int param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 0x4928))) {
    iVar1 = (**(code **)(*(int *)(unaff_EBX + 0x5932bc /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(unaff_EBX + 0x5932bc /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */);
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
      (**(code **)(*piVar2 + 200))(piVar2);
      DevMsg((char *)(unaff_EBX + 0x227e88 /* "Bot %i - Completed Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - Completed Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - Completed Movement Request: %3.1f , %3.1f 
" */));
    }
    *(undefined1 *)(*(int *)(param_1 + 0x491c) + 0xc + in_stack_00000008 * 0x24) = 0;
    *(undefined1 *)(*(int *)(param_1 + 0x491c) + 0xd + in_stack_00000008 * 0x24) = 1;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::OnFailedMovementRequest
 * Address: 0075eda0
 * ---------------------------------------- */

/* CINSBotLocomotion::OnFailedMovementRequest(int) */

void __thiscall CINSBotLocomotion::OnFailedMovementRequest(CINSBotLocomotion *this,int param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 0x4928))) {
    iVar1 = (**(code **)(*(int *)(unaff_EBX + 0x59302c /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(unaff_EBX + 0x59302c /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */);
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
      (**(code **)(*piVar2 + 200))(piVar2);
      DevMsg((char *)(unaff_EBX + 0x227c64 /* "Bot %i - Failed Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - Failed Movement Request: %3.1f , %3.1f 
" */ /* "Bot %i - Failed Movement Request: %3.1f , %3.1f 
" */));
    }
    *(undefined1 *)(*(int *)(param_1 + 0x491c) + 0xc + in_stack_00000008 * 0x24) = 0;
    *(undefined1 *)(*(int *)(param_1 + 0x491c) + 0xe + in_stack_00000008 * 0x24) = 1;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::UpdateMovement
 * Address: 0075faa0
 * ---------------------------------------- */

/* CINSBotLocomotion::UpdateMovement() */

void __thiscall CINSBotLocomotion::UpdateMovement(CINSBotLocomotion *this)

{
  CINSPathFollower *this_00;
  byte bVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  CINSPathFollower *this_01;
  INextBot *pIVar7;
  uint uVar8;
  int *piVar9;
  CFmtStrN<256,false> *this_02;
  CINSBotLocomotion *extraout_ECX;
  CINSBotLocomotion *extraout_ECX_00;
  CINSBotLocomotion *this_03;
  CINSBotLocomotion *this_04;
  CINSBotLocomotion *extraout_ECX_01;
  CINSBotLocomotion *extraout_ECX_02;
  CINSPathFollower *this_05;
  CINSBotLocomotion *extraout_ECX_03;
  CINSBotLocomotion *this_06;
  CINSPathFollower *this_07;
  CINSBotLocomotion *extraout_ECX_04;
  CINSBotLocomotion *extraout_ECX_05;
  CINSBotLocomotion *this_08;
  CINSBotLocomotion *extraout_ECX_06;
  int unaff_EBX;
  CINSBotLocomotion *pCVar10;
  float10 fVar11;
  float fVar12;
  int *in_stack_00000004;
  undefined8 in_stack_fffffe6c;
  undefined4 uVar14;
  undefined8 uVar13;
  CINSBotLocomotion *local_154;
  float local_14c;
  CINSBotLocomotion *local_148;
  CINSBotLocomotion *local_144;
  float local_140;
  char local_134 [5];
  char local_12f [263];
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uVar14 = (undefined4)((ulonglong)in_stack_fffffe6c >> 0x20);
  uStack_14 = 0x75faab;
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  iVar4 = (**(code **)(*piVar3 + 200))(piVar3);
  if (iVar4 == 0) {
LAB_0075fe98:
    ClearMovementRequests();
    return;
  }
  piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3);
  cVar2 = (**(code **)(*piVar3 + 0x118 /* CBaseEntity::IsAlive */))(piVar3);
  if (cVar2 == '\0') goto LAB_0075fe98;
  iVar4 = (**(code **)(*(int *)(unaff_EBX + 0x592335 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(unaff_EBX + 0x592335 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */);
  if (iVar4 != 0) {
    uVar13 = CONCAT44(uVar14,in_stack_00000004[0x124a]);
    iVar4 = unaff_EBX + 0x226e85 /* "Count:%i , Cur:  " */ /* "Count:%i , Cur:  " */ /* "Count:%i , Cur:  " */;
    CFmtStrN<256,false>::CFmtStrN(this_02,local_134);
    piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004,iVar4,uVar13);
    piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3);
    (**(code **)(*piVar3 + 0x20c /* CINSNextBot::EyePosition */))(local_28);
    NDebugOverlay::Text(local_28,local_12f,false,0.01023);
  }
  piVar3 = in_stack_00000004 + 0x1252;
  fVar11 = (float10)CountdownTimer::Now();
  if ((float)in_stack_00000004[0x1254] <= (float)fVar11 &&
      (float)fVar11 != (float)in_stack_00000004[0x1254]) {
    iVar4 = in_stack_00000004[0x124a];
    pCVar10 = (CINSBotLocomotion *)(iVar4 + -1);
    if ((int)pCVar10 < 0) {
      local_154 = (CINSBotLocomotion *)0xffffffff;
      this_03 = extraout_ECX;
LAB_00760626:
      if ((0 < iVar4) && (local_154 != (CINSBotLocomotion *)0xffffffff)) {
        ApplyMovementRequest(this_03,(int)in_stack_00000004);
        fVar11 = (float10)CountdownTimer::Now();
        fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1c3fe1 /* 0.25f */ /* 0.25f */ /* 0.25f */);
        if ((float)in_stack_00000004[0x1254] == fVar12) goto LAB_00760020;
LAB_0075ffec:
        (**(code **)(in_stack_00000004[0x1252] + 4))(piVar3,in_stack_00000004 + 0x1254);
        in_stack_00000004[0x1254] = (int)fVar12;
LAB_00760020:
        if (in_stack_00000004[0x1253] == 0x3e800000 /* 0.25f */) {
          return;
        }
        (**(code **)(in_stack_00000004[0x1252] + 4))(piVar3,in_stack_00000004 + 0x1253);
        in_stack_00000004[0x1253] = 0x3e800000 /* 0.25f */;
        return;
      }
    }
    else {
      iVar4 = (int)pCVar10 * 0x24;
      local_154 = (CINSBotLocomotion *)0xffffffff;
      local_148 = (CINSBotLocomotion *)0x0;
      local_14c = 0.0;
      local_144 = (CINSBotLocomotion *)0xffffffff;
      do {
        while( true ) {
          iVar5 = iVar4 + in_stack_00000004[0x1247];
          if ((*(char *)(iVar5 + 0xc) == '\0') &&
             (((*(char *)(iVar5 + 0xd) != '\0' || (*(char *)(iVar5 + 0xe) != '\0')) ||
              (fVar12 = *(float *)(**(int **)(unaff_EBX + 0x446df5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc),
              *(float *)(iVar5 + 0x14) <= fVar12 && fVar12 != *(float *)(iVar5 + 0x14))))) break;
          this_03 = *(CINSBotLocomotion **)(iVar5 + 0x1c);
          if (((int)local_148 <= (int)this_03) && (local_14c < *(float *)(iVar5 + 0x10))) {
            local_154 = pCVar10;
            local_14c = *(float *)(iVar5 + 0x10);
            local_148 = this_03;
          }
          if (*(char *)(iVar5 + 0xc) != '\0') {
            local_144 = pCVar10;
          }
          pCVar10 = pCVar10 + -1;
          iVar4 = iVar4 + -0x24;
          if (pCVar10 == (CINSBotLocomotion *)0xffffffff) goto LAB_0075fcad;
        }
        iVar5 = (**(code **)(*(int *)(unaff_EBX + 0x592335 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */) + 0x40))(unaff_EBX + 0x592335 /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */ /* ins_bot_debug_movement_requests */);
        if (iVar5 != 0) {
          piVar9 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
          (**(code **)(*piVar9 + 200))(piVar9);
          piVar9 = *(int **)(unaff_EBX + 0x446df5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */);
          DevMsg((char *)(unaff_EBX + 0x226fa1 /* "Bot %i - Movement Request removed: " */ /* "Bot %i - Movement Request removed: " */ /* "Bot %i - Movement Request removed: " */));
          iVar5 = iVar4 + in_stack_00000004[0x1247];
          if (*(char *)(iVar5 + 0xd) != '\0') {
            DevMsg((char *)(unaff_EBX + 0x226e97 /* "Completed - " */ /* "Completed - " */ /* "Completed - " */));
            iVar5 = iVar4 + in_stack_00000004[0x1247];
          }
          if (*(char *)(iVar5 + 0xe) != '\0') {
            DevMsg((char *)(unaff_EBX + 0x226ea4 /* "Failed - " */ /* "Failed - " */ /* "Failed - " */));
            iVar5 = iVar4 + in_stack_00000004[0x1247];
          }
          fVar12 = *(float *)(*piVar9 + 0xc);
          if (*(float *)(iVar5 + 0x14) <= fVar12 && fVar12 != *(float *)(iVar5 + 0x14)) {
            DevMsg(&UNK_00226eae + unaff_EBX);
          }
          DevMsg((char *)(unaff_EBX + 0x226eb9 /* "%3.1f , %3.1f 
" */ /* "%3.1f , %3.1f 
" */ /* "%3.1f , %3.1f 
" */));
        }
        pCVar10 = pCVar10 + -1;
        iVar4 = iVar4 + -0x24;
        CUtlVector<INSBotMovementRequest,CUtlMemory<INSBotMovementRequest,int>>::Remove
                  ((int)(in_stack_00000004 + 0x1247));
        this_03 = extraout_ECX_00;
      } while (pCVar10 != (CINSBotLocomotion *)0xffffffff);
LAB_0075fcad:
      if (local_144 == (CINSBotLocomotion *)0xffffffff) {
        iVar4 = in_stack_00000004[0x124a];
        goto LAB_00760626;
      }
      if (local_144 != local_154) {
        OnFailedMovementRequest(local_154,(int)in_stack_00000004);
        ApplyMovementRequest(local_154,(int)in_stack_00000004);
        fVar11 = (float10)CountdownTimer::Now();
        fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1c3fe1 /* 0.25f */ /* 0.25f */ /* 0.25f */);
        if ((float)in_stack_00000004[0x1254] == fVar12) goto LAB_00760020;
        goto LAB_0075ffec;
      }
    }
    fVar11 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1c3fe1 /* 0.25f */ /* 0.25f */ /* 0.25f */);
    if ((float)in_stack_00000004[0x1254] != fVar12) {
      (**(code **)(in_stack_00000004[0x1252] + 4))(piVar3);
      in_stack_00000004[0x1254] = (int)fVar12;
    }
    if (in_stack_00000004[0x1253] != 0x3e800000 /* 0.25f */) {
      (**(code **)(in_stack_00000004[0x1252] + 4))(piVar3);
      in_stack_00000004[0x1253] = 0x3e800000 /* 0.25f */;
    }
  }
  piVar3 = in_stack_00000004 + 0x1255;
  fVar11 = (float10)CountdownTimer::Now();
  if (((((float)fVar11 < (float)in_stack_00000004[0x1257] ||
         (float)fVar11 == (float)in_stack_00000004[0x1257]) ||
       (fVar11 = (float10)CountdownTimer::Now(),
       *(float *)(&DAT_0059239d + unaff_EBX) <= (float)fVar11 &&
       (float)fVar11 != *(float *)(&DAT_0059239d + unaff_EBX))) ||
      (fVar11 = (float10)CountdownTimer::Now(),
      fVar12 = (((float)in_stack_00000004[0x1256] - (float)in_stack_00000004[0x1257]) +
               (float)fVar11) -
               (float)(in_stack_00000004[0x1256] & -(uint)(0.0 < (float)in_stack_00000004[0x1257])),
      fVar12 < *(float *)(&DAT_001c4cb5 + unaff_EBX) ||
      fVar12 == *(float *)(&DAT_001c4cb5 + unaff_EBX))) &&
     ((fVar11 = (float10)CountdownTimer::Now(),
      (float)fVar11 < (float)in_stack_00000004[0x1257] ||
      (float)fVar11 == (float)in_stack_00000004[0x1257] ||
      (fVar11 = (float10)CountdownTimer::Now(),
      (float)fVar11 < *(float *)(&DAT_0059239d + unaff_EBX) ||
      (float)fVar11 == *(float *)(&DAT_0059239d + unaff_EBX))))) goto LAB_0075fdb4;
  iVar4 = TheINSNextBots();
  fVar12 = *(float *)(unaff_EBX + 0x1f98f9 /* 2.2f */ /* 2.2f */ /* 2.2f */) / (float)(*(ushort *)(iVar4 + 0x16) + 1);
  fVar11 = (float10)CountdownTimer::Now();
  if (*(float *)(&DAT_0059239d + unaff_EBX) != (float)fVar11 + fVar12) {
    (**(code **)(*(int *)(unaff_EBX + 0x592395 /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */) + 4))(unaff_EBX + 0x592395 /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */);
    *(float *)(&DAT_0059239d + unaff_EBX) = (float)fVar11 + fVar12;
  }
  if (*(float *)(unaff_EBX + 0x592399 /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */ /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */ /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */) != fVar12) {
    (**(code **)(*(int *)(unaff_EBX + 0x592395 /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */) + 4))(unaff_EBX + 0x592395 /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */ /* CINSBotLocomotion::s_fixedRepathCooldown */);
    *(float *)(unaff_EBX + 0x592399 /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */ /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */ /* CINSBotLocomotion::s_fixedRepathCooldown+0x4 */) = fVar12;
  }
  fVar11 = (float10)CountdownTimer::Now();
  pCVar10 = (CINSBotLocomotion *)((float)fVar11 + *(float *)(unaff_EBX + 0x1f98f9 /* 2.2f */ /* 2.2f */ /* 2.2f */));
  if ((CINSBotLocomotion *)in_stack_00000004[0x1257] != pCVar10) {
    (**(code **)(in_stack_00000004[0x1255] + 4))(piVar3);
    in_stack_00000004[0x1257] = (int)pCVar10;
    pCVar10 = extraout_ECX_01;
  }
  if (in_stack_00000004[0x1256] != 0x400ccccd /* 2.2f */) {
    (**(code **)(in_stack_00000004[0x1255] + 4))(piVar3);
    in_stack_00000004[0x1256] = 0x400ccccd /* 2.2f */;
    pCVar10 = extraout_ECX_02;
  }
  iVar4 = GetCurrentMovementRequest(pCVar10);
  if (iVar4 == -1) goto LAB_0075fdb4;
  if (0 < in_stack_00000004[0x112c]) {
    (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
    cVar2 = CINSPathFollower::IsComputeExpired(this_05,(INextBot *)(in_stack_00000004 + 0x2b));
    pCVar10 = extraout_ECX_03;
    if (((cVar2 == '\0') &&
        ((cVar2 = (**(code **)(*in_stack_00000004 + 0x18c))(in_stack_00000004),
         pCVar10 = extraout_ECX_04, cVar2 == '\0' ||
         (fVar11 = (float10)(**(code **)(*in_stack_00000004 + 400))(in_stack_00000004),
         pCVar10 = extraout_ECX_05,
         (float)fVar11 < *(float *)(&DAT_001c7305 + unaff_EBX) ||
         (float)fVar11 == *(float *)(&DAT_001c7305 + unaff_EBX))))) &&
       ((iVar4 = GetCurrentMovementRequest(pCVar10), iVar4 == -1 ||
        (fVar11 = (float10)GetStillDuration(this_08), pCVar10 = extraout_ECX_06,
        (float)fVar11 < *(float *)(unaff_EBX + 0x159069 /* 1.0f */ /* 1.0f */ /* 1.0f */) ||
        (float)fVar11 == *(float *)(unaff_EBX + 0x159069 /* 1.0f */ /* 1.0f */ /* 1.0f */))))) goto LAB_0075fdb4;
    iVar4 = GetCurrentMovementRequest(pCVar10);
  }
  iVar5 = iVar4 * 0x24;
  if (*(uint *)(in_stack_00000004[0x1247] + 0x18 + iVar5) < 0xb) {
    local_14c._0_1_ = (byte)*(undefined4 *)(in_stack_00000004[0x1247] + 0x18 + iVar5);
    bVar1 = local_14c._0_1_;
    local_14c = 1.4013e-45;
    uVar8 = 1 << (bVar1 & 0x1f);
    if (((uVar8 & 0x1d0) == 0) && (local_14c = 2.8026e-45, (uVar8 & 0x606) == 0)) goto LAB_007602a5;
  }
  else {
LAB_007602a5:
    local_14c = 0.0;
  }
  iVar6 = (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  if (((iVar6 == 0) ||
      (this_01 = (CINSPathFollower *)
                 __dynamic_cast(iVar6,*(undefined4 *)(unaff_EBX + 0x447525 /* &typeinfo for INextBot */ /* &typeinfo for INextBot */ /* &typeinfo for INextBot */),
                                *(undefined4 *)(unaff_EBX + 0x446f7d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0x2060),
      this_01 == (CINSPathFollower *)0x0)) || (iVar4 == -1)) {
LAB_0075fdb4:
    fVar11 = (float10)CountdownTimer::Now();
    if ((float)in_stack_00000004[0x124e] <= (float)fVar11 &&
        (float)fVar11 != (float)in_stack_00000004[0x124e]) {
      iVar4 = GetCurrentMovementRequest(this_04);
      if ((iVar4 != -1) && (0 < in_stack_00000004[0x112c])) {
        piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
        pIVar7 = (INextBot *)(**(code **)(*piVar3 + 0x114 /* CBasePlayer::TakeHealth */))(piVar3);
        if (pIVar7 == (INextBot *)(in_stack_00000004 + 0x2b)) {
          piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
          piVar3 = (int *)(**(code **)(*piVar3 + 0xd4 /* CBasePlayer::NetworkStateChanged_m_nNextThinkTick */))(piVar3);
          cVar2 = (**(code **)(*piVar3 + 0x128 /* CBaseEntity::IsTriggered */))(piVar3);
          if (cVar2 != '\0') {
            (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
            CINSPathFollower::Update(this_07,pIVar7);
          }
        }
      }
      piVar3 = (int *)(*(int **)(&DAT_004472e5 + unaff_EBX))[7];
      if (piVar3 == *(int **)(&DAT_004472e5 + unaff_EBX)) {
        local_140 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar11 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_140 = (float)fVar11;
      }
      fVar11 = (float10)CountdownTimer::Now();
      if ((float)in_stack_00000004[0x124e] != (float)fVar11 + local_140) {
        (**(code **)(in_stack_00000004[0x124c] + 4))
                  (in_stack_00000004 + 0x124c,in_stack_00000004 + 0x124e);
        in_stack_00000004[0x124e] = (int)((float)fVar11 + local_140);
      }
      if ((float)in_stack_00000004[0x124d] != local_140) {
        (**(code **)(in_stack_00000004[0x124c] + 4))
                  (in_stack_00000004 + 0x124c,in_stack_00000004 + 0x124d);
        in_stack_00000004[0x124d] = (int)local_140;
      }
    }
    fVar11 = (float10)CountdownTimer::Now();
    if ((float)fVar11 < (float)in_stack_00000004[0x125a] ||
        (float)fVar11 == (float)in_stack_00000004[0x125a]) {
      return;
    }
    fVar11 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x159069 /* 1.0f */ /* 1.0f */ /* 1.0f */);
    if ((float)in_stack_00000004[0x125a] != fVar12) {
      (**(code **)(in_stack_00000004[0x1258] + 4))
                (in_stack_00000004 + 0x1258,in_stack_00000004 + 0x125a);
      in_stack_00000004[0x125a] = (int)fVar12;
    }
    if (in_stack_00000004[0x1259] == 0x3f800000 /* 1.0f */) {
      return;
    }
    (**(code **)(in_stack_00000004[0x1258] + 4))
              (in_stack_00000004 + 0x1258,in_stack_00000004 + 0x1259);
    in_stack_00000004[0x1259] = 0x3f800000 /* 1.0f */;
    return;
  }
  fVar11 = (float10)CINSNextBot::MaxPathLength();
  this_00 = (CINSPathFollower *)(in_stack_00000004 + 0x2b);
  cVar2 = CINSPathFollower::ComputePath
                    (this_01,this_00,this_01 + 0x2060,iVar5 + in_stack_00000004[0x1247],local_14c,
                     (float)fVar11,0,0x41f00000 /* 30.0f */);
  if (cVar2 == '\0') {
    iVar4 = *(int *)(iVar5 + in_stack_00000004[0x1247] + 0x20);
    if (2 < iVar4) {
      CINSPathFollower::Invalidate(this_00);
      OnFailedMovementRequest(this_06,(int)in_stack_00000004);
      goto LAB_007603c7;
    }
    *(int *)(iVar5 + in_stack_00000004[0x1247] + 0x20) = iVar4 + 1;
    fVar11 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1f98f9 /* 2.2f */ /* 2.2f */ /* 2.2f */);
    if ((float)in_stack_00000004[0x1257] == fVar12) goto LAB_0076041f;
  }
  else {
    *(undefined1 *)(in_stack_00000004[0x1247] + 0xc + iVar5) = 1;
    CINSPathFollower::Update(this_01,(INextBot *)this_00);
    piVar9 = (int *)(**(code **)(*(int *)this_01 + 0x970 /* CINSNextBot::GetBodyInterface */))(this_01);
    (**(code **)(*piVar9 + 0x110 /* CINSBotBody::SetDesiredPosture */))(piVar9,0xc);
LAB_007603c7:
    fVar11 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1f98f9 /* 2.2f */ /* 2.2f */ /* 2.2f */);
    if ((float)in_stack_00000004[0x1257] == fVar12) goto LAB_0076041f;
  }
  (**(code **)(in_stack_00000004[0x1255] + 4))(piVar3,in_stack_00000004 + 0x1257);
  in_stack_00000004[0x1257] = (int)fVar12;
LAB_0076041f:
  if (in_stack_00000004[0x1256] == 0x400ccccd /* 2.2f */) {
    return;
  }
  (**(code **)(in_stack_00000004[0x1255] + 4))(piVar3,in_stack_00000004 + 0x1256);
  in_stack_00000004[0x1256] = 0x400ccccd /* 2.2f */;
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::UpdateMovementPosture
 * Address: 0075f0c0
 * ---------------------------------------- */

/* CINSBotLocomotion::UpdateMovementPosture() */

void CINSBotLocomotion::UpdateMovementPosture(void)

{
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::Upkeep
 * Address: 00760830
 * ---------------------------------------- */

/* CINSBotLocomotion::Upkeep() */

void __thiscall CINSBotLocomotion::Upkeep(CINSBotLocomotion *this)

{
  int *piVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSBotLocomotion *extraout_ECX;
  CINSBotLocomotion *extraout_ECX_00;
  CINSBotLocomotion *extraout_ECX_01;
  CINSRules *this_02;
  int unaff_EBX;
  int *in_stack_00000004;
  undefined4 uVar6;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(&DAT_004460ba + unaff_EBX);
  cVar2 = CINSRules::IsGameState(this_00,*piVar1);
  this_02 = this_01;
  if (cVar2 != '\0') {
LAB_00760900:
    UpdateMovement((CINSBotLocomotion *)this_02);
    return;
  }
  uVar6 = 3;
  cVar2 = CINSRules::IsGameState(this_01,*piVar1);
  if (cVar2 != '\0') {
    piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004,uVar6);
    iVar4 = (**(code **)(*piVar3 + 200))(piVar3);
    iVar5 = 0;
    if (*(int *)(iVar4 + 0x20) != 0) {
      iVar5 = *(int *)(iVar4 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x446062 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    piVar3 = (int *)UTIL_PlayerByIndex(iVar5);
    this_02 = (CINSRules *)extraout_ECX;
    if (((piVar3 == (int *)0x0) ||
        (cVar2 = (**(code **)(*piVar3 + 0x158))(piVar3), this_02 = (CINSRules *)extraout_ECX_00,
        cVar2 == '\0')) ||
       (cVar2 = (**(code **)(*(int *)*piVar1 + 0x3a8))((int *)*piVar1,piVar3),
       this_02 = (CINSRules *)extraout_ECX_01, cVar2 != '\0')) goto LAB_00760900;
  }
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::~CINSBotLocomotion
 * Address: 00760ca0
 * ---------------------------------------- */

/* CINSBotLocomotion::~CINSBotLocomotion() */

void __thiscall CINSBotLocomotion::~CINSBotLocomotion(CINSBotLocomotion *this)

{
  int iVar1;
  CUtlMemory<INSBotMovementRequest,int> *extraout_ECX;
  CUtlMemory<INSBotMovementRequest,int> *extraout_ECX_00;
  CUtlMemory<INSBotMovementRequest,int> *this_00;
  CINSPathFollower *this_01;
  ILocomotion *this_02;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[0x124a] = 0;
  *in_stack_00000004 = unaff_EBX + 0x43c3fe /* vtable for CINSBotLocomotion+0x8 */ /* vtable for CINSBotLocomotion+0x8 */ /* vtable for CINSBotLocomotion+0x8 */;
  iVar1 = in_stack_00000004[0x1247];
  this_00 = extraout_ECX;
  if (-1 < in_stack_00000004[0x1249]) {
    if (iVar1 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(&LAB_00445bce + unaff_EBX) + 8))
                ((int *)**(undefined4 **)(&LAB_00445bce + unaff_EBX),iVar1);
      in_stack_00000004[0x1247] = 0;
      this_00 = extraout_ECX_00;
    }
    in_stack_00000004[0x1248] = 0;
    iVar1 = 0;
  }
  in_stack_00000004[0x124b] = iVar1;
  CUtlMemory<INSBotMovementRequest,int>::~CUtlMemory(this_00);
  CINSPathFollower::~CINSPathFollower(this_01);
  *in_stack_00000004 = *(int *)(CEnvPlayerSurfaceTrigger::PlayerSurfaceChanged + unaff_EBX + 2) + 8;
  ILocomotion::~ILocomotion(this_02);
  return;
}



/* ----------------------------------------
 * CINSBotLocomotion::~CINSBotLocomotion
 * Address: 00760d90
 * ---------------------------------------- */

/* CINSBotLocomotion::~CINSBotLocomotion() */

void __thiscall CINSBotLocomotion::~CINSBotLocomotion(CINSBotLocomotion *this)

{
  CINSBotLocomotion *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSBotLocomotion(this_00);
  operator_delete(in_stack_00000004);
  return;
}



