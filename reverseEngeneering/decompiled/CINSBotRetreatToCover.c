/*
 * CINSBotRetreatToCover -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 18
 */

/* ----------------------------------------
 * CINSBotRetreatToCover::CINSBotRetreatToCover
 * Address: 0072f700
 * ---------------------------------------- */

/* CINSBotRetreatToCover::CINSBotRetreatToCover(bool, float) */

void __thiscall
CINSBotRetreatToCover::CINSBotRetreatToCover(CINSBotRetreatToCover *this,bool param_1,float param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int unaff_EBX;
  undefined3 in_stack_00000005;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  _param_1[2] = 0;
  *_param_1 = unaff_EBX + 0x468a1d /* vtable for CINSBotRetreatToCover+0x8 */;
  _param_1[1] = unaff_EBX + 0x468bb5 /* vtable for CINSBotRetreatToCover+0x1a0 */;
  piVar1 = *(int **)(unaff_EBX + 0x476ec1 /* &vec3_origin */);
  _param_1[3] = 0;
  _param_1[4] = 0;
  _param_1[8] = 0;
  iVar2 = *piVar1;
  _param_1[9] = 0;
  _param_1[10] = 0;
  _param_1[5] = 0;
  _param_1[6] = 0;
  _param_1[0xe] = iVar2;
  iVar2 = piVar1[1];
  iVar3 = piVar1[2];
  _param_1[7] = 0;
  *(undefined1 *)(_param_1 + 0xc) = 0;
  *(undefined1 *)((int)_param_1 + 0x31) = 0;
  _param_1[0xb] = 0;
  _param_1[0x10] = iVar3;
  _param_1[0x11] = unaff_EBX + 0x3f8aad /* vtable for CountdownTimer+0x8 */;
  _param_1[0xd] = 0;
  _param_1[0xf] = iVar2;
  _param_1[0x12] = 0;
  (*(code *)(unaff_EBX + -0x4fef9b /* CountdownTimer::NetworkStateChanged */))(_param_1 + 0x11,_param_1 + 0x12);
  _param_1[0x13] = -0x40800000 /* -1.0f */;
  (**(code **)(_param_1[0x11] + 4))(_param_1 + 0x11,_param_1 + 0x13);
  _param_1[0x17] = 0;
  _param_1[0x16] = unaff_EBX + 0x3f8aad /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x4fef9b /* CountdownTimer::NetworkStateChanged */))(_param_1 + 0x16,_param_1 + 0x17);
  _param_1[0x18] = -0x40800000 /* -1.0f */;
  (**(code **)(_param_1[0x16] + 4))(_param_1 + 0x16,_param_1 + 0x18);
  *(undefined1 *)(_param_1 + 0x14) = param_2._0_1_;
  _param_1[0x15] = in_stack_0000000c;
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::CINSBotRetreatToCover
 * Address: 0072f840
 * ---------------------------------------- */

/* CINSBotRetreatToCover::CINSBotRetreatToCover(Vector, bool, float) */

void __thiscall
CINSBotRetreatToCover::CINSBotRetreatToCover
          (undefined4 param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,undefined1 param_6,undefined4 param_7)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  *param_2 = &UNK_004688dd + unaff_EBX;
  param_2[1] = unaff_EBX + 0x468a75 /* vtable for CINSBotRetreatToCover+0x1a0 */;
  param_2[9] = 0;
  param_2[10] = 0;
  param_2[3] = 0;
  param_2[0xe] = param_3;
  param_2[4] = 0;
  param_2[5] = 0;
  param_2[6] = 0;
  param_2[0xf] = param_4;
  param_2[7] = 0;
  param_2[2] = 0;
  *(undefined1 *)(param_2 + 0xc) = 0;
  param_2[0x10] = param_5;
  param_2[0x11] = unaff_EBX + 0x3f896d /* vtable for CountdownTimer+0x8 */;
  *(undefined1 *)((int)param_2 + 0x31) = 0;
  param_2[0xb] = 0;
  param_2[0xd] = 0;
  param_2[0x12] = 0;
  (*(code *)(unaff_EBX + -0x4ff0db /* CountdownTimer::NetworkStateChanged */))(param_2 + 0x11,param_2 + 0x12);
  param_2[0x13] = 0xbf800000 /* -1.0f */;
  (**(code **)(param_2[0x11] + 4))(param_2 + 0x11,param_2 + 0x13);
  param_2[0x17] = 0;
  param_2[0x16] = unaff_EBX + 0x3f896d /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x4ff0db /* CountdownTimer::NetworkStateChanged */))(param_2 + 0x16,param_2 + 0x17);
  param_2[0x18] = 0xbf800000 /* -1.0f */;
  (**(code **)(param_2[0x16] + 4))(param_2 + 0x16,param_2 + 0x18);
  *(undefined1 *)(param_2 + 0x14) = param_6;
  param_2[0x15] = param_7;
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnStart
 * Address: 0072e870
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotRetreatToCover::OnStart(CINSBotRetreatToCover *this,CINSNextBot *param_1,Action *param_2)

{
  float *pfVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  void *pvVar5;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *this_03;
  CINSBotRetreat *this_04;
  CBaseEntity *extraout_ECX_02;
  CINSBotRetreat *this_05;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  int *in_stack_0000000c;
  undefined4 uVar10;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  pfVar1 = *(float **)(unaff_EBX + 0x477d51 /* &vec3_origin */);
  if ((((*pfVar1 == *(float *)(param_2 + 0x38)) && (pfVar1[1] == *(float *)(param_2 + 0x3c))) &&
      (pfVar1[2] == *(float *)(param_2 + 0x40))) &&
     (((CINSNextBot::GetAnyCover(this_00), local_28 != *pfVar1 || (local_24 != pfVar1[1])) ||
      (local_20 != pfVar1[2])))) {
    *(float *)(param_2 + 0x38) = local_28;
    *(float *)(param_2 + 0x3c) = local_24;
    *(float *)(param_2 + 0x40) = local_20;
    iVar4 = in_stack_0000000c[0x2cce];
    if (iVar4 == -1) goto LAB_0072ebf0;
LAB_0072e8b8:
    piVar3 = (int *)UTIL_EntityByIndex(iVar4);
    if (piVar3 == (int *)0x0) goto LAB_0072ebf0;
  }
  else {
    iVar4 = in_stack_0000000c[0x2cce];
    if (iVar4 != -1) goto LAB_0072e8b8;
LAB_0072ebf0:
    piVar3 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
    if ((piVar3 == (int *)0x0) ||
       (piVar3 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3), piVar3 == (int *)0x0))
    goto LAB_0072eb2e;
  }
  if ((*pfVar1 != *(float *)(param_2 + 0x38)) ||
     ((pfVar1[1] != *(float *)(param_2 + 0x3c) || (pfVar1[2] != *(float *)(param_2 + 0x40))))) {
    cVar2 = (**(code **)(*piVar3 + 0x158))(piVar3);
    if (cVar2 == '\0') {
      iVar4 = __dynamic_cast(piVar3,*(undefined4 *)(unaff_EBX + 0x478889 /* &typeinfo for CBaseEntity */),
                             *(undefined4 *)(CFuncInstanceIoProxy::InputProxyRelay8 + unaff_EBX + 1)
                             ,0);
      if (iVar4 == 0) {
        pvVar5 = ::operator_new(0x48f8);
        CINSBotRetreat::CINSBotRetreat(this_05,SUB41(pvVar5,0),0.0);
        *(undefined4 *)param_1 = 1;
        *(void **)(param_1 + 4) = pvVar5;
        *(int *)(param_1 + 8) = unaff_EBX + 0x253291 /* "Bailing on retreat to cover, unknown threat entity" */;
        return param_1;
      }
      fVar6 = (float10)CBaseDetonator::GetDetonateDamage();
      if (*(float *)(unaff_EBX + 0x18a28d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar6 &&
          (float)fVar6 != *(float *)(unaff_EBX + 0x18a28d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        this_02 = this_01;
        if ((*(byte *)(iVar4 + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_01);
          this_02 = extraout_ECX_02;
        }
        if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_02);
        }
        fVar9 = (float)in_stack_0000000c[0x82] - *(float *)(iVar4 + 0x208);
        fVar7 = (float)in_stack_0000000c[0x83] - *(float *)(iVar4 + 0x20c);
        fVar8 = (float)in_stack_0000000c[0x84] - *(float *)(iVar4 + 0x210);
        fVar6 = (float10)CBaseDetonator::GetDetonateDamageRadius();
        if (SQRT(fVar7 * fVar7 + fVar9 * fVar9 + fVar8 * fVar8) < (float)fVar6) {
          (**(code **)(*in_stack_0000000c + 0x800 /* CINSPlayer::SpeakConceptIfAllowed */))(in_stack_0000000c,0x68,0,0,0,0);
        }
      }
    }
    fVar7 = *(float *)(param_2 + 0x54);
    fVar6 = (float10)CountdownTimer::Now();
    this_03 = extraout_ECX;
    if (*(float *)(param_2 + 0x60) != (float)fVar6 + fVar7) {
      (**(code **)(*(int *)(param_2 + 0x58) + 4))(param_2 + 0x58,param_2 + 0x60);
      *(float *)(param_2 + 0x60) = (float)fVar6 + fVar7;
      this_03 = extraout_ECX_00;
    }
    if (*(float *)(param_2 + 0x5c) != fVar7) {
      (**(code **)(*(int *)(param_2 + 0x58) + 4))(param_2 + 0x58,param_2 + 0x5c);
      *(float *)(param_2 + 0x5c) = fVar7;
      this_03 = extraout_ECX_01;
    }
    CINSNextBot::ResetIdleStatus(this_03);
    (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
    uVar10 = 0xd;
    CINSBotLocomotion::ClearMovementRequests();
    uVar10 = (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,uVar10);
    CINSBotLocomotion::AddMovementRequest
              (uVar10,*(undefined4 *)(param_2 + 0x38),*(undefined4 *)(param_2 + 0x3c),
               *(undefined4 *)(param_2 + 0x40),6,7,0x40a00000 /* 5.0f */);
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
LAB_0072eb2e:
  pvVar5 = ::operator_new(0x48f8);
  CINSBotRetreat::CINSBotRetreat(this_04,SUB41(pvVar5,0),0.0);
  *(undefined4 *)param_1 = 1;
  *(void **)(param_1 + 4) = pvVar5;
  *(int *)(param_1 + 8) = unaff_EBX + 0x253255 /* "Bailing on retreat to cover, no pos or threat is invalid" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::Update
 * Address: 0072f050
 * ---------------------------------------- */

/* CINSBotRetreatToCover::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotRetreatToCover::Update(CINSBotRetreatToCover *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  undefined *puVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  int *piVar6;
  undefined4 uVar7;
  CINSNextBot *this_00;
  CINSPlayer *extraout_ECX;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_01;
  CINSPlayer *extraout_ECX_01;
  CINSNextBot *this_02;
  int unaff_EBX;
  float10 fVar8;
  float fVar9;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar4 = CINSNextBot::IsIdle(this_00);
  if ((cVar4 != '\0') &&
     (fVar8 = (float10)CINSNextBot::GetIdleDuration(in_stack_0000000c),
     *(float *)(unaff_EBX + 0x1f5711 /* typeinfo name for CBaseGameSystem+0x32 */) <= (float)fVar8 &&
     (float)fVar8 != *(float *)(unaff_EBX + 0x1f5711 /* typeinfo name for CBaseGameSystem+0x32 */))) {
    *(undefined4 *)param_1 = 3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x252a5a /* "Idle in retreat to cover" */;
    *(undefined4 *)(param_1 + 4) = 0;
    return param_1;
  }
  if ((0.0 < *(float *)((int)param_2 + 0x60)) &&
     (fVar8 = (float10)CountdownTimer::Now(),
     *(float *)((int)param_2 + 0x60) <= (float)fVar8 &&
     (float)fVar8 != *(float *)((int)param_2 + 0x60))) {
    if (*(char *)((int)param_2 + 0x50) == '\0') {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x252863 /* "Retreat timer elapsed." */;
      return param_1;
    }
    piVar5 = (int *)::operator_new(0x5c);
    pcVar1 = (code *)(unaff_EBX + -0x4fe8eb /* CountdownTimer::NetworkStateChanged */);
    piVar5[8] = 0;
    piVar5[9] = 0;
    piVar5[10] = 0;
    piVar5[3] = 0;
    piVar5[4] = 0;
    piVar5[5] = 0;
    piVar5[6] = 0;
    piVar5[7] = 0;
    piVar5[2] = 0;
    *(undefined1 *)(piVar5 + 0xc) = 0;
    *(undefined1 *)((int)piVar5 + 0x31) = 0;
    piVar5[0xb] = 0;
    piVar5[0xd] = 0;
    iVar3 = *(int *)(unaff_EBX + 0x47799d /* &vtable for CINSBotReload */);
    piVar5[0xf] = 0;
    piVar5[1] = iVar3 + 0x198;
    *piVar5 = iVar3 + 8;
    puVar2 = &UNK_003f915d + unaff_EBX;
    piVar5[0xe] = (int)puVar2;
    (*pcVar1)(piVar5 + 0xe,piVar5 + 0xf);
    piVar5[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar5[0xe] + 4))(piVar5 + 0xe,piVar5 + 0x10);
    piVar5[0x12] = 0;
    piVar5[0x11] = (int)puVar2;
    (*pcVar1)(piVar5 + 0x11,piVar5 + 0x12);
    piVar5[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar5[0x11] + 4))(piVar5 + 0x11,piVar5 + 0x13);
    piVar5[0x15] = 0;
    piVar5[0x14] = (int)puVar2;
    (*pcVar1)(piVar5 + 0x14,piVar5 + 0x15);
    piVar5[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar5[0x14] + 4))(piVar5 + 0x14,piVar5 + 0x16);
    *(undefined4 *)param_1 = 1;
    *(undefined **)(param_1 + 8) = &UNK_002529ed + unaff_EBX;
    *(int **)(param_1 + 4) = piVar5;
    return param_1;
  }
  iVar3 = (int)param_2 + 0x38;
  fVar8 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                             (in_stack_0000000c + 0x2060,iVar3);
  if (*(float *)(unaff_EBX + 0x20e9ad /* typeinfo name for CEntityFactory<CINSRemoteBase>+0x28 */) <= (float)fVar8) {
    fVar8 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x4c) <= (float)fVar8 &&
        (float)fVar8 != *(float *)((int)param_2 + 0x4c)) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
      this_01 = extraout_ECX;
      if (((piVar5 == (int *)0x0) ||
          (cVar4 = (**(code **)(*piVar5 + 0x38))(piVar5), this_01 = extraout_ECX_00, cVar4 == '\0'))
         || (fVar8 = (float10)CINSNextBot::GetActiveWeaponAmmoRatio(), this_01 = extraout_ECX_01,
            (float)fVar8 <= 0.0)) {
        cVar4 = CINSPlayer::IsMoving(this_01);
        if (cVar4 == '\0') {
          piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
          cVar4 = (**(code **)(*piVar5 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar5,iVar3,1);
          if (cVar4 != '\0') {
            piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            (**(code **)(*piVar5 + 0xd4 /* PlayerBody::AimHeadTowards */))(piVar5,iVar3,3,0x3f000000 /* 0.5f */,0,unaff_EBX + 0x252b61 /* "looking at our cover position while retreating" */);
          }
        }
      }
      else {
        piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        pcVar1 = *(code **)(*piVar6 + 0xd8);
        uVar7 = (**(code **)(*piVar5 + 0x10 /* INextBotEventResponder::OnLeaveGround */))(piVar5);
        (*pcVar1)(piVar6,uVar7,3,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x252b35 /* "Looking at threat while retreating to cover" */);
        CINSNextBot::FireWeaponAtEnemy(this_02);
      }
      fVar8 = (float10)CountdownTimer::Now();
      fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x1f4a31 /* typeinfo name for ISaveRestoreOps+0x67 */);
      if (*(float *)((int)param_2 + 0x4c) != fVar9) {
        (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c);
        *(float *)((int)param_2 + 0x4c) = fVar9;
      }
      if (*(int *)((int)param_2 + 0x48) != 0x3e800000 /* 0.25f */) {
        (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48);
        *(undefined4 *)((int)param_2 + 0x48) = 0x3e800000 /* 0.25f */;
      }
    }
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  if (*(char *)((int)param_2 + 0x50) == '\0') {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x251887 /* "In Cover" */;
    return param_1;
  }
  piVar5 = (int *)::operator_new(0x5c);
  piVar5[8] = 0;
  piVar5[9] = 0;
  piVar5[10] = 0;
  piVar5[3] = 0;
  piVar5[4] = 0;
  piVar5[5] = 0;
  piVar5[6] = 0;
  piVar5[7] = 0;
  piVar5[2] = 0;
  *(undefined1 *)(piVar5 + 0xc) = 0;
  *(undefined1 *)((int)piVar5 + 0x31) = 0;
  piVar5[0xb] = 0;
  piVar5[0xd] = 0;
  iVar3 = *(int *)(unaff_EBX + 0x47799d /* &vtable for CINSBotReload */);
  piVar5[0xf] = 0;
  piVar5[1] = iVar3 + 0x198;
  puVar2 = &UNK_003f915d + unaff_EBX;
  *piVar5 = iVar3 + 8;
  pcVar1 = (code *)(unaff_EBX + -0x4fe8eb /* CountdownTimer::NetworkStateChanged */);
  piVar5[0xe] = (int)puVar2;
  (*pcVar1)(piVar5 + 0xe,piVar5 + 0xf);
  piVar5[0x10] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar5[0xe] + 4))(piVar5 + 0xe,piVar5 + 0x10);
  piVar5[0x12] = 0;
  piVar5[0x11] = (int)puVar2;
  (*pcVar1)(piVar5 + 0x11,piVar5 + 0x12);
  piVar5[0x13] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar5[0x11] + 4))(piVar5 + 0x11,piVar5 + 0x13);
  piVar5[0x15] = 0;
  piVar5[0x14] = (int)puVar2;
  (*pcVar1)(piVar5 + 0x14,piVar5 + 0x15);
  piVar5[0x16] = -0x40800000 /* -1.0f */;
  (**(code **)(piVar5[0x14] + 4))(piVar5 + 0x14,piVar5 + 0x16);
  *(undefined4 *)param_1 = 1;
  *(int **)(param_1 + 4) = piVar5;
  *(int *)(param_1 + 8) = unaff_EBX + 0x252b09 /* "Doing given action now that I'm in cover" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnEnd
 * Address: 0072e740
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotRetreatToCover::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::GetName
 * Address: 0072f980
 * ---------------------------------------- */

/* CINSBotRetreatToCover::GetName() const */

int CINSBotRetreatToCover::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25043a /* "Retreating to cover" */;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::ShouldHurry
 * Address: 0072e750
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToCover::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotRetreatToCover::ShouldHurry(CINSBotRetreatToCover *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::ShouldHurry
 * Address: 0072e760
 * ---------------------------------------- */

/* CINSBotRetreatToCover::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotRetreatToCover::ShouldHurry(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::ShouldAttack
 * Address: 0072e770
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToCover::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotRetreatToCover::ShouldAttack
          (CINSBotRetreatToCover *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::ShouldAttack
 * Address: 0072e780
 * ---------------------------------------- */

/* CINSBotRetreatToCover::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotRetreatToCover::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnMoveToSuccess
 * Address: 0072ee80
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotRetreatToCover::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar2 + 0x50) == '\0') {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x252c07 /* "We got to target's position!" */;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar2 = *(int *)(&DAT_00477b67 + unaff_EBX);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x3f9327 /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4fe721 /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar2;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10);
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar2;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar2;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *(undefined4 *)param_1 = 1;
    *(int **)(param_1 + 4) = piVar3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x252caf /* "Doing reload after OnMoveToSuccess" */;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnMoveToFailure
 * Address: 0072ecb0
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotRetreatToCover::OnMoveToFailure(undefined4 *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar2 + 0x50) == '\0') {
    *param_1 = 3;
    param_1[1] = 0;
    param_1[2] = unaff_EBX + 0x252c4b /* "We couldn't get to target's position!" */;
    param_1[3] = 1;
  }
  else {
    piVar3 = (int *)::operator_new(0x5c);
    piVar3[8] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0;
    piVar3[3] = 0;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    piVar3[7] = 0;
    piVar3[2] = 0;
    *(undefined1 *)(piVar3 + 0xc) = 0;
    *(undefined1 *)((int)piVar3 + 0x31) = 0;
    piVar3[0xb] = 0;
    piVar3[0xd] = 0;
    iVar2 = *(int *)(unaff_EBX + 0x477d37 /* &vtable for CINSBotReload */);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x3f94f7 /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4fe551 /* CountdownTimer::NetworkStateChanged */);
    piVar3[0xe] = iVar2;
    (*pcVar1)(piVar3 + 0xe,piVar3 + 0xf);
    piVar3[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0xe] + 4))(piVar3 + 0xe,piVar3 + 0x10);
    piVar3[0x12] = 0;
    piVar3[0x11] = iVar2;
    (*pcVar1)(piVar3 + 0x11,piVar3 + 0x12);
    piVar3[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x11] + 4))(piVar3 + 0x11,piVar3 + 0x13);
    piVar3[0x15] = 0;
    piVar3[0x14] = iVar2;
    (*pcVar1)(piVar3 + 0x14,piVar3 + 0x15);
    piVar3[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar3[0x14] + 4))(piVar3 + 0x14,piVar3 + 0x16);
    *param_1 = 1;
    param_1[1] = piVar3;
    param_1[2] = unaff_EBX + 0x252c27 /* "Doing reload after OnMoveToFailure" */;
    param_1[3] = 1;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnStuck
 * Address: 0072e790
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnStuck(CINSNextBot*) */

void CINSBotRetreatToCover::OnStuck(CINSNextBot *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x2532f3 /* "Im Stuck, help!" */;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::OnInjured
 * Address: 0072f9a0
 * ---------------------------------------- */

/* CINSBotRetreatToCover::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotRetreatToCover::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 4;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x251e86 /* "Sustaining retreat." */;
  *(undefined4 *)(param_1 + 0xc) = 2;
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::~CINSBotRetreatToCover
 * Address: 0072f9e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToCover::~CINSBotRetreatToCover() */

void __thiscall CINSBotRetreatToCover::~CINSBotRetreatToCover(CINSBotRetreatToCover *this)

{
  ~CINSBotRetreatToCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::~CINSBotRetreatToCover
 * Address: 0072f9f0
 * ---------------------------------------- */

/* CINSBotRetreatToCover::~CINSBotRetreatToCover() */

void __thiscall CINSBotRetreatToCover::~CINSBotRetreatToCover(CINSBotRetreatToCover *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x468733 /* vtable for CINSBotRetreatToCover+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_004688cb + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x477783 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::~CINSBotRetreatToCover
 * Address: 0072fa20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToCover::~CINSBotRetreatToCover() */

void __thiscall CINSBotRetreatToCover::~CINSBotRetreatToCover(CINSBotRetreatToCover *this)

{
  ~CINSBotRetreatToCover(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToCover::~CINSBotRetreatToCover
 * Address: 0072fa30
 * ---------------------------------------- */

/* CINSBotRetreatToCover::~CINSBotRetreatToCover() */

void __thiscall CINSBotRetreatToCover::~CINSBotRetreatToCover(CINSBotRetreatToCover *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4686ea /* vtable for CINSBotRetreatToCover+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_00468882 + unaff_EBX);
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



