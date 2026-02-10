/*
 * CINSBotRetreatToHidingSpot -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 17
 */

/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::CINSBotRetreatToHidingSpot
 * Address: 00730b40
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::CINSBotRetreatToHidingSpot(bool, float) */

void __thiscall
CINSBotRetreatToHidingSpot::CINSBotRetreatToHidingSpot
          (CINSBotRetreatToHidingSpot *this,bool param_1,float param_2)

{
  int *piVar1;
  float fVar2;
  int iVar3;
  CINSPathFollower *this_00;
  int unaff_EBX;
  float10 fVar4;
  undefined3 in_stack_00000005;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  _param_1[8] = 0;
  *_param_1 = unaff_EBX + 0x4677dd /* vtable for CINSBotRetreatToHidingSpot+0x8 */ /* vtable for CINSBotRetreatToHidingSpot+0x8 */;
  _param_1[9] = 0;
  _param_1[10] = 0;
  _param_1[3] = 0;
  _param_1[4] = 0;
  _param_1[5] = 0;
  _param_1[6] = 0;
  _param_1[7] = 0;
  _param_1[2] = 0;
  *(undefined1 *)(_param_1 + 0xc) = 0;
  *(undefined1 *)((int)_param_1 + 0x31) = 0;
  _param_1[0xb] = 0;
  _param_1[0xd] = 0;
  _param_1[1] = (int)(&UNK_00467975 + unaff_EBX);
  CINSPathFollower::CINSPathFollower(this_00);
  _param_1[0x122e] = 0;
  _param_1[0x122d] = (int)(&UNK_003f766d + unaff_EBX);
  (*(code *)(unaff_EBX + -0x5003db /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(_param_1 + 0x122d,_param_1 + 0x122e);
  _param_1[0x122f] = -0x40800000 /* -1.0f */;
  (**(code **)(_param_1[0x122d] + 4))(_param_1 + 0x122d,_param_1 + 0x122f);
  piVar1 = _param_1 + 0x1230;
  _param_1[0x1231] = 0;
  _param_1[0x1230] = (int)(&UNK_003f766d + unaff_EBX);
  (*(code *)(unaff_EBX + -0x5003db /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar1,_param_1 + 0x1231);
  _param_1[0x1232] = -0x40800000 /* -1.0f */;
  (**(code **)(_param_1[0x1230] + 4))(piVar1,_param_1 + 0x1232);
  _param_1[0x1236] = -0x40800000 /* -1.0f */;
  iVar3 = *(int *)(unaff_EBX + 0x476105 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  _param_1[0x1235] = iVar3 + 8;
  (**(code **)(iVar3 + 0x10))(_param_1 + 0x1235,_param_1 + 0x1236);
  *(undefined1 *)(_param_1 + 0x1233) = param_2._0_1_;
  _param_1[0x1234] = in_stack_0000000c;
  if (_param_1[0x1236] != -0x40800000 /* -1.0f */) {
    (**(code **)(_param_1[0x1235] + 8))(_param_1 + 0x1235,_param_1 + 0x1236);
    _param_1[0x1236] = -0x40800000 /* -1.0f */;
  }
  fVar4 = (float10)CountdownTimer::Now();
  fVar2 = (float)_param_1[0x1231];
  if ((float)_param_1[0x1232] != (float)fVar4 + fVar2) {
    (**(code **)(_param_1[0x1230] + 4))(piVar1,_param_1 + 0x1232);
    _param_1[0x1232] = (int)((float)fVar4 + fVar2);
  }
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnStart
 * Address: 0072fc10
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotRetreatToHidingSpot::OnStart
          (CINSBotRetreatToHidingSpot *this,CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  int *piVar2;
  undefined4 *puVar3;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  int unaff_EBX;
  float10 fVar4;
  float in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar4 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this_00);
  piVar1 = *(int **)(unaff_EBX + 0x476df1 /* &ins_bot_retreat_to_hidingspot_range */ /* &ins_bot_retreat_to_hidingspot_range */);
  *(float *)(param_2 + 0x4814) = (float)fVar4;
  piVar2 = (int *)piVar1[7];
  if (piVar2 == piVar1) {
    puVar3 = (undefined4 *)CINSNextBot::FindNearbyCoverPosition(this_01,in_stack_0000000c);
  }
  else {
    (**(code **)(*piVar2 + 0x3c))(piVar2);
    puVar3 = (undefined4 *)CINSNextBot::FindNearbyCoverPosition(this_02,in_stack_0000000c);
  }
  if (puVar3 != (undefined4 *)0x0) {
    *(undefined4 *)(param_2 + 0x48a8) = *puVar3;
    *(undefined4 *)(param_2 + 0x48ac) = puVar3[1];
    *(undefined4 *)(param_2 + 0x48b0) = puVar3[2];
    param_2[0x48dc] = *(Action *)((int)in_stack_0000000c + 0x2291);
    *(undefined1 *)((int)in_stack_0000000c + 0x2291) = 1;
    CINSNextBot::MaxPathLength();
    CINSPathFollower::ComputePath();
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x25205d /* "Failed finding cover nearby...
" */ /* "Failed finding cover nearby...
" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::Update
 * Address: 007303c0
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotRetreatToHidingSpot::Update
          (CINSBotRetreatToHidingSpot *this,CINSNextBot *param_1,float param_2)

{
  code *pcVar1;
  float fVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  CINSNextBot *pCVar8;
  CINSPathFollower *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *this_01;
  CINSNextBotManager *this_02;
  int unaff_EBX;
  float10 fVar9;
  CINSNextBot *in_stack_0000000c;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  iVar5 = (**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,1);
  pCVar8 = in_stack_0000000c + 0x2060;
  iVar6 = (**(code **)(*(int *)((int)param_2 + 4) + 0x10))((int)param_2 + 4,pCVar8);
  if (iVar6 == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x251890 /* "No longer need to retreat" */ /* "No longer need to retreat" */;
    return param_1;
  }
  if (0.0 < *(float *)((int)param_2 + 0x48d8)) {
    fVar2 = *(float *)((int)param_2 + 0x48d0);
    fVar9 = (float10)IntervalTimer::Now();
    if (fVar2 < (float)fVar9 - *(float *)((int)param_2 + 0x48d8)) {
      if (*(char *)((int)param_2 + 0x48cc) == '\0') {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(int *)(param_1 + 8) = unaff_EBX + 0x2514f3 /* "Retreat timer elapsed." */ /* "Retreat timer elapsed." */;
        *(undefined4 *)(param_1 + 4) = 0;
        return param_1;
      }
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
      iVar6 = *(int *)(unaff_EBX + 0x47662d /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
      piVar4[0xf] = 0;
      piVar4[1] = iVar6 + 0x198;
      iVar5 = unaff_EBX + 0x3f7ded /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
      *piVar4 = iVar6 + 8;
      pcVar1 = (code *)(unaff_EBX + -0x4ffc5b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
      piVar4[0xe] = iVar5;
      (*pcVar1)(piVar4 + 0xe,piVar4 + 0xf);
      piVar4[0x10] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
      piVar4[0x12] = 0;
      piVar4[0x11] = iVar5;
      (*pcVar1)(piVar4 + 0x11,piVar4 + 0x12);
      piVar4[0x13] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
      piVar4[0x15] = 0;
      piVar4[0x14] = iVar5;
      (*pcVar1)(piVar4 + 0x14,piVar4 + 0x15);
      piVar4[0x16] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(int *)(param_1 + 8) = unaff_EBX + 0x251909 /* "Timer elapsed, changing to reload action" */ /* "Timer elapsed, changing to reload action" */;
      *(int **)(param_1 + 4) = piVar4;
      return param_1;
    }
    if (0.0 < *(float *)((int)param_2 + 0x48d8)) {
      if (iVar5 != 0) {
        piVar4 = (int *)(*(int **)(unaff_EBX + 0x476641 /* &ins_bot_retreat_to_hidingspot_range */ /* &ins_bot_retreat_to_hidingspot_range */))[7];
        if (piVar4 != *(int **)(unaff_EBX + 0x476641 /* &ins_bot_retreat_to_hidingspot_range */ /* &ins_bot_retreat_to_hidingspot_range */)) {
          (**(code **)(*piVar4 + 0x3c))(piVar4);
        }
        puVar7 = (undefined4 *)
                 CINSNextBot::FindNearbyCoverPosition(in_stack_0000000c,(float)in_stack_0000000c);
        if (puVar7 == (undefined4 *)0x0) {
          if (*(char *)((int)param_2 + 0x48cc) == '\0') {
            *(undefined4 *)param_1 = 3 /* Done */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(int *)(param_1 + 8) = unaff_EBX + 0x251961 /* "Got to cover, couldn't find another.
" */ /* "Got to cover, couldn't find another.
" */;
            return param_1;
          }
          piVar4 = (int *)::operator_new(0x5c);
          pcVar1 = (code *)(unaff_EBX + -0x4ffc5b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
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
          iVar5 = *(int *)(unaff_EBX + 0x47662d /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
          piVar4[0xf] = 0;
          piVar4[1] = iVar5 + 0x198;
          *piVar4 = iVar5 + 8;
          iVar5 = unaff_EBX + 0x3f7ded /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
          piVar4[0xe] = iVar5;
          (*pcVar1)(piVar4 + 0xe,piVar4 + 0xf);
          piVar4[0x10] = -0x40800000 /* -1.0f */;
          (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
          piVar4[0x12] = 0;
          piVar4[0x11] = iVar5;
          (*pcVar1)(piVar4 + 0x11,piVar4 + 0x12);
          piVar4[0x13] = -0x40800000 /* -1.0f */;
          (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
          piVar4[0x15] = 0;
          piVar4[0x14] = iVar5;
          (*pcVar1)(piVar4 + 0x14,piVar4 + 0x15);
          piVar4[0x16] = -0x40800000 /* -1.0f */;
          (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
          *(undefined4 *)param_1 = 1 /* ChangeTo */;
          *(int **)(param_1 + 4) = piVar4;
          *(int *)(param_1 + 8) = unaff_EBX + 0x251935 /* "Failed finding another cover, doing reload." */ /* "Failed finding another cover, doing reload." */;
          return param_1;
        }
        if (*(int *)((int)param_2 + 0x48d8) != -0x40800000 /* -1.0f */) {
          (**(code **)(*(int *)((int)param_2 + 0x48d4) + 8))
                    ((int)param_2 + 0x48d4,(int)param_2 + 0x48d8);
          *(undefined4 *)((int)param_2 + 0x48d8) = 0xbf800000 /* -1.0f */;
        }
        *(undefined4 *)((int)param_2 + 0x48a8) = *puVar7;
        *(undefined4 *)((int)param_2 + 0x48ac) = puVar7[1];
        *(undefined4 *)((int)param_2 + 0x48b0) = puVar7[2];
      }
      goto LAB_00730507;
    }
  }
  fVar9 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x48bc) <= (float)fVar9 &&
      (float)fVar9 != *(float *)((int)param_2 + 0x48bc)) {
    fVar9 = (float10)RandomFloat(0x40200000 /* 2.5f */,0x40a00000 /* 5.0f */);
    fVar2 = (float)fVar9;
    fVar9 = (float10)CountdownTimer::Now();
    this_01 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x48bc) != (float)fVar9 + fVar2) {
      (**(code **)(*(int *)((int)param_2 + 0x48b4) + 4))
                ((int)param_2 + 0x48b4,(int)param_2 + 0x48bc);
      *(float *)((int)param_2 + 0x48bc) = (float)fVar9 + fVar2;
      this_01 = extraout_ECX_00;
    }
    if (*(float *)((int)param_2 + 0x48b8) != fVar2) {
      (**(code **)(*(int *)((int)param_2 + 0x48b4) + 4))
                ((int)param_2 + 0x48b4,(int)param_2 + 0x48b8);
      *(float *)((int)param_2 + 0x48b8) = fVar2;
      this_01 = extraout_ECX_01;
    }
    CBaseEntity::GetTeamNumber(this_01);
    iVar5 = TheINSNextBots();
    cVar3 = CINSNextBotManager::AreBotsOnTeamInCombat(this_02,iVar5);
    if (cVar3 != '\0') {
      CINSNextBot::MaxPathLength();
      CINSPathFollower::ComputePath();
    }
  }
  fVar9 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x48c8) <= (float)fVar9 &&
      (float)fVar9 != *(float *)((int)param_2 + 0x48c8)) {
    CINSPathFollower::Update(this_00,(INextBot *)((int)param_2 + 0x38));
    piVar4 = (int *)(*(int **)(&LAB_004769c5 + unaff_EBX))[7];
    if (piVar4 == *(int **)(&LAB_004769c5 + unaff_EBX)) {
      local_24 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4,pCVar8);
      local_24 = (float)fVar9;
    }
    fVar9 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x48c8) != (float)fVar9 + local_24) {
      (**(code **)(*(int *)((int)param_2 + 0x48c0) + 4))
                ((int)param_2 + 0x48c0,(int)param_2 + 0x48c8);
      *(float *)((int)param_2 + 0x48c8) = (float)fVar9 + local_24;
    }
    if (*(float *)((int)param_2 + 0x48c4) != local_24) {
      (**(code **)(*(int *)((int)param_2 + 0x48c0) + 4))
                ((int)param_2 + 0x48c0,(int)param_2 + 0x48c4);
      *(float *)((int)param_2 + 0x48c4) = local_24;
    }
  }
LAB_00730507:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnEnd
 * Address: 0072faa0
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotRetreatToHidingSpot::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  *(CINSNextBot *)(param_2 + 0x2291) = param_1[0x48dc];
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::GetName
 * Address: 00730d60
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::GetName() const */

int CINSBotRetreatToHidingSpot::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x250ebe /* "Retreating to hiding spot" */ /* "Retreating to hiding spot" */;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::ShouldHurry
 * Address: 0072fac0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToHidingSpot::ShouldHurry(INextBot const*) const */

void __thiscall
CINSBotRetreatToHidingSpot::ShouldHurry(CINSBotRetreatToHidingSpot *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::ShouldHurry
 * Address: 0072fad0
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotRetreatToHidingSpot::ShouldHurry(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::ShouldAttack
 * Address: 0072fae0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToHidingSpot::ShouldAttack(INextBot const*, CKnownEntity
   const*) const */

void __thiscall
CINSBotRetreatToHidingSpot::ShouldAttack
          (CINSBotRetreatToHidingSpot *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::ShouldAttack
 * Address: 0072faf0
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotRetreatToHidingSpot::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnMoveToSuccess
 * Address: 0072fd50
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotRetreatToHidingSpot::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  int unaff_EBX;
  float10 fVar5;
  
  __i686_get_pc_thunk_bx();
  fVar5 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x48d8) != (float)fVar5) {
    (**(code **)(*(int *)(param_2 + 0x48d4) + 8))(param_2 + 0x48d4,param_2 + 0x48d8);
    *(float *)(param_2 + 0x48d8) = (float)fVar5;
  }
  if (param_2[0x48cc] == (Path)0x0) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  else {
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
    iVar3 = *(int *)(unaff_EBX + 0x476c9a /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
    piVar4[0xf] = 0;
    piVar4[1] = iVar3 + 0x198;
    iVar1 = unaff_EBX + 0x3f845a /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    *piVar4 = iVar3 + 8;
    pcVar2 = (code *)(unaff_EBX + -0x4ff5ee /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
    piVar4[0xe] = iVar1;
    (*pcVar2)(piVar4 + 0xe,piVar4 + 0xf);
    piVar4[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
    piVar4[0x12] = 0;
    piVar4[0x11] = iVar1;
    (*pcVar2)(piVar4 + 0x11,piVar4 + 0x12);
    piVar4[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
    piVar4[0x15] = 0;
    piVar4[0x14] = iVar1;
    (*pcVar2)(piVar4 + 0x14,piVar4 + 0x15);
    piVar4[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(int **)(param_1 + 4) = piVar4;
    *(int *)(param_1 + 8) = unaff_EBX + 0x251b8a /* "Doing reload after OnMoveToFailure" */ /* "Doing reload after OnMoveToFailure" */;
    *(undefined4 *)(param_1 + 0xc) = 3;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnMoveToFailure
 * Address: 0072ff70
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotRetreatToHidingSpot::OnMoveToFailure(undefined4 *param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (*(char *)(iVar2 + 0x48cc) == '\0') {
    *param_1 = 3;
    param_1[1] = 0;
    param_1[2] = unaff_EBX + 0x25198b /* "We couldn't get to target's position!" */ /* "We couldn't get to target's position!" */;
    param_1[3] = 3;
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
    iVar2 = *(int *)(unaff_EBX + 0x476a77 /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
    piVar3[0xf] = 0;
    piVar3[1] = iVar2 + 0x198;
    *piVar3 = iVar2 + 8;
    iVar2 = unaff_EBX + 0x3f8237 /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    pcVar1 = (code *)(unaff_EBX + -0x4ff811 /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
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
    param_1[2] = unaff_EBX + 0x251967 /* "Doing reload after OnMoveToFailure" */ /* "Doing reload after OnMoveToFailure" */;
    param_1[3] = 3;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnStuck
 * Address: 00730150
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotRetreatToHidingSpot::OnStuck(CINSNextBot *param_1)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  CINSPathFollower *this;
  int unaff_EBX;
  float10 fVar5;
  int in_stack_00000008;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  CINSPathFollower::Invalidate(this);
  fVar5 = (float10)CINSNextBot::MaxPathLength();
  iVar3 = 0;
  if (in_stack_0000000c != 0) {
    iVar3 = in_stack_0000000c + 0x2060;
  }
  cVar2 = CINSPathFollower::ComputePath
                    ((CINSPathFollower *)(in_stack_00000008 + 0x48a8),in_stack_00000008 + 0x38,iVar3
                     ,(CINSPathFollower *)(in_stack_00000008 + 0x48a8),3,(float)fVar5,0,0x41f00000 /* 30.0f */);
  if (cVar2 != '\0') {
    if (*(char *)(in_stack_00000008 + 0x48cc) == '\0') {
      *(undefined4 *)param_1 = 0 /* Continue */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      *(undefined4 *)(param_1 + 0xc) = 1;
      return param_1;
    }
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
    iVar3 = *(int *)(unaff_EBX + 0x47689d /* &vtable for CINSBotReload */ /* &vtable for CINSBotReload */);
    piVar4[0xf] = 0;
    *piVar4 = iVar3 + 8;
    piVar4[1] = iVar3 + 0x198;
    iVar3 = unaff_EBX + 0x3f805d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    piVar4[0xe] = iVar3;
    pcVar1 = (code *)(unaff_EBX + -0x4ff9eb /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
    (*pcVar1)(piVar4 + 0xe,piVar4 + 0xf);
    piVar4[0x10] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0xe] + 4))(piVar4 + 0xe,piVar4 + 0x10);
    piVar4[0x12] = 0;
    piVar4[0x11] = iVar3;
    (*pcVar1)(piVar4 + 0x11,piVar4 + 0x12);
    piVar4[0x13] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x11] + 4))(piVar4 + 0x11,piVar4 + 0x13);
    piVar4[0x15] = 0;
    piVar4[0x14] = iVar3;
    (*pcVar1)(piVar4 + 0x14,piVar4 + 0x15);
    piVar4[0x16] = -0x40800000 /* -1.0f */;
    (**(code **)(piVar4[0x14] + 4))(piVar4 + 0x14,piVar4 + 0x16);
    *(undefined4 *)param_1 = 1 /* ChangeTo */;
    *(undefined **)(param_1 + 8) = &UNK_0025178d + unaff_EBX;
    *(int **)(param_1 + 4) = piVar4;
    *(undefined4 *)(param_1 + 0xc) = 3;
    return param_1;
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x251b3d /* "We couldn't get a path to our target after getting stuck" */ /* "We couldn't get a path to our target after getting stuck" */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0xc) = 3;
  return param_1;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::OnInjured
 * Address: 0072fb00
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotRetreatToHidingSpot::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  int extraout_ECX;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_cx();
  if ((*(byte *)(in_stack_00000010 + 0x3c) & 8) == 0) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 1;
    return;
  }
  *(undefined4 *)param_1 = 4;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x252138 /* "Sustaining retreat from fire." */ /* "Sustaining retreat from fire." */;
  *(undefined4 *)(param_1 + 0xc) = 3;
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot
 * Address: 00730d80
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot() */

void __thiscall
CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot(CINSBotRetreatToHidingSpot *this)

{
  ~CINSBotRetreatToHidingSpot(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot
 * Address: 00730d90
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot() */

void __thiscall
CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot(CINSBotRetreatToHidingSpot *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46758a /* vtable for CINSBotRetreatToHidingSpot+0x8 */ /* vtable for CINSBotRetreatToHidingSpot+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x467722 /* vtable for CINSBotRetreatToHidingSpot+0x1a0 */ /* vtable for CINSBotRetreatToHidingSpot+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot
 * Address: 00730df0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot() */

void __thiscall
CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot(CINSBotRetreatToHidingSpot *this)

{
  ~CINSBotRetreatToHidingSpot(this);
  return;
}



/* ----------------------------------------
 * CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot
 * Address: 00730e00
 * ---------------------------------------- */

/* CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot() */

void __thiscall
CINSBotRetreatToHidingSpot::~CINSBotRetreatToHidingSpot(CINSBotRetreatToHidingSpot *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46751a /* vtable for CINSBotRetreatToHidingSpot+0x8 */ /* vtable for CINSBotRetreatToHidingSpot+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4676b2 /* vtable for CINSBotRetreatToHidingSpot+0x1a0 */ /* vtable for CINSBotRetreatToHidingSpot+0x1a0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



